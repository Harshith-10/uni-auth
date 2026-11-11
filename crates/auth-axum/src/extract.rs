//! Dual Cookie and Bearer session extractors for Axum routes.
//!
//! Allows any protected endpoint (auth routes or custom SaaS APIs like `/api/saas/me`)
//! to be called seamlessly from both React web apps (via cookies) and GPUI native desktop
//! apps (via `Authorization: Bearer <token>`).

use axum::Json;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::ops::Deref;

use crate::cookies::extract_cookie_token;
use crate::state::AuthState;
use auth_core::RequestMeta;
use auth_proto::{AuthErrorResponse, SessionWire, UserWire, error_codes};

/// Extracts client IP address (`x-forwarded-for` / `x-real-ip`) and `user-agent` from HTTP headers.
pub fn extract_request_meta(headers: &HeaderMap) -> RequestMeta {
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    RequestMeta {
        ip_address,
        user_agent,
    }
}

/// Extracts an authentication token from either `Authorization: Bearer <token>` or cookies.
pub fn extract_token_from_headers(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    // 1. Bearer token extraction (case-insensitive scheme)
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            let trimmed = auth_str.trim();
            if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
                let token = trimmed[7..].trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }

    // 2. Cookie extraction fallback
    extract_cookie_token(headers, cookie_name)
}

/// Extractor that requires a valid, active session.
/// Rejects with HTTP 401 Unauthorized if missing or expired.
#[derive(Debug, Clone)]
pub struct CurrentSession {
    pub session: SessionWire,
    pub user: UserWire,
    /// Indicates whether the session was authenticated via Bearer token (true) or Cookie (false)
    pub is_bearer: bool,
}

impl Deref for CurrentSession {
    type Target = SessionWire;
    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl<S> FromRequestParts<S> for CurrentSession
where
    S: Send + Sync,
    AuthState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);

        let is_bearer = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase().starts_with("bearer "))
            .unwrap_or(false);

        let token = extract_token_from_headers(&parts.headers, &auth_state.cookie_name);

        let token = match token {
            Some(t) => t,
            None => {
                let err = AuthErrorResponse::new("UNAUTHORIZED", "Unauthorized").with_status(401);
                return Err((StatusCode::UNAUTHORIZED, Json(err)).into_response());
            }
        };

        // Cookies must carry a valid HMAC signature
        if !is_bearer && auth_state.service.verify_signed_token(&token).is_none() {
            let err = AuthErrorResponse::new("UNAUTHORIZED", "Unauthorized").with_status(401);
            return Err((StatusCode::UNAUTHORIZED, Json(err)).into_response());
        }

        match auth_state.service.get_session(&token).await {
            Ok(Some(session_and_user)) => Ok(CurrentSession {
                session: session_and_user.session,
                user: session_and_user.user,
                is_bearer,
            }),
            Ok(None) | Err(_) => {
                let err = AuthErrorResponse::new("UNAUTHORIZED", "Unauthorized").with_status(401);
                Err((StatusCode::UNAUTHORIZED, Json(err)).into_response())
            }
        }
    }
}

/// Extractor that requires a valid AND fresh session (created within `session_fresh_age`).
///
/// Matches Better Auth's `freshSessionMiddleware` (`packages/better-auth/src/api/routes/session.ts:599-617`),
/// rejecting stale sessions with HTTP `403 Forbidden` and error code `SESSION_NOT_FRESH`.
#[derive(Debug, Clone)]
pub struct FreshSession(pub CurrentSession);

impl Deref for FreshSession {
    type Target = CurrentSession;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for FreshSession
where
    S: Send + Sync,
    AuthState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let current = CurrentSession::from_request_parts(parts, state).await?;
        let auth_state = AuthState::from_ref(state);

        if !auth_state.service.is_session_fresh(&current.session) {
            let err =
                AuthErrorResponse::new(error_codes::SESSION_NOT_FRESH, "Session is not fresh")
                    .with_status(403);
            return Err((StatusCode::FORBIDDEN, Json(err)).into_response());
        }

        Ok(FreshSession(current))
    }
}

/// Extractor for optional authentication.
/// Resolves to `Some(session)` if a valid token is provided, or `None` if unauthenticated.
#[derive(Debug, Clone)]
pub struct OptionalSession(pub Option<CurrentSession>);

impl Deref for OptionalSession {
    type Target = Option<CurrentSession>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for OptionalSession
where
    S: Send + Sync,
    AuthState: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);

        let is_bearer = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase().starts_with("bearer "))
            .unwrap_or(false);

        let token = extract_token_from_headers(&parts.headers, &auth_state.cookie_name);

        let token = match token {
            Some(t) => t,
            None => return Ok(OptionalSession(None)),
        };

        if !is_bearer && auth_state.service.verify_signed_token(&token).is_none() {
            return Ok(OptionalSession(None));
        }

        match auth_state.service.get_session(&token).await {
            Ok(Some(session_and_user)) => Ok(OptionalSession(Some(CurrentSession {
                session: session_and_user.session,
                user: session_and_user.user,
                is_bearer,
            }))),
            _ => Ok(OptionalSession(None)),
        }
    }
}
