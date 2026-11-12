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
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;

use crate::cookies::extract_cookie_token;
use crate::state::AuthState;
use auth_core::RequestMeta;
use auth_proto::{AuthErrorResponse, SessionWire, UserWire, error_codes};

/// IP network CIDR range used for trusted proxy validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCidr {
    V4 { addr: u32, mask: u32 },
    V6 { addr: u128, mask: u128 },
}

impl IpCidr {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpCidr::V4 { addr, mask }, IpAddr::V4(v4)) => {
                let ip_u32 = u32::from(*v4);
                (ip_u32 & mask) == (*addr & mask)
            }
            (IpCidr::V4 { addr, mask }, IpAddr::V6(v6)) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let ip_u32 = u32::from(v4);
                    (ip_u32 & mask) == (*addr & mask)
                } else {
                    false
                }
            }
            (IpCidr::V6 { addr, mask }, IpAddr::V6(v6)) => {
                let ip_u128 = u128::from(*v6);
                (ip_u128 & mask) == (*addr & mask)
            }
            (IpCidr::V6 { addr, mask }, IpAddr::V4(v4)) => {
                let v6 = v4.to_ipv6_mapped();
                let ip_u128 = u128::from(v6);
                (ip_u128 & mask) == (*addr & mask)
            }
        }
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        match parts.len() {
            1 => {
                let ip: IpAddr = parts[0].trim().parse().map_err(|e| format!("Invalid IP: {e}"))?;
                match ip {
                    IpAddr::V4(v4) => Ok(IpCidr::V4 {
                        addr: u32::from(v4),
                        mask: u32::MAX,
                    }),
                    IpAddr::V6(v6) => Ok(IpCidr::V6 {
                        addr: u128::from(v6),
                        mask: u128::MAX,
                    }),
                }
            }
            2 => {
                let ip: IpAddr = parts[0].trim().parse().map_err(|e| format!("Invalid IP: {e}"))?;
                let prefix: u32 = parts[1]
                    .trim()
                    .parse()
                    .map_err(|e| format!("Invalid prefix length: {e}"))?;
                match ip {
                    IpAddr::V4(v4) => {
                        if prefix > 32 {
                            return Err(format!("IPv4 prefix length must be <= 32, got {prefix}"));
                        }
                        let mask = if prefix == 0 {
                            0
                        } else {
                            !((1u32 << (32 - prefix)) - 1)
                        };
                        Ok(IpCidr::V4 {
                            addr: u32::from(v4) & mask,
                            mask,
                        })
                    }
                    IpAddr::V6(v6) => {
                        if prefix > 128 {
                            return Err(format!("IPv6 prefix length must be <= 128, got {prefix}"));
                        }
                        let mask = if prefix == 0 {
                            0
                        } else {
                            !((1u128 << (128 - prefix)) - 1)
                        };
                        Ok(IpCidr::V6 {
                            addr: u128::from(v6) & mask,
                            mask,
                        })
                    }
                }
            }
            _ => Err("Invalid CIDR format".to_string()),
        }
    }
}

/// Extracts the client IP address from HTTP headers (`X-Forwarded-For`, `X-Real-IP`),
/// validating against trusted proxy CIDRs if configured.
pub fn extract_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpCidr],
) -> Option<String> {
    let header_ip = headers
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

    match peer_ip {
        Some(peer) => {
            if trusted_proxies.is_empty() {
                header_ip.or_else(|| Some(peer.to_string()))
            } else {
                let is_trusted = trusted_proxies.iter().any(|cidr| cidr.contains(&peer));
                if is_trusted {
                    header_ip.or_else(|| Some(peer.to_string()))
                } else {
                    Some(peer.to_string())
                }
            }
        }
        None => {
            if trusted_proxies.is_empty() {
                header_ip
            } else {
                // When trusted proxies are configured, unverified headers without peer confirmation are untrusted
                None
            }
        }
    }
}

/// Extracts client IP address and `user-agent` with optional peer address and trusted proxy validation.
pub fn extract_request_meta_with_peer(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[IpCidr],
) -> RequestMeta {
    let ip_address = extract_client_ip(headers, peer_ip, trusted_proxies);

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

/// Extracts client IP address (`x-forwarded-for` / `x-real-ip`) and `user-agent` from HTTP headers.
pub fn extract_request_meta(headers: &HeaderMap) -> RequestMeta {
    extract_request_meta_with_peer(headers, None, &[])
}

/// Extractor that automatically extracts `RequestMeta` with client IP and `user-agent`,
/// validating client IP against configured trusted proxies and socket peer IP.
#[derive(Debug, Clone)]
pub struct ExtractedMeta(pub RequestMeta);

impl Deref for ExtractedMeta {
    type Target = RequestMeta;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ExtractedMeta {
    pub fn into_inner(self) -> RequestMeta {
        self.0
    }
}

impl<S> FromRequestParts<S> for ExtractedMeta
where
    S: Send + Sync,
    AuthState: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);
        let peer_ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());
        let meta = extract_request_meta_with_peer(
            &parts.headers,
            peer_ip,
            &auth_state.trusted_proxies,
        );
        Ok(ExtractedMeta(meta))
    }
}

/// Token source origin indicating whether it came from Bearer Authorization header or Cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractedToken {
    Bearer(String),
    Cookie(String),
}

impl ExtractedToken {
    pub fn is_bearer(&self) -> bool {
        matches!(self, Self::Bearer(_))
    }

    pub fn token(&self) -> &str {
        match self {
            Self::Bearer(t) | Self::Cookie(t) => t,
        }
    }
}

/// Extracts an authentication token with its source origin (Bearer or Cookie).
pub fn extract_token_with_source(headers: &HeaderMap, cookie_name: &str) -> Option<ExtractedToken> {
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            let trimmed = auth_str.trim();
            if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
                let token = trimmed[7..].trim();
                if !token.is_empty() {
                    return Some(ExtractedToken::Bearer(token.to_string()));
                }
            }
        }
    }
    extract_cookie_token(headers, cookie_name).map(ExtractedToken::Cookie)
}

/// Extracts an authentication token from either `Authorization: Bearer <token>` or cookies.
pub fn extract_token_from_headers(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    extract_token_with_source(headers, cookie_name).map(|t| t.token().to_string())
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

        let extracted = match extract_token_with_source(&parts.headers, &auth_state.cookie_name) {
            Some(t) => t,
            None => {
                let err = AuthErrorResponse::new("UNAUTHORIZED", "Unauthorized").with_status(401);
                return Err((StatusCode::UNAUTHORIZED, Json(err)).into_response());
            }
        };

        let is_bearer = extracted.is_bearer();
        let token = match extracted {
            ExtractedToken::Bearer(tok) => tok,
            ExtractedToken::Cookie(signed_cookie) => {
                // Cookies must carry a valid HMAC signature
                if auth_state
                    .service
                    .verify_signed_token(&signed_cookie)
                    .is_none()
                {
                    let err =
                        AuthErrorResponse::new("UNAUTHORIZED", "Unauthorized").with_status(401);
                    return Err((StatusCode::UNAUTHORIZED, Json(err)).into_response());
                }
                signed_cookie
            }
        };

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

/// Extractor that requires a valid AND fresh session (created within `session_fresh_age`),
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

        let extracted = match extract_token_with_source(&parts.headers, &auth_state.cookie_name) {
            Some(t) => t,
            None => return Ok(OptionalSession(None)),
        };

        let is_bearer = extracted.is_bearer();
        let token = match extracted {
            ExtractedToken::Bearer(tok) => tok,
            ExtractedToken::Cookie(signed_cookie) => {
                if auth_state
                    .service
                    .verify_signed_token(&signed_cookie)
                    .is_none()
                {
                    return Ok(OptionalSession(None));
                }
                signed_cookie
            }
        };

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
