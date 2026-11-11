use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::{error_codes, AuthErrorResponse, RevokeSessionRequest};
use crate::cookies::build_clear_session_cookie;
use crate::extract::{extract_token_from_headers, CurrentSession};
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

pub async fn get_session(
    State(state): State<AuthState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method == Method::POST && !state.service.config().defer_session_refresh {
        let err = AuthErrorResponse::new(
            error_codes::METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED,
            "deferSessionRefresh is required for POST /get-session",
        )
        .with_status(405);
        return (StatusCode::METHOD_NOT_ALLOWED, Json(err)).into_response();
    }
    let is_bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase().starts_with("bearer "))
        .unwrap_or(false);

    let token = match extract_token_from_headers(&headers, &state.cookie_name) {
        Some(t) => t,
        None => {
            // Per Better Auth spec: returns 200 OK with null when unauthenticated
            return (StatusCode::OK, Json(serde_json::Value::Null)).into_response();
        }
    };

    if !is_bearer && state.service.verify_signed_token(&token).is_none() {
        let mut response = (StatusCode::OK, Json(serde_json::Value::Null)).into_response();
        let clear_cookie = build_clear_session_cookie(
            &state.cookie_name,
            state.secure_cookies,
            &state.same_site,
        );
        if let Ok(cookie_val) = clear_cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, cookie_val);
        }
        return response;
    }

    match state.service.get_session(&token).await {
        Ok(Some(session)) => {
            let mut response = (StatusCode::OK, Json(session)).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            response
                .headers_mut()
                .insert(header::PRAGMA, "no-cache".parse().unwrap());
            response
        }
        Ok(None) | Err(_) => {
            let mut response = (StatusCode::OK, Json(serde_json::Value::Null)).into_response();
            let clear_cookie = build_clear_session_cookie(
                &state.cookie_name,
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(cookie_val) = clear_cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, cookie_val);
            }
            response
        }
    }
}

pub async fn list_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    match state.service.list_sessions(&current_session.user.id).await {
        Ok(sessions) => (StatusCode::OK, Json(sessions)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn revoke_session(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<RevokeSessionRequest>,
) -> Response {
    match state.service.revoke_session(&current_session.user.id, &payload.token).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn revoke_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    match state.service.revoke_sessions(&current_session.user.id).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn revoke_other_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    match state
        .service
        .revoke_other_sessions(&current_session.user.id, &current_session.session.token)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}
