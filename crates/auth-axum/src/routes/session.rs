use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error_to_response;
use crate::extract::{CurrentSession, extract_token_from_headers};
use crate::state::AuthState;
use auth_proto::{AuthErrorResponse, RevokeSessionRequest, error_codes};

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
        state.clear_session_cookie(&mut response);
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
            state.clear_session_cookie(&mut response);
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
    match state
        .service
        .revoke_session(&current_session.user.id, &payload.token)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn revoke_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    match state
        .service
        .revoke_sessions(&current_session.user.id)
        .await
    {
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
