use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error_to_response;
use crate::extract::{CurrentSession, ExtractedToken, extract_token_with_source};
use crate::state::AuthState;
use uni_auth_proto::{
    AuthErrorResponse, RevokeSessionRequest, UpdateSessionRequest, error_codes,
};

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
    let extracted = match extract_token_with_source(&headers, &state.cookie_name) {
        Some(t) => t,
        None => {
            // Returns 200 OK with null when unauthenticated
            return (StatusCode::OK, Json(serde_json::Value::Null)).into_response();
        }
    };

    let is_bearer = extracted.is_bearer();
    let token = match extracted {
        ExtractedToken::Bearer(tok) => tok,
        ExtractedToken::Cookie(signed_cookie) => {
            if state.service.verify_signed_token(&signed_cookie).is_none() {
                let mut response = (StatusCode::OK, Json(serde_json::Value::Null)).into_response();
                state.clear_session_cookie(&mut response);
                return response;
            }
            signed_cookie
        }
    };

    match state.service.get_session(&token).await {
        Ok(Some(session)) => {
            let mut response = (StatusCode::OK, Json(session)).into_response();
            if !is_bearer {
                let raw_token = state.service.verify_token(&token).unwrap_or(token);
                state.attach_session_cookie(&mut response, &raw_token, true, None);
            }
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

/// `POST /api/auth/update-session` (updates active session metadata)
pub async fn update_session(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<UpdateSessionRequest>,
) -> Response {
    match state
        .service
        .update_session(&current_session.session.token, payload)
        .await
    {
        Ok(session) => (
            StatusCode::OK,
            Json(uni_auth_proto::UpdateSessionResponse { session }),
        )
            .into_response(),
        Err(err) => error_to_response(err),
    }
}
