use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::{AuthErrorResponse, DeleteUserRequest, UpdateUserRequest};
use crate::cookies::build_clear_session_cookie;
use crate::extract::{CurrentSession, FreshSession};
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body =
        AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

/// `POST /api/auth/update-user`
pub async fn update_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<UpdateUserRequest>,
) -> Response {
    match state
        .service
        .update_user(&current_session.user.id, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/delete-user` (requires a fresh session)
pub async fn delete_user(
    State(state): State<AuthState>,
    fresh_session: FreshSession,
    bytes: axum::body::Bytes,
) -> Response {
    let payload: DeleteUserRequest = if bytes.is_empty() {
        DeleteUserRequest::default()
    } else {
        serde_json::from_slice(&bytes).unwrap_or_default()
    };

    match state
        .service
        .delete_user(&fresh_session.user.id, payload)
        .await
    {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res)).into_response();
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
        Err(err) => error_to_response(err),
    }
}
