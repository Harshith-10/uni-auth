use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::{DeleteUserRequest, UpdateUserRequest};
use crate::error_to_response;
use crate::extract::CurrentSession;
use crate::state::AuthState;

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

/// `POST /api/auth/delete-user` (requires current password or fresh session)
pub async fn delete_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    bytes: axum::body::Bytes,
) -> Response {
    let payload: DeleteUserRequest = if bytes.is_empty() {
        DeleteUserRequest::default()
    } else {
        serde_json::from_slice(&bytes).unwrap_or_default()
    };

    match state
        .service
        .delete_user(
            &current_session.user.id,
            Some(current_session.session.created_at),
            payload,
        )
        .await
    {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res)).into_response();
            state.clear_session_cookie(&mut response);
            response
        }
        Err(err) => error_to_response(err),
    }
}
