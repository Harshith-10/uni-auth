use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::error_to_response;
use crate::extract::CurrentSession;
use crate::state::AuthState;
use auth_proto::{ChangeEmailRequest, DeleteUserRequest, UpdateUserRequest};

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

/// `POST /api/auth/change-email`
pub async fn change_email(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<ChangeEmailRequest>,
) -> Response {
    if let Some(ref cb) = payload.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }
    match state
        .service
        .change_email(&current_session.user.id, payload)
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

#[derive(Debug, Deserialize)]
pub struct DeleteUserCallbackQuery {
    pub token: String,
    #[serde(default, alias = "callbackURL", alias = "callback_url")]
    pub callback_url: Option<String>,
}

/// `GET /api/auth/delete-user/callback`
pub async fn delete_user_callback(
    State(state): State<AuthState>,
    Query(query): Query<DeleteUserCallbackQuery>,
) -> Response {
    if let Some(ref cb) = query.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }

    match state.service.delete_user_by_callback(&query.token).await {
        Ok(_user_id) => {
            if let Some(cb) = query.callback_url {
                let mut response = Redirect::temporary(&cb).into_response();
                state.clear_session_cookie(&mut response);
                response
            } else {
                let mut response = (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "success": true,
                        "message": "User deleted"
                    })),
                )
                    .into_response();
                state.clear_session_cookie(&mut response);
                response
            }
        }
        Err(err) => error_to_response(err),
    }
}
