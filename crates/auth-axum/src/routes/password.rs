use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;

use auth_proto::{
    AuthErrorResponse, ChangePasswordRequest, RequestPasswordResetRequest, ResetPasswordRequest,
};
use crate::extract::CurrentSession;
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

pub async fn request_password_reset(
    State(state): State<AuthState>,
    Json(payload): Json<RequestPasswordResetRequest>,
) -> Response {
    match state.service.request_password_reset(payload).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    #[serde(rename = "callbackURL", alias = "callbackUrl")]
    pub callback_url: Option<String>,
}

pub async fn reset_password_callback(
    State(state): State<AuthState>,
    Path(token): Path<String>,
    Query(query): Query<ResetPasswordQuery>,
) -> Response {
    let callback = query.callback_url.unwrap_or_else(|| "/".to_string());
    let identifier = format!("reset-password:{token}");

    match state.service.adapter().find_verification(&identifier).await {
        Ok(Some(record)) if !record.is_expired() => {
            let separator = if callback.contains('?') { "&" } else { "?" };
            Redirect::temporary(&format!("{callback}{separator}token={token}")).into_response()
        }
        _ => {
            let separator = if callback.contains('?') { "&" } else { "?" };
            Redirect::temporary(&format!("{callback}{separator}error=INVALID_TOKEN")).into_response()
        }
    }
}

pub async fn reset_password(
    State(state): State<AuthState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Response {
    match state.service.reset_password(payload).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn change_password(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<ChangePasswordRequest>,
) -> Response {
    match state
        .service
        .change_password(
            &current_session.user.id,
            &current_session.session.token,
            payload,
        )
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}
