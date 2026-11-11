use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::error_to_response;
use crate::extract::{CurrentSession, ExtractedMeta, FreshSession};
use crate::state::AuthState;
use auth_proto::{
    ChangePasswordRequest, RequestPasswordResetRequest, ResetPasswordRequest, SetPasswordRequest,
    VerifyPasswordRequest,
};

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
    if let Err(err) = crate::middleware::validate_callback_url(&callback, &state.trusted_origins) {
        return error_to_response(err);
    }
    let identifier = format!("reset-password:{token}");

    match state.service.adapter().find_verification(&identifier).await {
        Ok(Some(record)) if !record.is_expired() => {
            let separator = if callback.contains('?') { "&" } else { "?" };
            Redirect::temporary(&format!("{callback}{separator}token={token}")).into_response()
        }
        _ => {
            let separator = if callback.contains('?') { "&" } else { "?" };
            Redirect::temporary(&format!("{callback}{separator}error=INVALID_TOKEN"))
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ResetPasswordPostQuery {
    pub token: Option<String>,
}

pub async fn reset_password(
    State(state): State<AuthState>,
    meta: ExtractedMeta,
    Query(query): Query<ResetPasswordPostQuery>,
    Json(mut payload): Json<ResetPasswordRequest>,
) -> Response {
    if payload.token.is_none() || payload.token.as_deref() == Some("") {
        payload.token = query.token;
    }
    let meta = meta.into_inner();
    match state.service.reset_password_with_meta(payload, meta).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/set-password` (sets initial password for passwordless users)
pub async fn set_password(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<SetPasswordRequest>,
) -> Response {
    match state
        .service
        .set_password(&current_session.user.id, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/verify-password` (stateless verification of current password)
pub async fn verify_password(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<VerifyPasswordRequest>,
) -> Response {
    match state
        .service
        .verify_password(&current_session.user.id, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn change_password(
    State(state): State<AuthState>,
    fresh_session: FreshSession,
    Json(payload): Json<ChangePasswordRequest>,
) -> Response {
    match state
        .service
        .change_password(
            &fresh_session.user.id,
            &fresh_session.session.token,
            payload,
        )
        .await
    {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();
            if let Some(ref raw_token) = res.token {
                state.attach_session_cookie(&mut response, raw_token, true, None);
            }
            response
        }
        Err(err) => error_to_response(err),
    }
}
