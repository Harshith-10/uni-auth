use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;

use auth_proto::{
    AuthErrorResponse, ChangePasswordRequest, RequestPasswordResetRequest, ResetPasswordRequest,
};
use crate::cookies::build_session_cookie;
use crate::extract::FreshSession;
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
                let signed_token = state.service.sign_token(raw_token);
                let cookie = build_session_cookie(
                    &state.cookie_name,
                    &signed_token,
                    state.service.config().session_expires_in.whole_seconds(),
                    state.secure_cookies,
                    &state.same_site,
                );
                if let Ok(cookie_val) = cookie.parse() {
                    response.headers_mut().append(header::SET_COOKIE, cookie_val);
                }
                if let Ok(token_val) = signed_token.parse() {
                    response.headers_mut().insert("set-auth-token", token_val);
                }
            }
            response
        }
        Err(err) => error_to_response(err),
    }
}
