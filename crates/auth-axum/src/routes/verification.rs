use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;

use auth_proto::{AuthErrorResponse, SendVerificationEmailRequest};
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

pub async fn send_verification_email(
    State(state): State<AuthState>,
    Json(payload): Json<SendVerificationEmailRequest>,
) -> Response {
    match state.service.send_verification_email(payload).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
    #[serde(rename = "callbackURL", alias = "callbackUrl")]
    pub callback_url: Option<String>,
}

pub async fn verify_email(
    State(state): State<AuthState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    match state.service.verify_email(&query.token).await {
        Ok(res) => {
            if let Some(ref callback) = query.callback_url {
                Redirect::temporary(callback).into_response()
            } else {
                (StatusCode::OK, Json(res)).into_response()
            }
        }
        Err(err) => {
            if let Some(ref callback) = query.callback_url {
                let separator = if callback.contains('?') { "&" } else { "?" };
                Redirect::temporary(&format!("{callback}{separator}error={}", err.error_code()))
                    .into_response()
            } else {
                error_to_response(err)
            }
        }
    }
}
