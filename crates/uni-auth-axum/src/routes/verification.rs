use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::error_to_response;
use crate::extract::ExtractedMeta;
use crate::state::AuthState;
use uni_auth_proto::SendVerificationEmailRequest;

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
    #[serde(rename = "callbackURL", alias = "callbackUrl", alias = "callback_url")]
    pub callback_url: Option<String>,
}

pub async fn verify_email(
    State(state): State<AuthState>,
    meta: ExtractedMeta,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    if let Some(ref callback) = query.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(callback, &state.trusted_origins)
        {
            return error_to_response(err);
        }
    }

    let meta = meta.into_inner();
    match state
        .service
        .verify_email_with_meta(&query.token, meta)
        .await
    {
        Ok(res) => {
            let mut response = if let Some(ref callback) = query.callback_url {
                Redirect::temporary(callback).into_response()
            } else {
                (StatusCode::OK, Json(res.clone())).into_response()
            };

            if let Some(ref raw_token) = res.token {
                state.attach_session_cookie(&mut response, raw_token, true, None);
                if let Ok(Some(ses)) = state
                    .service
                    .adapter()
                    .find_session_by_token(raw_token)
                    .await
                {
                    if let Some(ref u) = res.user {
                        if let Ok(Some(usr)) = state.service.adapter().find_user_by_id(&u.id).await
                        {
                            response
                                .extensions_mut()
                                .insert(crate::state::NewSessionExt(ses, usr));
                        }
                    }
                }
            }

            response
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
