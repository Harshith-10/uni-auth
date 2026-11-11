use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use time::OffsetDateTime;

use auth_core::models::CreateVerificationInput;
use auth_core::OAuthCallbackResult;
use auth_proto::{
    AuthErrorResponse, LinkSocialRequest, SignInSocialRequest, UnlinkAccountRequest,
};
use crate::error_to_response;
use crate::extract::{extract_request_meta, CurrentSession, FreshSession};
use crate::state::AuthState;

pub async fn sign_in_social(
    State(state): State<AuthState>,
    Json(payload): Json<SignInSocialRequest>,
) -> Response {
    let provider = match state.oauth_providers.get(&payload.provider) {
        Some(p) => p,
        None => {
            let err = AuthErrorResponse::new(
                "PROVIDER_NOT_FOUND",
                format!("Provider '{}' not found", payload.provider),
            )
            .with_status(404);
            return (StatusCode::NOT_FOUND, Json(err)).into_response();
        }
    };

    match state.service.begin_social_sign_in(provider, payload).await {
        Ok(res) => {
            if res.redirect {
                let mut response = (StatusCode::OK, Json(res.clone())).into_response();
                if let Ok(loc) = res.url.parse() {
                    response.headers_mut().insert(header::LOCATION, loc);
                }
                response
            } else {
                (StatusCode::OK, Json(res)).into_response()
            }
        }
        Err(err) => error_to_response(err),
    }
}

pub async fn link_social(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<LinkSocialRequest>,
) -> Response {
    let provider = match state.oauth_providers.get(&payload.provider) {
        Some(p) => p,
        None => {
            let err = AuthErrorResponse::new(
                "PROVIDER_NOT_FOUND",
                format!("Provider '{}' not found", payload.provider),
            )
            .with_status(404);
            return (StatusCode::NOT_FOUND, Json(err)).into_response();
        }
    };

    match state
        .service
        .begin_link_social(provider, &current_session.user.id, payload)
        .await
    {
        Ok(res) => {
            if res.redirect {
                let mut response = (StatusCode::OK, Json(res.clone())).into_response();
                if let Ok(loc) = res.url.parse() {
                    response.headers_mut().insert(header::LOCATION, loc);
                }
                response
            } else {
                (StatusCode::OK, Json(res)).into_response()
            }
        }
        Err(err) => error_to_response(err),
    }
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

fn is_loopback_ott_callback(url: &str) -> bool {
    let without_query = url.split('?').next().unwrap_or(url).trim_end_matches('/');
    without_query.ends_with("/auth/callback") || url.contains("loopback=1")
}

pub async fn oauth_callback(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Path(provider_name): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Response {
    let meta = extract_request_meta(&headers);
    if let Some(ref err) = query.error {
        let desc = query.error_description.as_deref().unwrap_or(err);
        return (
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse::new("OAUTH_ERROR", desc).with_status(400)),
        )
            .into_response();
    }

    let code = match query.code {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse::new("INVALID_CODE", "Missing authorization code").with_status(400)),
            )
                .into_response();
        }
    };

    let oauth_state = match query.state {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse::new("INVALID_STATE", "Missing OAuth state").with_status(400)),
            )
                .into_response();
        }
    };

    let state_data = match state.service.consume_oauth_state(&oauth_state).await {
        Ok(d) => d,
        Err(err) => return error_to_response(err),
    };

    let provider = match state.oauth_providers.get(&provider_name) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(AuthErrorResponse::new("PROVIDER_NOT_FOUND", "Provider not configured").with_status(404)),
            )
                .into_response();
        }
    };

    let callback_uri = format!(
        "{}/callback/{}",
        state.service.config().base_url,
        provider.provider_id
    );

    let profile = match state
        .oauth_http_client
        .exchange_code_and_fetch_profile(
            provider,
            &code,
            &state_data.code_verifier,
            &callback_uri,
        )
        .await
    {
        Ok(p) => p,
        Err(err_msg) => {
            if let Some(ref err_cb) = state_data.error_callback_url {
                let sep = if err_cb.contains('?') { "&" } else { "?" };
                return Redirect::temporary(&format!(
                    "{err_cb}{sep}error={}",
                    auth_proto::url_encode(&err_msg)
                ))
                .into_response();
            }
            return (
                StatusCode::BAD_GATEWAY,
                Json(AuthErrorResponse::new("FAILED_TO_GET_USER_INFO", err_msg).with_status(502)),
            )
                .into_response();
        }
    };

    let callback_url = state_data.callback_url.clone();
    let new_user_callback_url = state_data.new_user_callback_url.clone();
    let error_callback_url = state_data.error_callback_url.clone();

    let outcome = match state
        .service
        .complete_oauth_callback(&provider_name, profile, state_data.link_user_id, meta)
        .await
    {
        Ok(o) => o,
        Err(err) => {
            if let Some(ref err_cb) = error_callback_url {
                let sep = if err_cb.contains('?') { "&" } else { "?" };
                return Redirect::temporary(&format!(
                    "{err_cb}{sep}error={}",
                    err.error_code()
                ))
                .into_response();
            }
            return error_to_response(err);
        }
    };

    match outcome {
        OAuthCallbackResult::Linked { .. } => {
            if let Some(target) = callback_url {
                Redirect::temporary(&target).into_response()
            } else {
                (StatusCode::OK, Json(serde_json::json!({ "status": true }))).into_response()
            }
        }
        OAuthCallbackResult::Authenticated {
            user,
            session,
            is_new_user,
        } => {
            let redirect_target = if is_new_user {
                new_user_callback_url.or(callback_url)
            } else {
                callback_url
            };

            if let Some(target) = redirect_target {
                let redirect_url = if is_loopback_ott_callback(&target) {
                    let ott = auth_core::crypto::generate_random_token(32);
                    let ott_exp = OffsetDateTime::now_utc() + state.service.config().ott_expires_in;
                    let _ = state
                        .service
                        .adapter()
                        .create_verification(CreateVerificationInput {
                            id: None,
                            identifier: format!("one-time-token:{ott}"),
                            value: session.token.clone(),
                            expires_at: ott_exp,
                        })
                        .await;
                    let separator = if target.contains('?') { "&" } else { "?" };
                    format!("{target}{separator}token={ott}")
                } else {
                    target
                };

                let mut response = Redirect::temporary(&redirect_url).into_response();
                state.attach_session_cookie(&mut response, &session.token, true, None);
                response
            } else {
                let ott = auth_core::crypto::generate_random_token(32);
                let ott_exp = OffsetDateTime::now_utc() + state.service.config().ott_expires_in;
                let _ = state
                    .service
                    .adapter()
                    .create_verification(CreateVerificationInput {
                        id: None,
                        identifier: format!("one-time-token:{ott}"),
                        value: session.token.clone(),
                        expires_at: ott_exp,
                    })
                    .await;

                let mut response = (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "token": session.token,
                        "oneTimeToken": ott,
                        "user": user.to_wire()
                    })),
                )
                    .into_response();
                state.attach_session_cookie(&mut response, &session.token, true, None);
                response
            }
        }
    }
}

pub async fn list_accounts(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    match state.service.list_accounts(&current_session.user.id).await {
        Ok(accounts) => (StatusCode::OK, Json(accounts)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn unlink_account(
    State(state): State<AuthState>,
    fresh_session: FreshSession,
    Json(payload): Json<UnlinkAccountRequest>,
) -> Response {
    let account_id = payload.account_id.as_deref().unwrap_or("");
    match state
        .service
        .unlink_account(&fresh_session.user.id, &payload.provider_id, account_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}
