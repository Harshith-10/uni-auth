use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::error_to_response;
use crate::extract::{CurrentSession, ExtractedMeta, FreshSession};
use crate::state::AuthState;
use auth_core::OAuthCallbackResult;
use auth_proto::{
    AuthErrorResponse, LinkSocialRequest, OAuthAccountSelectionRequest, SignInSocialRequest,
    UnlinkAccountRequest,
};

pub async fn sign_in_social(
    State(state): State<AuthState>,
    Json(payload): Json<SignInSocialRequest>,
) -> Response {
    if let Some(ref cb) = payload.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }
    if let Some(ref cb) = payload.new_user_callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }
    if let Some(ref cb) = payload.error_callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }

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
    if let Some(ref cb) = payload.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }
    if let Some(ref cb) = payload.error_callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(cb, &state.trusted_origins) {
            return error_to_response(err);
        }
    }

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
    if !crate::middleware::is_loopback_url(url) {
        return false;
    }
    let without_query = url.split('?').next().unwrap_or(url).trim_end_matches('/');
    without_query.ends_with("/auth/callback") || url.contains("loopback=1")
}

pub async fn oauth_callback(
    State(state): State<AuthState>,
    meta: ExtractedMeta,
    Path(provider_name): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Response {
    let meta = meta.into_inner();
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
                Json(
                    AuthErrorResponse::new("INVALID_CODE", "Missing authorization code")
                        .with_status(400),
                ),
            )
                .into_response();
        }
    };

    let oauth_state = match query.state {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    AuthErrorResponse::new("INVALID_STATE", "Missing OAuth state").with_status(400),
                ),
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
                Json(
                    AuthErrorResponse::new("PROVIDER_NOT_FOUND", "Provider not configured")
                        .with_status(404),
                ),
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
        .exchange_code_and_fetch_profile(provider, &code, &state_data.code_verifier, &callback_uri)
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
                return Redirect::temporary(&format!("{err_cb}{sep}error={}", err.error_code()))
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
                    let ott_res = match state.service.generate_one_time_token(&session.token).await
                    {
                        Ok(r) => r,
                        Err(err) => return error_to_response(err),
                    };
                    let separator = if target.contains('?') { "&" } else { "?" };
                    format!("{target}{separator}token={}", ott_res.token)
                } else {
                    target
                };

                let mut response = Redirect::temporary(&redirect_url).into_response();
                state.attach_session_cookie(&mut response, &session.token, true, None);
                response
                    .extensions_mut()
                    .insert(crate::state::NewSessionExt(session, user));
                response
            } else {
                let ott_res = match state.service.generate_one_time_token(&session.token).await {
                    Ok(r) => r,
                    Err(err) => return error_to_response(err),
                };

                let mut response = (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "token": session.token,
                        "oneTimeToken": ott_res.token,
                        "user": user.to_wire()
                    })),
                )
                    .into_response();
                state.attach_session_cookie(&mut response, &session.token, true, None);
                response
                    .extensions_mut()
                    .insert(crate::state::NewSessionExt(session, user));
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

/// `POST /api/auth/get-access-token`
pub async fn get_access_token(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<OAuthAccountSelectionRequest>,
) -> Response {
    match state
        .service
        .get_access_token(&current_session.user.id, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/refresh-token`
pub async fn refresh_token(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<OAuthAccountSelectionRequest>,
) -> Response {
    match state
        .service
        .refresh_token(&current_session.user.id, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `GET /api/auth/account-info`
pub async fn get_account_info(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Query(query): Query<OAuthAccountSelectionRequest>,
) -> Response {
    match state
        .service
        .get_account_info(&current_session.user.id, query)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}
