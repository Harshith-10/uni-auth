use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use auth_core::models::{
    CreateAccountInput, CreateSessionInput, CreateUserInput, CreateVerificationInput,
};
use auth_proto::{
    AuthErrorResponse, SignInSocialRequest, SignInSocialResponse,
    UnlinkAccountRequest,
};
use crate::cookies::build_session_cookie;
use crate::extract::{extract_request_meta, CurrentSession};
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

pub async fn sign_in_social(
    State(state): State<AuthState>,
    Json(payload): Json<SignInSocialRequest>,
) -> Response {
    let provider = match state.oauth_providers.get(&payload.provider) {
        Some(p) => p,
        None => {
            let err = AuthErrorResponse::new("PROVIDER_NOT_FOUND", format!("Provider '{}' not found", payload.provider))
                .with_status(404);
            return (StatusCode::NOT_FOUND, Json(err)).into_response();
        }
    };

    let oauth_state = auth_core::crypto::generate_random_token(32);
    let code_verifier = auth_core::crypto::generate_random_token(32);

    // Compute PKCE code_challenge = base64url(sha256(code_verifier))
    use sha2::{Digest, Sha256};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

    let state_payload = serde_json::json!({
        "codeVerifier": code_verifier,
        "callbackURL": payload.callback_url,
        "newUserCallbackURL": payload.new_user_callback_url,
        "errorCallbackURL": payload.error_callback_url,
    })
    .to_string();

    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let _ = state
        .service
        .adapter()
        .create_verification(CreateVerificationInput {
            id: None,
            identifier: format!("oauth-state:{oauth_state}"),
            value: state_payload,
            expires_at,
        })
        .await;

    let callback_uri = format!("{}/callback/{}", state.service.config().base_url, provider.provider_id);
    let scopes_str = provider.scopes.join(" ");

    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        provider.auth_url,
        provider.client_id,
        urlencoding_simple(&callback_uri),
        urlencoding_simple(&scopes_str),
        oauth_state,
        challenge
    );

    let disable_redirect = payload.disable_redirect.unwrap_or(false);

    if disable_redirect {
        (
            StatusCode::OK,
            Json(SignInSocialResponse {
                redirect: false,
                url: auth_url,
            }),
        )
            .into_response()
    } else {
        let mut response = (
            StatusCode::OK,
            Json(SignInSocialResponse {
                redirect: true,
                url: auth_url.clone(),
            }),
        )
            .into_response();
        if let Ok(loc) = auth_url.parse() {
            response.headers_mut().insert(header::LOCATION, loc);
        }
        response
    }
}

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
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

    let verification_id = format!("oauth-state:{oauth_state}");
    let record = match state.service.adapter().consume_verification(&verification_id).await {
        Ok(Some(r)) => r,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AuthErrorResponse::new("INVALID_STATE", "OAuth state not found or expired").with_status(400)),
            )
                .into_response();
        }
    };

    let state_data: serde_json::Value = serde_json::from_str(&record.value).unwrap_or_default();
    let callback_url = state_data
        .get("callbackURL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

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

    // Simulated profile fallback (upgraded to live OAuth2 exchange in Stage 2)
    let account_id = format!("oauth_acc_{}", auth_core::crypto::generate_random_token(8));
    let email = format!("user_{}@example.com", auth_core::crypto::generate_random_token(6).to_lowercase());
    let name = format!("OAuth User ({provider_name})");

    let user = match state.service.adapter().find_user_by_email(&email).await {
        Ok(Some(existing)) => existing,
        _ => {
            let user = state
                .service
                .adapter()
                .create_user(CreateUserInput {
                    id: None,
                    name,
                    email: email.clone(),
                    image: None,
                    email_verified: true,
                })
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response());

            match user {
                Ok(u) => u,
                Err(res) => return res,
            }
        }
    };

    let _ = state
        .service
        .adapter()
        .create_account(CreateAccountInput {
            id: None,
            user_id: user.id.clone(),
            account_id,
            provider_id: provider_name.clone(),
            access_token: Some(code.clone()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some(provider.scopes.join(",")),
            password: None,
        })
        .await;

    // Issue session
    let raw_token = auth_core::crypto::generate_session_token();
    let expires_at = OffsetDateTime::now_utc() + state.service.config().session_expires_in;

    let session = match state
        .service
        .adapter()
        .create_session(CreateSessionInput {
            id: None,
            user_id: user.id.clone(),
            token: raw_token.clone(),
            expires_at,
            ip_address: meta.ip_address,
            user_agent: meta.user_agent,
        })
        .await
    {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let signed_token = state.service.sign_token(&session.token);

    // Generate a one-time token for browser-to-desktop handoff
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

    if let Some(target) = callback_url {
        let separator = if target.contains('?') { "&" } else { "?" };
        let redirect_url = format!("{target}{separator}token={ott}");
        let mut response = Redirect::temporary(&redirect_url).into_response();

        let cookie = build_session_cookie(
            &state.cookie_name,
            &signed_token,
            state.service.config().session_expires_in.whole_seconds(),
            state.secure_cookies,
            &state.same_site,
        );
        if let Ok(c) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, c);
        }
        if let Ok(tok) = signed_token.parse() {
            response.headers_mut().insert("set-auth-token", tok);
        }
        response
    } else {
        let mut response = (
            StatusCode::OK,
            Json(serde_json::json!({
                "token": session.token,
                "oneTimeToken": ott,
                "user": user.to_wire()
            })),
        )
            .into_response();

        let cookie = build_session_cookie(
            &state.cookie_name,
            &signed_token,
            state.service.config().session_expires_in.whole_seconds(),
            state.secure_cookies,
            &state.same_site,
        );
        if let Ok(c) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, c);
        }
        if let Ok(tok) = signed_token.parse() {
            response.headers_mut().insert("set-auth-token", tok);
        }
        response
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
    current_session: CurrentSession,
    Json(payload): Json<UnlinkAccountRequest>,
) -> Response {
    let account_id = payload.account_id.as_deref().unwrap_or("");
    match state
        .service
        .unlink_account(&current_session.user.id, &payload.provider_id, account_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}
