use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use auth_core::models::{
    CreateAccountInput, CreateUserInput, CreateVerificationInput,
};
use auth_proto::{
    AuthErrorResponse, LinkSocialRequest, SignInSocialRequest, SignInSocialResponse,
    UnlinkAccountRequest,
};
use crate::cookies::build_session_cookie;
use crate::extract::{extract_request_meta, CurrentSession, FreshSession};
use crate::state::{AuthState, OAuthProviderConfig};

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
        "linkUserId": serde_json::Value::Null,
    })
    .to_string();

    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let _ = state
        .service
        .adapter()
        .create_verification(CreateVerificationInput {
            id: None,
            identifier: format!("auth-state:{oauth_state}"),
            value: state_payload,
            expires_at,
        })
        .await;

    let callback_uri = format!("{}/callback/{}", state.service.config().base_url, provider.provider_id);
    let scopes_str = provider.scopes.join(" ");

    let mut auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        provider.auth_url,
        provider.client_id,
        urlencoding_simple(&callback_uri),
        urlencoding_simple(&scopes_str),
        oauth_state,
        challenge
    );
    if let Some(ref hint) = payload.login_hint {
        auth_url.push_str(&format!("&login_hint={}", urlencoding_simple(hint)));
    }

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

/// `POST /api/auth/link-social`
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

    let oauth_state = auth_core::crypto::generate_random_token(32);
    let code_verifier = auth_core::crypto::generate_random_token(32);

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

    let state_payload = serde_json::json!({
        "codeVerifier": code_verifier,
        "callbackURL": payload.callback_url,
        "errorCallbackURL": payload.error_callback_url,
        "linkUserId": current_session.user.id,
    })
    .to_string();

    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let _ = state
        .service
        .adapter()
        .create_verification(CreateVerificationInput {
            id: None,
            identifier: format!("auth-state:{oauth_state}"),
            value: state_payload,
            expires_at,
        })
        .await;

    let callback_uri = format!(
        "{}/callback/{}",
        state.service.config().base_url,
        provider.provider_id
    );
    let mut scopes = provider.scopes.clone();
    if let Some(extra) = payload.scopes {
        for s in extra {
            if !scopes.contains(&s) {
                scopes.push(s);
            }
        }
    }
    let scopes_str = scopes.join(" ");

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

struct OAuthProfileResult {
    account_id: String,
    email: String,
    name: String,
    image: Option<String>,
    email_verified: bool,
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    access_token_expires_at: Option<OffsetDateTime>,
    scope: Option<String>,
}

async fn exchange_oauth_code_and_fetch_profile(
    provider: &OAuthProviderConfig,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<OAuthProfileResult, String> {
    // Allow deterministic mock/simulated mode when token_url starts with "mock://" or in local test fixtures
    if provider.token_url.starts_with("mock://") || provider.token_url.contains("127.0.0.1:0") {
        let unverified = provider.token_url.contains("unverified") || code.contains("unverified");
        let suffix = if let Some(rest) = code.strip_prefix("fixed_") {
            rest.to_lowercase()
        } else {
            auth_core::crypto::generate_random_token(6).to_lowercase()
        };
        return Ok(OAuthProfileResult {
            account_id: format!("oauth_acc_{suffix}"),
            email: format!("user_{suffix}@example.com"),
            name: format!("OAuth User ({})", provider.provider_id),
            image: None,
            email_verified: !unverified,
            access_token: format!("mock_access_{code}"),
            refresh_token: Some(format!("mock_refresh_{code}")),
            id_token: None,
            access_token_expires_at: None,
            scope: Some(provider.scopes.join(",")),
        });
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let token_res = http
        .post(&provider.token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|e| format!("Token exchange request failed: {e}"))?;

    if !token_res.status().is_success() {
        let status = token_res.status();
        let body = token_res.text().await.unwrap_or_default();
        return Err(format!("Token endpoint returned {status}: {body}"));
    }

    let token_json: serde_json::Value = token_res
        .json()
        .await
        .map_err(|e| format!("Invalid token JSON response: {e}"))?;

    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing access_token in provider response".to_string())?
        .to_string();

    let refresh_token = token_json
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let id_token = token_json
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let access_token_expires_at = token_json
        .get("expires_in")
        .and_then(|v| v.as_i64())
        .map(|secs| OffsetDateTime::now_utc() + Duration::seconds(secs));

    let scope = token_json
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.replace(' ', ","))
        .or_else(|| Some(provider.scopes.join(",")));

    let user_res = http
        .get(&provider.userinfo_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::USER_AGENT, "uni-auth-rust/0.1")
        .bearer_auth(&access_token)
        .send()
        .await
        .map_err(|e| format!("Userinfo request failed: {e}"))?;

    if !user_res.status().is_success() {
        let status = user_res.status();
        return Err(format!("Userinfo endpoint returned {status}"));
    }

    let profile: serde_json::Value = user_res
        .json()
        .await
        .map_err(|e| format!("Invalid userinfo JSON: {e}"))?;

    let account_id = profile
        .get("sub")
        .or_else(|| profile.get("id"))
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            other => other.to_string(),
        })
        .ok_or_else(|| "Missing user ID ('sub' or 'id') in userinfo response".to_string())?;

    let email = profile
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase())
        .ok_or_else(|| "Missing email in provider userinfo response".to_string())?;

    let name = profile
        .get("name")
        .or_else(|| profile.get("login"))
        .and_then(|v| v.as_str())
        .unwrap_or(&email)
        .to_string();

    let image = profile
        .get("picture")
        .or_else(|| profile.get("avatar_url"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let email_verified = profile
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(OAuthProfileResult {
        account_id,
        email,
        name,
        image,
        email_verified,
        access_token,
        refresh_token,
        id_token,
        access_token_expires_at,
        scope,
    })
}

/// Returns `true` if `url` is a native desktop loopback callback (e.g. `http://127.0.0.1:{port}/auth/callback`).
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

    // Match upstream `auth-state:{state}` identifier while supporting legacy `oauth-state:{state}`
    let primary_id = format!("auth-state:{oauth_state}");
    let legacy_id = format!("oauth-state:{oauth_state}");
    let record = match state.service.adapter().consume_verification(&primary_id).await {
        Ok(Some(r)) => r,
        _ => match state.service.adapter().consume_verification(&legacy_id).await {
            Ok(Some(r)) => r,
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(AuthErrorResponse::new("INVALID_STATE", "OAuth state not found or expired").with_status(400)),
                )
                    .into_response();
            }
        },
    };

    let state_data: serde_json::Value = serde_json::from_str(&record.value).unwrap_or_default();
    let code_verifier = state_data
        .get("codeVerifier")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let callback_url = state_data
        .get("callbackURL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let new_user_callback_url = state_data
        .get("newUserCallbackURL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let error_callback_url = state_data
        .get("errorCallbackURL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let link_user_id = state_data
        .get("linkUserId")
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

    let callback_uri = format!(
        "{}/callback/{}",
        state.service.config().base_url,
        provider.provider_id
    );

    let profile = match exchange_oauth_code_and_fetch_profile(
        provider,
        &code,
        &code_verifier,
        &callback_uri,
    )
    .await
    {
        Ok(p) => p,
        Err(err_msg) => {
            if let Some(err_cb) = error_callback_url {
                let sep = if err_cb.contains('?') { "&" } else { "?" };
                return Redirect::temporary(&format!(
                    "{err_cb}{sep}error={}",
                    urlencoding_simple(&err_msg)
                ))
                .into_response();
            }
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    AuthErrorResponse::new("FAILED_TO_GET_USER_INFO", err_msg).with_status(502),
                ),
            )
                .into_response();
        }
    };

    // Case 1: Account linking flow initiated via POST /link-social
    if let Some(target_user_id) = link_user_id {
        if let Ok(Some(existing_acc)) = state
            .service
            .adapter()
            .find_account(&provider_name, &profile.account_id)
            .await
        {
            if existing_acc.user_id != target_user_id {
                return error_to_response(auth_core::AuthError::SocialAccountAlreadyLinked);
            }
            let _ = state
                .service
                .adapter()
                .update_account_tokens(
                    &provider_name,
                    &profile.account_id,
                    Some(profile.access_token),
                    profile.refresh_token,
                    profile.id_token,
                    profile.access_token_expires_at,
                    profile.scope,
                )
                .await;
        } else {
            let _ = state
                .service
                .adapter()
                .create_account(CreateAccountInput {
                    id: None,
                    user_id: target_user_id.clone(),
                    account_id: profile.account_id,
                    provider_id: provider_name.clone(),
                    access_token: Some(profile.access_token),
                    refresh_token: profile.refresh_token,
                    id_token: profile.id_token,
                    access_token_expires_at: profile.access_token_expires_at,
                    refresh_token_expires_at: None,
                    scope: profile.scope,
                    password: None,
                })
                .await;
        }

        if let Some(target) = callback_url {
            return Redirect::temporary(&target).into_response();
        }
        return (StatusCode::OK, Json(serde_json::json!({ "status": true }))).into_response();
    }

    // Case 2: Standard sign-in / sign-up social flow
    let mut is_new_user = false;
    let user = if let Ok(Some(existing_acc)) = state
        .service
        .adapter()
        .find_account(&provider_name, &profile.account_id)
        .await
    {
        let _ = state
            .service
            .adapter()
            .update_account_tokens(
                &provider_name,
                &profile.account_id,
                Some(profile.access_token),
                profile.refresh_token,
                profile.id_token,
                profile.access_token_expires_at,
                profile.scope,
            )
            .await;

        match state
            .service
            .adapter()
            .find_user_by_id(&existing_acc.user_id)
            .await
        {
            Ok(Some(u)) => u,
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthErrorResponse::new("USER_NOT_FOUND", "Linked user not found")),
                )
                    .into_response();
            }
        }
    } else {
        let user = match state
            .service
            .adapter()
            .find_user_by_email(&profile.email)
            .await
        {
            Ok(Some(mut existing)) => {
                // Prevent implicit account takeover when provider email is not verified
                if !profile.email_verified {
                    if let Some(err_cb) = error_callback_url {
                        let sep = if err_cb.contains('?') { "&" } else { "?" };
                        return Redirect::temporary(&format!(
                            "{err_cb}{sep}error=EMAIL_NOT_VERIFIED"
                        ))
                        .into_response();
                    }
                    return error_to_response(auth_core::AuthError::EmailNotVerified);
                }

                if !existing.email_verified {
                    let _ = state
                        .service
                        .adapter()
                        .update_user_email_verified(&existing.id, true)
                        .await;
                    existing.email_verified = true;
                }
                existing
            }
            _ => {
                is_new_user = true;
                let created = state
                    .service
                    .adapter()
                    .create_user(CreateUserInput {
                        id: None,
                        name: profile.name,
                        email: profile.email.clone(),
                        image: profile.image,
                        email_verified: profile.email_verified,
                    })
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response());

                match created {
                    Ok(u) => {
                        state.service.notify_user_created(&u.to_wire()).await;
                        u
                    }
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
                account_id: profile.account_id,
                provider_id: provider_name.clone(),
                access_token: Some(profile.access_token),
                refresh_token: profile.refresh_token,
                id_token: profile.id_token,
                access_token_expires_at: profile.access_token_expires_at,
                refresh_token_expires_at: None,
                scope: profile.scope,
                password: None,
            })
            .await;

        user
    };

    // Issue session through AuthService so AuthPlugin and AuthHooks run consistently
    let session = match state
        .service
        .issue_session_for_user(&user, meta, true)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            if let Some(err_cb) = error_callback_url {
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

    let signed_token = state.service.sign_token(&session.token);

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
