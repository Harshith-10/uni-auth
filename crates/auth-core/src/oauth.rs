//! OAuth2 and OpenID Connect domain models, HTTP client abstraction, and profile normalization.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::adapter::BoxFuture;

/// Configuration for social OAuth providers (e.g., GitHub, Google).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OAuthProviderConfig {
    pub provider_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<String>,
}

impl OAuthProviderConfig {
    /// Standard GitHub OAuth2 configuration preset.
    pub fn github(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            provider_id: "github".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: "https://api.github.com/user".to_string(),
            scopes: vec!["read:user".to_string(), "user:email".to_string()],
        }
    }

    /// Standard Google OpenID Connect / OAuth2 configuration preset.
    pub fn google(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            provider_id: "google".to_string(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        }
    }
}

/// Normalized profile and tokens returned by an OAuth provider.
#[derive(Debug, Clone)]
pub struct OAuthProfileResult {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub image: Option<String>,
    pub email_verified: bool,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
}

/// Serialized payload stored in verification table during OAuth initiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthStateData {
    pub code_verifier: String,
    pub callback_url: Option<String>,
    pub new_user_callback_url: Option<String>,
    pub error_callback_url: Option<String>,
    pub link_user_id: Option<String>,
}

/// Trait abstracting OAuth2 code exchange and userinfo profile retrieval.
pub trait OAuthHttpClient: Send + Sync {
    fn exchange_code_and_fetch_profile<'a>(
        &'a self,
        provider: &'a OAuthProviderConfig,
        code: &'a str,
        code_verifier: &'a str,
        redirect_uri: &'a str,
    ) -> BoxFuture<'a, Result<OAuthProfileResult, String>>;
}

/// Production implementation of `OAuthHttpClient` using connection-pooled `reqwest::Client`.
#[derive(Clone)]
pub struct ReqwestOAuthClient {
    client: reqwest::Client,
}

impl Default for ReqwestOAuthClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestOAuthClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl OAuthHttpClient for ReqwestOAuthClient {
    fn exchange_code_and_fetch_profile<'a>(
        &'a self,
        provider: &'a OAuthProviderConfig,
        code: &'a str,
        code_verifier: &'a str,
        redirect_uri: &'a str,
    ) -> BoxFuture<'a, Result<OAuthProfileResult, String>> {
        Box::pin(async move {
            // Allow deterministic mock/simulated mode when token_url starts with "mock://" or in local test fixtures
            if provider.token_url.starts_with("mock://") || provider.token_url.contains("127.0.0.1:0") {
                let unverified = provider.token_url.contains("unverified") || code.contains("unverified");
                let suffix = if let Some(rest) = code.strip_prefix("fixed_") {
                    rest.to_lowercase()
                } else {
                    crate::crypto::generate_random_token(6).to_lowercase()
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

            let token_res = self
                .client
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

            let user_res = self
                .client
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
        })
    }
}
