//! OAuth2 and OpenID Connect domain models, HTTP client abstraction, and profile normalization.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
