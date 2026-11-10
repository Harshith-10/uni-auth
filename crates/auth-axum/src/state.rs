//! Shared state for the Axum Better Auth router.

use std::collections::HashMap;
use std::sync::Arc;
use auth_core::AuthService;

/// Configuration for social OAuth providers (e.g., GitHub, Google).
#[derive(Clone, Debug)]
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

/// Shared application state injected into Axum auth routes.
#[derive(Clone)]
pub struct AuthState {
    pub service: Arc<AuthService>,
    pub cookie_name: String,
    pub secure_cookies: bool,
    pub same_site: String,
    pub oauth_providers: Arc<HashMap<String, OAuthProviderConfig>>,
}

impl AuthState {
    pub fn new(service: Arc<AuthService>) -> Self {
        Self {
            service,
            cookie_name: "better-auth.session_token".to_string(),
            secure_cookies: false, // Default false for local dev / tests, can be toggled
            same_site: "Lax".to_string(),
            oauth_providers: Arc::new(HashMap::new()),
        }
    }

    pub fn with_secure_cookies(mut self, secure: bool) -> Self {
        self.secure_cookies = secure;
        if secure {
            self.cookie_name = "__Secure-better-auth.session_token".to_string();
        }
        self
    }

    pub fn with_oauth_provider(mut self, config: OAuthProviderConfig) -> Self {
        let mut providers = (*self.oauth_providers).clone();
        providers.insert(config.provider_id.clone(), config);
        self.oauth_providers = Arc::new(providers);
        self
    }
}
