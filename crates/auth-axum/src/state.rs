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
