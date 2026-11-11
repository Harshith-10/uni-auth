//! Shared state for the Axum Better Auth router.

use std::collections::HashMap;
use std::sync::Arc;
use auth_core::AuthService;

pub use auth_core::{OAuthHttpClient, OAuthProviderConfig, ReqwestOAuthClient};

/// Shared application state injected into Axum auth routes.
#[derive(Clone)]
pub struct AuthState {
    pub service: Arc<AuthService>,
    pub cookie_name: String,
    pub secure_cookies: bool,
    pub same_site: String,
    pub oauth_providers: Arc<HashMap<String, OAuthProviderConfig>>,
    pub oauth_http_client: Arc<dyn OAuthHttpClient>,
    pub trusted_origins: Arc<Vec<String>>,
    pub axum_plugins: Arc<Vec<Arc<dyn crate::plugin::AxumAuthPlugin>>>,
}

impl AuthState {
    pub fn new(service: Arc<AuthService>) -> Self {
        Self {
            service,
            cookie_name: "better-auth.session_token".to_string(),
            secure_cookies: false, // Default false for local dev / tests, can be toggled
            same_site: "Lax".to_string(),
            oauth_providers: Arc::new(HashMap::new()),
            oauth_http_client: Arc::new(ReqwestOAuthClient::new()),
            trusted_origins: Arc::new(Vec::new()),
            axum_plugins: Arc::new(Vec::new()),
        }
    }

    pub fn with_plugin(mut self, plugin: Arc<dyn crate::plugin::AxumAuthPlugin>) -> Self {
        let mut plugins = (*self.axum_plugins).clone();
        plugins.push(plugin);
        self.axum_plugins = Arc::new(plugins);
        self
    }

    pub fn with_oauth_http_client(mut self, client: Arc<dyn OAuthHttpClient>) -> Self {
        self.oauth_http_client = client;
        self
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

    /// Configures trusted origins for CSRF `Origin` header validation on mutation endpoints.
    pub fn with_trusted_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.trusted_origins = Arc::new(origins.into_iter().map(Into::into).collect());
        self
    }

    /// Attaches the signed session cookie (and `set-auth-token` header) to an outgoing Response.
    pub fn attach_session_cookie(
        &self,
        response: &mut axum::response::Response,
        raw_token: &str,
        remember_me: bool,
        custom_duration: Option<time::Duration>,
    ) {
        let signed = self.service.sign_cookie_token(raw_token);
        let max_age = if remember_me {
            Some(
                custom_duration
                    .unwrap_or_else(|| self.service.config().session_expires_in)
                    .whole_seconds(),
            )
        } else {
            None
        };
        let cookie = crate::cookies::build_session_cookie_with_options(
            &self.cookie_name,
            &signed,
            max_age,
            self.secure_cookies,
            &self.same_site,
        );
        if let Ok(val) = cookie.parse() {
            response.headers_mut().append(axum::http::header::SET_COOKIE, val);
        }
        if let Ok(val) = signed.parse() {
            response.headers_mut().insert("set-auth-token", val);
        }
    }

    /// Attaches the cleared session cookie to an outgoing Response.
    pub fn clear_session_cookie(&self, response: &mut axum::response::Response) {
        let clear = crate::cookies::build_clear_session_cookie(
            &self.cookie_name,
            self.secure_cookies,
            &self.same_site,
        );
        if let Ok(val) = clear.parse() {
            response.headers_mut().append(axum::http::header::SET_COOKIE, val);
        }
    }
}
