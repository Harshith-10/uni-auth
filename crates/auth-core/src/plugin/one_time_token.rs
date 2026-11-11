//! One-Time Token (OTT) authentication plugin matching upstream Better Auth (`packages/better-auth/src/plugins/one-time-token/index.ts`).
//!
//! Supports browser-to-desktop handoff with single-use atomic consumption, optional SHA-256 token hashing,
//! configurable expiration, and automatic `set-ott` header issuance on new sessions.

use sha2::{Digest, Sha256};
use std::any::Any;
use time::{Duration, OffsetDateTime};

use auth_proto::{OneTimeTokenGenerateResponse, SessionAndUserResponse};

use crate::adapter::{AuthAdapter, BoxFuture};
use crate::crypto;
use crate::error::AuthError;
use crate::models::CreateVerificationInput;
use crate::plugin::{BetterAuthPlugin, EndpointHookContext};
use crate::service::AuthService;

/// Storage hashing mode for OTT tokens in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OttStoreTokenMode {
    #[default]
    Plain,
    HashedSha256,
}

/// Configuration options for the One-Time Token plugin.
#[derive(Debug, Clone)]
pub struct OneTimeTokenConfig {
    /// Token lifetime (upstream default: 3 minutes).
    pub expires_in: Duration,
    /// Whether client-initiated requests to `/one-time-token/generate` are rejected with 400 Bad Request.
    pub disable_client_request: bool,
    /// Whether setting the session cookie on verification is disabled.
    pub disable_set_session_cookie: bool,
    /// Database storage format for the token identifier (`Plain` or `HashedSha256`).
    pub store_token: OttStoreTokenMode,
    /// Whether the `set-ott` header is automatically issued on new sessions.
    pub set_ott_header_on_new_session: bool,
}

impl Default for OneTimeTokenConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::minutes(3),
            disable_client_request: false,
            disable_set_session_cookie: false,
            store_token: OttStoreTokenMode::Plain,
            set_ott_header_on_new_session: false,
        }
    }
}

/// One-Time Token authentication plugin.
#[derive(Debug, Clone, Default)]
pub struct OneTimeTokenPlugin {
    pub config: OneTimeTokenConfig,
}

impl OneTimeTokenPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: OneTimeTokenConfig) -> Self {
        Self { config }
    }

    pub fn hash_token(&self, token: &str) -> String {
        match self.config.store_token {
            OttStoreTokenMode::Plain => token.to_string(),
            OttStoreTokenMode::HashedSha256 => {
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                format!("{:x}", hasher.finalize())
            }
        }
    }

    /// Generates a single-use OTT linked to `session_token`.
    pub async fn generate_token(
        &self,
        session_token: &str,
        adapter: &dyn AuthAdapter,
    ) -> Result<OneTimeTokenGenerateResponse, AuthError> {
        let token = crypto::generate_random_token(32);
        let stored = self.hash_token(&token);
        let expires_at = OffsetDateTime::now_utc() + self.config.expires_in;

        adapter
            .create_verification(CreateVerificationInput {
                id: None,
                identifier: format!("one-time-token:{stored}"),
                value: session_token.to_string(),
                expires_at,
            })
            .await?;

        Ok(OneTimeTokenGenerateResponse { token })
    }

    /// Atomically burns and verifies an OTT, returning the authenticated session and user.
    pub async fn verify_token(
        &self,
        token: &str,
        adapter: &dyn AuthAdapter,
    ) -> Result<SessionAndUserResponse, AuthError> {
        let stored = self.hash_token(token);
        let identifier = format!("one-time-token:{stored}");

        // Atomic consume prevents replay attacks
        let verification = adapter
            .consume_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if verification.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        let session = adapter
            .find_session_by_token(&verification.value)
            .await?
            .ok_or(AuthError::SessionExpired)?;

        if session.is_expired() {
            return Err(AuthError::SessionExpired);
        }

        let user = adapter
            .find_user_by_id(&session.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok(SessionAndUserResponse {
            session: session.to_wire(),
            user: user.to_wire(),
        })
    }
}

impl BetterAuthPlugin for OneTimeTokenPlugin {
    fn id(&self) -> &'static str {
        "one-time-token"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn matches_after(&self, _path: &str) -> bool {
        self.config.set_ott_header_on_new_session
    }

    fn on_after_endpoint<'a>(
        &'a self,
        ctx: &'a mut EndpointHookContext,
        service: &'a AuthService,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        let Some((ref session, _)) = ctx.new_session else {
            return Box::pin(async { Ok(()) });
        };

        let session_token = session.token.clone();
        let plugin = self.clone();
        let adapter = service.adapter().clone();

        Box::pin(async move {
            let res = plugin.generate_token(&session_token, &*adapter).await?;

            ctx.response_headers
                .insert("set-ott".to_string(), res.token);

            let expose = ctx
                .response_headers
                .entry("access-control-expose-headers".to_string())
                .or_default();
            if !expose.contains("set-ott") {
                if !expose.is_empty() {
                    expose.push_str(", ");
                }
                expose.push_str("set-ott");
            }

            Ok(())
        })
    }
}

/// Extension trait providing access to `OneTimeTokenPlugin` on `AuthService`.
pub trait OneTimeTokenServiceExt {
    fn one_time_token(&self) -> Option<&OneTimeTokenPlugin>;
}

impl OneTimeTokenServiceExt for AuthService {
    fn one_time_token(&self) -> Option<&OneTimeTokenPlugin> {
        self.get_plugin::<OneTimeTokenPlugin>()
    }
}
