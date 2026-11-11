//! Bearer authentication plugin matching upstream Better Auth (`packages/better-auth/src/plugins/bearer/index.ts`).
//!
//! Converts `Authorization: Bearer <token>` requests into session authentication cookies,
//! and automatically mirrors outgoing session `Set-Cookie` headers into `set-auth-token` headers.

use std::any::Any;

use crate::adapter::BoxFuture;
use crate::crypto;
use crate::error::AuthError;
use crate::plugin::{BetterAuthPlugin, EndpointHookContext};
use crate::service::AuthService;

/// Configuration options for the Bearer plugin.
#[derive(Debug, Clone, Default)]
pub struct BearerConfig {
    /// If true, only pre-signed tokens (`token.signature`) will be accepted as session credentials.
    ///
    /// Parity with upstream `BearerOptions.requireSignature` (default: `false`).
    pub require_signature: bool,
}

/// Bearer authentication plugin.
#[derive(Debug, Clone, Default)]
pub struct BearerPlugin {
    pub config: BearerConfig,
}

impl BearerPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_require_signature(mut self, require_signature: bool) -> Self {
        self.config.require_signature = require_signature;
        self
    }
}

impl BetterAuthPlugin for BearerPlugin {
    fn id(&self) -> &'static str {
        "bearer"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn matches_before(&self, _path: &str) -> bool {
        true
    }

    fn on_before_endpoint<'a>(
        &'a self,
        ctx: &'a mut EndpointHookContext,
        service: &'a AuthService,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        let auth_header = ctx.request_headers.get("authorization").cloned();
        let require_signature = self.config.require_signature;
        let secret = service.config().secret.clone();

        Box::pin(async move {
            let Some(auth_str) = auth_header else {
                return Ok(());
            };

            let trimmed = auth_str.trim();
            if trimmed.len() <= 7 || !trimmed[..7].eq_ignore_ascii_case("bearer ") {
                return Ok(());
            }

            let token = trimmed[7..].trim();
            if token.is_empty() {
                return Ok(());
            }

            let decoded_token = if token.contains('.') {
                if token.contains('%') {
                    auth_proto::url_decode(token)
                } else {
                    token.to_string()
                }
            } else {
                if require_signature {
                    return Ok(());
                }
                crypto::sign_cookie_better_call(&secret, token)
            };

            // Verify signature
            if let Some((raw, sig)) = decoded_token.split_once('.') {
                if !crypto::verify_signature(&secret, raw, sig) {
                    return Ok(());
                }
            } else {
                return Ok(());
            }

            // Inject into cookie header
            let cookie_name = "better-auth.session_token";
            let new_cookie = format!("{cookie_name}={decoded_token}");
            if let Some(existing) = ctx.request_headers.get_mut("cookie") {
                if !existing.contains(cookie_name) {
                    existing.push_str("; ");
                    existing.push_str(&new_cookie);
                }
            } else {
                ctx.request_headers.insert("cookie".to_string(), new_cookie);
            }

            Ok(())
        })
    }

    fn matches_after(&self, _path: &str) -> bool {
        true
    }

    fn on_after_endpoint<'a>(
        &'a self,
        ctx: &'a mut EndpointHookContext,
        _service: &'a AuthService,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        // Look for session cookie in response headers
        if let Some(set_cookie) = ctx.response_headers.get("set-cookie").cloned() {
            if let Some(token) = extract_session_token_from_set_cookie(&set_cookie) {
                ctx.response_headers
                    .insert("set-auth-token".to_string(), token);

                let expose = ctx
                    .response_headers
                    .entry("access-control-expose-headers".to_string())
                    .or_default();
                if !expose.contains("set-auth-token") {
                    if !expose.is_empty() {
                        expose.push_str(", ");
                    }
                    expose.push_str("set-auth-token");
                }
            }
        }
        Box::pin(async { Ok(()) })
    }
}

fn extract_session_token_from_set_cookie(set_cookie: &str) -> Option<String> {
    if set_cookie.contains("Max-Age=0") || set_cookie.contains("expires=Thu, 01 Jan 1970") {
        return None;
    }
    for part in set_cookie.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("better-auth.session_token=") {
            return Some(rest.to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("__Secure-better-auth.session_token=") {
            return Some(rest.to_string());
        }
    }
    None
}
