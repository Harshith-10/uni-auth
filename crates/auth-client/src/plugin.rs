//! Client plugin architecture modeled on `@better-auth/client` (`packages/core/src/types/plugin-client.ts`).
//!
//! Enables modular extensions, request/response interceptors, and reactive `$sessionSignal` listeners.

use std::any::Any;

use crate::client::ClientError;
use crate::transport::{ClientRequestContext, ClientResponseContext};

/// Reactive session signal name triggering automatic state refreshes across client stores and UI subscribers.
pub const SESSION_SIGNAL: &str = "$sessionSignal";

/// Reactive atom/signal listener rule (`packages/core/src/types/plugin-client.ts:31-35`).
#[derive(Clone)]
pub struct ClientSignalListener {
    pub signal: &'static str,
    pub matcher: fn(&str) -> bool,
}

/// Client-side plugin trait for extending `BetterAuthNativeClient`.
pub trait AuthClientPlugin: Send + Sync + 'static {
    /// Unique client plugin ID (e.g. `"admin-client"`, `"one-time-token-client"`).
    fn id(&self) -> &'static str;

    /// Downcasting helper for typed plugin access.
    fn as_any(&self) -> &dyn Any;

    /// Intercepts outgoing requests (e.g., attaching custom headers).
    fn on_request(&self, _ctx: &mut ClientRequestContext) -> Result<(), ClientError> {
        Ok(())
    }

    /// Intercepts incoming responses (e.g., capturing plugin-specific token headers).
    fn on_response(&self, _ctx: &ClientResponseContext) -> Result<(), ClientError> {
        Ok(())
    }

    /// Declares endpoint paths that should trigger a reactive signal (such as `$sessionSignal`).
    fn signal_listeners(&self) -> Vec<ClientSignalListener> {
        Vec::new()
    }
}

/// Matches core session-mutating endpoint paths (`packages/better-auth/src/client/config.ts:42-55`).
pub fn matches_core_session_signal(path: &str) -> bool {
    matches!(
        path,
        "/sign-out"
            | "/update-user"
            | "/update-session"
            | "/sign-up/email"
            | "/sign-in/email"
            | "/delete-user"
            | "/verify-email"
            | "/revoke-sessions"
            | "/revoke-session"
            | "/revoke-other-sessions"
            | "/change-email"
            | "/change-password"
            | "/one-time-token/verify"
    )
}
