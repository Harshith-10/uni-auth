//! Client plugin architecture for modular extensions, request/response interceptors, and reactive session signals.

use std::any::Any;

use auth_proto::{SessionWire, UserWire};

use crate::client::ClientError;
use crate::transport::{ClientRequestContext, ClientResponseContext};

/// Reactive session signal name triggering automatic state refreshes across client stores and UI subscribers.
pub const SESSION_SIGNAL: &str = "$sessionSignal";

/// Session mutation events emitted over the client's reactive signal system.
#[derive(Debug, Clone)]
pub enum SessionSignalEvent {
    /// Session was explicitly established or replaced (e.g. impersonate-user, stop-impersonating, one-time-token/verify)
    SessionUpdated {
        user: UserWire,
        session: SessionWire,
    },
    /// User profile was updated in-place (e.g. /update-user)
    UserUpdated(UserWire),
    /// Session was cleared (e.g. /sign-out, /delete-user)
    SignedOut,
    /// Session state changed and should be refreshed from server (e.g. /sign-in/email, /revoke-sessions)
    NeedsRefresh,
}

/// Reactive atom/signal listener rule.
#[derive(Clone)]
pub struct ClientSignalListener {
    pub signal: &'static str,
    pub matcher: fn(&str) -> bool,
}

/// Client-side plugin trait for extending `AuthClient`.
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

/// Matches core session-mutating endpoint paths.
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
