//! Modular plugin architecture for uni-auth.
//!
//! Provides first-class database lifecycle hooks (`DatabaseHooks`), endpoint hooks (`EndpointHookContext`),
//! declarative migrations (`PluginMigration`), rate limiting rules (`PluginRateLimitRule`), and typed
//! plugin downcasting.

use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use uni_auth_proto::{SessionWire, UserWire};

use crate::adapter::{AuthAdapter, BoxFuture};
use crate::error::AuthError;
use crate::models::{
    CreateSessionInput, CreateUserInput, SessionRecord, UpdateUserFields, UserRecord,
};

/// Allocation-free hook future that avoids heap allocations on no-op default hooks.
pub enum HookFuture<'a, T> {
    Ready(Option<Result<T, AuthError>>),
    Boxed(BoxFuture<'a, Result<T, AuthError>>),
}

impl<'a, T> HookFuture<'a, T> {
    #[inline]
    pub fn ready_ok(val: T) -> Self {
        Self::Ready(Some(Ok(val)))
    }

    #[inline]
    pub fn ready_err(err: AuthError) -> Self {
        Self::Ready(Some(Err(err)))
    }

    #[inline]
    pub fn boxed(fut: BoxFuture<'a, Result<T, AuthError>>) -> Self {
        Self::Boxed(fut)
    }
}

impl<'a, T: Unpin> Future for HookFuture<'a, T> {
    type Output = Result<T, AuthError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::into_inner(self) {
            HookFuture::Ready(val) => {
                Poll::Ready(val.take().expect("HookFuture polled after completion"))
            }
            HookFuture::Boxed(fut) => fut.as_mut().poll(cx),
        }
    }
}

impl<'a, T> From<BoxFuture<'a, Result<T, AuthError>>> for HookFuture<'a, T> {
    fn from(fut: BoxFuture<'a, Result<T, AuthError>>) -> Self {
        Self::Boxed(fut)
    }
}

/// Trait for plugins that declare HTTP routes without requiring hardcoded downcasting.
pub trait PluginRouteProvider: Send + Sync {
    /// Unique plugin identifier.
    fn route_plugin_id(&self) -> &'static str;

    /// Builds the plugin router for the given application state (passed as `&dyn Any`).
    fn build_router_any(&self, state_any: &dyn Any) -> Option<Box<dyn Any>>;
}

pub mod admin;
pub mod bearer;
pub mod hooked_adapter;
pub mod one_time_token;
pub mod registry;
pub mod totp;

pub use admin::{AdminPlugin, AdminService, AdminServiceExt};
pub use bearer::{BearerConfig, BearerPlugin};
pub use hooked_adapter::HookedAdapter;
pub use one_time_token::{
    OneTimeTokenConfig, OneTimeTokenPlugin, OneTimeTokenServiceExt, OttStoreTokenMode,
};
pub use registry::PluginRegistry;
pub use totp::TotpValidator;

/// Outcome of a `before` database hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookOutcome<T> {
    /// Proceed with the current value unchanged.
    Continue(T),
    /// Proceed with a modified value (e.g., Admin plugin injecting `default_role`).
    Modified(T),
    /// Abort the database operation without throwing an error (`return false` in TS).
    Cancel,
}

impl<T> HookOutcome<T> {
    pub fn into_value(self) -> Option<T> {
        match self {
            Self::Continue(val) | Self::Modified(val) => Some(val),
            Self::Cancel => None,
        }
    }
}

/// Dynamic user update payload passed to `before_update_user` database hooks.
/// Unified with `UpdateUserFields` to avoid fragmented update representations.
pub type UserUpdatePatch = UpdateUserFields;

/// Database lifecycle hooks executed before and after database mutations.
pub trait DatabaseHooks: Send + Sync {
    // ── User Hooks ──

    fn before_create_user<'a>(
        &'a self,
        input: CreateUserInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<CreateUserInput>> {
        HookFuture::ready_ok(HookOutcome::Continue(input))
    }

    fn after_create_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        HookFuture::ready_ok(())
    }

    fn before_update_user<'a>(
        &'a self,
        _user_id: &'a str,
        patch: UpdateUserFields,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<UpdateUserFields>> {
        HookFuture::ready_ok(HookOutcome::Continue(patch))
    }

    fn after_update_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        HookFuture::ready_ok(())
    }

    fn before_delete_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, bool> {
        HookFuture::ready_ok(true)
    }

    fn after_delete_user<'a>(
        &'a self,
        _user_id: &'a str,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        HookFuture::ready_ok(())
    }

    // ── Session Hooks ──

    fn before_create_session<'a>(
        &'a self,
        input: CreateSessionInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<CreateSessionInput>> {
        HookFuture::ready_ok(HookOutcome::Continue(input))
    }

    fn after_create_session<'a>(
        &'a self,
        _session: &'a SessionRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        HookFuture::ready_ok(())
    }

    fn before_delete_session<'a>(
        &'a self,
        _token: &'a str,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, bool> {
        HookFuture::ready_ok(true)
    }

    fn after_delete_session<'a>(
        &'a self,
        _token: &'a str,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        HookFuture::ready_ok(())
    }
}

/// Context passed to plugin `before_endpoint` and `after_endpoint` hooks.
#[derive(Debug, Clone, Default)]
pub struct EndpointHookContext {
    /// Normalized endpoint path relative to `/api/auth` (e.g., `"/list-sessions"`, `"/sign-in/email"`).
    pub path: String,
    pub method: String,
    pub request_headers: http::HeaderMap,
    pub response_headers: http::HeaderMap,
    /// JSON response body (populated in `after_endpoint` hooks so plugins can filter/transform JSON).
    pub response_body: Option<serde_json::Value>,
    /// Populated when a new session was just created during this request.
    pub new_session: Option<(SessionRecord, UserRecord)>,
}

/// Declarative database schema migration contributed by a plugin.
#[derive(Debug, Clone, Default)]
pub struct PluginMigration {
    pub plugin_id: &'static str,
    pub postgres_ddl: &'static [&'static str],
    pub sqlite_ddl: &'static [&'static str],
}

/// Per-plugin rate limit rule.
#[derive(Clone)]
pub struct PluginRateLimitRule {
    pub id: &'static str,
    pub window: std::time::Duration,
    pub max_requests: usize,
    pub path_matcher: fn(&str) -> bool,
}

/// Unified server-side plugin trait for uni-auth extensions.
pub trait AuthPlugin: Send + Sync + 'static {
    /// Unique plugin identifier (e.g., `"admin"`, `"one-time-token"`, `"bearer"`, `"two-factor"`).
    fn id(&self) -> &'static str;

    /// Downcast helper so extension traits (`service.get_plugin::<AdminPlugin>()`) can access typed plugin state.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Optional database lifecycle hooks (`user`, `session`, `account`, `verification`).
    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
        None
    }

    /// Optional generic route provider for declaring Axum routes.
    fn route_provider(&self) -> Option<Arc<dyn PluginRouteProvider>> {
        None
    }

    /// Optional `before` endpoint hook (runs when `matches_before(path)` is true).
    fn matches_before(&self, _path: &str) -> bool {
        false
    }

    fn on_before_endpoint<'a>(
        &'a self,
        _ctx: &'a mut EndpointHookContext,
        _service: &'a crate::service::AuthService,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    /// Optional `after` endpoint hook (runs when `matches_after(path)` is true).
    fn matches_after(&self, _path: &str) -> bool {
        false
    }

    fn on_after_endpoint<'a>(
        &'a self,
        _ctx: &'a mut EndpointHookContext,
        _service: &'a crate::service::AuthService,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    /// Optional SQL DDL migrations required by this plugin.
    fn migration(&self) -> Option<PluginMigration> {
        None
    }

    /// Optional path-based rate-limit rules.
    fn rate_limits(&self) -> Vec<PluginRateLimitRule> {
        Vec::new()
    }
}

/// Backward compatibility alias for `AuthPlugin`.
pub use AuthPlugin as BetterAuthPlugin;

/// Object-safe legacy plugin trait for hooking into `AuthService` authentication flows.
#[deprecated(note = "Implement AuthPlugin and DatabaseHooks instead")]
pub trait LegacyAuthPlugin: Send + Sync {
    /// Unique plugin identifier (e.g. `"two-factor"`, `"api-key"`, `"organization"`).
    fn id(&self) -> &'static str;

    /// Invoked before an email sign-in completes. Returning `Err(AuthError)` aborts sign-in.
    fn on_before_sign_in(&self, _user: &UserWire) -> BoxFuture<'static, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    /// Invoked after a session is issued.
    fn on_after_session_issued(
        &self,
        _session: &SessionWire,
        _user: &UserWire,
    ) -> BoxFuture<'static, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }
}
