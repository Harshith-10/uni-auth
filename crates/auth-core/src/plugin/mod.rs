//! Modular plugin architecture modeled directly on `@better-auth/core` (`packages/core/src/types/plugin.ts`).
//!
//! Provides first-class database lifecycle hooks (`DatabaseHooks`), endpoint hooks (`EndpointHookContext`),
//! declarative migrations (`PluginMigration`), rate limiting rules (`PluginRateLimitRule`), and typed
//! plugin downcasting.

use std::sync::Arc;

use auth_proto::{SessionWire, UserWire};

use crate::adapter::{AuthAdapter, BoxFuture};
use crate::error::AuthError;
use crate::models::{
    CreateSessionInput, CreateUserInput, SessionRecord, UpdateUserFields, UserRecord,
};

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

/// Outcome of a `before` database hook (`packages/better-auth/src/db/with-hooks.ts:56-65`).
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

/// Database lifecycle hooks matching `BetterAuthOptions["databaseHooks"]`.
pub trait DatabaseHooks: Send + Sync {
    // ── User Hooks ──

    fn before_create_user<'a>(
        &'a self,
        input: CreateUserInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<HookOutcome<CreateUserInput>, AuthError>> {
        Box::pin(async move { Ok(HookOutcome::Continue(input)) })
    }

    fn after_create_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    fn before_update_user<'a>(
        &'a self,
        _user_id: &'a str,
        patch: UpdateUserFields,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<HookOutcome<UpdateUserFields>, AuthError>> {
        Box::pin(async move { Ok(HookOutcome::Continue(patch)) })
    }

    fn after_update_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    fn before_delete_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        Box::pin(async { Ok(true) })
    }

    fn after_delete_user<'a>(
        &'a self,
        _user_id: &'a str,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    // ── Session Hooks ──

    fn before_create_session<'a>(
        &'a self,
        input: CreateSessionInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<HookOutcome<CreateSessionInput>, AuthError>> {
        Box::pin(async move { Ok(HookOutcome::Continue(input)) })
    }

    fn after_create_session<'a>(
        &'a self,
        _session: &'a SessionRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }

    fn before_delete_session<'a>(
        &'a self,
        _token: &'a str,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        Box::pin(async { Ok(true) })
    }

    fn after_delete_session<'a>(
        &'a self,
        _token: &'a str,
        _adapter: &'a dyn AuthAdapter,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Context passed to plugin `before_endpoint` and `after_endpoint` hooks.
#[derive(Debug, Clone, Default)]
pub struct EndpointHookContext {
    /// Normalized endpoint path relative to `/api/auth` (e.g., `"/list-sessions"`, `"/sign-in/email"`).
    pub path: String,
    pub method: String,
    pub request_headers: std::collections::HashMap<String, String>,
    pub response_headers: std::collections::HashMap<String, String>,
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

/// Per-plugin rate limit rule (`packages/core/src/types/plugin.ts:150-156`).
#[derive(Clone)]
pub struct PluginRateLimitRule {
    pub id: &'static str,
    pub window: std::time::Duration,
    pub max_requests: usize,
    pub path_matcher: fn(&str) -> bool,
}

/// Unified server-side plugin trait matching `@better-auth/core`'s `BetterAuthPlugin`.
pub trait BetterAuthPlugin: Send + Sync + 'static {
    /// Unique plugin identifier (e.g., `"admin"`, `"one-time-token"`, `"bearer"`, `"two-factor"`).
    fn id(&self) -> &'static str;

    /// Downcast helper so extension traits (`service.get_plugin::<AdminPlugin>()`) can access typed plugin state.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Optional database lifecycle hooks (`user`, `session`, `account`, `verification`).
    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
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

/// Object-safe legacy plugin trait for hooking into `AuthService` authentication flows.
#[deprecated(note = "Implement BetterAuthPlugin and DatabaseHooks instead")]
pub trait AuthPlugin: Send + Sync {
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
