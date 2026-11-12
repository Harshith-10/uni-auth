//! Admin plugin providing RBAC, user management, and impersonation.
//!
//! Provides RBAC permission checks, user management, impersonation, bans with auto-unban on expiration,
//! session revocation, and endpoint filtering for `/list-sessions`.

use std::any::Any;
use std::sync::Arc;
use time::OffsetDateTime;

use crate::access::AdminConfig;
use crate::adapter::{AuthAdapter, BoxFuture};
use crate::error::AuthError;
use crate::models::{AdminUpdateUserFields, CreateSessionInput, CreateUserInput, FieldUpdate};
use crate::plugin::{
    AuthPlugin, DatabaseHooks, EndpointHookContext, HookFuture, HookOutcome, PluginMigration,
};
use crate::service::AuthService;

pub mod service;

pub use service::{AdminService, AdminServiceExt};

/// Admin plugin providing RBAC and administrative domain operations.
#[derive(Debug, Clone, Default)]
pub struct AdminPlugin {
    pub config: AdminConfig,
}

impl AdminPlugin {
    /// Creates a new `AdminPlugin` with `config`, validating that `admin_roles` exist in `ac.roles`.
    pub fn new(config: AdminConfig) -> Result<Self, AuthError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn with_config(config: AdminConfig) -> Self {
        Self { config }
    }
}

impl DatabaseHooks for AdminPlugin {
    fn before_create_user<'a>(
        &'a self,
        mut input: CreateUserInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<CreateUserInput>> {
        let default_role = self.config.default_role.clone();
        HookFuture::boxed(Box::pin(async move {
            if input.role.is_none() {
                input.role = Some(default_role);
            }
            Ok(HookOutcome::Modified(input))
        }))
    }

    fn before_create_session<'a>(
        &'a self,
        input: CreateSessionInput,
        adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<CreateSessionInput>> {
        let user_id = input.user_id.clone();
        let banned_msg = self.config.banned_user_message.clone();

        HookFuture::boxed(Box::pin(async move {
            if let Some(user) = adapter.find_user_by_id(&user_id).await? {
                if user.banned {
                    if let Some(exp) = user.ban_expires {
                        if exp < OffsetDateTime::now_utc() {
                            // Ban has expired: auto-unban the user
                            let _ = adapter
                                .update_user_admin(
                                    &user.id,
                                    AdminUpdateUserFields {
                                        banned: Some(false),
                                        ban_reason: FieldUpdate::Clear,
                                        ban_expires: FieldUpdate::Clear,
                                        ..Default::default()
                                    },
                                )
                                .await;
                            return Ok(HookOutcome::Continue(input));
                        }
                    }
                    return Err(AuthError::BannedUser(banned_msg));
                }
            }
            Ok(HookOutcome::Continue(input))
        }))
    }
}

impl AuthPlugin for AdminPlugin {
    fn id(&self) -> &'static str {
        "admin"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
        Some(Arc::new(self.clone()))
    }

    fn matches_after(&self, path: &str) -> bool {
        path == "/list-sessions"
    }

    fn on_after_endpoint<'a>(
        &'a self,
        ctx: &'a mut EndpointHookContext,
        _service: &'a AuthService,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        // Filter out impersonated sessions from GET /list-sessions response
        if let Some(serde_json::Value::Array(ref mut sessions)) = ctx.response_body {
            sessions.retain(|s| s.get("impersonatedBy").map(|v| v.is_null()).unwrap_or(true));
        }
        Box::pin(async { Ok(()) })
    }

    fn migration(&self) -> Option<PluginMigration> {
        Some(PluginMigration {
            plugin_id: "admin",
            postgres_ddl: &[
                "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';",
                "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE;",
                "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS ban_reason TEXT;",
                "ALTER TABLE \"user\" ADD COLUMN IF NOT EXISTS ban_expires TIMESTAMPTZ;",
                "ALTER TABLE \"session\" ADD COLUMN IF NOT EXISTS impersonated_by TEXT;",
            ],
            sqlite_ddl: &[
                "ALTER TABLE \"user\" ADD COLUMN role TEXT DEFAULT 'user';",
                "ALTER TABLE \"user\" ADD COLUMN banned INTEGER DEFAULT 0;",
                "ALTER TABLE \"user\" ADD COLUMN ban_reason TEXT;",
                "ALTER TABLE \"user\" ADD COLUMN ban_expires TEXT;",
                "ALTER TABLE \"session\" ADD COLUMN impersonated_by TEXT;",
            ],
        })
    }
}
