//! Integration tests for Better Auth server plugin ecosystem, database hooks, and plugin downcasting.

use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use auth_core::adapter::{AuthAdapter, BoxFuture};
use auth_core::error::AuthError;
use auth_core::models::*;
use auth_core::plugin::{
    BetterAuthPlugin, DatabaseHooks, HookOutcome, PluginMigration, PluginRateLimitRule,
    UserUpdatePatch,
};
use auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};

// ──────────────────────────────────────────────
// Test Database Hook Implementation
// ──────────────────────────────────────────────

#[derive(Default)]
struct CustomHooks {
    created_users: Arc<AtomicUsize>,
    created_sessions: Arc<AtomicUsize>,
    cancel_create_user: Arc<AtomicBool>,
    reject_session_with_banned: Arc<AtomicBool>,
    override_role_on_create: Arc<AtomicBool>,
    prevent_delete_user: Arc<AtomicBool>,
}

impl DatabaseHooks for CustomHooks {
    fn before_create_user(
        &self,
        mut input: CreateUserInput,
        _adapter: &dyn AuthAdapter,
    ) -> BoxFuture<'static, Result<HookOutcome<CreateUserInput>, AuthError>> {
        let cancel = self.cancel_create_user.load(Ordering::SeqCst);
        let override_role = self.override_role_on_create.load(Ordering::SeqCst);
        Box::pin(async move {
            if cancel {
                return Ok(HookOutcome::Cancel);
            }
            if override_role {
                input.role = Some("superadmin".to_string());
                return Ok(HookOutcome::Modified(input));
            }
            Ok(HookOutcome::Continue(input))
        })
    }

    fn after_create_user(
        &self,
        _user: &UserRecord,
        _adapter: &dyn AuthAdapter,
    ) -> BoxFuture<'static, Result<(), AuthError>> {
        self.created_users.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn before_create_session(
        &self,
        input: CreateSessionInput,
        _adapter: &dyn AuthAdapter,
    ) -> BoxFuture<'static, Result<HookOutcome<CreateSessionInput>, AuthError>> {
        let reject = self.reject_session_with_banned.load(Ordering::SeqCst);
        Box::pin(async move {
            if reject {
                return Err(AuthError::forbidden("BANNED_USER", "User is banned from issuing sessions"));
            }
            Ok(HookOutcome::Continue(input))
        })
    }

    fn after_create_session(
        &self,
        _session: &SessionRecord,
        _adapter: &dyn AuthAdapter,
    ) -> BoxFuture<'static, Result<(), AuthError>> {
        self.created_sessions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn before_delete_user(
        &self,
        _user: &UserRecord,
        _adapter: &dyn AuthAdapter,
    ) -> BoxFuture<'static, Result<bool, AuthError>> {
        let prevent = self.prevent_delete_user.load(Ordering::SeqCst);
        Box::pin(async move { Ok(!prevent) })
    }

    fn before_update_user(
        &self,
        _user_id: &str,
        patch: UserUpdatePatch,
        _adapter: &dyn AuthAdapter,
    ) -> BoxFuture<'static, Result<HookOutcome<UserUpdatePatch>, AuthError>> {
        Box::pin(async move {
            match patch {
                UserUpdatePatch::Profile { name: _, image } => {
                    Ok(HookOutcome::Modified(UserUpdatePatch::Profile {
                        name: Some("Overridden Name".to_string()),
                        image,
                    }))
                }
                other => Ok(HookOutcome::Continue(other)),
            }
        })
    }
}

// ──────────────────────────────────────────────
// Test BetterAuthPlugin Implementation
// ──────────────────────────────────────────────

struct SamplePlugin {
    plugin_id: &'static str,
    secret_key: String,
    hooks: Arc<CustomHooks>,
}

impl BetterAuthPlugin for SamplePlugin {
    fn id(&self) -> &'static str {
        self.plugin_id
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn database_hooks(&self) -> Option<Arc<dyn DatabaseHooks>> {
        Some(self.hooks.clone())
    }

    fn migration(&self) -> Option<PluginMigration> {
        Some(PluginMigration {
            plugin_id: "sample-plugin",
            postgres_ddl: &["CREATE TABLE sample_plugin_data (id TEXT PRIMARY KEY);"],
            sqlite_ddl: &["CREATE TABLE sample_plugin_data (id TEXT PRIMARY KEY);"],
        })
    }

    fn rate_limits(&self) -> Vec<PluginRateLimitRule> {
        vec![PluginRateLimitRule {
            id: "sample_limit",
            window: std::time::Duration::from_secs(60),
            max_requests: 10,
            path_matcher: |p| p.starts_with("/sample"),
        }]
    }
}

fn create_test_service_with_plugin(hooks: Arc<CustomHooks>) -> (AuthService, SamplePlugin) {
    let config = AuthConfig {
        secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        base_url: "http://localhost:3000/api/auth".to_string(),
        session_expires_in: time::Duration::days(7),
        verify_email_expires_in: time::Duration::hours(1),
        reset_password_expires_in: time::Duration::hours(1),
        ott_expires_in: time::Duration::minutes(3),
        require_email_verification: false,
        auto_sign_in: true,
        delete_user_enabled: true,
        defer_session_refresh: true,
        min_password_length: 8,
        max_password_length: 128,
    };
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let plugin = SamplePlugin {
        plugin_id: "sample-plugin",
        secret_key: "top-secret-val".to_string(),
        hooks,
    };
    let service = AuthService::new(config, adapter).with_plugin_arc(Arc::new(SamplePlugin {
        plugin_id: plugin.plugin_id,
        secret_key: plugin.secret_key.clone(),
        hooks: plugin.hooks.clone(),
    }));
    (service, plugin)
}

#[tokio::test]
async fn test_database_hooks_user_creation_and_role_override() {
    let hooks = Arc::new(CustomHooks::default());
    hooks.override_role_on_create.store(true, Ordering::SeqCst);
    let (service, _) = create_test_service_with_plugin(hooks.clone());

    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "Hook User".to_string(),
            email: "hook_user@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .expect("User creation should succeed");

    // Assert that before_create_user modified the role to "superadmin"
    assert_eq!(user.role.as_deref(), Some("superadmin"));
    // Assert after_create_user counter incremented
    assert_eq!(hooks.created_users.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_database_hooks_user_creation_cancel() {
    let hooks = Arc::new(CustomHooks::default());
    hooks.cancel_create_user.store(true, Ordering::SeqCst);
    let (service, _) = create_test_service_with_plugin(hooks.clone());

    let res = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "Cancelled User".to_string(),
            email: "cancelled@example.com".to_string(),
            image: None,
            email_verified: false,
            role: None,
        })
        .await;

    assert!(res.is_err());
    let err = res.err().unwrap();
    // AdapterError::Auth should unbox to AuthError::Forbidden
    let auth_err = AuthError::from(err);
    assert_eq!(auth_err.http_status(), 403);
    assert_eq!(auth_err.error_code(), "HOOK_CANCELLED");
    assert_eq!(hooks.created_users.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_database_hooks_session_creation_rejection() {
    let hooks = Arc::new(CustomHooks::default());
    let (service, _) = create_test_service_with_plugin(hooks.clone());

    // Create a user normally first
    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "Session Test".to_string(),
            email: "session_test@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    // Now enable session rejection in hooks
    hooks.reject_session_with_banned.store(true, Ordering::SeqCst);

    let session_res = service
        .adapter()
        .create_session(CreateSessionInput {
            id: None,
            user_id: user.id.clone(),
            token: "test_token_123".to_string(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::days(1),
            ip_address: None,
            user_agent: None,
        })
        .await;

    assert!(session_res.is_err());
    let err = session_res.err().unwrap();
    let auth_err = AuthError::from(err);
    assert_eq!(auth_err.http_status(), 403);
    assert_eq!(auth_err.error_code(), "BANNED_USER");
    assert_eq!(hooks.created_sessions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_database_hooks_prevent_delete_user() {
    let hooks = Arc::new(CustomHooks::default());
    let (service, _) = create_test_service_with_plugin(hooks.clone());

    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "Delete Test".to_string(),
            email: "delete_test@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    // Set prevent delete to true
    hooks.prevent_delete_user.store(true, Ordering::SeqCst);
    service.adapter().delete_user(&user.id).await.unwrap();

    // User should still exist because before_delete_user cancelled deletion
    let still_exists = service.adapter().find_user_by_id(&user.id).await.unwrap();
    assert!(still_exists.is_some());

    // Now allow deletion
    hooks.prevent_delete_user.store(false, Ordering::SeqCst);
    service.adapter().delete_user(&user.id).await.unwrap();
    let gone = service.adapter().find_user_by_id(&user.id).await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
async fn test_database_hooks_update_user_override() {
    let hooks = Arc::new(CustomHooks::default());
    let (service, _) = create_test_service_with_plugin(hooks);

    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "Initial Name".to_string(),
            email: "initial@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    let updated = service
        .adapter()
        .update_user_profile(&user.id, Some("Requested Name".to_string()), None)
        .await
        .unwrap();

    assert_eq!(updated.name, "Overridden Name");
}

#[test]
fn test_plugin_downcasting_and_metadata() {
    let hooks = Arc::new(CustomHooks::default());
    let (service, _) = create_test_service_with_plugin(hooks);

    // Retrieve typed plugin via downcasting
    let plugin = service.get_plugin::<SamplePlugin>();
    assert!(plugin.is_some());
    let plugin = plugin.unwrap();
    assert_eq!(plugin.id(), "sample-plugin");
    assert_eq!(plugin.secret_key, "top-secret-val");

    // Check migrations and rate limits collected
    let migrations = service.plugins().migrations();
    assert_eq!(migrations.len(), 1);
    assert_eq!(migrations[0].plugin_id, "sample-plugin");

    let rate_limits = service.plugins().rate_limits();
    assert_eq!(rate_limits.len(), 1);
    assert_eq!(rate_limits[0].id, "sample_limit");
    assert!((rate_limits[0].path_matcher)("/sample/action"));
    assert!(!(rate_limits[0].path_matcher)("/other"));
}
