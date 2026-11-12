//! Integration tests for server plugin ecosystem, database hooks, and plugin downcasting.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use uni_auth_core::adapter::AuthAdapter;
use uni_auth_core::error::AuthError;
use uni_auth_core::models::*;
use uni_auth_core::plugin::{
    AuthPlugin, DatabaseHooks, EndpointHookContext, HookFuture, HookOutcome, PluginMigration,
    PluginRateLimitRule, UserUpdatePatch,
};
use uni_auth_core::{
    AuthConfig, AuthService, BearerConfig, BearerPlugin, InMemoryAuthAdapter, OneTimeTokenConfig,
    OneTimeTokenPlugin, OttStoreTokenMode,
};

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
    fn before_create_user<'a>(
        &'a self,
        mut input: CreateUserInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<CreateUserInput>> {
        let cancel = self.cancel_create_user.load(Ordering::SeqCst);
        let override_role = self.override_role_on_create.load(Ordering::SeqCst);
        HookFuture::boxed(Box::pin(async move {
            if cancel {
                return Ok(HookOutcome::Cancel);
            }
            if override_role {
                input.role = Some("superadmin".to_string());
                return Ok(HookOutcome::Modified(input));
            }
            Ok(HookOutcome::Continue(input))
        }))
    }

    fn after_create_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        self.created_users.fetch_add(1, Ordering::SeqCst);
        HookFuture::ready_ok(())
    }

    fn before_create_session<'a>(
        &'a self,
        input: CreateSessionInput,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<CreateSessionInput>> {
        let reject = self.reject_session_with_banned.load(Ordering::SeqCst);
        HookFuture::boxed(Box::pin(async move {
            if reject {
                return Err(AuthError::forbidden(
                    "BANNED_USER",
                    "User is banned from issuing sessions",
                ));
            }
            Ok(HookOutcome::Continue(input))
        }))
    }

    fn after_create_session<'a>(
        &'a self,
        _session: &'a SessionRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, ()> {
        self.created_sessions.fetch_add(1, Ordering::SeqCst);
        HookFuture::ready_ok(())
    }

    fn before_delete_user<'a>(
        &'a self,
        _user: &'a UserRecord,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, bool> {
        let prevent = self.prevent_delete_user.load(Ordering::SeqCst);
        HookFuture::ready_ok(!prevent)
    }

    fn before_update_user<'a>(
        &'a self,
        _user_id: &'a str,
        mut patch: UserUpdatePatch,
        _adapter: &'a dyn AuthAdapter,
    ) -> HookFuture<'a, HookOutcome<UserUpdatePatch>> {
        HookFuture::boxed(Box::pin(async move {
            if patch.name.is_some() {
                patch.name = Some("Overridden Name".to_string());
                Ok(HookOutcome::Modified(patch))
            } else {
                Ok(HookOutcome::Continue(patch))
            }
        }))
    }
}

// ──────────────────────────────────────────────
// Test AuthPlugin Implementation
// ──────────────────────────────────────────────

struct SamplePlugin {
    plugin_id: &'static str,
    secret_key: String,
    hooks: Arc<CustomHooks>,
}

impl AuthPlugin for SamplePlugin {
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
    hooks
        .reject_session_with_banned
        .store(true, Ordering::SeqCst);

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
    let cancel_res = service.adapter().delete_user(&user.id).await;
    assert!(cancel_res.is_err());
    let auth_err = AuthError::from(cancel_res.err().unwrap());
    assert_eq!(auth_err.error_code(), "HOOK_CANCELLED");

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
    assert!(migrations.iter().any(|m| m.plugin_id == "sample-plugin"));

    let rate_limits = service.plugins().rate_limits();
    assert_eq!(rate_limits.len(), 1);
    assert_eq!(rate_limits[0].id, "sample_limit");
    assert!((rate_limits[0].path_matcher)("/sample/action"));
    assert!(!(rate_limits[0].path_matcher)("/other"));
}

#[tokio::test]
async fn test_bearer_plugin_before_and_after_endpoint() {
    let hooks = Arc::new(CustomHooks::default());
    let (mut service, _) = create_test_service_with_plugin(hooks);
    let bearer = BearerPlugin::new();
    service = service.with_plugin(bearer);

    // 1. Before endpoint hook: convert Bearer token to cookie header
    let raw_token = "raw_sample_session_token_12345";
    let mut req_headers = http::HeaderMap::new();
    req_headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {raw_token}").parse().unwrap(),
    );
    let mut ctx = EndpointHookContext {
        path: "/api/saas/me".to_string(),
        method: "GET".to_string(),
        request_headers: req_headers,
        response_headers: Default::default(),
        response_body: None,
        new_session: None,
    };

    service
        .plugins()
        .run_before_endpoint(&mut ctx, &service)
        .await
        .unwrap();

    let cookie_val = ctx.request_headers.get(http::header::COOKIE);
    assert!(cookie_val.is_some());
    let cookie = cookie_val.unwrap().to_str().unwrap();
    assert!(cookie.contains("better-auth.session_token="));
    assert!(cookie.contains(raw_token));

    // 2. Strict mode: with require_signature, unsigned token is not converted
    let strict_bearer = BearerPlugin {
        config: BearerConfig {
            require_signature: true,
        },
    };
    let mut strict_headers = http::HeaderMap::new();
    strict_headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {raw_token}").parse().unwrap(),
    );
    let mut strict_ctx = EndpointHookContext {
        path: "/api/saas/me".to_string(),
        method: "GET".to_string(),
        request_headers: strict_headers,
        response_headers: Default::default(),
        response_body: None,
        new_session: None,
    };
    strict_bearer
        .on_before_endpoint(&mut strict_ctx, &service)
        .await
        .unwrap();
    assert!(strict_ctx.request_headers.get(http::header::COOKIE).is_none());

    // 3. After endpoint hook: Set-Cookie in response emits set-auth-token and exposes header
    let mut after_headers = http::HeaderMap::new();
    after_headers.insert(
        http::header::SET_COOKIE,
        format!("better-auth.session_token={raw_token}; Path=/; HttpOnly")
            .parse()
            .unwrap(),
    );
    let mut after_ctx = EndpointHookContext {
        path: "/sign-in/email".to_string(),
        method: "POST".to_string(),
        request_headers: Default::default(),
        response_headers: after_headers,
        response_body: None,
        new_session: None,
    };
    service
        .plugins()
        .run_after_endpoint(&mut after_ctx, &service)
        .await
        .unwrap();

    assert_eq!(
        after_ctx
            .response_headers
            .get("set-auth-token")
            .unwrap()
            .to_str()
            .unwrap(),
        raw_token
    );
    assert!(
        after_ctx
            .response_headers
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("set-auth-token")
    );

    // 4. Cleared cookie (Max-Age=0) must NOT emit set-auth-token
    let mut clear_headers = http::HeaderMap::new();
    clear_headers.insert(
        http::header::SET_COOKIE,
        "better-auth.session_token=; Max-Age=0; Path=/"
            .parse()
            .unwrap(),
    );
    let mut clear_ctx = EndpointHookContext {
        path: "/sign-out".to_string(),
        method: "POST".to_string(),
        request_headers: Default::default(),
        response_headers: clear_headers,
        response_body: None,
        new_session: None,
    };
    service
        .plugins()
        .run_after_endpoint(&mut clear_ctx, &service)
        .await
        .unwrap();
    assert!(!clear_ctx.response_headers.contains_key("set-auth-token"));
}

#[tokio::test]
async fn test_one_time_token_plugin_atomic_consumption_and_hashing() {
    let hooks = Arc::new(CustomHooks::default());
    let (mut service, _) = create_test_service_with_plugin(hooks);

    // Test with HashedSha256 storage mode
    let ott_plugin = OneTimeTokenPlugin {
        config: OneTimeTokenConfig {
            expires_in: time::Duration::minutes(3),
            disable_client_request: false,
            disable_set_session_cookie: false,
            store_token: OttStoreTokenMode::HashedSha256,
            set_ott_header_on_new_session: true,
        },
    };
    service = service.with_plugin(ott_plugin.clone());

    // Create user and session
    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "OTT Test".to_string(),
            email: "ott_test@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    let session = service
        .adapter()
        .create_session(CreateSessionInput {
            id: None,
            user_id: user.id.clone(),
            token: "active_session_token_xyz".to_string(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::days(1),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    // 1. Generate OTT
    let ott_res = ott_plugin
        .generate_token(&session.token, service.adapter().as_ref())
        .await
        .unwrap();
    assert!(!ott_res.token.is_empty());

    // 2. Verify and atomically burn
    let verified = ott_plugin
        .verify_token(&ott_res.token, service.adapter().as_ref())
        .await
        .unwrap();
    assert_eq!(verified.session.token, session.token);
    assert_eq!(verified.user.id, user.id);

    // 3. Second redemption MUST fail (atomic burn)
    let re_verify = ott_plugin
        .verify_token(&ott_res.token, service.adapter().as_ref())
        .await;
    assert!(re_verify.is_err());
    assert_eq!(re_verify.err().unwrap().error_code(), "INVALID_TOKEN");

    // 4. Hook on new session emits set-ott header
    let mut session_ctx = EndpointHookContext {
        path: "/sign-in/email".to_string(),
        method: "POST".to_string(),
        request_headers: Default::default(),
        response_headers: Default::default(),
        response_body: None,
        new_session: Some((session, user)),
    };

    service
        .plugins()
        .run_after_endpoint(&mut session_ctx, &service)
        .await
        .unwrap();

    let ott_header = session_ctx.response_headers.get("set-ott");
    assert!(ott_header.is_some());
    assert!(
        session_ctx
            .response_headers
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("set-ott")
    );
}

#[test]
fn test_plugin_registry_replace_by_id_and_removal() {
    use uni_auth_core::plugin::PluginRegistry;

    struct DummyPlugin {
        id: &'static str,
        val: i32,
    }
    impl AuthPlugin for DummyPlugin {
        fn id(&self) -> &'static str {
            self.id
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let mut reg = PluginRegistry::new();
    assert_eq!(reg.plugins().len(), 0);

    reg.register(Arc::new(DummyPlugin {
        id: "dummy",
        val: 1,
    }));
    assert_eq!(reg.plugins().len(), 1);
    assert!(reg.has("dummy"));
    assert_eq!(
        reg.plugins()
            .iter()
            .find(|p| p.id() == "dummy")
            .unwrap()
            .as_any()
            .downcast_ref::<DummyPlugin>()
            .unwrap()
            .val,
        1
    );

    // Re-registering with the same id should replace in-place
    reg.register(Arc::new(DummyPlugin {
        id: "dummy",
        val: 2,
    }));
    assert_eq!(reg.plugins().len(), 1);
    assert_eq!(
        reg.plugins()
            .iter()
            .find(|p| p.id() == "dummy")
            .unwrap()
            .as_any()
            .downcast_ref::<DummyPlugin>()
            .unwrap()
            .val,
        2
    );

    // Register another plugin
    reg.register(Arc::new(DummyPlugin {
        id: "other",
        val: 10,
    }));
    assert_eq!(reg.plugins().len(), 2);
    assert!(reg.has("other"));

    // Remove by ID
    assert!(reg.remove("dummy"));
    assert_eq!(reg.plugins().len(), 1);
    assert!(!reg.has("dummy"));
    assert!(reg.has("other"));
}

#[tokio::test]
async fn test_totp_validator_plugin_registration() {
    use uni_auth_core::plugin::TotpValidator;

    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"01234567890123456789012345678901".to_vec(),
        base_url: "http://localhost:3000/api/auth".to_string(),
        session_expires_in: time::Duration::days(7),
        ott_expires_in: time::Duration::minutes(3),
        reset_password_expires_in: time::Duration::hours(1),
        verify_email_expires_in: time::Duration::hours(24),
        auto_sign_in: true,
        require_email_verification: false,
        min_password_length: 8,
        max_password_length: 128,
        delete_user_enabled: true,
        defer_session_refresh: false,
    };

    let totp = TotpValidator::default();
    let service = AuthService::new(config, adapter).with_plugin(totp);

    let retrieved = service.get_plugin::<TotpValidator>();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id(), "two-factor");
}

#[tokio::test]
async fn test_unified_update_user_adapter_and_hooks() {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let user = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Original Name".to_string(),
            email: "orig@example.com".to_string(),
            email_verified: false,
            image: None,
            role: Some("user".to_string()),
        })
        .await
        .unwrap();

    let patch = UpdateUserFields {
        name: Some("Updated Name".to_string()),
        email: None,
        image: FieldUpdate::Set("https://avatar.com/1.png".to_string()),
        email_verified: Some(true),
        role: Some("admin".to_string()),
        banned: Some(true),
        ban_reason: FieldUpdate::Set("spamming".to_string()),
        ban_expires: FieldUpdate::Unchanged,
    };

    let updated = adapter.update_user(&user.id, patch).await.unwrap();
    assert_eq!(updated.name, "Updated Name");
    assert_eq!(updated.image.as_deref(), Some("https://avatar.com/1.png"));
    assert!(updated.email_verified);
    assert_eq!(updated.role.as_deref(), Some("admin"));
    assert!(updated.banned);
    assert_eq!(updated.ban_reason.as_deref(), Some("spamming"));
}
