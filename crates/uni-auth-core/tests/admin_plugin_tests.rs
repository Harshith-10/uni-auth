//! Unit and integration tests for `AdminPlugin`, RBAC `Connector::And` / `Connector::Or`,
//! `AdminServiceExt`, database ban auto-unban hooks, and impersonation protection.

use std::collections::HashMap;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use uni_auth_core::AuthAdapter;
use uni_auth_core::access::{AdminConfig, Connector, RolePermissions};
use uni_auth_core::adapter::InMemoryAuthAdapter;
use uni_auth_core::error::AuthError;
use uni_auth_core::models::{
    AdminUpdateUserFields, CreateSessionInput, CreateUserInput, FieldUpdate, RequestMeta,
};
use uni_auth_core::plugin::admin::{AdminPlugin, AdminServiceExt};
use uni_auth_core::plugin::{AuthPlugin, EndpointHookContext};
use uni_auth_core::service::{AuthConfig, AuthService};
use uni_auth_proto::{AdminBanUserRequest, AdminHasPermissionRequest, AdminSetRoleRequest, RoleValue};

fn setup_test_service() -> (Arc<AuthService>, Arc<InMemoryAuthAdapter>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"test-secret-key-for-admin-plugin-tests".to_vec(),
        base_url: "http://localhost:3000/api/auth".to_string(),
        session_expires_in: Duration::days(7),
        ott_expires_in: Duration::minutes(3),
        reset_password_expires_in: Duration::hours(1),
        verify_email_expires_in: Duration::hours(24),
        auto_sign_in: true,
        require_email_verification: false,
        min_password_length: 8,
        max_password_length: 128,
        delete_user_enabled: true,
        defer_session_refresh: false,
    };
    let service = Arc::new(AuthService::new(config, adapter.clone()));
    (service, adapter)
}

#[tokio::test]
async fn test_admin_config_validation() {
    let bad_config = AdminConfig {
        admin_roles: vec!["superadmin".to_string()],
        ..Default::default()
    };
    // "superadmin" is not in default ac.roles ("admin", "user")
    let err = AdminPlugin::new(bad_config);
    assert!(err.is_err());
    if let Err(AuthError::Internal(msg)) = err {
        assert!(msg.contains("superadmin"));
    } else {
        panic!("Expected Internal error with missing role message");
    }

    let good_config = AdminConfig {
        admin_roles: vec!["admin".to_string()],
        ..Default::default()
    };
    assert!(AdminPlugin::new(good_config).is_ok());
}

#[test]
fn test_rbac_and_or_connectors() {
    let perms = RolePermissions::new().with_resource("user", ["get", "list"]);

    let mut requested = HashMap::new();
    requested.insert(
        "user".to_string(),
        vec!["get".to_string(), "delete".to_string()],
    );

    // AND connector: requires ALL requested actions ("get" AND "delete") -> false
    assert!(!perms.authorize_with_connector(&requested, Connector::And));

    // OR connector: requires ANY requested action ("get" OR "delete") -> true
    assert!(perms.authorize_with_connector(&requested, Connector::Or));

    // Non-existent resource with OR connector -> false
    let mut other_req = HashMap::new();
    other_req.insert("billing".to_string(), vec!["charge".to_string()]);
    assert!(!perms.authorize_with_connector(&other_req, Connector::Or));
}

#[test]
fn test_admin_has_permission_with_connector() {
    let config = AdminConfig::default();

    // Admin role has "delete" on "user", but does not have "fly_to_moon"
    let mut requested = HashMap::new();
    requested.insert(
        "user".to_string(),
        vec!["delete".to_string(), "fly_to_moon".to_string()],
    );

    // AND -> false (admin cannot fly to moon)
    assert!(!config.has_permission_map_with_connector(
        None,
        Some("admin"),
        &requested,
        Connector::And
    ));

    // OR -> true (admin can delete)
    assert!(config.has_permission_map_with_connector(
        None,
        Some("admin"),
        &requested,
        Connector::Or
    ));
}

#[tokio::test]
async fn test_admin_service_ext_operations() {
    let (service, adapter) = setup_test_service();

    // 1. service.admin() downcasting succeeds
    let admin_svc = service
        .admin()
        .expect("AdminPlugin should be registered by default");

    // Create an admin actor and a regular user
    let admin_user = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Super Admin".to_string(),
            email: "admin@corp.com".to_string(),
            image: None,
            email_verified: true,
            role: Some("admin".to_string()),
        })
        .await
        .unwrap();

    let target_user = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Jane Doe".to_string(),
            email: "jane@corp.com".to_string(),
            image: None,
            email_verified: false,
            role: Some("user".to_string()),
        })
        .await
        .unwrap();

    let admin_actor = admin_user.to_wire();

    // 2. admin.set_role
    let set_res = admin_svc
        .set_role(
            &admin_actor,
            AdminSetRoleRequest {
                user_id: target_user.id.clone(),
                role: RoleValue::Single("admin".to_string()),
            },
        )
        .await
        .unwrap();
    assert_eq!(set_res.user.role.as_deref(), Some("admin"));

    // 3. admin.ban_user and unban_user
    let ban_res = admin_svc
        .ban_user(
            &admin_actor,
            AdminBanUserRequest {
                user_id: target_user.id.clone(),
                ban_reason: Some("Violated terms".to_string()),
                ban_expires_in: Some(3600),
            },
        )
        .await
        .unwrap();
    assert_eq!(ban_res.user.banned, Some(true));

    let unban_res = admin_svc
        .unban_user(&admin_actor, &target_user.id)
        .await
        .unwrap();
    assert_eq!(unban_res.user.banned, Some(false));

    // 4. admin.has_permission with connector
    let mut check_perms = HashMap::new();
    check_perms.insert(
        "user".to_string(),
        vec!["ban".to_string(), "delete".to_string()],
    );

    let perm_resp = admin_svc
        .has_permission(
            Some(&admin_actor),
            AdminHasPermissionRequest {
                user_id: Some(admin_actor.id.clone()),
                role: None,
                permissions: Some(check_perms),
                permission: None,
                connector: Some("OR".to_string()),
            },
        )
        .await
        .unwrap();
    assert!(perm_resp.success);
}

#[tokio::test]
async fn test_database_hook_auto_unban_on_expired_ban() {
    let (service, adapter) = setup_test_service();

    // Create a banned user whose ban has expired 1 hour ago
    let past_exp = OffsetDateTime::now_utc() - Duration::hours(1);
    let user = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Expired Banned User".to_string(),
            email: "expired-ban@example.com".to_string(),
            image: None,
            email_verified: true,
            role: Some("user".to_string()),
        })
        .await
        .unwrap();

    adapter
        .update_user_admin(
            &user.id,
            AdminUpdateUserFields {
                banned: Some(true),
                ban_reason: FieldUpdate::Set("Temporary suspension".to_string()),
                ban_expires: FieldUpdate::Set(past_exp),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Issue session via service - should auto-unban and succeed!
    let session_result = service
        .adapter()
        .create_session(CreateSessionInput {
            id: None,
            user_id: user.id.clone(),
            token: "test-token-123".to_string(),
            expires_at: OffsetDateTime::now_utc() + Duration::days(1),
            ip_address: None,
            user_agent: None,
        })
        .await;

    assert!(
        session_result.is_ok(),
        "Session creation should succeed after auto-unban"
    );

    // Verify user in adapter is no longer banned
    let reloaded = adapter.find_user_by_id(&user.id).await.unwrap().unwrap();
    assert!(!reloaded.banned, "User should be unbanned in database");
    assert!(reloaded.ban_expires.is_none());
}

#[tokio::test]
async fn test_impersonate_admin_protection() {
    let (service, adapter) = setup_test_service();
    let admin_svc = service.admin().unwrap();

    // Create an admin user and another admin user
    let admin_1 = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Admin One".to_string(),
            email: "admin1@test.com".to_string(),
            image: None,
            email_verified: true,
            role: Some("admin".to_string()),
        })
        .await
        .unwrap();

    let admin_2 = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Admin Two".to_string(),
            email: "admin2@test.com".to_string(),
            image: None,
            email_verified: true,
            role: Some("admin".to_string()),
        })
        .await
        .unwrap();

    // Admin 1 attempts to impersonate Admin 2 without "impersonate-admins" permission
    let res = admin_svc
        .impersonate_user(&admin_1.to_wire(), &admin_2.id, RequestMeta::default())
        .await;

    assert!(res.is_err());
    if let Err(AuthError::Forbidden { code, .. }) = res {
        assert_eq!(code, "YOU_CANNOT_IMPERSONATE_ADMINS");
    } else {
        panic!("Expected YOU_CANNOT_IMPERSONATE_ADMINS error");
    }
}

#[tokio::test]
async fn test_list_sessions_after_endpoint_hook_filters_impersonation() {
    let plugin = AdminPlugin::default();

    let mut ctx = EndpointHookContext {
        path: "/list-sessions".to_string(),
        method: "GET".to_string(),
        response_body: Some(serde_json::json!([
            { "id": "s1", "userId": "u1", "impersonatedBy": null },
            { "id": "s2", "userId": "u1", "impersonatedBy": "admin_u9" },
            { "id": "s3", "userId": "u1" }
        ])),
        ..Default::default()
    };

    let (service, _) = setup_test_service();
    plugin.on_after_endpoint(&mut ctx, &service).await.unwrap();

    let body = ctx.response_body.unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], "s1");
    assert_eq!(arr[1]["id"], "s3");
}
