use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use auth_core::adapter::AuthAdapter;
use auth_core::models::{
    AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput, CreateSessionInput,
    CreateUserInput, CreateVerificationInput,
};
use auth_core::{AuthConfig, AuthService};
use auth_proto::{SignInEmailRequest, SignUpEmailRequest};
use auth_sqlx::SqliteAuthAdapter;

#[tokio::test]
async fn test_sqlite_adapter_direct_crud() {
    let adapter = SqliteAuthAdapter::new_in_memory()
        .await
        .expect("In-memory SQLite should initialize");

    // 1. Create user
    let user = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Sqlite User".to_string(),
            email: "sqlite@example.com".to_string(),
            image: Some("https://example.com/pic.png".to_string()),
            email_verified: false,
            role: None,
        })
        .await
        .expect("Create user should succeed");

    assert_eq!(user.name, "Sqlite User");
    assert_eq!(user.email, "sqlite@example.com");
    assert!(!user.email_verified);
    assert_eq!(user.role.as_deref(), Some("user"));
    assert!(!user.banned);

    // 2. Find by email (case-insensitive)
    let found = adapter
        .find_user_by_email("SQLITE@EXAMPLE.COM")
        .await
        .unwrap()
        .expect("Should find user case-insensitively");
    assert_eq!(found.id, user.id);

    // 3. Duplicate email rejected
    let dup_err = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Duplicate".to_string(),
            email: "sqlite@example.com".to_string(),
            image: None,
            email_verified: false,
            role: None,
        })
        .await;
    assert!(dup_err.is_err());

    // 4. Update email verified & Admin fields
    adapter
        .update_user_email_verified(&user.id, true)
        .await
        .unwrap();
    let updated = adapter.find_user_by_id(&user.id).await.unwrap().unwrap();
    assert!(updated.email_verified);

    let admin_updated = adapter
        .update_user_admin(
            &user.id,
            AdminUpdateUserFields {
                role: Some("admin".to_string()),
                banned: Some(true),
                ban_reason: Some(Some("Testing ban".to_string())),
                ..Default::default()
            },
        )
        .await
        .expect("update_user_admin should succeed");
    assert_eq!(admin_updated.role.as_deref(), Some("admin"));
    assert!(admin_updated.banned);
    assert_eq!(admin_updated.ban_reason.as_deref(), Some("Testing ban"));

    let (listed_users, total) = adapter
        .list_users(AdminListUsersFilter {
            search_value: Some("sqlite@".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(listed_users[0].id, user.id);

    // 5. Account creation & lookup
    let account = adapter
        .create_account(CreateAccountInput {
            id: None,
            user_id: user.id.clone(),
            account_id: user.id.clone(),
            provider_id: "credential".to_string(),
            password: Some("hashed_pw_here".to_string()),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await
        .unwrap();

    assert_eq!(account.provider_id, "credential");

    let found_acc = adapter
        .find_account("credential", &user.id)
        .await
        .unwrap()
        .expect("Account should be found");
    assert_eq!(found_acc.password.as_deref(), Some("hashed_pw_here"));

    // 5B. OAuth Account token refresh update
    adapter
        .create_account(CreateAccountInput {
            id: None,
            user_id: user.id.clone(),
            account_id: "google_sub_123".to_string(),
            provider_id: "google".to_string(),
            password: None,
            access_token: Some("old_access".to_string()),
            refresh_token: Some("initial_refresh".to_string()),
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("openid,email".to_string()),
        })
        .await
        .unwrap();

    adapter
        .update_account_tokens(
            "google",
            "google_sub_123",
            Some("new_access".to_string()),
            None, // OAuth refresh_token omitted on subsequent login -> should preserve initial_refresh
            Some("new_id_tok".to_string()),
            Some(OffsetDateTime::now_utc() + Duration::hours(1)),
            Some("openid,email,profile".to_string()),
        )
        .await
        .expect("update_account_tokens should succeed");

    let refreshed_acc = adapter
        .find_account("google", "google_sub_123")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refreshed_acc.access_token.as_deref(), Some("new_access"));
    assert_eq!(
        refreshed_acc.refresh_token.as_deref(),
        Some("initial_refresh")
    );
    assert_eq!(refreshed_acc.id_token.as_deref(), Some("new_id_tok"));
    assert_eq!(
        refreshed_acc.scope.as_deref(),
        Some("openid,email,profile")
    );

    // 6. Session & Impersonated session lifecycle
    let session = adapter
        .create_session(CreateSessionInput {
            id: None,
            user_id: user.id.clone(),
            token: "sqlite_session_token_123".to_string(),
            expires_at: OffsetDateTime::now_utc() + Duration::days(7),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
        })
        .await
        .unwrap();

    let found_ses = adapter
        .find_session_by_token("sqlite_session_token_123")
        .await
        .unwrap()
        .expect("Session should be found");
    assert_eq!(found_ses.user_id, user.id);
    assert_eq!(found_ses.impersonated_by, None);

    let imp_session = adapter
        .create_impersonated_session(
            CreateSessionInput {
                id: None,
                user_id: user.id.clone(),
                token: "sqlite_imp_token_456".to_string(),
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                ip_address: Some("127.0.0.1".to_string()),
                user_agent: Some("AdminAgent/1.0".to_string()),
            },
            "admin_user_id_99".to_string(),
        )
        .await
        .unwrap();
    assert_eq!(
        imp_session.impersonated_by.as_deref(),
        Some("admin_user_id_99")
    );

    // List sessions
    let user_sessions = adapter.list_sessions_by_user_id(&user.id).await.unwrap();
    assert_eq!(user_sessions.len(), 2);

    // 7. Verification atomic consumption
    let ver = adapter
        .create_verification(CreateVerificationInput {
            id: None,
            identifier: "one-time-token:ott_xyz".to_string(),
            value: session.token.clone(),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(3),
        })
        .await
        .unwrap();
    assert_eq!(ver.value, session.token);

    // Consume once -> success
    let consumed = adapter
        .consume_verification("one-time-token:ott_xyz")
        .await
        .unwrap()
        .expect("Should consume successfully");
    assert_eq!(consumed.value, session.token);

    // Consume second time -> None
    let consumed_again = adapter
        .consume_verification("one-time-token:ott_xyz")
        .await
        .unwrap();
    assert!(consumed_again.is_none());
}

#[tokio::test]
async fn test_auth_service_with_sqlite_backend() {
    let adapter = Arc::new(
        SqliteAuthAdapter::new_in_memory()
            .await
            .expect("In-memory SQLite should initialize"),
    );

    let config = AuthConfig {
        secret: b"sqlite-test-secret-32-bytes-long-ok".to_vec(),
        base_url: "http://127.0.0.1:3000/api/auth".to_string(),
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

    let service = AuthService::new(config, adapter);

    // 1. Sign up
    let signup_res = service
        .sign_up_email(SignUpEmailRequest {
            name: "SQLite Tester".to_string(),
            email: "sqlitetester@example.com".to_string(),
            password: "supersecretpassword1".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Sign-up with SQLite should succeed");

    let token = signup_res.token.unwrap();

    // 2. Resolve session
    let session = service
        .get_session(&token)
        .await
        .unwrap()
        .expect("Session should resolve from SQLite");
    assert_eq!(session.user.email, "sqlitetester@example.com");

    // 3. Sign in
    let signin_res = service
        .sign_in_email(SignInEmailRequest {
            email: "sqlitetester@example.com".to_string(),
            password: "supersecretpassword1".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Sign-in with SQLite should succeed");

    assert!(!signin_res.token.is_empty());

    // 4. One-Time Token handoff flow
    let ott_res = service
        .generate_one_time_token(&token)
        .await
        .expect("OTT generate with SQLite should succeed");

    let verified = service
        .verify_one_time_token(&ott_res.token)
        .await
        .expect("OTT verify with SQLite should succeed");
    assert_eq!(verified.user.email, "sqlitetester@example.com");

    // Re-verification fails (burned)
    assert!(service.verify_one_time_token(&ott_res.token).await.is_err());

    // 5. Update user profile and clear image with null
    let updated = service
        .update_user(
            &signup_res.user.id,
            auth_proto::UpdateUserRequest {
                name: Some("SQLite Updated".to_string()),
                image: Some(Some("https://example.com/pic.png".to_string())),
                ..Default::default()
            },
        )
        .await
        .expect("Profile update with image should succeed");
    assert_eq!(updated.user.as_ref().unwrap().name, "SQLite Updated");
    assert_eq!(updated.user.as_ref().unwrap().image.as_deref(), Some("https://example.com/pic.png"));

    let cleared = service
        .update_user(
            &signup_res.user.id,
            auth_proto::UpdateUserRequest {
                name: None,
                image: Some(None),
                ..Default::default()
            },
        )
        .await
        .expect("Profile update with null image should succeed");
    assert_eq!(cleared.user.as_ref().unwrap().image, None);
}

#[tokio::test]
async fn test_sqlite_list_users_parameterized_query_builder() {
    let adapter = SqliteAuthAdapter::new_in_memory()
        .await
        .expect("in-memory sqlite should init");

    // Seed 5 users with varied attributes
    let u1 = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Alice Adams".to_string(),
            email: "alice@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    let u2 = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Bob Baker".to_string(),
            email: "bob@example.com".to_string(),
            image: None,
            email_verified: false,
            role: None,
        })
        .await
        .unwrap();

    let u3 = adapter
        .create_user(CreateUserInput {
            id: None,
            name: "Charlie Clark".to_string(),
            email: "charlie@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    adapter
        .update_user_admin(
            &u2.id,
            AdminUpdateUserFields {
                role: Some("admin".to_string()),
                banned: Some(true),
                ban_reason: Some(Some("Spamming".to_string())),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 1. Search name with starts_with
    let (res, total) = adapter
        .list_users(AdminListUsersFilter {
            search_field: Some("name".to_string()),
            search_value: Some("ali".to_string()),
            search_operator: Some("starts_with".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(res[0].id, u1.id);

    // 2. Filter by banned = true
    let (res, total) = adapter
        .list_users(AdminListUsersFilter {
            filter_field: Some("banned".to_string()),
            filter_value: Some("true".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(res[0].id, u2.id);

    // 3. Filter by role = admin
    let (res, total) = adapter
        .list_users(AdminListUsersFilter {
            filter_field: Some("role".to_string()),
            filter_value: Some("admin".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(res[0].id, u2.id);

    // 4. Pagination: limit 2, offset 1, sort by name ASC
    let (res, total) = adapter
        .list_users(AdminListUsersFilter {
            sort_by: Some("name".to_string()),
            sort_direction: Some("asc".to_string()),
            limit: Some(2),
            offset: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0].id, u2.id); // Bob Baker is 2nd alphabetically
    assert_eq!(res[1].id, u3.id); // Charlie Clark is 3rd alphabetically

    // 5. Delete user transaction verification
    adapter.delete_user(&u1.id).await.unwrap();
    assert!(adapter.find_user_by_id(&u1.id).await.unwrap().is_none());
}
