use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use auth_core::adapter::AuthAdapter;
use auth_core::models::{
    CreateAccountInput, CreateSessionInput, CreateUserInput, CreateVerificationInput,
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
        })
        .await
        .expect("Create user should succeed");

    assert_eq!(user.name, "Sqlite User");
    assert_eq!(user.email, "sqlite@example.com");
    assert!(!user.email_verified);

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
        })
        .await;
    assert!(dup_err.is_err());

    // 4. Update email verified
    adapter
        .update_user_email_verified(&user.id, true)
        .await
        .unwrap();
    let updated = adapter.find_user_by_id(&user.id).await.unwrap().unwrap();
    assert!(updated.email_verified);

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

    // 6. Session lifecycle
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

    // List sessions
    let user_sessions = adapter.list_sessions_by_user_id(&user.id).await.unwrap();
    assert_eq!(user_sessions.len(), 1);

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
}
