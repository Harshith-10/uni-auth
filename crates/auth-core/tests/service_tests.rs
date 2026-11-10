use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use auth_core::crypto::hash_scrypt_better_auth;
use auth_core::models::{AdminUpdateUserFields, CreateAccountInput, CreateUserInput, RequestMeta};
use auth_core::{
    AuthConfig, AuthError, AuthService, EmailSender, InMemoryAuthAdapter, MockEmailSender,
    SlidingWindowRateLimiter, TotpValidator,
};
use auth_proto::{
    AdminBanUserRequest, AdminCreateUserRequest, AdminListUsersQuery, AdminSetRoleRequest,
    AdminSetUserPasswordRequest, ChangePasswordRequest, DeleteUserRequest,
    RequestPasswordResetRequest, ResetPasswordRequest, RoleValue, SignInEmailRequest,
    SignUpEmailRequest, UpdateUserRequest,
};

fn create_test_service() -> (AuthService, Arc<MockEmailSender>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let email_sender = Arc::new(MockEmailSender::new());
    let config = AuthConfig {
        secret: b"test-secret-key-for-unit-tests-only-32b".to_vec(),
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

    let sender_trait: Arc<dyn EmailSender> = email_sender.clone();
    let service = AuthService::new(config, adapter).with_email_sender(sender_trait);
    (service, email_sender)
}

#[tokio::test]
async fn test_sign_up_and_sign_in_flow() {
    let (service, _) = create_test_service();

    // 1. Sign up
    let signup_res = service
        .sign_up_email(SignUpEmailRequest {
            name: "Alice Wonderland".to_string(),
            email: "alice@example.com".to_string(),
            password: "correcthorsebatterystaple".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Sign-up should succeed");

    assert!(signup_res.token.is_some());
    assert_eq!(signup_res.user.email, "alice@example.com");
    assert_eq!(signup_res.user.name, "Alice Wonderland");
    assert_eq!(signup_res.user.role.as_deref(), Some("user"));

    let signup_token = signup_res.token.unwrap();

    // 2. Get session using the token from sign-up
    let session = service
        .get_session(&signup_token)
        .await
        .unwrap()
        .expect("Session should be valid");

    assert_eq!(session.user.email, "alice@example.com");

    // 3. Sign in with same credentials
    let signin_res = service
        .sign_in_email(SignInEmailRequest {
            email: "alice@example.com".to_string(),
            password: "correcthorsebatterystaple".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Sign-in should succeed");

    assert!(!signin_res.token.is_empty());
    assert_eq!(signin_res.user.id, signup_res.user.id);
}

#[tokio::test]
async fn test_duplicate_email_rejection() {
    let (service, _) = create_test_service();

    service
        .sign_up_email(SignUpEmailRequest {
            name: "Bob".to_string(),
            email: "bob@example.com".to_string(),
            password: "password123".to_string(),
            image: None,
            callback_url: None,
            remember_me: None,
        })
        .await
        .unwrap();

    // Try signing up with same email in different casing
    let err = service
        .sign_up_email(SignUpEmailRequest {
            name: "Bob Duplicate".to_string(),
            email: "BOB@example.com".to_string(),
            password: "differentpassword123".to_string(),
            image: None,
            callback_url: None,
            remember_me: None,
        })
        .await
        .unwrap_err();

    assert_eq!(
        err.error_code(),
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
    );
}

#[tokio::test]
async fn test_invalid_password_rejection() {
    let (service, _) = create_test_service();

    service
        .sign_up_email(SignUpEmailRequest {
            name: "Charlie".to_string(),
            email: "charlie@example.com".to_string(),
            password: "correctpassword1".to_string(),
            image: None,
            callback_url: None,
            remember_me: None,
        })
        .await
        .unwrap();

    let err = service
        .sign_in_email(SignInEmailRequest {
            email: "charlie@example.com".to_string(),
            password: "wrongpassword".to_string(),
            callback_url: None,
            remember_me: None,
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "INVALID_EMAIL_OR_PASSWORD");
}

#[tokio::test]
async fn test_password_length_validation() {
    let (service, _) = create_test_service();

    let err = service
        .sign_up_email(SignUpEmailRequest {
            name: "Dave".to_string(),
            email: "dave@example.com".to_string(),
            password: "short".to_string(), // < 8 chars
            image: None,
            callback_url: None,
            remember_me: None,
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), "PASSWORD_TOO_SHORT");
}

#[tokio::test]
async fn test_password_reset_revokes_all_active_sessions() {
    let (service, mock_email) = create_test_service();

    // Sign up
    let user_res = service
        .sign_up_email(SignUpEmailRequest {
            name: "Eve".to_string(),
            email: "eve@example.com".to_string(),
            password: "originalpassword1".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let session_token_1 = user_res.token.unwrap();

    // Create a second session via sign-in
    let signin_res = service
        .sign_in_email(SignInEmailRequest {
            email: "eve@example.com".to_string(),
            password: "originalpassword1".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let session_token_2 = signin_res.token;

    // Verify both sessions exist
    assert!(service.get_session(&session_token_1).await.unwrap().is_some());
    assert!(service.get_session(&session_token_2).await.unwrap().is_some());

    // Request password reset
    let reset_msg = service
        .request_password_reset(RequestPasswordResetRequest {
            email: "eve@example.com".to_string(),
            redirect_to: None,
        })
        .await
        .unwrap();
    assert!(reset_msg.status);

    // Extract token from mock email
    let sent_resets = mock_email.sent_password_resets.lock().unwrap();
    assert_eq!(sent_resets.len(), 1);
    let reset_token = sent_resets[0].2.clone();
    drop(sent_resets);

    // Reset password
    service
        .reset_password(ResetPasswordRequest {
            token: Some(reset_token.clone()),
            new_password: "newsecretpassword2".to_string(),
        })
        .await
        .unwrap();

    // Re-using the token fails (single-use)
    assert!(service
        .reset_password(ResetPasswordRequest {
            token: Some(reset_token),
            new_password: "anotherpassword3".to_string(),
        })
        .await
        .is_err());

    // Both previous sessions must now be revoked!
    assert!(service.get_session(&session_token_1).await.unwrap().is_none());
    assert!(service.get_session(&session_token_2).await.unwrap().is_none());

    // Old password no longer works
    assert!(service
        .sign_in_email(SignInEmailRequest {
            email: "eve@example.com".to_string(),
            password: "originalpassword1".to_string(),
            callback_url: None,
            remember_me: None,
        })
        .await
        .is_err());

    // New password works
    let new_signin = service
        .sign_in_email(SignInEmailRequest {
            email: "eve@example.com".to_string(),
            password: "newsecretpassword2".to_string(),
            callback_url: None,
            remember_me: None,
        })
        .await
        .unwrap();
    assert!(!new_signin.token.is_empty());
}

#[tokio::test]
async fn test_one_time_token_single_use_consumption() {
    let (service, _) = create_test_service();

    let signup = service
        .sign_up_email(SignUpEmailRequest {
            name: "Frank".to_string(),
            email: "frank@example.com".to_string(),
            password: "securepassword123".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let session_token = signup.token.unwrap();

    // Generate OTT
    let ott_res = service
        .generate_one_time_token(&session_token)
        .await
        .expect("OTT generation should succeed");

    assert!(!ott_res.token.is_empty());

    // First verification succeeds and resolves to Frank's session
    let verified = service
        .verify_one_time_token(&ott_res.token)
        .await
        .expect("First OTT verification should succeed");

    assert_eq!(verified.user.email, "frank@example.com");

    // Second verification MUST fail (burned)
    let second_attempt = service.verify_one_time_token(&ott_res.token).await;
    assert!(second_attempt.is_err());
}

#[tokio::test]
async fn test_session_revocation_methods() {
    let (service, _) = create_test_service();

    let user_res = service
        .sign_up_email(SignUpEmailRequest {
            name: "Grace".to_string(),
            email: "grace@example.com".to_string(),
            password: "password12345".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let t1 = user_res.token.unwrap();

    let signin2 = service
        .sign_in_email(SignInEmailRequest {
            email: "grace@example.com".to_string(),
            password: "password12345".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();
    let t2 = signin2.token;

    let signin3 = service
        .sign_in_email(SignInEmailRequest {
            email: "grace@example.com".to_string(),
            password: "password12345".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();
    let t3 = signin3.token;

    // List active sessions
    let sessions = service.list_sessions(&user_res.user.id).await.unwrap();
    assert_eq!(sessions.len(), 3);

    // Revoke t2
    service.revoke_session(&user_res.user.id, &t2).await.unwrap();
    assert!(service.get_session(&t2).await.unwrap().is_none());
    assert!(service.get_session(&t1).await.unwrap().is_some());
    assert!(service.get_session(&t3).await.unwrap().is_some());

    // Revoke other sessions keeping t3
    service
        .revoke_other_sessions(&user_res.user.id, &t3)
        .await
        .unwrap();
    assert!(service.get_session(&t1).await.unwrap().is_none());
    assert!(service.get_session(&t3).await.unwrap().is_some());

    // Revoke all
    service.revoke_sessions(&user_res.user.id).await.unwrap();
    assert!(service.get_session(&t3).await.unwrap().is_none());
}

#[tokio::test]
async fn test_scrypt_migration_and_account_unlink_and_user_lifecycle() {
    let (service, _) = create_test_service();

    // 1. Sign up a user and replace their password hash with a Better Auth scrypt hash
    let signup = service
        .sign_up_email(SignUpEmailRequest {
            name: "Legacy TS User".to_string(),
            email: "legacy@example.com".to_string(),
            password: "migrated-password-123".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let scrypt_hash =
        hash_scrypt_better_auth("00112233445566778899aabbccddeeff", "migrated-password-123")
            .unwrap();
    service
        .adapter()
        .update_account_password(&signup.user.id, &scrypt_hash)
        .await
        .unwrap();

    // 2. Sign in succeeds against the scrypt hash and transparently upgrades it to Argon2id
    let signin = service
        .sign_in_email(SignInEmailRequest {
            email: "legacy@example.com".to_string(),
            password: "migrated-password-123".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Sign-in with legacy scrypt hash should succeed");

    let upgraded_acc = service
        .adapter()
        .find_account("credential", &signup.user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        upgraded_acc.password.unwrap().starts_with("$argon2"),
        "Legacy scrypt hash must be transparently upgraded to Argon2id on login"
    );

    // 3. Cannot unlink the last remaining authentication account
    let unlink_err = service
        .unlink_account(&signup.user.id, "credential", "")
        .await
        .unwrap_err();
    assert_eq!(unlink_err.error_code(), "FAILED_TO_UNLINK_LAST_ACCOUNT");
    assert_eq!(unlink_err.http_status(), 400);

    // 4. Link a social account (with provider-specific account_id != user.id) and unlink it
    service
        .adapter()
        .create_account(CreateAccountInput {
            id: None,
            user_id: signup.user.id.clone(),
            account_id: "github_uid_99999".to_string(),
            provider_id: "github".to_string(),
            password: None,
            access_token: Some("gho_token".to_string()),
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: Some("read:user,user:email".to_string()),
        })
        .await
        .unwrap();

    assert_eq!(
        service.list_accounts(&signup.user.id).await.unwrap().len(),
        2
    );

    service
        .unlink_account(&signup.user.id, "github", "")
        .await
        .expect("Unlinking social account by provider_id should succeed");
    assert_eq!(
        service.list_accounts(&signup.user.id).await.unwrap().len(),
        1
    );

    // 5. Change password with revoke_other_sessions rotates session token
    let change_res = service
        .change_password(
            &signup.user.id,
            &signin.token,
            ChangePasswordRequest {
                current_password: "migrated-password-123".to_string(),
                new_password: "rotated-password-456".to_string(),
                revoke_other_sessions: Some(true),
            },
        )
        .await
        .unwrap();
    let rotated_token = change_res.token.expect("Must return rotated session token");
    assert_ne!(rotated_token, signin.token);
    assert!(service.get_session(&signin.token).await.unwrap().is_none());
    assert!(service.get_session(&rotated_token).await.unwrap().is_some());

    // 6. Update user profile and delete user
    let updated_user = service
        .update_user(
            &signup.user.id,
            UpdateUserRequest {
                name: Some("Updated Name".to_string()),
                image: Some("https://example.com/new.png".to_string()),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated_user.user.unwrap().name, "Updated Name");

    service
        .delete_user(
            &signup.user.id,
            DeleteUserRequest {
                password: Some("rotated-password-456".to_string()),
                callback_url: None,
            },
        )
        .await
        .unwrap();
    assert!(service.get_session(&rotated_token).await.unwrap().is_none());
}

#[tokio::test]
async fn test_credential_account_with_distinct_account_id() {
    let (service, _) = create_test_service();

    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: Some("usr_migrated_1".to_string()),
            name: "Migrated Credential User".to_string(),
            email: "migrated_cred@example.com".to_string(),
            image: None,
            email_verified: true,
        })
        .await
        .unwrap();

    let scrypt_hash =
        hash_scrypt_better_auth("aabbccddeeff00112233445566778899", "caf\u{00e9}-password-99")
            .unwrap();

    // Create a credential account where account_id != user.id
    service
        .adapter()
        .create_account(CreateAccountInput {
            id: Some("acc_custom_1".to_string()),
            user_id: user.id.clone(),
            account_id: "custom_cred_account_id".to_string(),
            provider_id: "credential".to_string(),
            password: Some(scrypt_hash),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
        })
        .await
        .unwrap();

    // Sign in using decomposed UTF-8 password ("cafe\u{0301}") and verify lookup + NFKC scrypt rehashing
    let signin = service
        .sign_in_email(SignInEmailRequest {
            email: "migrated_cred@example.com".to_string(),
            password: "cafe\u{0301}-password-99".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Sign-in should locate credential account by user_id and verify NFKC scrypt");

    // Change password also works when account_id != user.id
    let changed = service
        .change_password(
            &user.id,
            &signin.token,
            ChangePasswordRequest {
                current_password: "caf\u{00e9}-password-99".to_string(),
                new_password: "new-password-8888".to_string(),
                revoke_other_sessions: Some(false),
            },
        )
        .await
        .expect("change_password should locate credential account by user_id");
    assert_eq!(changed.user.id, user.id);
}

#[tokio::test]
async fn test_admin_plugin_rbac_ban_impersonation_and_lifecycle() {
    let (service, _) = create_test_service();

    // 1. Create an admin user and promote role to "admin"
    let admin_signup = service
        .sign_up_email(SignUpEmailRequest {
            name: "Admin User".to_string(),
            email: "admin@example.com".to_string(),
            password: "adminpassword123".to_string(),
            image: None,
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let admin_record = service
        .adapter()
        .update_user_admin(
            &admin_signup.user.id,
            AdminUpdateUserFields {
                role: Some("admin".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let admin_wire = admin_record.to_wire();

    // 2. Admin creates a regular user
    let created = service
        .admin_create_user(
            &admin_wire,
            AdminCreateUserRequest {
                email: "member@example.com".to_string(),
                password: Some("memberpassword123".to_string()),
                name: "Member User".to_string(),
                role: Some(RoleValue::Single("user".to_string())),
                data: None,
            },
        )
        .await
        .expect("Admin should create user");
    let member_wire = created.user;
    assert_eq!(member_wire.role.as_deref(), Some("user"));

    // 3. Regular user cannot call admin_set_role or admin_ban_user (403 Forbidden)
    let forbidden_err = service
        .admin_set_role(
            &member_wire,
            AdminSetRoleRequest {
                user_id: admin_wire.id.clone(),
                role: RoleValue::Single("user".to_string()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(forbidden_err.http_status(), 403);
    assert_eq!(
        forbidden_err.error_code(),
        "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
    );

    // 4. Admin cannot ban or remove themselves
    let self_ban_err = service
        .admin_ban_user(
            &admin_wire,
            AdminBanUserRequest {
                user_id: admin_wire.id.clone(),
                ban_reason: Some("Self ban".to_string()),
                ban_expires_in: None,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(self_ban_err.error_code(), "YOU_CANNOT_BAN_YOURSELF");

    let self_remove_err = service
        .admin_remove_user(&admin_wire, &admin_wire.id)
        .await
        .unwrap_err();
    assert_eq!(self_remove_err.error_code(), "YOU_CANNOT_REMOVE_YOURSELF");

    // 5. Member signs in, then Admin bans member -> member's sessions are revoked and sign-in blocked
    let member_signin = service
        .sign_in_email(SignInEmailRequest {
            email: "member@example.com".to_string(),
            password: "memberpassword123".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap();

    let banned_res = service
        .admin_ban_user(
            &admin_wire,
            AdminBanUserRequest {
                user_id: member_wire.id.clone(),
                ban_reason: Some("Policy violation".to_string()),
                ban_expires_in: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(banned_res.user.banned, Some(true));
    assert_eq!(
        banned_res.user.ban_reason.as_deref(),
        Some("Policy violation")
    );

    // Existing session is immediately revoked
    assert!(service
        .get_session(&member_signin.token)
        .await
        .unwrap()
        .is_none());

    // Banned user cannot sign in (403 BANNED_USER)
    let banned_login_err = service
        .sign_in_email(SignInEmailRequest {
            email: "member@example.com".to_string(),
            password: "memberpassword123".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .unwrap_err();
    assert_eq!(banned_login_err.error_code(), "BANNED_USER");
    assert_eq!(banned_login_err.http_status(), 403);

    // 6. Unban user -> sign-in succeeds again
    let unbanned = service
        .admin_unban_user(&admin_wire, &member_wire.id)
        .await
        .unwrap();
    assert_eq!(unbanned.user.banned, Some(false));
    assert!(unbanned.user.ban_reason.is_none());

    let member_relogin = service
        .sign_in_email(SignInEmailRequest {
            email: "member@example.com".to_string(),
            password: "memberpassword123".to_string(),
            callback_url: None,
            remember_me: Some(true),
        })
        .await
        .expect("Unbanned user should sign in");

    // 7. Admin impersonates member -> impersonated session is hidden from member's /list-sessions
    let imp_res = service
        .admin_impersonate_user(&admin_wire, &member_wire.id, RequestMeta::default())
        .await
        .expect("Admin impersonation should succeed");
    assert_eq!(imp_res.user.id, member_wire.id);
    assert_eq!(
        imp_res.session.impersonated_by.as_deref(),
        Some(admin_wire.id.as_str())
    );

    // Standard list_sessions hides impersonated sessions, while admin_list_user_sessions includes them
    let visible_sessions = service.list_sessions(&member_wire.id).await.unwrap();
    assert_eq!(visible_sessions.len(), 1);
    assert_eq!(visible_sessions[0].token, member_relogin.token);

    let all_member_sessions = service
        .admin_list_user_sessions(&admin_wire, &member_wire.id)
        .await
        .unwrap();
    assert_eq!(all_member_sessions.sessions.len(), 2);

    // Stop impersonating restores admin session and deletes impersonated session
    let stopped = service
        .admin_stop_impersonating(
            &imp_res.session,
            admin_signup.token.as_deref(),
        )
        .await
        .expect("stop_impersonating should restore admin session");
    assert_eq!(stopped.user.id, admin_wire.id);
    assert!(service
        .get_session(&imp_res.session.token)
        .await
        .unwrap()
        .is_none());

    // 8. Admin sets user password and lists users with search
    service
        .admin_set_user_password(
            &admin_wire,
            AdminSetUserPasswordRequest {
                user_id: member_wire.id.clone(),
                new_password: "admin-reset-password-99".to_string(),
            },
        )
        .await
        .unwrap();

    let list_res = service
        .admin_list_users(
            &admin_wire,
            AdminListUsersQuery {
                search_value: Some("member@".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(list_res.total, 1);
    assert_eq!(list_res.users[0].email, "member@example.com");
}

#[test]
fn test_rate_limiter_and_totp_validator() {
    let limiter = SlidingWindowRateLimiter::new(2, std::time::Duration::from_secs(60));
    assert!(limiter.check("sign-in:127.0.0.1").is_ok());
    assert!(limiter.check("sign-in:127.0.0.1").is_ok());
    let err = limiter.check("sign-in:127.0.0.1").unwrap_err();
    assert!(matches!(err, AuthError::RateLimitExceeded));
    assert_eq!(err.http_status(), 429);

    let totp = TotpValidator::default();
    let secret = b"12345678901234567890";
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let code = totp.generate_at(secret, now);
    assert_eq!(code.len(), 6);
    assert!(totp.verify(secret, &code));
    assert!(!totp.verify(secret, "000000"));
}
