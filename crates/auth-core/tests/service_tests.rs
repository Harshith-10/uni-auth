use std::sync::Arc;
use time::Duration;

use auth_core::{AuthConfig, AuthService, EmailSender, InMemoryAuthAdapter, MockEmailSender};
use auth_proto::{
    RequestPasswordResetRequest, ResetPasswordRequest, SignInEmailRequest, SignUpEmailRequest,
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

    let signup_token = signup_res.token.unwrap();

    // 2. Get session using the signed token from sign-up
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
