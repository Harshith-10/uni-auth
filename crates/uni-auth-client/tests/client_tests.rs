use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::Duration;
use tokio::net::TcpListener;

use uni_auth_axum::{AuthState, auth_router};
use uni_auth_client::{
    AuthStatus, AuthStore, AuthClient, MockTokenStorage, TokenStorage,
    start_loopback_listener,
};
use uni_auth_core::models::AdminUpdateUserFields;
use uni_auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use uni_auth_proto::{AdminCreateUserRequest, RoleValue};
use axum::Router;

async fn start_test_server() -> (String, Arc<AuthService>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"auth-client-test-secret-32b-key".to_vec(),
        base_url: "http://127.0.0.1:0/api/auth".to_string(),
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

    let service = Arc::new(AuthService::new(config, adapter));
    let state = AuthState::new(Arc::clone(&service));

    let app = Router::new().nest("/api/auth", auth_router(state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base_url = format!("http://127.0.0.1:{port}/api/auth");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, service)
}

#[tokio::test]
async fn test_sign_up_and_token_storage() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));

    assert!(storage.get_token().unwrap().is_none());

    // 1. Sign up
    let res = client
        .sign_up_email("GPUI User", "gpui@example.com", "securepass123", Some(true))
        .await
        .expect("Sign-up should succeed");

    assert_eq!(res.user.email, "gpui@example.com");

    // 2. Token must now be persisted in storage automatically
    let stored_token = storage
        .get_token()
        .unwrap()
        .expect("Token should be in storage");
    assert!(!stored_token.is_empty());

    // 3. get_session works using the stored token
    let session = client
        .get_session()
        .await
        .unwrap()
        .expect("Session should resolve");
    assert_eq!(session.user.email, "gpui@example.com");
}

#[tokio::test]
async fn test_session_restoration_on_fresh_client_instance() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());

    // Client 1 signs in
    {
        let client1 = Arc::new(AuthClient::new(
            base_url.clone(),
            Arc::clone(&storage) as Arc<dyn TokenStorage>,
        ));
        client1
            .sign_up_email(
                "Persist User",
                "persist@example.com",
                "mypassword123",
                Some(true),
            )
            .await
            .unwrap();
    }

    // Client 2 boots up later sharing the same secure storage (simulating app relaunch)
    let client2 = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));

    let store = AuthStore::new(client2);
    let restored = store.restore_session().await.unwrap();
    assert!(restored);

    match store.status() {
        AuthStatus::Authenticated { user, .. } => {
            assert_eq!(user.email, "persist@example.com");
        }
        _ => panic!("Expected Authenticated status"),
    }
}

#[tokio::test]
async fn test_sign_out_clears_local_keyring_and_server_session() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));

    client
        .sign_up_email(
            "Signout User",
            "signout@example.com",
            "mypassword123",
            Some(true),
        )
        .await
        .unwrap();

    assert!(storage.get_token().unwrap().is_some());

    // Sign out
    let signout_res = client.sign_out().await.expect("Sign out should succeed");
    assert!(signout_res.success);

    // Storage must now be cleared
    assert!(storage.get_token().unwrap().is_none());

    // get_session must return None
    assert!(client.get_session().await.unwrap().is_none());
}

#[tokio::test]
async fn test_loopback_listener_and_ott_exchange() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(AuthClient::new(
        base_url.clone(),
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));

    // Sign up an account
    client
        .sign_up_email(
            "OAuth User",
            "oauth@example.com",
            "passphrase123",
            Some(true),
        )
        .await
        .unwrap();

    // Generate OTT from existing session
    let ott_res = client.generate_one_time_token().await.unwrap();
    let ott = ott_res.token;

    // Start loopback listener
    let (port, rx) = start_loopback_listener().await.unwrap();

    // Simulate browser redirect to loopback callback
    let callback_url = format!("http://127.0.0.1:{port}/auth/callback?token={ott}");
    let http = reqwest::Client::new();

    let redirect_response = http.get(&callback_url).send().await.unwrap();
    assert_eq!(redirect_response.status(), 200);

    let html = redirect_response.text().await.unwrap();
    assert!(html.contains("Sign-in Complete"));

    // Receiver should have caught the token
    let received_token = rx.await.unwrap().expect("Should receive valid token");
    assert_eq!(received_token, ott);

    // Fresh client on another machine / storage exchanges OTT
    let fresh_storage = Arc::new(MockTokenStorage::new());
    let fresh_client = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&fresh_storage) as Arc<dyn TokenStorage>,
    ));

    let session = fresh_client
        .verify_one_time_token(&received_token)
        .await
        .expect("Verification should succeed");

    assert_eq!(session.user.email, "oauth@example.com");
    assert!(fresh_storage.get_token().unwrap().is_some());
}

#[tokio::test]
async fn test_auth_store_reactive_notifications() {
    let (base_url, _) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));

    let store = AuthStore::new(client);

    let transitions = Arc::new(AtomicUsize::new(0));
    let t_clone = Arc::clone(&transitions);

    store.subscribe(move |_status| {
        t_clone.fetch_add(1, Ordering::SeqCst);
    });

    assert_eq!(store.status(), AuthStatus::Loading);

    // 1. Restore (unauthenticated) -> notification 1
    store.restore_session().await.unwrap();
    assert_eq!(store.status(), AuthStatus::Unauthenticated);
    assert_eq!(transitions.load(Ordering::SeqCst), 1);

    // 2. Sign up -> Authenticated -> notification 2
    store
        .sign_up_email(
            "Reactive",
            "reactive@example.com",
            "secretpass123",
            Some(true),
        )
        .await
        .unwrap();

    assert!(store.is_authenticated());
    assert_eq!(transitions.load(Ordering::SeqCst), 2);

    // 3. Sign out -> Unauthenticated -> notification 3
    store.sign_out().await.unwrap();
    assert_eq!(store.status(), AuthStatus::Unauthenticated);
    assert_eq!(transitions.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_native_client_admin_operations_and_impersonation() {
    let (base_url, service) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(AuthClient::new(
        base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));
    let store = AuthStore::new(Arc::clone(&client));

    let admin_signup = client
        .sign_up_email(
            "Native Admin",
            "native_admin@example.com",
            "adminpass123",
            Some(true),
        )
        .await
        .unwrap();

    service
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
    store.restore_session().await.unwrap();

    let created = client
        .admin_create_user(AdminCreateUserRequest {
            email: "target_user@example.com".to_string(),
            password: Some("targetpass123".to_string()),
            name: "Target User".to_string(),
            role: Some(RoleValue::Single("user".to_string())),
            data: None,
        })
        .await
        .unwrap();

    // Impersonate target user via AuthStore
    let imp = store.impersonate_user(&created.user.id).await.unwrap();
    assert_eq!(imp.user.email, "target_user@example.com");

    // Stop impersonating restores admin session in AuthStore
    let restored = store.stop_impersonating().await.unwrap();
    assert_eq!(restored.user.email, "native_admin@example.com");
}

#[tokio::test]
async fn test_keyring_token_storage_serialized_writes_and_cache() {
    let storage = uni_auth_client::KeyringTokenStorage::new(
        "test-app-service",
        "test-user-account",
    );
    assert_eq!(storage.service_name(), "test-app-service");
    assert_eq!(storage.account_name(), "test-user-account");

    // Immediate write-through cache check
    storage.set_token("token_alpha").unwrap();
    assert_eq!(storage.get_token().unwrap(), Some("token_alpha".to_string()));

    // Rapid concurrent mutations are serialized in order
    for i in 0..20 {
        storage.set_token(&format!("token_{i}")).unwrap();
    }
    assert_eq!(storage.get_token().unwrap(), Some("token_19".to_string()));

    storage.delete_token().unwrap();
    assert_eq!(storage.get_token().unwrap(), None);
}
