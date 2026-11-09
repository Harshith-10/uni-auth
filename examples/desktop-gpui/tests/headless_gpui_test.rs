use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;

use auth_axum::{auth_router, AuthState};
use auth_client::{AuthStatus, AuthStore, BetterAuthNativeClient, MockTokenStorage, TokenStorage};
use auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use axum::Router;
use desktop_gpui::DesktopAuthApp;
use gpui_kit::component::Root;
use gpui_kit::{AppContext as _, TestAppContext};

async fn start_test_server() -> (String, String) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"desktop-gpui-headless-test-secret-32b".to_vec(),
        base_url: "http://127.0.0.1:0/api/auth".to_string(),
        session_expires_in: Duration::days(7),
        ott_expires_in: Duration::minutes(3),
        reset_password_expires_in: Duration::hours(1),
        verify_email_expires_in: Duration::hours(24),
        auto_sign_in: true,
        require_email_verification: false,
        min_password_length: 8,
        max_password_length: 128,
    };

    let service = Arc::new(AuthService::new(config, adapter));
    let state = AuthState::new(service);

    let app = Router::new().nest("/api/auth", auth_router(state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_url = format!("http://127.0.0.1:{port}");
    let auth_base_url = format!("{server_url}/api/auth");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (server_url, auth_base_url)
}

#[gpui_kit::test]
async fn test_desktop_auth_headless_interaction(cx: &mut TestAppContext) {
    cx.executor().allow_parking();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    cx.update(gpui_kit::init);

    let (server_url, auth_base_url) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(BetterAuthNativeClient::new(
        auth_base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));
    let store = AuthStore::new(client);

    // Pre-create user account so we can test sign-in flow
    store
        .sign_up_email("GPUI Tester", "gpui_test@example.com", "password123", Some(true))
        .await
        .expect("Sign up should succeed");

    // Sign out to test the clean login screen interaction
    store.sign_out().await.unwrap();
    assert_eq!(store.status(), AuthStatus::Unauthenticated);

    let mut app_entity = None;
    let store_clone = store.clone();
    let server_url_clone = server_url.clone();

    let (_root, cx) = cx.add_window_view(|window, cx| {
        let view = cx.new(|cx| DesktopAuthApp::new(store_clone, server_url_clone, window, cx));
        app_entity = Some(view.clone());
        Root::new(view, window, cx)
    });

    let app = app_entity.expect("DesktopAuthApp view should be mounted");

    // Let the initial restore_session task settle
    cx.background_executor.run_until_parked();
    cx.run_until_parked();

    // Verify initial unauthenticated state
    app.read_with(cx, |view, _| {
        assert_eq!(view.store.status(), AuthStatus::Unauthenticated);
    });

    // Populate credentials in the input fields
    cx.update(|window, cx| {
        app.update(cx, |view, cx| {
            view.email_input.update(cx, |input, cx| {
                input.set_value("gpui_test@example.com", window, cx);
            });
            view.password_input.update(cx, |input, cx| {
                input.set_value("password123", window, cx);
            });
        });
    });

    // Verify inputs have the expected values
    app.read_with(cx, |view, cx| {
        assert_eq!(view.email_input.read(cx).value().as_ref(), "gpui_test@example.com");
        assert_eq!(view.password_input.read(cx).value().as_ref(), "password123");
    });

    // Submit the form
    cx.update(|window, cx| {
        app.update(cx, |view, cx| {
            view.submit_form(window, cx);
        });
    });

    // Poll until the background tokio task completes and GPUI updates
    let mut authenticated = false;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        cx.run_until_parked();
        app.read_with(cx, |view, _| {
            if matches!(view.store.status(), AuthStatus::Authenticated { .. }) {
                authenticated = true;
            }
        });
        if authenticated {
            break;
        }
    }
    assert!(authenticated, "Expected AuthStatus::Authenticated, but timed out waiting for authentication");

    // Verify successful authentication transition
    app.read_with(cx, |view, _| {
        match view.store.status() {
            AuthStatus::Authenticated { user, session } => {
                assert_eq!(user.email, "gpui_test@example.com");
                assert_eq!(user.name, "GPUI Tester");
                assert!(!session.token.is_empty());
            }
            other => panic!("Expected AuthStatus::Authenticated, got {:?}", other),
        }
    });

    // Refresh sessions and test sign-out
    cx.update(|window, cx| {
        app.update(cx, |view, cx| {
            view.sign_out(window, cx);
        });
    });

    let mut signed_out = false;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        cx.run_until_parked();
        app.read_with(cx, |view, _| {
            if matches!(view.store.status(), AuthStatus::Unauthenticated) {
                signed_out = true;
            }
        });
        if signed_out {
            break;
        }
    }
    assert!(signed_out, "Expected AuthStatus::Unauthenticated after sign out");
}
