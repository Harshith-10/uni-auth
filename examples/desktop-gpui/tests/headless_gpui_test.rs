use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;

use auth_axum::{auth_router, AuthState};
use auth_client::{AuthStatus, AuthStore, BetterAuthNativeClient, MockTokenStorage, TokenStorage};
use auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use auth_proto::{AdminCreateUserRequest, RoleValue, UserWire};
use axum::Router;
use desktop_gpui::{DashboardTab, DesktopAuthApp};
use gpui_kit::component::Root;
use gpui_kit::{AppContext as _, TestAppContext};

async fn start_test_server() -> (String, String, Arc<AuthService>) {
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
        delete_user_enabled: true,
        defer_session_refresh: false,
    };

    let service = Arc::new(AuthService::new(config, adapter));
    let state = AuthState::new(Arc::clone(&service));

    let app = Router::new().nest("/api/auth", auth_router(state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_url = format!("http://127.0.0.1:{port}");
    let auth_base_url = format!("{server_url}/api/auth");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (server_url, auth_base_url, service)
}

#[gpui_kit::test]
async fn test_desktop_auth_headless_interaction(cx: &mut TestAppContext) {
    cx.executor().allow_parking();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();

    cx.update(gpui_kit::init);

    let (server_url, auth_base_url, service) = start_test_server().await;
    let storage = Arc::new(MockTokenStorage::new());
    let client = Arc::new(BetterAuthNativeClient::new(
        auth_base_url,
        Arc::clone(&storage) as Arc<dyn TokenStorage>,
    ));
    let store = AuthStore::new(client);

    let admin_actor = UserWire {
        id: "seed-admin".to_string(),
        name: "Seed Admin".to_string(),
        email: "seed-admin@system.local".to_string(),
        email_verified: true,
        image: None,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
        role: Some("admin".to_string()),
        banned: Some(false),
        ban_reason: None,
        ban_expires: None,
    };

    // Seed an admin account to test both sign-in and Admin Console loading
    service
        .admin_create_user(
            &admin_actor,
            AdminCreateUserRequest {
                email: "admin@example.com".to_string(),
                password: Some("admin12345".to_string()),
                name: "Admin User".to_string(),
                role: Some(RoleValue::Single("admin".to_string())),
                data: None,
            },
        )
        .await
        .expect("Seed admin user should succeed");

    // Pre-create standard user account as well
    store
        .sign_up_email(
            "GPUI Tester",
            "gpui_test@example.com",
            "password123",
            Some(true),
        )
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

    // Populate credentials using fill_demo_account helper
    cx.update(|window, cx| {
        app.update(cx, |view, cx| {
            view.fill_demo_account("admin@example.com", "admin12345", window, cx);
        });
    });

    // Verify inputs have the expected values
    app.read_with(cx, |view, cx| {
        assert_eq!(
            view.email_input.read(cx).value().as_ref(),
            "admin@example.com"
        );
        assert_eq!(view.password_input.read(cx).value().as_ref(), "admin12345");
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
    assert!(
        authenticated,
        "Expected AuthStatus::Authenticated, but timed out waiting for authentication"
    );

    // Let any background session/SaaS fetch settle and draw window
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        cx.run_until_parked();
    }
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
    });

    // Switch to Admin tab and verify admin users list populates
    cx.update(|window, cx| {
        app.update(cx, |view, cx| {
            view.set_tab(DashboardTab::Admin, window, cx);
        });
    });

    let mut admin_loaded = false;
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        cx.run_until_parked();
        app.read_with(cx, |view, _| {
            if view.admin_users_total >= 2 {
                admin_loaded = true;
            }
        });
        if admin_loaded {
            break;
        }
    }
    assert!(admin_loaded, "Expected admin_users_total >= 2 in Admin tab");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
    });

    // Sign out
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
    assert!(
        signed_out,
        "Expected AuthStatus::Unauthenticated after sign out"
    );
}
