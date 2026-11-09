//! Cross-platform End-to-End integration test.
//!
//! Verifies wire parity and concurrent multi-session interaction across platforms:
//! 1. Web Client (Cookie transport mimicking React + official `@better-auth/client`).
//! 2. Native Desktop Client (Bearer token + Keychain transport mimicking GPUI-Kit desktop app).
//! 3. Dual-mode SaaS route (`GET /api/saas/me`) detecting Cookie vs Bearer transport.
//! 4. Cross-platform session listing (`GET /api/auth/list-sessions`).
//! 5. Desktop-initiated revocation of Web session (`POST /api/auth/revoke-session`).
//! 6. Immediate invalidation of Web cookie session while Desktop bearer session stays active.

use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;

use auth_axum::{auth_routes, AuthState, CurrentSession};
use auth_client::{AuthStatus, AuthStore, BetterAuthNativeClient, MockTokenStorage, TokenStorage};
use auth_core::{AuthConfig, AuthService};
use auth_proto::SessionWire;
use auth_sqlx::SqliteAuthAdapter;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

/// Protected SaaS endpoint that returns user profile and authentication transport details.
async fn saas_me(session: CurrentSession) -> Response {
    let transport = if session.is_bearer {
        "Bearer (Native Desktop / GPUI Keychain)"
    } else {
        "Cookie (Web Browser / better-auth-client)"
    };

    Json(serde_json::json!({
        "status": "authenticated",
        "transport": transport,
        "user": session.user,
        "session": {
            "id": session.session.id,
            "token": session.session.token,
            "expiresAt": session.session.expires_at,
            "createdAt": session.session.created_at,
        }
    }))
    .into_response()
}

/// Spawns an in-memory SQLite Axum server serving Better Auth routes and `/api/saas/me`.
async fn spawn_test_server() -> (String, String) {
    let adapter = Arc::new(SqliteAuthAdapter::new_in_memory().await.unwrap());
    let config = AuthConfig {
        secret: b"cross-platform-e2e-secret-key-32b-length!".to_vec(),
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

    let app = Router::new()
        .route("/api/saas/me", get(saas_me))
        .nest("/api/auth", auth_routes())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let auth_base_url = format!("http://127.0.0.1:{port}/api/auth");
    let server_base_url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (auth_base_url, server_base_url)
}

#[tokio::test]
async fn test_cross_platform_dual_session_and_invalidation() {
    let (auth_base_url, server_base_url) = spawn_test_server().await;

    // =========================================================================
    // STEP 1: Web Client (Cookie Transport) Registers and Calls Protected API
    // =========================================================================
    let web_cookie_jar = Arc::new(reqwest::cookie::Jar::default());
    let web_client = reqwest::Client::builder()
        .cookie_provider(Arc::clone(&web_cookie_jar))
        .build()
        .expect("Failed to build web reqwest client");

    let sign_up_url = format!("{auth_base_url}/sign-up/email");
    let sign_up_resp = web_client
        .post(&sign_up_url)
        .json(&serde_json::json!({
            "name": "Cross Platform User",
            "email": "cross_user@example.com",
            "password": "Password123!",
            "callbackURL": "http://localhost:5173"
        }))
        .send()
        .await
        .expect("Web sign-up request failed");

    assert_eq!(sign_up_resp.status(), reqwest::StatusCode::OK);
    let web_sign_up_data: serde_json::Value = sign_up_resp.json().await.unwrap();
    assert_eq!(web_sign_up_data["user"]["email"], "cross_user@example.com");

    // Verify Web Client access to protected SaaS route using Cookie
    let saas_url = format!("{server_base_url}/api/saas/me");
    let web_saas_resp = web_client
        .get(&saas_url)
        .send()
        .await
        .expect("Web saas/me request failed");

    assert_eq!(web_saas_resp.status(), reqwest::StatusCode::OK);
    let web_saas_data: serde_json::Value = web_saas_resp.json().await.unwrap();
    assert_eq!(web_saas_data["status"], "authenticated");
    assert_eq!(
        web_saas_data["transport"],
        "Cookie (Web Browser / better-auth-client)"
    );
    let web_session_id = web_saas_data["session"]["id"]
        .as_str()
        .expect("Missing web session id")
        .to_string();

    // =========================================================================
    // STEP 2: Desktop Client (Bearer + Keychain Transport) Signs In
    // =========================================================================
    let desktop_storage = Arc::new(MockTokenStorage::new());
    let desktop_client = Arc::new(BetterAuthNativeClient::new(
        auth_base_url.clone(),
        Arc::clone(&desktop_storage) as Arc<dyn TokenStorage>,
    ));
    let desktop_store = AuthStore::new(desktop_client);

    desktop_store
        .sign_in_email(
            "cross_user@example.com".to_string(),
            "Password123!".to_string(),
            Some(true),
        )
        .await
        .expect("Desktop sign-in should succeed");

    // Verify Desktop Client state and token in storage
    let desktop_token = desktop_storage
        .get_token()
        .unwrap()
        .expect("Token must be saved in desktop storage");

    match desktop_store.status() {
        AuthStatus::Authenticated { user, session } => {
            assert_eq!(user.email, "cross_user@example.com");
            assert!(desktop_token.starts_with(&session.token));
        }
        other => panic!("Expected Authenticated status, got {:?}", other),
    }

    // Verify Desktop Client access to protected SaaS route using Bearer token
    let desktop_saas_resp = reqwest::Client::new()
        .get(&saas_url)
        .bearer_auth(&desktop_token)
        .send()
        .await
        .expect("Desktop saas/me request failed");

    assert_eq!(desktop_saas_resp.status(), reqwest::StatusCode::OK);
    let desktop_saas_data: serde_json::Value = desktop_saas_resp.json().await.unwrap();
    assert_eq!(desktop_saas_data["status"], "authenticated");
    assert_eq!(
        desktop_saas_data["transport"],
        "Bearer (Native Desktop / GPUI Keychain)"
    );
    let desktop_session_id = desktop_saas_data["session"]["id"]
        .as_str()
        .expect("Missing desktop session id")
        .to_string();

    // Ensure two separate, unique sessions exist for Web and Desktop
    assert_ne!(
        web_session_id, desktop_session_id,
        "Web and Desktop should have distinct session IDs"
    );

    // =========================================================================
    // STEP 3: Dual Session Listing from Both Clients
    // =========================================================================
    // 3A. Desktop client queries list_sessions
    let desktop_sessions = desktop_store
        .client()
        .list_sessions()
        .await
        .expect("Desktop list_sessions failed");

    assert_eq!(desktop_sessions.len(), 2);
    let has_web_session = desktop_sessions.iter().any(|s| s.id == web_session_id);
    let has_desktop_session = desktop_sessions.iter().any(|s| s.id == desktop_session_id);
    assert!(has_web_session, "Desktop list must include Web session");
    assert!(has_desktop_session, "Desktop list must include Desktop session");

    // 3B. Web client queries list-sessions via Cookie
    let web_list_resp = web_client
        .get(format!("{auth_base_url}/list-sessions"))
        .send()
        .await
        .expect("Web list-sessions request failed");

    assert_eq!(web_list_resp.status(), reqwest::StatusCode::OK);
    let web_sessions: Vec<SessionWire> = web_list_resp.json().await.unwrap();
    assert_eq!(web_sessions.len(), 2);
    assert!(web_sessions.iter().any(|s| s.id == web_session_id));
    assert!(web_sessions.iter().any(|s| s.id == desktop_session_id));

    // =========================================================================
    // STEP 4: Desktop Revokes Web Session (Cross-Platform Revocation)
    // =========================================================================
    desktop_store
        .client()
        .revoke_session(&web_session_id)
        .await
        .expect("Revoking web session from desktop client must succeed");

    // =========================================================================
    // STEP 5: Verify Web Cookie Session Invalidation
    // =========================================================================
    // 5A. Web client get-session should now return null
    let web_get_session_resp = web_client
        .get(format!("{auth_base_url}/get-session"))
        .send()
        .await
        .expect("Web get-session request failed");

    assert_eq!(web_get_session_resp.status(), reqwest::StatusCode::OK);
    let web_session_body: serde_json::Value = web_get_session_resp.json().await.unwrap();
    assert!(
        web_session_body.is_null(),
        "Revoked web session must return null to get-session"
    );

    // 5B. Web client request to protected SaaS route must now return 401 Unauthorized
    let web_saas_revoked_resp = web_client
        .get(&saas_url)
        .send()
        .await
        .expect("Web saas/me revoked request failed");

    assert_eq!(
        web_saas_revoked_resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Revoked web session must be rejected by CurrentSession extractor"
    );

    // =========================================================================
    // STEP 6: Verify Desktop Bearer Session Remains Active and Valid
    // =========================================================================
    // 6A. Desktop client get-session remains authenticated
    let desktop_curr_session = desktop_store
        .client()
        .get_session()
        .await
        .expect("Desktop get_session request failed")
        .expect("Desktop session must still be active");

    assert_eq!(desktop_curr_session.session.id, desktop_session_id);

    // 6B. Desktop client can still access protected SaaS route
    let desktop_saas_active_resp = reqwest::Client::new()
        .get(&saas_url)
        .bearer_auth(&desktop_token)
        .send()
        .await
        .expect("Desktop saas/me active request failed");

    assert_eq!(desktop_saas_active_resp.status(), reqwest::StatusCode::OK);
    let desktop_active_data: serde_json::Value = desktop_saas_active_resp.json().await.unwrap();
    assert_eq!(desktop_active_data["status"], "authenticated");
    assert_eq!(
        desktop_active_data["transport"],
        "Bearer (Native Desktop / GPUI Keychain)"
    );

    // =========================================================================
    // STEP 7: Desktop Signs Out and Verifies Cleanup
    // =========================================================================
    desktop_store
        .sign_out()
        .await
        .expect("Desktop sign_out failed");

    assert!(
        desktop_storage.get_token().unwrap().is_none(),
        "Desktop token storage must be empty after sign_out"
    );
    assert_eq!(desktop_store.status(), AuthStatus::Unauthenticated);

    // Desktop former bearer token is now rejected by CurrentSession
    let desktop_signed_out_resp = reqwest::Client::new()
        .get(&saas_url)
        .bearer_auth(&desktop_token)
        .send()
        .await
        .expect("Desktop saas/me signed-out request failed");

    assert_eq!(desktop_signed_out_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
