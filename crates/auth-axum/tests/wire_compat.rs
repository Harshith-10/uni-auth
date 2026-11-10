use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;

use auth_axum::{auth_router, AuthState, OAuthProviderConfig};
use auth_core::models::CreateUserInput;
use auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use auth_proto::{
    OkResponse, OneTimeTokenGenerateResponse, SessionAndUserResponse, SignInSocialResponse,
    SignUpResponse,
};
use axum::Router;

async fn start_test_server() -> (String, Arc<AuthService>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"axum-wire-compat-secret-32-bytes-long".to_vec(),
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
    let mut mock_google = OAuthProviderConfig::google("mock_client_id", "mock_client_secret");
    mock_google.token_url = "mock://google/token".to_string();
    let state = AuthState::new(Arc::clone(&service)).with_oauth_provider(mock_google);

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
async fn test_ok_endpoint() {
    let (base_url, _) = start_test_server().await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{base_url}/ok"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: OkResponse = res.json().await.unwrap();
    assert!(body.ok);
}

#[tokio::test]
async fn test_unauthenticated_get_session_returns_null() {
    let (base_url, _) = start_test_server().await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{base_url}/get-session"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body_text = res.text().await.unwrap();
    assert_eq!(body_text.trim(), "null");
}

#[tokio::test]
async fn test_sign_up_and_cookie_flow() {
    let (base_url, _) = start_test_server().await;

    // Use a client with a cookie jar
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();

    // 1. Sign up
    let res = client
        .post(format!("{base_url}/sign-up/email"))
        .json(&serde_json::json!({
            "name": "Web User",
            "email": "webuser@example.com",
            "password": "superpassword123",
            "rememberMe": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);

    // Verify set-auth-token header was emitted
    let auth_token_header = res
        .headers()
        .get("set-auth-token")
        .expect("set-auth-token header must be set")
        .to_str()
        .unwrap()
        .to_string();

    assert!(!auth_token_header.is_empty());
    assert!(auth_token_header.contains('.'));

    let signup_body: SignUpResponse = res.json().await.unwrap();
    assert_eq!(signup_body.user.email, "webuser@example.com");

    // 2. GET /get-session using automatically stored cookie
    let session_res = client
        .get(format!("{base_url}/get-session"))
        .send()
        .await
        .unwrap();

    assert_eq!(session_res.status(), 200);
    let session_data: SessionAndUserResponse = session_res.json().await.unwrap();
    assert_eq!(session_data.user.email, "webuser@example.com");

    // 3. GET /list-sessions
    let list_res = client
        .get(format!("{base_url}/list-sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), 200);
    let sessions: Vec<serde_json::Value> = list_res.json().await.unwrap();
    assert_eq!(sessions.len(), 1);

    // 4. Sign out -> clears cookie and deletes session
    let signout_res = client
        .post(format!("{base_url}/sign-out"))
        .send()
        .await
        .unwrap();
    assert_eq!(signout_res.status(), 200);

    // 5. Subsequent get-session returns null
    let unauth_res = client
        .get(format!("{base_url}/get-session"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), 200);
    assert_eq!(unauth_res.text().await.unwrap().trim(), "null");
}

#[tokio::test]
async fn test_bearer_token_flow_desktop_parity() {
    let (base_url, _) = start_test_server().await;

    // Client WITHOUT cookie jar (simulating native desktop app)
    let client = reqwest::Client::new();

    // 1. Sign in (first create user)
    let signup_res = client
        .post(format!("{base_url}/sign-up/email"))
        .json(&serde_json::json!({
            "name": "Desktop User",
            "email": "desktop@example.com",
            "password": "desktop-secret-pass",
            "rememberMe": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(signup_res.status(), 200);
    let desktop_token = signup_res
        .headers()
        .get("set-auth-token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 2. Call /get-session with Authorization: Bearer <token>
    let get_session_res = client
        .get(format!("{base_url}/get-session"))
        .header("Authorization", format!("Bearer {desktop_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(get_session_res.status(), 200);
    let session_data: SessionAndUserResponse = get_session_res.json().await.unwrap();
    assert_eq!(session_data.user.email, "desktop@example.com");

    // 3. One-Time Token handoff flow via Bearer token
    let ott_gen_res = client
        .get(format!("{base_url}/one-time-token/generate"))
        .header("Authorization", format!("Bearer {desktop_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(ott_gen_res.status(), 200);
    let ott_body: OneTimeTokenGenerateResponse = ott_gen_res.json().await.unwrap();

    // 4. Verify OTT from a fresh unauthenticated client
    let ott_verify_res = client
        .post(format!("{base_url}/one-time-token/verify"))
        .json(&serde_json::json!({ "token": ott_body.token }))
        .send()
        .await
        .unwrap();

    assert_eq!(ott_verify_res.status(), 200);
    let new_auth_token = ott_verify_res
        .headers()
        .get("set-auth-token")
        .expect("Verification must emit set-auth-token")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!new_auth_token.is_empty());
}

#[tokio::test]
async fn test_oauth_callback_redirect_hygiene_and_unverified_email_protection() {
    let (base_url, service) = start_test_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // 1. Web browser redirect (http://localhost:5173) must NOT leak ?token=<ott>
    let init_web: SignInSocialResponse = client
        .post(format!("{base_url}/sign-in/social"))
        .json(&serde_json::json!({
            "provider": "google",
            "callbackURL": "http://localhost:5173",
            "disableRedirect": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let state_param = init_web
        .url
        .split("state=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let cb_web = client
        .get(format!(
            "{base_url}/callback/google?code=fixed_web1&state={state_param}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb_web.status(), 307);
    let loc_web = cb_web
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(loc_web, "http://localhost:5173");

    // 2. Desktop loopback redirect (/auth/callback) MUST append ?token=<ott>
    let init_desktop: SignInSocialResponse = client
        .post(format!("{base_url}/sign-in/social"))
        .json(&serde_json::json!({
            "provider": "google",
            "callbackURL": "http://127.0.0.1:54321/auth/callback",
            "disableRedirect": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let state_desktop = init_desktop
        .url
        .split("state=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let cb_desktop = client
        .get(format!(
            "{base_url}/callback/google?code=fixed_web1&state={state_desktop}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb_desktop.status(), 307);
    let loc_desktop = cb_desktop
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        loc_desktop.starts_with("http://127.0.0.1:54321/auth/callback?token="),
        "Loopback callback must include ?token=<ott>, got: {loc_desktop}"
    );

    // 3. Unverified OAuth email must NOT auto-link to an existing user account
    service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "Victim User".to_string(),
            email: "user_unverified_victim@example.com".to_string(),
            image: None,
            email_verified: true,
        })
        .await
        .unwrap();

    let init_unverified: SignInSocialResponse = client
        .post(format!("{base_url}/sign-in/social"))
        .json(&serde_json::json!({
            "provider": "google",
            "callbackURL": "http://localhost:5173",
            "disableRedirect": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let state_unverified = init_unverified
        .url
        .split("state=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    let cb_unverified = client
        .get(format!(
            "{base_url}/callback/google?code=fixed_unverified_victim&state={state_unverified}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb_unverified.status(), 403);
}
