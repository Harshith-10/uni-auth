use std::collections::HashMap;
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt;

use uni_auth_axum::{AuthState, OAuthProviderConfig, auth_router};
use uni_auth_core::models::{AdminUpdateUserFields, CreateUserInput};
use uni_auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use uni_auth_proto::{
    AdminListUsersResponse, AdminPermissionResponse, AdminUserResponse, OkResponse,
    OneTimeTokenGenerateResponse, SessionAndUserResponse, SignInSocialResponse, SignUpResponse,
};
use axum::Router;

#[derive(Clone)]
pub struct TestClient {
    pub app: Router,
    pub cookie_store: bool,
    pub cookies: Arc<std::sync::Mutex<HashMap<String, String>>>,
}

impl TestClient {
    pub fn get(&self, uri: impl Into<String>) -> TestRequestBuilder {
        TestRequestBuilder::new(self.clone(), http::Method::GET, uri.into())
    }

    pub fn post(&self, uri: impl Into<String>) -> TestRequestBuilder {
        TestRequestBuilder::new(self.clone(), http::Method::POST, uri.into())
    }
}

pub struct TestRequestBuilder {
    client: TestClient,
    method: http::Method,
    uri: String,
    headers: http::HeaderMap,
    body: axum::body::Body,
}

impl TestRequestBuilder {
    pub fn new(client: TestClient, method: http::Method, uri: String) -> Self {
        Self {
            client,
            method,
            uri,
            headers: http::HeaderMap::new(),
            body: axum::body::Body::empty(),
        }
    }

    pub fn header(mut self, name: &'static str, val: impl AsRef<str>) -> Self {
        self.headers.insert(
            http::header::HeaderName::from_static(name),
            http::HeaderValue::from_str(val.as_ref()).unwrap(),
        );
        self
    }

    pub fn json<T: serde::Serialize>(mut self, json: &T) -> Self {
        let bytes = serde_json::to_vec(json).unwrap();
        self.headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        self.body = axum::body::Body::from(bytes);
        self
    }

    pub async fn send(mut self) -> Result<TestResponse, String> {
        let path_and_query = if let Ok(url) = url::Url::parse(&self.uri) {
            let p = url.path();
            if let Some(q) = url.query() {
                format!("{p}?{q}")
            } else {
                p.to_string()
            }
        } else {
            self.uri.clone()
        };

        let mut req = axum::extract::Request::builder()
            .method(self.method)
            .uri(path_and_query);

        if self.client.cookie_store {
            let cookies = self.client.cookies.lock().unwrap();
            if !cookies.is_empty() {
                let cookie_str = cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                self.headers.insert(
                    http::header::COOKIE,
                    http::HeaderValue::from_str(&cookie_str).unwrap(),
                );
            }
        }

        for (k, v) in self.headers {
            if let Some(name) = k {
                req = req.header(name, v);
            }
        }

        let request = req.body(self.body).map_err(|e| e.to_string())?;
        let response = self
            .client
            .app
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| format!("{e:?}"))?;

        if self.client.cookie_store {
            let mut cookies = self.client.cookies.lock().unwrap();
            for val in response.headers().get_all(http::header::SET_COOKIE) {
                if let Ok(cookie_str) = val.to_str() {
                    let first_part = cookie_str.split(';').next().unwrap_or("");
                    if let Some((name, val)) = first_part.split_once('=') {
                        let name = name.trim();
                        let val = val.trim();
                        if val.is_empty()
                            || cookie_str.contains("Max-Age=0")
                            || cookie_str.contains("Expires=Thu, 01 Jan 1970")
                        {
                            cookies.remove(name);
                        } else {
                            cookies.insert(name.to_string(), val.to_string());
                        }
                    }
                }
            }
        }

        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .map_err(|e| e.to_string())?;

        Ok(TestResponse {
            status: parts.status,
            headers: parts.headers,
            bytes,
        })
    }
}

pub struct TestResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub bytes: axum::body::Bytes,
}

impl TestResponse {
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    pub fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    pub async fn text(self) -> Result<String, String> {
        String::from_utf8(self.bytes.to_vec()).map_err(|e| e.to_string())
    }

    pub async fn json<T: serde::de::DeserializeOwned>(self) -> Result<T, String> {
        serde_json::from_slice(&self.bytes).map_err(|e| e.to_string())
    }
}

pub struct TestServer {
    pub app: Router,
    pub base_url: String,
}

impl std::ops::Deref for TestServer {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.base_url
    }
}

impl std::fmt::Display for TestServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base_url)
    }
}

impl TestServer {
    pub fn client(&self) -> TestClient {
        TestClient {
            app: self.app.clone(),
            cookie_store: false,
            cookies: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn cookie_client(&self) -> TestClient {
        TestClient {
            app: self.app.clone(),
            cookie_store: true,
            cookies: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }
}

async fn start_test_server() -> (TestServer, Arc<AuthService>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"axum-wire-compat-secret-32-bytes-long".to_vec(),
        base_url: "http://127.0.0.1:54321/api/auth".to_string(),
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
    let mut mock_google = OAuthProviderConfig::google("mock_client_id", "mock_client_secret");
    mock_google.token_url = "mock://google/token".to_string();
    let state = AuthState::new(Arc::clone(&service)).with_oauth_provider(mock_google);

    let app = Router::new().nest("/api/auth", auth_router(state));
    let base_url = "http://127.0.0.1:54321/api/auth".to_string();

    (TestServer { app, base_url }, service)
}

#[tokio::test]
async fn test_ok_endpoint() {
    let (server, _) = start_test_server().await;
    let client = server.client();

    let res = client.get(format!("{server}/ok")).send().await.unwrap();

    assert_eq!(res.status(), 200);
    let body: OkResponse = res.json().await.unwrap();
    assert!(body.ok);
}

#[tokio::test]
async fn test_unauthenticated_get_session_returns_null() {
    let (server, _) = start_test_server().await;
    let client = server.client();

    let res = client
        .get(format!("{server}/get-session"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body_text = res.text().await.unwrap();
    assert_eq!(body_text.trim(), "null");
}

#[tokio::test]
async fn test_sign_up_and_cookie_flow() {
    let (server, _) = start_test_server().await;
    let client = server.cookie_client();

    // 1. Sign up
    let res = client
        .post(format!("{server}/sign-up/email"))
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
        .get(format!("{server}/get-session"))
        .send()
        .await
        .unwrap();

    assert_eq!(session_res.status(), 200);
    let session_data: SessionAndUserResponse = session_res.json().await.unwrap();
    assert_eq!(session_data.user.email, "webuser@example.com");

    // 3. GET /list-sessions
    let list_res = client
        .get(format!("{server}/list-sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), 200);
    let sessions: Vec<serde_json::Value> = list_res.json().await.unwrap();
    assert_eq!(sessions.len(), 1);

    // 4. Sign out -> clears cookie and deletes session
    let signout_res = client
        .post(format!("{server}/sign-out"))
        .send()
        .await
        .unwrap();
    assert_eq!(signout_res.status(), 200);

    // 5. Subsequent get-session returns null
    let unauth_res = client
        .get(format!("{server}/get-session"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), 200);
    assert_eq!(unauth_res.text().await.unwrap().trim(), "null");
}

#[tokio::test]
async fn test_bearer_token_flow_desktop_parity() {
    let (server, _) = start_test_server().await;
    let client = server.client();

    // 1. Sign in (first create user)
    let signup_res = client
        .post(format!("{server}/sign-up/email"))
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
        .get(format!("{server}/get-session"))
        .header("authorization", format!("Bearer {desktop_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(get_session_res.status(), 200);
    let session_data: SessionAndUserResponse = get_session_res.json().await.unwrap();
    assert_eq!(session_data.user.email, "desktop@example.com");

    // 3. One-Time Token handoff flow via Bearer token
    let ott_gen_res = client
        .get(format!("{server}/one-time-token/generate"))
        .header("authorization", format!("Bearer {desktop_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(ott_gen_res.status(), 200);
    let ott_body: OneTimeTokenGenerateResponse = ott_gen_res.json().await.unwrap();

    // 4. Verify OTT from a fresh unauthenticated client
    let ott_verify_res = client
        .post(format!("{server}/one-time-token/verify"))
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
    let (server, service) = start_test_server().await;
    let client = server.client();

    // 1. Web browser redirect (http://localhost:5173) must NOT leak ?token=<ott>
    let init_web: SignInSocialResponse = client
        .post(format!("{server}/sign-in/social"))
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
            "{server}/callback/google?code=fixed_web1&state={state_param}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb_web.status(), 307);
    let loc_web = cb_web.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(loc_web, "http://localhost:5173");

    // 2. Desktop loopback redirect (/auth/callback) MUST append ?token=<ott>
    let init_desktop: SignInSocialResponse = client
        .post(format!("{server}/sign-in/social"))
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
            "{server}/callback/google?code=fixed_web1&state={state_desktop}"
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
            role: None,
        })
        .await
        .unwrap();

    let init_unverified: SignInSocialResponse = client
        .post(format!("{server}/sign-in/social"))
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
            "{server}/callback/google?code=fixed_unverified_victim&state={state_unverified}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cb_unverified.status(), 403);
}

#[tokio::test]
async fn test_admin_http_endpoints_and_cookie_impersonation() {
    let (server, service) = start_test_server().await;
    let client = server.cookie_client();

    // 1. Register admin user and promote to "admin"
    let admin_signup: SignUpResponse = client
        .post(format!("{server}/sign-up/email"))
        .json(&serde_json::json!({
            "name": "Root Admin",
            "email": "root@example.com",
            "password": "rootpassword123"
        }))
        .send()
        .await
        .unwrap()
        .json()
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

    // 2. POST /admin/create-user
    let create_res = client
        .post(format!("{server}/admin/create-user"))
        .json(&serde_json::json!({
            "name": "Created By Admin",
            "email": "created@example.com",
            "password": "createdpass123",
            "role": "user"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), 200);
    let created_user: AdminUserResponse = create_res.json().await.unwrap();
    assert_eq!(created_user.user.email, "created@example.com");

    // 3. GET /admin/list-users
    let list_res: AdminListUsersResponse = client
        .get(format!("{server}/admin/list-users?searchValue=created@"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list_res.total, 1);

    // 4. POST /admin/has-permission
    let perm_res: AdminPermissionResponse = client
        .post(format!("{server}/admin/has-permission"))
        .json(&serde_json::json!({
            "permissions": {
                "user": ["create", "ban", "impersonate"]
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(perm_res.success);

    // 5. POST /admin/impersonate-user -> switches cookie session to target user
    let imp_res = client
        .post(format!("{server}/admin/impersonate-user"))
        .json(&serde_json::json!({
            "userId": created_user.user.id
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(imp_res.status(), 200);

    let active_ses: SessionAndUserResponse = client
        .get(format!("{server}/get-session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(active_ses.user.id, created_user.user.id);
    assert_eq!(
        active_ses.session.impersonated_by.as_deref(),
        Some(admin_signup.user.id.as_str())
    );

    // 6. POST /admin/stop-impersonating -> restores Root Admin cookie session
    let stop_res = client
        .post(format!("{server}/admin/stop-impersonating"))
        .send()
        .await
        .unwrap();
    assert_eq!(stop_res.status(), 200);

    let restored_ses: SessionAndUserResponse = client
        .get(format!("{server}/get-session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restored_ses.user.id, admin_signup.user.id);
    assert!(restored_ses.session.impersonated_by.is_none());

    // 7. Security: Unauthenticated POST /admin/has-permission rejected with 401
    let unauth_client = server.client();
    let unauth_perm = unauth_client
        .post(format!("{server}/admin/has-permission"))
        .json(&serde_json::json!({
            "userId": created_user.user.id,
            "permissions": { "user": ["create"] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_perm.status(), http::StatusCode::UNAUTHORIZED);

    // 8. Wire Parity: POST /get-session returns 405 Method Not Allowed without deferSessionRefresh
    let post_sess = client
        .post(format!("{server}/get-session"))
        .send()
        .await
        .unwrap();
    assert_eq!(post_sess.status(), http::StatusCode::METHOD_NOT_ALLOWED);

    // 9. Wire Parity: POST /delete-user returns { "success": true, "message": "User deleted" }
    let del_res = client
        .post(format!("{server}/delete-user"))
        .json(&serde_json::json!({
            "password": "rootpassword123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(del_res.status(), http::StatusCode::OK);
    let del_json: serde_json::Value = del_res.json().await.unwrap();
    assert_eq!(del_json["success"], true);
    assert_eq!(del_json["message"], "User deleted");
}
