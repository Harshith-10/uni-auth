use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt;

use auth_axum::extract::{IpCidr, extract_client_ip};
use auth_axum::middleware::{is_loopback_url, validate_callback_url};
use auth_axum::{AuthState, OAuthProviderConfig, auth_router};
use auth_core::models::{CreateSessionInput, CreateUserInput, CreateVerificationInput};
use auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};
use auth_proto::{
    ChangeEmailRequest, SetPasswordRequest, SignUpResponse, UpdateSessionRequest,
    UpdateSessionResponse, VerifyPasswordRequest,
};
use axum::Router;

#[derive(Clone)]
pub struct TestClient {
    pub app: Router,
    pub cookie_store: bool,
    pub cookies: Arc<std::sync::Mutex<HashMap<String, String>>>,
    pub custom_headers: HashMap<String, String>,
}

impl TestClient {
    pub fn get(&self, uri: impl Into<String>) -> TestRequestBuilder {
        TestRequestBuilder::new(self.clone(), http::Method::GET, uri.into())
    }

    pub fn post(&self, uri: impl Into<String>) -> TestRequestBuilder {
        TestRequestBuilder::new(self.clone(), http::Method::POST, uri.into())
    }

    pub fn with_header(mut self, name: impl Into<String>, val: impl Into<String>) -> Self {
        self.custom_headers.insert(name.into(), val.into());
        self
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
        let mut headers = http::HeaderMap::new();
        for (k, v) in &client.custom_headers {
            if let (Ok(hname), Ok(hval)) = (
                http::header::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.insert(hname, hval);
            }
        }
        Self {
            client,
            method,
            uri,
            headers,
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
            custom_headers: HashMap::new(),
        }
    }

    pub fn cookie_client(&self) -> TestClient {
        TestClient {
            app: self.app.clone(),
            cookie_store: true,
            cookies: Arc::new(std::sync::Mutex::new(HashMap::new())),
            custom_headers: HashMap::new(),
        }
    }
}

async fn start_secondary_test_server() -> (TestServer, Arc<AuthService>) {
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let config = AuthConfig {
        secret: b"secondary-routes-test-secret-32-long".to_vec(),
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
    let mut mock_github = OAuthProviderConfig::github("mock_client_id", "mock_client_secret");
    mock_github.token_url = "mock://github/token".to_string();
    let state = AuthState::new(Arc::clone(&service))
        .with_oauth_provider(mock_github)
        .with_trusted_origins(["http://localhost:3000", "http://127.0.0.1:*"]);

    let app = Router::new().nest("/api/auth", auth_router(state));
    let base_url = "http://127.0.0.1:54321/api/auth".to_string();

    (TestServer { app, base_url }, service)
}

#[tokio::test]
async fn test_trusted_proxy_cidr_validation() {
    let mut headers = http::HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.195, 198.51.100.1".parse().unwrap());

    let trusted: Vec<IpCidr> = vec![
        "10.0.0.0/8".parse().unwrap(),
        "127.0.0.1/32".parse().unwrap(),
    ];

    // Case 1: Untrusted peer IP -> ignored, returns peer IP
    let peer_untrusted: IpAddr = "192.168.1.100".parse().unwrap();
    let client_ip = extract_client_ip(&headers, Some(peer_untrusted), &trusted);
    assert_eq!(client_ip, Some("192.168.1.100".to_string()));

    // Case 2: Trusted peer IP -> accepted, returns forwarded IP
    let peer_trusted: IpAddr = "10.1.2.3".parse().unwrap();
    let client_ip = extract_client_ip(&headers, Some(peer_trusted), &trusted);
    assert_eq!(client_ip, Some("203.0.113.195".to_string()));
}

#[tokio::test]
async fn test_loopback_wildcard_port_validation() {
    // 1. URL helper validation
    assert!(is_loopback_url("http://127.0.0.1:54321/auth/callback"));
    assert!(is_loopback_url("http://localhost:8080/callback"));
    assert!(is_loopback_url("http://[::1]:9000/auth"));
    assert!(!is_loopback_url("https://127.0.0.1:54321/auth/callback")); // non-http rejected
    assert!(!is_loopback_url("http://evil.com/auth/callback"));

    // 2. Wildcard pattern matching in callback URLs
    let trusted = vec![
        "http://localhost:3000".to_string(),
        "http://127.0.0.1:*".to_string(),
        "http://localhost:*".to_string(),
    ];

    assert!(validate_callback_url("http://127.0.0.1:49152/auth/callback", &trusted).is_ok());
    assert!(validate_callback_url("http://localhost:59999/auth/callback", &trusted).is_ok());
    assert!(validate_callback_url("http://localhost:3000/dashboard", &trusted).is_ok());
    assert!(validate_callback_url("http://evil.com/auth/callback", &trusted).is_err());
}

#[tokio::test]
async fn test_set_and_verify_password_endpoints() {
    let (server, service) = start_secondary_test_server().await;

    // 1. Create a passwordless OAuth user directly in adapter
    let user = service
        .adapter()
        .create_user(CreateUserInput {
            id: None,
            name: "OAuth User".to_string(),
            email: "oauthuser@example.com".to_string(),
            image: None,
            email_verified: true,
            role: None,
        })
        .await
        .unwrap();

    let session = service
        .adapter()
        .create_session(CreateSessionInput {
            id: None,
            user_id: user.id.clone(),
            token: "tok_test_passwordless_123".to_string(),
            expires_at: time::OffsetDateTime::now_utc() + Duration::days(7),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    let client = server
        .client()
        .with_header("authorization", format!("Bearer {}", session.token));

    // 2. POST /set-password
    let set_res = client
        .post(format!("{server}/set-password"))
        .json(&SetPasswordRequest {
            new_password: "fresh-new-password-123".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(set_res.status(), 200);

    // 3. POST /verify-password with correct password -> 200 OK
    let verify_res = client
        .post(format!("{server}/verify-password"))
        .json(&VerifyPasswordRequest {
            password: "fresh-new-password-123".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(verify_res.status(), 200);

    // 4. POST /verify-password with wrong password -> 400 Bad Request
    let wrong_res = client
        .post(format!("{server}/verify-password"))
        .json(&VerifyPasswordRequest {
            password: "wrong-password-guess".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(wrong_res.status(), 400);
}

#[tokio::test]
async fn test_change_email_and_update_session_endpoints() {
    let (server, _) = start_secondary_test_server().await;
    let client = server.cookie_client();

    // 1. Sign up
    let signup_res = client
        .post(format!("{server}/sign-up/email"))
        .json(&serde_json::json!({
            "name": "Change User",
            "email": "initial@example.com",
            "password": "initialpassword123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(signup_res.status(), 200);
    let signup_user: SignUpResponse = signup_res.json().await.unwrap();

    // 2. POST /change-email
    let change_email_res = client
        .post(format!("{server}/change-email"))
        .json(&ChangeEmailRequest {
            new_email: "updated@example.com".to_string(),
            callback_url: Some("http://localhost:3000/settings".to_string()),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(change_email_res.status(), 200);

    // 3. POST /update-session
    let update_sess_res = client
        .post(format!("{server}/update-session"))
        .json(&UpdateSessionRequest::default())
        .send()
        .await
        .unwrap();
    assert_eq!(update_sess_res.status(), 200);
    let sess_data: UpdateSessionResponse = update_sess_res.json().await.unwrap();
    assert_eq!(sess_data.session.user_id, signup_user.user.id);
}

#[tokio::test]
async fn test_delete_user_callback_flow() {
    let (server, service) = start_secondary_test_server().await;
    let client = server.cookie_client();

    // 1. Sign up
    let signup: SignUpResponse = client
        .post(format!("{server}/sign-up/email"))
        .json(&serde_json::json!({
            "name": "Deletable User",
            "email": "deletable@example.com",
            "password": "deletablepass123"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // 2. Generate delete-user confirmation token in database
    let delete_token = "del_token_xyz_123";
    service
        .adapter()
        .create_verification(CreateVerificationInput {
            id: None,
            identifier: format!("delete-account-{delete_token}"),
            value: signup.user.id.clone(),
            expires_at: time::OffsetDateTime::now_utc() + Duration::hours(1),
        })
        .await
        .unwrap();

    // 3. GET /delete-user/callback
    let cb_res = client
        .get(format!(
            "{server}/delete-user/callback?token={delete_token}&callbackURL=http://localhost:3000/goodbye"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(cb_res.status(), 307);
    let loc = cb_res.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(loc, "http://localhost:3000/goodbye");

    // 4. Verify user was actually deleted
    let user_check = service.adapter().find_user_by_id(&signup.user.id).await.unwrap();
    assert!(user_check.is_none());
}

#[tokio::test]
async fn test_error_endpoint_rendering() {
    let (server, _) = start_secondary_test_server().await;
    let client = server.client();

    let res = client
        .get(format!(
            "{server}/error?error=TEST_ERROR_CODE&error_description=Invalid+Credentials+Provided"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let html = res.text().await.unwrap();
    assert!(html.contains("TEST_ERROR_CODE"));
    assert!(html.contains("Invalid Credentials Provided"));
}
