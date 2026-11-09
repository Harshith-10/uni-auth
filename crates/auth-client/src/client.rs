//! High-level native HTTP client with automated Bearer token attachment and response capture.

use std::sync::Arc;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use thiserror::Error;

use auth_proto::{
    AuthErrorResponse, OneTimeTokenGenerateResponse, OneTimeTokenVerifyRequest,
    RevokeSessionRequest, SessionAndUserResponse, SessionWire, SignInEmailRequest, SignInResponse,
    SignOutResponse, SignUpEmailRequest, SignUpResponse, StatusResponse,
};
use crate::storage::{StorageError, TokenStorage};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Server returned error: [{status}] {code:?}: {message}")]
    Api {
        status: u16,
        code: Option<String>,
        message: String,
    },

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("OAuth error: {0}")]
    OAuth(String),
}

/// Native Better Auth client designed for desktop and mobile applications.
///
/// Features:
/// - Automatically injects `Authorization: Bearer <token>` from secure storage.
/// - Automatically intercepts `set-auth-token` response headers and updates the storage.
/// - Automatically clears token storage upon `sign_out()`.
#[derive(Clone)]
pub struct BetterAuthNativeClient {
    pub(crate) base_url: String,
    pub(crate) http: reqwest::Client,
    pub(crate) storage: Arc<dyn TokenStorage>,
}

impl BetterAuthNativeClient {
    /// Initializes a new native auth client.
    ///
    /// # Arguments
    /// - `base_url`: Root auth endpoint (e.g., `http://127.0.0.1:3000/api/auth`).
    /// - `storage`: Backend implementing `TokenStorage` (e.g. `KeyringTokenStorage` or `MockTokenStorage`).
    pub fn new(base_url: impl Into<String>, storage: Arc<dyn TokenStorage>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("Failed to build reqwest HTTP client");

        Self {
            base_url,
            http,
            storage,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn storage(&self) -> &Arc<dyn TokenStorage> {
        &self.storage
    }

    /// Captures the `set-auth-token` response header and saves it to storage.
    fn handle_auth_token_header(&self, headers: &HeaderMap) {
        if let Some(token_header) = headers.get("set-auth-token") {
            if let Ok(token_str) = token_header.to_str() {
                let token = decode_if_percent_encoded(token_str.trim());
                if !token.is_empty() {
                    let _ = self.storage.set_token(&token);
                }
            }
        }
    }

    /// Prepares request headers with `Authorization: Bearer <token>` if a token is present in storage.
    fn prepare_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Ok(Some(token)) = self.storage.get_token() {
            let auth_val = format!("Bearer {token}");
            if let Ok(header_val) = HeaderValue::from_str(&auth_val) {
                headers.insert(AUTHORIZATION, header_val);
            }
        }

        headers
    }

    // ──────────────────────────────────────────────
    // Authentication Operations
    // ──────────────────────────────────────────────

    /// Signs up a new user using email and password.
    pub async fn sign_up_email(
        &self,
        name: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
        remember_me: Option<bool>,
    ) -> Result<SignUpResponse, ClientError> {
        let payload = SignUpEmailRequest {
            name: name.into(),
            email: email.into(),
            password: password.into(),
            image: None,
            callback_url: None,
            remember_me,
        };

        let res = self
            .http
            .post(format!("{}/sign-up/email", self.base_url))
            .headers(self.prepare_headers())
            .json(&payload)
            .send()
            .await?;

        self.handle_auth_token_header(res.headers());

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("SIGN_UP_FAILED", "Failed to sign up").with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let body: SignUpResponse = res.json().await?;
        if let Some(ref token) = body.token {
            let _ = self.storage.set_token(token);
        }

        Ok(body)
    }

    /// Signs in an existing user using email and password.
    pub async fn sign_in_email(
        &self,
        email: impl Into<String>,
        password: impl Into<String>,
        remember_me: Option<bool>,
    ) -> Result<SignInResponse, ClientError> {
        let payload = SignInEmailRequest {
            email: email.into(),
            password: password.into(),
            callback_url: None,
            remember_me,
        };

        let res = self
            .http
            .post(format!("{}/sign-in/email", self.base_url))
            .headers(self.prepare_headers())
            .json(&payload)
            .send()
            .await?;

        self.handle_auth_token_header(res.headers());

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("SIGN_IN_FAILED", "Invalid credentials").with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let body: SignInResponse = res.json().await?;
        let _ = self.storage.set_token(&body.token);

        Ok(body)
    }

    /// Retrieves the current session and user details.
    /// Returns `None` if unauthenticated or session has expired.
    pub async fn get_session(&self) -> Result<Option<SessionAndUserResponse>, ClientError> {
        let res = self
            .http
            .get(format!("{}/get-session", self.base_url))
            .headers(self.prepare_headers())
            .send()
            .await?;

        let status = res.status().as_u16();
        if status >= 400 {
            return Ok(None);
        }

        let text = res.text().await?;
        if text.trim() == "null" || text.trim().is_empty() {
            return Ok(None);
        }

        let session: SessionAndUserResponse = serde_json::from_str(&text)?;
        Ok(Some(session))
    }

    /// Lists active sessions for the current user.
    pub async fn list_sessions(&self) -> Result<Vec<SessionWire>, ClientError> {
        let res = self
            .http
            .get(format!("{}/list-sessions", self.base_url))
            .headers(self.prepare_headers())
            .send()
            .await?;

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("LIST_SESSIONS_FAILED", "Failed to list sessions")
                    .with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let sessions: Vec<SessionWire> = res.json().await?;
        Ok(sessions)
    }

    /// Revokes a specific session by token.
    pub async fn revoke_session(&self, token: &str) -> Result<StatusResponse, ClientError> {
        let res = self
            .http
            .post(format!("{}/revoke-session", self.base_url))
            .headers(self.prepare_headers())
            .json(&RevokeSessionRequest {
                token: token.to_string(),
            })
            .send()
            .await?;

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("REVOKE_SESSION_FAILED", "Failed to revoke session")
                    .with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let body: StatusResponse = res.json().await?;
        Ok(body)
    }

    /// Signs out the user, invalidates the remote session, and clears local token storage.
    pub async fn sign_out(&self) -> Result<SignOutResponse, ClientError> {
        let res = self
            .http
            .post(format!("{}/sign-out", self.base_url))
            .headers(self.prepare_headers())
            .send()
            .await?;

        // Always delete local token regardless of server response
        let _ = self.storage.delete_token();

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("SIGN_OUT_FAILED", "Sign out error").with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let body: SignOutResponse = res.json().await?;
        Ok(body)
    }

    // ──────────────────────────────────────────────
    // One-Time Token (OTT) Operations
    // ──────────────────────────────────────────────

    /// Generates a single-use 3-minute token from the current session.
    pub async fn generate_one_time_token(&self) -> Result<OneTimeTokenGenerateResponse, ClientError> {
        let res = self
            .http
            .get(format!("{}/one-time-token/generate", self.base_url))
            .headers(self.prepare_headers())
            .send()
            .await?;

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("OTT_GENERATE_FAILED", "Failed to generate token")
                    .with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let body: OneTimeTokenGenerateResponse = res.json().await?;
        Ok(body)
    }

    /// Verifies a one-time token and establishes a new session in storage.
    pub async fn verify_one_time_token(
        &self,
        token: &str,
    ) -> Result<SessionAndUserResponse, ClientError> {
        let res = self
            .http
            .post(format!("{}/one-time-token/verify", self.base_url))
            .json(&OneTimeTokenVerifyRequest {
                token: token.to_string(),
            })
            .send()
            .await?;

        self.handle_auth_token_header(res.headers());

        let status = res.status().as_u16();
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("OTT_VERIFY_FAILED", "Invalid or expired token")
                    .with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let body: SessionAndUserResponse = res.json().await?;

        // If set-auth-token header was present, it was saved above.
        // Otherwise, save session token directly:
        if self.storage.get_token()?.is_none() {
            let _ = self.storage.set_token(&body.session.token);
        }

        Ok(body)
    }

    /// Custom authenticated request helper for calling application-specific protected APIs.
    ///
    /// Automatically injects `Authorization: Bearer <token>`.
    pub async fn fetch_protected<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, ClientError> {
        let mut builder = self.http.request(method, url).headers(self.prepare_headers());

        if let Some(b) = body {
            builder = builder.json(&b);
        }

        let res = builder.send().await?;
        let status = res.status().as_u16();

        if status >= 400 {
            let text = res.text().await.unwrap_or_default();
            return Err(ClientError::Api {
                status,
                code: None,
                message: text,
            });
        }

        let parsed: T = res.json().await?;
        Ok(parsed)
    }
}

fn decode_if_percent_encoded(s: &str) -> String {
    if s.contains('%') {
        urlencoding_decode(s).unwrap_or_else(|| s.to_string())
    } else {
        s.to_string()
    }
}

fn urlencoding_decode(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next()?;
            let h2 = chars.next()?;
            let val = hex_val(h1)? * 16 + hex_val(h2)?;
            bytes.push(val);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
