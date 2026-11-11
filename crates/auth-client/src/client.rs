//! High-level native HTTP client with automated Bearer token attachment and response capture.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use thiserror::Error;

use auth_proto::access::Connector;
use auth_proto::{
    AccountListEntryWire, AdminCreateUserRequest, AdminHasPermissionRequest, AdminListUsersQuery,
    AdminListUsersResponse, AdminPermissionResponse, AdminSuccessResponse, AdminUpdateUserRequest,
    AdminUserResponse, ChangePasswordRequest, DeleteUserRequest, DeleteUserResponse,
    OneTimeTokenGenerateResponse, RequestPasswordResetRequest, ResetPasswordRequest,
    RevokeSessionRequest, RoleValue, SendVerificationEmailRequest, SessionAndUserResponse,
    SessionWire, SignInEmailRequest, SignInResponse, SignInSocialRequest, SignInSocialResponse,
    SignOutResponse, SignUpEmailRequest, SignUpResponse, StatusResponse, UnlinkAccountRequest,
    UpdateUserRequest, UserWire, VerifyEmailResponse,
};

use crate::plugin::{AuthClientPlugin, SESSION_SIGNAL, matches_core_session_signal};
use crate::plugins::{
    AdminClientExt, AdminClientPlugin, OneTimeTokenClientExt, OneTimeTokenClientPlugin,
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

type SignalSubscriber = Box<dyn Fn(&str) + Send + Sync + 'static>;

/// Native Better Auth client designed for desktop and mobile applications.
///
/// Features:
/// - Automated Bearer token injection (`Authorization: Bearer <token>`).
/// - Automated `set-auth-token` response header capture across all endpoints.
/// - Client plugin ecosystem (`AuthClientPlugin`) with interceptors and typed extensions (`client.admin()`, `client.one_time_token()`).
/// - Reactive `$sessionSignal` listeners for automatic store updates.
#[derive(Clone)]
pub struct BetterAuthNativeClient {
    pub(crate) base_url: String,
    pub(crate) http: reqwest::Client,
    pub(crate) storage: Arc<dyn TokenStorage>,
    pub(crate) plugins: Vec<Arc<dyn AuthClientPlugin>>,
    pub(crate) signal_subscribers: Arc<RwLock<Vec<SignalSubscriber>>>,
}

impl BetterAuthNativeClient {
    /// Initializes a new native auth client with default `AdminClientPlugin` and `OneTimeTokenClientPlugin`.
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
            plugins: vec![
                Arc::new(AdminClientPlugin::default()),
                Arc::new(OneTimeTokenClientPlugin),
            ],
            signal_subscribers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Attaches an `AuthClientPlugin` to the client.
    pub fn with_plugin<P: AuthClientPlugin>(mut self, plugin: P) -> Self {
        self.plugins.push(Arc::new(plugin));
        self
    }

    /// Attaches an `Arc<dyn AuthClientPlugin>` to the client.
    pub fn with_plugin_arc(mut self, plugin: Arc<dyn AuthClientPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    pub fn plugins(&self) -> &[Arc<dyn AuthClientPlugin>] {
        &self.plugins
    }

    /// Retrieves a registered `AuthClientPlugin` by type.
    pub fn get_plugin<P: AuthClientPlugin>(&self) -> Option<&P> {
        self.plugins
            .iter()
            .find_map(|p| p.as_any().downcast_ref::<P>())
    }

    /// Subscribes to reactive signals emitted by this client (e.g. `$sessionSignal`).
    pub fn subscribe_signal<F: Fn(&str) + Send + Sync + 'static>(&self, listener: F) {
        if let Ok(mut subs) = self.signal_subscribers.write() {
            subs.push(Box::new(listener));
        }
    }

    pub(crate) async fn notify_matching_signals(&self, path: &str) {
        let is_session_signal = matches_core_session_signal(path)
            || self.plugins.iter().any(|p| {
                p.signal_listeners()
                    .iter()
                    .any(|l| l.signal == SESSION_SIGNAL && (l.matcher)(path))
            });

        if is_session_signal {
            if let Ok(subs) = self.signal_subscribers.read() {
                for sub in subs.iter() {
                    sub(SESSION_SIGNAL);
                }
            }
        }

        for p in &self.plugins {
            for l in p.signal_listeners() {
                if l.signal != SESSION_SIGNAL && (l.matcher)(path) {
                    if let Ok(subs) = self.signal_subscribers.read() {
                        for sub in subs.iter() {
                            sub(l.signal);
                        }
                    }
                }
            }
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn storage(&self) -> &Arc<dyn TokenStorage> {
        &self.storage
    }

    /// Captures the `set-auth-token` response header and saves it to storage.
    pub(crate) fn handle_auth_token_header(&self, headers: &HeaderMap) -> bool {
        if let Some(token_header) = headers.get("set-auth-token") {
            if let Ok(token_str) = token_header.to_str() {
                let token = auth_proto::url_decode(token_str.trim());
                if !token.is_empty() {
                    let _ = self.storage.set_token(&token);
                    return true;
                }
            }
        }
        false
    }

    /// Prepares request headers with `Authorization: Bearer <token>` if a token is present in storage.
    pub(crate) fn prepare_headers(&self) -> HeaderMap {
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

    /// Executes a request to an arbitrary protected endpoint (e.g. `/api/saas/me`),
    /// automatically injecting `Authorization: Bearer <token>` and intercepting `set-auth-token`.
    pub async fn fetch_protected<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, ClientError> {
        let mut builder = self
            .http
            .request(method, url)
            .headers(self.prepare_headers());

        if let Some(b) = body {
            builder = builder.json(&b);
        }

        let res = builder.send().await?;
        self.handle_auth_token_header(res.headers());

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

    // ──────────────────────────────────────────────
    // Core Authentication Endpoints
    // ──────────────────────────────────────────────

    /// Signs up a new user using email and password.
    pub async fn sign_up_email(
        &self,
        name: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
        remember_me: Option<bool>,
    ) -> Result<SignUpResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/sign-up/email",
            None::<&()>,
            Some(&SignUpEmailRequest {
                name: name.into(),
                email: email.into(),
                password: password.into(),
                image: None,
                callback_url: None,
                remember_me,
            }),
        )
        .await
    }

    /// Signs in an existing user with email and password.
    pub async fn sign_in_email(
        &self,
        email: impl Into<String>,
        password: impl Into<String>,
        remember_me: Option<bool>,
    ) -> Result<SignInResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/sign-in/email",
            None::<&()>,
            Some(&SignInEmailRequest {
                email: email.into(),
                password: password.into(),
                callback_url: None,
                remember_me,
            }),
        )
        .await
    }

    /// Retrieves the active user session and user record.
    pub async fn get_session(&self) -> Result<Option<SessionAndUserResponse>, ClientError> {
        self.send_auth_request(Method::GET, "/get-session", None::<&()>, None::<&()>)
            .await
    }

    /// Lists active sessions for the currently authenticated user.
    pub async fn list_sessions(&self) -> Result<Vec<SessionWire>, ClientError> {
        self.send_auth_request(Method::GET, "/list-sessions", None::<&()>, None::<&()>)
            .await
    }

    /// Revokes a specific session by token or session ID.
    pub async fn revoke_session(
        &self,
        session_token: impl Into<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/revoke-session",
            None::<&()>,
            Some(&RevokeSessionRequest {
                token: session_token.into(),
            }),
        )
        .await
    }

    /// Revokes all active sessions for the currently authenticated user.
    pub async fn revoke_sessions(&self) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(Method::POST, "/revoke-sessions", None::<&()>, None::<&()>)
            .await
    }

    /// Revokes all sessions belonging to the current user EXCEPT the current session.
    pub async fn revoke_other_sessions(&self) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/revoke-other-sessions",
            None::<&()>,
            None::<&()>,
        )
        .await
    }

    /// Signs out the current user and clears the token from storage.
    pub async fn sign_out(&self) -> Result<SignOutResponse, ClientError> {
        let res = self
            .send_auth_request(Method::POST, "/sign-out", None::<&()>, None::<&()>)
            .await;
        let _ = self.storage.delete_token();
        res
    }

    /// Changes user password, optionally revoking other sessions.
    pub async fn change_password(
        &self,
        current_password: impl Into<String>,
        new_password: impl Into<String>,
        revoke_other_sessions: Option<bool>,
    ) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/change-password",
            None::<&()>,
            Some(&ChangePasswordRequest {
                current_password: current_password.into(),
                new_password: new_password.into(),
                revoke_other_sessions,
            }),
        )
        .await
    }

    /// Updates the current user's profile information (name and/or image).
    pub async fn update_user(
        &self,
        name: Option<String>,
        image: Option<Option<String>>,
    ) -> Result<UserWire, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/update-user",
            None::<&()>,
            Some(&UpdateUserRequest {
                name,
                image,
                extra: serde_json::Map::new(),
            }),
        )
        .await
    }

    /// Deletes the current user account and clears secure storage.
    pub async fn delete_user(
        &self,
        password: Option<String>,
        callback_url: Option<String>,
    ) -> Result<DeleteUserResponse, ClientError> {
        let res = self
            .send_auth_request(
                Method::POST,
                "/delete-user",
                None::<&()>,
                Some(&DeleteUserRequest {
                    password,
                    callback_url,
                }),
            )
            .await;
        if res.is_ok() {
            let _ = self.storage.delete_token();
        }
        res
    }

    /// Initiates a password reset email request.
    pub async fn request_password_reset(
        &self,
        email: impl Into<String>,
        redirect_to: Option<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/request-password-reset",
            None::<&()>,
            Some(&RequestPasswordResetRequest {
                email: email.into(),
                redirect_to,
            }),
        )
        .await
    }

    /// Resets a password using a verification token received via email.
    pub async fn reset_password(
        &self,
        new_password: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/reset-password",
            None::<&()>,
            Some(&ResetPasswordRequest {
                new_password: new_password.into(),
                token: Some(token.into()),
            }),
        )
        .await
    }

    /// Sends or re-sends an email verification email to the current user.
    pub async fn send_verification_email(
        &self,
        email: impl Into<String>,
        callback_url: Option<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/send-verification-email",
            None::<&()>,
            Some(&SendVerificationEmailRequest {
                email: email.into(),
                callback_url,
            }),
        )
        .await
    }

    /// Verifies an email address using a verification token.
    pub async fn verify_email(
        &self,
        token: impl Into<String>,
        callback_url: Option<String>,
    ) -> Result<VerifyEmailResponse, ClientError> {
        #[derive(serde::Serialize)]
        struct VerifyEmailQuery {
            token: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            callback_url: Option<String>,
        }
        self.send_auth_request(
            Method::GET,
            "/verify-email",
            Some(&VerifyEmailQuery {
                token: token.into(),
                callback_url,
            }),
            None::<&()>,
        )
        .await
    }

    /// Lists connected OAuth accounts for the current user.
    pub async fn list_accounts(&self) -> Result<Vec<AccountListEntryWire>, ClientError> {
        self.send_auth_request(Method::GET, "/list-accounts", None::<&()>, None::<&()>)
            .await
    }

    /// Unlinks a connected OAuth account.
    pub async fn unlink_account(
        &self,
        provider_id: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/unlink-account",
            None::<&()>,
            Some(&UnlinkAccountRequest {
                provider_id: provider_id.into(),
                account_id: Some(account_id.into()),
            }),
        )
        .await
    }

    /// Initiates a social account link.
    pub async fn link_social(
        &self,
        provider: impl Into<String>,
        callback_url: Option<String>,
    ) -> Result<SignInSocialResponse, ClientError> {
        self.send_auth_request(
            Method::POST,
            "/link-social",
            None::<&()>,
            Some(&SignInSocialRequest {
                provider: provider.into(),
                callback_url,
                error_callback_url: None,
                disable_redirect: Some(true),
                ..Default::default()
            }),
        )
        .await
    }

    // ──────────────────────────────────────────────
    // Legacy Delegating Methods (For Full Backward Compatibility)
    // ──────────────────────────────────────────────

    /// Generates a single-use one-time token (OTT).
    pub async fn generate_one_time_token(
        &self,
    ) -> Result<OneTimeTokenGenerateResponse, ClientError> {
        self.one_time_token().generate().await
    }

    /// Exchanges an OTT for an authenticated session.
    pub async fn verify_one_time_token(
        &self,
        token: impl Into<String>,
    ) -> Result<SessionAndUserResponse, ClientError> {
        self.one_time_token().verify(token).await
    }

    pub async fn admin_list_users(
        &self,
        query: &AdminListUsersQuery,
    ) -> Result<AdminListUsersResponse, ClientError> {
        self.admin().list_users(query).await
    }

    pub async fn admin_create_user(
        &self,
        req: AdminCreateUserRequest,
    ) -> Result<AdminUserResponse, ClientError> {
        self.admin().create_user(req).await
    }

    pub async fn admin_set_role(
        &self,
        user_id: impl Into<String>,
        role: impl Into<RoleValue>,
    ) -> Result<AdminUserResponse, ClientError> {
        self.admin().set_role(user_id, role).await
    }

    pub async fn admin_get_user(&self, id: impl Into<String>) -> Result<UserWire, ClientError> {
        self.admin().get_user(id).await
    }

    pub async fn admin_update_user(
        &self,
        req: AdminUpdateUserRequest,
    ) -> Result<UserWire, ClientError> {
        self.admin().update_user(req).await
    }

    pub async fn admin_ban_user(
        &self,
        user_id: impl Into<String>,
        ban_reason: Option<String>,
        ban_expires_in: Option<i64>,
    ) -> Result<AdminUserResponse, ClientError> {
        self.admin()
            .ban_user(user_id, ban_reason, ban_expires_in)
            .await
    }

    pub async fn admin_unban_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminUserResponse, ClientError> {
        self.admin().unban_user(user_id).await
    }

    pub async fn admin_impersonate_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<SessionAndUserResponse, ClientError> {
        self.admin().impersonate_user(user_id).await
    }

    pub async fn admin_stop_impersonating(&self) -> Result<SessionAndUserResponse, ClientError> {
        self.admin().stop_impersonating().await
    }

    pub async fn admin_revoke_user_session(
        &self,
        session_token: impl Into<String>,
    ) -> Result<AdminSuccessResponse, ClientError> {
        self.admin().revoke_user_session(session_token).await
    }

    pub async fn admin_revoke_user_sessions(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminSuccessResponse, ClientError> {
        self.admin().revoke_user_sessions(user_id).await
    }

    pub async fn admin_remove_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminSuccessResponse, ClientError> {
        self.admin().remove_user(user_id).await
    }

    pub async fn admin_set_user_password(
        &self,
        user_id: impl Into<String>,
        new_password: impl Into<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.admin().set_user_password(user_id, new_password).await
    }

    pub async fn admin_has_permission(
        &self,
        req: AdminHasPermissionRequest,
    ) -> Result<AdminPermissionResponse, ClientError> {
        self.admin().has_permission(req).await
    }

    pub fn admin_check_role_permission(
        &self,
        role_csv: &str,
        permissions: &HashMap<String, Vec<String>>,
    ) -> bool {
        self.admin().check_role_permission(role_csv, permissions)
    }

    pub fn admin_check_role_permission_with_connector(
        &self,
        role_csv: &str,
        permissions: &HashMap<String, Vec<String>>,
        connector: Connector,
    ) -> bool {
        self.admin()
            .check_role_permission_with_connector(role_csv, permissions, connector)
    }
}
