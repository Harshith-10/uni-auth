//! Core authentication service coordinating business logic, crypto, hooks, and persistence.

use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use auth_proto::{
    AccountListEntryWire, ChangePasswordRequest, ChangePasswordResponse, DeleteUserRequest,
    OneTimeTokenGenerateResponse, RequestPasswordResetRequest, ResetPasswordRequest,
    SendVerificationEmailRequest, SessionAndUserResponse, SessionWire, SignInEmailRequest,
    SignInResponse, SignOutRequest, SignOutResponse, SignUpEmailRequest, SignUpResponse,
    StatusMessageResponse, StatusResponse, UpdateUserRequest, UpdateUserResponse,
    VerifyEmailResponse,
};

use crate::adapter::AuthAdapter;
use crate::crypto;
use crate::email::{EmailSender, NoopEmailSender};
use crate::error::{AdapterError, AuthError};
use crate::hooks::{AuthHooks, NoopAuthHooks, SlidingWindowRateLimiter};
use crate::models::{
    CreateAccountInput, CreateSessionInput, CreateUserInput, CreateVerificationInput, RequestMeta,
};

/// Configuration options for `AuthService`.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Secret key used for HMAC signing and HKDF key derivation.
    pub secret: Vec<u8>,

    /// Public base URL of the auth server (e.g., "http://localhost:3000/api/auth").
    pub base_url: String,

    /// Session lifetime. Default: 7 days.
    pub session_expires_in: Duration,

    /// One-time token lifetime. Default: 3 minutes.
    pub ott_expires_in: Duration,

    /// Password reset token lifetime. Default: 1 hour.
    pub reset_password_expires_in: Duration,

    /// Email verification token lifetime. Default: 24 hours.
    pub verify_email_expires_in: Duration,

    /// Whether to automatically log in the user upon successful sign-up. Default: true.
    pub auto_sign_in: bool,

    /// Whether to require email verification before allowing sign-in. Default: false.
    pub require_email_verification: bool,

    /// Minimum password length. Default: 8.
    pub min_password_length: usize,

    /// Maximum password length. Default: 128.
    pub max_password_length: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            secret: b"default-insecure-secret-key-change-me-in-production".to_vec(),
            base_url: "http://localhost:3000/api/auth".to_string(),
            session_expires_in: Duration::days(7),
            ott_expires_in: Duration::minutes(3),
            reset_password_expires_in: Duration::hours(1),
            verify_email_expires_in: Duration::hours(24),
            auto_sign_in: true,
            require_email_verification: false,
            min_password_length: 8,
            max_password_length: 128,
        }
    }
}

/// Core domain service handling all Better Auth workflows.
#[derive(Clone)]
pub struct AuthService {
    config: AuthConfig,
    adapter: Arc<dyn AuthAdapter>,
    email_sender: Arc<dyn EmailSender>,
    hooks: Arc<dyn AuthHooks>,
    rate_limiter: Option<Arc<SlidingWindowRateLimiter>>,
    auto_sign_in_after_verification: bool,
    session_update_age: Duration,
    session_fresh_age: Duration,
}

impl AuthService {
    pub fn new(config: AuthConfig, adapter: Arc<dyn AuthAdapter>) -> Self {
        Self {
            config,
            adapter,
            email_sender: Arc::new(NoopEmailSender),
            hooks: Arc::new(NoopAuthHooks),
            rate_limiter: None,
            auto_sign_in_after_verification: false,
            session_update_age: Duration::hours(24),
            session_fresh_age: Duration::hours(24),
        }
    }

    pub fn with_email_sender(mut self, email_sender: Arc<dyn EmailSender>) -> Self {
        self.email_sender = email_sender;
        self
    }

    pub fn with_hooks(mut self, hooks: Arc<dyn AuthHooks>) -> Self {
        self.hooks = hooks;
        self
    }

    pub fn with_rate_limiter(mut self, limiter: Arc<SlidingWindowRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Configures whether verifying an email address automatically issues a session token.
    pub fn with_auto_sign_in_after_verification(mut self, enabled: bool) -> Self {
        self.auto_sign_in_after_verification = enabled;
        self
    }

    /// Configures how frequently an active session's `expires_at` is extended on `get_session`.
    pub fn with_session_update_age(mut self, update_age: Duration) -> Self {
        self.session_update_age = update_age;
        self
    }

    /// Configures the `freshAge` window required for sensitive operations (`change-password`, `unlink-account`, `delete-user`).
    /// Set to `Duration::ZERO` to disable freshness checks.
    pub fn with_session_fresh_age(mut self, fresh_age: Duration) -> Self {
        self.session_fresh_age = fresh_age;
        self
    }

    pub fn auto_sign_in_after_verification(&self) -> bool {
        self.auto_sign_in_after_verification
    }

    pub fn session_fresh_age(&self) -> Duration {
        self.session_fresh_age
    }

    /// Returns `true` if the session was created within `session_fresh_age` (or if `session_fresh_age <= 0`).
    pub fn is_session_fresh(&self, session: &SessionWire) -> bool {
        if self.session_fresh_age <= Duration::ZERO {
            return true;
        }
        (OffsetDateTime::now_utc() - session.created_at) < self.session_fresh_age
    }

    /// Enforces rate limiting for the given bucket key if a `SlidingWindowRateLimiter` is attached.
    pub fn check_rate_limit(&self, key: &str) -> Result<(), AuthError> {
        if let Some(ref limiter) = self.rate_limiter {
            limiter.check(key)?;
        }
        Ok(())
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    pub fn adapter(&self) -> &Arc<dyn AuthAdapter> {
        &self.adapter
    }

    /// Signs a raw token for cookie or `set-auth-token` header emission.
    pub fn sign_token(&self, raw_token: &str) -> String {
        crypto::sign_token(&self.config.secret, raw_token)
    }

    /// Strictly verifies a signed `<token>.<signature>` token (required for cookies).
    pub fn verify_signed_token(&self, signed_token: &str) -> Option<String> {
        crypto::extract_and_verify_signed_token(&self.config.secret, signed_token)
    }

    /// Verifies and extracts a raw token from a signed or raw token string.
    pub fn verify_token(&self, signed_or_raw: &str) -> Option<String> {
        crypto::extract_and_verify_token(&self.config.secret, signed_or_raw)
    }

    // ──────────────────────────────────────────────
    // Sign-Up & Sign-In
    // ──────────────────────────────────────────────

    /// Registers a new user with email and password.
    pub async fn sign_up_email(&self, req: SignUpEmailRequest) -> Result<SignUpResponse, AuthError> {
        self.sign_up_email_with_meta(req, RequestMeta::default())
            .await
    }

    /// Registers a new user with email, password, and HTTP request metadata (`ip_address`, `user_agent`).
    pub async fn sign_up_email_with_meta(
        &self,
        req: SignUpEmailRequest,
        meta: RequestMeta,
    ) -> Result<SignUpResponse, AuthError> {
        let rate_key = format!(
            "sign-up:{}",
            meta.ip_address.as_deref().unwrap_or("local")
        );
        self.check_rate_limit(&rate_key)?;

        let email = req.email.trim().to_lowercase();
        if !email.contains('@') || !email.contains('.') {
            return Err(AuthError::InvalidEmail);
        }

        if req.password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort);
        }
        if req.password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        // Check duplicate email
        if self.adapter.find_user_by_email(&email).await?.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        // Hash password non-blocking
        let password_hash = crypto::hash_password(req.password)
            .await
            .map_err(AuthError::Crypto)?;

        // Create user
        let user = self
            .adapter
            .create_user(CreateUserInput {
                id: None,
                name: req.name,
                email: email.clone(),
                image: req.image,
                email_verified: false,
            })
            .await?;

        let user_wire = user.to_wire();
        self.hooks.on_user_created(&user_wire).await;

        // Link credential account
        self.adapter
            .create_account(CreateAccountInput {
                id: None,
                user_id: user.id.clone(),
                account_id: user.id.clone(),
                provider_id: "credential".to_string(),
                password: Some(password_hash),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
            })
            .await?;

        // Send verification email if required
        if self.config.require_email_verification {
            let token = crypto::generate_random_token(32);
            let expires_at = OffsetDateTime::now_utc() + self.config.verify_email_expires_in;
            self.adapter
                .create_verification(CreateVerificationInput {
                    id: None,
                    identifier: format!("verify-email:{token}"),
                    value: user.id.clone(),
                    expires_at,
                })
                .await?;

            let callback_url = req.callback_url.as_deref().unwrap_or("/");
            let url = format!(
                "{}/verify-email?token={}&callbackURL={}",
                self.config.base_url,
                token,
                urlencoding_simple(callback_url)
            );

            self.email_sender
                .send_verification_email(&email, &url, &token)
                .await
                .map_err(AuthError::Email)?;

            return Ok(SignUpResponse {
                token: None,
                user: user_wire,
            });
        }

        // Auto sign-in if enabled
        if self.config.auto_sign_in {
            let raw_token = crypto::generate_session_token();
            let expires_at = OffsetDateTime::now_utc() + self.config.session_expires_in;

            let session = self
                .adapter
                .create_session(CreateSessionInput {
                    id: None,
                    user_id: user.id.clone(),
                    token: raw_token,
                    expires_at,
                    ip_address: meta.ip_address,
                    user_agent: meta.user_agent,
                })
                .await?;

            let session_wire = session.to_wire();
            self.hooks.on_session_created(&session_wire, &user_wire).await;

            Ok(SignUpResponse {
                token: Some(session.token),
                user: user_wire,
            })
        } else {
            Ok(SignUpResponse {
                token: None,
                user: user_wire,
            })
        }
    }

    /// Authenticates a user with email and password, issuing a new session.
    pub async fn sign_in_email(&self, req: SignInEmailRequest) -> Result<SignInResponse, AuthError> {
        self.sign_in_email_with_meta(req, RequestMeta::default())
            .await
    }

    /// Authenticates a user with email, password, and HTTP request metadata (`ip_address`, `user_agent`).
    pub async fn sign_in_email_with_meta(
        &self,
        req: SignInEmailRequest,
        meta: RequestMeta,
    ) -> Result<SignInResponse, AuthError> {
        let rate_key = format!(
            "sign-in:{}",
            meta.ip_address.as_deref().unwrap_or("local")
        );
        self.check_rate_limit(&rate_key)?;

        let email = req.email.trim().to_lowercase();
        if !email.contains('@') || !email.contains('.') {
            return Err(AuthError::InvalidEmail);
        }
        if req.password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let user = self.adapter.find_user_by_email(&email).await?;

        let user = match user {
            Some(u) => u,
            None => {
                let _ = crypto::hash_password(req.password).await;
                return Err(AuthError::InvalidEmailOrPassword);
            }
        };

        let account = self
            .adapter
            .find_account("credential", &user.id)
            .await?;

        let account = match account {
            Some(a) => a,
            None => {
                let _ = crypto::hash_password(req.password).await;
                return Err(AuthError::InvalidEmailOrPassword);
            }
        };

        let stored_hash = match account.password {
            Some(h) => h,
            None => {
                let _ = crypto::hash_password(req.password).await;
                return Err(AuthError::InvalidEmailOrPassword);
            }
        };

        let is_valid = crypto::verify_password(stored_hash, req.password)
            .await
            .map_err(AuthError::Crypto)?;

        if !is_valid {
            return Err(AuthError::InvalidEmailOrPassword);
        }

        if self.config.require_email_verification && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        let raw_token = crypto::generate_session_token();
        let expires_at = OffsetDateTime::now_utc() + self.config.session_expires_in;

        let session = self
            .adapter
            .create_session(CreateSessionInput {
                id: None,
                user_id: user.id.clone(),
                token: raw_token,
                expires_at,
                ip_address: meta.ip_address,
                user_agent: meta.user_agent,
            })
            .await?;

        let user_wire = user.to_wire();
        let session_wire = session.to_wire();
        self.hooks.on_session_created(&session_wire, &user_wire).await;

        Ok(SignInResponse {
            redirect: req.callback_url.is_some(),
            token: session.token,
            url: req.callback_url,
            user: user_wire,
        })
    }

    // ──────────────────────────────────────────────
    // Sessions
    // ──────────────────────────────────────────────

    /// Retrieves an active session and user by raw or signed session token.
    /// Automatically slides session expiry forward if `session_update_age` has elapsed.
    pub async fn get_session(
        &self,
        token_or_signed: &str,
    ) -> Result<Option<SessionAndUserResponse>, AuthError> {
        let raw_token = match self.verify_token(token_or_signed) {
            Some(t) => t,
            None => return Ok(None),
        };

        let mut session = match self.adapter.find_session_by_token(&raw_token).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        if session.is_expired() {
            let _ = self.adapter.delete_session(&raw_token).await;
            return Ok(None);
        }

        // Sliding window session refresh when updateAge has elapsed
        let now = OffsetDateTime::now_utc();
        if self.session_update_age > Duration::ZERO
            && (now - session.updated_at) >= self.session_update_age
        {
            let new_expires_at = now + self.config.session_expires_in;
            if self
                .adapter
                .update_session_expiry(&raw_token, new_expires_at)
                .await
                .is_ok()
            {
                session.expires_at = new_expires_at;
                session.updated_at = now;
            }
        }

        let user = match self.adapter.find_user_by_id(&session.user_id).await? {
            Some(u) => u,
            None => return Ok(None),
        };

        Ok(Some(SessionAndUserResponse {
            session: session.to_wire(),
            user: user.to_wire(),
        }))
    }

    /// Signs out the session corresponding to the provided token.
    pub async fn sign_out(
        &self,
        token_or_signed: &str,
        req: Option<SignOutRequest>,
    ) -> Result<SignOutResponse, AuthError> {
        if let Some(raw_token) = self.verify_token(token_or_signed) {
            let _ = self.adapter.delete_session(&raw_token).await;
        }

        let (url, redirect) = match req {
            Some(r) => {
                let redirect = !r.disable_redirect.unwrap_or(false);
                (r.callback_url, Some(redirect))
            }
            None => (None, None),
        };

        Ok(SignOutResponse {
            success: true,
            url,
            redirect,
        })
    }

    /// Lists active sessions for a user.
    pub async fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionWire>, AuthError> {
        let records = self.adapter.list_sessions_by_user_id(user_id).await?;
        Ok(records.into_iter().map(|s| s.to_wire()).collect())
    }

    /// Revokes a specific session belonging to the user. Accepts either session token or session ID.
    pub async fn revoke_session(
        &self,
        user_id: &str,
        token_or_signed: &str,
    ) -> Result<StatusResponse, AuthError> {
        let raw_token = self
            .verify_token(token_or_signed)
            .unwrap_or_else(|| token_or_signed.to_string());

        if let Some(session) = self.adapter.find_session_by_token(&raw_token).await? {
            if session.user_id == user_id {
                self.adapter.delete_session(&raw_token).await?;
                return Ok(StatusResponse::success());
            }
        }

        let user_sessions = self.adapter.list_sessions_by_user_id(user_id).await?;
        if let Some(session) = user_sessions.into_iter().find(|s| s.id == token_or_signed) {
            self.adapter.delete_session(&session.token).await?;
        }

        Ok(StatusResponse::success())
    }

    /// Revokes all active sessions for a user.
    pub async fn revoke_sessions(&self, user_id: &str) -> Result<StatusResponse, AuthError> {
        self.adapter.delete_sessions_by_user_id(user_id).await?;
        Ok(StatusResponse::success())
    }

    /// Revokes all other sessions for a user except the current one.
    pub async fn revoke_other_sessions(
        &self,
        user_id: &str,
        current_token_or_signed: &str,
    ) -> Result<StatusResponse, AuthError> {
        let raw_token = self
            .verify_token(current_token_or_signed)
            .unwrap_or_else(|| current_token_or_signed.to_string());

        self.adapter
            .delete_other_sessions(user_id, &raw_token)
            .await?;
        Ok(StatusResponse::success())
    }

    // ──────────────────────────────────────────────
    // Password Management
    // ──────────────────────────────────────────────

    /// Requests a password reset email.
    pub async fn request_password_reset(
        &self,
        req: RequestPasswordResetRequest,
    ) -> Result<StatusMessageResponse, AuthError> {
        let email = req.email.trim().to_lowercase();
        self.check_rate_limit(&format!("password-reset:{email}"))?;

        let user = self.adapter.find_user_by_email(&email).await?;

        if let Some(u) = user {
            let token = crypto::generate_random_token(32);
            let expires_at = OffsetDateTime::now_utc() + self.config.reset_password_expires_in;

            self.adapter
                .create_verification(CreateVerificationInput {
                    id: None,
                    identifier: format!("reset-password:{token}"),
                    value: u.id.clone(),
                    expires_at,
                })
                .await?;

            let redirect_param = req
                .redirect_to
                .map(|r| format!("?callbackURL={}", urlencoding_simple(&r)))
                .unwrap_or_default();

            let reset_url = format!("{}/reset-password/{}{}", self.config.base_url, token, redirect_param);

            let _ = self
                .email_sender
                .send_password_reset_email(&email, &reset_url, &token)
                .await;
        } else {
            let _ = crypto::generate_random_token(24);
            let _ = self
                .adapter
                .find_verification("reset-password:dummy-verification-token")
                .await;
        }

        Ok(StatusMessageResponse {
            status: true,
            message: "If this email exists in our system, check your email for the reset link"
                .to_string(),
        })
    }

    /// Resets the user's password using a verification token and revokes all active sessions.
    pub async fn reset_password(&self, req: ResetPasswordRequest) -> Result<StatusResponse, AuthError> {
        let token = req.token.ok_or(AuthError::InvalidToken)?;

        if req.new_password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort);
        }
        if req.new_password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let identifier = format!("reset-password:{token}");
        let preview = self
            .adapter
            .find_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if preview.is_expired() {
            let _ = self.adapter.delete_verification(&identifier).await;
            return Err(AuthError::InvalidToken);
        }

        let user_id = preview.value;
        if self.adapter.find_user_by_id(&user_id).await?.is_none() {
            return Err(AuthError::UserNotFound);
        }

        let password_hash = crypto::hash_password(req.new_password)
            .await
            .map_err(AuthError::Crypto)?;

        self.adapter
            .consume_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        match self
            .adapter
            .update_account_password(&user_id, &password_hash)
            .await
        {
            Ok(()) => {}
            Err(AdapterError::NotFound) => {
                self.adapter
                    .create_account(CreateAccountInput {
                        id: None,
                        user_id: user_id.clone(),
                        account_id: user_id.clone(),
                        provider_id: "credential".to_string(),
                        password: Some(password_hash),
                        access_token: None,
                        refresh_token: None,
                        id_token: None,
                        access_token_expires_at: None,
                        refresh_token_expires_at: None,
                        scope: None,
                    })
                    .await?;
            }
            Err(e) => return Err(AuthError::Adapter(e)),
        }

        self.adapter.delete_sessions_by_user_id(&user_id).await?;
        self.hooks.on_password_reset(&user_id).await;

        Ok(StatusResponse::success())
    }

    /// Changes password for an authenticated user.
    pub async fn change_password(
        &self,
        user_id: &str,
        current_token_or_signed: &str,
        req: ChangePasswordRequest,
    ) -> Result<ChangePasswordResponse, AuthError> {
        if req.new_password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort);
        }
        if req.new_password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }
        if req.current_password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let account = self
            .adapter
            .find_account("credential", user_id)
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;

        let stored_hash = account
            .password
            .ok_or(AuthError::CredentialAccountNotFound)?;

        let is_valid = crypto::verify_password(stored_hash, req.current_password)
            .await
            .map_err(AuthError::Crypto)?;

        if !is_valid {
            return Err(AuthError::InvalidPassword);
        }

        let new_hash = crypto::hash_password(req.new_password)
            .await
            .map_err(AuthError::Crypto)?;

        self.adapter
            .update_account_password(user_id, &new_hash)
            .await?;

        let user = self
            .adapter
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let token = if req.revoke_other_sessions == Some(true) {
            let current_raw = self
                .verify_token(current_token_or_signed)
                .unwrap_or_else(|| current_token_or_signed.to_string());
            let current_meta = self
                .adapter
                .find_session_by_token(&current_raw)
                .await?
                .map(|s| RequestMeta {
                    ip_address: s.ip_address,
                    user_agent: s.user_agent,
                })
                .unwrap_or_default();

            self.adapter.delete_sessions_by_user_id(user_id).await?;
            let fresh_raw_token = crypto::generate_session_token();
            let expires_at = OffsetDateTime::now_utc() + self.config.session_expires_in;
            let new_session = self
                .adapter
                .create_session(CreateSessionInput {
                    id: None,
                    user_id: user_id.to_string(),
                    token: fresh_raw_token,
                    expires_at,
                    ip_address: current_meta.ip_address,
                    user_agent: current_meta.user_agent,
                })
                .await?;
            Some(new_session.token)
        } else {
            None
        };

        Ok(ChangePasswordResponse {
            token,
            user: user.to_wire(),
        })
    }

    // ──────────────────────────────────────────────
    // User Profile & Account Deletion
    // ──────────────────────────────────────────────

    /// Updates a user's profile (`name` and/or `image`).
    pub async fn update_user(
        &self,
        user_id: &str,
        req: UpdateUserRequest,
    ) -> Result<UpdateUserResponse, AuthError> {
        let updated = self
            .adapter
            .update_user_profile(user_id, req.name, req.image)
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::Adapter(other),
            })?;

        Ok(UpdateUserResponse {
            status: true,
            user: Some(updated.to_wire()),
        })
    }

    /// Deletes a user account (verifying current password if supplied) and cascades all sessions/accounts.
    pub async fn delete_user(
        &self,
        user_id: &str,
        req: DeleteUserRequest,
    ) -> Result<StatusMessageResponse, AuthError> {
        if let Some(password) = req.password {
            if password.len() > self.config.max_password_length {
                return Err(AuthError::PasswordTooLong);
            }
            let account = self
                .adapter
                .find_account("credential", user_id)
                .await?
                .ok_or(AuthError::CredentialAccountNotFound)?;
            let stored_hash = account
                .password
                .ok_or(AuthError::CredentialAccountNotFound)?;
            let valid = crypto::verify_password(stored_hash, password)
                .await
                .map_err(AuthError::Crypto)?;
            if !valid {
                return Err(AuthError::InvalidPassword);
            }
        }

        self.adapter.delete_user(user_id).await?;
        self.hooks.on_user_deleted(user_id).await;
        Ok(StatusMessageResponse {
            status: true,
            message: "User deleted".to_string(),
        })
    }

    // ──────────────────────────────────────────────
    // Email Verification
    // ──────────────────────────────────────────────

    /// Sends a verification email.
    pub async fn send_verification_email(
        &self,
        req: SendVerificationEmailRequest,
    ) -> Result<StatusResponse, AuthError> {
        let email = req.email.trim().to_lowercase();
        let user = self.adapter.find_user_by_email(&email).await?;

        if let Some(u) = user {
            if !u.email_verified {
                let token = crypto::generate_random_token(32);
                let expires_at = OffsetDateTime::now_utc() + self.config.verify_email_expires_in;

                self.adapter
                    .create_verification(CreateVerificationInput {
                        id: None,
                        identifier: format!("verify-email:{token}"),
                        value: u.id.clone(),
                        expires_at,
                    })
                    .await?;

                let callback_url = req.callback_url.as_deref().unwrap_or("/");
                let url = format!(
                    "{}/verify-email?token={}&callbackURL={}",
                    self.config.base_url,
                    token,
                    urlencoding_simple(callback_url)
                );

                let _ = self
                    .email_sender
                    .send_verification_email(&email, &url, &token)
                    .await;
            }
        }

        Ok(StatusResponse::success())
    }

    /// Verifies email via token.
    pub async fn verify_email(&self, token: &str) -> Result<VerifyEmailResponse, AuthError> {
        self.verify_email_with_meta(token, RequestMeta::default())
            .await
    }

    /// Verifies email via token and optionally issues a session when `auto_sign_in_after_verification` is enabled.
    pub async fn verify_email_with_meta(
        &self,
        token: &str,
        meta: RequestMeta,
    ) -> Result<VerifyEmailResponse, AuthError> {
        let identifier = format!("verify-email:{token}");
        let record = self
            .adapter
            .consume_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        let user_id = record.value;
        self.adapter
            .update_user_email_verified(&user_id, true)
            .await?;

        let user = self.adapter.find_user_by_id(&user_id).await?;
        let user_wire = user.as_ref().map(|u| u.to_wire());
        if let Some(ref uw) = user_wire {
            self.hooks.on_email_verified(uw).await;
        }

        let session_token = if self.auto_sign_in_after_verification && user.is_some() {
            let raw_token = crypto::generate_session_token();
            let expires_at = OffsetDateTime::now_utc() + self.config.session_expires_in;
            let session = self
                .adapter
                .create_session(CreateSessionInput {
                    id: None,
                    user_id: user_id.clone(),
                    token: raw_token,
                    expires_at,
                    ip_address: meta.ip_address,
                    user_agent: meta.user_agent,
                })
                .await?;
            Some(session.token)
        } else {
            None
        };

        Ok(VerifyEmailResponse {
            status: true,
            user: user_wire,
            token: session_token,
        })
    }

    // ──────────────────────────────────────────────
    // One-Time Token Plugin (Browser to Desktop Handoff)
    // ──────────────────────────────────────────────

    /// Generates a single-use 3-minute token linked to the current active session.
    pub async fn generate_one_time_token(
        &self,
        session_token_or_signed: &str,
    ) -> Result<OneTimeTokenGenerateResponse, AuthError> {
        let raw_token = self
            .verify_token(session_token_or_signed)
            .ok_or(AuthError::InvalidToken)?;

        let session = self
            .adapter
            .find_session_by_token(&raw_token)
            .await?
            .ok_or(AuthError::SessionExpired)?;

        if session.is_expired() {
            return Err(AuthError::SessionExpired);
        }

        let token = crypto::generate_random_token(32);
        let expires_at = OffsetDateTime::now_utc() + self.config.ott_expires_in;

        self.adapter
            .create_verification(CreateVerificationInput {
                id: None,
                identifier: format!("one-time-token:{token}"),
                value: session.token,
                expires_at,
            })
            .await?;

        Ok(OneTimeTokenGenerateResponse { token })
    }

    /// Atomically verifies and burns a one-time token, resolving to the attached session.
    pub async fn verify_one_time_token(
        &self,
        token: &str,
    ) -> Result<SessionAndUserResponse, AuthError> {
        let identifier = format!("one-time-token:{token}");
        let record = self
            .adapter
            .consume_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        let session = self
            .adapter
            .find_session_by_token(&record.value)
            .await?
            .ok_or(AuthError::SessionExpired)?;

        if session.is_expired() {
            return Err(AuthError::SessionExpired);
        }

        let user = self
            .adapter
            .find_user_by_id(&session.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok(SessionAndUserResponse {
            session: session.to_wire(),
            user: user.to_wire(),
        })
    }

    // ──────────────────────────────────────────────
    // Accounts
    // ──────────────────────────────────────────────

    /// Lists connected accounts for a user with sensitive fields stripped.
    pub async fn list_accounts(&self, user_id: &str) -> Result<Vec<AccountListEntryWire>, AuthError> {
        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        Ok(accounts
            .into_iter()
            .map(|a| {
                let scopes = a
                    .scope
                    .map(|s| {
                        s.split(',')
                            .map(|p| p.trim().to_string())
                            .filter(|p| !p.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                AccountListEntryWire {
                    id: a.id,
                    provider_id: a.provider_id,
                    account_id: a.account_id,
                    user_id: a.user_id,
                    created_at: a.created_at,
                    updated_at: a.updated_at,
                    scopes,
                }
            })
            .collect())
    }

    /// Unlinks an account by `provider_id` and/or `account_id`.
    /// Prevents unlinking if it is the user's last remaining authentication method.
    pub async fn unlink_account(
        &self,
        user_id: &str,
        provider_id: &str,
        account_id: &str,
    ) -> Result<StatusResponse, AuthError> {
        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        if accounts.len() <= 1 {
            return Err(AuthError::FailedToUnlinkLastAccount);
        }

        let target = accounts
            .iter()
            .find(|a| {
                let provider_matches =
                    provider_id.is_empty() || a.provider_id == provider_id;
                let account_matches = account_id.is_empty()
                    || a.account_id == account_id
                    || a.id == account_id;
                provider_matches && account_matches
            })
            .or_else(|| {
                if !provider_id.is_empty() {
                    accounts.iter().find(|a| a.provider_id == provider_id)
                } else {
                    None
                }
            })
            .ok_or(AuthError::AccountNotFound)?;

        self.adapter
            .delete_account(&target.provider_id, &target.account_id)
            .await?;
        Ok(StatusResponse::success())
    }
}

fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}
