//! Core authentication service coordinating business logic, crypto, hooks, plugins, and persistence.

use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use auth_proto::{
    error_codes, AccountListEntryWire, AdminBanUserRequest, AdminCreateUserRequest,
    AdminHasPermissionRequest, AdminListUserSessionsResponse, AdminListUsersQuery,
    AdminListUsersResponse, AdminPermissionResponse, AdminSetRoleRequest,
    AdminSetUserPasswordRequest, AdminSuccessResponse, AdminUpdateUserRequest, AdminUserResponse,
    ChangePasswordRequest, ChangePasswordResponse, DeleteUserRequest, DeleteUserResponse,
    OneTimeTokenGenerateResponse, RequestPasswordResetRequest, ResetPasswordRequest, RoleValue,
    SendVerificationEmailRequest, SessionAndUserResponse, SessionWire, SignInEmailRequest,
    SignInResponse, SignOutRequest, SignOutResponse, SignUpEmailRequest, SignUpResponse,
    StatusMessageResponse, StatusResponse, UpdateUserRequest, UpdateUserResponse, UserWire,
    VerifyEmailResponse, url_encode,
};

use crate::access::AdminConfig;
use crate::adapter::AuthAdapter;
use crate::crypto;
use crate::email::{EmailSender, NoopEmailSender};
use crate::error::{AdapterError, AuthError};
use crate::hooks::{AuthHooks, NoopAuthHooks, SlidingWindowRateLimiter};
use crate::models::{
    AccountRecord, AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput,
    CreateSessionInput, CreateUserInput, CreateVerificationInput, RequestMeta, SessionRecord,
    UserRecord,
};
use crate::plugin::{AuthPlugin, BetterAuthPlugin, HookedAdapter, PluginRegistry};

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

    /// Whether user self-deletion is enabled. Default: true.
    pub delete_user_enabled: bool,

    /// Whether deferred session refresh is required for POST /get-session. Default: false.
    pub defer_session_refresh: bool,
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
            delete_user_enabled: true,
            defer_session_refresh: false,
        }
    }
}

/// Core domain service handling all Better Auth workflows.
#[derive(Clone)]
pub struct AuthService {
    config: AuthConfig,
    admin_config: AdminConfig,
    raw_adapter: Arc<dyn AuthAdapter>,
    adapter: Arc<dyn AuthAdapter>,
    email_sender: Arc<dyn EmailSender>,
    hooks: Arc<dyn AuthHooks>,
    rate_limiter: Option<Arc<SlidingWindowRateLimiter>>,
    plugins: PluginRegistry,
    legacy_plugins: Arc<Vec<Arc<dyn AuthPlugin>>>,
    auto_sign_in_after_verification: bool,
    session_update_age: Duration,
    session_fresh_age: Duration,
}

impl AuthService {
    pub fn new(config: AuthConfig, adapter: Arc<dyn AuthAdapter>) -> Self {
        let raw_adapter = adapter.clone();
        Self {
            config,
            admin_config: AdminConfig::default(),
            raw_adapter,
            adapter,
            email_sender: Arc::new(NoopEmailSender),
            hooks: Arc::new(NoopAuthHooks),
            rate_limiter: None,
            plugins: PluginRegistry::new(),
            legacy_plugins: Arc::new(Vec::new()),
            auto_sign_in_after_verification: false,
            session_update_age: Duration::hours(24),
            session_fresh_age: Duration::hours(24),
        }
    }

    pub fn with_admin_config(mut self, admin_config: AdminConfig) -> Self {
        self.admin_config = admin_config;
        self
    }

    pub fn admin_config(&self) -> &AdminConfig {
        &self.admin_config
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

    /// Registers a modular `BetterAuthPlugin` with `AuthService`.
    pub fn with_plugin<P: BetterAuthPlugin + 'static>(mut self, plugin: P) -> Self {
        self.plugins.register(Arc::new(plugin));
        self.rebuild_hooked_adapter();
        self
    }

    /// Registers an `Arc<dyn BetterAuthPlugin>` with `AuthService`.
    pub fn with_plugin_arc(mut self, plugin: Arc<dyn BetterAuthPlugin>) -> Self {
        self.plugins.register(plugin);
        self.rebuild_hooked_adapter();
        self
    }

    /// Accessor for the registered `PluginRegistry`.
    pub fn plugins(&self) -> &PluginRegistry {
        &self.plugins
    }

    /// Retrieves and downcasts a registered `BetterAuthPlugin` by type.
    pub fn get_plugin<P: BetterAuthPlugin + 'static>(&self) -> Option<&P> {
        self.plugins.get::<P>()
    }

    /// Registers a legacy `AuthPlugin` with `AuthService`.
    pub fn with_legacy_plugin(mut self, plugin: Arc<dyn AuthPlugin>) -> Self {
        let mut list = (*self.legacy_plugins).clone();
        list.push(plugin);
        self.legacy_plugins = Arc::new(list);
        self
    }

    /// Accessor for legacy plugins.
    pub fn legacy_plugins(&self) -> &[Arc<dyn AuthPlugin>] {
        &self.legacy_plugins
    }

    fn rebuild_hooked_adapter(&mut self) {
        let db_hooks = self.plugins.database_hooks();
        if db_hooks.is_empty() {
            self.adapter = self.raw_adapter.clone();
        } else {
            self.adapter = Arc::new(HookedAdapter::new(self.raw_adapter.clone(), db_hooks));
        }
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

    /// Configures whether user self-deletion (`POST /delete-user`) is enabled.
    pub fn with_delete_user_enabled(mut self, enabled: bool) -> Self {
        self.config.delete_user_enabled = enabled;
        self
    }

    /// Configures whether deferred session refresh is required for `POST /get-session`.
    pub fn with_defer_session_refresh(mut self, enabled: bool) -> Self {
        self.config.defer_session_refresh = enabled;
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

    /// Signs a raw token using raw-secret HMAC-SHA256 with standard padded Base64 (`=`).
    pub fn sign_cookie_token(&self, raw_token: &str) -> String {
        crypto::sign_cookie_better_call(&self.config.secret, raw_token)
    }

    /// Strictly verifies a signed `<token>.<signature>` token (required for cookies).
    pub fn verify_signed_token(&self, signed_token: &str) -> Option<String> {
        crypto::extract_and_verify_signed_token(&self.config.secret, signed_token)
    }

    /// Verifies and extracts a raw token from a signed or raw token string.
    pub fn verify_token(&self, signed_or_raw: &str) -> Option<String> {
        crypto::extract_and_verify_token(&self.config.secret, signed_or_raw)
    }

    /// Emits the `on_user_created` lifecycle hook (used by email and OAuth user registration).
    pub async fn notify_user_created(&self, user: &UserWire) {
        self.hooks.on_user_created(user).await;
    }

    /// Enforces the Admin plugin banned-user check before creating a session.
    /// Automatically clears expired bans (`ban_expires < now`).
    ///
    /// Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/admin.ts` lines 81-112
    async fn enforce_not_banned(&self, user: &UserRecord) -> Result<(), AuthError> {
        if user.banned {
            if let Some(exp) = user.ban_expires {
                if exp < OffsetDateTime::now_utc() {
                    let _ = self
                        .adapter
                        .update_user_admin(
                            &user.id,
                            AdminUpdateUserFields {
                                banned: Some(false),
                                ban_reason: Some(None),
                                ban_expires: Some(None),
                                ..Default::default()
                            },
                        )
                        .await;
                    return Ok(());
                }
            }
            return Err(AuthError::BannedUser(
                self.admin_config.banned_user_message.clone(),
            ));
        }
        Ok(())
    }

    /// Issues a session for `user` while executing banned-user checks, `AuthPlugin`, and `AuthHooks` callbacks.
    pub async fn issue_session_for_user(
        &self,
        user: &UserRecord,
        meta: RequestMeta,
        run_before_sign_in: bool,
    ) -> Result<SessionRecord, AuthError> {
        self.enforce_not_banned(user).await?;

        let user_wire = user.to_wire();
        if run_before_sign_in {
            for plugin in self.legacy_plugins.iter() {
                plugin.on_before_sign_in(&user_wire).await?;
            }
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

        let session_wire = session.to_wire();
        self.hooks.on_session_created(&session_wire, &user_wire).await;
        for plugin in self.legacy_plugins.iter() {
            plugin
                .on_after_session_issued(&session_wire, &user_wire)
                .await?;
        }

        Ok(session)
    }

    /// Looks up a user's `credential` account by `(provider_id = "credential", account_id = user_id)`
    /// with a fallback scan across `find_accounts_by_user_id` for migrated Better Auth databases
    /// where `account.account_id` differs from `user.id`.
    async fn find_credential_account(
        &self,
        user_id: &str,
    ) -> Result<Option<AccountRecord>, AuthError> {
        if let Some(account) = self.adapter.find_account("credential", user_id).await? {
            return Ok(Some(account));
        }
        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        Ok(accounts
            .into_iter()
            .find(|a| a.provider_id == "credential"))
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

        if self.adapter.find_user_by_email(&email).await?.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        let password_hash = crypto::hash_password(req.password)
            .await
            .map_err(AuthError::Crypto)?;

        let user = self
            .adapter
            .create_user(CreateUserInput {
                id: None,
                name: req.name,
                email: email.clone(),
                image: req.image,
                email_verified: false,
                role: None,
            })
            .await?;

        let user_wire = user.to_wire();
        self.notify_user_created(&user_wire).await;

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
                url_encode(callback_url)
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

        if self.config.auto_sign_in {
            let session = self.issue_session_for_user(&user, meta, true).await?;

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

        let account = self.find_credential_account(&user.id).await?;

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

        let was_legacy_scrypt = crypto::is_legacy_scrypt_hash(&stored_hash);
        let password_clone = req.password.clone();
        let is_valid = crypto::verify_password(stored_hash, req.password)
            .await
            .map_err(AuthError::Crypto)?;

        if !is_valid {
            return Err(AuthError::InvalidEmailOrPassword);
        }

        // Transparently upgrade legacy Better Auth scrypt password hashes to Argon2id
        if was_legacy_scrypt {
            if let Ok(upgraded_hash) = crypto::hash_password(password_clone).await {
                let _ = self
                    .adapter
                    .update_account_password(&user.id, &upgraded_hash)
                    .await;
            }
        }

        if self.config.require_email_verification && !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        let session = self.issue_session_for_user(&user, meta, true).await?;

        // Re-read user in case an expired ban was auto-cleared during issue_session_for_user
        let fresh_user = self
            .adapter
            .find_user_by_id(&user.id)
            .await?
            .unwrap_or(user);

        Ok(SignInResponse {
            redirect: req.callback_url.is_some(),
            token: session.token,
            url: req.callback_url,
            user: fresh_user.to_wire(),
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

    /// Lists active non-impersonated sessions for a user.
    ///
    /// Per upstream `plugins/admin/admin.ts` lines 116-129, sessions with `impersonatedBy`
    /// are excluded from standard `/list-sessions` responses.
    pub async fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionWire>, AuthError> {
        let records = self.adapter.list_sessions_by_user_id(user_id).await?;
        Ok(records
            .into_iter()
            .filter(|s| s.impersonated_by.is_none())
            .map(|s| s.to_wire())
            .collect())
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
                .map(|r| format!("?callbackURL={}", url_encode(&r)))
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
        let consumed = self
            .adapter
            .consume_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        let user_id = consumed.value;
        if self.adapter.find_user_by_id(&user_id).await?.is_none() {
            return Err(AuthError::UserNotFound);
        }

        let password_hash = crypto::hash_password(req.new_password)
            .await
            .map_err(AuthError::Crypto)?;

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
            Err(e) => return Err(AuthError::from(e)),
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
            .find_credential_account(user_id)
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
            let new_session = self
                .issue_session_for_user(&user, current_meta, false)
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
        if req.extra.contains_key("email") {
            return Err(AuthError::bad_request(
                error_codes::EMAIL_CAN_NOT_BE_UPDATED,
                "Email can not be updated",
            ));
        }

        if req.name.is_none() && req.image.is_none() && req.extra.is_empty() {
            return Err(AuthError::bad_request(
                "BAD_REQUEST",
                "No fields to update",
            ));
        }

        let updated = self
            .adapter
            .update_user_profile(user_id, req.name, req.image)
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
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
        session_created_at: Option<OffsetDateTime>,
        req: DeleteUserRequest,
    ) -> Result<DeleteUserResponse, AuthError> {
        if !self.config.delete_user_enabled {
            return Err(AuthError::NotFound);
        }

        if let Some(password) = req.password {
            if password.len() > self.config.max_password_length {
                return Err(AuthError::PasswordTooLong);
            }
            let account = self
                .find_credential_account(user_id)
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
        } else if !self.session_fresh_age.is_zero() {
            if let Some(created_at) = session_created_at {
                let age = OffsetDateTime::now_utc() - created_at;
                if age > self.session_fresh_age {
                    return Err(AuthError::SessionNotFresh);
                }
            }
        }

        self.adapter.delete_user(user_id).await?;
        self.hooks.on_user_deleted(user_id).await;
        Ok(DeleteUserResponse {
            success: true,
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
                    url_encode(callback_url)
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

        let session_token = if self.auto_sign_in_after_verification {
            if let Some(ref u) = user {
                let session = self.issue_session_for_user(u, meta, true).await?;
                Some(session.token)
            } else {
                None
            }
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

    // ──────────────────────────────────────────────
    // Admin Plugin Operations
    // ──────────────────────────────────────────────

    fn check_admin_permission(
        &self,
        actor: &UserWire,
        resource: &str,
        action: &str,
        err_code: &'static str,
        err_msg: &'static str,
    ) -> Result<(), AuthError> {
        if !self.admin_config.has_permission(
            Some(&actor.id),
            actor.role.as_deref(),
            resource,
            action,
        ) {
            return Err(AuthError::forbidden(err_code, err_msg));
        }
        Ok(())
    }

    fn validate_role_names(&self, roles: &[String]) -> Result<(), AuthError> {
        if roles.is_empty() {
            return Err(AuthError::bad_request(
                error_codes::INVALID_ROLE_TYPE,
                "Invalid role type",
            ));
        }
        for role in roles {
            if !self.admin_config.ac.has_role(role) {
                return Err(AuthError::bad_request(
                    error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE,
                    "You are not allowed to set a non-existent role value",
                ));
            }
        }
        Ok(())
    }

    /// `POST /api/auth/admin/set-role`
    pub async fn admin_set_role(
        &self,
        actor: &UserWire,
        req: AdminSetRoleRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "set-role",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE,
            "You are not allowed to change users role",
        )?;

        let role_list = req.role.to_vec();
        self.validate_role_names(&role_list)?;

        let updated = self
            .adapter
            .update_user_admin(
                &req.user_id,
                AdminUpdateUserFields {
                    role: Some(req.role.to_csv()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
            })?;

        Ok(AdminUserResponse {
            user: updated.to_wire(),
        })
    }

    /// `GET /api/auth/admin/get-user`
    pub async fn admin_get_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<UserWire, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "get",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_GET_USER,
            "You are not allowed to get user",
        )?;

        let user = self
            .adapter
            .find_user_by_id(target_user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok(user.to_wire())
    }

    /// `POST /api/auth/admin/create-user`
    pub async fn admin_create_user(
        &self,
        actor: &UserWire,
        req: AdminCreateUserRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "create",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS,
            "You are not allowed to create users",
        )?;

        let data_map = req.data.unwrap_or_default();

        // Extract role from top-level `role` or `data.role`
        let requested_role: Option<RoleValue> = if req.role.is_some() {
            req.role
        } else if let Some(val) = data_map.get("role") {
            match serde_json::from_value::<RoleValue>(val.clone()) {
                Ok(rv) => Some(rv),
                Err(_) => {
                    return Err(AuthError::bad_request(
                        error_codes::INVALID_ROLE_TYPE,
                        "Invalid role type",
                    ));
                }
            }
        } else {
            None
        };

        if let Some(ref rv) = requested_role {
            self.check_admin_permission(
                actor,
                "user",
                "set-role",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE,
                "You are not allowed to change users role",
            )?;
            let role_list = rv.to_vec();
            self.validate_role_names(&role_list)?;
        }

        if ["banned", "banReason", "banExpires"]
            .iter()
            .any(|k| data_map.contains_key(*k))
        {
            self.check_admin_permission(
                actor,
                "user",
                "ban",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
                "You are not allowed to ban users",
            )?;
        }

        let email = req.email.trim().to_lowercase();
        if !email.contains('@') || !email.contains('.') {
            return Err(AuthError::InvalidEmail);
        }

        if let Some(ref pw) = req.password {
            if pw.len() > self.config.max_password_length {
                return Err(AuthError::PasswordTooLong);
            }
        }

        if self.adapter.find_user_by_email(&email).await?.is_some() {
            return Err(AuthError::bad_request(
                error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
                "User already exists. Use another email.",
            ));
        }

        let hashed_password = match req.password {
            Some(pw) => Some(crypto::hash_password(pw).await.map_err(AuthError::Crypto)?),
            None => None,
        };

        let image = data_map
            .get("image")
            .and_then(|v| v.as_str())
            .map(String::from);
        let email_verified = data_map
            .get("emailVerified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let created = self
            .adapter
            .create_user(CreateUserInput {
                id: None,
                name: req.name,
                email: email.clone(),
                image,
                email_verified,
                role: requested_role.as_ref().map(|r| r.to_csv()),
            })
            .await?;

        let final_role = requested_role
            .map(|r| r.to_csv())
            .unwrap_or_else(|| self.admin_config.default_role.clone());

        let banned = data_map.get("banned").and_then(|v| v.as_bool());
        let ban_reason = data_map
            .get("banReason")
            .map(|v| v.as_str().map(String::from));
        let ban_expires = data_map.get("banExpires").and_then(|v| {
            v.as_str()
                .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
                .map(Some)
        });

        let updated = self
            .adapter
            .update_user_admin(
                &created.id,
                AdminUpdateUserFields {
                    role: Some(final_role),
                    banned,
                    ban_reason,
                    ban_expires,
                    ..Default::default()
                },
            )
            .await?;

        if let Some(pw_hash) = hashed_password {
            self.adapter
                .create_account(CreateAccountInput {
                    id: None,
                    user_id: updated.id.clone(),
                    account_id: updated.id.clone(),
                    provider_id: "credential".to_string(),
                    password: Some(pw_hash),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?;
        }

        let wire = updated.to_wire();
        self.notify_user_created(&wire).await;

        Ok(AdminUserResponse { user: wire })
    }

    /// `POST /api/auth/admin/update-user`
    pub async fn admin_update_user(
        &self,
        actor: &UserWire,
        req: AdminUpdateUserRequest,
    ) -> Result<UserWire, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "update",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS,
            "You are not allowed to update users",
        )?;

        if req.data.is_empty() {
            return Err(AuthError::bad_request(
                error_codes::NO_DATA_TO_UPDATE,
                "No data to update",
            ));
        }

        if req.data.contains_key("password") {
            return Err(AuthError::bad_request(
                error_codes::PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER,
                "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
            ));
        }

        if req.data.contains_key("id") {
            return Err(AuthError::bad_request(
                error_codes::USER_ID_CANNOT_BE_UPDATED,
                "User id cannot be updated",
            ));
        }

        let mut fields = AdminUpdateUserFields::default();

        if let Some(role_val) = req.data.get("role") {
            self.check_admin_permission(
                actor,
                "user",
                "set-role",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE,
                "You are not allowed to change users role",
            )?;
            let rv: RoleValue = serde_json::from_value(role_val.clone()).map_err(|_| {
                AuthError::bad_request(error_codes::INVALID_ROLE_TYPE, "Invalid role type")
            })?;
            let role_list = rv.to_vec();
            self.validate_role_names(&role_list)?;
            fields.role = Some(rv.to_csv());
        }

        if ["banned", "banReason", "banExpires"]
            .iter()
            .any(|k| req.data.contains_key(*k))
        {
            self.check_admin_permission(
                actor,
                "user",
                "ban",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
                "You are not allowed to ban users",
            )?;
            if let Some(b) = req.data.get("banned").and_then(|v| v.as_bool()) {
                if b && req.user_id == actor.id {
                    return Err(AuthError::bad_request(
                        error_codes::YOU_CANNOT_BAN_YOURSELF,
                        "You cannot ban yourself",
                    ));
                }
                fields.banned = Some(b);
            }
            if let Some(reason_val) = req.data.get("banReason") {
                fields.ban_reason = Some(reason_val.as_str().map(String::from));
            }
            if let Some(exp_val) = req.data.get("banExpires") {
                if exp_val.is_null() {
                    fields.ban_expires = Some(None);
                } else if let Some(s) = exp_val.as_str() {
                    if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
                        fields.ban_expires = Some(Some(dt));
                    }
                }
            }
        }

        if req.data.contains_key("email") || req.data.contains_key("emailVerified") {
            self.check_admin_permission(
                actor,
                "user",
                "set-email",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL,
                "You are not allowed to update users email",
            )?;
            if let Some(email_val) = req.data.get("email").and_then(|v| v.as_str()) {
                let normalized = email_val.trim().to_lowercase();
                if !normalized.contains('@') || !normalized.contains('.') {
                    return Err(AuthError::InvalidEmail);
                }
                if let Some(existing) = self.adapter.find_user_by_email(&normalized).await? {
                    if existing.id != req.user_id {
                        return Err(AuthError::bad_request(
                            error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
                            "User already exists. Use another email.",
                        ));
                    }
                }
                fields.email = Some(normalized);
            }
            if let Some(ev) = req.data.get("emailVerified").and_then(|v| v.as_bool()) {
                fields.email_verified = Some(ev);
            }
        }

        if req.data.contains_key("phoneNumber") || req.data.contains_key("phoneNumberVerified") {
            self.check_admin_permission(
                actor,
                "user",
                "set-phone",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PHONE_NUMBER,
                "You are not allowed to update users phone number",
            )?;
        }

        if let Some(name) = req.data.get("name").and_then(|v| v.as_str()) {
            fields.name = Some(name.to_string());
        }
        if let Some(img_val) = req.data.get("image") {
            fields.image = Some(img_val.as_str().filter(|s| !s.is_empty()).map(String::from));
        }

        let updated = self
            .adapter
            .update_user_admin(&req.user_id, fields.clone())
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
            })?;

        if fields.banned == Some(true) {
            self.adapter.delete_sessions_by_user_id(&req.user_id).await?;
        }

        Ok(updated.to_wire())
    }

    /// `GET /api/auth/admin/list-users`
    pub async fn admin_list_users(
        &self,
        actor: &UserWire,
        query: AdminListUsersQuery,
    ) -> Result<AdminListUsersResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "list",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_LIST_USERS,
            "You are not allowed to list users",
        )?;

        let filter = AdminListUsersFilter {
            search_value: query.search_value,
            search_field: query.search_field,
            search_operator: query.search_operator,
            filter_field: query.filter_field,
            filter_value: query.filter_value,
            filter_operator: query.filter_operator,
            sort_by: query.sort_by,
            sort_direction: query.sort_direction,
            limit: query.limit,
            offset: query.offset,
        };

        let (records, total) = self.adapter.list_users(filter).await?;
        let users = records.into_iter().map(|u| u.to_wire()).collect();

        Ok(AdminListUsersResponse {
            users,
            total,
            limit: query.limit,
            offset: query.offset,
        })
    }

    /// `POST /api/auth/admin/list-user-sessions`
    pub async fn admin_list_user_sessions(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminListUserSessionsResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "session",
            "list",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS,
            "You are not allowed to list users sessions",
        )?;

        let records = self.adapter.list_sessions_by_user_id(target_user_id).await?;
        Ok(AdminListUserSessionsResponse {
            sessions: records.into_iter().map(|s| s.to_wire()).collect(),
        })
    }

    /// `POST /api/auth/admin/ban-user`
    pub async fn admin_ban_user(
        &self,
        actor: &UserWire,
        req: AdminBanUserRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "ban",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
            "You are not allowed to ban users",
        )?;

        if self.adapter.find_user_by_id(&req.user_id).await?.is_none() {
            return Err(AuthError::UserNotFound);
        }

        if req.user_id == actor.id {
            return Err(AuthError::bad_request(
                error_codes::YOU_CANNOT_BAN_YOURSELF,
                "You cannot ban yourself",
            ));
        }

        let reason = req
            .ban_reason
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.admin_config.default_ban_reason.clone());

        let expires = req
            .ban_expires_in
            .or(self.admin_config.default_ban_expires_in)
            .map(|secs| OffsetDateTime::now_utc() + Duration::seconds(secs));

        let updated = self
            .adapter
            .update_user_admin(
                &req.user_id,
                AdminUpdateUserFields {
                    banned: Some(true),
                    ban_reason: Some(Some(reason)),
                    ban_expires: Some(expires),
                    ..Default::default()
                },
            )
            .await?;

        self.adapter.delete_sessions_by_user_id(&req.user_id).await?;

        Ok(AdminUserResponse {
            user: updated.to_wire(),
        })
    }

    /// `POST /api/auth/admin/unban-user`
    pub async fn admin_unban_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "ban",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
            "You are not allowed to ban users",
        )?;

        let updated = self
            .adapter
            .update_user_admin(
                target_user_id,
                AdminUpdateUserFields {
                    banned: Some(false),
                    ban_reason: Some(None),
                    ban_expires: Some(None),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
            })?;

        Ok(AdminUserResponse {
            user: updated.to_wire(),
        })
    }

    /// `POST /api/auth/admin/impersonate-user`
    pub async fn admin_impersonate_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
        meta: RequestMeta,
    ) -> Result<SessionAndUserResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "impersonate",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS,
            "You are not allowed to impersonate users",
        )?;

        let target = self
            .adapter
            .find_user_by_id(target_user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if self
            .admin_config
            .is_admin_user(&target.id, target.role.as_deref())
        {
            let can_impersonate_admins = self.admin_config.allow_impersonating_admins
                || self.admin_config.has_permission(
                    Some(&actor.id),
                    actor.role.as_deref(),
                    "user",
                    "impersonate-admins",
                );
            if !can_impersonate_admins {
                return Err(AuthError::forbidden(
                    error_codes::YOU_CANNOT_IMPERSONATE_ADMINS,
                    "You cannot impersonate admins",
                ));
            }
        }

        let raw_token = crypto::generate_session_token();
        let expires_at =
            OffsetDateTime::now_utc() + self.admin_config.impersonation_session_duration;

        let session = self
            .adapter
            .create_impersonated_session(
                CreateSessionInput {
                    id: None,
                    user_id: target.id.clone(),
                    token: raw_token,
                    expires_at,
                    ip_address: meta.ip_address,
                    user_agent: meta.user_agent,
                },
                actor.id.clone(),
            )
            .await?;

        Ok(SessionAndUserResponse {
            session: session.to_wire(),
            user: target.to_wire(),
        })
    }

    /// `POST /api/auth/admin/stop-impersonating`
    pub async fn admin_stop_impersonating(
        &self,
        current_session: &SessionWire,
        admin_token_or_signed: Option<&str>,
    ) -> Result<SessionAndUserResponse, AuthError> {
        let admin_user_id = current_session.impersonated_by.as_ref().ok_or_else(|| {
            AuthError::bad_request("NOT_IMPERSONATING", "You are not impersonating anyone")
        })?;

        let admin_user = self
            .adapter
            .find_user_by_id(admin_user_id)
            .await?
            .ok_or_else(|| AuthError::Internal("Failed to find admin user".to_string()))?;

        let tok_str = admin_token_or_signed.ok_or_else(|| {
            AuthError::Internal("Failed to find admin session".to_string())
        })?;

        let clean = tok_str.split(':').next().unwrap_or(tok_str);
        let raw = self.verify_signed_token(clean).ok_or_else(|| {
            AuthError::Internal("Failed to find admin session".to_string())
        })?;

        let admin_session = match self.adapter.find_session_by_token(&raw).await? {
            Some(s) if s.user_id == admin_user.id && !s.is_expired() => s,
            _ => {
                return Err(AuthError::Internal(
                    "Failed to find admin session".to_string(),
                ))
            }
        };

        self.adapter.delete_session(&current_session.token).await?;

        Ok(SessionAndUserResponse {
            session: admin_session.to_wire(),
            user: admin_user.to_wire(),
        })
    }

    /// `POST /api/auth/admin/revoke-user-session`
    pub async fn admin_revoke_user_session(
        &self,
        actor: &UserWire,
        session_token_or_signed: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "session",
            "revoke",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS,
            "You are not allowed to revoke users sessions",
        )?;

        let raw_token = self
            .verify_token(session_token_or_signed)
            .unwrap_or_else(|| session_token_or_signed.to_string());

        self.adapter.delete_session(&raw_token).await?;
        Ok(AdminSuccessResponse::ok())
    }

    /// `POST /api/auth/admin/revoke-user-sessions`
    pub async fn admin_revoke_user_sessions(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "session",
            "revoke",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS,
            "You are not allowed to revoke users sessions",
        )?;

        self.adapter.delete_sessions_by_user_id(target_user_id).await?;
        Ok(AdminSuccessResponse::ok())
    }

    /// `POST /api/auth/admin/remove-user`
    pub async fn admin_remove_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "delete",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS,
            "You are not allowed to delete users",
        )?;

        if target_user_id == actor.id {
            return Err(AuthError::bad_request(
                error_codes::YOU_CANNOT_REMOVE_YOURSELF,
                "You cannot remove yourself",
            ));
        }

        if self.adapter.find_user_by_id(target_user_id).await?.is_none() {
            return Err(AuthError::UserNotFound);
        }

        self.adapter.delete_sessions_by_user_id(target_user_id).await?;
        self.adapter.delete_user(target_user_id).await?;
        self.hooks.on_user_deleted(target_user_id).await;

        Ok(AdminSuccessResponse::ok())
    }

    /// `POST /api/auth/admin/set-user-password`
    pub async fn admin_set_user_password(
        &self,
        actor: &UserWire,
        req: AdminSetUserPasswordRequest,
    ) -> Result<StatusResponse, AuthError> {
        self.check_admin_permission(
            actor,
            "user",
            "set-password",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD,
            "You are not allowed to set users password",
        )?;

        if req.new_password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort);
        }
        if req.new_password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let user = self
            .adapter
            .find_user_by_id(&req.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let password_hash = crypto::hash_password(req.new_password)
            .await
            .map_err(AuthError::Crypto)?;

        if self.find_credential_account(&user.id).await?.is_some() {
            self.adapter
                .update_account_password(&user.id, &password_hash)
                .await?;
        } else {
            self.adapter
                .create_account(CreateAccountInput {
                    id: None,
                    user_id: user.id.clone(),
                    account_id: user.id,
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

        Ok(StatusResponse::success())
    }

    /// `POST /api/auth/admin/has-permission`
    pub async fn admin_has_permission(
        &self,
        actor: Option<&UserWire>,
        req: AdminHasPermissionRequest,
    ) -> Result<AdminPermissionResponse, AuthError> {
        let perms = req
            .permissions
            .or(req.permission)
            .ok_or_else(|| {
                AuthError::bad_request(
                    "INVALID_PERMISSION_CHECK",
                    "invalid permission check. no permission(s) were passed.",
                )
            })?;

        let (resolved_user_id, resolved_role) = if let Some(role) = req.role {
            (req.user_id, Some(role))
        } else if let Some(uid) = req.user_id {
            let user = self
                .adapter
                .find_user_by_id(&uid)
                .await?
                .ok_or_else(|| AuthError::bad_request(error_codes::USER_NOT_FOUND, "user not found"))?;
            (Some(user.id), user.role)
        } else if let Some(act) = actor {
            (Some(act.id.clone()), act.role.clone())
        } else {
            return Err(AuthError::bad_request(
                "USER_ID_OR_ROLE_REQUIRED",
                "user id or role is required",
            ));
        };

        let success = self.admin_config.has_permission_map(
            resolved_user_id.as_deref(),
            resolved_role.as_deref(),
            &perms,
        );

        Ok(AdminPermissionResponse {
            error: None,
            success,
        })
    }

    /// `POST /api/auth/sign-in/social`
    pub async fn begin_social_sign_in(
        &self,
        provider: &crate::oauth::OAuthProviderConfig,
        payload: auth_proto::SignInSocialRequest,
    ) -> Result<auth_proto::SignInSocialResponse, AuthError> {
        let oauth_state = crypto::generate_random_token(32);
        let code_verifier = crypto::generate_random_token(32);

        use sha2::{Digest, Sha256};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        let state_data = crate::oauth::OAuthStateData {
            code_verifier,
            callback_url: payload.callback_url,
            new_user_callback_url: payload.new_user_callback_url,
            error_callback_url: payload.error_callback_url,
            link_user_id: None,
        };
        let value = serde_json::to_string(&state_data)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
        self.adapter
            .create_verification(CreateVerificationInput {
                id: None,
                identifier: format!("auth-state:{oauth_state}"),
                value,
                expires_at,
            })
            .await?;

        let callback_uri = format!("{}/callback/{}", self.config.base_url, provider.provider_id);
        let scopes_str = provider.scopes.join(" ");

        let mut auth_url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            provider.auth_url,
            provider.client_id,
            auth_proto::url_encode(&callback_uri),
            auth_proto::url_encode(&scopes_str),
            oauth_state,
            challenge
        );
        if let Some(ref hint) = payload.login_hint {
            auth_url.push_str(&format!("&login_hint={}", auth_proto::url_encode(hint)));
        }

        let disable_redirect = payload.disable_redirect.unwrap_or(false);
        Ok(auth_proto::SignInSocialResponse {
            redirect: !disable_redirect,
            url: auth_url,
        })
    }

    /// `POST /api/auth/link-social`
    pub async fn begin_link_social(
        &self,
        provider: &crate::oauth::OAuthProviderConfig,
        user_id: &str,
        payload: auth_proto::LinkSocialRequest,
    ) -> Result<auth_proto::SignInSocialResponse, AuthError> {
        let oauth_state = crypto::generate_random_token(32);
        let code_verifier = crypto::generate_random_token(32);

        use sha2::{Digest, Sha256};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        let state_data = crate::oauth::OAuthStateData {
            code_verifier,
            callback_url: payload.callback_url,
            new_user_callback_url: None,
            error_callback_url: payload.error_callback_url,
            link_user_id: Some(user_id.to_string()),
        };
        let value = serde_json::to_string(&state_data)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
        self.adapter
            .create_verification(CreateVerificationInput {
                id: None,
                identifier: format!("auth-state:{oauth_state}"),
                value,
                expires_at,
            })
            .await?;

        let callback_uri = format!("{}/callback/{}", self.config.base_url, provider.provider_id);
        let mut scopes = provider.scopes.clone();
        if let Some(extra) = payload.scopes {
            for s in extra {
                if !scopes.contains(&s) {
                    scopes.push(s);
                }
            }
        }
        let scopes_str = scopes.join(" ");

        let auth_url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            provider.auth_url,
            provider.client_id,
            auth_proto::url_encode(&callback_uri),
            auth_proto::url_encode(&scopes_str),
            oauth_state,
            challenge
        );

        let disable_redirect = payload.disable_redirect.unwrap_or(false);
        Ok(auth_proto::SignInSocialResponse {
            redirect: !disable_redirect,
            url: auth_url,
        })
    }

    /// Consumes and validates the OAuth `state` verification record.
    pub async fn consume_oauth_state(
        &self,
        oauth_state: &str,
    ) -> Result<crate::oauth::OAuthStateData, AuthError> {
        let primary_id = format!("auth-state:{oauth_state}");
        let legacy_id = format!("oauth-state:{oauth_state}");
        let record = match self.adapter.consume_verification(&primary_id).await? {
            Some(r) => r,
            None => match self.adapter.consume_verification(&legacy_id).await? {
                Some(r) => r,
                None => {
                    return Err(AuthError::bad_request(
                        "INVALID_STATE",
                        "OAuth state not found or expired",
                    ));
                }
            },
        };

        serde_json::from_str(&record.value).map_err(|e| {
            AuthError::bad_request("INVALID_STATE", format!("Corrupted OAuth state payload: {e}"))
        })
    }

    /// Completes the OAuth callback: links an account or signs in/signs up the user and issues a session.
    pub async fn complete_oauth_callback(
        &self,
        provider_name: &str,
        profile: crate::oauth::OAuthProfileResult,
        link_user_id: Option<String>,
        meta: RequestMeta,
    ) -> Result<OAuthCallbackResult, AuthError> {
        // Case 1: Account linking flow
        if let Some(target_user_id) = link_user_id {
            if let Some(existing_acc) = self.adapter.find_account(provider_name, &profile.account_id).await? {
                if existing_acc.user_id != target_user_id {
                    return Err(AuthError::SocialAccountAlreadyLinked);
                }
                self.adapter
                    .update_account_tokens(
                        provider_name,
                        &profile.account_id,
                        Some(profile.access_token),
                        profile.refresh_token,
                        profile.id_token,
                        profile.access_token_expires_at,
                        profile.scope,
                    )
                    .await?;
            } else {
                self.adapter
                    .create_account(CreateAccountInput {
                        id: None,
                        user_id: target_user_id.clone(),
                        account_id: profile.account_id,
                        provider_id: provider_name.to_string(),
                        access_token: Some(profile.access_token),
                        refresh_token: profile.refresh_token,
                        id_token: profile.id_token,
                        access_token_expires_at: profile.access_token_expires_at,
                        refresh_token_expires_at: None,
                        scope: profile.scope,
                        password: None,
                    })
                    .await?;
            }
            return Ok(OAuthCallbackResult::Linked { user_id: target_user_id });
        }

        // Case 2: Sign-in / sign-up flow
        let mut is_new_user = false;
        let user = if let Some(existing_acc) = self.adapter.find_account(provider_name, &profile.account_id).await? {
            self.adapter
                .update_account_tokens(
                    provider_name,
                    &profile.account_id,
                    Some(profile.access_token),
                    profile.refresh_token,
                    profile.id_token,
                    profile.access_token_expires_at,
                    profile.scope,
                )
                .await?;

            self.adapter
                .find_user_by_id(&existing_acc.user_id)
                .await?
                .ok_or_else(|| AuthError::Internal("Linked user not found".to_string()))?
        } else {
            let user = match self.adapter.find_user_by_email(&profile.email).await? {
                Some(mut existing) => {
                    if !profile.email_verified {
                        return Err(AuthError::EmailNotVerified);
                    }
                    if !existing.email_verified {
                        self.adapter
                            .update_user_email_verified(&existing.id, true)
                            .await?;
                        existing.email_verified = true;
                    }
                    existing
                }
                None => {
                    is_new_user = true;
                    let created = self
                        .adapter
                        .create_user(CreateUserInput {
                            id: None,
                            name: profile.name,
                            email: profile.email.clone(),
                            image: profile.image,
                            email_verified: profile.email_verified,
                            role: None,
                        })
                        .await?;
                    self.notify_user_created(&created.to_wire()).await;
                    created
                }
            };

            self.adapter
                .create_account(CreateAccountInput {
                    id: None,
                    user_id: user.id.clone(),
                    account_id: profile.account_id,
                    provider_id: provider_name.to_string(),
                    access_token: Some(profile.access_token),
                    refresh_token: profile.refresh_token,
                    id_token: profile.id_token,
                    access_token_expires_at: profile.access_token_expires_at,
                    refresh_token_expires_at: None,
                    scope: profile.scope,
                    password: None,
                })
                .await?;

            user
        };

        let session = self.issue_session_for_user(&user, meta, true).await?;
        Ok(OAuthCallbackResult::Authenticated {
            user,
            session,
            is_new_user,
        })
    }
}

/// Result of an OAuth callback handled by `AuthService::complete_oauth_callback`.
#[derive(Debug, Clone)]
pub enum OAuthCallbackResult {
    /// Account linked to an existing authenticated user.
    Linked { user_id: String },
    /// User authenticated (either via existing account or new registration) and session issued.
    Authenticated {
        user: UserRecord,
        session: SessionRecord,
        is_new_user: bool,
    },
}
