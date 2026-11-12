//! Core authentication service coordinating business logic, crypto, hooks, plugins, and persistence.

use auth_proto::{
    AccountInfoResponse, AccountListEntryWire, AdminBanUserRequest, AdminCreateUserRequest,
    AdminHasPermissionRequest, AdminListUserSessionsResponse, AdminListUsersQuery,
    AdminListUsersResponse, AdminPermissionResponse, AdminSetRoleRequest,
    AdminSetUserPasswordRequest, AdminSuccessResponse, AdminUpdateUserRequest, AdminUserResponse,
    ChangeEmailRequest, ChangePasswordRequest, ChangePasswordResponse, DeleteUserRequest,
    DeleteUserResponse, OAuthAccountSelectionRequest, OAuthTokenResponse,
    OneTimeTokenGenerateResponse, RequestPasswordResetRequest, ResetPasswordRequest,
    SendVerificationEmailRequest, SessionAndUserResponse, SessionWire, SetPasswordRequest,
    SignInEmailRequest, SignInResponse, SignOutRequest, SignOutResponse, SignUpEmailRequest,
    SignUpResponse, StatusMessageResponse, StatusResponse, UpdateSessionRequest, UpdateUserRequest,
    UpdateUserResponse, UserWire, VerifyEmailResponse, VerifyPasswordRequest, error_codes,
    url_encode,
};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use crate::access::AdminConfig;
use crate::adapter::AuthAdapter;
use crate::crypto;
use crate::email::{EmailSender, NoopEmailSender};
use crate::error::{AdapterError, AuthError};
use crate::hooks::{AuthHooks, NoopAuthHooks, SlidingWindowRateLimiter};
use crate::models::{
    AccountRecord, CreateAccountInput, CreateSessionInput, CreateUserInput,
    CreateVerificationInput, RequestMeta, SessionRecord, UpdateUserFields, UserRecord,
};
#[allow(deprecated)]
use crate::plugin::LegacyAuthPlugin;
use crate::plugin::admin::{AdminPlugin, AdminServiceExt};
use crate::plugin::{AuthPlugin, HookedAdapter, PluginRateLimitRule, PluginRegistry};

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

/// Core domain service handling authentication workflows, sessions, and plugins.
#[derive(Clone)]
pub struct AuthService {
    config: AuthConfig,
    raw_adapter: Arc<dyn AuthAdapter>,
    adapter: Arc<dyn AuthAdapter>,
    email_sender: Arc<dyn EmailSender>,
    hooks: Arc<dyn AuthHooks>,
    rate_limiter: Option<Arc<SlidingWindowRateLimiter>>,
    plugins: PluginRegistry,
    plugin_rate_limiters: Vec<(PluginRateLimitRule, Arc<SlidingWindowRateLimiter>)>,
    #[allow(deprecated)]
    legacy_plugins: Arc<Vec<Arc<dyn LegacyAuthPlugin>>>,
    auto_sign_in_after_verification: bool,
    session_update_age: Duration,
    session_fresh_age: Duration,
}

/// Validates an email address format.
pub fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    if email.len() < 3 || email.len() > 254 {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    true
}

impl AuthService {
    pub fn new(config: AuthConfig, adapter: Arc<dyn AuthAdapter>) -> Self {
        let raw_adapter = adapter.clone();
        let mut plugins = PluginRegistry::new();
        plugins.register(Arc::new(AdminPlugin::default()));
        plugins.register(Arc::new(crate::plugin::OneTimeTokenPlugin::default()));
        let mut s = Self {
            config,
            raw_adapter,
            adapter,
            email_sender: Arc::new(NoopEmailSender),
            hooks: Arc::new(NoopAuthHooks),
            rate_limiter: None,
            plugins,
            plugin_rate_limiters: Vec::new(),
            legacy_plugins: Arc::new(Vec::new()),
            auto_sign_in_after_verification: false,
            session_update_age: Duration::hours(24),
            session_fresh_age: Duration::hours(24),
        };
        s.rebuild_hooked_adapter();
        s
    }

    pub fn with_admin_config(mut self, admin_config: AdminConfig) -> Self {
        self.plugins
            .register(Arc::new(AdminPlugin::with_config(admin_config)));
        self.rebuild_hooked_adapter();
        self
    }

    pub fn admin_config(&self) -> Option<&AdminConfig> {
        self.get_plugin::<AdminPlugin>().map(|p| &p.config)
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

    /// Registers a modular plugin with `AuthService`.
    pub fn with_plugin<P: AuthPlugin + 'static>(mut self, plugin: P) -> Self {
        self.plugins.register(Arc::new(plugin));
        self.rebuild_hooked_adapter();
        self
    }

    /// Registers a plugin `Arc` with `AuthService`.
    pub fn with_plugin_arc(mut self, plugin: Arc<dyn AuthPlugin>) -> Self {
        self.plugins.register(plugin);
        self.rebuild_hooked_adapter();
        self
    }

    /// Accessor for the registered `PluginRegistry`.
    pub fn plugins(&self) -> &PluginRegistry {
        &self.plugins
    }

    /// Retrieves and downcasts a registered plugin by type.
    pub fn get_plugin<P: AuthPlugin + 'static>(&self) -> Option<&P> {
        self.plugins.get::<P>()
    }

    /// Registers a legacy plugin with `AuthService`.
    #[allow(deprecated)]
    pub fn with_legacy_plugin(mut self, plugin: Arc<dyn LegacyAuthPlugin>) -> Self {
        let mut list = (*self.legacy_plugins).clone();
        list.push(plugin);
        self.legacy_plugins = Arc::new(list);
        self
    }

    /// Accessor for legacy plugins.
    #[allow(deprecated)]
    pub fn legacy_plugins(&self) -> &[Arc<dyn LegacyAuthPlugin>] {
        &self.legacy_plugins
    }

    fn rebuild_hooked_adapter(&mut self) {
        let db_hooks = self.plugins.database_hooks();
        if db_hooks.is_empty() {
            self.adapter = self.raw_adapter.clone();
        } else {
            self.adapter = Arc::new(HookedAdapter::new(self.raw_adapter.clone(), db_hooks));
        }
        self.plugin_rate_limiters = self
            .plugins
            .rate_limits()
            .into_iter()
            .map(|rule| {
                let limiter = Arc::new(SlidingWindowRateLimiter::new(
                    rule.max_requests,
                    rule.window,
                ));
                (rule, limiter)
            })
            .collect();
    }

    /// Checks path-based rate limits defined by registered plugins.
    pub fn check_plugin_rate_limits(&self, path: &str, client_ip: &str) -> Result<(), AuthError> {
        for (rule, limiter) in &self.plugin_rate_limiters {
            if (rule.path_matcher)(path) {
                let key = format!("plugin:{}:{}:{}", rule.id, path, client_ip);
                limiter.check(&key)?;
            }
        }
        Ok(())
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
        crypto::sign_cookie_hmac(&self.config.secret, raw_token)
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

    /// Emits the `on_user_deleted` lifecycle hook.
    pub async fn notify_user_deleted(&self, user_id: &str) {
        self.hooks.on_user_deleted(user_id).await;
    }

    /// Issues a session for `user` while executing `AuthPlugin` and `AuthHooks` callbacks.
    pub async fn issue_session_for_user(
        &self,
        user: &UserRecord,
        meta: RequestMeta,
        run_before_sign_in: bool,
    ) -> Result<SessionRecord, AuthError> {
        let user_wire = user.to_wire();
        if run_before_sign_in {
            #[allow(deprecated)]
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
        self.hooks
            .on_session_created(&session_wire, &user_wire)
            .await;
        #[allow(deprecated)]
        for plugin in self.legacy_plugins.iter() {
            plugin
                .on_after_session_issued(&session_wire, &user_wire)
                .await?;
        }

        Ok(session)
    }

    /// Looks up a user's `credential` account by `(provider_id = "credential", account_id = user_id)`
    /// with a fallback scan across `find_accounts_by_user_id` for migrated databases
    /// where `account.account_id` differs from `user.id`.
    pub async fn find_credential_account(
        &self,
        user_id: &str,
    ) -> Result<Option<AccountRecord>, AuthError> {
        if let Some(account) = self.adapter.find_account("credential", user_id).await? {
            return Ok(Some(account));
        }
        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        Ok(accounts.into_iter().find(|a| a.provider_id == "credential"))
    }

    // ──────────────────────────────────────────────
    // Sign-Up & Sign-In
    // ──────────────────────────────────────────────

    /// Registers a new user with email and password.
    pub async fn sign_up_email(
        &self,
        req: SignUpEmailRequest,
    ) -> Result<SignUpResponse, AuthError> {
        self.sign_up_email_with_meta(req, RequestMeta::default())
            .await
    }

    /// Registers a new user with email, password, and HTTP request metadata (`ip_address`, `user_agent`).
    pub async fn sign_up_email_with_meta(
        &self,
        req: SignUpEmailRequest,
        meta: RequestMeta,
    ) -> Result<SignUpResponse, AuthError> {
        let rate_key = format!("sign-up:{}", meta.ip_address.as_deref().unwrap_or("local"));
        self.check_rate_limit(&rate_key)?;

        let email = req.email.trim().to_lowercase();
        if !is_valid_email(&email) {
            return Err(AuthError::InvalidEmail);
        }

        if req.password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort {
                min: self.config.min_password_length,
            });
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

        let (user, _account) = self
            .adapter
            .create_user_with_account(
                CreateUserInput {
                    id: None,
                    name: req.name,
                    email: email.clone(),
                    image: req.image,
                    email_verified: false,
                    role: None,
                },
                CreateAccountInput {
                    id: None,
                    user_id: String::new(),
                    account_id: String::new(),
                    provider_id: "credential".to_string(),
                    password: Some(password_hash),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                },
            )
            .await?;

        let user_wire = user.to_wire();
        self.notify_user_created(&user_wire).await;

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
    pub async fn sign_in_email(
        &self,
        req: SignInEmailRequest,
    ) -> Result<SignInResponse, AuthError> {
        self.sign_in_email_with_meta(req, RequestMeta::default())
            .await
    }

    /// Authenticates a user with email, password, and HTTP request metadata (`ip_address`, `user_agent`).
    pub async fn sign_in_email_with_meta(
        &self,
        req: SignInEmailRequest,
        meta: RequestMeta,
    ) -> Result<SignInResponse, AuthError> {
        let rate_key = format!("sign-in:{}", meta.ip_address.as_deref().unwrap_or("local"));
        self.check_rate_limit(&rate_key)?;

        let email = req.email.trim().to_lowercase();
        if !is_valid_email(&email) {
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

        // Transparently upgrade legacy scrypt password hashes to Argon2id
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

            let reset_url = format!(
                "{}/reset-password/{}{}",
                self.config.base_url, token, redirect_param
            );

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
    pub async fn reset_password(
        &self,
        req: ResetPasswordRequest,
    ) -> Result<StatusResponse, AuthError> {
        self.reset_password_with_meta(req, RequestMeta::default())
            .await
    }

    /// Resets the user's password using a verification token with IP rate limiting.
    pub async fn reset_password_with_meta(
        &self,
        req: ResetPasswordRequest,
        meta: RequestMeta,
    ) -> Result<StatusResponse, AuthError> {
        let rate_key = format!(
            "reset-password:{}",
            meta.ip_address.as_deref().unwrap_or("local")
        );
        self.check_rate_limit(&rate_key)?;

        let token = req.token.ok_or(AuthError::InvalidToken)?;

        if req.new_password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort {
                min: self.config.min_password_length,
            });
        }
        if req.new_password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let identifier = format!("reset-password:{token}");
        let record = self
            .adapter
            .find_verification(&identifier)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if record.expires_at < OffsetDateTime::now_utc() {
            let _ = self.adapter.consume_verification(&identifier).await;
            return Err(AuthError::TokenExpired);
        }

        let user_id = record.value;
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

        let _ = self.adapter.consume_verification(&identifier).await;

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
            return Err(AuthError::PasswordTooShort {
                min: self.config.min_password_length,
            });
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

    /// Sets the initial password for a user without requiring an existing password.
    pub async fn set_password(
        &self,
        user_id: &str,
        req: SetPasswordRequest,
    ) -> Result<StatusResponse, AuthError> {
        if req.new_password.len() < self.config.min_password_length {
            return Err(AuthError::PasswordTooShort {
                min: self.config.min_password_length,
            });
        }
        if req.new_password.len() > self.config.max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let existing_account = self.find_credential_account(user_id).await?;
        let password_hash = crypto::hash_password(req.new_password)
            .await
            .map_err(AuthError::Crypto)?;

        match existing_account {
            None => {
                self.adapter
                    .create_account(CreateAccountInput {
                        id: None,
                        user_id: user_id.to_string(),
                        account_id: user_id.to_string(),
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
                Ok(StatusResponse::success())
            }
            Some(account) => {
                if account.password.is_some() {
                    return Err(AuthError::PasswordAlreadySet);
                }
                self.adapter
                    .update_account_password(user_id, &password_hash)
                    .await?;
                Ok(StatusResponse::success())
            }
        }
    }

    /// Statelessly verifies the user's password without modifying any state.
    pub async fn verify_password(
        &self,
        user_id: &str,
        req: VerifyPasswordRequest,
    ) -> Result<StatusResponse, AuthError> {
        let account = self
            .find_credential_account(user_id)
            .await?
            .ok_or(AuthError::InvalidPassword)?;

        let stored_hash = account.password.ok_or(AuthError::InvalidPassword)?;
        let valid = crypto::verify_password(stored_hash, req.password)
            .await
            .map_err(AuthError::Crypto)?;

        if !valid {
            return Err(AuthError::InvalidPassword);
        }

        Ok(StatusResponse::success())
    }

    /// Initiates email address change with verification token emission.
    pub async fn change_email(
        &self,
        user_id: &str,
        req: ChangeEmailRequest,
    ) -> Result<StatusResponse, AuthError> {
        let new_email = req.new_email.trim().to_lowercase();
        if !is_valid_email(&new_email) {
            return Err(AuthError::InvalidEmail);
        }

        let current_user = self
            .adapter
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if new_email == current_user.email.to_lowercase() {
            return Err(AuthError::bad_request("BAD_REQUEST", "Email is the same"));
        }

        // Return status true to avoid timing/enumeration leaks if email already exists
        if let Some(_existing) = self.adapter.find_user_by_email(&new_email).await? {
            return Ok(StatusResponse::success());
        }

        let token = crypto::generate_random_token(32);
        let identifier = format!("change-email:{token}");
        let expires_at = OffsetDateTime::now_utc() + self.config.verify_email_expires_in;

        self.adapter
            .create_verification(CreateVerificationInput {
                id: None,
                identifier,
                value: format!("{user_id}:{new_email}"),
                expires_at,
            })
            .await?;

        let callback_url = req.callback_url.as_deref().unwrap_or("/");
        let verification_url = format!(
            "{}/verify-email?token={}&callbackURL={}",
            self.config.base_url.trim_end_matches('/'),
            token,
            url_encode(callback_url)
        );

        self.email_sender
            .send_verification_email(&current_user.email, &verification_url, &token)
            .await
            .map_err(AuthError::Email)?;

        Ok(StatusResponse::success())
    }

    /// Updates session metadata and touches updated_at.
    pub async fn update_session(
        &self,
        token: &str,
        _req: UpdateSessionRequest,
    ) -> Result<SessionWire, AuthError> {
        let raw_token = self
            .verify_token(token)
            .unwrap_or_else(|| token.to_string());
        let session = self
            .adapter
            .find_session_by_token(&raw_token)
            .await?
            .ok_or(AuthError::SessionExpired)?;

        let now = OffsetDateTime::now_utc();
        let _ = self
            .adapter
            .update_session_expiry(&raw_token, session.expires_at)
            .await;

        let updated_session = SessionRecord {
            updated_at: now,
            ..session
        };
        Ok(updated_session.to_wire())
    }

    /// Retrieves OAuth tokens for a linked account.
    pub async fn get_access_token(
        &self,
        user_id: &str,
        req: OAuthAccountSelectionRequest,
    ) -> Result<OAuthTokenResponse, AuthError> {
        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        let account = accounts
            .into_iter()
            .find(|a| {
                if let Some(ref pid) = req.provider_id {
                    if !a.provider_id.eq_ignore_ascii_case(pid) {
                        return false;
                    }
                }
                if let Some(ref aid) = req.account_id {
                    if a.account_id != *aid {
                        return false;
                    }
                }
                a.provider_id != "credential"
            })
            .ok_or(AuthError::AccountNotFound)?;

        Ok(OAuthTokenResponse {
            token_type: Some("Bearer".to_string()),
            id_token: account.id_token,
            access_token: account.access_token,
            refresh_token: account.refresh_token,
            access_token_expires_at: account.access_token_expires_at,
            refresh_token_expires_at: account.refresh_token_expires_at,
        })
    }

    /// Refreshes and returns OAuth tokens for a linked account.
    pub async fn refresh_token(
        &self,
        user_id: &str,
        req: OAuthAccountSelectionRequest,
    ) -> Result<OAuthTokenResponse, AuthError> {
        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        let account = accounts
            .into_iter()
            .find(|a| {
                if let Some(ref pid) = req.provider_id {
                    if !a.provider_id.eq_ignore_ascii_case(pid) {
                        return false;
                    }
                }
                if let Some(ref aid) = req.account_id {
                    if a.account_id != *aid {
                        return false;
                    }
                }
                a.provider_id != "credential"
            })
            .ok_or(AuthError::AccountNotFound)?;

        if account.refresh_token.is_none() {
            return Err(AuthError::FailedToRefreshAccessToken);
        }

        Ok(OAuthTokenResponse {
            token_type: Some("Bearer".to_string()),
            id_token: account.id_token,
            access_token: account.access_token,
            refresh_token: account.refresh_token,
            access_token_expires_at: account.access_token_expires_at,
            refresh_token_expires_at: account.refresh_token_expires_at,
        })
    }

    /// Deletes user upon verification of email callback token.
    pub async fn delete_user_by_callback(&self, token: &str) -> Result<String, AuthError> {
        if !self.config.delete_user_enabled {
            return Err(AuthError::NotFound);
        }

        let identifier = format!("delete-account-{token}");
        let alt_identifier = format!("delete-user:{token}");

        let record = match self.adapter.consume_verification(&identifier).await? {
            Some(rec) => rec,
            None => self
                .adapter
                .consume_verification(&alt_identifier)
                .await?
                .ok_or(AuthError::InvalidToken)?,
        };

        if record.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        let user_id = record.value;
        self.adapter.delete_user(&user_id).await?;
        self.adapter.delete_sessions_by_user_id(&user_id).await?;
        self.hooks.on_user_deleted(&user_id).await;
        Ok(user_id)
    }

    /// Returns public account information and provider metadata for a linked account.
    pub async fn get_account_info(
        &self,
        user_id: &str,
        req: OAuthAccountSelectionRequest,
    ) -> Result<AccountInfoResponse, AuthError> {
        let user = self
            .adapter
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let accounts = self.adapter.find_accounts_by_user_id(user_id).await?;
        let account = accounts
            .into_iter()
            .find(|a| {
                if let Some(ref pid) = req.provider_id {
                    if !a.provider_id.eq_ignore_ascii_case(pid) {
                        return false;
                    }
                }
                if let Some(ref aid) = req.account_id {
                    if a.account_id != *aid {
                        return false;
                    }
                }
                a.provider_id != "credential"
            })
            .ok_or(AuthError::AccountNotFound)?;

        Ok(AccountInfoResponse {
            user: user.to_wire(),
            account: AccountListEntryWire {
                id: account.id,
                provider_id: account.provider_id,
                account_id: account.account_id,
                user_id: account.user_id,
                created_at: account.created_at,
                updated_at: account.updated_at,
                scopes: account
                    .scope
                    .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
                    .unwrap_or_default(),
            },
            data: serde_json::json!({}),
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
            return Err(AuthError::bad_request("BAD_REQUEST", "No fields to update"));
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
            } else {
                return Err(AuthError::SessionNotFresh);
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

    /// Verifies email via token (for signup verification or change-email confirmation) and optionally issues a session when `auto_sign_in_after_verification` is enabled.
    pub async fn verify_email_with_meta(
        &self,
        token: &str,
        meta: RequestMeta,
    ) -> Result<VerifyEmailResponse, AuthError> {
        let verify_id = format!("verify-email:{token}");
        let change_id = format!("change-email:{token}");

        let (record, is_change_email) = match self.adapter.consume_verification(&verify_id).await? {
            Some(rec) => (rec, false),
            None => match self.adapter.consume_verification(&change_id).await? {
                Some(rec) => (rec, true),
                None => return Err(AuthError::InvalidToken),
            },
        };

        if record.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        let user_id = if is_change_email {
            let (uid, new_email) = match record.value.split_once(':') {
                Some((u, e)) => (u.to_string(), e.to_string()),
                None => (record.value, String::new()),
            };

            if !new_email.is_empty() {
                self.adapter
                    .update_user(
                        &uid,
                        UpdateUserFields {
                            email: Some(new_email),
                            email_verified: Some(true),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
            uid
        } else {
            let uid = record.value;
            self.adapter
                .update_user_email_verified(&uid, true)
                .await?;
            uid
        };

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

        if let Some(plugin) = self.get_plugin::<crate::plugin::OneTimeTokenPlugin>() {
            plugin.generate_token(&session.token, &*self.adapter).await
        } else {
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
    }

    /// Atomically verifies and burns a one-time token, resolving to the attached session.
    pub async fn verify_one_time_token(
        &self,
        token: &str,
    ) -> Result<SessionAndUserResponse, AuthError> {
        if let Some(plugin) = self.get_plugin::<crate::plugin::OneTimeTokenPlugin>() {
            plugin.verify_token(token, &*self.adapter).await
        } else {
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
    }

    // ──────────────────────────────────────────────
    // Accounts
    // ──────────────────────────────────────────────

    /// Lists connected accounts for a user with sensitive fields stripped.
    pub async fn list_accounts(
        &self,
        user_id: &str,
    ) -> Result<Vec<AccountListEntryWire>, AuthError> {
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
                let provider_matches = provider_id.is_empty() || a.provider_id == provider_id;
                let account_matches =
                    account_id.is_empty() || a.account_id == account_id || a.id == account_id;
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
    // Admin Plugin Operations (Delegated to AdminPlugin via AdminServiceExt)
    // ──────────────────────────────────────────────

    /// `POST /api/auth/admin/set-role`
    pub async fn admin_set_role(
        &self,
        actor: &UserWire,
        req: AdminSetRoleRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.admin()?.set_role(actor, req).await
    }

    /// `GET /api/auth/admin/get-user`
    pub async fn admin_get_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<UserWire, AuthError> {
        self.admin()?.get_user(actor, target_user_id).await
    }

    /// `POST /api/auth/admin/create-user`
    pub async fn admin_create_user(
        &self,
        actor: &UserWire,
        req: AdminCreateUserRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.admin()?.create_user(actor, req).await
    }

    /// `POST /api/auth/admin/update-user`
    pub async fn admin_update_user(
        &self,
        actor: &UserWire,
        req: AdminUpdateUserRequest,
    ) -> Result<UserWire, AuthError> {
        self.admin()?.update_user(actor, req).await
    }

    /// `GET /api/auth/admin/list-users`
    pub async fn admin_list_users(
        &self,
        actor: &UserWire,
        query: AdminListUsersQuery,
    ) -> Result<AdminListUsersResponse, AuthError> {
        self.admin()?.list_users(actor, query).await
    }

    /// `POST /api/auth/admin/list-user-sessions`
    pub async fn admin_list_user_sessions(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminListUserSessionsResponse, AuthError> {
        self.admin()?
            .list_user_sessions(actor, target_user_id)
            .await
    }

    /// `POST /api/auth/admin/ban-user`
    pub async fn admin_ban_user(
        &self,
        actor: &UserWire,
        req: AdminBanUserRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.admin()?.ban_user(actor, req).await
    }

    /// `POST /api/auth/admin/unban-user`
    pub async fn admin_unban_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminUserResponse, AuthError> {
        self.admin()?.unban_user(actor, target_user_id).await
    }

    /// `POST /api/auth/admin/impersonate-user`
    pub async fn admin_impersonate_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
        meta: RequestMeta,
    ) -> Result<SessionAndUserResponse, AuthError> {
        self.admin()?
            .impersonate_user(actor, target_user_id, meta)
            .await
    }

    /// `POST /api/auth/admin/stop-impersonating`
    pub async fn admin_stop_impersonating(
        &self,
        current_session: &SessionWire,
        admin_token_or_signed: Option<&str>,
    ) -> Result<SessionAndUserResponse, AuthError> {
        self.admin()?
            .stop_impersonating(current_session, admin_token_or_signed)
            .await
    }

    /// `POST /api/auth/admin/revoke-user-session`
    pub async fn admin_revoke_user_session(
        &self,
        actor: &UserWire,
        session_token_or_signed: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.admin()?
            .revoke_user_session(actor, session_token_or_signed)
            .await
    }

    /// `POST /api/auth/admin/revoke-user-sessions`
    pub async fn admin_revoke_user_sessions(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.admin()?
            .revoke_user_sessions(actor, target_user_id)
            .await
    }

    /// `POST /api/auth/admin/remove-user`
    pub async fn admin_remove_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.admin()?.remove_user(actor, target_user_id).await
    }

    /// `POST /api/auth/admin/set-user-password`
    pub async fn admin_set_user_password(
        &self,
        actor: &UserWire,
        req: AdminSetUserPasswordRequest,
    ) -> Result<StatusResponse, AuthError> {
        self.admin()?.set_user_password(actor, req).await
    }

    /// `POST /api/auth/admin/has-permission`
    pub async fn admin_has_permission(
        &self,
        actor: Option<&UserWire>,
        req: AdminHasPermissionRequest,
    ) -> Result<AdminPermissionResponse, AuthError> {
        self.admin()?.has_permission(actor, req).await
    }

    /// `POST /api/auth/sign-in/social`
    pub async fn begin_social_sign_in(
        &self,
        provider: &crate::oauth::OAuthProviderConfig,
        payload: auth_proto::SignInSocialRequest,
    ) -> Result<auth_proto::SignInSocialResponse, AuthError> {
        let oauth_state = crypto::generate_random_token(32);
        let code_verifier = crypto::generate_random_token(32);

        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use sha2::{Digest, Sha256};
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        let state_data = crate::oauth::OAuthStateData {
            code_verifier,
            callback_url: payload.callback_url,
            new_user_callback_url: payload.new_user_callback_url,
            error_callback_url: payload.error_callback_url,
            link_user_id: None,
        };
        let value =
            serde_json::to_string(&state_data).map_err(|e| AuthError::Internal(e.to_string()))?;

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

        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use sha2::{Digest, Sha256};
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

        let state_data = crate::oauth::OAuthStateData {
            code_verifier,
            callback_url: payload.callback_url,
            new_user_callback_url: None,
            error_callback_url: payload.error_callback_url,
            link_user_id: Some(user_id.to_string()),
        };
        let value =
            serde_json::to_string(&state_data).map_err(|e| AuthError::Internal(e.to_string()))?;

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
            AuthError::bad_request(
                "INVALID_STATE",
                format!("Corrupted OAuth state payload: {e}"),
            )
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
            if let Some(existing_acc) = self
                .adapter
                .find_account(provider_name, &profile.account_id)
                .await?
            {
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
            return Ok(OAuthCallbackResult::Linked {
                user_id: target_user_id,
            });
        }

        // Case 2: Sign-in / sign-up flow
        let mut is_new_user = false;
        let user = if let Some(existing_acc) = self
            .adapter
            .find_account(provider_name, &profile.account_id)
            .await?
        {
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
