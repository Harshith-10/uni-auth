//! Hooked adapter executing registered `DatabaseHooks` around core data mutations.
//!
//! Directly mirrors Better Auth's `getWithHooks` (`packages/better-auth/src/db/with-hooks.ts`).

use std::sync::Arc;
use time::OffsetDateTime;

use crate::adapter::{AuthAdapter, BoxFuture};
use crate::error::{AdapterError, AuthError};
use crate::models::{
    AccountRecord, AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput,
    CreateSessionInput, CreateUserInput, CreateVerificationInput, SessionRecord, UpdateUserFields,
    UserRecord, VerificationRecord,
};
use crate::plugin::{DatabaseHooks, HookOutcome};

/// Decorator around `Arc<dyn AuthAdapter>` executing lifecycle hooks before and after mutations.
pub struct HookedAdapter {
    inner: Arc<dyn AuthAdapter>,
    hooks: Vec<Arc<dyn DatabaseHooks>>,
}

impl HookedAdapter {
    /// Creates a new `HookedAdapter` wrapping `inner` with `hooks`.
    pub fn new(inner: Arc<dyn AuthAdapter>, hooks: Vec<Arc<dyn DatabaseHooks>>) -> Self {
        Self { inner, hooks }
    }

    /// Accessor for the underlying raw adapter.
    pub fn inner(&self) -> &Arc<dyn AuthAdapter> {
        &self.inner
    }

    /// Accessor for the registered database hooks.
    pub fn hooks(&self) -> &[Arc<dyn DatabaseHooks>] {
        &self.hooks
    }
}

impl AuthAdapter for HookedAdapter {
    // ── Users ──

    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        Box::pin(async move {
            let mut current = input;
            for hook in &hooks {
                match hook.before_create_user(current, &*inner).await {
                    Ok(HookOutcome::Continue(val)) | Ok(HookOutcome::Modified(val)) => {
                        current = val;
                    }
                    Ok(HookOutcome::Cancel) => {
                        return Err(AdapterError::Auth(Box::new(AuthError::forbidden(
                            "HOOK_CANCELLED",
                            "User creation cancelled by database hook",
                        ))));
                    }
                    Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                }
            }

            let user = inner.create_user(current).await?;

            for hook in &hooks {
                if let Err(err) = hook.after_create_user(&user, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok(user)
        })
    }

    fn create_user_with_account(
        &self,
        user_input: CreateUserInput,
        account_input: CreateAccountInput,
    ) -> BoxFuture<'static, Result<(UserRecord, AccountRecord), AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        Box::pin(async move {
            let mut current = user_input;
            for hook in &hooks {
                match hook.before_create_user(current, &*inner).await {
                    Ok(HookOutcome::Continue(val)) | Ok(HookOutcome::Modified(val)) => {
                        current = val;
                    }
                    Ok(HookOutcome::Cancel) => {
                        return Err(AdapterError::Auth(Box::new(AuthError::forbidden(
                            "HOOK_CANCELLED",
                            "User creation cancelled by database hook",
                        ))));
                    }
                    Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                }
            }

            let (user, account) = inner
                .create_user_with_account(current, account_input)
                .await?;

            for hook in &hooks {
                if let Err(err) = hook.after_create_user(&user, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok((user, account))
        })
    }

    fn find_user_by_id(
        &self,
        id: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>> {
        self.inner.find_user_by_id(id)
    }

    fn find_user_by_email(
        &self,
        email: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>> {
        self.inner.find_user_by_email(email)
    }

    fn update_user(
        &self,
        id: &str,
        fields: UpdateUserFields,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        let user_id = id.to_string();
        Box::pin(async move {
            let mut cur_fields = fields;
            for hook in &hooks {
                match hook
                    .before_update_user(&user_id, cur_fields.clone(), &*inner)
                    .await
                {
                    Ok(HookOutcome::Continue(f)) | Ok(HookOutcome::Modified(f)) => {
                        cur_fields = f;
                    }
                    Ok(HookOutcome::Cancel) => {
                        return inner
                            .find_user_by_id(&user_id)
                            .await?
                            .ok_or(AdapterError::NotFound);
                    }
                    Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                }
            }

            let user = inner.update_user(&user_id, cur_fields).await?;

            for hook in &hooks {
                if let Err(err) = hook.after_update_user(&user, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok(user)
        })
    }

    fn update_user_email_verified(
        &self,
        id: &str,
        verified: bool,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let fut = self.update_user(
            id,
            UpdateUserFields {
                email_verified: Some(verified),
                ..Default::default()
            },
        );
        Box::pin(async move { fut.await.map(|_| ()) })
    }

    fn update_user_profile(
        &self,
        id: &str,
        name: Option<String>,
        image: Option<Option<String>>,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        self.update_user(
            id,
            UpdateUserFields {
                name,
                image: image.into(),
                ..Default::default()
            },
        )
    }

    fn update_user_admin(
        &self,
        id: &str,
        fields: AdminUpdateUserFields,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        self.update_user(id, fields)
    }

    fn list_users(
        &self,
        filter: AdminListUsersFilter,
    ) -> BoxFuture<'static, Result<(Vec<UserRecord>, usize), AdapterError>> {
        self.inner.list_users(filter)
    }

    fn delete_user(&self, id: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        let user_id = id.to_string();
        Box::pin(async move {
            let maybe_user = inner.find_user_by_id(&user_id).await?;
            if let Some(ref user) = maybe_user {
                for hook in &hooks {
                    match hook.before_delete_user(user, &*inner).await {
                        Ok(true) => {}
                        Ok(false) => {
                            return Err(AdapterError::Auth(Box::new(AuthError::forbidden(
                                "HOOK_CANCELLED",
                                "User deletion cancelled by database hook",
                            ))));
                        }
                        Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                    }
                }
            }

            inner.delete_user(&user_id).await?;

            for hook in &hooks {
                if let Err(err) = hook.after_delete_user(&user_id, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok(())
        })
    }

    // ── Accounts ──

    fn create_account(
        &self,
        input: CreateAccountInput,
    ) -> BoxFuture<'static, Result<AccountRecord, AdapterError>> {
        self.inner.create_account(input)
    }

    fn find_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<Option<AccountRecord>, AdapterError>> {
        self.inner.find_account(provider_id, account_id)
    }

    fn find_accounts_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<AccountRecord>, AdapterError>> {
        self.inner.find_accounts_by_user_id(user_id)
    }

    fn update_account_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        self.inner.update_account_password(user_id, password_hash)
    }

    fn update_account_tokens(
        &self,
        provider_id: &str,
        account_id: &str,
        access_token: Option<String>,
        refresh_token: Option<String>,
        id_token: Option<String>,
        access_token_expires_at: Option<OffsetDateTime>,
        scope: Option<String>,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        self.inner.update_account_tokens(
            provider_id,
            account_id,
            access_token,
            refresh_token,
            id_token,
            access_token_expires_at,
            scope,
        )
    }

    fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        self.inner.delete_account(provider_id, account_id)
    }

    // ── Sessions ──

    fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        Box::pin(async move {
            let mut current = input;
            for hook in &hooks {
                match hook.before_create_session(current, &*inner).await {
                    Ok(HookOutcome::Continue(val)) | Ok(HookOutcome::Modified(val)) => {
                        current = val;
                    }
                    Ok(HookOutcome::Cancel) => {
                        return Err(AdapterError::Auth(Box::new(AuthError::forbidden(
                            "HOOK_CANCELLED",
                            "Session creation cancelled by database hook",
                        ))));
                    }
                    Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                }
            }

            let session = inner.create_session(current).await?;

            for hook in &hooks {
                if let Err(err) = hook.after_create_session(&session, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok(session)
        })
    }

    fn create_impersonated_session(
        &self,
        input: CreateSessionInput,
        impersonated_by: String,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        Box::pin(async move {
            let mut current = input;
            for hook in &hooks {
                match hook.before_create_session(current, &*inner).await {
                    Ok(HookOutcome::Continue(val)) | Ok(HookOutcome::Modified(val)) => {
                        current = val;
                    }
                    Ok(HookOutcome::Cancel) => {
                        return Err(AdapterError::Auth(Box::new(AuthError::forbidden(
                            "HOOK_CANCELLED",
                            "Impersonated session creation cancelled by database hook",
                        ))));
                    }
                    Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                }
            }

            let session = inner
                .create_impersonated_session(current, impersonated_by)
                .await?;

            for hook in &hooks {
                if let Err(err) = hook.after_create_session(&session, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok(session)
        })
    }

    fn find_session_by_token(
        &self,
        token: &str,
    ) -> BoxFuture<'static, Result<Option<SessionRecord>, AdapterError>> {
        self.inner.find_session_by_token(token)
    }

    fn list_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<SessionRecord>, AdapterError>> {
        self.inner.list_sessions_by_user_id(user_id)
    }

    fn update_session_expiry(
        &self,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        self.inner.update_session_expiry(token, expires_at)
    }

    fn delete_session(&self, token: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        let tok = token.to_string();
        Box::pin(async move {
            for hook in &hooks {
                match hook.before_delete_session(&tok, &*inner).await {
                    Ok(true) => {}
                    Ok(false) => return Ok(()),
                    Err(err) => return Err(AdapterError::Auth(Box::new(err))),
                }
            }

            inner.delete_session(&tok).await?;

            for hook in &hooks {
                if let Err(err) = hook.after_delete_session(&tok, &*inner).await {
                    return Err(AdapterError::Auth(Box::new(err)));
                }
            }

            Ok(())
        })
    }

    fn delete_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        let uid = user_id.to_string();
        Box::pin(async move {
            if !hooks.is_empty() {
                if let Ok(sessions) = inner.list_sessions_by_user_id(&uid).await {
                    for s in &sessions {
                        for hook in &hooks {
                            let _ = hook.before_delete_session(&s.token, &*inner).await;
                        }
                    }
                    inner.delete_sessions_by_user_id(&uid).await?;
                    for s in &sessions {
                        for hook in &hooks {
                            let _ = hook.after_delete_session(&s.token, &*inner).await;
                        }
                    }
                    return Ok(());
                }
            }
            inner.delete_sessions_by_user_id(&uid).await
        })
    }

    fn delete_other_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let inner = self.inner.clone();
        let hooks = self.hooks.clone();
        let uid = user_id.to_string();
        let cur_tok = current_token.to_string();
        Box::pin(async move {
            if !hooks.is_empty() {
                if let Ok(sessions) = inner.list_sessions_by_user_id(&uid).await {
                    let targets: Vec<_> = sessions
                        .into_iter()
                        .filter(|s| s.token != cur_tok)
                        .collect();
                    for s in &targets {
                        for hook in &hooks {
                            let _ = hook.before_delete_session(&s.token, &*inner).await;
                        }
                    }
                    inner.delete_other_sessions(&uid, &cur_tok).await?;
                    for s in &targets {
                        for hook in &hooks {
                            let _ = hook.after_delete_session(&s.token, &*inner).await;
                        }
                    }
                    return Ok(());
                }
            }
            inner.delete_other_sessions(&uid, &cur_tok).await
        })
    }

    fn delete_expired_sessions(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        self.inner.delete_expired_sessions()
    }

    // ── Verifications ──

    fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> BoxFuture<'static, Result<VerificationRecord, AdapterError>> {
        self.inner.create_verification(input)
    }

    fn find_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>> {
        self.inner.find_verification(identifier)
    }

    fn consume_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>> {
        self.inner.consume_verification(identifier)
    }

    fn delete_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        self.inner.delete_verification(identifier)
    }

    fn delete_expired_verifications(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        self.inner.delete_expired_verifications()
    }
}
