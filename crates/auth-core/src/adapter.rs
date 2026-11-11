//! Persistence abstraction trait and in-memory test implementation.
//!
//! The `AuthAdapter` trait is object-safe (`Arc<dyn AuthAdapter>`) to allow dynamic swapping
//! between in-memory, SQLite, and PostgreSQL storage backends without template bloat in Axum routes.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::AdapterError;
use crate::models::{
    AccountRecord, AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput,
    CreateSessionInput, CreateUserInput, CreateVerificationInput, SessionRecord, UpdateUserFields,
    UserRecord, VerificationRecord,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Applies Better Auth `admin/list-users` search, filter, sort, and pagination rules to a user list.
pub fn filter_and_paginate_users(
    users: impl IntoIterator<Item = UserRecord>,
    filter: &AdminListUsersFilter,
) -> (Vec<UserRecord>, usize) {
    let mut matched: Vec<UserRecord> = users
        .into_iter()
        .filter(|u| {
            if let Some(ref sv) = filter.search_value {
                if !sv.is_empty() {
                    let needle = sv.to_lowercase();
                    let field_val = match filter.search_field.as_deref().unwrap_or("email") {
                        "name" => u.name.to_lowercase(),
                        "role" => u.role.as_deref().unwrap_or("user").to_lowercase(),
                        _ => u.email.to_lowercase(),
                    };
                    let op = filter.search_operator.as_deref().unwrap_or("contains");
                    let ok = match op {
                        "starts_with" => field_val.starts_with(&needle),
                        "ends_with" => field_val.ends_with(&needle),
                        _ => field_val.contains(&needle),
                    };
                    if !ok {
                        return false;
                    }
                }
            }

            if let Some(ref fv) = filter.filter_value {
                let needle = fv.to_lowercase();
                let field_val = match filter.filter_field.as_deref().unwrap_or("email") {
                    "name" => u.name.to_lowercase(),
                    "role" => u.role.as_deref().unwrap_or("user").to_lowercase(),
                    "banned" => u.banned.to_string(),
                    "emailVerified" | "email_verified" => u.email_verified.to_string(),
                    "id" => u.id.to_lowercase(),
                    _ => u.email.to_lowercase(),
                };
                let op = filter.filter_operator.as_deref().unwrap_or("eq");
                let ok = match op {
                    "ne" => field_val != needle,
                    "contains" => field_val.contains(&needle),
                    "starts_with" => field_val.starts_with(&needle),
                    "ends_with" => field_val.ends_with(&needle),
                    _ => field_val == needle,
                };
                if !ok {
                    return false;
                }
            }

            true
        })
        .collect();

    let desc = filter
        .sort_direction
        .as_deref()
        .map(|d| d.eq_ignore_ascii_case("desc"))
        .unwrap_or(false);

    match filter.sort_by.as_deref().unwrap_or("createdAt") {
        "name" => matched.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        "email" => matched.sort_by(|a, b| a.email.cmp(&b.email)),
        "role" => matched.sort_by(|a, b| {
            a.role
                .as_deref()
                .unwrap_or("user")
                .cmp(b.role.as_deref().unwrap_or("user"))
        }),
        _ => matched.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        }),
    }

    if desc {
        matched.reverse();
    }

    let total = matched.len();
    let offset = filter.offset.unwrap_or(0);
    let iter = matched.into_iter().skip(offset);
    let page: Vec<UserRecord> = match filter.limit {
        Some(limit) if limit > 0 => iter.take(limit).collect(),
        _ => iter.collect(),
    };

    (page, total)
}

/// Object-safe persistence adapter interface for Better Auth data models.
pub trait AuthAdapter: Send + Sync {
    // ── Users ──
    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>>;
    fn find_user_by_id(
        &self,
        id: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>>;
    fn find_user_by_email(
        &self,
        email: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>>;
    fn update_user(
        &self,
        id: &str,
        fields: UpdateUserFields,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>>;
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
                image,
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
    ) -> BoxFuture<'static, Result<(Vec<UserRecord>, usize), AdapterError>>;
    fn delete_user(&self, id: &str) -> BoxFuture<'static, Result<(), AdapterError>>;

    // ── Accounts ──
    fn create_account(
        &self,
        input: CreateAccountInput,
    ) -> BoxFuture<'static, Result<AccountRecord, AdapterError>>;
    fn find_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<Option<AccountRecord>, AdapterError>>;
    fn find_accounts_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<AccountRecord>, AdapterError>>;
    fn update_account_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
    fn update_account_tokens(
        &self,
        provider_id: &str,
        account_id: &str,
        access_token: Option<String>,
        refresh_token: Option<String>,
        id_token: Option<String>,
        access_token_expires_at: Option<OffsetDateTime>,
        scope: Option<String>,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
    fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;

    // ── Sessions ──
    fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>>;
    fn create_impersonated_session(
        &self,
        input: CreateSessionInput,
        impersonated_by: String,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>>;
    fn find_session_by_token(
        &self,
        token: &str,
    ) -> BoxFuture<'static, Result<Option<SessionRecord>, AdapterError>>;
    fn list_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<SessionRecord>, AdapterError>>;
    fn update_session_expiry(
        &self,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
    fn delete_session(&self, token: &str) -> BoxFuture<'static, Result<(), AdapterError>>;
    fn delete_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
    fn delete_other_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
    fn delete_expired_sessions(&self) -> BoxFuture<'static, Result<usize, AdapterError>>;

    // ── Verifications ──
    fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> BoxFuture<'static, Result<VerificationRecord, AdapterError>>;
    fn find_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>>;
    fn consume_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>>;
    fn delete_verification(&self, identifier: &str)
    -> BoxFuture<'static, Result<(), AdapterError>>;
    fn delete_expired_verifications(&self) -> BoxFuture<'static, Result<usize, AdapterError>>;
}

// ──────────────────────────────────────────────
// In-Memory Implementation for Fast Tests
// ──────────────────────────────────────────────

#[derive(Default)]
struct MemoryStore {
    users: HashMap<String, UserRecord>,
    email_to_id: HashMap<String, String>,
    accounts: HashMap<String, AccountRecord>, // key: "{provider_id}:{account_id}"
    sessions: HashMap<String, SessionRecord>, // key: token
    verifications: HashMap<String, VerificationRecord>, // key: identifier
}

/// Thread-safe in-memory `AuthAdapter` for unit testing.
#[derive(Clone, Default)]
pub struct InMemoryAuthAdapter {
    store: Arc<RwLock<MemoryStore>>,
}

impl InMemoryAuthAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuthAdapter for InMemoryAuthAdapter {
    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let normalized_email = input.email.to_lowercase();
            if s.email_to_id.contains_key(&normalized_email) {
                return Err(AdapterError::UniqueViolation(format!(
                    "User with email '{normalized_email}' already exists"
                )));
            }

            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();
            let user = UserRecord {
                id: id.clone(),
                name: input.name,
                email: normalized_email.clone(),
                email_verified: input.email_verified,
                image: input.image,
                created_at: now,
                updated_at: now,
                role: Some(input.role.unwrap_or_else(|| "user".to_string())),
                banned: false,
                ban_reason: None,
                ban_expires: None,
            };

            s.email_to_id.insert(normalized_email, id.clone());
            s.users.insert(id, user.clone());
            Ok(user)
        })
    }

    fn find_user_by_id(
        &self,
        id: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let id = id.to_string();
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            Ok(s.users.get(&id).cloned())
        })
    }

    fn find_user_by_email(
        &self,
        email: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let email = email.to_lowercase();
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(id) = s.email_to_id.get(&email) {
                Ok(s.users.get(id).cloned())
            } else {
                Ok(None)
            }
        })
    }

    fn update_user(
        &self,
        id: &str,
        fields: UpdateUserFields,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let store = Arc::clone(&self.store);
        let id = id.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(ref new_email) = fields.email {
                let normalized = new_email.to_lowercase();
                if let Some(existing_id) = s.email_to_id.get(&normalized) {
                    if existing_id != &id {
                        return Err(AdapterError::UniqueViolation(format!(
                            "User with email '{normalized}' already exists"
                        )));
                    }
                }
            }

            let old_email = s
                .users
                .get(&id)
                .map(|u| u.email.clone())
                .ok_or(AdapterError::NotFound)?;

            if let Some(ref new_email) = fields.email {
                let normalized = new_email.to_lowercase();
                if normalized != old_email {
                    s.email_to_id.remove(&old_email);
                    s.email_to_id.insert(normalized, id.clone());
                }
            }

            let user = s.users.get_mut(&id).ok_or(AdapterError::NotFound)?;
            if let Some(name) = fields.name {
                user.name = name;
            }
            if let Some(email) = fields.email {
                user.email = email.to_lowercase();
            }
            if let Some(verified) = fields.email_verified {
                user.email_verified = verified;
            }
            if let Some(img_opt) = fields.image {
                user.image = match img_opt {
                    Some(img) if !img.is_empty() => Some(img),
                    _ => None,
                };
            }
            if let Some(role) = fields.role {
                user.role = Some(role);
            }
            if let Some(banned) = fields.banned {
                user.banned = banned;
            }
            if let Some(reason_opt) = fields.ban_reason {
                user.ban_reason = reason_opt;
            }
            if let Some(exp_opt) = fields.ban_expires {
                user.ban_expires = exp_opt;
            }
            user.updated_at = OffsetDateTime::now_utc();
            Ok(user.clone())
        })
    }

    fn list_users(
        &self,
        filter: AdminListUsersFilter,
    ) -> BoxFuture<'static, Result<(Vec<UserRecord>, usize), AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            Ok(filter_and_paginate_users(
                s.users.values().cloned(),
                &filter,
            ))
        })
    }

    fn delete_user(&self, id: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let id = id.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(user) = s.users.remove(&id) {
                s.email_to_id.remove(&user.email);
                // Cascade delete accounts and sessions
                s.accounts.retain(|_, a| a.user_id != id);
                s.sessions.retain(|_, ses| ses.user_id != id);
            }
            Ok(())
        })
    }

    fn create_account(
        &self,
        input: CreateAccountInput,
    ) -> BoxFuture<'static, Result<AccountRecord, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let key = format!("{}:{}", input.provider_id, input.account_id);
            if s.accounts.contains_key(&key) {
                return Err(AdapterError::UniqueViolation(format!(
                    "Account for provider '{}' with account ID '{}' already exists",
                    input.provider_id, input.account_id
                )));
            }

            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();
            let account = AccountRecord {
                id,
                user_id: input.user_id,
                account_id: input.account_id,
                provider_id: input.provider_id,
                access_token: input.access_token,
                refresh_token: input.refresh_token,
                id_token: input.id_token,
                access_token_expires_at: input.access_token_expires_at,
                refresh_token_expires_at: input.refresh_token_expires_at,
                scope: input.scope,
                password: input.password,
                created_at: now,
                updated_at: now,
            };

            s.accounts.insert(key, account.clone());
            Ok(account)
        })
    }

    fn find_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<Option<AccountRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let key = format!("{provider_id}:{account_id}");
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            Ok(s.accounts.get(&key).cloned())
        })
    }

    fn find_accounts_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<AccountRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let user_id = user_id.to_string();
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let accounts: Vec<AccountRecord> = s
                .accounts
                .values()
                .filter(|a| a.user_id == user_id)
                .cloned()
                .collect();
            Ok(accounts)
        })
    }

    fn update_account_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let user_id = user_id.to_string();
        let hash = password_hash.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let key = format!("credential:{user_id}");
            if let Some(account) = s.accounts.get_mut(&key) {
                account.password = Some(hash);
                account.updated_at = OffsetDateTime::now_utc();
                Ok(())
            } else {
                // Also search by provider_id = "credential" and user_id
                if let Some(account) = s
                    .accounts
                    .values_mut()
                    .find(|a| a.provider_id == "credential" && a.user_id == user_id)
                {
                    account.password = Some(hash);
                    account.updated_at = OffsetDateTime::now_utc();
                    Ok(())
                } else {
                    Err(AdapterError::NotFound)
                }
            }
        })
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
        let store = Arc::clone(&self.store);
        let key = format!("{provider_id}:{account_id}");
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(account) = s.accounts.get_mut(&key) {
                account.access_token = access_token;
                if refresh_token.is_some() {
                    account.refresh_token = refresh_token;
                }
                if id_token.is_some() {
                    account.id_token = id_token;
                }
                account.access_token_expires_at = access_token_expires_at;
                if scope.is_some() {
                    account.scope = scope;
                }
                account.updated_at = OffsetDateTime::now_utc();
                Ok(())
            } else {
                Err(AdapterError::NotFound)
            }
        })
    }

    fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let key = format!("{provider_id}:{account_id}");
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.accounts.remove(&key);
            Ok(())
        })
    }

    fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();
            let session = SessionRecord {
                id,
                user_id: input.user_id,
                token: input.token.clone(),
                expires_at: input.expires_at,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                created_at: now,
                updated_at: now,
                impersonated_by: None,
            };
            s.sessions.insert(input.token, session.clone());
            Ok(session)
        })
    }

    fn create_impersonated_session(
        &self,
        input: CreateSessionInput,
        impersonated_by: String,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();
            let session = SessionRecord {
                id,
                user_id: input.user_id,
                token: input.token.clone(),
                expires_at: input.expires_at,
                ip_address: input.ip_address,
                user_agent: input.user_agent,
                created_at: now,
                updated_at: now,
                impersonated_by: Some(impersonated_by),
            };
            s.sessions.insert(input.token, session.clone());
            Ok(session)
        })
    }

    fn find_session_by_token(
        &self,
        token: &str,
    ) -> BoxFuture<'static, Result<Option<SessionRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let token = token.to_string();
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            Ok(s.sessions.get(&token).cloned())
        })
    }

    fn list_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<SessionRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let user_id = user_id.to_string();
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let sessions: Vec<SessionRecord> = s
                .sessions
                .values()
                .filter(|ses| ses.user_id == user_id && ses.expires_at > now)
                .cloned()
                .collect();
            Ok(sessions)
        })
    }

    fn update_session_expiry(
        &self,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let token = token.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(session) = s.sessions.get_mut(&token) {
                session.expires_at = expires_at;
                session.updated_at = OffsetDateTime::now_utc();
                Ok(())
            } else {
                Err(AdapterError::NotFound)
            }
        })
    }

    fn delete_session(&self, token: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let token = token.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.sessions.remove(&token);
            Ok(())
        })
    }

    fn delete_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let user_id = user_id.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.sessions.retain(|_, ses| ses.user_id != user_id);
            Ok(())
        })
    }

    fn delete_other_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let user_id = user_id.to_string();
        let current_token = current_token.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.sessions
                .retain(|token, ses| ses.user_id != user_id || token == &current_token);
            Ok(())
        })
    }

    fn delete_expired_sessions(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let before = s.sessions.len();
            s.sessions.retain(|_, ses| ses.expires_at > now);
            Ok(before - s.sessions.len())
        })
    }

    fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> BoxFuture<'static, Result<VerificationRecord, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();
            let record = VerificationRecord {
                id,
                identifier: input.identifier.clone(),
                value: input.value,
                expires_at: input.expires_at,
                created_at: now,
                updated_at: now,
            };
            s.verifications.insert(input.identifier, record.clone());
            Ok(record)
        })
    }

    fn find_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let identifier = identifier.to_string();
        Box::pin(async move {
            let s = store
                .read()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            Ok(s.verifications.get(&identifier).cloned())
        })
    }

    fn consume_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>> {
        let store = Arc::clone(&self.store);
        let identifier = identifier.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let record = s.verifications.remove(&identifier);
            if let Some(r) = record {
                if r.is_expired() {
                    Ok(None)
                } else {
                    Ok(Some(r))
                }
            } else {
                Ok(None)
            }
        })
    }

    fn delete_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let identifier = identifier.to_string();
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.verifications.remove(&identifier);
            Ok(())
        })
    }

    fn delete_expired_verifications(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store
                .write()
                .map_err(|e| AdapterError::Internal(e.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let before = s.verifications.len();
            s.verifications.retain(|_, v| v.expires_at > now);
            Ok(before - s.verifications.len())
        })
    }
}
