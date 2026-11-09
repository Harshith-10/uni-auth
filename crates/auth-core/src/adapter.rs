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
    AccountRecord, CreateAccountInput, CreateSessionInput, CreateUserInput,
    CreateVerificationInput, SessionRecord, UserRecord, VerificationRecord,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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
    fn update_user_email_verified(
        &self,
        id: &str,
        verified: bool,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
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
    fn delete_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>>;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(id) = s.email_to_id.get(&email) {
                Ok(s.users.get(id).cloned())
            } else {
                Ok(None)
            }
        })
    }

    fn update_user_email_verified(
        &self,
        id: &str,
        verified: bool,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let id = id.to_string();
        Box::pin(async move {
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
            if let Some(user) = s.users.get_mut(&id) {
                user.email_verified = verified;
                user.updated_at = OffsetDateTime::now_utc();
                Ok(())
            } else {
                Err(AdapterError::NotFound)
            }
        })
    }

    fn delete_user(&self, id: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let id = id.to_string();
        Box::pin(async move {
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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

    fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let store = Arc::clone(&self.store);
        let key = format!("{provider_id}:{account_id}");
        Box::pin(async move {
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.sessions
                .retain(|token, ses| ses.user_id != user_id || token == &current_token);
            Ok(())
        })
    }

    fn delete_expired_sessions(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let s = store.read().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
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
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
            s.verifications.remove(&identifier);
            Ok(())
        })
    }

    fn delete_expired_verifications(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let mut s = store.write().map_err(|e| AdapterError::Internal(e.to_string()))?;
            let now = OffsetDateTime::now_utc();
            let before = s.verifications.len();
            s.verifications.retain(|_, v| v.expires_at > now);
            Ok(before - s.verifications.len())
        })
    }
}
