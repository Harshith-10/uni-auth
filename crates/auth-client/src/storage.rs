//! Secure token storage abstractions with OS Keychain support and memory write-through caching.

use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Keyring error: {0}")]
    Keyring(String),

    #[error("Internal lock error: {0}")]
    Lock(String),
}

/// Thread-safe token storage interface for native client authentication.
pub trait TokenStorage: Send + Sync {
    /// Reads the stored session token.
    fn get_token(&self) -> Result<Option<String>, StorageError>;

    /// Persists a session token.
    fn set_token(&self, token: &str) -> Result<(), StorageError>;

    /// Deletes the stored session token.
    fn delete_token(&self) -> Result<(), StorageError>;
}

/// OS Keyring storage backend using `keyring` crate with an in-memory write-through cache.
///
/// UI render loops can read `get_token` instantly from the memory cache without blocking
/// on OS IPC or DBus calls. Writes update the cache immediately and persist to the OS keychain
/// on a background blocking thread when a Tokio runtime is active.
#[derive(Clone)]
pub struct KeyringTokenStorage {
    service_name: String,
    account_name: String,
    cache: Arc<RwLock<Option<String>>>,
}

impl KeyringTokenStorage {
    /// Creates a new `KeyringTokenStorage` for the specified service and account.
    ///
    /// Automatically attempts to pre-populate the cache from the OS keychain.
    pub fn new(service_name: impl Into<String>, account_name: impl Into<String>) -> Self {
        let service = service_name.into();
        let account = account_name.into();

        // Attempt initial load from OS keyring
        let initial_token = match keyring::Entry::new(&service, &account) {
            Ok(entry) => match entry.get_password() {
                Ok(token) => Some(token),
                Err(keyring::Error::NoEntry) => None,
                Err(e) => {
                    tracing::warn!("Could not read from OS keyring on startup: {e}");
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to create keyring entry: {e}");
                None
            }
        };

        Self {
            service_name: service,
            account_name: account,
            cache: Arc::new(RwLock::new(initial_token)),
        }
    }
}

impl TokenStorage for KeyringTokenStorage {
    fn get_token(&self) -> Result<Option<String>, StorageError> {
        let cache = self
            .cache
            .read()
            .map_err(|e| StorageError::Lock(e.to_string()))?;
        Ok(cache.clone())
    }

    fn set_token(&self, token: &str) -> Result<(), StorageError> {
        // 1. Update memory cache immediately
        {
            let mut cache = self
                .cache
                .write()
                .map_err(|e| StorageError::Lock(e.to_string()))?;
            *cache = Some(token.to_string());
        }

        // 2. Persist to OS keyring on background blocking pool if Tokio is running
        let service = self.service_name.clone();
        let account = self.account_name.clone();
        let token_owned = token.to_string();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                if let Ok(entry) = keyring::Entry::new(&service, &account) {
                    if let Err(e) = entry.set_password(&token_owned) {
                        tracing::warn!("Failed to persist token to OS keyring: {e}");
                    }
                }
            });
            Ok(())
        } else {
            let entry = keyring::Entry::new(&service, &account)
                .map_err(|e| StorageError::Keyring(e.to_string()))?;
            entry
                .set_password(&token_owned)
                .map_err(|e| StorageError::Keyring(e.to_string()))
        }
    }

    fn delete_token(&self) -> Result<(), StorageError> {
        // 1. Clear memory cache immediately
        {
            let mut cache = self
                .cache
                .write()
                .map_err(|e| StorageError::Lock(e.to_string()))?;
            *cache = None;
        }

        // 2. Delete from OS keyring on background blocking pool if Tokio is running
        let service = self.service_name.clone();
        let account = self.account_name.clone();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                if let Ok(entry) = keyring::Entry::new(&service, &account) {
                    if let Err(e) = entry.delete_credential() {
                        if !matches!(e, keyring::Error::NoEntry) {
                            tracing::warn!("Failed to delete token from OS keyring: {e}");
                        }
                    }
                }
            });
            Ok(())
        } else {
            let entry = keyring::Entry::new(&service, &account)
                .map_err(|e| StorageError::Keyring(e.to_string()))?;
            match entry.delete_credential() {
                Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(StorageError::Keyring(e.to_string())),
            }
        }
    }
}

/// In-memory token storage for headless CI environments and unit tests.
#[derive(Clone, Default)]
pub struct MockTokenStorage {
    token: Arc<RwLock<Option<String>>>,
}

impl MockTokenStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            token: Arc::new(RwLock::new(Some(token.into()))),
        }
    }
}

impl TokenStorage for MockTokenStorage {
    fn get_token(&self) -> Result<Option<String>, StorageError> {
        let t = self
            .token
            .read()
            .map_err(|e| StorageError::Lock(e.to_string()))?;
        Ok(t.clone())
    }

    fn set_token(&self, token: &str) -> Result<(), StorageError> {
        let mut t = self
            .token
            .write()
            .map_err(|e| StorageError::Lock(e.to_string()))?;
        *t = Some(token.to_string());
        Ok(())
    }

    fn delete_token(&self) -> Result<(), StorageError> {
        let mut t = self
            .token
            .write()
            .map_err(|e| StorageError::Lock(e.to_string()))?;
        *t = None;
        Ok(())
    }
}
