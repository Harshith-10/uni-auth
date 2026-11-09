//! Reactive authentication store with observable state transitions for desktop UI integration.

use std::sync::{Arc, Mutex, RwLock};
use auth_proto::{SessionWire, UserWire};

use crate::client::{BetterAuthNativeClient, ClientError};

/// Reactive state of the current user session.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthStatus {
    /// Initial startup state while verifying stored credentials.
    Loading,

    /// No active or valid session exists in secure storage.
    Unauthenticated,

    /// User is actively authenticated with a valid session.
    Authenticated {
        user: UserWire,
        session: SessionWire,
    },
}

impl Default for AuthStatus {
    fn default() -> Self {
        Self::Loading
    }
}

type Listener = Box<dyn Fn(&AuthStatus) + Send + Sync + 'static>;

/// Observable store holding the current authentication state.
///
/// Designed to easily plug into GPUI reactive views (`cx.notify()`) or other desktop frameworks.
#[derive(Clone)]
pub struct AuthStore {
    client: Arc<BetterAuthNativeClient>,
    status: Arc<RwLock<AuthStatus>>,
    listeners: Arc<Mutex<Vec<Listener>>>,
}

impl AuthStore {
    /// Creates a new `AuthStore` wrapping the native client.
    pub fn new(client: Arc<BetterAuthNativeClient>) -> Self {
        Self {
            client,
            status: Arc::new(RwLock::new(AuthStatus::Loading)),
            listeners: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn client(&self) -> &Arc<BetterAuthNativeClient> {
        &self.client
    }

    pub fn status(&self) -> AuthStatus {
        self.status.read().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.status(), AuthStatus::Authenticated { .. })
    }

    /// Subscribes a listener to receive notifications whenever `AuthStatus` changes.
    pub fn subscribe<F: Fn(&AuthStatus) + Send + Sync + 'static>(&self, listener: F) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(Box::new(listener));
        }
    }

    fn set_status(&self, new_status: AuthStatus) {
        if let Ok(mut status) = self.status.write() {
            *status = new_status.clone();
        }
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener(&new_status);
            }
        }
    }

    /// Attempts to restore the session from secure storage upon application launch.
    pub async fn restore_session(&self) -> Result<bool, ClientError> {
        if self.status() != AuthStatus::Loading {
            self.set_status(AuthStatus::Loading);
        }

        match self.client.get_session().await {
            Ok(Some(session_and_user)) => {
                self.set_status(AuthStatus::Authenticated {
                    user: session_and_user.user,
                    session: session_and_user.session,
                });
                Ok(true)
            }
            Ok(None) | Err(_) => {
                self.set_status(AuthStatus::Unauthenticated);
                Ok(false)
            }
        }
    }

    /// Signs in with email and password and updates the reactive status.
    pub async fn sign_in_email(
        &self,
        email: impl Into<String>,
        password: impl Into<String>,
        remember_me: Option<bool>,
    ) -> Result<(), ClientError> {
        let res = self
            .client
            .sign_in_email(email, password, remember_me)
            .await?;

        // Re-read session to get complete SessionWire metadata
        if let Some(session_and_user) = self.client.get_session().await? {
            self.set_status(AuthStatus::Authenticated {
                user: session_and_user.user,
                session: session_and_user.session,
            });
        } else {
            self.set_status(AuthStatus::Authenticated {
                user: res.user,
                session: SessionWire {
                    id: String::new(),
                    user_id: String::new(),
                    token: res.token,
                    expires_at: time::OffsetDateTime::now_utc(),
                    ip_address: None,
                    user_agent: None,
                    created_at: time::OffsetDateTime::now_utc(),
                    updated_at: time::OffsetDateTime::now_utc(),
                },
            });
        }

        Ok(())
    }

    /// Signs up with email and password and updates the reactive status.
    pub async fn sign_up_email(
        &self,
        name: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
        remember_me: Option<bool>,
    ) -> Result<(), ClientError> {
        let res = self
            .client
            .sign_up_email(name, email, password, remember_me)
            .await?;

        if res.token.is_some() {
            if let Some(session_and_user) = self.client.get_session().await? {
                self.set_status(AuthStatus::Authenticated {
                    user: session_and_user.user,
                    session: session_and_user.session,
                });
                return Ok(());
            }
        }

        self.set_status(AuthStatus::Unauthenticated);
        Ok(())
    }

    /// Signs out and sets the reactive status to `Unauthenticated`.
    pub async fn sign_out(&self) -> Result<(), ClientError> {
        let _ = self.client.sign_out().await;
        self.set_status(AuthStatus::Unauthenticated);
        Ok(())
    }
}
