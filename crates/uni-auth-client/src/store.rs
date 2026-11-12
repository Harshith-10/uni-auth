//! Reactive authentication store with observable state transitions for desktop UI integration.

use uni_auth_proto::{SessionAndUserResponse, SessionWire, UserWire};
use std::sync::{Arc, Mutex, RwLock};

use crate::client::{AuthClient, ClientError};
use crate::plugin::SessionSignalEvent;

/// Reactive state of the current user session.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum AuthStatus {
    /// Initial startup state while verifying stored credentials.
    #[default]
    Loading,

    /// No active or valid session exists in secure storage.
    Unauthenticated,

    /// User is actively authenticated with a valid session.
    Authenticated {
        user: UserWire,
        session: SessionWire,
    },
}

type Listener = Box<dyn Fn(&AuthStatus) + Send + Sync + 'static>;

/// Observable store holding the current authentication state.
///
/// Designed to easily plug into GPUI reactive views (`cx.notify()`) or other desktop frameworks.
#[derive(Clone)]
pub struct AuthStore {
    client: Arc<AuthClient>,
    status: Arc<RwLock<AuthStatus>>,
    listeners: Arc<Mutex<Vec<Listener>>>,
}

impl AuthStore {
    /// Creates a new `AuthStore` wrapping the native client, automatically subscribing to reactive session signals.
    pub fn new(client: Arc<AuthClient>) -> Self {
        let store = Self {
            client: client.clone(),
            status: Arc::new(RwLock::new(AuthStatus::Loading)),
            listeners: Arc::new(Mutex::new(Vec::new())),
        };

        let weak_status = Arc::downgrade(&store.status);
        let weak_listeners = Arc::downgrade(&store.listeners);
        let client_clone = client.clone();

        client.subscribe_session_events(move |event| {
            let Some(status_lock) = weak_status.upgrade() else {
                return;
            };
            let Some(listeners_lock) = weak_listeners.upgrade() else {
                return;
            };

            let new_status_opt = match event {
                SessionSignalEvent::SessionUpdated { user, session } => {
                    Some(AuthStatus::Authenticated {
                        user: user.clone(),
                        session: session.clone(),
                    })
                }
                SessionSignalEvent::UserUpdated(new_user) => {
                    let mut current = status_lock.read().map(|s| s.clone()).unwrap_or_default();
                    if let AuthStatus::Authenticated { ref mut user, .. } = current {
                        *user = new_user.clone();
                        Some(current)
                    } else {
                        None
                    }
                }
                SessionSignalEvent::SignedOut => Some(AuthStatus::Unauthenticated),
                SessionSignalEvent::NeedsRefresh => {
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let client = client_clone.clone();
                        let weak_st = Arc::downgrade(&status_lock);
                        let weak_ls = Arc::downgrade(&listeners_lock);
                        handle.spawn(async move {
                            if let Ok(Some(ses)) = client.get_session().await {
                                if let Some(st) = weak_st.upgrade() {
                                    let new_st = AuthStatus::Authenticated {
                                        user: ses.user,
                                        session: ses.session,
                                    };
                                    let changed = if let Ok(mut g) = st.write() {
                                        if *g != new_st {
                                            *g = new_st.clone();
                                            true
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    };
                                    if changed {
                                        if let Some(ls) = weak_ls.upgrade() {
                                            if let Ok(listeners) = ls.lock() {
                                                for l in listeners.iter() {
                                                    l(&new_st);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    None
                }
            };

            if let Some(new_status) = new_status_opt {
                let changed = if let Ok(mut s) = status_lock.write() {
                    if *s != new_status {
                        *s = new_status.clone();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if changed {
                    if let Ok(listeners) = listeners_lock.lock() {
                        for listener in listeners.iter() {
                            listener(&new_status);
                        }
                    }
                }
            }
        });

        store
    }

    pub fn client(&self) -> &Arc<AuthClient> {
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
        let changed = if let Ok(mut status) = self.status.write() {
            if *status != new_status {
                *status = new_status.clone();
                true
            } else {
                false
            }
        } else {
            false
        };
        if changed {
            if let Ok(listeners) = self.listeners.lock() {
                for listener in listeners.iter() {
                    listener(&new_status);
                }
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
                    impersonated_by: None,
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

    /// Impersonates a target user and transitions `AuthStore` to the impersonated session.
    pub async fn impersonate_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<SessionAndUserResponse, ClientError> {
        use crate::plugins::AdminClientExt;
        let res = self.client.admin().impersonate_user(user_id).await?;
        self.set_status(AuthStatus::Authenticated {
            user: res.user.clone(),
            session: res.session.clone(),
        });
        Ok(res)
    }

    /// Stops impersonating and restores `AuthStore` to the original admin session.
    pub async fn stop_impersonating(&self) -> Result<SessionAndUserResponse, ClientError> {
        use crate::plugins::AdminClientExt;
        let res = self.client.admin().stop_impersonating().await?;
        self.set_status(AuthStatus::Authenticated {
            user: res.user.clone(),
            session: res.session.clone(),
        });
        Ok(res)
    }

    /// Signs out and sets the reactive status to `Unauthenticated`.
    pub async fn sign_out(&self) -> Result<(), ClientError> {
        let _ = self.client.sign_out().await;
        self.set_status(AuthStatus::Unauthenticated);
        Ok(())
    }
}
