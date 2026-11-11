//! # auth-client
//!
//! Native Rust authentication client and state store for GPUI-Kit desktop applications.
//!
//! - `BetterAuthNativeClient`: `reqwest`-based client attaching `Authorization: Bearer <token>` and capturing `set-auth-token`.
//! - `TokenStorage`: Secure credential storage trait with `KeyringTokenStorage` (OS keychain) and `MockTokenStorage`.
//! - `AuthStore` & `AuthStatus`: Reactive desktop observable store suitable for GPUI view subscription.
//! - Native loopback OAuth handler for system browser logins.

pub mod client;
pub mod loopback;
pub mod plugin;
pub mod plugins;
pub mod storage;
pub mod store;
pub mod transport;

pub use client::{BetterAuthNativeClient, ClientError};
pub use loopback::{start_loopback_listener, start_loopback_listener_with_timeout};
pub use plugin::{AuthClientPlugin, ClientSignalListener, SESSION_SIGNAL};
pub use plugins::{
    AdminClientExt, AdminClientHandle, AdminClientPlugin, OneTimeTokenClientExt,
    OneTimeTokenClientHandle, OneTimeTokenClientPlugin,
};
pub use storage::{KeyringTokenStorage, MockTokenStorage, StorageError, TokenStorage};
pub use store::{AuthStatus, AuthStore};
pub use transport::{ClientRequestContext, ClientResponseContext};
