//! # auth-core
//!
//! Core domain engine for BetterAuth-compatible Rust authentication:
//! - `AuthService`: Comprehensive domain logic coordinating sign-up, sign-in, sessions, tokens, verification, and Admin operations.
//! - `AuthAdapter`: Object-safe persistence trait for swapping in-memory, SQLite, and PostgreSQL backends.
//! - `InMemoryAuthAdapter`: High-performance in-memory adapter for zero-dependency unit tests.
//! - `access`: Shared resource-action RBAC permission engine (`AccessControl`, `RolePermissions`, `AdminConfig`).
//! - `crypto`: Argon2id non-blocking hashing, legacy Better Auth `scrypt` verification, HMAC-SHA256 signing, HKDF derivation, and constant-time checks.
//! - `EmailSender`: Abstraction for email verification and password reset dispatch.
//! - `hooks`: Lifecycle event hooks (`AuthHooks`), sliding-window rate limiter, and background cleanup task.
//! - `plugin`: Modular `AuthPlugin` trait and `TotpValidator` for two-factor authentication.

pub mod access;
pub mod adapter;
pub mod crypto;
pub mod email;
pub mod error;
pub mod hooks;
pub mod models;
pub mod oauth;
pub mod plugin;
pub mod service;

pub use access::{AccessControl, AdminConfig, RolePermissions};
pub use adapter::{AuthAdapter, InMemoryAuthAdapter};
pub use email::{EmailSender, MockEmailSender, NoopEmailSender};
pub use error::{AdapterError, AuthError};
pub use hooks::{
    spawn_expired_cleanup_worker, AuthHooks, NoopAuthHooks, SlidingWindowRateLimiter,
};
pub use models::*;
pub use oauth::{
    OAuthHttpClient, OAuthProfileResult, OAuthProviderConfig, OAuthStateData, ReqwestOAuthClient,
};
pub use plugin::{AuthPlugin, TotpValidator};
pub use service::{AuthConfig, AuthService, OAuthCallbackResult};
