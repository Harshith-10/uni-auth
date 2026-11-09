//! # auth-core
//!
//! Core domain engine for BetterAuth-compatible Rust authentication:
//! - `AuthService`: Comprehensive domain logic coordinating sign-up, sign-in, sessions, tokens, and verification.
//! - `AuthAdapter`: Object-safe persistence trait for swapping in-memory, SQLite, and PostgreSQL backends.
//! - `InMemoryAuthAdapter`: High-performance in-memory adapter for zero-dependency unit tests.
//! - `crypto`: Argon2id non-blocking hashing, HMAC-SHA256 signing, HKDF derivation, and constant-time checks.
//! - `EmailSender`: Abstraction for email verification and password reset dispatch.

pub mod adapter;
pub mod crypto;
pub mod email;
pub mod error;
pub mod models;
pub mod service;

pub use adapter::{AuthAdapter, InMemoryAuthAdapter};
pub use email::{EmailSender, MockEmailSender, NoopEmailSender};
pub use error::{AdapterError, AuthError};
pub use models::*;
pub use service::{AuthConfig, AuthService};
