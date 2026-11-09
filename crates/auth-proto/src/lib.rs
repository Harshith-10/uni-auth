//! # auth-proto
//!
//! Shared wire DTOs and camelCase serde models for BetterAuth-compatible Rust authentication.
//!
//! This crate contains **no server dependencies** — only serialization types that are shared
//! between the server (`auth-core`, `auth-axum`) and native client (`auth-client`).
//!
//! All JSON field names use `camelCase` to match the Better Auth TypeScript wire protocol.

pub mod error;
pub mod models;
pub mod requests;
pub mod responses;

pub use error::*;
pub use models::*;
pub use requests::*;
pub use responses::*;
