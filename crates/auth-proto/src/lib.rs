//! # auth-proto
//!
//! Shared wire DTOs and serialization models for uni-auth.
//!
//! This crate contains **no server dependencies** — only serialization types that are shared
//! between the server (`auth-core`, `auth-axum`) and native client (`auth-client`).
//!
//! All JSON field names use `camelCase` for protocol interoperability.

pub mod access;
pub mod error;
pub mod models;
pub mod requests;
pub mod responses;
pub mod types;
pub mod url_utils;

pub use access::{AccessControl, Connector, RolePermissions};
pub use error::*;
pub use models::*;
pub use requests::*;
pub use responses::*;
pub use types::*;
pub use url_utils::*;
