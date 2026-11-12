//! # uni-auth
//!
//! Modular, high-performance, cross-platform authentication engine and toolkit for Rust.
//!
//! ## Overview
//!
//! `uni-auth` provides a modular suite of authentication crates:
//! - [`uni_auth_proto`]: Shared wire DTOs and serialization models
//! - [`uni_auth_core`]: Headless authentication domain engine, hashing, sessions, RBAC, plugins, and hooks
//! - [`uni_auth_sqlx`]: SQLite and PostgreSQL database adapters with automated migrations
//! - [`uni_auth_axum`]: Axum HTTP router, session extractors, middleware, and OAuth routes
//! - [`uni_auth_client`]: Cross-platform client SDK with OS Keychain storage and loopback OAuth

#![doc(html_root_url = "https://docs.rs/uni-auth/0.1.0")]

#[cfg(feature = "proto")]
pub use uni_auth_proto as proto;

#[cfg(feature = "core")]
pub use uni_auth_core as core;

#[cfg(feature = "core")]
pub use uni_auth_core::*;

#[cfg(feature = "sqlx")]
pub use uni_auth_sqlx as sqlx;

#[cfg(feature = "axum")]
pub use uni_auth_axum as axum;

#[cfg(feature = "client")]
pub use uni_auth_client as client;
