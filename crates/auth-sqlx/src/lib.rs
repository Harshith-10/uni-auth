//! # auth-sqlx
//!
//! SQLx-based implementations of `AuthAdapter` for PostgreSQL and SQLite.
//!
//! - `SqliteAuthAdapter`: Full Better Auth implementation using SQLite (with in-memory mode for fast headless tests).
//! - `PostgresAuthAdapter`: Production-grade Better Auth implementation using PostgreSQL.
//! - Embedded DDL migrations for automatic table creation.

pub mod naming;
pub mod postgres;
pub mod sqlite;

pub use naming::NamingConvention;
pub use postgres::PostgresAuthAdapter;
pub use sqlite::SqliteAuthAdapter;
