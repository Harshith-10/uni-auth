//! # auth-sqlx
//!
//! SQLx-based implementations of `AuthAdapter` for PostgreSQL and SQLite.
//!
//! - `SqliteAuthAdapter`: SQLite implementation of `AuthAdapter` (with in-memory mode for fast headless tests).
//! - `PostgresAuthAdapter`: PostgreSQL implementation of `AuthAdapter`.
//! - Embedded DDL migrations for automatic table creation.

pub mod naming;
pub mod postgres;
pub mod sqlite;

pub use naming::NamingConvention;
pub use postgres::PostgresAuthAdapter;
pub use sqlite::SqliteAuthAdapter;
