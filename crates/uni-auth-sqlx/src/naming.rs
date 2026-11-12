//! Configurable column naming conventions for Better Auth database compatibility.

/// Naming convention used for database columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamingConvention {
    /// Idiomatic Rust snake_case (`email_verified`, `created_at`, `user_id`, etc.)
    #[default]
    SnakeCase,
    /// TypeScript Better-Auth default camelCase (`emailVerified`, `createdAt`, `userId`, etc.)
    CamelCase,
}

impl NamingConvention {
    /// Returns the appropriate column identifier based on the active naming convention.
    #[inline]
    pub fn col(&self, snake: &'static str, camel: &'static str) -> &'static str {
        match self {
            Self::SnakeCase => snake,
            Self::CamelCase => camel,
        }
    }
}
