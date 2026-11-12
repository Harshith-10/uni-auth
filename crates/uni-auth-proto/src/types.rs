//! Strongly-typed newtype wrappers for primitive identifiers.
//!
//! Prevents primitive obsession and argument transposition bugs (e.g. accidentally
//! swapping `user_id` and `account_id` or `token`).

use std::fmt;
use std::ops::Deref;
use serde::{Deserialize, Serialize};

/// Strongly-typed wrapper around a user identifier string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub String);

impl UserId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for UserId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Strongly-typed wrapper around a session token string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionToken(pub String);

impl SessionToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for SessionToken {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for SessionToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SessionToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionToken {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Strongly-typed wrapper around an email address string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Email(pub String);

impl Email {
    pub fn new(email: impl Into<String>) -> Self {
        Self(email.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Email {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Email {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Email {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}
