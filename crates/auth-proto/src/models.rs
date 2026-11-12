//! Core wire models: User, Session, Account entities in camelCase JSON.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// User entity as seen on the wire (JSON responses).
///
/// Includes optional `admin` plugin fields (`role`, `banned`, `banReason`, `banExpires`).
/// The `password` field from the `account` table is **never** included here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UserWire {
    /// Unique identifier (UUIDv7 or nanoid)
    pub id: String,

    /// Display name
    pub name: String,

    /// Email address (normalized to lowercase)
    pub email: String,

    /// Whether the email has been verified
    pub email_verified: bool,

    /// Profile image URL (nullable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// When the user was created (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// When the user was last updated (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,

    /// User role or comma-separated roles (Admin plugin, e.g. `"user"`, `"admin"`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// Whether the user is banned (Admin plugin)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banned: Option<bool>,

    /// Reason for the ban if banned (Admin plugin)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban_reason: Option<String>,

    /// Expiration timestamp of the ban if temporary (Admin plugin)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub ban_expires: Option<OffsetDateTime>,
}

/// Session entity as seen on the wire (JSON responses).
///
/// Includes optional `impersonatedBy` from the `admin` plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionWire {
    /// Unique session identifier
    pub id: String,

    /// The user this session belongs to
    pub user_id: String,

    /// Session token (opaque, base64url-encoded)
    pub token: String,

    /// When the session expires (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,

    /// IP address of the client that created this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// User-Agent header of the client that created this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,

    /// When the session was created (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// When the session was last updated (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,

    /// ID of the admin user impersonating this session (Admin plugin)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<String>,
}

/// Account entity as seen on the wire (JSON responses).
///
/// This is the public view — the `password` field is **always** excluded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountWire {
    /// Unique account identifier
    pub id: String,

    /// The user this account belongs to
    pub user_id: String,

    /// Provider-specific account identifier
    pub account_id: String,

    /// Provider identifier (e.g., "credential", "google", "github")
    pub provider_id: String,

    /// OAuth access token (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// OAuth refresh token (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// OAuth ID token (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,

    /// When the access token expires (ISO-8601)
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option",
        default
    )]
    pub access_token_expires_at: Option<OffsetDateTime>,

    /// When the refresh token expires (ISO-8601)
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option",
        default
    )]
    pub refresh_token_expires_at: Option<OffsetDateTime>,

    /// OAuth scopes granted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// When the account was created (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,

    /// When the account was last updated (ISO-8601)
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}
