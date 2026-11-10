//! Request payloads for all Better Auth v1 API routes and plugins.
//!
//! Each struct matches the Zod body/query schema from the upstream TypeScript source.
//! Note: Better Auth uses `callbackURL`, `newUserCallbackURL`, and `errorCallbackURL`
//! with uppercase `URL`, so explicit `#[serde(rename = ...)]` attributes are used.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────
// Email / Password Authentication
// ──────────────────────────────────────────────

/// `POST /api/auth/sign-up/email`
///
/// Reference: `.reference/better-auth/.../sign-up.ts` lines 21-30
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignUpEmailRequest {
    /// Display name of the user
    pub name: String,

    /// Email address
    pub email: String,

    /// Password (must be >= 8 characters)
    pub password: String,

    /// Optional profile image URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Callback URL for email verification redirect
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,

    /// If false, the session will not be remembered. Default: true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
}

/// `POST /api/auth/sign-in/email`
///
/// Reference: `.reference/better-auth/.../sign-in.ts` lines 412-448
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInEmailRequest {
    /// Email address
    pub email: String,

    /// Password
    pub password: String,

    /// Callback URL for possible redirect
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,

    /// If false, the session will not be remembered. Default: true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remember_me: Option<bool>,
}

// ──────────────────────────────────────────────
// Social OAuth
// ──────────────────────────────────────────────

/// `POST /api/auth/sign-in/social`
///
/// Reference: `.reference/better-auth/.../sign-in.ts` lines 31-195
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignInSocialRequest {
    /// OAuth provider identifier (e.g., "google", "github")
    pub provider: String,

    /// Callback URL to redirect to after sign-in
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,

    /// Callback URL for newly registered users
    #[serde(
        rename = "newUserCallbackURL",
        alias = "newUserCallbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub new_user_callback_url: Option<String>,

    /// Callback URL on error
    #[serde(
        rename = "errorCallbackURL",
        alias = "errorCallbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub error_callback_url: Option<String>,

    /// Disable automatic redirection to the provider
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_redirect: Option<bool>,

    /// Explicitly request sign-up (when disableImplicitSignUp is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,

    /// Login hint for the authorization URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_hint: Option<String>,
}

/// `POST /api/auth/link-social`
///
/// Reference: `.reference/better-auth/.../account.ts` lines 128-235
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSocialRequest {
    /// OAuth provider identifier (e.g., "google", "github")
    pub provider: String,

    /// Callback URL to redirect to after linking
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,

    /// Callback URL on error
    #[serde(
        rename = "errorCallbackURL",
        alias = "errorCallbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub error_callback_url: Option<String>,

    /// Disable automatic redirection to the provider
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_redirect: Option<bool>,

    /// Additional OAuth scopes to request when linking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

// ──────────────────────────────────────────────
// Password Management
// ──────────────────────────────────────────────

/// `POST /api/auth/request-password-reset`
///
/// Reference: `.reference/better-auth/.../password.ts` lines 40-65
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPasswordResetRequest {
    /// The email address of the user to send a password reset to
    pub email: String,

    /// URL to redirect the user for password reset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

/// `POST /api/auth/reset-password`
///
/// Reference: `.reference/better-auth/.../password.ts` lines 234-254
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    /// The new password to set
    pub new_password: String,

    /// The password reset token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// `POST /api/auth/change-password`
///
/// Used when the user is authenticated and wants to change their password.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    /// The current password for verification
    pub current_password: String,

    /// The new password to set
    pub new_password: String,

    /// Whether to revoke other sessions after password change
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_other_sessions: Option<bool>,
}

// ──────────────────────────────────────────────
// Email Verification
// ──────────────────────────────────────────────

/// `POST /api/auth/send-verification-email`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendVerificationEmailRequest {
    /// The email address to send verification to
    pub email: String,

    /// Callback URL for the verification link
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,
}

// ──────────────────────────────────────────────
// Session Management
// ──────────────────────────────────────────────

/// `POST /api/auth/revoke-session`
///
/// Reference: `.reference/better-auth/.../session.ts` lines 677-685
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionRequest {
    /// The session token to revoke
    pub token: String,
}

/// `POST /api/auth/sign-out`
///
/// Reference: `.reference/better-auth/.../sign-out.ts` lines 5-26
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOutRequest {
    /// URL to redirect to after provider logout
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,

    /// Return the provider logout URL without redirecting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_redirect: Option<bool>,
}

// ──────────────────────────────────────────────
// One-Time Token Plugin
// ──────────────────────────────────────────────

/// `POST /api/auth/one-time-token/verify`
///
/// Reference: `.reference/better-auth/.../plugins/one-time-token/index.ts` lines 71-75
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OneTimeTokenVerifyRequest {
    /// The one-time token to verify
    pub token: String,
}

// ──────────────────────────────────────────────
// Account & User Management
// ──────────────────────────────────────────────

/// `POST /api/auth/unlink-account`
///
/// Reference: `.reference/better-auth/.../account.ts` lines 468-524
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlinkAccountRequest {
    /// The provider ID to unlink (e.g., "google", "github")
    #[serde(default)]
    pub provider_id: String,

    /// Optional Better Auth account ID or provider account ID to unlink
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

/// `POST /api/auth/update-user`
///
/// Reference: `.reference/better-auth/.../update-user.ts` lines 31-95
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    /// Updated display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated profile image URL (`Some(None)` or `None` clears or leaves unchanged)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// `POST /api/auth/delete-user`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeleteUserRequest {
    /// Optional current password verification before deleting the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Optional callback URL after deletion
    #[serde(
        rename = "callbackURL",
        alias = "callbackUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub callback_url: Option<String>,
}

// ──────────────────────────────────────────────
// Admin Plugin Requests
// ──────────────────────────────────────────────

/// Role specification accepting either a single role string (`"admin"`) or an array (`["admin", "user"]`).
///
/// Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/routes.ts` lines 57-76
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RoleValue {
    Single(String),
    Multiple(Vec<String>),
}

impl RoleValue {
    /// Normalizes into a comma-separated role string (`"admin,user"`).
    pub fn to_csv(&self) -> String {
        match self {
            Self::Single(s) => s.clone(),
            Self::Multiple(list) => list.join(","),
        }
    }

    /// Returns individual role strings.
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => s
                .split(',')
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect(),
            Self::Multiple(list) => list
                .iter()
                .flat_map(|s| s.split(','))
                .map(|r| r.trim().to_string())
                .filter(|r| !r.is_empty())
                .collect(),
        }
    }
}

impl From<String> for RoleValue {
    fn from(s: String) -> Self {
        RoleValue::Single(s)
    }
}

impl From<&str> for RoleValue {
    fn from(s: &str) -> Self {
        RoleValue::Single(s.to_string())
    }
}

impl From<Vec<String>> for RoleValue {
    fn from(v: Vec<String>) -> Self {
        RoleValue::Multiple(v)
    }
}

/// `POST /api/auth/admin/set-role`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSetRoleRequest {
    pub user_id: String,
    pub role: RoleValue,
}

/// `GET /api/auth/admin/get-user?id=...`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminGetUserQuery {
    pub id: String,
}

/// `POST /api/auth/admin/create-user`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCreateUserRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
}

/// `POST /api/auth/admin/update-user`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUpdateUserRequest {
    pub user_id: String,
    pub data: serde_json::Map<String, serde_json::Value>,
}

/// `GET /api/auth/admin/list-users` query parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminListUsersQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_operator: Option<String>,
}

/// Common `{ userId }` body for `list-user-sessions`, `unban-user`, `impersonate-user`,
/// `revoke-user-sessions`, and `remove-user`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserIdRequest {
    pub user_id: String,
}

/// `POST /api/auth/admin/ban-user`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminBanUserRequest {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ban_expires_in: Option<i64>,
}

/// `POST /api/auth/admin/revoke-user-session`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRevokeUserSessionRequest {
    pub session_token: String,
}

/// `POST /api/auth/admin/set-user-password`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSetUserPasswordRequest {
    pub user_id: String,
    pub new_password: String,
}

/// `POST /api/auth/admin/has-permission`
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHasPermissionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<HashMap<String, Vec<String>>>,
}
