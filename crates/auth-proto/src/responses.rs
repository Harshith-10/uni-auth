//! Response payloads for Better Auth v1 API routes and plugins.
//!
//! All structs use `camelCase` for JSON serialization to match Better Auth TypeScript conventions.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::models::{SessionWire, UserWire};

// ──────────────────────────────────────────────
// Health / Status
// ──────────────────────────────────────────────

/// `GET /api/auth/ok`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OkResponse {
    pub ok: bool,
}

impl Default for OkResponse {
    fn default() -> Self {
        Self { ok: true }
    }
}

/// Generic boolean status response (e.g., `revoke-session`, `unlink-account`)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    pub status: bool,
}

impl StatusResponse {
    pub fn success() -> Self {
        Self { status: true }
    }
}

/// Status with a human-readable message (e.g., `request-password-reset`)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StatusMessageResponse {
    pub status: bool,
    pub message: String,
}

/// Matches Better Auth `POST /delete-user` response (`{ "success": true, "message": "User deleted" }`)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteUserResponse {
    pub success: bool,
    pub message: String,
}

// ──────────────────────────────────────────────
// Authentication Responses
// ──────────────────────────────────────────────

/// `POST /api/auth/sign-up/email` response.
///
/// If auto-sign-in is disabled or email verification is required, `token` will be `None`.
///
/// Reference: `.reference/better-auth/.../sign-up.ts` lines 55-58, 442-448
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignUpResponse {
    /// Session token (nullable if email verification required or autoSignIn=false)
    pub token: Option<String>,

    /// The created user
    pub user: UserWire,
}

/// `POST /api/auth/sign-in/email` response.
///
/// Reference: `.reference/better-auth/.../sign-in.ts` lines 461-466, 635-643
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignInResponse {
    /// Whether the client should redirect
    pub redirect: bool,

    /// Session token
    pub token: String,

    /// Optional redirect URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// The authenticated user
    pub user: UserWire,
}

/// `GET/POST /api/auth/get-session` and `POST /api/auth/one-time-token/verify` response.
///
/// When the request is unauthenticated, `/get-session` returns HTTP 200 with JSON `null`.
///
/// Reference: `.reference/better-auth/.../session.ts` lines 68-71
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionAndUserResponse {
    /// The active session
    pub session: SessionWire,

    /// The authenticated user
    pub user: UserWire,
}

/// `POST /api/auth/sign-in/social` and `POST /api/auth/link-social` response.
///
/// In standard OAuth flow, returns `{ redirect: true, url: "https://..." }`.
/// When `disableRedirect: true`, returns `{ redirect: false, url: "https://..." }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignInSocialResponse {
    /// Whether automatic redirect should occur
    pub redirect: bool,

    /// The provider authorization URL
    pub url: String,
}

/// `POST /api/auth/sign-out` response.
///
/// Reference: `.reference/better-auth/.../sign-out.ts` lines 28-34
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SignOutResponse {
    /// Always true on successful sign out
    pub success: bool,

    /// Provider logout URL if RP-initiated logout is configured
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Whether the client should redirect to `url`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<bool>,
}

impl Default for SignOutResponse {
    fn default() -> Self {
        Self {
            success: true,
            url: None,
            redirect: None,
        }
    }
}

// ──────────────────────────────────────────────
// Password, User & Token Responses
// ──────────────────────────────────────────────

/// `POST /api/auth/change-password` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordResponse {
    /// New session token if other sessions were revoked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Updated user profile
    pub user: UserWire,
}

/// `POST /api/auth/update-user` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserResponse {
    pub status: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserWire>,
}

/// `GET /api/auth/one-time-token/generate` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OneTimeTokenGenerateResponse {
    /// The generated one-time token (valid for ~3 minutes)
    pub token: String,
}

/// Account entry as returned by `GET /api/auth/list-accounts`.
///
/// All sensitive credentials (passwords, tokens) are omitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountListEntryWire {
    pub id: String,
    pub provider_id: String,
    pub account_id: String,
    pub user_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

/// `GET /api/auth/verify-email` response (when no callbackURL is provided).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailResponse {
    pub status: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

// ──────────────────────────────────────────────
// Admin Plugin Responses
// ──────────────────────────────────────────────

/// Envelope `{ "user": UserWire }` returned by `set-role`, `create-user`, `ban-user`, and `unban-user`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserResponse {
    pub user: UserWire,
}

/// `GET /api/auth/admin/list-users` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminListUsersResponse {
    pub users: Vec<UserWire>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

/// `POST /api/auth/admin/list-user-sessions` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminListUserSessionsResponse {
    pub sessions: Vec<SessionWire>,
}

/// `{ "success": true }` response returned by `revoke-user-session`, `revoke-user-sessions`, and `remove-user`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminSuccessResponse {
    pub success: bool,
}

impl AdminSuccessResponse {
    pub fn ok() -> Self {
        Self { success: true }
    }
}

/// `POST /api/auth/admin/has-permission` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminPermissionResponse {
    pub error: Option<String>,
    pub success: bool,
}

// ──────────────────────────────────────────────
// Secondary Feature Parity Responses
// ──────────────────────────────────────────────

/// Response returned by `POST /get-access-token` and `POST /refresh-token`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct OAuthTokenResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<time::OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<time::OffsetDateTime>,
}

/// Response returned by `GET /account-info`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfoResponse {
    pub user: UserWire,
    pub account: AccountListEntryWire,
    pub data: serde_json::Value,
}

/// Response returned by `POST /update-session`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSessionResponse {
    pub session: SessionWire,
}

/// Upstream error query payload or error landing page JSON model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponseWire {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}
