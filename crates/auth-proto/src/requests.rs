//! Request payloads for all Better Auth v1 API routes.
//!
//! Each struct matches the Zod body schema from the upstream TypeScript source.
//! Note: Better Auth uses `callbackURL`, `newUserCallbackURL`, and `errorCallbackURL`
//! with uppercase `URL`, so explicit `#[serde(rename = ...)]` attributes are used.

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
// Account Management
// ──────────────────────────────────────────────

/// `POST /api/auth/unlink-account`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlinkAccountRequest {
    /// The provider ID to unlink (e.g., "google", "github")
    pub provider_id: String,
}
