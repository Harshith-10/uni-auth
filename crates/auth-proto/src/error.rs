//! Better Auth error codes and JSON error response envelope.
//!
//! Matches the upstream definitions in `@better-auth/core/error`:
//! - `.reference/better-auth/packages/core/src/error/codes.ts`

use serde::{Deserialize, Serialize};

/// Better Auth wire error envelope.
///
/// Returned on HTTP 4xx / 5xx error responses.
/// Better Auth clients look for `message` and `code`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthErrorResponse {
    /// Human-readable error message
    pub message: String,

    /// Machine-readable error code (e.g. `INVALID_EMAIL_OR_PASSWORD`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    /// HTTP status code (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

impl AuthErrorResponse {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            message: message.into(),
            status: None,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
}

/// Standard Better Auth error code constants.
///
/// Direct parity with `BASE_ERROR_CODES` in `.reference/better-auth/packages/core/src/error/codes.ts`.
pub mod error_codes {
    pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
    pub const FAILED_TO_CREATE_USER: &str = "FAILED_TO_CREATE_USER";
    pub const FAILED_TO_CREATE_SESSION: &str = "FAILED_TO_CREATE_SESSION";
    pub const FAILED_TO_UPDATE_USER: &str = "FAILED_TO_UPDATE_USER";
    pub const FAILED_TO_GET_SESSION: &str = "FAILED_TO_GET_SESSION";
    pub const INVALID_PASSWORD: &str = "INVALID_PASSWORD";
    pub const INVALID_EMAIL: &str = "INVALID_EMAIL";
    pub const INVALID_EMAIL_OR_PASSWORD: &str = "INVALID_EMAIL_OR_PASSWORD";
    pub const INVALID_USER: &str = "INVALID_USER";
    pub const SOCIAL_ACCOUNT_ALREADY_LINKED: &str = "SOCIAL_ACCOUNT_ALREADY_LINKED";
    pub const PROVIDER_NOT_FOUND: &str = "PROVIDER_NOT_FOUND";
    pub const INVALID_TOKEN: &str = "INVALID_TOKEN";
    pub const TOKEN_EXPIRED: &str = "TOKEN_EXPIRED";
    pub const ID_TOKEN_NOT_SUPPORTED: &str = "ID_TOKEN_NOT_SUPPORTED";
    pub const FAILED_TO_GET_USER_INFO: &str = "FAILED_TO_GET_USER_INFO";
    pub const USER_EMAIL_NOT_FOUND: &str = "USER_EMAIL_NOT_FOUND";
    pub const EMAIL_NOT_VERIFIED: &str = "EMAIL_NOT_VERIFIED";
    pub const PASSWORD_TOO_SHORT: &str = "PASSWORD_TOO_SHORT";
    pub const PASSWORD_TOO_LONG: &str = "PASSWORD_TOO_LONG";
    pub const USER_ALREADY_EXISTS: &str = "USER_ALREADY_EXISTS";
    pub const USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: &str =
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL";
    pub const EMAIL_CAN_NOT_BE_UPDATED: &str = "EMAIL_CAN_NOT_BE_UPDATED";
    pub const CHANGE_EMAIL_DISABLED: &str = "CHANGE_EMAIL_DISABLED";
    pub const CREDENTIAL_ACCOUNT_NOT_FOUND: &str = "CREDENTIAL_ACCOUNT_NOT_FOUND";
    pub const SESSION_EXPIRED: &str = "SESSION_EXPIRED";
    pub const FAILED_TO_UNLINK_LAST_ACCOUNT: &str = "FAILED_TO_UNLINK_LAST_ACCOUNT";
    pub const ACCOUNT_NOT_FOUND: &str = "ACCOUNT_NOT_FOUND";
    pub const SESSION_NOT_FRESH: &str = "SESSION_NOT_FRESH";
    pub const LINKED_ACCOUNT_ALREADY_EXISTS: &str = "LINKED_ACCOUNT_ALREADY_EXISTS";
    pub const INVALID_ORIGIN: &str = "INVALID_ORIGIN";
    pub const INVALID_CALLBACK_URL: &str = "INVALID_CALLBACK_URL";
    pub const METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED: &str =
        "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED";
    pub const EMAIL_PASSWORD_DISABLED: &str = "EMAIL_PASSWORD_DISABLED";
    pub const EMAIL_PASSWORD_SIGN_UP_DISABLED: &str = "EMAIL_PASSWORD_SIGN_UP_DISABLED";
    pub const RESET_PASSWORD_DISABLED: &str = "RESET_PASSWORD_DISABLED";
}
