//! Better Auth error codes and JSON error response envelope.
//!
//! Matches the upstream definitions in `@better-auth/core/error` and `plugins/admin/error-codes.ts`:
//! - `.reference/better-auth/packages/core/src/error/codes.ts`
//! - `.reference/better-auth/packages/better-auth/src/plugins/admin/error-codes.ts`

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
/// Direct parity with `BASE_ERROR_CODES` in `.reference/better-auth/packages/core/src/error/codes.ts`
/// and `ADMIN_ERROR_CODES` in `.reference/better-auth/packages/better-auth/src/plugins/admin/error-codes.ts`.
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
    pub const USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL: &str = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL";
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
    pub const PASSWORD_ALREADY_SET: &str = "PASSWORD_ALREADY_SET";
    pub const PROVIDER_NOT_CONFIGURED: &str = "PROVIDER_NOT_CONFIGURED";
    pub const FAILED_TO_REFRESH_ACCESS_TOKEN: &str = "FAILED_TO_REFRESH_ACCESS_TOKEN";
    pub const BODY_MUST_BE_AN_OBJECT: &str = "BODY_MUST_BE_AN_OBJECT";

    // ── Admin Plugin Error Codes ──
    pub const YOU_CANNOT_BAN_YOURSELF: &str = "YOU_CANNOT_BAN_YOURSELF";
    pub const YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE: &str =
        "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE";
    pub const YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS: &str = "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_LIST_USERS: &str = "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS: &str =
        "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS";
    pub const YOU_ARE_NOT_ALLOWED_TO_BAN_USERS: &str = "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS: &str =
        "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS: &str =
        "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS";
    pub const YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS: &str = "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS";
    pub const YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD: &str =
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD";
    pub const BANNED_USER: &str = "BANNED_USER";
    pub const YOU_ARE_NOT_ALLOWED_TO_GET_USER: &str = "YOU_ARE_NOT_ALLOWED_TO_GET_USER";
    pub const NO_DATA_TO_UPDATE: &str = "NO_DATA_TO_UPDATE";
    pub const YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS: &str = "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS";
    pub const YOU_CANNOT_REMOVE_YOURSELF: &str = "YOU_CANNOT_REMOVE_YOURSELF";
    pub const YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE: &str =
        "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE";
    pub const YOU_CANNOT_IMPERSONATE_ADMINS: &str = "YOU_CANNOT_IMPERSONATE_ADMINS";
    pub const INVALID_ROLE_TYPE: &str = "INVALID_ROLE_TYPE";
    pub const YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL: &str =
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL";
    pub const YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PHONE_NUMBER: &str =
        "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PHONE_NUMBER";
    pub const PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER: &str =
        "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER";
    pub const USER_ID_CANNOT_BE_UPDATED: &str = "USER_ID_CANNOT_BE_UPDATED";
}
