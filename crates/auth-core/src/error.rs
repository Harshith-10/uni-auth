//! Error types for the core authentication engine.

use auth_proto::error_codes;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid email")]
    InvalidEmail,

    #[error("Password too short: must be at least 8 characters")]
    PasswordTooShort,

    #[error("Password too long")]
    PasswordTooLong,

    #[error("Invalid email or password")]
    InvalidEmailOrPassword,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("User already exists. Use another email.")]
    UserAlreadyExists,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Invalid or expired token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Session expired")]
    SessionExpired,

    #[error("Session not fresh")]
    SessionNotFresh,

    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Email and password authentication is disabled")]
    EmailPasswordDisabled,

    #[error("Email and password sign up is disabled")]
    SignUpDisabled,

    #[error("Database adapter error: {0}")]
    Adapter(#[from] AdapterError),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Email sender error: {0}")]
    Email(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AuthError {
    /// Maps to Better Auth standard error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::UserNotFound => error_codes::USER_NOT_FOUND,
            Self::InvalidEmail => error_codes::INVALID_EMAIL,
            Self::PasswordTooShort => error_codes::PASSWORD_TOO_SHORT,
            Self::PasswordTooLong => error_codes::PASSWORD_TOO_LONG,
            Self::InvalidEmailOrPassword => error_codes::INVALID_EMAIL_OR_PASSWORD,
            Self::InvalidPassword => error_codes::INVALID_PASSWORD,
            Self::UserAlreadyExists => error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
            Self::EmailNotVerified => error_codes::EMAIL_NOT_VERIFIED,
            Self::InvalidToken => error_codes::INVALID_TOKEN,
            Self::TokenExpired => error_codes::TOKEN_EXPIRED,
            Self::SessionExpired => error_codes::SESSION_EXPIRED,
            Self::SessionNotFresh => error_codes::SESSION_NOT_FRESH,
            Self::ProviderNotFound(_) => error_codes::PROVIDER_NOT_FOUND,
            Self::EmailPasswordDisabled => error_codes::EMAIL_PASSWORD_DISABLED,
            Self::SignUpDisabled => error_codes::EMAIL_PASSWORD_SIGN_UP_DISABLED,
            _ => "INTERNAL_SERVER_ERROR",
        }
    }

    /// Corresponding HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidEmail | Self::PasswordTooShort | Self::PasswordTooLong => 400,
            Self::InvalidEmailOrPassword | Self::InvalidPassword | Self::InvalidToken => 401,
            Self::EmailNotVerified | Self::SessionNotFresh => 403,
            Self::UserNotFound | Self::ProviderNotFound(_) => 404,
            Self::UserAlreadyExists => 422,
            Self::RateLimitExceeded => 429,
            _ => 500,
        }
    }
}

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Record not found")]
    NotFound,

    #[error("Unique constraint violation: {0}")]
    UniqueViolation(String),

    #[error("Database query failed: {0}")]
    Query(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Internal error: {0}")]
    Internal(String),
}
