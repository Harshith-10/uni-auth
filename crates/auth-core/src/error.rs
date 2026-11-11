//! Error types for the core authentication engine.

use auth_proto::error_codes;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid email")]
    InvalidEmail,

    #[error("Password too short: must be at least {min} characters")]
    PasswordTooShort { min: usize },

    #[error("Password too long")]
    PasswordTooLong,

    #[error("Password is already set")]
    PasswordAlreadySet,

    #[error("Change email is disabled")]
    ChangeEmailDisabled,

    #[error("Account is not associated with a configured social provider")]
    ProviderNotConfigured,

    #[error("Failed to refresh access token")]
    FailedToRefreshAccessToken,

    #[error("Body must be an object")]
    BodyMustBeAnObject,

    #[error("Invalid email or password")]
    InvalidEmailOrPassword,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Credential account not found")]
    CredentialAccountNotFound,

    #[error("Account not found")]
    AccountNotFound,

    #[error("You cannot unlink your last authentication method")]
    FailedToUnlinkLastAccount,

    #[error("Social account already linked")]
    SocialAccountAlreadyLinked,

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

    #[error("Invalid origin")]
    InvalidOrigin,

    #[error("Invalid callback URL")]
    InvalidCallbackUrl,

    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Email and password authentication is disabled")]
    EmailPasswordDisabled,

    #[error("Email and password sign up is disabled")]
    SignUpDisabled,

    #[error("{0}")]
    BannedUser(String),

    #[error("{message}")]
    Forbidden { code: &'static str, message: String },

    #[error("{message}")]
    BadRequest { code: &'static str, message: String },

    #[error("Database adapter error: {0}")]
    Adapter(AdapterError),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Email sender error: {0}")]
    Email(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Not found")]
    NotFound,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AuthError {
    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            message: message.into(),
        }
    }

    /// Maps to Better Auth standard error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::UserNotFound => error_codes::USER_NOT_FOUND,
            Self::InvalidEmail => error_codes::INVALID_EMAIL,
            Self::PasswordTooShort { .. } => error_codes::PASSWORD_TOO_SHORT,
            Self::PasswordTooLong => error_codes::PASSWORD_TOO_LONG,
            Self::PasswordAlreadySet => error_codes::PASSWORD_ALREADY_SET,
            Self::ChangeEmailDisabled => error_codes::CHANGE_EMAIL_DISABLED,
            Self::ProviderNotConfigured => error_codes::PROVIDER_NOT_CONFIGURED,
            Self::FailedToRefreshAccessToken => error_codes::FAILED_TO_REFRESH_ACCESS_TOKEN,
            Self::BodyMustBeAnObject => error_codes::BODY_MUST_BE_AN_OBJECT,
            Self::InvalidEmailOrPassword => error_codes::INVALID_EMAIL_OR_PASSWORD,
            Self::InvalidPassword => error_codes::INVALID_PASSWORD,
            Self::CredentialAccountNotFound => error_codes::CREDENTIAL_ACCOUNT_NOT_FOUND,
            Self::AccountNotFound => error_codes::ACCOUNT_NOT_FOUND,
            Self::FailedToUnlinkLastAccount => error_codes::FAILED_TO_UNLINK_LAST_ACCOUNT,
            Self::SocialAccountAlreadyLinked => error_codes::SOCIAL_ACCOUNT_ALREADY_LINKED,
            Self::UserAlreadyExists => error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
            Self::EmailNotVerified => error_codes::EMAIL_NOT_VERIFIED,
            Self::InvalidToken => error_codes::INVALID_TOKEN,
            Self::TokenExpired => error_codes::TOKEN_EXPIRED,
            Self::SessionExpired => error_codes::SESSION_EXPIRED,
            Self::SessionNotFresh => error_codes::SESSION_NOT_FRESH,
            Self::InvalidOrigin => error_codes::INVALID_ORIGIN,
            Self::InvalidCallbackUrl => error_codes::INVALID_CALLBACK_URL,
            Self::ProviderNotFound(_) => error_codes::PROVIDER_NOT_FOUND,
            Self::EmailPasswordDisabled => error_codes::EMAIL_PASSWORD_DISABLED,
            Self::SignUpDisabled => error_codes::EMAIL_PASSWORD_SIGN_UP_DISABLED,
            Self::BannedUser(_) => error_codes::BANNED_USER,
            Self::Forbidden { code, .. } | Self::BadRequest { code, .. } => code,
            Self::RateLimitExceeded => "RATE_LIMITED",
            Self::NotFound => "NOT_FOUND",
            _ => "INTERNAL_SERVER_ERROR",
        }
    }

    /// Corresponding HTTP status code.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidEmail
            | Self::PasswordTooShort { .. }
            | Self::PasswordTooLong
            | Self::PasswordAlreadySet
            | Self::ChangeEmailDisabled
            | Self::ProviderNotConfigured
            | Self::FailedToRefreshAccessToken
            | Self::BodyMustBeAnObject
            | Self::InvalidPassword
            | Self::InvalidToken
            | Self::TokenExpired
            | Self::CredentialAccountNotFound
            | Self::AccountNotFound
            | Self::FailedToUnlinkLastAccount
            | Self::SocialAccountAlreadyLinked
            | Self::InvalidCallbackUrl
            | Self::EmailPasswordDisabled
            | Self::SignUpDisabled
            | Self::BadRequest { .. } => 400,
            Self::InvalidEmailOrPassword | Self::SessionExpired => 401,
            Self::EmailNotVerified
            | Self::SessionNotFresh
            | Self::InvalidOrigin
            | Self::BannedUser(_)
            | Self::Forbidden { .. } => 403,
            Self::UserNotFound | Self::ProviderNotFound(_) | Self::NotFound => 404,
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

    #[error("{0}")]
    Auth(Box<AuthError>),
}

impl From<AdapterError> for AuthError {
    fn from(err: AdapterError) -> Self {
        match err {
            AdapterError::Auth(auth_err) => *auth_err,
            AdapterError::UniqueViolation(_) => AuthError::UserAlreadyExists,
            other => AuthError::Adapter(other),
        }
    }
}

impl From<AuthError> for AdapterError {
    fn from(err: AuthError) -> Self {
        AdapterError::Auth(Box::new(err))
    }
}
