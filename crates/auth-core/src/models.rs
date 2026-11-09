//! Domain models representing internal database records and their mapping to wire DTOs.

use auth_proto::{AccountWire, SessionWire, UserWire};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Internal user database entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserRecord {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl UserRecord {
    pub fn to_wire(&self) -> UserWire {
        UserWire {
            id: self.id.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            email_verified: self.email_verified,
            image: self.image.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Internal session database entity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl SessionRecord {
    pub fn to_wire(&self) -> SessionWire {
        SessionWire {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            token: self.token.clone(),
            expires_at: self.expires_at,
            ip_address: self.ip_address.clone(),
            user_agent: self.user_agent.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }
}

/// Internal account database entity.
///
/// Contains sensitive credential data (password hash, tokens) that is **never** serialized to wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountRecord {
    pub id: String,
    pub user_id: String,
    pub account_id: String,
    pub provider_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
    pub password: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl AccountRecord {
    pub fn to_wire(&self) -> AccountWire {
        AccountWire {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            account_id: self.account_id.clone(),
            provider_id: self.provider_id.clone(),
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            id_token: self.id_token.clone(),
            access_token_expires_at: self.access_token_expires_at,
            refresh_token_expires_at: self.refresh_token_expires_at,
            scope: self.scope.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Internal verification database entity.
///
/// Used for:
/// - Email verification tokens (`identifier = "verify-email:{token}"`)
/// - Password reset tokens (`identifier = "reset-password:{token}"`)
/// - One-time tokens (`identifier = "one-time-token:{token}"`)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationRecord {
    pub id: String,
    pub identifier: String,
    pub value: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl VerificationRecord {
    pub fn is_expired(&self) -> bool {
        self.expires_at < OffsetDateTime::now_utc()
    }
}

// ──────────────────────────────────────────────
// Creation Inputs
// ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CreateUserInput {
    pub id: Option<String>,
    pub name: String,
    pub email: String,
    pub image: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, Clone)]
pub struct CreateAccountInput {
    pub id: Option<String>,
    pub user_id: String,
    pub account_id: String,
    pub provider_id: String,
    pub password: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateSessionInput {
    pub id: Option<String>,
    pub user_id: String,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateVerificationInput {
    pub id: Option<String>,
    pub identifier: String,
    pub value: String,
    pub expires_at: OffsetDateTime,
}
