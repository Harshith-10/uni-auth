//! PostgreSQL implementation of `AuthAdapter`.

use sqlx::postgres::{PgPool, PgRow};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use auth_core::adapter::{filter_and_paginate_users, AuthAdapter, BoxFuture};
use auth_core::error::AdapterError;
use auth_core::models::{
    AccountRecord, AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput,
    CreateSessionInput, CreateUserInput, CreateVerificationInput, SessionRecord, UserRecord,
    VerificationRecord,
};

const POSTGRES_SCHEMA: &str = include_str!("../migrations/postgres.sql");

fn map_user_row(row: PgRow) -> Result<UserRecord, AdapterError> {
    Ok(UserRecord {
        id: row
            .try_get("id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        name: row
            .try_get("name")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        email: row
            .try_get("email")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        email_verified: row
            .try_get("email_verified")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        image: row
            .try_get("image")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        role: row.try_get("role").ok().flatten(),
        banned: row.try_get("banned").unwrap_or(false),
        ban_reason: row.try_get("ban_reason").ok().flatten(),
        ban_expires: row.try_get("ban_expires").ok().flatten(),
    })
}

fn map_session_row(row: PgRow) -> Result<SessionRecord, AdapterError> {
    Ok(SessionRecord {
        id: row
            .try_get("id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        user_id: row
            .try_get("user_id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        token: row
            .try_get("token")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        ip_address: row
            .try_get("ip_address")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        user_agent: row
            .try_get("user_agent")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        impersonated_by: row.try_get("impersonated_by").ok().flatten(),
    })
}

fn map_account_row(row: PgRow) -> Result<AccountRecord, AdapterError> {
    Ok(AccountRecord {
        id: row
            .try_get("id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        user_id: row
            .try_get("user_id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        account_id: row
            .try_get("account_id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        provider_id: row
            .try_get("provider_id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        access_token: row
            .try_get("access_token")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        refresh_token: row
            .try_get("refresh_token")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        id_token: row
            .try_get("id_token")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        access_token_expires_at: row
            .try_get("access_token_expires_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        refresh_token_expires_at: row
            .try_get("refresh_token_expires_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        scope: row
            .try_get("scope")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        password: row
            .try_get("password")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
    })
}

fn map_verification_row(row: PgRow) -> Result<VerificationRecord, AdapterError> {
    Ok(VerificationRecord {
        id: row
            .try_get("id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        identifier: row
            .try_get("identifier")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        value: row
            .try_get("value")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
    })
}

/// PostgreSQL-backed implementation of `AuthAdapter`.
#[derive(Clone)]
pub struct PostgresAuthAdapter {
    pool: PgPool,
}

impl PostgresAuthAdapter {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Executes the embedded Better Auth schema migration and idempotently upgrades older tables.
    pub async fn run_migrations(&self) -> Result<(), sqlx::Error> {
        sqlx::raw_sql(POSTGRES_SCHEMA).execute(&self.pool).await?;
        for stmt in [
            r#"ALTER TABLE "user" ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'"#,
            r#"ALTER TABLE "user" ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT FALSE"#,
            r#"ALTER TABLE "user" ADD COLUMN IF NOT EXISTS ban_reason TEXT"#,
            r#"ALTER TABLE "user" ADD COLUMN IF NOT EXISTS ban_expires TIMESTAMPTZ"#,
            r#"ALTER TABLE "session" ADD COLUMN IF NOT EXISTS impersonated_by TEXT"#,
        ] {
            let _ = sqlx::query(stmt).execute(&self.pool).await;
        }
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

impl AuthAdapter for PostgresAuthAdapter {
    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let email = input.email.to_lowercase();
            let now = OffsetDateTime::now_utc();
            let default_role = "user".to_string();

            let res = sqlx::query(
                r#"
                INSERT INTO "user" (id, name, email, email_verified, image, role, banned, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, $8)
                "#,
            )
            .bind(&id)
            .bind(&input.name)
            .bind(&email)
            .bind(input.email_verified)
            .bind(&input.image)
            .bind(&default_role)
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await;

            match res {
                Ok(_) => Ok(UserRecord {
                    id,
                    name: input.name,
                    email,
                    email_verified: input.email_verified,
                    image: input.image,
                    created_at: now,
                    updated_at: now,
                    role: Some(default_role),
                    banned: false,
                    ban_reason: None,
                    ban_expires: None,
                }),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    Err(AdapterError::UniqueViolation(e.message().to_string()))
                }
                Err(e) => Err(AdapterError::Query(e.to_string())),
            }
        })
    }

    fn find_user_by_id(
        &self,
        id: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            let row = sqlx::query(r#"SELECT * FROM "user" WHERE id = $1"#)
                .bind(id)
                .fetch_optional(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            row.map(map_user_row).transpose()
        })
    }

    fn find_user_by_email(
        &self,
        email: &str,
    ) -> BoxFuture<'static, Result<Option<UserRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let email = email.to_lowercase();
        Box::pin(async move {
            let row = sqlx::query(r#"SELECT * FROM "user" WHERE LOWER(email) = LOWER($1)"#)
                .bind(email)
                .fetch_optional(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            row.map(map_user_row).transpose()
        })
    }

    fn update_user_email_verified(
        &self,
        id: &str,
        verified: bool,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let res = sqlx::query(
                r#"UPDATE "user" SET email_verified = $1, updated_at = $2 WHERE id = $3"#,
            )
            .bind(verified)
            .bind(now)
            .bind(id)
            .execute(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            if res.rows_affected() == 0 {
                Err(AdapterError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    fn update_user_profile(
        &self,
        id: &str,
        name: Option<String>,
        image: Option<Option<String>>,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            let current_row = sqlx::query(r#"SELECT * FROM "user" WHERE id = $1"#)
                .bind(&id)
                .fetch_optional(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?
                .ok_or(AdapterError::NotFound)?;

            let current = map_user_row(current_row)?;
            let new_name = name.unwrap_or(current.name);
            let new_image = match image {
                Some(Some(img)) if !img.is_empty() => Some(img),
                Some(_) => None,
                None => current.image,
            };
            let now = OffsetDateTime::now_utc();

            let row = sqlx::query(
                r#"
                UPDATE "user"
                SET name = $1, image = $2, updated_at = $3
                WHERE id = $4
                RETURNING *
                "#,
            )
            .bind(&new_name)
            .bind(&new_image)
            .bind(now)
            .bind(&id)
            .fetch_one(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            map_user_row(row)
        })
    }

    fn update_user_admin(
        &self,
        id: &str,
        fields: AdminUpdateUserFields,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            let current_row = sqlx::query(r#"SELECT * FROM "user" WHERE id = $1"#)
                .bind(&id)
                .fetch_optional(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?
                .ok_or(AdapterError::NotFound)?;

            let current = map_user_row(current_row)?;
            let new_name = fields.name.unwrap_or(current.name);
            let new_email = fields
                .email
                .map(|e| e.to_lowercase())
                .unwrap_or(current.email);
            let new_verified = fields.email_verified.unwrap_or(current.email_verified);
            let new_image = fields.image.unwrap_or(current.image);
            let new_role = fields.role.or(current.role);
            let new_banned = fields.banned.unwrap_or(current.banned);
            let new_ban_reason = fields.ban_reason.unwrap_or(current.ban_reason);
            let new_ban_expires = fields.ban_expires.unwrap_or(current.ban_expires);
            let now = OffsetDateTime::now_utc();

            let res = sqlx::query(
                r#"
                UPDATE "user"
                SET name = $1, email = $2, email_verified = $3, image = $4,
                    role = $5, banned = $6, ban_reason = $7, ban_expires = $8, updated_at = $9
                WHERE id = $10
                RETURNING *
                "#,
            )
            .bind(&new_name)
            .bind(&new_email)
            .bind(new_verified)
            .bind(&new_image)
            .bind(&new_role)
            .bind(new_banned)
            .bind(&new_ban_reason)
            .bind(new_ban_expires)
            .bind(now)
            .bind(&id)
            .fetch_one(&pool)
            .await;

            match res {
                Ok(row) => map_user_row(row),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    Err(AdapterError::UniqueViolation(e.message().to_string()))
                }
                Err(e) => Err(AdapterError::Query(e.to_string())),
            }
        })
    }

    fn list_users(
        &self,
        filter: AdminListUsersFilter,
    ) -> BoxFuture<'static, Result<(Vec<UserRecord>, usize), AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let rows = sqlx::query(r#"SELECT * FROM "user""#)
                .fetch_all(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let users: Vec<UserRecord> = rows
                .into_iter()
                .map(map_user_row)
                .collect::<Result<Vec<_>, _>>()?;

            Ok(filter_and_paginate_users(users, &filter))
        })
    }

    fn delete_user(&self, id: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            sqlx::query(r#"DELETE FROM "user" WHERE id = $1"#)
                .bind(id)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(())
        })
    }

    fn create_account(
        &self,
        input: CreateAccountInput,
    ) -> BoxFuture<'static, Result<AccountRecord, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();

            let res = sqlx::query(
                r#"
                INSERT INTO "account" (
                    id, user_id, account_id, provider_id, access_token, refresh_token,
                    id_token, access_token_expires_at, refresh_token_expires_at, scope, password,
                    created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
            )
            .bind(&id)
            .bind(&input.user_id)
            .bind(&input.account_id)
            .bind(&input.provider_id)
            .bind(&input.access_token)
            .bind(&input.refresh_token)
            .bind(&input.id_token)
            .bind(input.access_token_expires_at)
            .bind(input.refresh_token_expires_at)
            .bind(&input.scope)
            .bind(&input.password)
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await;

            match res {
                Ok(_) => Ok(AccountRecord {
                    id,
                    user_id: input.user_id,
                    account_id: input.account_id,
                    provider_id: input.provider_id,
                    access_token: input.access_token,
                    refresh_token: input.refresh_token,
                    id_token: input.id_token,
                    access_token_expires_at: input.access_token_expires_at,
                    refresh_token_expires_at: input.refresh_token_expires_at,
                    scope: input.scope,
                    password: input.password,
                    created_at: now,
                    updated_at: now,
                }),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    Err(AdapterError::UniqueViolation(e.message().to_string()))
                }
                Err(e) => Err(AdapterError::Query(e.to_string())),
            }
        })
    }

    fn find_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<Option<AccountRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let provider_id = provider_id.to_string();
        let account_id = account_id.to_string();
        Box::pin(async move {
            let row = sqlx::query(
                r#"SELECT * FROM "account" WHERE provider_id = $1 AND account_id = $2"#,
            )
            .bind(provider_id)
            .bind(account_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            row.map(map_account_row).transpose()
        })
    }

    fn find_accounts_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<AccountRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        Box::pin(async move {
            let rows = sqlx::query(r#"SELECT * FROM "account" WHERE user_id = $1"#)
                .bind(user_id)
                .fetch_all(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            rows.into_iter().map(map_account_row).collect()
        })
    }

    fn update_account_password(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        let password_hash = password_hash.to_string();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let res = sqlx::query(
                r#"
                UPDATE "account" SET password = $1, updated_at = $2
                WHERE user_id = $3 AND provider_id = 'credential'
                "#,
            )
            .bind(password_hash)
            .bind(now)
            .bind(user_id)
            .execute(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            if res.rows_affected() == 0 {
                Err(AdapterError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    fn update_account_tokens(
        &self,
        provider_id: &str,
        account_id: &str,
        access_token: Option<String>,
        refresh_token: Option<String>,
        id_token: Option<String>,
        access_token_expires_at: Option<OffsetDateTime>,
        scope: Option<String>,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let provider_id = provider_id.to_string();
        let account_id = account_id.to_string();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let res = sqlx::query(
                r#"
                UPDATE "account"
                SET access_token = $1,
                    refresh_token = COALESCE($2, refresh_token),
                    id_token = COALESCE($3, id_token),
                    access_token_expires_at = $4,
                    scope = COALESCE($5, scope),
                    updated_at = $6
                WHERE provider_id = $7 AND account_id = $8
                "#,
            )
            .bind(access_token)
            .bind(refresh_token)
            .bind(id_token)
            .bind(access_token_expires_at)
            .bind(scope)
            .bind(now)
            .bind(provider_id)
            .bind(account_id)
            .execute(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            if res.rows_affected() == 0 {
                Err(AdapterError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    fn delete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let provider_id = provider_id.to_string();
        let account_id = account_id.to_string();
        Box::pin(async move {
            sqlx::query(r#"DELETE FROM "account" WHERE provider_id = $1 AND account_id = $2"#)
                .bind(provider_id)
                .bind(account_id)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(())
        })
    }

    fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();

            let res = sqlx::query(
                r#"
                INSERT INTO "session" (id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8)
                "#,
            )
            .bind(&id)
            .bind(&input.user_id)
            .bind(&input.token)
            .bind(input.expires_at)
            .bind(&input.ip_address)
            .bind(&input.user_agent)
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await;

            match res {
                Ok(_) => Ok(SessionRecord {
                    id,
                    user_id: input.user_id,
                    token: input.token,
                    expires_at: input.expires_at,
                    ip_address: input.ip_address,
                    user_agent: input.user_agent,
                    created_at: now,
                    updated_at: now,
                    impersonated_by: None,
                }),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    Err(AdapterError::UniqueViolation(e.message().to_string()))
                }
                Err(e) => Err(AdapterError::Query(e.to_string())),
            }
        })
    }

    fn create_impersonated_session(
        &self,
        input: CreateSessionInput,
        impersonated_by: String,
    ) -> BoxFuture<'static, Result<SessionRecord, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();

            let res = sqlx::query(
                r#"
                INSERT INTO "session" (id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(&id)
            .bind(&input.user_id)
            .bind(&input.token)
            .bind(input.expires_at)
            .bind(&input.ip_address)
            .bind(&input.user_agent)
            .bind(&impersonated_by)
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await;

            match res {
                Ok(_) => Ok(SessionRecord {
                    id,
                    user_id: input.user_id,
                    token: input.token,
                    expires_at: input.expires_at,
                    ip_address: input.ip_address,
                    user_agent: input.user_agent,
                    created_at: now,
                    updated_at: now,
                    impersonated_by: Some(impersonated_by),
                }),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    Err(AdapterError::UniqueViolation(e.message().to_string()))
                }
                Err(e) => Err(AdapterError::Query(e.to_string())),
            }
        })
    }

    fn find_session_by_token(
        &self,
        token: &str,
    ) -> BoxFuture<'static, Result<Option<SessionRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let token = token.to_string();
        Box::pin(async move {
            let row = sqlx::query(r#"SELECT * FROM "session" WHERE token = $1"#)
                .bind(token)
                .fetch_optional(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            row.map(map_session_row).transpose()
        })
    }

    fn list_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<Vec<SessionRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let rows = sqlx::query(
                r#"SELECT * FROM "session" WHERE user_id = $1 AND expires_at > $2 ORDER BY created_at DESC"#,
            )
            .bind(user_id)
            .bind(now)
            .fetch_all(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            rows.into_iter().map(map_session_row).collect()
        })
    }

    fn update_session_expiry(
        &self,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let token = token.to_string();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let res = sqlx::query(
                r#"UPDATE "session" SET expires_at = $1, updated_at = $2 WHERE token = $3"#,
            )
            .bind(expires_at)
            .bind(now)
            .bind(token)
            .execute(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            if res.rows_affected() == 0 {
                Err(AdapterError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    fn delete_session(&self, token: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let token = token.to_string();
        Box::pin(async move {
            sqlx::query(r#"DELETE FROM "session" WHERE token = $1"#)
                .bind(token)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        Box::pin(async move {
            sqlx::query(r#"DELETE FROM "session" WHERE user_id = $1"#)
                .bind(user_id)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_other_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        let current_token = current_token.to_string();
        Box::pin(async move {
            sqlx::query(r#"DELETE FROM "session" WHERE user_id = $1 AND token != $2"#)
                .bind(user_id)
                .bind(current_token)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_expired_sessions(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let res = sqlx::query(r#"DELETE FROM "session" WHERE expires_at <= $1"#)
                .bind(now)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(res.rows_affected() as usize)
        })
    }

    fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> BoxFuture<'static, Result<VerificationRecord, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let now = OffsetDateTime::now_utc();

            sqlx::query(
                r#"
                INSERT INTO "verification" (id, identifier, value, expires_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(&id)
            .bind(&input.identifier)
            .bind(&input.value)
            .bind(input.expires_at)
            .bind(now)
            .bind(now)
            .execute(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            Ok(VerificationRecord {
                id,
                identifier: input.identifier,
                value: input.value,
                expires_at: input.expires_at,
                created_at: now,
                updated_at: now,
            })
        })
    }

    fn find_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let identifier = identifier.to_string();
        Box::pin(async move {
            let row = sqlx::query(r#"SELECT * FROM "verification" WHERE identifier = $1"#)
                .bind(identifier)
                .fetch_optional(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            row.map(map_verification_row).transpose()
        })
    }

    fn consume_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<Option<VerificationRecord>, AdapterError>> {
        let pool = self.pool.clone();
        let identifier = identifier.to_string();
        Box::pin(async move {
            let row = sqlx::query(
                r#"DELETE FROM "verification" WHERE identifier = $1 RETURNING *"#,
            )
            .bind(&identifier)
            .fetch_optional(&pool)
            .await
            .map_err(|e| AdapterError::Query(e.to_string()))?;

            if let Some(r) = row {
                let record = map_verification_row(r)?;
                if record.is_expired() {
                    Ok(None)
                } else {
                    Ok(Some(record))
                }
            } else {
                Ok(None)
            }
        })
    }

    fn delete_verification(
        &self,
        identifier: &str,
    ) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let identifier = identifier.to_string();
        Box::pin(async move {
            sqlx::query(r#"DELETE FROM "verification" WHERE identifier = $1"#)
                .bind(identifier)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(())
        })
    }

    fn delete_expired_verifications(&self) -> BoxFuture<'static, Result<usize, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();
            let res = sqlx::query(r#"DELETE FROM "verification" WHERE expires_at <= $1"#)
                .bind(now)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(res.rows_affected() as usize)
        })
    }
}
