//! SQLite implementation of `AuthAdapter`.
//!
//! Suitable for lightweight embedded deployments, mobile/desktop, and zero-container CI testing.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow};
use sqlx::{QueryBuilder, Row};
use std::str::FromStr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use auth_core::adapter::{AuthAdapter, BoxFuture};
use auth_core::error::AdapterError;
use auth_core::models::{
    AccountRecord, AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput,
    CreateSessionInput, CreateUserInput, CreateVerificationInput, SessionRecord, UserRecord,
    VerificationRecord,
};

const SQLITE_SCHEMA: &str = include_str!("../migrations/sqlite.sql");

fn format_dt(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc().format(&Rfc3339).unwrap())
}

fn parse_dt(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &Rfc3339).unwrap_or_else(|_| OffsetDateTime::now_utc())
}

fn parse_opt_dt(opt: Option<String>) -> Option<OffsetDateTime> {
    opt.and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok())
}

fn format_opt_dt(opt: Option<OffsetDateTime>) -> Option<String> {
    opt.map(format_dt)
}

fn map_user_row(row: SqliteRow) -> Result<UserRecord, AdapterError> {
    let email_verified_int: i64 = row
        .try_get("email_verified")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let banned_int: i64 = row.try_get("banned").unwrap_or(0);
    let ban_expires_str: Option<String> = row.try_get("ban_expires").ok().flatten();
    let created_at_str: String = row
        .try_get("created_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at_str: String = row
        .try_get("updated_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;

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
        email_verified: email_verified_int != 0,
        image: row
            .try_get("image")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: parse_dt(&created_at_str),
        updated_at: parse_dt(&updated_at_str),
        role: row.try_get("role").ok().flatten(),
        banned: banned_int != 0,
        ban_reason: row.try_get("ban_reason").ok().flatten(),
        ban_expires: parse_opt_dt(ban_expires_str),
    })
}

fn map_session_row(row: SqliteRow) -> Result<SessionRecord, AdapterError> {
    let expires_at_str: String = row
        .try_get("expires_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let created_at_str: String = row
        .try_get("created_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at_str: String = row
        .try_get("updated_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;

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
        expires_at: parse_dt(&expires_at_str),
        ip_address: row
            .try_get("ip_address")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        user_agent: row
            .try_get("user_agent")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: parse_dt(&created_at_str),
        updated_at: parse_dt(&updated_at_str),
        impersonated_by: row.try_get("impersonated_by").ok().flatten(),
    })
}

fn map_account_row(row: SqliteRow) -> Result<AccountRecord, AdapterError> {
    let access_token_expires_at: Option<String> = row
        .try_get("access_token_expires_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let refresh_token_expires_at: Option<String> = row
        .try_get("refresh_token_expires_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let created_at_str: String = row
        .try_get("created_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at_str: String = row
        .try_get("updated_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;

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
        access_token_expires_at: parse_opt_dt(access_token_expires_at),
        refresh_token_expires_at: parse_opt_dt(refresh_token_expires_at),
        scope: row
            .try_get("scope")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        password: row
            .try_get("password")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at: parse_dt(&created_at_str),
        updated_at: parse_dt(&updated_at_str),
    })
}

fn map_verification_row(row: SqliteRow) -> Result<VerificationRecord, AdapterError> {
    let expires_at_str: String = row
        .try_get("expires_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let created_at_str: String = row
        .try_get("created_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at_str: String = row
        .try_get("updated_at")
        .map_err(|e| AdapterError::Query(e.to_string()))?;

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
        expires_at: parse_dt(&expires_at_str),
        created_at: parse_dt(&created_at_str),
        updated_at: parse_dt(&updated_at_str),
    })
}

/// SQLite-backed implementation of `AuthAdapter`.
#[derive(Clone)]
pub struct SqliteAuthAdapter {
    pool: SqlitePool,
}

impl SqliteAuthAdapter {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Creates an in-memory SQLite database and applies embedded Better Auth schema.
    pub async fn new_in_memory() -> Result<Self, sqlx::Error> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1) // In-memory DB requires 1 connection or shared cache
            .connect_with(opts)
            .await?;

        let adapter = Self::new(pool);
        adapter.run_migrations().await?;
        Ok(adapter)
    }

    /// Executes the embedded Better Auth schema migration and idempotently upgrades older tables.
    pub async fn run_migrations(&self) -> Result<(), sqlx::Error> {
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&self.pool)
            .await?;
        sqlx::raw_sql(SQLITE_SCHEMA).execute(&self.pool).await?;

        // Idempotent column additions for existing pre-Admin SQLite database files
        for stmt in [
            r#"ALTER TABLE "user" ADD COLUMN role TEXT DEFAULT 'user'"#,
            r#"ALTER TABLE "user" ADD COLUMN banned INTEGER NOT NULL DEFAULT 0"#,
            r#"ALTER TABLE "user" ADD COLUMN ban_reason TEXT"#,
            r#"ALTER TABLE "user" ADD COLUMN ban_expires TEXT"#,
            r#"ALTER TABLE "session" ADD COLUMN impersonated_by TEXT"#,
        ] {
            let _ = sqlx::query(stmt).execute(&self.pool).await;
        }
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn apply_sqlite_user_filters(
    qb: &mut QueryBuilder<'_, sqlx::Sqlite>,
    filter: &AdminListUsersFilter,
) {
    let mut has_where = false;

    // Search condition
    if let Some(ref sv) = filter.search_value {
        if !sv.is_empty() {
            let col = match filter.search_field.as_deref().unwrap_or("email") {
                "name" => "LOWER(name)",
                "role" => "LOWER(COALESCE(role, 'user'))",
                _ => "LOWER(email)",
            };
            let pattern = match filter.search_operator.as_deref().unwrap_or("contains") {
                "starts_with" => format!("{}%", sv.to_lowercase()),
                "ends_with" => format!("%{}", sv.to_lowercase()),
                _ => format!("%{}%", sv.to_lowercase()),
            };
            qb.push(" WHERE ");
            has_where = true;
            qb.push(col);
            qb.push(" LIKE ");
            qb.push_bind(pattern);
        }
    }

    // Filter condition
    if let Some(ref fv) = filter.filter_value {
        let needle = fv.to_lowercase();
        let field = filter.filter_field.as_deref().unwrap_or("email");
        let op = filter.filter_operator.as_deref().unwrap_or("eq");

        if has_where {
            qb.push(" AND ");
        } else {
            qb.push(" WHERE ");
        }

        match field {
            "banned" => {
                let banned_int: i64 = if needle == "true" || needle == "1" {
                    1
                } else {
                    0
                };
                if op == "ne" {
                    qb.push("banned != ");
                } else {
                    qb.push("banned = ");
                }
                qb.push_bind(banned_int);
            }
            "emailVerified" | "email_verified" => {
                let ver_int: i64 = if needle == "true" || needle == "1" {
                    1
                } else {
                    0
                };
                if op == "ne" {
                    qb.push("email_verified != ");
                } else {
                    qb.push("email_verified = ");
                }
                qb.push_bind(ver_int);
            }
            "name" => {
                let col = "LOWER(name)";
                match op {
                    "ne" => {
                        qb.push(col).push(" != ").push_bind(needle);
                    }
                    "contains" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("%{needle}%"));
                    }
                    "starts_with" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("{needle}%"));
                    }
                    "ends_with" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("%{needle}"));
                    }
                    _ => {
                        qb.push(col).push(" = ").push_bind(needle);
                    }
                }
            }
            "role" => {
                let col = "LOWER(COALESCE(role, 'user'))";
                match op {
                    "ne" => {
                        qb.push(col).push(" != ").push_bind(needle);
                    }
                    "contains" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("%{needle}%"));
                    }
                    "starts_with" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("{needle}%"));
                    }
                    "ends_with" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("%{needle}"));
                    }
                    _ => {
                        qb.push(col).push(" = ").push_bind(needle);
                    }
                }
            }
            "id" => {
                if op == "ne" {
                    qb.push("id != ").push_bind(needle);
                } else {
                    qb.push("id = ").push_bind(needle);
                }
            }
            _ => {
                let col = "LOWER(email)";
                match op {
                    "ne" => {
                        qb.push(col).push(" != ").push_bind(needle);
                    }
                    "contains" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("%{needle}%"));
                    }
                    "starts_with" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("{needle}%"));
                    }
                    "ends_with" => {
                        qb.push(col).push(" LIKE ").push_bind(format!("%{needle}"));
                    }
                    _ => {
                        qb.push(col).push(" = ").push_bind(needle);
                    }
                }
            }
        }
    }
}

impl AuthAdapter for SqliteAuthAdapter {
    fn create_user(
        &self,
        input: CreateUserInput,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let id = input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let email = input.email.to_lowercase();
            let now = OffsetDateTime::now_utc();
            let now_str = format_dt(now);
            let verified_int: i64 = if input.email_verified { 1 } else { 0 };
            let role = input.role.unwrap_or_else(|| "user".to_string());

            let res = sqlx::query(
                r#"
                INSERT INTO "user" (id, name, email, email_verified, image, role, banned, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&input.name)
            .bind(&email)
            .bind(verified_int)
            .bind(&input.image)
            .bind(&role)
            .bind(&now_str)
            .bind(&now_str)
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
                    role: Some(role),
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
            let row = sqlx::query(r#"SELECT * FROM "user" WHERE id = ?"#)
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
            let row = sqlx::query(r#"SELECT * FROM "user" WHERE LOWER(email) = LOWER(?)"#)
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
            let verified_int: i64 = if verified { 1 } else { 0 };
            let now_str = format_dt(OffsetDateTime::now_utc());

            let res =
                sqlx::query(r#"UPDATE "user" SET email_verified = ?, updated_at = ? WHERE id = ?"#)
                    .bind(verified_int)
                    .bind(now_str)
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
            let current_row = sqlx::query(r#"SELECT * FROM "user" WHERE id = ?"#)
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
            let now_str = format_dt(now);

            sqlx::query(r#"UPDATE "user" SET name = ?, image = ?, updated_at = ? WHERE id = ?"#)
                .bind(&new_name)
                .bind(&new_image)
                .bind(&now_str)
                .bind(&id)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            Ok(UserRecord {
                id,
                name: new_name,
                email: current.email,
                email_verified: current.email_verified,
                image: new_image,
                created_at: current.created_at,
                updated_at: now,
                role: current.role,
                banned: current.banned,
                ban_reason: current.ban_reason,
                ban_expires: current.ban_expires,
            })
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
            let current_row = sqlx::query(r#"SELECT * FROM "user" WHERE id = ?"#)
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

            let verified_int: i64 = if new_verified { 1 } else { 0 };
            let banned_int: i64 = if new_banned { 1 } else { 0 };
            let ban_exp_str = format_opt_dt(new_ban_expires);
            let now = OffsetDateTime::now_utc();
            let now_str = format_dt(now);

            let res = sqlx::query(
                r#"
                UPDATE "user"
                SET name = ?, email = ?, email_verified = ?, image = ?,
                    role = ?, banned = ?, ban_reason = ?, ban_expires = ?, updated_at = ?
                WHERE id = ?
                "#,
            )
            .bind(&new_name)
            .bind(&new_email)
            .bind(verified_int)
            .bind(&new_image)
            .bind(&new_role)
            .bind(banned_int)
            .bind(&new_ban_reason)
            .bind(&ban_exp_str)
            .bind(&now_str)
            .bind(&id)
            .execute(&pool)
            .await;

            match res {
                Ok(_) => Ok(UserRecord {
                    id,
                    name: new_name,
                    email: new_email,
                    email_verified: new_verified,
                    image: new_image,
                    created_at: current.created_at,
                    updated_at: now,
                    role: new_role,
                    banned: new_banned,
                    ban_reason: new_ban_reason,
                    ban_expires: new_ban_expires,
                }),
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
            let mut count_qb = QueryBuilder::<sqlx::Sqlite>::new(r#"SELECT COUNT(*) FROM "user""#);
            apply_sqlite_user_filters(&mut count_qb, &filter);
            let total: i64 = count_qb
                .build_query_scalar()
                .fetch_one(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let mut qb = QueryBuilder::<sqlx::Sqlite>::new(r#"SELECT * FROM "user""#);
            apply_sqlite_user_filters(&mut qb, &filter);

            let sort_col = match filter.sort_by.as_deref().unwrap_or("createdAt") {
                "name" => "LOWER(name)",
                "email" => "email",
                "role" => "COALESCE(role, 'user')",
                "updatedAt" | "updated_at" => "updated_at",
                _ => "created_at",
            };
            let sort_dir = if filter
                .sort_direction
                .as_deref()
                .map(|d| d.eq_ignore_ascii_case("desc"))
                .unwrap_or(false)
            {
                "DESC"
            } else {
                "ASC"
            };
            qb.push(" ORDER BY ");
            qb.push(sort_col);
            qb.push(" ");
            qb.push(sort_dir);
            qb.push(", id ");
            qb.push(sort_dir);

            if let Some(limit) = filter.limit {
                qb.push(" LIMIT ");
                qb.push_bind(limit as i64);
                if let Some(offset) = filter.offset {
                    qb.push(" OFFSET ");
                    qb.push_bind(offset as i64);
                }
            } else if let Some(offset) = filter.offset {
                qb.push(" LIMIT -1 OFFSET ");
                qb.push_bind(offset as i64);
            }

            let rows = qb
                .build()
                .fetch_all(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let users: Vec<UserRecord> = rows
                .into_iter()
                .map(map_user_row)
                .collect::<Result<Vec<_>, _>>()?;

            Ok((users, total as usize))
        })
    }

    fn delete_user(&self, id: &str) -> BoxFuture<'static, Result<(), AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            sqlx::query(r#"DELETE FROM "account" WHERE user_id = ?"#)
                .bind(&id)
                .execute(&mut *tx)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            sqlx::query(r#"DELETE FROM "session" WHERE user_id = ?"#)
                .bind(&id)
                .execute(&mut *tx)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            sqlx::query(r#"DELETE FROM "user" WHERE id = ?"#)
                .bind(&id)
                .execute(&mut *tx)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            tx.commit()
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
            let now_str = format_dt(now);
            let access_exp = format_opt_dt(input.access_token_expires_at);
            let refresh_exp = format_opt_dt(input.refresh_token_expires_at);

            let res = sqlx::query(
                r#"
                INSERT INTO "account" (
                    id, user_id, account_id, provider_id, access_token, refresh_token,
                    id_token, access_token_expires_at, refresh_token_expires_at, scope, password,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&input.user_id)
            .bind(&input.account_id)
            .bind(&input.provider_id)
            .bind(&input.access_token)
            .bind(&input.refresh_token)
            .bind(&input.id_token)
            .bind(access_exp)
            .bind(refresh_exp)
            .bind(&input.scope)
            .bind(&input.password)
            .bind(&now_str)
            .bind(&now_str)
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
            let row =
                sqlx::query(r#"SELECT * FROM "account" WHERE provider_id = ? AND account_id = ?"#)
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
            let rows = sqlx::query(r#"SELECT * FROM "account" WHERE user_id = ?"#)
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
            let now_str = format_dt(OffsetDateTime::now_utc());
            let res = sqlx::query(
                r#"
                UPDATE "account" SET password = ?, updated_at = ?
                WHERE user_id = ? AND provider_id = 'credential'
                "#,
            )
            .bind(password_hash)
            .bind(now_str)
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
            let now_str = format_dt(OffsetDateTime::now_utc());
            let access_exp = format_opt_dt(access_token_expires_at);
            let res = sqlx::query(
                r#"
                UPDATE "account"
                SET access_token = ?,
                    refresh_token = COALESCE(?, refresh_token),
                    id_token = COALESCE(?, id_token),
                    access_token_expires_at = ?,
                    scope = COALESCE(?, scope),
                    updated_at = ?
                WHERE provider_id = ? AND account_id = ?
                "#,
            )
            .bind(access_token)
            .bind(refresh_token)
            .bind(id_token)
            .bind(access_exp)
            .bind(scope)
            .bind(now_str)
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
            sqlx::query(r#"DELETE FROM "account" WHERE provider_id = ? AND account_id = ?"#)
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
            let now_str = format_dt(now);
            let expires_str = format_dt(input.expires_at);

            let res = sqlx::query(
                r#"
                INSERT INTO "session" (id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&input.user_id)
            .bind(&input.token)
            .bind(&expires_str)
            .bind(&input.ip_address)
            .bind(&input.user_agent)
            .bind(&now_str)
            .bind(&now_str)
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
            let now_str = format_dt(now);
            let expires_str = format_dt(input.expires_at);

            let res = sqlx::query(
                r#"
                INSERT INTO "session" (id, user_id, token, expires_at, ip_address, user_agent, impersonated_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&input.user_id)
            .bind(&input.token)
            .bind(&expires_str)
            .bind(&input.ip_address)
            .bind(&input.user_agent)
            .bind(&impersonated_by)
            .bind(&now_str)
            .bind(&now_str)
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
            let row = sqlx::query(r#"SELECT * FROM "session" WHERE token = ?"#)
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
            let now_str = format_dt(OffsetDateTime::now_utc());
            let rows = sqlx::query(
                r#"SELECT * FROM "session" WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC"#,
            )
            .bind(user_id)
            .bind(now_str)
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
            let expires_str = format_dt(expires_at);
            let now_str = format_dt(OffsetDateTime::now_utc());

            let res = sqlx::query(
                r#"UPDATE "session" SET expires_at = ?, updated_at = ? WHERE token = ?"#,
            )
            .bind(expires_str)
            .bind(now_str)
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
            sqlx::query(r#"DELETE FROM "session" WHERE token = ?"#)
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
            sqlx::query(r#"DELETE FROM "session" WHERE user_id = ?"#)
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
            sqlx::query(r#"DELETE FROM "session" WHERE user_id = ? AND token != ?"#)
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
            let now_str = format_dt(OffsetDateTime::now_utc());
            let res = sqlx::query(r#"DELETE FROM "session" WHERE expires_at <= ?"#)
                .bind(now_str)
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
            let now_str = format_dt(now);
            let expires_str = format_dt(input.expires_at);

            sqlx::query(
                r#"
                INSERT INTO "verification" (id, identifier, value, expires_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&id)
            .bind(&input.identifier)
            .bind(&input.value)
            .bind(&expires_str)
            .bind(&now_str)
            .bind(&now_str)
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
            let row = sqlx::query(r#"SELECT * FROM "verification" WHERE identifier = ?"#)
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
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let row = sqlx::query(r#"SELECT * FROM "verification" WHERE identifier = ?"#)
                .bind(&identifier)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            if let Some(r) = row {
                let record = map_verification_row(r)?;
                sqlx::query(r#"DELETE FROM "verification" WHERE identifier = ?"#)
                    .bind(&identifier)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| AdapterError::Query(e.to_string()))?;

                tx.commit()
                    .await
                    .map_err(|e| AdapterError::Query(e.to_string()))?;

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
            sqlx::query(r#"DELETE FROM "verification" WHERE identifier = ?"#)
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
            let now_str = format_dt(OffsetDateTime::now_utc());
            let res = sqlx::query(r#"DELETE FROM "verification" WHERE expires_at <= ?"#)
                .bind(now_str)
                .execute(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;
            Ok(res.rows_affected() as usize)
        })
    }
}
