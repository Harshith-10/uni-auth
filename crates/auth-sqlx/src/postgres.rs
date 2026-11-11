//! PostgreSQL implementation of `AuthAdapter`.

use sqlx::postgres::{PgPool, PgRow};
use sqlx::{QueryBuilder, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use auth_core::adapter::{AuthAdapter, BoxFuture};
use auth_core::error::AdapterError;
use auth_core::models::{
    AccountRecord, AdminListUsersFilter, CreateAccountInput, CreateSessionInput, CreateUserInput,
    CreateVerificationInput, FieldUpdate, SessionRecord, UpdateUserFields, UserRecord,
    VerificationRecord,
};
use auth_core::plugin::PluginMigration;

use crate::naming::NamingConvention;

const POSTGRES_SCHEMA: &str = include_str!("../migrations/postgres.sql");

fn map_user_row(row: PgRow) -> Result<UserRecord, AdapterError> {
    let email_verified: bool = row
        .try_get("email_verified")
        .or_else(|_| row.try_get("emailVerified"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let created_at = row
        .try_get("created_at")
        .or_else(|_| row.try_get("createdAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at = row
        .try_get("updated_at")
        .or_else(|_| row.try_get("updatedAt"))
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
        email_verified,
        image: row
            .try_get("image")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at,
        updated_at,
        role: row.try_get("role").ok().flatten(),
        banned: row.try_get("banned").unwrap_or(false),
        ban_reason: row
            .try_get("ban_reason")
            .ok()
            .or_else(|| row.try_get("banReason").ok())
            .flatten(),
        ban_expires: row
            .try_get("ban_expires")
            .ok()
            .or_else(|| row.try_get("banExpires").ok())
            .flatten(),
    })
}

fn map_session_row(row: PgRow) -> Result<SessionRecord, AdapterError> {
    let user_id: String = row
        .try_get("user_id")
        .or_else(|_| row.try_get("userId"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let expires_at = row
        .try_get("expires_at")
        .or_else(|_| row.try_get("expiresAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let ip_address: Option<String> = row
        .try_get("ip_address")
        .ok()
        .or_else(|| row.try_get("ipAddress").ok())
        .flatten();
    let user_agent: Option<String> = row
        .try_get("user_agent")
        .ok()
        .or_else(|| row.try_get("userAgent").ok())
        .flatten();
    let created_at = row
        .try_get("created_at")
        .or_else(|_| row.try_get("createdAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at = row
        .try_get("updated_at")
        .or_else(|_| row.try_get("updatedAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;

    Ok(SessionRecord {
        id: row
            .try_get("id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        user_id,
        token: row
            .try_get("token")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        expires_at,
        ip_address,
        user_agent,
        created_at,
        updated_at,
        impersonated_by: row
            .try_get("impersonated_by")
            .ok()
            .or_else(|| row.try_get("impersonatedBy").ok())
            .flatten(),
    })
}

fn map_account_row(row: PgRow) -> Result<AccountRecord, AdapterError> {
    let user_id: String = row
        .try_get("user_id")
        .or_else(|_| row.try_get("userId"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let account_id: String = row
        .try_get("account_id")
        .or_else(|_| row.try_get("accountId"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let provider_id: String = row
        .try_get("provider_id")
        .or_else(|_| row.try_get("providerId"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let access_token: Option<String> = row
        .try_get("access_token")
        .ok()
        .or_else(|| row.try_get("accessToken").ok())
        .flatten();
    let refresh_token: Option<String> = row
        .try_get("refresh_token")
        .ok()
        .or_else(|| row.try_get("refreshToken").ok())
        .flatten();
    let id_token: Option<String> = row
        .try_get("id_token")
        .ok()
        .or_else(|| row.try_get("idToken").ok())
        .flatten();
    let access_token_expires_at = row
        .try_get("access_token_expires_at")
        .ok()
        .or_else(|| row.try_get("accessTokenExpiresAt").ok())
        .flatten();
    let refresh_token_expires_at = row
        .try_get("refresh_token_expires_at")
        .ok()
        .or_else(|| row.try_get("refreshTokenExpiresAt").ok())
        .flatten();
    let created_at = row
        .try_get("created_at")
        .or_else(|_| row.try_get("createdAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at = row
        .try_get("updated_at")
        .or_else(|_| row.try_get("updatedAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;

    Ok(AccountRecord {
        id: row
            .try_get("id")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        user_id,
        account_id,
        provider_id,
        access_token,
        refresh_token,
        id_token,
        access_token_expires_at,
        refresh_token_expires_at,
        scope: row
            .try_get("scope")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        password: row
            .try_get("password")
            .map_err(|e| AdapterError::Query(e.to_string()))?,
        created_at,
        updated_at,
    })
}

fn map_verification_row(row: PgRow) -> Result<VerificationRecord, AdapterError> {
    let expires_at = row
        .try_get("expires_at")
        .or_else(|_| row.try_get("expiresAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let created_at = row
        .try_get("created_at")
        .or_else(|_| row.try_get("createdAt"))
        .map_err(|e| AdapterError::Query(e.to_string()))?;
    let updated_at = row
        .try_get("updated_at")
        .or_else(|_| row.try_get("updatedAt"))
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
        expires_at,
        created_at,
        updated_at,
    })
}

/// PostgreSQL-backed implementation of `AuthAdapter`.
#[derive(Clone)]
pub struct PostgresAuthAdapter {
    pool: PgPool,
    naming: NamingConvention,
}

impl PostgresAuthAdapter {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            naming: NamingConvention::SnakeCase,
        }
    }

    pub fn with_naming_convention(mut self, naming: NamingConvention) -> Self {
        self.naming = naming;
        self
    }

    pub fn naming_convention(&self) -> NamingConvention {
        self.naming
    }

    /// Executes the embedded Better Auth schema migration.
    pub async fn run_migrations(&self) -> Result<(), sqlx::Error> {
        sqlx::raw_sql(POSTGRES_SCHEMA).execute(&self.pool).await?;
        Ok(())
    }

    /// Executes declarative Admin plugin migrations adding role, ban, and impersonation columns.
    pub async fn run_admin_migrations(&self) -> Result<(), sqlx::Error> {
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

    /// Applies declarative DDL migrations for all registered plugins.
    pub async fn run_plugin_migrations(
        &self,
        migrations: &[PluginMigration],
    ) -> Result<(), AdapterError> {
        for migration in migrations {
            for stmt in migration.postgres_ddl {
                sqlx::query(stmt).execute(&self.pool).await.map_err(|e| {
                    AdapterError::Query(format!(
                        "Plugin '{}' migration failed: {e}",
                        migration.plugin_id
                    ))
                })?;
            }
        }
        Ok(())
    }
}

fn escape_like(s: &str) -> String {
    s.to_lowercase()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn apply_postgres_user_filters(
    qb: &mut QueryBuilder<'_, sqlx::Postgres>,
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
            let escaped = escape_like(sv);
            let pattern = match filter.search_operator.as_deref().unwrap_or("contains") {
                "starts_with" => format!("{escaped}%"),
                "ends_with" => format!("%{escaped}"),
                _ => format!("%{escaped}%"),
            };
            qb.push(" WHERE ");
            has_where = true;
            qb.push(col);
            qb.push(" LIKE ");
            qb.push_bind(pattern);
            qb.push(" ESCAPE '\\'");
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
                let banned_bool: bool = needle == "true" || needle == "1";
                if op == "ne" {
                    qb.push("banned != ");
                } else {
                    qb.push("banned = ");
                }
                qb.push_bind(banned_bool);
            }
            "emailVerified" | "email_verified" => {
                let ver_bool: bool = needle == "true" || needle == "1";
                if op == "ne" {
                    qb.push("email_verified != ");
                } else {
                    qb.push("email_verified = ");
                }
                qb.push_bind(ver_bool);
            }
            "name" => {
                let col = "LOWER(name)";
                let escaped = escape_like(&needle);
                match op {
                    "ne" => {
                        qb.push(col).push(" != ").push_bind(needle);
                    }
                    "contains" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("%{escaped}%"))
                            .push(" ESCAPE '\\'");
                    }
                    "starts_with" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("{escaped}%"))
                            .push(" ESCAPE '\\'");
                    }
                    "ends_with" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("%{escaped}"))
                            .push(" ESCAPE '\\'");
                    }
                    _ => {
                        qb.push(col).push(" = ").push_bind(needle);
                    }
                }
            }
            "role" => {
                let col = "LOWER(COALESCE(role, 'user'))";
                let escaped = escape_like(&needle);
                match op {
                    "ne" => {
                        qb.push(col).push(" != ").push_bind(needle);
                    }
                    "contains" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("%{escaped}%"))
                            .push(" ESCAPE '\\'");
                    }
                    "starts_with" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("{escaped}%"))
                            .push(" ESCAPE '\\'");
                    }
                    "ends_with" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("%{escaped}"))
                            .push(" ESCAPE '\\'");
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
                let escaped = escape_like(&needle);
                match op {
                    "ne" => {
                        qb.push(col).push(" != ").push_bind(needle);
                    }
                    "contains" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("%{escaped}%"))
                            .push(" ESCAPE '\\'");
                    }
                    "starts_with" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("{escaped}%"))
                            .push(" ESCAPE '\\'");
                    }
                    "ends_with" => {
                        qb.push(col)
                            .push(" LIKE ")
                            .push_bind(format!("%{escaped}"))
                            .push(" ESCAPE '\\'");
                    }
                    _ => {
                        qb.push(col).push(" = ").push_bind(needle);
                    }
                }
            }
        }
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
            let role = input.role.unwrap_or_else(|| "user".to_string());

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
            .bind(&role)
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

    fn create_user_with_account(
        &self,
        user_input: CreateUserInput,
        mut account_input: CreateAccountInput,
    ) -> BoxFuture<'static, Result<(UserRecord, AccountRecord), AdapterError>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let mut tx = pool
                .begin()
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let id = user_input.id.unwrap_or_else(|| Uuid::now_v7().to_string());
            let email = user_input.email.to_lowercase();
            let now = OffsetDateTime::now_utc();
            let role = user_input.role.unwrap_or_else(|| "user".to_string());

            let user_res = sqlx::query(
                r#"
                INSERT INTO "user" (id, name, email, email_verified, image, role, banned, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, $8)
                "#,
            )
            .bind(&id)
            .bind(&user_input.name)
            .bind(&email)
            .bind(user_input.email_verified)
            .bind(&user_input.image)
            .bind(&role)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await;

            if let Err(sqlx::Error::Database(e)) = &user_res {
                if e.is_unique_violation() {
                    return Err(AdapterError::UniqueViolation(e.message().to_string()));
                }
            }
            user_res.map_err(|e| AdapterError::Query(e.to_string()))?;

            if account_input.user_id.is_empty() {
                account_input.user_id = id.clone();
            }
            if account_input.account_id.is_empty() {
                account_input.account_id = id.clone();
            }

            let acc_id = account_input
                .id
                .unwrap_or_else(|| Uuid::now_v7().to_string());
            let acc_res = sqlx::query(
                r#"
                INSERT INTO "account" (
                    id, user_id, account_id, provider_id, access_token, refresh_token,
                    id_token, access_token_expires_at, refresh_token_expires_at, scope,
                    password, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
            )
            .bind(&acc_id)
            .bind(&account_input.user_id)
            .bind(&account_input.account_id)
            .bind(&account_input.provider_id)
            .bind(&account_input.access_token)
            .bind(&account_input.refresh_token)
            .bind(&account_input.id_token)
            .bind(account_input.access_token_expires_at)
            .bind(account_input.refresh_token_expires_at)
            .bind(&account_input.scope)
            .bind(&account_input.password)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await;

            if let Err(sqlx::Error::Database(e)) = &acc_res {
                if e.is_unique_violation() {
                    return Err(AdapterError::UniqueViolation(e.message().to_string()));
                }
            }
            acc_res.map_err(|e| AdapterError::Query(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let user = UserRecord {
                id,
                name: user_input.name,
                email,
                email_verified: user_input.email_verified,
                image: user_input.image,
                created_at: now,
                updated_at: now,
                role: Some(role),
                banned: false,
                ban_reason: None,
                ban_expires: None,
            };

            let account = AccountRecord {
                id: acc_id,
                user_id: account_input.user_id,
                account_id: account_input.account_id,
                provider_id: account_input.provider_id,
                access_token: account_input.access_token,
                refresh_token: account_input.refresh_token,
                id_token: account_input.id_token,
                access_token_expires_at: account_input.access_token_expires_at,
                refresh_token_expires_at: account_input.refresh_token_expires_at,
                scope: account_input.scope,
                password: account_input.password,
                created_at: now,
                updated_at: now,
            };

            Ok((user, account))
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

    fn update_user(
        &self,
        id: &str,
        fields: UpdateUserFields,
    ) -> BoxFuture<'static, Result<UserRecord, AdapterError>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        Box::pin(async move {
            let now = OffsetDateTime::now_utc();

            let mut qb = QueryBuilder::<sqlx::Postgres>::new(r#"UPDATE "user" SET "#);
            let mut separated = qb.separated(", ");

            if let Some(ref name) = fields.name {
                separated.push("name = ");
                separated.push_bind_unseparated(name);
            }
            if let Some(ref email) = fields.email {
                separated.push("email = ");
                separated.push_bind_unseparated(email.to_lowercase());
            }
            if let Some(verified) = fields.email_verified {
                separated.push("email_verified = ");
                separated.push_bind_unseparated(verified);
            }
            match fields.image {
                FieldUpdate::Set(ref img) if !img.is_empty() => {
                    separated.push("image = ");
                    separated.push_bind_unseparated(img);
                }
                FieldUpdate::Clear => {
                    separated.push("image = NULL");
                }
                _ => {}
            }
            if let Some(ref role) = fields.role {
                separated.push("role = ");
                separated.push_bind_unseparated(role);
            }
            if let Some(banned) = fields.banned {
                separated.push("banned = ");
                separated.push_bind_unseparated(banned);
            }
            match fields.ban_reason {
                FieldUpdate::Set(ref reason) => {
                    separated.push("ban_reason = ");
                    separated.push_bind_unseparated(reason);
                }
                FieldUpdate::Clear => {
                    separated.push("ban_reason = NULL");
                }
                FieldUpdate::Unchanged => {}
            }
            match fields.ban_expires {
                FieldUpdate::Set(exp) => {
                    separated.push("ban_expires = ");
                    separated.push_bind_unseparated(exp);
                }
                FieldUpdate::Clear => {
                    separated.push("ban_expires = NULL");
                }
                FieldUpdate::Unchanged => {}
            }

            separated.push("updated_at = ");
            separated.push_bind_unseparated(now);

            qb.push(r#" WHERE id = "#);
            qb.push_bind(&id);
            qb.push(r#" RETURNING *"#);

            let res = qb.build().fetch_optional(&pool).await;
            match res {
                Ok(Some(row)) => map_user_row(row),
                Ok(None) => Err(AdapterError::NotFound),
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
            let mut count_qb =
                QueryBuilder::<sqlx::Postgres>::new(r#"SELECT COUNT(*) FROM "user""#);
            apply_postgres_user_filters(&mut count_qb, &filter);
            let total: i64 = count_qb
                .build_query_scalar()
                .fetch_one(&pool)
                .await
                .map_err(|e| AdapterError::Query(e.to_string()))?;

            let mut qb = QueryBuilder::<sqlx::Postgres>::new(r#"SELECT * FROM "user""#);
            apply_postgres_user_filters(&mut qb, &filter);

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
            }
            if let Some(offset) = filter.offset {
                qb.push(" OFFSET ");
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
            sqlx::query(r#"DELETE FROM "user" WHERE id = $1"#)
                .bind(id)
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
            let row =
                sqlx::query(r#"DELETE FROM "verification" WHERE identifier = $1 RETURNING *"#)
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
