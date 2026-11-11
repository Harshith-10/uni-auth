//! Example Axum authentication server.
//!
//! Serves Better Auth v1 routes at `/api/auth/*` for both:
//! 1. React Web application (Cookie-based auth)
//! 2. GPUI Native Desktop application (Bearer token + Keychain auth)
//!
//! Seeds demo user accounts on startup (`admin@example.com`, `alice@example.com`,
//! `bob@example.com`, `banned@example.com`) and exposes a protected demo SaaS
//! route `GET /api/saas/me`.

use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth_axum::{
    auth_routes_with_plugins, build_auth_cors_layer, AuthState, CurrentSession, OAuthProviderConfig,
};
use auth_core::{AdminUpdateUserFields, AuthConfig, AuthService};
use auth_proto::{AdminCreateUserRequest, RoleValue, UserWire};
use auth_sqlx::SqliteAuthAdapter;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

/// Protected SaaS endpoint that returns user profile and authentication transport details.
async fn saas_me(session: CurrentSession) -> Response {
    let transport = if session.is_bearer {
        "Bearer (Native Desktop / GPUI Keychain)"
    } else {
        "Cookie (Web Browser / better-auth-client)"
    };

    let expires_at = session
        .session
        .expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let created_at = session
        .session
        .created_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    Json(serde_json::json!({
        "status": "authenticated",
        "transport": transport,
        "user": session.user,
        "session": {
            "id": session.session.id,
            "expiresAt": expires_at,
            "createdAt": created_at,
            "impersonatedBy": session.session.impersonated_by,
        }
    }))
    .into_response()
}

/// Idempotently seeds demo user accounts into the database on startup so
/// developers can immediately sign in and test Admin and standard user flows.
async fn seed_demo_accounts(service: &AuthService) -> Result<(), Box<dyn std::error::Error>> {
    struct SeedAccount {
        name: &'static str,
        email: &'static str,
        password: &'static str,
        role: &'static str,
        email_verified: bool,
        banned: bool,
        ban_reason: Option<&'static str>,
    }

    let accounts = [
        SeedAccount {
            name: "Admin User",
            email: "admin@example.com",
            password: "admin12345",
            role: "admin",
            email_verified: true,
            banned: false,
            ban_reason: None,
        },
        SeedAccount {
            name: "Alice Wonderland",
            email: "alice@example.com",
            password: "password123",
            role: "user",
            email_verified: true,
            banned: false,
            ban_reason: None,
        },
        SeedAccount {
            name: "Bob Builder",
            email: "bob@example.com",
            password: "password123",
            role: "user",
            email_verified: false,
            banned: false,
            ban_reason: None,
        },
        SeedAccount {
            name: "Banned Account",
            email: "banned@example.com",
            password: "password123",
            role: "user",
            email_verified: true,
            banned: true,
            ban_reason: Some("Terms of service violation"),
        },
    ];

    let admin_actor = UserWire {
        id: "seed-admin".to_string(),
        name: "Seed Admin".to_string(),
        email: "seed-admin@system.local".to_string(),
        email_verified: true,
        image: None,
        created_at: time::OffsetDateTime::now_utc(),
        updated_at: time::OffsetDateTime::now_utc(),
        role: Some("admin".to_string()),
        banned: Some(false),
        ban_reason: None,
        ban_expires: None,
    };

    for acct in accounts {
        if service
            .adapter()
            .find_user_by_email(acct.email)
            .await?
            .is_some()
        {
            continue;
        }

        let mut data = serde_json::Map::new();
        data.insert(
            "emailVerified".to_string(),
            serde_json::Value::Bool(acct.email_verified),
        );

        let created = service
            .admin_create_user(
                &admin_actor,
                AdminCreateUserRequest {
                    email: acct.email.to_string(),
                    password: Some(acct.password.to_string()),
                    name: acct.name.to_string(),
                    role: Some(RoleValue::Single(acct.role.to_string())),
                    data: Some(data),
                },
            )
            .await?;

        if acct.banned {
            service
                .adapter()
                .update_user_admin(
                    &created.user.id,
                    AdminUpdateUserFields {
                        banned: Some(true),
                        ban_reason: Some(acct.ban_reason.map(|s| s.to_string())),
                        ..Default::default()
                    },
                )
                .await?;
        }
    }

    tracing::info!("🌱 Seeded demo accounts:");
    tracing::info!("   • Admin:  admin@example.com  / admin12345  (role: admin)");
    tracing::info!("   • User 1: alice@example.com  / password123 (role: user, verified)");
    tracing::info!("   • User 2: bob@example.com    / password123 (role: user, unverified)");
    tracing::info!("   • Banned: banned@example.com / password123 (role: user, banned)");

    Ok(())
}

/// Helper to parse .env from the working directory or workspace root into a HashMap.
fn load_env_map() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let candidates = [".env", "../../.env"];
    for path in candidates {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim().to_string();
                    let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                    map.insert(k, v);
                }
            }
            break;
        }
    }
    map
}

fn get_env(key: &str, env_map: &std::collections::HashMap<String, String>) -> Option<String> {
    std::env::var(key).ok().or_else(|| env_map.get(key).cloned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env_map = load_env_map();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 1. Initialize SQLite persistence
    let db_path =
        get_env("DATABASE_URL", &env_map).unwrap_or_else(|| "sqlite::memory:".to_string());
    tracing::info!("Connecting to SQLite database: {}", db_path);

    let adapter = if db_path == "sqlite::memory:" {
        Arc::new(SqliteAuthAdapter::new_in_memory().await?)
    } else {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&db_path)
            .await?;
        let a = SqliteAuthAdapter::new(pool);
        a.run_migrations().await?;
        Arc::new(a)
    };

    // 2. Configure AuthService
    let secret = get_env("UNI_AUTH_SECRET", &env_map)
        .unwrap_or_else(|| "uni-auth-super-secret-development-key-32-chars".to_string())
        .into_bytes();

    let port: u16 = get_env("PORT", &env_map)
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let base_url = get_env("AUTH_BASE_URL", &env_map)
        .unwrap_or_else(|| format!("http://localhost:{port}/api/auth"));

    let config = AuthConfig {
        secret,
        base_url,
        session_expires_in: Duration::days(7),
        ott_expires_in: Duration::minutes(3),
        reset_password_expires_in: Duration::hours(1),
        verify_email_expires_in: Duration::hours(24),
        auto_sign_in: true,
        require_email_verification: false,
        min_password_length: 8,
        max_password_length: 128,
        delete_user_enabled: true,
        defer_session_refresh: false,
    };

    let service = Arc::new(AuthService::new(config, adapter));

    // Seed demo accounts on startup
    seed_demo_accounts(&service).await?;

    let mut auth_state = AuthState::new(Arc::clone(&service));

    let mut configured_providers = Vec::new();
    if let (Some(client_id), Some(client_secret)) = (
        get_env("GOOGLE_CLIENT_ID", &env_map),
        get_env("GOOGLE_CLIENT_SECRET", &env_map),
    ) {
        let id = client_id.trim();
        let sec = client_secret.trim();
        if !id.is_empty() && !sec.is_empty() {
            auth_state = auth_state.with_oauth_provider(OAuthProviderConfig::google(id, sec));
            configured_providers.push("google");
        }
    }

    if let (Some(client_id), Some(client_secret)) = (
        get_env("GITHUB_CLIENT_ID", &env_map),
        get_env("GITHUB_CLIENT_SECRET", &env_map),
    ) {
        let id = client_id.trim();
        let sec = client_secret.trim();
        if !id.is_empty() && !sec.is_empty() {
            auth_state = auth_state.with_oauth_provider(OAuthProviderConfig::github(id, sec));
            configured_providers.push("github");
        }
    }

    if configured_providers.is_empty() {
        tracing::warn!("⚠️ No OAuth providers configured. Set GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET in .env to enable Google OAuth");
    } else {
        tracing::info!("🔑 OAuth providers registered: {:?}", configured_providers);
    }

    // 3. Build Axum App with CORS
    let cors = build_auth_cors_layer(&[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]);

    let app = Router::new()
        .route("/api/saas/me", get(saas_me))
        .nest("/api/auth", auth_routes_with_plugins(&auth_state))
        .layer(cors)
        .with_state(auth_state);

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("🚀 uni-auth server listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
