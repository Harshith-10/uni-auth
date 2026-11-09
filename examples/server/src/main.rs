//! Example Axum authentication server.
//!
//! Serves Better Auth v1 routes at `/api/auth/*` for both:
//! 1. React Web application (Cookie-based auth)
//! 2. GPUI Native Desktop application (Bearer token + Keychain auth)
//!
//! Also exposes a protected demo SaaS route `GET /api/saas/me`.

use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth_axum::{auth_routes, build_auth_cors_layer, AuthState, CurrentSession};
use auth_core::{AuthConfig, AuthService};
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

    Json(serde_json::json!({
        "status": "authenticated",
        "transport": transport,
        "user": session.user,
        "session": {
            "id": session.session.id,
            "expiresAt": session.session.expires_at,
            "createdAt": session.session.created_at,
        }
    }))
    .into_response()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 1. Initialize SQLite persistence
    let db_path = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());
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
    let secret = std::env::var("UNI_AUTH_SECRET")
        .unwrap_or_else(|_| "uni-auth-super-secret-development-key-32-chars".to_string())
        .into_bytes();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let base_url = format!("http://127.0.0.1:{port}/api/auth");

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
    };

    let service = Arc::new(AuthService::new(config, adapter));
    let auth_state = AuthState::new(Arc::clone(&service));

    // 3. Build Axum App with CORS
    let cors = build_auth_cors_layer(&[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]);

    let app = Router::new()
        .route("/api/saas/me", get(saas_me))
        .nest("/api/auth", auth_routes())
        .layer(cors)
        .with_state(auth_state);

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("🚀 uni-auth server listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
