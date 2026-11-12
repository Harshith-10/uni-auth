# uni-auth

[![Rust Version](https://img.shields.io/badge/rust-1.99.1%2B%20(2024%20edition)-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Axum](https://img.shields.io/badge/axum-0.8-purple.svg)](https://github.com/tokio-rs/axum)
[![SQLx](https://img.shields.io/badge/sqlx-0.8-blue.svg)](https://github.com/launchbadge/sqlx)

A modular, high-performance, cross-platform authentication engine and toolkit for Rust.

**uni-auth** combines a headless authentication core with production-ready database adapters, Axum HTTP routes, and a cross-platform client SDK. It is designed to provide full wire-protocol interoperability with modern TypeScript/JavaScript web clients (including Better Auth clients) while delivering an extensible, native Rust authentication ecosystem.

---

## Highlights

- **Modular Workspace Architecture**: Decoupled crates separating protocol DTOs, domain logic, database persistence, HTTP routing, and client SDKs.
- **Wire & Protocol Interoperability**: Compatible with standard camelCase JSON endpoints, cookie signing schemes, bearer tokens, OAuth2 redirect/loopback flows, and RFC 7807 problem details.
- **Robust Cryptography**: Argon2id password hashing with seamless on-the-fly migration from legacy Scrypt hashes; HKDF-SHA256 key derivation and HMAC-SHA256 signature verification.
- **Multi-Backend SQLx Adapters**: Automated DDL migrations and parameterized queries for SQLite and PostgreSQL, with configurable column naming conventions (`snake_case` or `camelCase`).
- **Pluggable Architecture & Lifecycle Hooks**: Extensible `AuthPlugin` trait with endpoint interceptors, rate limiting, dynamic route registration, and `DatabaseHooks` for user and session lifecycle events.
- **Full-Featured Admin & RBAC**: Role-based access control, user provisioning, ban/unban with expiration, and admin session impersonation.
- **Social OAuth 2.0**: Built-in Google and GitHub OAuth providers with PKCE, state hygiene, and loopback listener support for desktop clients.
- **Cross-Platform Native Client**: Dedicated client library (`auth-client`) with reactive session state (`AuthStore`), loopback OAuth listeners, and secure OS Keychain token persistence (`keyring` for macOS Keychain, Windows Credential Manager, and Linux Secret Service).

---

## Workspace Architecture

```
uni-auth/
├── crates/
│   ├── auth-proto      # Shared wire DTOs, camelCase serde models, and error envelopes
│   ├── auth-core       # Headless domain engine: hashing, sessions, RBAC, plugins, and hooks
│   ├── auth-sqlx       # SQLite and PostgreSQL adapters with migrations and naming strategies
│   ├── auth-axum       # Axum 0.8 HTTP routes (/api/auth/*), middleware, extractors, and CORS
│   └── auth-client     # Native client SDK with OS keychain storage and loopback OAuth
├── examples/
│   ├── server          # Standalone Axum backend server with demo SaaS endpoints
│   ├── web-react       # React + Vite client illustrating browser cookie authentication
│   └── desktop-gpui    # Native desktop GUI built with GPUI and OS Keychain storage
└── tests/              # Parity and cross-platform integration test suites
```

### Crate Breakdown

| Crate | Description |
|---|---|
| [`auth-proto`](crates/auth-proto) | Wire models and request/response envelopes conforming to camelCase JSON conventions. Defines `UserWire`, `SessionWire`, `AccountWire`, and typed error envelopes. |
| [`auth-core`](crates/auth-core) | Pure headless domain engine. Encapsulates `AuthService`, `AuthAdapter` trait, cryptographic token signing (`crypto`), password hashing (`Argon2id` + legacy `Scrypt`), plugin system (`AuthPlugin`), and database lifecycle hooks (`DatabaseHooks`). |
| [`auth-sqlx`](crates/auth-sqlx) | Production database adapters built on SQLx 0.8 for SQLite (`SqliteAuthAdapter`) and PostgreSQL (`PostgresAuthAdapter`). Includes embedded schema migrations and configurable `NamingConvention`. |
| [`auth-axum`](crates/auth-axum) | Axum 0.8 integration providing `/api/auth/*` routes, session extractors (`CurrentSession`, `FreshSession`), CSRF protection, rate limiting, and cookie handling. |
| [`auth-client`](crates/auth-client) | Native client SDK (`AuthClient`) featuring pluggable token storage, OS Keychain persistence (`KeyringTokenStorage`), reactive session events (`AuthStore`), and desktop loopback OAuth listeners. |

---

## Getting Started

### Prerequisites

- **Rust**: 1.99.1 or higher (Rust 2024 edition)
- **Node.js & pnpm**: Optional, required for running the `examples/web-react` client

### 1. Environment Configuration

Copy the example environment file to `.env`:

```bash
cp .env.example .env
```

Configure the following variables in `.env`:

```env
PORT=3000
AUTH_BASE_URL=http://localhost:3000/api/auth
UNI_AUTH_SECRET=your-32-character-or-longer-secret-key-here
DATABASE_URL=sqlite::memory:

# Optional: OAuth 2.0 Credentials
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

### 2. Running the Server

Start the backend Axum server with in-memory SQLite storage and pre-seeded demo accounts:

```bash
cargo run -p uni-auth-server
```

The server listens on `http://127.0.0.1:3000` and seeds the following demo users:
- **Admin**: `admin@example.com` / `admin12345` (role: `admin`)
- **User (Verified)**: `alice@example.com` / `password123` (role: `user`)
- **User (Unverified)**: `bob@example.com` / `password123` (role: `user`)
- **User (Banned)**: `banned@example.com` / `password123` (role: `user`)

### 3. Running the React Web Client

Navigate to the React example and start the Vite dev server:

```bash
cd examples/web-react
pnpm install
pnpm dev
```

Open `http://localhost:5173` to test cookie-based authentication, admin console features, and protected API diagnostics against the Axum server.

### 4. Running the Native Desktop Client (GPUI)

Launch the cross-platform native desktop application:

```bash
cargo run -p desktop-gpui
```

The desktop app demonstrates:
- Bearer token authentication stored securely in your operating system's keychain.
- Loopback OAuth2 authentication opening your default web browser and capturing callback redirects locally.
- Reactive state updates and admin management via GPUI components.

---

## Usage Guide

### Setting Up the Server (`auth-axum` & `auth-core`)

```rust
use std::sync::Arc;
use time::Duration;
use tokio::net::TcpListener;
use axum::Router;
use auth_axum::{AuthState, auth_routes_with_plugins, build_auth_cors_layer};
use auth_core::{AuthConfig, AuthService};
use auth_sqlx::SqliteAuthAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize database adapter
    let adapter = Arc::new(SqliteAuthAdapter::new_in_memory().await?);

    // 2. Configure auth service
    let config = AuthConfig {
        secret: b"your-32-character-or-longer-secret-key-here".to_vec(),
        base_url: "http://localhost:3000/api/auth".to_string(),
        session_expires_in: Duration::days(7),
        ott_expires_in: Duration::minutes(5),
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
    let auth_state = AuthState::new(service);

    // 3. Build Axum router with CORS and auth endpoints
    let cors = build_auth_cors_layer(&["http://localhost:5173"]);
    let app = Router::new()
        .nest("/api/auth", auth_routes_with_plugins(&auth_state))
        .layer(cors)
        .with_state(auth_state);

    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

### Protecting Axum Endpoints

```rust
use axum::response::{IntoResponse, Response};
use axum::Json;
use auth_axum::CurrentSession;

async fn protected_profile(session: CurrentSession) -> Response {
    Json(serde_json::json!({
        "status": "authenticated",
        "user": session.user,
        "is_bearer": session.is_bearer
    }))
    .into_response()
}
```

### Using the Native Client SDK (`auth-client`)

```rust
use std::sync::Arc;
use auth_client::{AuthClient, AuthStore, KeyringTokenStorage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize OS Keychain storage
    let storage = Arc::new(KeyringTokenStorage::new(
        "com.my-app.desktop",
        "session_token",
    ));

    // 2. Instantiate client and reactive store
    let client = Arc::new(AuthClient::new("http://localhost:3000/api/auth", storage));
    let store = AuthStore::new(client.clone());

    // 3. Sign in with email and password
    let session = client.sign_in_email("alice@example.com", "password123").await?;
    println!("Signed in as: {}", session.user.name);

    // Tokens are automatically persisted to the OS Keychain and session signals notify subscribers
    Ok(())
}
```

---

## Security & Cryptography

- **Password Hashing**: Passwords are hashed using **Argon2id** with secure random salts. Legacy Scrypt password hashes are automatically verified and upgraded to Argon2id upon valid login.
- **Session Tokens**: Cryptographically random UUID v7 session tokens with sliding-window expiration.
- **Token Signing**: Signed cookies and tokens use **HKDF-SHA256** for key derivation combined with **HMAC-SHA256** signatures to prevent tampering.
- **CSRF & Origin Verification**: Built-in middleware verifies request origins against trusted domain lists, supporting wildcard port matching for desktop loopback callbacks.
- **Key Storage**: Desktop tokens are securely held in operating-system-level secure enclaves via [`keyring`](https://crates.io/crates/keyring), ensuring tokens never touch disk in plain text.

---

## Testing

Run the Rust test suite across all workspace crates:

```bash
cargo test --all
```

Run the Node.js protocol compatibility verification test:

```bash
node tests/node_compat_test.mjs
```

---

## License

This project is dual-licensed under either:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
