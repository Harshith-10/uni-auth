//! # auth-axum
//!
//! Axum HTTP router and dual Cookie/Bearer middleware achieving wire-level compatibility
//! with the Better Auth TypeScript framework.
//!
//! - `auth_router(state: AuthState)`: Full router of Better Auth v1 endpoints mounted at `/api/auth`.
//! - `CurrentSession` & `OptionalSession`: Transparent extractors for both Web (Cookie) and Desktop (Bearer).
//! - `build_auth_cors_layer()`: Preconfigured CORS layer exposing `set-auth-token`.

pub mod cookies;
pub mod cors;
pub mod extract;
pub mod routes;
pub mod state;

pub use cors::build_auth_cors_layer;
pub use extract::{extract_token_from_headers, CurrentSession, OptionalSession};
pub use routes::{auth_router, auth_routes};
pub use state::{AuthState, OAuthProviderConfig};
