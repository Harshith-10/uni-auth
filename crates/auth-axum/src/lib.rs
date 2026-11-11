//! # auth-axum
//!
//! Axum HTTP router and dual Cookie/Bearer middleware achieving wire-level compatibility
//! with the Better Auth TypeScript framework.
//!
//! - `auth_router(state: AuthState)`: Full router of Better Auth v1 endpoints mounted at `/api/auth`.
//! - `CurrentSession`, `FreshSession` & `OptionalSession`: Transparent extractors for both Web (Cookie) and Desktop (Bearer).
//! - `build_auth_cors_layer()`: Preconfigured CORS layer exposing `set-auth-token`.

pub mod cookies;
pub mod cors;
pub mod error;
pub mod extract;
pub mod middleware;
pub mod plugin;
pub mod routes;
pub mod state;

pub use cors::build_auth_cors_layer;
pub use error::*;
pub use extract::{
    CurrentSession, FreshSession, OptionalSession, extract_request_meta, extract_token_from_headers,
};
pub use middleware::verify_trusted_origin;
pub use plugin::{AxumAuthPlugin, RouteDescriptor, check_endpoint_conflicts};
pub use routes::{auth_router, auth_routes, auth_routes_with_plugins};
pub use state::{AuthState, OAuthProviderConfig};
