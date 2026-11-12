//! # auth-axum
//!
//! Axum HTTP router and dual Cookie/Bearer middleware for authentication.
//!
//! - `auth_router(state: AuthState)`: Full router of auth endpoints mounted at `/api/auth`.
//! - `CurrentSession`, `FreshSession` & `OptionalSession`: Transparent extractors for both Web (Cookie) and Desktop (Bearer).
//! - `build_auth_cors_layer()`: Preconfigured CORS layer exposing `set-auth-token`.

pub mod cookies;
pub mod cors;
pub mod error;
pub mod extract;
pub mod middleware;
pub mod oauth;
pub mod plugin;
pub mod routes;
pub mod state;

pub use cors::build_auth_cors_layer;
pub use error::*;
pub use extract::{
    CurrentSession, ExtractedMeta, FreshSession, IpCidr, OptionalSession, extract_client_ip,
    extract_request_meta, extract_request_meta_with_peer, extract_token_from_headers,
};
pub use middleware::{csrf_origin_middleware, is_loopback_url, validate_callback_url, verify_trusted_origin};
pub use oauth::ReqwestOAuthClient;
pub use plugin::{AxumAuthPlugin, AxumPluginRouteAdapter, RouteDescriptor, check_endpoint_conflicts};
pub use routes::{auth_router, auth_routes, auth_routes_with_plugins};
pub use state::{AuthState, OAuthProviderConfig};
