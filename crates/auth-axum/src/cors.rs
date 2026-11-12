//! Preconfigured CORS layer helper for web and native clients.
//!
//! Exposes `set-auth-token`, `set-admin-auth-token`, and `set-ott` in `Access-Control-Expose-Headers`
//! and allows credentials for seamless web and desktop cross-origin requests.

use axum::http::{HeaderName, HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Builds a CORS layer configured for auth client compatibility.
///
/// # Arguments
/// - `allowed_origins`: Optional list of explicit origin strings (e.g. `["http://localhost:5173"]`).
///   If empty, allows any origin.
pub fn build_auth_cors_layer(allowed_origins: &[&str]) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::COOKIE,
            header::ACCEPT,
            header::ORIGIN,
            HeaderName::from_static("x-admin-auth-token"),
        ])
        .expose_headers([
            HeaderName::from_static("set-auth-token"),
            HeaderName::from_static("set-admin-auth-token"),
            HeaderName::from_static("set-ott"),
            header::SET_COOKIE,
        ]);

    if allowed_origins.is_empty() {
        layer = layer.allow_origin(tower_http::cors::Any);
    } else {
        let origins: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        layer = layer
            .allow_origin(AllowOrigin::list(origins))
            .allow_credentials(true);
    }

    layer
}
