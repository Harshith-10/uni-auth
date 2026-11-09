//! Preconfigured CORS layer helper for Better Auth and native clients.
//!
//! Exposes `set-auth-token` and `set-ott` in `Access-Control-Expose-Headers`
//! and allows credentials for seamless web and desktop cross-origin requests.

use axum::http::{header, HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Builds a CORS layer configured specifically for Better Auth client compatibility.
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
        ])
        .expose_headers([
            HeaderName::from_static("set-auth-token"),
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
