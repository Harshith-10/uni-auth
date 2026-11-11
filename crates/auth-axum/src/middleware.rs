//! Security middleware utilities for CSRF Origin validation and rate limiting.

use auth_core::AuthError;
use axum::http::HeaderMap;

/// Validates the `Origin` (or `Referer`) header against a list of trusted origins.
///
/// - If `trusted_origins` is empty, origin validation is disabled (`Ok(())`).
/// - Requests without an `Origin` header (e.g. native desktop Bearer requests) are permitted.
/// - Browser requests carrying an `Origin` header must match one of the configured `trusted_origins`.
pub fn verify_trusted_origin(
    headers: &HeaderMap,
    trusted_origins: &[String],
) -> Result<(), AuthError> {
    if trusted_origins.is_empty() {
        return Ok(());
    }

    if let Some(origin_val) = headers.get(axum::http::header::ORIGIN) {
        let origin_str = origin_val
            .to_str()
            .map_err(|_| AuthError::InvalidOrigin)?
            .trim()
            .trim_end_matches('/');

        let allowed = trusted_origins.iter().any(|trusted| {
            trusted
                .trim()
                .trim_end_matches('/')
                .eq_ignore_ascii_case(origin_str)
        });

        if !allowed {
            return Err(AuthError::InvalidOrigin);
        }
    }

    Ok(())
}
