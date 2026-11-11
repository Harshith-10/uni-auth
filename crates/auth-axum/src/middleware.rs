//! Security middleware utilities for CSRF Origin validation and rate limiting.

use auth_core::AuthError;
use auth_proto::error_codes;
use axum::http::HeaderMap;

/// Validates that a callback URL is either a relative path (`/dashboard`)
/// or starts with one of the configured `trusted_origins` (when `trusted_origins` is non-empty).
pub fn validate_callback_url(url: &str, trusted_origins: &[String]) -> Result<(), AuthError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    // Relative paths starting with a single '/' (not protocol-relative '//') are always safe
    if trimmed.starts_with('/') && !trimmed.starts_with("//") {
        return Ok(());
    }
    if trusted_origins.is_empty() {
        return Ok(());
    }
    let allowed = trusted_origins.iter().any(|trusted| {
        let base = trusted.trim().trim_end_matches('/');
        trimmed.len() >= base.len()
            && trimmed[..base.len()].eq_ignore_ascii_case(base)
            && (trimmed.len() == base.len()
                || matches!(trimmed.as_bytes()[base.len()], b'/' | b'?' | b'#'))
    });
    if !allowed {
        return Err(AuthError::forbidden(
            error_codes::INVALID_CALLBACK_URL,
            "Invalid callbackURL",
        ));
    }
    Ok(())
}

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
