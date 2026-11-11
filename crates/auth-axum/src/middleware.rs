//! Security middleware utilities for CSRF Origin validation and rate limiting.

use auth_core::AuthError;
use auth_proto::error_codes;
use axum::http::HeaderMap;

/// Determines if the provided URL targets a local loopback interface (IPv4 127.0.0.1, IPv6 ::1, or localhost).
pub fn is_loopback_url(url_str: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url_str) {
        if parsed.scheme() != "http" {
            return false;
        }
        match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            _ => false,
        }
    } else {
        false
    }
}

/// Validates that a callback URL is either a relative path (`/dashboard`)
/// or starts with one of the configured `trusted_origins` (when `trusted_origins` is non-empty).
/// Supports wildcard loopback port patterns such as `http://127.0.0.1:*` and `http://localhost:*`.
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

    let parsed_candidate = url::Url::parse(trimmed).ok();

    let allowed = trusted_origins.iter().any(|trusted| {
        let base = trusted.trim().trim_end_matches('/');

        // Wildcard port matching: e.g. "http://127.0.0.1:*" or "http://localhost:*"
        if let Some(prefix) = base.strip_suffix(":*") {
            if let Some(ref cand) = parsed_candidate {
                if let Ok(p_url) = url::Url::parse(prefix) {
                    if cand.scheme() == p_url.scheme() && cand.host() == p_url.host() {
                        return true;
                    }
                }
            }
        }

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

        let parsed_origin = url::Url::parse(origin_str).ok();

        let allowed = trusted_origins.iter().any(|trusted| {
            let base = trusted.trim().trim_end_matches('/');
            if let Some(prefix) = base.strip_suffix(":*") {
                if let Some(ref orig) = parsed_origin {
                    if let Ok(p_url) = url::Url::parse(prefix) {
                        if orig.scheme() == p_url.scheme() && orig.host() == p_url.host() {
                            return true;
                        }
                    }
                }
            }
            base.eq_ignore_ascii_case(origin_str)
        });

        if !allowed {
            return Err(AuthError::InvalidOrigin);
        }
    }

    Ok(())
}

/// Axum middleware function that enforces CSRF Origin validation on mutating HTTP methods.
pub async fn csrf_origin_middleware(
    axum::extract::State(state): axum::extract::State<crate::state::AuthState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let is_mutating = matches!(
        *req.method(),
        http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE
    );
    let has_bearer = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase().starts_with("bearer "))
        .unwrap_or(false);

    if is_mutating && !has_bearer {
        if let Err(err) = verify_trusted_origin(req.headers(), &state.trusted_origins) {
            return crate::error::error_to_response(err);
        }
    }

    next.run(req).await
}
