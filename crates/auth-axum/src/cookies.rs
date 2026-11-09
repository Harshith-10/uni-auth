//! Cookie utilities for Better Auth session management.

use axum::http::HeaderMap;

/// Constructs a `Set-Cookie` header value to establish a session.
pub fn build_session_cookie(
    name: &str,
    token: &str,
    max_age_secs: i64,
    secure: bool,
    same_site: &str,
) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{name}={token}; Path=/; HttpOnly; SameSite={same_site}; Max-Age={max_age_secs}{secure_flag}"
    )
}

/// Constructs a `Set-Cookie` header value to clear the session.
pub fn build_clear_session_cookie(name: &str, secure: bool, same_site: &str) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{name}=; Path=/; HttpOnly; SameSite={same_site}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT{secure_flag}"
    )
}

/// Extracts the session token from request `Cookie` headers.
///
/// Checks both the primary cookie name (e.g. `better-auth.session_token`)
/// and the secure prefixed version (`__Secure-better-auth.session_token`).
pub fn extract_cookie_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    for cookie_header in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for part in cookie_str.split(';') {
                let trimmed = part.trim();
                if let Some((k, v)) = trimmed.split_once('=') {
                    let k = k.trim();
                    if k == cookie_name
                        || k == "better-auth.session_token"
                        || k == "__Secure-better-auth.session_token"
                    {
                        let val = v.trim();
                        if !val.is_empty() {
                            return Some(val.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}
