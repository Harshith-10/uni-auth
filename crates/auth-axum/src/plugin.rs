//! Plugin architecture for `auth-axum` enabling dynamic route mounting, route collision validation,
//! and request/response endpoint hooks.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use auth_core::plugin::EndpointHookContext;
use auth_core::{AdminPlugin, BearerPlugin, OneTimeTokenPlugin};

use crate::state::AuthState;

/// Declares an HTTP route descriptor for collision validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDescriptor {
    pub path: &'static str,
    pub methods: &'static [&'static str],
}

impl RouteDescriptor {
    pub const fn new(path: &'static str, methods: &'static [&'static str]) -> Self {
        Self { path, methods }
    }
}

/// Implemented by plugins that contribute routes to `auth-axum`.
pub trait AxumAuthPlugin: Send + Sync {
    /// Unique plugin identifier.
    fn plugin_id(&self) -> &'static str;

    /// Declared routes exposed by this plugin for collision detection.
    fn declared_routes(&self) -> Vec<RouteDescriptor>;

    /// Sub-router providing endpoint handlers for this plugin.
    fn router(&self) -> Router<AuthState>;
}

/// Validates that no two plugins register conflicting `(path, method)` pairs.
/// Parity with Better Auth's `checkEndpointConflicts` (`packages/better-auth/src/api/index.ts:58-171`).
pub fn check_endpoint_conflicts(plugins: &[Arc<dyn AxumAuthPlugin>]) -> Result<(), String> {
    let mut seen: std::collections::HashMap<(&'static str, &'static str), &'static str> =
        std::collections::HashMap::new();

    for plugin in plugins {
        let plugin_id = plugin.plugin_id();
        for route in plugin.declared_routes() {
            for &method in route.methods {
                if let Some(existing_plugin) = seen.get(&(route.path, method)) {
                    return Err(format!(
                        "Endpoint conflict: route '{}' [{}] registered by plugin '{}' conflicts with plugin '{}'",
                        route.path, method, plugin_id, existing_plugin
                    ));
                }
                seen.insert((route.path, method), plugin_id);
            }
        }
    }

    Ok(())
}

/// Tower middleware executing `on_before_endpoint` and `on_after_endpoint` plugin hooks.
pub async fn endpoint_hooks_middleware(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Normalize path relative to /api/auth if not already stripped by nest()
    let raw_path = req.uri().path();
    let path = raw_path
        .strip_prefix("/api/auth")
        .filter(|p| !p.is_empty())
        .unwrap_or(raw_path)
        .to_string();
    let method = req.method().as_str().to_string();

    // CSRF Origin verification for mutating requests (POST, PUT, PATCH, DELETE) without Bearer header
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
        if let Err(err) =
            crate::middleware::verify_trusted_origin(req.headers(), &state.trusted_origins)
        {
            return crate::error::error_to_response(err);
        }
    }

    // Enforce plugin rate limits before executing endpoint
    let client_ip = crate::extract::extract_request_meta(req.headers())
        .ip_address
        .unwrap_or_else(|| "local".to_string());
    if let Err(err) = state.service.check_plugin_rate_limits(&path, &client_ip) {
        return crate::error::error_to_response(err);
    }

    let mut request_headers = std::collections::HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v_str) = value.to_str() {
            request_headers.insert(name.as_str().to_lowercase(), v_str.to_string());
        }
    }

    let mut ctx = EndpointHookContext {
        path,
        method,
        request_headers,
        response_headers: std::collections::HashMap::new(),
        response_body: None,
        new_session: None,
    };

    if let Err(err) = state
        .service
        .plugins()
        .run_before_endpoint(&mut ctx, &state.service)
        .await
    {
        return crate::error::error_to_response(err);
    }

    for (k, v) in &ctx.request_headers {
        if let (Ok(hname), Ok(hval)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(v),
        ) {
            req.headers_mut().insert(hname, hval);
        }
    }

    let response = next.run(req).await;

    // Only run after-hook processing if at least one plugin matches `ctx.path`
    let has_after_hook = state
        .service
        .plugins()
        .plugins()
        .iter()
        .any(|p| p.matches_after(&ctx.path));

    if !has_after_hook {
        return response;
    }

    // 1. Copy outgoing response headers into ctx.response_headers
    for (name, value) in response.headers() {
        if let Ok(v_str) = value.to_str() {
            ctx.response_headers
                .insert(name.as_str().to_lowercase(), v_str.to_string());
        }
    }

    // 2. Extract NewSessionExt if a new session was issued during this request
    if let Some(crate::state::NewSessionExt(ses, usr)) = response
        .extensions()
        .get::<crate::state::NewSessionExt>()
        .cloned()
    {
        ctx.new_session = Some((ses, usr));
    }

    // 3. Buffer JSON body if content-type is application/json so after-hooks can inspect/filter it
    let (mut parts, body) = response.into_parts();
    let is_json = parts
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("application/json"))
        .unwrap_or(false);

    let body_bytes = if is_json {
        match axum::body::to_bytes(body, 2 * 1024 * 1024).await {
            Ok(b) => {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&b) {
                    ctx.response_body = Some(val);
                }
                b
            }
            Err(_) => axum::body::Bytes::new(),
        }
    } else {
        match axum::body::to_bytes(body, 2 * 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => axum::body::Bytes::new(),
        }
    };

    if let Err(err) = state
        .service
        .plugins()
        .run_after_endpoint(&mut ctx, &state.service)
        .await
    {
        return crate::error::error_to_response(err);
    }

    for (k, v) in ctx.response_headers {
        if let (Ok(hname), Ok(hval)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::header::HeaderValue::from_str(&v),
        ) {
            parts.headers.insert(hname, hval);
        }
    }

    let final_bytes = if let Some(modified_json) = ctx.response_body {
        parts.headers.remove(http::header::CONTENT_LENGTH);
        serde_json::to_vec(&modified_json)
            .map(axum::body::Bytes::from)
            .unwrap_or(body_bytes)
    } else {
        body_bytes
    };

    Response::from_parts(parts, axum::body::Body::from(final_bytes))
}

impl AxumAuthPlugin for OneTimeTokenPlugin {
    fn plugin_id(&self) -> &'static str {
        "one-time-token"
    }

    fn declared_routes(&self) -> Vec<RouteDescriptor> {
        vec![
            RouteDescriptor::new("/one-time-token/generate", &["GET"]),
            RouteDescriptor::new("/one-time-token/verify", &["POST"]),
        ]
    }

    fn router(&self) -> Router<AuthState> {
        Router::new()
            .route(
                "/one-time-token/generate",
                axum::routing::get(crate::routes::one_time_token::generate_one_time_token),
            )
            .route(
                "/one-time-token/verify",
                axum::routing::post(crate::routes::one_time_token::verify_one_time_token),
            )
    }
}

impl AxumAuthPlugin for BearerPlugin {
    fn plugin_id(&self) -> &'static str {
        "bearer"
    }

    fn declared_routes(&self) -> Vec<RouteDescriptor> {
        Vec::new()
    }

    fn router(&self) -> Router<AuthState> {
        Router::new()
    }
}

impl AxumAuthPlugin for AdminPlugin {
    fn plugin_id(&self) -> &'static str {
        "admin"
    }

    fn declared_routes(&self) -> Vec<RouteDescriptor> {
        vec![
            RouteDescriptor::new("/admin/set-role", &["POST"]),
            RouteDescriptor::new("/admin/get-user", &["GET"]),
            RouteDescriptor::new("/admin/create-user", &["POST"]),
            RouteDescriptor::new("/admin/update-user", &["POST"]),
            RouteDescriptor::new("/admin/list-users", &["GET"]),
            RouteDescriptor::new("/admin/list-user-sessions", &["POST"]),
            RouteDescriptor::new("/admin/ban-user", &["POST"]),
            RouteDescriptor::new("/admin/unban-user", &["POST"]),
            RouteDescriptor::new("/admin/impersonate-user", &["POST"]),
            RouteDescriptor::new("/admin/stop-impersonating", &["POST"]),
            RouteDescriptor::new("/admin/revoke-user-session", &["POST"]),
            RouteDescriptor::new("/admin/revoke-user-sessions", &["POST"]),
            RouteDescriptor::new("/admin/remove-user", &["POST"]),
            RouteDescriptor::new("/admin/set-user-password", &["POST"]),
            RouteDescriptor::new("/admin/has-permission", &["POST"]),
        ]
    }

    fn router(&self) -> Router<AuthState> {
        Router::new()
            .route(
                "/admin/set-role",
                axum::routing::post(crate::routes::admin::set_role),
            )
            .route(
                "/admin/get-user",
                axum::routing::get(crate::routes::admin::get_user),
            )
            .route(
                "/admin/create-user",
                axum::routing::post(crate::routes::admin::create_user),
            )
            .route(
                "/admin/update-user",
                axum::routing::post(crate::routes::admin::admin_update_user),
            )
            .route(
                "/admin/list-users",
                axum::routing::get(crate::routes::admin::list_users),
            )
            .route(
                "/admin/list-user-sessions",
                axum::routing::post(crate::routes::admin::list_user_sessions),
            )
            .route(
                "/admin/ban-user",
                axum::routing::post(crate::routes::admin::ban_user),
            )
            .route(
                "/admin/unban-user",
                axum::routing::post(crate::routes::admin::unban_user),
            )
            .route(
                "/admin/impersonate-user",
                axum::routing::post(crate::routes::admin::impersonate_user),
            )
            .route(
                "/admin/stop-impersonating",
                axum::routing::post(crate::routes::admin::stop_impersonating),
            )
            .route(
                "/admin/revoke-user-session",
                axum::routing::post(crate::routes::admin::revoke_user_session),
            )
            .route(
                "/admin/revoke-user-sessions",
                axum::routing::post(crate::routes::admin::revoke_user_sessions),
            )
            .route(
                "/admin/remove-user",
                axum::routing::post(crate::routes::admin::remove_user),
            )
            .route(
                "/admin/set-user-password",
                axum::routing::post(crate::routes::admin::set_user_password),
            )
            .route(
                "/admin/has-permission",
                axum::routing::post(crate::routes::admin::user_has_permission),
            )
    }
}
