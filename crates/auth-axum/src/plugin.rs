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
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();

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

    let mut response = next.run(req).await;

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
            response.headers_mut().insert(hname, hval);
        }
    }

    response
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
