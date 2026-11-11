//! Plugin architecture for `auth-axum` enabling dynamic route mounting, route collision validation,
//! and request/response endpoint hooks.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;

use auth_core::plugin::EndpointHookContext;

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
