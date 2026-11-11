//! Integration tests for Axum dynamic plugin route mounting, route conflict validation,
//! and request/response endpoint hooks.

use std::any::Any;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

use auth_axum::plugin::{check_endpoint_conflicts, AxumAuthPlugin, RouteDescriptor};
use auth_axum::{auth_router, AuthState};
use auth_core::adapter::BoxFuture;
use auth_core::error::AuthError;
use auth_core::plugin::{BetterAuthPlugin, EndpointHookContext};
use auth_core::{AuthConfig, AuthService, InMemoryAuthAdapter};

// ──────────────────────────────────────────────
// Test Axum Plugin Exposing Custom Routes
// ──────────────────────────────────────────────

struct PingPongPlugin;

impl AxumAuthPlugin for PingPongPlugin {
    fn plugin_id(&self) -> &'static str {
        "ping-pong"
    }

    fn declared_routes(&self) -> Vec<RouteDescriptor> {
        vec![RouteDescriptor::new("/ping-pong/ping", &["GET"])]
    }

    fn router(&self) -> Router<AuthState> {
        Router::new().route(
            "/ping-pong/ping",
            get(|| async { axum::Json(serde_json::json!({ "message": "pong" })) }),
        )
    }
}

// ──────────────────────────────────────────────
// Test Endpoint Hooks Plugin
// ──────────────────────────────────────────────

struct HeaderHookPlugin;

impl BetterAuthPlugin for HeaderHookPlugin {
    fn id(&self) -> &'static str {
        "header-hook"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn matches_before(&self, path: &str) -> bool {
        path == "/ok"
    }

    fn on_before_endpoint(
        &self,
        ctx: &mut EndpointHookContext,
        _service: &AuthService,
    ) -> BoxFuture<'static, Result<(), AuthError>> {
        // Inject a request header before handler runs
        ctx.request_headers
            .insert("x-custom-req-tag".to_string(), "tagged-123".to_string());
        Box::pin(async { Ok(()) })
    }

    fn matches_after(&self, path: &str) -> bool {
        path == "/ok"
    }

    fn on_after_endpoint(
        &self,
        ctx: &mut EndpointHookContext,
        _service: &AuthService,
    ) -> BoxFuture<'static, Result<(), AuthError>> {
        // Inject a custom response header
        ctx.response_headers
            .insert("x-plugin-processed".to_string(), "true".to_string());
        Box::pin(async { Ok(()) })
    }
}

fn create_test_state() -> AuthState {
    let config = AuthConfig {
        secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        base_url: "http://localhost:3000/api/auth".to_string(),
        session_expires_in: time::Duration::days(7),
        verify_email_expires_in: time::Duration::hours(1),
        reset_password_expires_in: time::Duration::hours(1),
        ott_expires_in: time::Duration::minutes(3),
        require_email_verification: false,
        auto_sign_in: true,
        delete_user_enabled: true,
        defer_session_refresh: true,
        min_password_length: 8,
        max_password_length: 128,
    };
    let adapter = Arc::new(InMemoryAuthAdapter::new());
    let service = AuthService::new(config, adapter).with_plugin(HeaderHookPlugin);
    AuthState::new(Arc::new(service))
}

#[tokio::test]
async fn test_axum_plugin_dynamic_route_mounting() {
    let state = create_test_state().with_plugin(Arc::new(PingPongPlugin));
    let app = auth_router(state);

    let req = Request::builder()
        .uri("/ping-pong/ping")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["message"], "pong");
}

#[tokio::test]
async fn test_axum_endpoint_hooks_injects_response_headers() {
    let state = create_test_state();
    let app = auth_router(state);

    let req = Request::builder()
        .uri("/ok")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify after-hook injected custom response header
    let header_val = res.headers().get("x-plugin-processed");
    assert!(header_val.is_some());
    assert_eq!(header_val.unwrap().to_str().unwrap(), "true");
}

#[test]
fn test_check_endpoint_conflicts_detection() {
    struct PluginA;
    impl AxumAuthPlugin for PluginA {
        fn plugin_id(&self) -> &'static str {
            "plugin-a"
        }
        fn declared_routes(&self) -> Vec<RouteDescriptor> {
            vec![RouteDescriptor::new("/duplicate/path", &["POST"])]
        }
        fn router(&self) -> Router<AuthState> {
            Router::new()
        }
    }

    struct PluginB;
    impl AxumAuthPlugin for PluginB {
        fn plugin_id(&self) -> &'static str {
            "plugin-b"
        }
        fn declared_routes(&self) -> Vec<RouteDescriptor> {
            vec![RouteDescriptor::new("/duplicate/path", &["POST", "GET"])]
        }
        fn router(&self) -> Router<AuthState> {
            Router::new()
        }
    }

    let plugins: Vec<Arc<dyn AxumAuthPlugin>> = vec![Arc::new(PluginA), Arc::new(PluginB)];
    let conflict = check_endpoint_conflicts(&plugins);
    assert!(conflict.is_err());
    let err_msg = conflict.err().unwrap();
    assert!(err_msg.contains("Endpoint conflict"));
    assert!(err_msg.contains("/duplicate/path"));
}
