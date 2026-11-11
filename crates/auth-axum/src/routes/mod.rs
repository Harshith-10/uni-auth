pub mod admin;
pub mod auth;
pub mod ok;
pub mod one_time_token;
pub mod password;
pub mod session;
pub mod social;
pub mod user;
pub mod verification;

use axum::Router;
use axum::extract::FromRef;
use axum::routing::{get, post};

use crate::state::AuthState;

/// Constructs auth routes with state `S` where `AuthState: FromRef<S>`.
///
/// Can be nested inside any router that holds `AuthState` or an application state containing it.
pub fn auth_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AuthState: FromRef<S>,
{
    Router::new()
        // Health
        .route("/ok", get(ok::ok))
        // Email Authentication
        .route("/sign-up/email", post(auth::sign_up_email))
        .route("/sign-in/email", post(auth::sign_in_email))
        .route("/sign-out", post(auth::sign_out))
        // Session Management
        .route(
            "/get-session",
            get(session::get_session).post(session::get_session),
        )
        .route("/list-sessions", get(session::list_sessions))
        .route("/revoke-session", post(session::revoke_session))
        .route("/revoke-sessions", post(session::revoke_sessions))
        .route(
            "/revoke-other-sessions",
            post(session::revoke_other_sessions),
        )
        // Password Management
        .route(
            "/request-password-reset",
            post(password::request_password_reset),
        )
        .route(
            "/reset-password/{token}",
            get(password::reset_password_callback),
        )
        .route("/reset-password", post(password::reset_password))
        .route("/change-password", post(password::change_password))
        // User Profile & Account Deletion
        .route("/update-user", post(user::update_user))
        .route("/delete-user", post(user::delete_user))
        // Email Verification
        .route(
            "/send-verification-email",
            post(verification::send_verification_email),
        )
        .route("/verify-email", get(verification::verify_email))
        // One-Time Token Plugin
        .route(
            "/one-time-token/generate",
            get(one_time_token::generate_one_time_token),
        )
        .route(
            "/one-time-token/verify",
            post(one_time_token::verify_one_time_token),
        )
        // Social OAuth & Accounts
        .route("/sign-in/social", post(social::sign_in_social))
        .route("/link-social", post(social::link_social))
        .route("/callback/{provider}", get(social::oauth_callback))
        .route("/list-accounts", get(social::list_accounts))
        .route("/unlink-account", post(social::unlink_account))
}

/// Constructs an `auth_routes` sub-router merged with any registered `AxumAuthPlugin` routers.
pub fn auth_routes_with_plugins(state: &AuthState) -> Router<AuthState> {
    let mut router = auth_routes::<AuthState>();

    // Dynamically mount AdminPlugin router if registered on AuthService and not already in axum_plugins
    let mut plugins: Vec<std::sync::Arc<dyn crate::plugin::AxumAuthPlugin>> =
        (*state.axum_plugins).clone();
    if let Some(admin_plugin) = state.service.get_plugin::<auth_core::AdminPlugin>() {
        if !plugins.iter().any(|p| p.plugin_id() == "admin") {
            plugins.push(std::sync::Arc::new(admin_plugin.clone()));
        }
    }

    if !plugins.is_empty() {
        if let Err(conflict) = crate::plugin::check_endpoint_conflicts(&plugins) {
            tracing::warn!("Endpoint conflict detected in Axum plugins: {}", conflict);
        }
        for plugin in plugins.iter() {
            router = router.merge(plugin.router());
        }
    }
    router
}

/// Constructs a self-contained auth router with `AuthState` applied, including plugins and endpoint hooks (state: `()`).
pub fn auth_router(state: AuthState) -> Router {
    let router = auth_routes_with_plugins(&state);
    router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::plugin::endpoint_hooks_middleware,
        ))
        .with_state(state)
}
