pub mod admin;
pub mod auth;
pub mod error;
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
        // Health & Error Display
        .route("/ok", get(ok::ok))
        .route("/error", get(error::error_page))
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
        .route("/update-session", post(session::update_session))
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
        .route("/set-password", post(password::set_password))
        .route("/verify-password", post(password::verify_password))
        // User Profile, Email Change & Account Deletion
        .route("/update-user", post(user::update_user))
        .route("/change-email", post(user::change_email))
        .route("/delete-user", post(user::delete_user))
        .route("/delete-user/callback", get(user::delete_user_callback))
        // Email Verification
        .route(
            "/send-verification-email",
            post(verification::send_verification_email),
        )
        .route("/verify-email", get(verification::verify_email))
        // Social OAuth & Accounts
        .route("/sign-in/social", post(social::sign_in_social))
        .route("/link-social", post(social::link_social))
        .route("/callback/{provider}", get(social::oauth_callback))
        .route("/list-accounts", get(social::list_accounts))
        .route("/unlink-account", post(social::unlink_account))
        .route("/get-access-token", post(social::get_access_token))
        .route("/refresh-token", post(social::refresh_token))
        .route("/account-info", get(social::get_account_info))
}

/// Constructs an `auth_routes` sub-router merged with any registered `AxumAuthPlugin` routers.
pub fn auth_routes_with_plugins(state: &AuthState) -> Router<AuthState> {
    let mut router = auth_routes::<AuthState>();

    let mut plugins: Vec<std::sync::Arc<dyn crate::plugin::AxumAuthPlugin>> =
        (*state.axum_plugins).clone();

    // Dynamically mount any registered plugin providing an Axum route provider
    for plugin in state.service.plugins().plugins() {
        if let Some(provider) = plugin.route_provider() {
            let pid = provider.route_plugin_id();
            if !plugins.iter().any(|p| p.plugin_id() == pid) {
                if let Some(boxed_router) = provider.build_router_any(state) {
                    if let Ok(r) = boxed_router.downcast::<Router<AuthState>>() {
                        router = router.merge(*r);
                    }
                }
            }
        }
    }

    // Mount AdminPlugin router if registered on AuthService and not already mounted
    if let Some(admin_plugin) = state.service.get_plugin::<auth_core::AdminPlugin>() {
        if !plugins.iter().any(|p| p.plugin_id() == "admin") {
            plugins.push(std::sync::Arc::new(admin_plugin.clone()));
        }
    }

    // Mount OneTimeTokenPlugin router if registered on AuthService and not already mounted
    if let Some(ott_plugin) = state.service.get_plugin::<auth_core::OneTimeTokenPlugin>() {
        if !plugins.iter().any(|p| p.plugin_id() == "one-time-token") {
            plugins.push(std::sync::Arc::new(ott_plugin.clone()));
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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::plugin::endpoint_hooks_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::csrf_origin_middleware,
        ))
}

/// Constructs a self-contained auth router with `AuthState` applied, including plugins and endpoint hooks (state: `()`).
pub fn auth_router(state: AuthState) -> Router {
    auth_routes_with_plugins(&state).with_state(state)
}
