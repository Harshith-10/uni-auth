pub mod admin;
pub mod auth;
pub mod ok;
pub mod one_time_token;
pub mod password;
pub mod session;
pub mod social;
pub mod user;
pub mod verification;

use axum::extract::FromRef;
use axum::routing::{get, post};
use axum::Router;

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
        // Admin Plugin
        .route("/admin/set-role", post(admin::set_role))
        .route("/admin/get-user", get(admin::get_user))
        .route("/admin/create-user", post(admin::create_user))
        .route("/admin/update-user", post(admin::admin_update_user))
        .route("/admin/list-users", get(admin::list_users))
        .route(
            "/admin/list-user-sessions",
            post(admin::list_user_sessions),
        )
        .route("/admin/ban-user", post(admin::ban_user))
        .route("/admin/unban-user", post(admin::unban_user))
        .route("/admin/impersonate-user", post(admin::impersonate_user))
        .route(
            "/admin/stop-impersonating",
            post(admin::stop_impersonating),
        )
        .route(
            "/admin/revoke-user-session",
            post(admin::revoke_user_session),
        )
        .route(
            "/admin/revoke-user-sessions",
            post(admin::revoke_user_sessions),
        )
        .route("/admin/remove-user", post(admin::remove_user))
        .route("/admin/set-user-password", post(admin::set_user_password))
        .route("/admin/has-permission", post(admin::user_has_permission))
}

/// Constructs a self-contained auth router with `AuthState` applied (state: `()`).
pub fn auth_router(state: AuthState) -> Router {
    auth_routes().with_state(state)
}
