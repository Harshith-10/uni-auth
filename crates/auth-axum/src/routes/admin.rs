//! Better Auth `admin` plugin HTTP endpoints (`/api/auth/admin/*`).
//!
//! Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/routes.ts`

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::{
    AdminBanUserRequest, AdminCreateUserRequest, AdminGetUserQuery, AdminHasPermissionRequest,
    AdminListUsersQuery, AdminRevokeUserSessionRequest, AdminSetRoleRequest,
    AdminSetUserPasswordRequest, AdminUpdateUserRequest, AdminUserIdRequest, AuthErrorResponse,
};
use crate::cookies::{build_clear_session_cookie, build_session_cookie};
use crate::extract::{extract_request_meta, CurrentSession};
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body =
        AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

fn admin_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Secure-better-auth.admin_session"
    } else {
        "better-auth.admin_session"
    }
}

fn extract_admin_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(hdr) = headers.get("x-admin-auth-token") {
        if let Ok(s) = hdr.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    for cookie_header in headers.get_all(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for part in cookie_str.split(';') {
                if let Some((k, v)) = part.trim().split_once('=') {
                    let k = k.trim();
                    if k == "better-auth.admin_session"
                        || k == "__Secure-better-auth.admin_session"
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

/// `POST /api/auth/admin/set-role`
pub async fn set_role(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminSetRoleRequest>,
) -> Response {
    match state
        .service
        .admin_set_role(&current_session.user, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `GET /api/auth/admin/get-user`
pub async fn get_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Query(query): Query<AdminGetUserQuery>,
) -> Response {
    match state
        .service
        .admin_get_user(&current_session.user, &query.id)
        .await
    {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/create-user`
pub async fn create_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminCreateUserRequest>,
) -> Response {
    match state
        .service
        .admin_create_user(&current_session.user, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/update-user`
pub async fn admin_update_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUpdateUserRequest>,
) -> Response {
    match state
        .service
        .admin_update_user(&current_session.user, payload)
        .await
    {
        Ok(user) => (StatusCode::OK, Json(user)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `GET /api/auth/admin/list-users`
pub async fn list_users(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Query(query): Query<AdminListUsersQuery>,
) -> Response {
    match state
        .service
        .admin_list_users(&current_session.user, query)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/list-user-sessions`
pub async fn list_user_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Response {
    match state
        .service
        .admin_list_user_sessions(&current_session.user, &payload.user_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/ban-user`
pub async fn ban_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminBanUserRequest>,
) -> Response {
    match state
        .service
        .admin_ban_user(&current_session.user, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/unban-user`
pub async fn unban_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Response {
    match state
        .service
        .admin_unban_user(&current_session.user, &payload.user_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/impersonate-user`
pub async fn impersonate_user(
    State(state): State<AuthState>,
    headers: HeaderMap,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Response {
    let meta = extract_request_meta(&headers);
    match state
        .service
        .admin_impersonate_user(&current_session.user, &payload.user_id, meta)
        .await
    {
        Ok(res) => {
            let signed_impersonated = state.service.sign_token(&res.session.token);
            let signed_admin = state.service.sign_token(&current_session.session.token);

            let mut response = (StatusCode::OK, Json(res)).into_response();

            // 1. Stash original admin session in `better-auth.admin_session` cookie and `set-admin-auth-token` header
            let admin_cookie = build_session_cookie(
                admin_cookie_name(state.secure_cookies),
                &signed_admin,
                state.service.config().session_expires_in.whole_seconds(),
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(c) = admin_cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, c);
            }
            if let Ok(tok) = signed_admin.parse() {
                response
                    .headers_mut()
                    .insert("set-admin-auth-token", tok);
            }

            // 2. Set active session cookie and `set-auth-token` to the impersonated session
            let session_cookie = build_session_cookie(
                &state.cookie_name,
                &signed_impersonated,
                state
                    .service
                    .admin_config()
                    .impersonation_session_duration
                    .whole_seconds(),
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(c) = session_cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, c);
            }
            if let Ok(tok) = signed_impersonated.parse() {
                response.headers_mut().insert("set-auth-token", tok);
            }

            response
        }
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/stop-impersonating`
pub async fn stop_impersonating(
    State(state): State<AuthState>,
    headers: HeaderMap,
    current_session: CurrentSession,
) -> Response {
    let stashed_admin = extract_admin_session_token(&headers);
    match state
        .service
        .admin_stop_impersonating(&current_session.session, stashed_admin.as_deref())
        .await
    {
        Ok(res) => {
            let signed_admin = state.service.sign_token(&res.session.token);
            let mut response = (StatusCode::OK, Json(res)).into_response();

            // 1. Restore admin session cookie and `set-auth-token`
            let session_cookie = build_session_cookie(
                &state.cookie_name,
                &signed_admin,
                state.service.config().session_expires_in.whole_seconds(),
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(c) = session_cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, c);
            }
            if let Ok(tok) = signed_admin.parse() {
                response.headers_mut().insert("set-auth-token", tok);
            }

            // 2. Expire `better-auth.admin_session` cookie
            let clear_admin = build_clear_session_cookie(
                admin_cookie_name(state.secure_cookies),
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(c) = clear_admin.parse() {
                response.headers_mut().append(header::SET_COOKIE, c);
            }

            response
        }
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/revoke-user-session`
pub async fn revoke_user_session(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminRevokeUserSessionRequest>,
) -> Response {
    match state
        .service
        .admin_revoke_user_session(&current_session.user, &payload.session_token)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/revoke-user-sessions`
pub async fn revoke_user_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Response {
    match state
        .service
        .admin_revoke_user_sessions(&current_session.user, &payload.user_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/remove-user`
pub async fn remove_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Response {
    match state
        .service
        .admin_remove_user(&current_session.user, &payload.user_id)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/set-user-password`
pub async fn set_user_password(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminSetUserPasswordRequest>,
) -> Response {
    match state
        .service
        .admin_set_user_password(&current_session.user, payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

/// `POST /api/auth/admin/has-permission`
pub async fn user_has_permission(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminHasPermissionRequest>,
) -> Response {
    match state
        .service
        .admin_has_permission(Some(&current_session.user), payload)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}
