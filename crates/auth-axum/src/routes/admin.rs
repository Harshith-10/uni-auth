//! Better Auth `admin` plugin HTTP endpoints (`/api/auth/admin/*`).
//!
//! Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/routes.ts`

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::cookies::{build_clear_session_cookie, build_session_cookie};
use crate::error::ApiError;
use crate::extract::{CurrentSession, extract_request_meta};
use crate::state::AuthState;
use auth_core::AdminServiceExt;
use auth_proto::{
    AdminBanUserRequest, AdminCreateUserRequest, AdminGetUserQuery, AdminHasPermissionRequest,
    AdminListUserSessionsResponse, AdminListUsersQuery, AdminListUsersResponse,
    AdminPermissionResponse, AdminRevokeUserSessionRequest, AdminSetRoleRequest,
    AdminSetUserPasswordRequest, AdminSuccessResponse, AdminUpdateUserRequest, AdminUserIdRequest,
    AdminUserResponse, StatusResponse, UserWire,
};

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
                    if k == "better-auth.admin_session" || k == "__Secure-better-auth.admin_session"
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
) -> Result<Json<AdminUserResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .set_role(&current_session.user, payload)
        .await?;
    Ok(Json(res))
}

/// `GET /api/auth/admin/get-user`
pub async fn get_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Query(query): Query<AdminGetUserQuery>,
) -> Result<Json<UserWire>, ApiError> {
    let res = state
        .service
        .admin()?
        .get_user(&current_session.user, &query.id)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/create-user`
pub async fn create_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminCreateUserRequest>,
) -> Result<Json<AdminUserResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .create_user(&current_session.user, payload)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/update-user`
pub async fn admin_update_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUpdateUserRequest>,
) -> Result<Json<UserWire>, ApiError> {
    let res = state
        .service
        .admin()?
        .update_user(&current_session.user, payload)
        .await?;
    Ok(Json(res))
}

/// `GET /api/auth/admin/list-users`
pub async fn list_users(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Query(query): Query<AdminListUsersQuery>,
) -> Result<Json<AdminListUsersResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .list_users(&current_session.user, query)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/list-user-sessions`
pub async fn list_user_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Result<Json<AdminListUserSessionsResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .list_user_sessions(&current_session.user, &payload.user_id)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/ban-user`
pub async fn ban_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminBanUserRequest>,
) -> Result<Json<AdminUserResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .ban_user(&current_session.user, payload)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/unban-user`
pub async fn unban_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Result<Json<AdminUserResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .unban_user(&current_session.user, &payload.user_id)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/impersonate-user`
pub async fn impersonate_user(
    State(state): State<AuthState>,
    headers: HeaderMap,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Result<Response, ApiError> {
    let meta = extract_request_meta(&headers);
    let admin_svc = state.service.admin()?;
    let res = admin_svc
        .impersonate_user(&current_session.user, &payload.user_id, meta)
        .await?;

    let signed_admin = state.service.sign_token(&current_session.session.token);

    let mut response = (StatusCode::OK, Json(res.clone())).into_response();

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
        response.headers_mut().insert("set-admin-auth-token", tok);
    }

    // 2. Set active session cookie and `set-auth-token` to the impersonated session
    let duration = admin_svc.plugin.config.impersonation_session_duration;
    state.attach_session_cookie(&mut response, &res.session.token, true, Some(duration));

    Ok(response)
}

/// `POST /api/auth/admin/stop-impersonating`
pub async fn stop_impersonating(
    State(state): State<AuthState>,
    headers: HeaderMap,
    current_session: CurrentSession,
) -> Result<Response, ApiError> {
    let stashed_admin = extract_admin_session_token(&headers);
    let res = state
        .service
        .admin()?
        .stop_impersonating(&current_session.session, stashed_admin.as_deref())
        .await?;

    let mut response = (StatusCode::OK, Json(res.clone())).into_response();

    // 1. Restore admin session cookie and `set-auth-token`
    state.attach_session_cookie(&mut response, &res.session.token, true, None);

    // 2. Expire `better-auth.admin_session` cookie
    let clear_admin = build_clear_session_cookie(
        admin_cookie_name(state.secure_cookies),
        state.secure_cookies,
        &state.same_site,
    );
    if let Ok(c) = clear_admin.parse() {
        response.headers_mut().append(header::SET_COOKIE, c);
    }

    Ok(response)
}

/// `POST /api/auth/admin/revoke-user-session`
pub async fn revoke_user_session(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminRevokeUserSessionRequest>,
) -> Result<Json<AdminSuccessResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .revoke_user_session(&current_session.user, &payload.session_token)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/revoke-user-sessions`
pub async fn revoke_user_sessions(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Result<Json<AdminSuccessResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .revoke_user_sessions(&current_session.user, &payload.user_id)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/remove-user`
pub async fn remove_user(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminUserIdRequest>,
) -> Result<Json<AdminSuccessResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .remove_user(&current_session.user, &payload.user_id)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/set-user-password`
pub async fn set_user_password(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminSetUserPasswordRequest>,
) -> Result<Json<StatusResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .set_user_password(&current_session.user, payload)
        .await?;
    Ok(Json(res))
}

/// `POST /api/auth/admin/has-permission`
pub async fn user_has_permission(
    State(state): State<AuthState>,
    current_session: CurrentSession,
    Json(payload): Json<AdminHasPermissionRequest>,
) -> Result<Json<AdminPermissionResponse>, ApiError> {
    let res = state
        .service
        .admin()?
        .has_permission(Some(&current_session.user), payload)
        .await?;
    Ok(Json(res))
}
