//! Admin client plugin for administrative operations and impersonation.
//!
//! Provides the `client.admin()` facade, local client-side role permission checks, automated admin session
//! token stashing and restoration across impersonation lifecycles, and `$sessionSignal` integration.

use std::collections::HashMap;
use std::sync::RwLock;

use reqwest::Method;
use reqwest::header::HeaderValue;

use uni_auth_proto::access::{AccessControl, Connector};
use uni_auth_proto::{
    AdminBanUserRequest, AdminCreateUserRequest, AdminGetUserQuery, AdminHasPermissionRequest,
    AdminListUserSessionsResponse, AdminListUsersQuery, AdminListUsersResponse,
    AdminPermissionResponse, AdminRevokeUserSessionRequest, AdminSetRoleRequest,
    AdminSetUserPasswordRequest, AdminSuccessResponse, AdminUpdateUserRequest, AdminUserIdRequest,
    AdminUserResponse, RoleValue, SessionAndUserResponse, StatusResponse, UserWire,
};

use crate::client::{AuthClient, ClientError};
use crate::plugin::{AuthClientPlugin, ClientSignalListener, SESSION_SIGNAL};
use crate::transport::{ClientRequestContext, ClientResponseContext};

/// Client plugin managing administrative endpoints and impersonation token preservation.
pub struct AdminClientPlugin {
    pub(crate) admin_token_backup: RwLock<Option<String>>,
    pub(crate) ac: AccessControl,
}

impl Default for AdminClientPlugin {
    fn default() -> Self {
        Self {
            admin_token_backup: RwLock::new(None),
            ac: AccessControl::default_admin(),
        }
    }
}

impl AdminClientPlugin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_access_control(ac: AccessControl) -> Self {
        Self {
            admin_token_backup: RwLock::new(None),
            ac,
        }
    }

    /// Returns the currently stashed original admin session token, if actively impersonating.
    pub fn admin_token_backup(&self) -> Option<String> {
        self.admin_token_backup.read().ok().and_then(|g| g.clone())
    }
}

impl AuthClientPlugin for AdminClientPlugin {
    fn id(&self) -> &'static str {
        "admin-client"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn on_request(&self, ctx: &mut ClientRequestContext) -> Result<(), ClientError> {
        // Automatically inject stashed admin session token when stopping impersonation
        if ctx.path == "/admin/stop-impersonating" {
            if let Ok(guard) = self.admin_token_backup.read() {
                if let Some(ref tok) = *guard {
                    if let Ok(hv) = HeaderValue::from_str(tok) {
                        ctx.headers.insert("x-admin-auth-token", hv);
                    }
                }
            }
        }
        Ok(())
    }

    fn on_response(&self, ctx: &ClientResponseContext) -> Result<(), ClientError> {
        if ctx.status < 400 {
            if ctx.path == "/admin/impersonate-user" {
                if let Some(tok) = ctx
                    .headers
                    .get("set-admin-auth-token")
                    .and_then(|v| v.to_str().ok())
                {
                    if let Ok(mut guard) = self.admin_token_backup.write() {
                        *guard = Some(tok.trim().to_string());
                    }
                }
            } else if ctx.path == "/admin/stop-impersonating" || ctx.path == "/sign-out" {
                if let Ok(mut guard) = self.admin_token_backup.write() {
                    *guard = None;
                }
            }
        }
        Ok(())
    }

    fn signal_listeners(&self) -> Vec<ClientSignalListener> {
        vec![ClientSignalListener {
            signal: SESSION_SIGNAL,
            matcher: |path| {
                path == "/admin/impersonate-user" || path == "/admin/stop-impersonating"
            },
        }]
    }
}

/// Administrative namespace handle returned by `client.admin()`.
pub struct AdminClientHandle<'a> {
    client: &'a AuthClient,
    plugin: Option<&'a AdminClientPlugin>,
}

impl<'a> AdminClientHandle<'a> {
    /// Pure client-side role permission check without a network round-trip.
    pub fn check_role_permission(
        &self,
        role_csv: &str,
        permissions: &HashMap<String, Vec<String>>,
    ) -> bool {
        self.check_role_permission_with_connector(role_csv, permissions, Connector::And)
    }

    /// Client-side role permission check with explicit `Connector::And` or `Connector::Or`.
    pub fn check_role_permission_with_connector(
        &self,
        role_csv: &str,
        permissions: &HashMap<String, Vec<String>>,
        connector: Connector,
    ) -> bool {
        let default_ac;
        let ac = match self.plugin {
            Some(p) => &p.ac,
            None => {
                default_ac = AccessControl::default_admin();
                &default_ac
            }
        };

        role_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|r| {
                ac.get_role(r)
                    .map(|def| def.authorize_with_connector(permissions, connector))
                    .unwrap_or(false)
            })
    }

    /// `POST /api/auth/admin/set-role`
    pub async fn set_role(
        &self,
        user_id: impl Into<String>,
        role: impl Into<RoleValue>,
    ) -> Result<AdminUserResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/set-role",
                None::<&()>,
                Some(&AdminSetRoleRequest {
                    user_id: user_id.into(),
                    role: role.into(),
                }),
            )
            .await
    }

    /// `GET /api/auth/admin/get-user`
    pub async fn get_user(&self, id: impl Into<String>) -> Result<UserWire, ClientError> {
        self.client
            .send_auth_request(
                Method::GET,
                "/admin/get-user",
                Some(&AdminGetUserQuery { id: id.into() }),
                None::<&()>,
            )
            .await
    }

    /// `POST /api/auth/admin/create-user`
    pub async fn create_user(
        &self,
        req: AdminCreateUserRequest,
    ) -> Result<AdminUserResponse, ClientError> {
        self.client
            .send_auth_request(Method::POST, "/admin/create-user", None::<&()>, Some(&req))
            .await
    }

    /// `POST /api/auth/admin/update-user`
    pub async fn update_user(&self, req: AdminUpdateUserRequest) -> Result<UserWire, ClientError> {
        self.client
            .send_auth_request(Method::POST, "/admin/update-user", None::<&()>, Some(&req))
            .await
    }

    /// `GET /api/auth/admin/list-users`
    pub async fn list_users(
        &self,
        query: &AdminListUsersQuery,
    ) -> Result<AdminListUsersResponse, ClientError> {
        self.client
            .send_auth_request(Method::GET, "/admin/list-users", Some(query), None::<&()>)
            .await
    }

    /// `POST /api/auth/admin/list-user-sessions`
    pub async fn list_user_sessions(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminListUserSessionsResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/list-user-sessions",
                None::<&()>,
                Some(&AdminUserIdRequest {
                    user_id: user_id.into(),
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/ban-user`
    pub async fn ban_user(
        &self,
        user_id: impl Into<String>,
        ban_reason: Option<String>,
        ban_expires_in: Option<i64>,
    ) -> Result<AdminUserResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/ban-user",
                None::<&()>,
                Some(&AdminBanUserRequest {
                    user_id: user_id.into(),
                    ban_reason,
                    ban_expires_in,
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/unban-user`
    pub async fn unban_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminUserResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/unban-user",
                None::<&()>,
                Some(&AdminUserIdRequest {
                    user_id: user_id.into(),
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/impersonate-user`
    pub async fn impersonate_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<SessionAndUserResponse, ClientError> {
        let res: SessionAndUserResponse = self
            .client
            .send_auth_request(
                Method::POST,
                "/admin/impersonate-user",
                None::<&()>,
                Some(&AdminUserIdRequest {
                    user_id: user_id.into(),
                }),
            )
            .await?;
        self.client
            .notify_session_event(crate::plugin::SessionSignalEvent::SessionUpdated {
                user: res.user.clone(),
                session: res.session.clone(),
            });
        Ok(res)
    }

    /// `POST /api/auth/admin/stop-impersonating`
    pub async fn stop_impersonating(&self) -> Result<SessionAndUserResponse, ClientError> {
        let res: SessionAndUserResponse = self
            .client
            .send_auth_request(
                Method::POST,
                "/admin/stop-impersonating",
                None::<&()>,
                None::<&()>,
            )
            .await?;
        self.client
            .notify_session_event(crate::plugin::SessionSignalEvent::SessionUpdated {
                user: res.user.clone(),
                session: res.session.clone(),
            });
        Ok(res)
    }

    /// `POST /api/auth/admin/revoke-user-session`
    pub async fn revoke_user_session(
        &self,
        session_token: impl Into<String>,
    ) -> Result<AdminSuccessResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/revoke-user-session",
                None::<&()>,
                Some(&AdminRevokeUserSessionRequest {
                    session_token: session_token.into(),
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/revoke-user-sessions`
    pub async fn revoke_user_sessions(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminSuccessResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/revoke-user-sessions",
                None::<&()>,
                Some(&AdminUserIdRequest {
                    user_id: user_id.into(),
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/remove-user`
    pub async fn remove_user(
        &self,
        user_id: impl Into<String>,
    ) -> Result<AdminSuccessResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/remove-user",
                None::<&()>,
                Some(&AdminUserIdRequest {
                    user_id: user_id.into(),
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/set-user-password`
    pub async fn set_user_password(
        &self,
        user_id: impl Into<String>,
        new_password: impl Into<String>,
    ) -> Result<StatusResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/set-user-password",
                None::<&()>,
                Some(&AdminSetUserPasswordRequest {
                    user_id: user_id.into(),
                    new_password: new_password.into(),
                }),
            )
            .await
    }

    /// `POST /api/auth/admin/has-permission`
    pub async fn has_permission(
        &self,
        req: AdminHasPermissionRequest,
    ) -> Result<AdminPermissionResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::POST,
                "/admin/has-permission",
                None::<&()>,
                Some(&req),
            )
            .await
    }
}

/// Extension trait granting access to the `client.admin()` administrative handle.
pub trait AdminClientExt {
    fn admin(&self) -> AdminClientHandle<'_>;
}

impl AdminClientExt for AuthClient {
    fn admin(&self) -> AdminClientHandle<'_> {
        AdminClientHandle {
            client: self,
            plugin: self.get_plugin::<AdminClientPlugin>(),
        }
    }
}
