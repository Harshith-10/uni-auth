//! Implementation of the 15 administrative operations for `AdminPlugin`.

use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use auth_proto::error_codes;
use auth_proto::{
    AdminBanUserRequest, AdminCreateUserRequest, AdminHasPermissionRequest,
    AdminListUserSessionsResponse, AdminListUsersQuery, AdminListUsersResponse,
    AdminPermissionResponse, AdminSetRoleRequest, AdminSetUserPasswordRequest,
    AdminSuccessResponse, AdminUpdateUserRequest, AdminUserResponse, RoleValue,
    SessionAndUserResponse, SessionWire, StatusResponse, UserWire,
};

use crate::access::Connector;
use crate::crypto;
use crate::error::{AdapterError, AuthError};
use crate::models::{
    AdminListUsersFilter, AdminUpdateUserFields, CreateAccountInput, CreateSessionInput,
    CreateUserInput, RequestMeta,
};
use crate::plugin::admin::AdminPlugin;
use crate::service::AuthService;

/// Domain facade providing all 15 administrative operations backed by `AdminPlugin`.
pub struct AdminService<'a> {
    pub service: &'a AuthService,
    pub plugin: &'a AdminPlugin,
}

/// Extension trait granting access to `AdminService` from an `AuthService`.
pub trait AdminServiceExt {
    /// Returns the `AdminService` facade if `AdminPlugin` is registered on this `AuthService`.
    fn admin(&self) -> Result<AdminService<'_>, AuthError>;
}

impl AdminServiceExt for AuthService {
    fn admin(&self) -> Result<AdminService<'_>, AuthError> {
        let plugin = self.get_plugin::<AdminPlugin>().ok_or_else(|| {
            AuthError::Internal("AdminPlugin is not registered on AuthService".to_string())
        })?;
        Ok(AdminService {
            service: self,
            plugin,
        })
    }
}

impl<'a> AdminService<'a> {
    /// Evaluates role/user permissions using `AdminConfig::has_permission`.
    pub fn check_permission(
        &self,
        actor: &UserWire,
        resource: &str,
        action: &str,
        err_code: &'static str,
        err_msg: &'static str,
    ) -> Result<(), AuthError> {
        if !self.plugin.config.has_permission(
            Some(&actor.id),
            actor.role.as_deref(),
            resource,
            action,
        ) {
            return Err(AuthError::forbidden(err_code, err_msg));
        }
        Ok(())
    }

    /// Validates that requested role names exist in the RBAC access control configuration.
    pub fn validate_role_names(&self, roles: &[String]) -> Result<(), AuthError> {
        if roles.is_empty() {
            return Err(AuthError::bad_request(
                error_codes::INVALID_ROLE_TYPE,
                "Invalid role type",
            ));
        }
        for role in roles {
            if !self.plugin.config.ac.has_role(role) {
                return Err(AuthError::bad_request(
                    error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE,
                    "You are not allowed to set a non-existent role value",
                ));
            }
        }
        Ok(())
    }

    /// `POST /api/auth/admin/set-role`
    pub async fn set_role(
        &self,
        actor: &UserWire,
        req: AdminSetRoleRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "set-role",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE,
            "You are not allowed to change users role",
        )?;

        let role_list = req.role.to_vec();
        self.validate_role_names(&role_list)?;

        let updated = self
            .service
            .adapter()
            .update_user_admin(
                &req.user_id,
                AdminUpdateUserFields {
                    role: Some(req.role.to_csv()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
            })?;

        Ok(AdminUserResponse {
            user: updated.to_wire(),
        })
    }

    /// `GET /api/auth/admin/get-user`
    pub async fn get_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<UserWire, AuthError> {
        self.check_permission(
            actor,
            "user",
            "get",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_GET_USER,
            "You are not allowed to get user",
        )?;

        let user = self
            .service
            .adapter()
            .find_user_by_id(target_user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Ok(user.to_wire())
    }

    /// `POST /api/auth/admin/create-user`
    pub async fn create_user(
        &self,
        actor: &UserWire,
        req: AdminCreateUserRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "create",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS,
            "You are not allowed to create users",
        )?;

        let data_map = req.data.unwrap_or_default();

        // Extract role from top-level `role` or `data.role`
        let requested_role: Option<RoleValue> = if req.role.is_some() {
            req.role
        } else if let Some(val) = data_map.get("role") {
            match serde_json::from_value::<RoleValue>(val.clone()) {
                Ok(rv) => Some(rv),
                Err(_) => {
                    return Err(AuthError::bad_request(
                        error_codes::INVALID_ROLE_TYPE,
                        "Invalid role type",
                    ));
                }
            }
        } else {
            None
        };

        if let Some(ref rv) = requested_role {
            self.check_permission(
                actor,
                "user",
                "set-role",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE,
                "You are not allowed to change users role",
            )?;
            let role_list = rv.to_vec();
            self.validate_role_names(&role_list)?;
        }

        if ["banned", "banReason", "banExpires"]
            .iter()
            .any(|k| data_map.contains_key(*k))
        {
            self.check_permission(
                actor,
                "user",
                "ban",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
                "You are not allowed to ban users",
            )?;
        }

        let email = req.email.trim().to_lowercase();
        if !email.contains('@') || !email.contains('.') {
            return Err(AuthError::InvalidEmail);
        }

        if let Some(ref pw) = req.password {
            if pw.len() > self.service.config().max_password_length {
                return Err(AuthError::PasswordTooLong);
            }
        }

        if self
            .service
            .adapter()
            .find_user_by_email(&email)
            .await?
            .is_some()
        {
            return Err(AuthError::bad_request(
                error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
                "User already exists. Use another email.",
            ));
        }

        let hashed_password = match req.password {
            Some(pw) => Some(crypto::hash_password(pw).await.map_err(AuthError::Crypto)?),
            None => None,
        };

        let image = data_map
            .get("image")
            .and_then(|v| v.as_str())
            .map(String::from);
        let email_verified = data_map
            .get("emailVerified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let created = self
            .service
            .adapter()
            .create_user(CreateUserInput {
                id: None,
                name: req.name,
                email: email.clone(),
                image,
                email_verified,
                role: requested_role.as_ref().map(|r| r.to_csv()),
            })
            .await?;

        let final_role = requested_role
            .map(|r| r.to_csv())
            .unwrap_or_else(|| self.plugin.config.default_role.clone());

        let banned = data_map.get("banned").and_then(|v| v.as_bool());
        let ban_reason = data_map
            .get("banReason")
            .map(|v| v.as_str().map(String::from));
        let ban_expires = data_map.get("banExpires").and_then(|v| {
            v.as_str()
                .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
                .map(Some)
        });

        let updated = self
            .service
            .adapter()
            .update_user_admin(
                &created.id,
                AdminUpdateUserFields {
                    role: Some(final_role),
                    banned,
                    ban_reason,
                    ban_expires,
                    ..Default::default()
                },
            )
            .await?;

        if let Some(pw_hash) = hashed_password {
            self.service
                .adapter()
                .create_account(CreateAccountInput {
                    id: None,
                    user_id: updated.id.clone(),
                    account_id: updated.id.clone(),
                    provider_id: "credential".to_string(),
                    password: Some(pw_hash),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?;
        }

        let wire = updated.to_wire();
        self.service.notify_user_created(&wire).await;

        Ok(AdminUserResponse { user: wire })
    }

    /// `POST /api/auth/admin/update-user`
    pub async fn update_user(
        &self,
        actor: &UserWire,
        req: AdminUpdateUserRequest,
    ) -> Result<UserWire, AuthError> {
        self.check_permission(
            actor,
            "user",
            "update",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS,
            "You are not allowed to update users",
        )?;

        if req.data.is_empty() {
            return Err(AuthError::bad_request(
                error_codes::NO_DATA_TO_UPDATE,
                "No data to update",
            ));
        }

        if req.data.contains_key("password") {
            return Err(AuthError::bad_request(
                error_codes::PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER,
                "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
            ));
        }

        if req.data.contains_key("id") {
            return Err(AuthError::bad_request(
                error_codes::USER_ID_CANNOT_BE_UPDATED,
                "User id cannot be updated",
            ));
        }

        let mut fields = AdminUpdateUserFields::default();

        if let Some(role_val) = req.data.get("role") {
            self.check_permission(
                actor,
                "user",
                "set-role",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE,
                "You are not allowed to change users role",
            )?;
            let rv: RoleValue = serde_json::from_value(role_val.clone()).map_err(|_| {
                AuthError::bad_request(error_codes::INVALID_ROLE_TYPE, "Invalid role type")
            })?;
            let role_list = rv.to_vec();
            self.validate_role_names(&role_list)?;
            fields.role = Some(rv.to_csv());
        }

        if ["banned", "banReason", "banExpires"]
            .iter()
            .any(|k| req.data.contains_key(*k))
        {
            self.check_permission(
                actor,
                "user",
                "ban",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
                "You are not allowed to ban users",
            )?;
            if let Some(b) = req.data.get("banned").and_then(|v| v.as_bool()) {
                if b && req.user_id == actor.id {
                    return Err(AuthError::bad_request(
                        error_codes::YOU_CANNOT_BAN_YOURSELF,
                        "You cannot ban yourself",
                    ));
                }
                fields.banned = Some(b);
            }
            if let Some(reason_val) = req.data.get("banReason") {
                fields.ban_reason = Some(reason_val.as_str().map(String::from));
            }
            if let Some(exp_val) = req.data.get("banExpires") {
                if exp_val.is_null() {
                    fields.ban_expires = Some(None);
                } else if let Some(s) = exp_val.as_str() {
                    if let Ok(dt) = OffsetDateTime::parse(s, &Rfc3339) {
                        fields.ban_expires = Some(Some(dt));
                    }
                }
            }
        }

        if req.data.contains_key("email") || req.data.contains_key("emailVerified") {
            self.check_permission(
                actor,
                "user",
                "set-email",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL,
                "You are not allowed to update users email",
            )?;
            if let Some(email_val) = req.data.get("email").and_then(|v| v.as_str()) {
                let normalized = email_val.trim().to_lowercase();
                if !normalized.contains('@') || !normalized.contains('.') {
                    return Err(AuthError::InvalidEmail);
                }
                if let Some(existing) = self
                    .service
                    .adapter()
                    .find_user_by_email(&normalized)
                    .await?
                {
                    if existing.id != req.user_id {
                        return Err(AuthError::bad_request(
                            error_codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
                            "User already exists. Use another email.",
                        ));
                    }
                }
                fields.email = Some(normalized);
            }
            if let Some(ev) = req.data.get("emailVerified").and_then(|v| v.as_bool()) {
                fields.email_verified = Some(ev);
            }
        }

        if req.data.contains_key("phoneNumber") || req.data.contains_key("phoneNumberVerified") {
            self.check_permission(
                actor,
                "user",
                "set-phone",
                error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PHONE_NUMBER,
                "You are not allowed to update users phone number",
            )?;
        }

        if let Some(name) = req.data.get("name").and_then(|v| v.as_str()) {
            fields.name = Some(name.to_string());
        }
        if let Some(img_val) = req.data.get("image") {
            fields.image = Some(img_val.as_str().filter(|s| !s.is_empty()).map(String::from));
        }

        let updated = self
            .service
            .adapter()
            .update_user_admin(&req.user_id, fields.clone())
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
            })?;

        if fields.banned == Some(true) {
            self.service
                .adapter()
                .delete_sessions_by_user_id(&req.user_id)
                .await?;
        }

        Ok(updated.to_wire())
    }

    /// `GET /api/auth/admin/list-users`
    pub async fn list_users(
        &self,
        actor: &UserWire,
        query: AdminListUsersQuery,
    ) -> Result<AdminListUsersResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "list",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_LIST_USERS,
            "You are not allowed to list users",
        )?;

        let filter = AdminListUsersFilter {
            search_value: query.search_value,
            search_field: query.search_field,
            search_operator: query.search_operator,
            filter_field: query.filter_field,
            filter_value: query.filter_value,
            filter_operator: query.filter_operator,
            sort_by: query.sort_by,
            sort_direction: query.sort_direction,
            limit: query.limit,
            offset: query.offset,
        };

        let (records, total) = self.service.adapter().list_users(filter).await?;
        let users = records.into_iter().map(|u| u.to_wire()).collect();

        Ok(AdminListUsersResponse {
            users,
            total,
            limit: query.limit,
            offset: query.offset,
        })
    }

    /// `POST /api/auth/admin/list-user-sessions`
    pub async fn list_user_sessions(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminListUserSessionsResponse, AuthError> {
        self.check_permission(
            actor,
            "session",
            "list",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS,
            "You are not allowed to list users sessions",
        )?;

        let records = self
            .service
            .adapter()
            .list_sessions_by_user_id(target_user_id)
            .await?;
        Ok(AdminListUserSessionsResponse {
            sessions: records.into_iter().map(|s| s.to_wire()).collect(),
        })
    }

    /// `POST /api/auth/admin/ban-user`
    pub async fn ban_user(
        &self,
        actor: &UserWire,
        req: AdminBanUserRequest,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "ban",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
            "You are not allowed to ban users",
        )?;

        if self
            .service
            .adapter()
            .find_user_by_id(&req.user_id)
            .await?
            .is_none()
        {
            return Err(AuthError::UserNotFound);
        }

        if req.user_id == actor.id {
            return Err(AuthError::bad_request(
                error_codes::YOU_CANNOT_BAN_YOURSELF,
                "You cannot ban yourself",
            ));
        }

        let reason = req
            .ban_reason
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.plugin.config.default_ban_reason.clone());

        let expires = req
            .ban_expires_in
            .or(self.plugin.config.default_ban_expires_in)
            .map(|secs| OffsetDateTime::now_utc() + Duration::seconds(secs));

        let updated = self
            .service
            .adapter()
            .update_user_admin(
                &req.user_id,
                AdminUpdateUserFields {
                    banned: Some(true),
                    ban_reason: Some(Some(reason)),
                    ban_expires: Some(expires),
                    ..Default::default()
                },
            )
            .await?;

        self.service
            .adapter()
            .delete_sessions_by_user_id(&req.user_id)
            .await?;

        Ok(AdminUserResponse {
            user: updated.to_wire(),
        })
    }

    /// `POST /api/auth/admin/unban-user`
    pub async fn unban_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminUserResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "ban",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS,
            "You are not allowed to ban users",
        )?;

        let updated = self
            .service
            .adapter()
            .update_user_admin(
                target_user_id,
                AdminUpdateUserFields {
                    banned: Some(false),
                    ban_reason: Some(None),
                    ban_expires: Some(None),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| match e {
                AdapterError::NotFound => AuthError::UserNotFound,
                other => AuthError::from(other),
            })?;

        Ok(AdminUserResponse {
            user: updated.to_wire(),
        })
    }

    /// `POST /api/auth/admin/impersonate-user`
    pub async fn impersonate_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
        meta: RequestMeta,
    ) -> Result<SessionAndUserResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "impersonate",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS,
            "You are not allowed to impersonate users",
        )?;

        let target = self
            .service
            .adapter()
            .find_user_by_id(target_user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if self
            .plugin
            .config
            .is_admin_user(&target.id, target.role.as_deref())
        {
            let can_impersonate_admins = self.plugin.config.allow_impersonating_admins
                || self.plugin.config.has_permission(
                    Some(&actor.id),
                    actor.role.as_deref(),
                    "user",
                    "impersonate-admins",
                );
            if !can_impersonate_admins {
                return Err(AuthError::forbidden(
                    error_codes::YOU_CANNOT_IMPERSONATE_ADMINS,
                    "You cannot impersonate admins",
                ));
            }
        }

        let raw_token = crypto::generate_session_token();
        let expires_at =
            OffsetDateTime::now_utc() + self.plugin.config.impersonation_session_duration;

        let session = self
            .service
            .adapter()
            .create_impersonated_session(
                CreateSessionInput {
                    id: None,
                    user_id: target.id.clone(),
                    token: raw_token,
                    expires_at,
                    ip_address: meta.ip_address,
                    user_agent: meta.user_agent,
                },
                actor.id.clone(),
            )
            .await?;

        Ok(SessionAndUserResponse {
            session: session.to_wire(),
            user: target.to_wire(),
        })
    }

    /// `POST /api/auth/admin/stop-impersonating`
    pub async fn stop_impersonating(
        &self,
        current_session: &SessionWire,
        admin_token_or_signed: Option<&str>,
    ) -> Result<SessionAndUserResponse, AuthError> {
        let admin_user_id = current_session.impersonated_by.as_ref().ok_or_else(|| {
            AuthError::bad_request("NOT_IMPERSONATING", "You are not impersonating anyone")
        })?;

        let admin_user = self
            .service
            .adapter()
            .find_user_by_id(admin_user_id)
            .await?
            .ok_or_else(|| AuthError::Internal("Failed to find admin user".to_string()))?;

        let tok_str = admin_token_or_signed
            .ok_or_else(|| AuthError::Internal("Failed to find admin session".to_string()))?;

        let clean = tok_str.split(':').next().unwrap_or(tok_str);
        let raw = self
            .service
            .verify_signed_token(clean)
            .ok_or_else(|| AuthError::Internal("Failed to find admin session".to_string()))?;

        let admin_session = match self.service.adapter().find_session_by_token(&raw).await? {
            Some(s) if s.user_id == admin_user.id && !s.is_expired() => s,
            _ => {
                return Err(AuthError::Internal(
                    "Failed to find admin session".to_string(),
                ));
            }
        };

        self.service
            .adapter()
            .delete_session(&current_session.token)
            .await?;

        Ok(SessionAndUserResponse {
            session: admin_session.to_wire(),
            user: admin_user.to_wire(),
        })
    }

    /// `POST /api/auth/admin/revoke-user-session`
    pub async fn revoke_user_session(
        &self,
        actor: &UserWire,
        session_token_or_signed: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.check_permission(
            actor,
            "session",
            "revoke",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS,
            "You are not allowed to revoke users sessions",
        )?;

        let raw_token = self
            .service
            .verify_token(session_token_or_signed)
            .unwrap_or_else(|| session_token_or_signed.to_string());

        self.service.adapter().delete_session(&raw_token).await?;
        Ok(AdminSuccessResponse::ok())
    }

    /// `POST /api/auth/admin/revoke-user-sessions`
    pub async fn revoke_user_sessions(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.check_permission(
            actor,
            "session",
            "revoke",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS,
            "You are not allowed to revoke users sessions",
        )?;

        self.service
            .adapter()
            .delete_sessions_by_user_id(target_user_id)
            .await?;
        Ok(AdminSuccessResponse::ok())
    }

    /// `POST /api/auth/admin/remove-user`
    pub async fn remove_user(
        &self,
        actor: &UserWire,
        target_user_id: &str,
    ) -> Result<AdminSuccessResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "delete",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS,
            "You are not allowed to delete users",
        )?;

        if target_user_id == actor.id {
            return Err(AuthError::bad_request(
                error_codes::YOU_CANNOT_REMOVE_YOURSELF,
                "You cannot remove yourself",
            ));
        }

        if self
            .service
            .adapter()
            .find_user_by_id(target_user_id)
            .await?
            .is_none()
        {
            return Err(AuthError::UserNotFound);
        }

        self.service
            .adapter()
            .delete_sessions_by_user_id(target_user_id)
            .await?;
        self.service.adapter().delete_user(target_user_id).await?;
        self.service.notify_user_deleted(target_user_id).await;

        Ok(AdminSuccessResponse::ok())
    }

    /// `POST /api/auth/admin/set-user-password`
    pub async fn set_user_password(
        &self,
        actor: &UserWire,
        req: AdminSetUserPasswordRequest,
    ) -> Result<StatusResponse, AuthError> {
        self.check_permission(
            actor,
            "user",
            "set-password",
            error_codes::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD,
            "You are not allowed to set users password",
        )?;

        if req.new_password.len() < self.service.config().min_password_length {
            return Err(AuthError::PasswordTooShort);
        }
        if req.new_password.len() > self.service.config().max_password_length {
            return Err(AuthError::PasswordTooLong);
        }

        let user = self
            .service
            .adapter()
            .find_user_by_id(&req.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        let password_hash = crypto::hash_password(req.new_password)
            .await
            .map_err(AuthError::Crypto)?;

        if self
            .service
            .find_credential_account(&user.id)
            .await?
            .is_some()
        {
            self.service
                .adapter()
                .update_account_password(&user.id, &password_hash)
                .await?;
        } else {
            self.service
                .adapter()
                .create_account(CreateAccountInput {
                    id: None,
                    user_id: user.id.clone(),
                    account_id: user.id,
                    provider_id: "credential".to_string(),
                    password: Some(password_hash),
                    access_token: None,
                    refresh_token: None,
                    id_token: None,
                    access_token_expires_at: None,
                    refresh_token_expires_at: None,
                    scope: None,
                })
                .await?;
        }

        Ok(StatusResponse::success())
    }

    /// `POST /api/auth/admin/has-permission`
    pub async fn has_permission(
        &self,
        actor: Option<&UserWire>,
        req: AdminHasPermissionRequest,
    ) -> Result<AdminPermissionResponse, AuthError> {
        let perms = req.permissions.or(req.permission).ok_or_else(|| {
            AuthError::bad_request(
                "INVALID_PERMISSION_CHECK",
                "invalid permission check. no permission(s) were passed.",
            )
        })?;

        let (resolved_user_id, resolved_role) = if let Some(role) = req.role {
            (req.user_id, Some(role))
        } else if let Some(uid) = req.user_id {
            let user = self
                .service
                .adapter()
                .find_user_by_id(&uid)
                .await?
                .ok_or_else(|| {
                    AuthError::bad_request(error_codes::USER_NOT_FOUND, "user not found")
                })?;
            (Some(user.id), user.role)
        } else if let Some(act) = actor {
            (Some(act.id.clone()), act.role.clone())
        } else {
            return Err(AuthError::bad_request(
                "USER_ID_OR_ROLE_REQUIRED",
                "user id or role is required",
            ));
        };

        let connector = match req.connector.as_deref() {
            Some("OR") | Some("or") => Connector::Or,
            _ => Connector::And,
        };

        let success = self.plugin.config.has_permission_map_with_connector(
            resolved_user_id.as_deref(),
            resolved_role.as_deref(),
            &perms,
            connector,
        );

        Ok(AdminPermissionResponse {
            error: None,
            success,
        })
    }
}
