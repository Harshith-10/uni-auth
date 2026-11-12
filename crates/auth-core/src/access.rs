//! Shared resource-action Access Control engine for auth plugins (`admin` and `organization`).

use std::collections::HashMap;
use time::Duration;

use crate::error::AuthError;
pub use auth_proto::access::{AccessControl, Connector, RolePermissions};

/// Configuration for the `admin` plugin.
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// Default role assigned to newly created users. Default: `"user"`.
    pub default_role: String,

    /// Roles considered administrative. Default: `["admin"]`.
    pub admin_roles: Vec<String>,

    /// Explicit list of user IDs granted full admin permissions regardless of role.
    pub admin_user_ids: Vec<String>,

    /// Default ban reason when none is provided. Default: `"No reason"`.
    pub default_ban_reason: String,

    /// Default ban duration in seconds (`None` means permanent ban).
    pub default_ban_expires_in: Option<i64>,

    /// Error message returned when a banned user attempts to sign in.
    pub banned_user_message: String,

    /// Lifetime of an impersonation session. Default: 1 hour.
    pub impersonation_session_duration: Duration,

    /// Whether admins are allowed to impersonate other admins. Default: `false`.
    pub allow_impersonating_admins: bool,

    /// Role-based access control definitions.
    pub ac: AccessControl,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            default_role: "user".to_string(),
            admin_roles: vec!["admin".to_string()],
            admin_user_ids: Vec::new(),
            default_ban_reason: "No reason".to_string(),
            default_ban_expires_in: None,
            banned_user_message: "You have been banned from this application. Please contact support if you believe this is an error.".to_string(),
            impersonation_session_duration: Duration::hours(1),
            allow_impersonating_admins: false,
            ac: AccessControl::default_admin(),
        }
    }
}

impl AdminConfig {
    /// Validates that all configured `admin_roles` exist in `ac.roles` (case-insensitive).
    pub fn validate(&self) -> Result<(), AuthError> {
        for admin_role in &self.admin_roles {
            let exists = self
                .ac
                .roles()
                .keys()
                .any(|r| r.eq_ignore_ascii_case(admin_role));
            if !exists {
                return Err(AuthError::Internal(format!(
                    "AdminConfig validation error: admin_role '{admin_role}' is not defined in AccessControl roles"
                )));
            }
        }
        Ok(())
    }

    /// Evaluates whether a user (by `user_id` and/or comma-separated `role_csv`) has all requested permissions.
    pub fn has_permission_map(
        &self,
        user_id: Option<&str>,
        role_csv: Option<&str>,
        permissions: &HashMap<String, Vec<String>>,
    ) -> bool {
        self.has_permission_map_with_connector(user_id, role_csv, permissions, Connector::And)
    }

    /// Evaluates whether a user has requested permissions using the specified `connector` (`And` or `Or`).
    pub fn has_permission_map_with_connector(
        &self,
        user_id: Option<&str>,
        role_csv: Option<&str>,
        permissions: &HashMap<String, Vec<String>>,
        connector: Connector,
    ) -> bool {
        if let Some(uid) = user_id {
            if self.admin_user_ids.iter().any(|id| id == uid) {
                return true;
            }
        }
        if permissions.is_empty() {
            return false;
        }
        let roles_str = role_csv.unwrap_or(&self.default_role);
        for role_name in roles_str
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Some(role_def) = self.ac.get_role(role_name) {
                if role_def.authorize_with_connector(permissions, connector) {
                    return true;
                }
            }
        }
        false
    }

    /// Convenience helper checking a single `(resource, action)` requirement.
    pub fn has_permission(
        &self,
        user_id: Option<&str>,
        role_csv: Option<&str>,
        resource: &str,
        action: &str,
    ) -> bool {
        let mut map = HashMap::new();
        map.insert(resource.to_string(), vec![action.to_string()]);
        self.has_permission_map(user_id, role_csv, &map)
    }

    /// Returns `true` if the target user has an admin role or is listed in `admin_user_ids`.
    pub fn is_admin_user(&self, user_id: &str, role_csv: Option<&str>) -> bool {
        if self.admin_user_ids.iter().any(|id| id == user_id) {
            return true;
        }
        let roles_str = role_csv.unwrap_or(&self.default_role);
        roles_str
            .split(',')
            .map(str::trim)
            .any(|r| self.admin_roles.iter().any(|ar| ar == r))
    }
}
