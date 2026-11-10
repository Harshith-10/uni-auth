//! Shared resource-action Access Control engine for Better Auth plugins (`admin` and `organization`).
//!
//! Matches upstream `@better-auth/src/plugins/access` and `plugins/admin/access/statement.ts`.

use std::collections::{HashMap, HashSet};
use time::Duration;

/// Resource-to-actions permission map for a single role.
#[derive(Debug, Clone, Default)]
pub struct RolePermissions {
    statements: HashMap<String, HashSet<String>>,
}

impl RolePermissions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_resource<I, S>(mut self, resource: impl Into<String>, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.statements.insert(
            resource.into(),
            actions.into_iter().map(Into::into).collect(),
        );
        self
    }

    /// Returns `true` if this role grants all requested actions on every requested resource.
    pub fn authorize(&self, requested: &HashMap<String, Vec<String>>) -> bool {
        for (resource, actions) in requested {
            let Some(allowed) = self.statements.get(resource) else {
                return false;
            };
            for action in actions {
                if !allowed.contains(action) {
                    return false;
                }
            }
        }
        true
    }
}

/// Registry of named roles and their resource-action permissions.
#[derive(Debug, Clone, Default)]
pub struct AccessControl {
    roles: HashMap<String, RolePermissions>,
}

impl AccessControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs the default Better Auth `admin` plugin role hierarchy (`admin` and `user`).
    ///
    /// Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/access/statement.ts`
    pub fn default_admin() -> Self {
        let admin_role = RolePermissions::new()
            .with_resource(
                "user",
                [
                    "create",
                    "list",
                    "set-role",
                    "ban",
                    "impersonate",
                    "delete",
                    "set-password",
                    "set-email",
                    "set-phone",
                    "get",
                    "update",
                ],
            )
            .with_resource("session", ["list", "revoke", "delete"]);

        let user_role = RolePermissions::new()
            .with_resource("user", Vec::<&str>::new())
            .with_resource("session", Vec::<&str>::new());

        let mut roles = HashMap::new();
        roles.insert("admin".to_string(), admin_role);
        roles.insert("user".to_string(), user_role);
        Self { roles }
    }

    pub fn with_role(mut self, name: impl Into<String>, role: RolePermissions) -> Self {
        self.roles.insert(name.into(), role);
        self
    }

    pub fn has_role(&self, name: &str) -> bool {
        self.roles.contains_key(name)
    }

    pub fn get_role(&self, name: &str) -> Option<&RolePermissions> {
        self.roles.get(name)
    }
}

/// Configuration for the Better Auth `admin` plugin.
///
/// Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/admin.ts` lines 38-67
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
    /// Evaluates whether a user (by `user_id` and/or comma-separated `role_csv`) has all requested permissions.
    ///
    /// Reference: `.reference/better-auth/packages/better-auth/src/plugins/admin/has-permission.ts`
    pub fn has_permission_map(
        &self,
        user_id: Option<&str>,
        role_csv: Option<&str>,
        permissions: &HashMap<String, Vec<String>>,
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
        for role_name in roles_str.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(role_def) = self.ac.get_role(role_name) {
                if role_def.authorize(permissions) {
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
