//! Shared resource-action Access Control engine for auth plugins (`admin` and `organization`).

use std::collections::{HashMap, HashSet};

/// Logical connector used for evaluating multi-permission requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Connector {
    #[default]
    And,
    Or,
}

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
        self.authorize_with_connector(requested, Connector::And)
    }

    /// Evaluates requested resource-action permissions against this role using `connector` (`And` or `Or`).
    pub fn authorize_with_connector(
        &self,
        requested: &HashMap<String, Vec<String>>,
        connector: Connector,
    ) -> bool {
        if requested.is_empty() {
            return true;
        }
        match connector {
            Connector::And => {
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
            Connector::Or => {
                for (resource, actions) in requested {
                    if let Some(allowed) = self.statements.get(resource) {
                        for action in actions {
                            if allowed.contains(action) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
        }
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

    /// Constructs the default `admin` plugin role hierarchy (`admin` and `user`).
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

    pub fn roles(&self) -> &HashMap<String, RolePermissions> {
        &self.roles
    }
}
