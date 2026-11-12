//! Plugin registry managing registered plugin instances, endpoint hooks, and downcasting.

use std::sync::Arc;

use super::{
    AuthPlugin, DatabaseHooks, EndpointHookContext, PluginMigration, PluginRateLimitRule,
};
use crate::error::AuthError;
use crate::service::AuthService;

/// Thread-safe registry of plugin extensions.
#[derive(Default, Clone)]
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn AuthPlugin>>,
}

impl PluginRegistry {
    /// Creates an empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Registers a plugin, replacing any existing plugin with the same `id()`.
    pub fn register(&mut self, plugin: Arc<dyn AuthPlugin>) {
        let id = plugin.id();
        if let Some(existing) = self.plugins.iter_mut().find(|p| p.id() == id) {
            *existing = plugin;
        } else {
            self.plugins.push(plugin);
        }
    }

    /// Removes a plugin by `id`, returning `true` if it was present.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.plugins.len();
        self.plugins.retain(|p| p.id() != id);
        self.plugins.len() != before
    }

    /// Checks whether a plugin with `id` is registered.
    pub fn has(&self, id: &str) -> bool {
        self.plugins.iter().any(|p| p.id() == id)
    }

    /// Returns a slice of all registered plugins.
    pub fn plugins(&self) -> &[Arc<dyn AuthPlugin>] {
        &self.plugins
    }

    /// Finds and downcasts a registered plugin to its concrete type.
    pub fn get<P: AuthPlugin + 'static>(&self) -> Option<&P> {
        self.plugins
            .iter()
            .find_map(|p| p.as_any().downcast_ref::<P>())
    }

    /// Collects all `DatabaseHooks` instances from registered plugins.
    pub fn database_hooks(&self) -> Vec<Arc<dyn DatabaseHooks>> {
        self.plugins
            .iter()
            .filter_map(|p| p.database_hooks())
            .collect()
    }

    /// Collects declarative migrations from registered plugins.
    pub fn migrations(&self) -> Vec<PluginMigration> {
        self.plugins.iter().filter_map(|p| p.migration()).collect()
    }

    /// Collects rate limit rules from registered plugins.
    pub fn rate_limits(&self) -> Vec<PluginRateLimitRule> {
        self.plugins.iter().flat_map(|p| p.rate_limits()).collect()
    }

    /// Executes `on_before_endpoint` hooks matching the given endpoint path.
    pub async fn run_before_endpoint(
        &self,
        ctx: &mut EndpointHookContext,
        service: &AuthService,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            if plugin.matches_before(&ctx.path) {
                plugin.on_before_endpoint(ctx, service).await?;
            }
        }
        Ok(())
    }

    /// Executes `on_after_endpoint` hooks matching the given endpoint path.
    pub async fn run_after_endpoint(
        &self,
        ctx: &mut EndpointHookContext,
        service: &AuthService,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            if plugin.matches_after(&ctx.path) {
                plugin.on_after_endpoint(ctx, service).await?;
            }
        }
        Ok(())
    }
}
