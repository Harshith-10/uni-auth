//! Lifecycle event hooks, sliding-window rate limiting, and background session cleanup.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use auth_proto::{SessionWire, UserWire};

use crate::adapter::{AuthAdapter, BoxFuture};
use crate::error::AuthError;

/// Async lifecycle hooks emitted by `AuthService` on key authentication events.
pub trait AuthHooks: Send + Sync {
    fn on_user_created(&self, _user: &UserWire) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn on_session_created(
        &self,
        _session: &SessionWire,
        _user: &UserWire,
    ) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn on_password_reset(&self, _user_id: &str) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn on_email_verified(&self, _user: &UserWire) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn on_user_deleted(&self, _user_id: &str) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

/// Default no-op lifecycle hooks implementation.
#[derive(Debug, Default, Clone)]
pub struct NoopAuthHooks;

impl AuthHooks for NoopAuthHooks {}

/// Thread-safe sliding-window rate limiter keyed by `(client_key, bucket_scope)`.
#[derive(Clone)]
pub struct SlidingWindowRateLimiter {
    window: StdDuration,
    max_requests: usize,
    buckets: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl SlidingWindowRateLimiter {
    /// Creates a new sliding-window rate limiter allowing `max_requests` per `window`.
    pub fn new(max_requests: usize, window: StdDuration) -> Self {
        Self {
            window,
            max_requests,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Checks and records a request for `key`. Returns `Err(AuthError::RateLimitExceeded)` if over limit.
    pub fn check(&self, key: &str) -> Result<(), AuthError> {
        let now = Instant::now();
        let window = self.window;
        let mut guard = self
            .buckets
            .lock()
            .map_err(|e| AuthError::Internal(format!("Rate limiter lock poisoned: {e}")))?;

        let timestamps = guard.entry(key.to_string()).or_default();
        timestamps.retain(|&t| now.duration_since(t) < window);

        if timestamps.len() >= self.max_requests {
            return Err(AuthError::RateLimitExceeded);
        }

        timestamps.push(now);
        Ok(())
    }
}

/// Spawns a background Tokio task that periodically purges expired sessions and verification tokens.
pub fn spawn_expired_cleanup_worker(
    adapter: Arc<dyn AuthAdapter>,
    interval: StdDuration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let _ = adapter.delete_expired_sessions().await;
            let _ = adapter.delete_expired_verifications().await;
        }
    })
}
