//! Email sending abstraction for verification and password reset flows.

use crate::adapter::BoxFuture;
use std::sync::{Arc, Mutex};

pub trait EmailSender: Send + Sync {
    fn send_verification_email(
        &self,
        to: &str,
        url: &str,
        token: &str,
    ) -> BoxFuture<'static, Result<(), String>>;

    fn send_password_reset_email(
        &self,
        to: &str,
        url: &str,
        token: &str,
    ) -> BoxFuture<'static, Result<(), String>>;
}

/// No-op email sender that logs to tracing.
pub struct NoopEmailSender;

impl EmailSender for NoopEmailSender {
    fn send_verification_email(
        &self,
        to: &str,
        url: &str,
        _token: &str,
    ) -> BoxFuture<'static, Result<(), String>> {
        let to = to.to_string();
        let url = url.to_string();
        Box::pin(async move {
            tracing::info!(to = %to, url = %url, "Verification email sent (noop)");
            Ok(())
        })
    }

    fn send_password_reset_email(
        &self,
        to: &str,
        url: &str,
        _token: &str,
    ) -> BoxFuture<'static, Result<(), String>> {
        let to = to.to_string();
        let url = url.to_string();
        Box::pin(async move {
            tracing::info!(to = %to, url = %url, "Password reset email sent (noop)");
            Ok(())
        })
    }
}

/// Mock email sender recording sent emails for test assertions.
#[derive(Default, Clone)]
pub struct MockEmailSender {
    pub sent_verifications: Arc<Mutex<Vec<(String, String, String)>>>,
    pub sent_password_resets: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl MockEmailSender {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EmailSender for MockEmailSender {
    fn send_verification_email(
        &self,
        to: &str,
        url: &str,
        token: &str,
    ) -> BoxFuture<'static, Result<(), String>> {
        let list = Arc::clone(&self.sent_verifications);
        let entry = (to.to_string(), url.to_string(), token.to_string());
        Box::pin(async move {
            if let Ok(mut l) = list.lock() {
                l.push(entry);
            }
            Ok(())
        })
    }

    fn send_password_reset_email(
        &self,
        to: &str,
        url: &str,
        token: &str,
    ) -> BoxFuture<'static, Result<(), String>> {
        let list = Arc::clone(&self.sent_password_resets);
        let entry = (to.to_string(), url.to_string(), token.to_string());
        Box::pin(async move {
            if let Ok(mut l) = list.lock() {
                l.push(entry);
            }
            Ok(())
        })
    }
}
