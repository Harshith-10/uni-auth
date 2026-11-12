//! One-Time Token (OTT) client plugin for cross-platform desktop/browser authentication handoff.

use reqwest::Method;

use auth_proto::{OneTimeTokenGenerateResponse, OneTimeTokenVerifyRequest, SessionAndUserResponse};

use crate::client::{AuthClient, ClientError};
use crate::plugin::{AuthClientPlugin, ClientSignalListener, SESSION_SIGNAL};

/// Client plugin for one-time token workflows.
#[derive(Debug, Clone, Default)]
pub struct OneTimeTokenClientPlugin;

impl AuthClientPlugin for OneTimeTokenClientPlugin {
    fn id(&self) -> &'static str {
        "one-time-token-client"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn signal_listeners(&self) -> Vec<ClientSignalListener> {
        vec![ClientSignalListener {
            signal: SESSION_SIGNAL,
            matcher: |path| path == "/one-time-token/verify",
        }]
    }
}

/// One-time token namespace handle returned by `client.one_time_token()`.
pub struct OneTimeTokenClientHandle<'a> {
    client: &'a AuthClient,
}

impl<'a> OneTimeTokenClientHandle<'a> {
    /// `GET /api/auth/one-time-token/generate`
    pub async fn generate(&self) -> Result<OneTimeTokenGenerateResponse, ClientError> {
        self.client
            .send_auth_request(
                Method::GET,
                "/one-time-token/generate",
                None::<&()>,
                None::<&()>,
            )
            .await
    }

    /// `POST /api/auth/one-time-token/verify`
    pub async fn verify(
        &self,
        token: impl Into<String>,
    ) -> Result<SessionAndUserResponse, ClientError> {
        let res: SessionAndUserResponse = self
            .client
            .send_auth_request(
                Method::POST,
                "/one-time-token/verify",
                None::<&()>,
                Some(&OneTimeTokenVerifyRequest {
                    token: token.into(),
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
}

/// Extension trait granting access to the `client.one_time_token()` handle.
pub trait OneTimeTokenClientExt {
    fn one_time_token(&self) -> OneTimeTokenClientHandle<'_>;
}

impl OneTimeTokenClientExt for AuthClient {
    fn one_time_token(&self) -> OneTimeTokenClientHandle<'_> {
        OneTimeTokenClientHandle { client: self }
    }
}
