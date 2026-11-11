//! Unified HTTP transport and interceptor pipeline modeled on Better Auth's `better-fetch`.
//!
//! Provides automated Bearer authorization header injection, `set-auth-token` interception,
//! plugin request/response lifecycle hooks, structured error decoding, and reactive signal emission.

use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::client::{BetterAuthNativeClient, ClientError};
use auth_proto::AuthErrorResponse;

/// Context passed to `AuthClientPlugin::on_request` hooks before transmission.
#[derive(Debug, Clone)]
pub struct ClientRequestContext {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
}

/// Context passed to `AuthClientPlugin::on_response` hooks after receiving headers.
#[derive(Debug, Clone)]
pub struct ClientResponseContext {
    pub path: String,
    pub status: u16,
    pub headers: HeaderMap,
}

impl BetterAuthNativeClient {
    /// Unified request executor with automated Bearer injection, `set-auth-token` capture,
    /// plugin middleware execution, structured error decoding, and `$sessionSignal` notification.
    pub async fn send_auth_request<Q, B, Res>(
        &self,
        method: Method,
        path: &str,
        query: Option<&Q>,
        body: Option<&B>,
    ) -> Result<Res, ClientError>
    where
        Q: Serialize + ?Sized,
        B: Serialize + ?Sized,
        Res: DeserializeOwned,
    {
        let mut ctx = ClientRequestContext {
            method: method.clone(),
            path: path.to_string(),
            headers: self.prepare_headers(),
        };

        // 1. Run plugin `on_request` hooks (e.g. AdminClientPlugin injecting `x-admin-auth-token`)
        for plugin in &self.plugins {
            plugin.on_request(&mut ctx)?;
        }

        let url = format!("{}{}", self.base_url, path);
        let mut req_builder = self.http.request(method, &url).headers(ctx.headers);
        if let Some(q) = query {
            req_builder = req_builder.query(q);
        }
        if let Some(b) = body {
            req_builder = req_builder.json(b);
        }

        let res = req_builder.send().await?;
        let status = res.status().as_u16();
        let res_headers = res.headers().clone();

        // 2. Always capture `set-auth-token` across ALL endpoints (including `/change-password` and `/verify-email`)
        self.handle_auth_token_header(&res_headers);

        // 3. Run plugin `on_response` hooks (e.g. AdminClientPlugin stashing `set-admin-auth-token`)
        let res_ctx = ClientResponseContext {
            path: path.to_string(),
            status,
            headers: res_headers,
        };
        for plugin in &self.plugins {
            plugin.on_response(&res_ctx)?;
        }

        // 4. Unified error decoding
        if status >= 400 {
            let err_body: AuthErrorResponse = res.json().await.unwrap_or_else(|_| {
                AuthErrorResponse::new("REQUEST_FAILED", format!("Request to {path} failed"))
                    .with_status(status)
            });
            return Err(ClientError::Api {
                status,
                code: err_body.code,
                message: err_body.message,
            });
        }

        let parsed: Res = res.json().await?;

        // 5. Notify reactive signal listeners (`$sessionSignal` or plugin-defined signals)
        self.notify_matching_signals(path).await;

        Ok(parsed)
    }
}
