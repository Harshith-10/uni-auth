//! Native Loopback OAuth redirect handler for system-browser login.
//!
//! Spawns an ephemeral HTTP listener on `127.0.0.1:0` to capture browser redirect tokens
//! without requiring custom URL schemes on the host operating system.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::client::{BetterAuthNativeClient, ClientError};

const DEFAULT_LOOPBACK_TIMEOUT: Duration = Duration::from_secs(120);

const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign-in Complete</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      background: #09090b;
      color: #fafafa;
    }
    .card {
      text-align: center;
      padding: 2.5rem 3rem;
      border: 1px solid #27272a;
      border-radius: 12px;
      background: #18181b;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    }
    h2 { margin: 0 0 0.5rem; color: #10b981; }
    p { margin: 0; color: #a1a1aa; font-size: 0.95rem; }
  </style>
</head>
<body>
  <div class="card">
    <h2>✓ Sign-in Complete</h2>
    <p>You can close this tab and return to your application.</p>
  </div>
</body>
</html>"#;

/// Spawns an ephemeral TCP listener on `127.0.0.1:0` and awaits a single OAuth callback
/// with the default 120-second timeout.
///
/// Returns `(port, receiver_channel)`.
pub async fn start_loopback_listener() -> Result<(u16, oneshot::Receiver<Result<String, String>>), std::io::Error> {
    start_loopback_listener_with_timeout(DEFAULT_LOOPBACK_TIMEOUT).await
}

/// Spawns an ephemeral TCP listener on `127.0.0.1:0` and awaits a single OAuth callback
/// bounded by `timeout` so abandoned browser tabs do not leave dangling listeners.
pub async fn start_loopback_listener_with_timeout(
    timeout: Duration,
) -> Result<(u16, oneshot::Receiver<Result<String, String>>), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut tx = Some(tx);
        match tokio::time::timeout(timeout, listener.accept()).await {
            Ok(Ok((mut stream, _))) => {
                let mut buf = [0u8; 4096];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await
                {
                    let req_text = String::from_utf8_lossy(&buf[..n]);

                    // Extract query parameters from GET /auth/callback?token=... HTTP/1.1
                    if let Some(first_line) = req_text.lines().next() {
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let path_and_query = parts[1];
                            if let Some((_, query)) = path_and_query.split_once('?') {
                                let mut token_found = None;
                                let mut error_found = None;

                                for param in query.split('&') {
                                    if let Some((k, v)) = param.split_once('=') {
                                        if k == "token" {
                                            token_found = Some(v.to_string());
                                        } else if k == "error" {
                                            error_found = Some(v.to_string());
                                        }
                                    }
                                }

                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    SUCCESS_HTML.len(),
                                    SUCCESS_HTML
                                );
                                let _ = stream.write_all(response.as_bytes()).await;
                                let _ = stream.flush().await;

                                if let Some(sender) = tx.take() {
                                    if let Some(token) = token_found {
                                        let _ = sender.send(Ok(token));
                                    } else if let Some(err) = error_found {
                                        let _ = sender.send(Err(err));
                                    } else {
                                        let _ = sender.send(Err("No token found in callback".to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                if let Some(sender) = tx.take() {
                    let _ = sender.send(Err(format!("Loopback listener accept error: {e}")));
                }
            }
            Err(_) => {
                if let Some(sender) = tx.take() {
                    let _ = sender.send(Err("Loopback OAuth listener timed out".to_string()));
                }
            }
        }
    });

    Ok((port, rx))
}

impl BetterAuthNativeClient {
    /// Executes the full native system-browser OAuth login flow:
    ///
    /// 1. Binds an ephemeral local loopback listener.
    /// 2. Requests an authorization URL from `POST /api/auth/sign-in/social`.
    /// 3. Returns the authorization URL so the caller (or UI) can launch the system browser.
    /// 4. Awaits browser redirect with the one-time token.
    /// 5. Automatically exchanges the OTT for a permanent session and stores it in secure storage.
    pub async fn prepare_social_loopback(
        &self,
        provider: &str,
    ) -> Result<(String, oneshot::Receiver<Result<String, String>>), ClientError> {
        let (port, rx) = start_loopback_listener()
            .await
            .map_err(|e| ClientError::OAuth(format!("Failed to bind loopback listener: {e}")))?;

        let callback_url = format!("http://127.0.0.1:{port}/auth/callback");

        let res = self
            .http
            .post(format!("{}/sign-in/social", self.base_url))
            .json(&serde_json::json!({
                "provider": provider,
                "callbackURL": callback_url,
                "disableRedirect": true
            }))
            .send()
            .await?;

        let status = res.status().as_u16();
        if status >= 400 {
            return Err(ClientError::OAuth(format!("Social sign-in initiation failed with HTTP {status}")));
        }

        let body: serde_json::Value = res.json().await?;
        let auth_url = body
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ClientError::OAuth("Missing 'url' in social sign-in response".to_string()))?
            .to_string();

        Ok((auth_url, rx))
    }
}
