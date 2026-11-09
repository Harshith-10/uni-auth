use std::sync::Arc;
use auth_client::{AuthStore, BetterAuthNativeClient, KeyringTokenStorage};
use desktop_gpui::{tokio_handle, DesktopAuthApp};
use gpui_kit::{AppContext, WindowOptions};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Initialize dedicated Tokio multi-threaded runtime for background HTTP/OAuth operations
    let _guard = tokio_handle().enter();

    let server_url = std::env::var("AUTH_SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let auth_base_url = format!("{}/api/auth", server_url.trim_end_matches('/'));

    tracing::info!("Starting uni-auth GPUI Desktop App targeting {}", auth_base_url);

    // Initialize OS Keyring token storage
    let storage = Arc::new(KeyringTokenStorage::new(
        "com.uni-auth.desktop",
        "session_token",
    ));
    let client = Arc::new(BetterAuthNativeClient::new(auth_base_url, storage));
    let store = AuthStore::new(client);

    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);

            let store_clone = store.clone();
            let server_url_clone = server_url.clone();

            gpui_kit::open_window(WindowOptions::default(), cx, move |window, cx| {
                cx.new(|cx| DesktopAuthApp::new(store_clone, server_url_clone, window, cx))
            })
            .expect("failed to open desktop window");
        });
}
