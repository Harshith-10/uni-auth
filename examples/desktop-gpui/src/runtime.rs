//! Background Tokio runtime manager for GPUI-Kit desktop application.
//!
//! Provides a dedicated multi-threaded runtime for reqwest HTTP requests and OAuth loopback servers,
//! isolating asynchronous network I/O from GPUI's UI thread and foreground render scheduler.

use std::sync::OnceLock;
use tokio::runtime::{Handle, Runtime};

static TOKIO_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Returns a reference to the global Tokio runtime handle for background I/O.
///
/// Ensures a multi-threaded Tokio 1.x runtime with timer and I/O reactors is initialized,
/// allowing GPUI foreground and worker threads to spawn async background tasks safely.
pub fn tokio_handle() -> &'static Handle {
    TOKIO_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("desktop-tokio-worker")
                .build()
                .expect("Failed to initialize background Tokio runtime")
        })
        .handle()
}

/// Spawns an async future on the background Tokio runtime.
///
/// Can be safely invoked from any thread, including the GPUI main thread and foreground render loops,
/// without relying on thread-local runtime contexts.
pub fn spawn_tokio<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio_handle().spawn(future)
}
