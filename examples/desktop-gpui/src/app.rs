use std::sync::Arc;
use auth_client::{AuthStatus, AuthStore, ClientError};
use auth_proto::SessionWire;
use gpui_kit::component::{
    scroll::ScrollableElement as _,
    WindowExt as _,
    input::{InputEvent, InputState},
    notification::Notification,
    spinner::Spinner,
};
use gpui_kit::{
    div, rgb, AnyElement, AppContext, Context, Entity, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, Subscription, Window,
};

use crate::views::{auth::AuthFormView, dashboard::DashboardView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    SignIn,
    SignUp,
}

pub struct DesktopAuthApp {
    pub store: AuthStore,
    pub server_url: String,
    pub mode: AuthMode,

    pub name_input: Entity<InputState>,
    pub email_input: Entity<InputState>,
    pub password_input: Entity<InputState>,

    pub is_submitting: bool,
    pub is_calling_saas: bool,
    pub is_loading_sessions: bool,
    pub is_raw_json_open: bool,

    pub error_message: Option<SharedString>,
    pub status_message: Option<SharedString>,
    pub saas_me_result: Option<SharedString>,
    pub saas_me_json: Option<serde_json::Value>,
    pub active_sessions: Vec<SessionWire>,

    _subscriptions: Vec<Subscription>,
}

impl DesktopAuthApp {
    pub fn new(
        store: AuthStore,
        server_url: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name_input = cx.new(|cx| InputState::new(window, cx).placeholder("Full Name"));
        let email_input = cx.new(|cx| InputState::new(window, cx).placeholder("user@example.com"));
        let password_input = cx.new(|cx| InputState::new(window, cx).placeholder("••••••••"));

        let sub_name = cx.subscribe_in(&name_input, window, |_, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        });
        let sub_email = cx.subscribe_in(&email_input, window, |_, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        });
        let sub_pass = cx.subscribe_in(&password_input, window, |_, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        });

        // Trigger session restoration on startup
        let store_clone = store.clone();
        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let _ = store_clone.restore_session().await;
                let _ = tx.send(());
            });
            let _ = rx.await;

            let _ = this.update_in(cx, |app, window, cx| {
                if let AuthStatus::Authenticated { .. } = app.store.status() {
                    app.refresh_sessions(window, cx);
                    app.call_saas_me(window, cx);
                }
                cx.notify();
            });
        })
        .detach();

        Self {
            store,
            server_url,
            mode: AuthMode::SignIn,
            name_input,
            email_input,
            password_input,
            is_submitting: false,
            is_calling_saas: false,
            is_loading_sessions: false,
            is_raw_json_open: false,
            error_message: None,
            status_message: None,
            saas_me_result: None,
            saas_me_json: None,
            active_sessions: Vec::new(),
            _subscriptions: vec![sub_name, sub_email, sub_pass],
        }
    }

    pub fn toggle_raw_json(&mut self, cx: &mut Context<Self>) {
        self.is_raw_json_open = !self.is_raw_json_open;
        cx.notify();
    }

    pub fn toggle_mode(&mut self, cx: &mut Context<Self>) {
        self.mode = match self.mode {
            AuthMode::SignIn => AuthMode::SignUp,
            AuthMode::SignUp => AuthMode::SignIn,
        };
        self.error_message = None;
        self.status_message = None;
        cx.notify();
    }

    pub fn submit_form(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_submitting {
            return;
        }

        let email = self.email_input.read(cx).value().to_string();
        let password = self.password_input.read(cx).value().to_string();
        let name = self.name_input.read(cx).value().to_string();

        if email.trim().is_empty() || password.trim().is_empty() {
            self.error_message = Some("Please fill in all required fields".into());
            cx.notify();
            return;
        }

        self.is_submitting = true;
        self.error_message = None;
        self.status_message = None;
        cx.notify();

        let store = self.store.clone();
        let mode = self.mode;

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let result = match mode {
                    AuthMode::SignIn => store.sign_in_email(email, password, Some(true)).await,
                    AuthMode::SignUp => {
                        let display_name = if name.trim().is_empty() {
                            "GPUI User".to_string()
                        } else {
                            name
                        };
                        store
                            .sign_up_email(display_name, email, password, Some(true))
                            .await
                    }
                };
                let _ = tx.send(result);
            });

            let result = rx.await.unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.is_submitting = false;
                match result {
                    Ok(()) => {
                        window.push_notification(
                            Notification::success(match mode {
                                AuthMode::SignIn => "Successfully signed in!",
                                AuthMode::SignUp => "Account created and signed in!",
                            }),
                            cx,
                        );
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        app.error_message = Some(err_str.clone().into());
                        window.push_notification(Notification::error(err_str), cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn call_saas_me(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_calling_saas {
            return;
        }

        self.is_calling_saas = true;
        cx.notify();

        let client = Arc::clone(self.store.client());
        let server_url = self.server_url.clone();

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let endpoint_url = format!("{}/api/saas/me", server_url.trim_end_matches('/'));

            crate::spawn_tokio(async move {
                let req_res = client
                    .fetch_protected::<serde_json::Value>(reqwest::Method::GET, &endpoint_url, None)
                    .await;
                let _ = tx.send(req_res);
            });

            let req_res = rx.await.unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.is_calling_saas = false;
                match req_res {
                    Ok(val) => {
                        let text = serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string());
                        app.saas_me_result = Some(text.into());
                        app.saas_me_json = Some(val);
                        window.push_notification(Notification::info("Received response from /api/saas/me"), cx);
                    }
                    Err(e) => {
                        let err_str = format!("Request failed: {e}");
                        app.saas_me_result = Some(err_str.clone().into());
                        app.saas_me_json = None;
                        window.push_notification(Notification::error(err_str), cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn refresh_sessions(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.is_loading_sessions {
            return;
        }

        self.is_loading_sessions = true;
        cx.notify();

        let client = Arc::clone(self.store.client());

        cx.spawn_in(_window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = client.list_sessions().await;
                let _ = tx.send(res);
            });

            let res = rx.await.unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, _, cx| {
                app.is_loading_sessions = false;
                if let Ok(sessions) = res {
                    app.active_sessions = sessions;
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn revoke_session(&mut self, session_id: String, window: &mut Window, cx: &mut Context<Self>) {
        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let s_id = session_id.clone();
            crate::spawn_tokio(async move {
                let res = client.revoke_session(&s_id).await;
                let _ = tx.send(res);
            });

            let res = rx.await.unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(_) => {
                        window.push_notification(Notification::success("Session revoked"), cx);
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(Notification::error(format!("Failed to revoke: {e}")), cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn social_login(&mut self, provider: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.status_message = Some(format!("Opening browser for {provider} login...").into());
        cx.notify();

        let client = Arc::clone(self.store.client());
        let store = self.store.clone();
        let provider_string = provider.to_string();

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res: Result<(), ClientError> = match client.prepare_social_loopback(&provider_string).await {
                    Ok((auth_url, rx_loopback)) => {
                        let _ = open_browser(&auth_url);
                        match rx_loopback.await {
                            Ok(Ok(ott)) => match client.verify_one_time_token(&ott).await {
                                Ok(_) => {
                                    let _ = store.restore_session().await;
                                    Ok(())
                                }
                                Err(e) => Err(e),
                            },
                            Ok(Err(e)) => Err(ClientError::OAuth(e)),
                            Err(e) => Err(ClientError::OAuth(e.to_string())),
                        }
                    }
                    Err(e) => Err(e),
                };
                let _ = tx.send(res);
            });

            let res = rx.await.unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.status_message = None;
                match res {
                    Ok(()) => {
                        window.push_notification(Notification::success("Social sign-in complete!"), cx);
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                    }
                    Err(e) => {
                        let err = format!("Social sign-in error: {e}");
                        app.error_message = Some(err.clone().into());
                        window.push_notification(Notification::error(err), cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn sign_out(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let store = self.store.clone();

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let _ = store.sign_out().await;
                let _ = tx.send(());
            });
            let _ = rx.await;

            let _ = this.update_in(cx, |app, window, cx| {
                app.saas_me_result = None;
                app.saas_me_json = None;
                app.active_sessions.clear();
                window.push_notification(Notification::info("Signed out successfully"), cx);
                cx.notify();
            });
        })
        .detach();
    }
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

impl Render for DesktopAuthApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content: AnyElement = match self.store.status() {
            AuthStatus::Loading => div()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .size_full()
                .gap_4()
                .bg(rgb(0x0f172a))
                .text_color(rgb(0xf8fafc))
                .child(Spinner::new())
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(0x94a3b8))
                        .child("Checking saved session from OS keychain..."),
                )
                .into_any_element(),
            AuthStatus::Unauthenticated => div()
                .size_full()
                .overflow_y_scrollbar()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .items_center()
                        .justify_center()
                        .w_full()
                        .p_8()
                        .child(AuthFormView::render(self, cx)),
                )
                .into_any_element(),
            AuthStatus::Authenticated { ref user, ref session } => {
                let user_clone = user.clone();
                let session_clone = session.clone();
                div()
                    .size_full()
                    .overflow_y_scrollbar()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_center()
                            .w_full()
                            .p_8()
                            .child(DashboardView::render(self, &user_clone, &session_clone, cx)),
                    )
                    .into_any_element()
            }
        };

        div().size_full().bg(rgb(0x0f172a)).child(content)
    }
}
