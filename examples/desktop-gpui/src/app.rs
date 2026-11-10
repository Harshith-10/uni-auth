use std::sync::Arc;

use auth_client::{AuthStatus, AuthStore, ClientError};
use auth_proto::{AdminCreateUserRequest, AdminListUsersQuery, RoleValue, SessionWire, UserWire};
use gpui_kit::component::{
    input::{InputEvent, InputState},
    notification::Notification,
    scroll::ScrollableElement as _,
    spinner::Spinner,
    ActiveTheme as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::{
    div, AnyElement, AppContext, Context, Entity, IntoElement, ParentElement as _, Render,
    SharedString, Styled as _, Subscription, Window,
};

use crate::views::{auth::AuthFormView, dashboard::DashboardView};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    SignIn,
    SignUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardTab {
    Overview,
    Admin,
}

pub struct DesktopAuthApp {
    pub store: AuthStore,
    pub server_url: String,
    pub mode: AuthMode,
    pub active_tab: DashboardTab,

    pub name_input: Entity<InputState>,
    pub email_input: Entity<InputState>,
    pub password_input: Entity<InputState>,

    // Admin management inputs
    pub admin_search_input: Entity<InputState>,
    pub admin_new_name_input: Entity<InputState>,
    pub admin_new_email_input: Entity<InputState>,
    pub admin_new_password_input: Entity<InputState>,
    pub admin_new_role: String,

    pub is_submitting: bool,
    pub is_calling_saas: bool,
    pub is_loading_sessions: bool,
    pub is_loading_admin_users: bool,
    pub is_creating_admin_user: bool,
    pub is_raw_json_open: bool,

    pub error_message: Option<SharedString>,
    pub status_message: Option<SharedString>,
    pub saas_me_result: Option<SharedString>,
    pub saas_me_json: Option<serde_json::Value>,
    pub active_sessions: Vec<SessionWire>,
    pub admin_users: Vec<UserWire>,
    pub admin_users_total: usize,

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

        let admin_search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Search users by email..."));
        let admin_new_name_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("New user full name"));
        let admin_new_email_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("newuser@example.com"));
        let admin_new_password_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Initial password"));

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
        let sub_admin_search =
            cx.subscribe_in(&admin_search_input, window, |_, _, event, _, cx| {
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
                if let AuthStatus::Authenticated { user, .. } = app.store.status() {
                    app.refresh_sessions(window, cx);
                    app.call_saas_me(window, cx);
                    if user.role.as_deref() == Some("admin") {
                        app.refresh_admin_users(window, cx);
                    }
                }
                cx.notify();
            });
        })
        .detach();

        Self {
            store,
            server_url,
            mode: AuthMode::SignIn,
            active_tab: DashboardTab::Overview,
            name_input,
            email_input,
            password_input,
            admin_search_input,
            admin_new_name_input,
            admin_new_email_input,
            admin_new_password_input,
            admin_new_role: "user".to_string(),
            is_submitting: false,
            is_calling_saas: false,
            is_loading_sessions: false,
            is_loading_admin_users: false,
            is_creating_admin_user: false,
            is_raw_json_open: false,
            error_message: None,
            status_message: None,
            saas_me_result: None,
            saas_me_json: None,
            active_sessions: Vec::new(),
            admin_users: Vec::new(),
            admin_users_total: 0,
            _subscriptions: vec![sub_name, sub_email, sub_pass, sub_admin_search],
        }
    }

    pub fn set_tab(&mut self, tab: DashboardTab, window: &mut Window, cx: &mut Context<Self>) {
        self.active_tab = tab;
        if tab == DashboardTab::Admin && self.admin_users.is_empty() {
            self.refresh_admin_users(window, cx);
        }
        cx.notify();
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

    pub fn toggle_admin_new_role(&mut self, cx: &mut Context<Self>) {
        self.admin_new_role = if self.admin_new_role == "admin" {
            "user".to_string()
        } else {
            "admin".to_string()
        };
        cx.notify();
    }

    pub fn fill_demo_account(
        &mut self,
        email: &str,
        password: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.mode = AuthMode::SignIn;
        self.error_message = None;
        let email_owned = email.to_string();
        let password_owned = password.to_string();
        self.email_input.update(cx, |input, cx| {
            input.set_value(&email_owned, window, cx);
        });
        self.password_input.update(cx, |input, cx| {
            input.set_value(&password_owned, window, cx);
        });
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

            let result = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.is_submitting = false;
                match result {
                    Ok(()) => {
                        window.push_notification(
                            Notification::success(match mode {
                                AuthMode::SignIn => "Signed in",
                                AuthMode::SignUp => "Account created and signed in",
                            }),
                            cx,
                        );
                        app.active_tab = DashboardTab::Overview;
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                        if let AuthStatus::Authenticated { user, .. } = app.store.status() {
                            if user.role.as_deref() == Some("admin") {
                                app.refresh_admin_users(window, cx);
                            }
                        }
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
                    .fetch_protected::<serde_json::Value>(
                        reqwest::Method::GET,
                        &endpoint_url,
                        None,
                    )
                    .await;
                let _ = tx.send(req_res);
            });

            let req_res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.is_calling_saas = false;
                match req_res {
                    Ok(val) => {
                        let text =
                            serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string());
                        app.saas_me_result = Some(text.into());
                        app.saas_me_json = Some(val);
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

    pub fn refresh_sessions(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_loading_sessions {
            return;
        }

        self.is_loading_sessions = true;
        cx.notify();

        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = client.list_sessions().await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

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

    pub fn revoke_session(
        &mut self,
        session_token: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = client.revoke_session(&session_token).await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(_) => {
                        window.push_notification(Notification::success("Session revoked"), cx);
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Failed to revoke: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn refresh_admin_users(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_loading_admin_users {
            return;
        }

        self.is_loading_admin_users = true;
        let search = self.admin_search_input.read(cx).value().trim().to_string();
        cx.notify();

        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let query = AdminListUsersQuery {
                    search_value: if search.is_empty() {
                        None
                    } else {
                        Some(search)
                    },
                    search_field: Some("email".to_string()),
                    search_operator: Some("contains".to_string()),
                    limit: Some(50),
                    offset: Some(0),
                    sort_by: Some("createdAt".to_string()),
                    sort_direction: Some("desc".to_string()),
                    filter_field: None,
                    filter_value: None,
                    filter_operator: None,
                };
                let res = client.admin_list_users(&query).await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.is_loading_admin_users = false;
                match res {
                    Ok(list) => {
                        app.admin_users_total = list.total;
                        app.admin_users = list.users;
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Admin list users failed: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn admin_create_user(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.is_creating_admin_user {
            return;
        }

        let name = self.admin_new_name_input.read(cx).value().trim().to_string();
        let email = self.admin_new_email_input.read(cx).value().trim().to_string();
        let password = self.admin_new_password_input.read(cx).value().to_string();
        let role = self.admin_new_role.clone();

        if email.is_empty() || password.is_empty() {
            window.push_notification(
                Notification::error("Email and password are required to create a user"),
                cx,
            );
            return;
        }

        let display_name = if name.is_empty() {
            email.split('@').next().unwrap_or("New User").to_string()
        } else {
            name
        };

        self.is_creating_admin_user = true;
        cx.notify();

        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = client
                    .admin_create_user(AdminCreateUserRequest {
                        email,
                        password: Some(password),
                        name: display_name,
                        role: Some(RoleValue::Single(role)),
                        data: None,
                    })
                    .await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.is_creating_admin_user = false;
                match res {
                    Ok(created) => {
                        app.admin_new_name_input.update(cx, |i, cx| {
                            i.set_value("", window, cx);
                        });
                        app.admin_new_email_input.update(cx, |i, cx| {
                            i.set_value("", window, cx);
                        });
                        app.admin_new_password_input.update(cx, |i, cx| {
                            i.set_value("", window, cx);
                        });
                        window.push_notification(
                            Notification::success(format!("Created user {}", created.email)),
                            cx,
                        );
                        app.refresh_admin_users(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Create user failed: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn admin_toggle_role(
        &mut self,
        user_id: String,
        next_role: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = client
                    .admin_set_role(&user_id, RoleValue::Single(next_role))
                    .await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(updated) => {
                        window.push_notification(
                            Notification::success(format!(
                                "Updated {} role to {}",
                                updated.email,
                                updated.role.as_deref().unwrap_or("user")
                            )),
                            cx,
                        );
                        app.refresh_admin_users(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Role update failed: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn admin_toggle_ban(
        &mut self,
        user_id: String,
        currently_banned: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = if currently_banned {
                    client.admin_unban_user(&user_id).await
                } else {
                    client
                        .admin_ban_user(&user_id, Some("Suspended by administrator".into()), None)
                        .await
                };
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(updated) => {
                        let action = if currently_banned {
                            "Unbanned"
                        } else {
                            "Banned"
                        };
                        window.push_notification(
                            Notification::success(format!("{action} {}", updated.email)),
                            cx,
                        );
                        app.refresh_admin_users(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Ban toggle failed: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn admin_impersonate(
        &mut self,
        user_id: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let store = self.store.clone();

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = store.impersonate_user(&user_id).await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(()) => {
                        app.active_tab = DashboardTab::Overview;
                        window.push_notification(
                            Notification::info("Now impersonating selected user"),
                            cx,
                        );
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Impersonation failed: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn stop_impersonating(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let store = self.store.clone();

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = store.stop_impersonating().await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(()) => {
                        window.push_notification(
                            Notification::success("Restored administrator session"),
                            cx,
                        );
                        app.refresh_sessions(window, cx);
                        app.call_saas_me(window, cx);
                        app.refresh_admin_users(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Stop impersonating failed: {e}")),
                            cx,
                        );
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn admin_delete_user(
        &mut self,
        user_id: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let client = Arc::clone(self.store.client());

        cx.spawn_in(window, async move |this, cx| {
            let (tx, rx) = tokio::sync::oneshot::channel();
            crate::spawn_tokio(async move {
                let res = client.admin_remove_user(&user_id).await;
                let _ = tx.send(res);
            });

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(_) => {
                        window.push_notification(Notification::success("User removed"), cx);
                        app.refresh_admin_users(window, cx);
                    }
                    Err(e) => {
                        window.push_notification(
                            Notification::error(format!("Remove user failed: {e}")),
                            cx,
                        );
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
                let res: Result<(), ClientError> =
                    match client.prepare_social_loopback(&provider_string).await {
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

            let res = rx
                .await
                .unwrap_or_else(|_| Err(ClientError::OAuth("Task cancelled".into())));

            let _ = this.update_in(cx, |app, window, cx| {
                app.status_message = None;
                match res {
                    Ok(()) => {
                        window.push_notification(
                            Notification::success("Social sign-in complete!"),
                            cx,
                        );
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
                app.admin_users.clear();
                app.admin_users_total = 0;
                app.active_tab = DashboardTab::Overview;
                window.push_notification(Notification::info("Signed out"), cx);
                cx.notify();
            });
        })
        .detach();
    }
}

fn open_browser(url: &str) -> std::io::Result<()> {
    open::that_detached(url)
}

impl Render for DesktopAuthApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let bg = theme.background;
        let fg = theme.foreground;
        let muted_fg = theme.muted_foreground;

        let content: AnyElement = match self.store.status() {
            AuthStatus::Loading => v_flex()
                .items_center()
                .justify_center()
                .size_full()
                .gap_3()
                .child(Spinner::new())
                .child(
                    div()
                        .text_sm()
                        .text_color(muted_fg)
                        .child("Restoring session from OS keychain..."),
                )
                .into_any_element(),
            AuthStatus::Unauthenticated => div()
                .size_full()
                .overflow_y_scrollbar()
                .child(
                    h_flex()
                        .justify_center()
                        .w_full()
                        .p_6()
                        .child(AuthFormView::render(self, cx)),
                )
                .into_any_element(),
            AuthStatus::Authenticated {
                ref user,
                ref session,
            } => {
                let user_clone = user.clone();
                let session_clone = session.clone();
                div()
                    .size_full()
                    .overflow_y_scrollbar()
                    .child(
                        h_flex().justify_center().w_full().p_6().child(
                            DashboardView::render(self, &user_clone, &session_clone, cx),
                        ),
                    )
                    .into_any_element()
            }
        };

        div().size_full().bg(bg).text_color(fg).child(content)
    }
}
