use auth_proto::{SessionWire, UserWire};
use gpui_kit::base::StyledExt;
use gpui_kit::component::button::ButtonVariants;
use gpui_kit::component::{
    badge::Badge,
    button::Button,
    form::{Field, Form},
    input::Input,
    separator::Separator,
    ActiveTheme as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::{div, AnyElement, Context, IntoElement, ParentElement as _, SharedString, Styled as _};

use crate::app::{DashboardTab, DesktopAuthApp};

pub struct DashboardView;

impl DashboardView {
    pub fn render(
        app: &DesktopAuthApp,
        user: &UserWire,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let warning = cx.theme().warning;
        let radius = cx.theme().radius;

        let role_str = user.role.as_deref().unwrap_or("user");
        let is_admin = role_str.split(',').any(|r| r.trim() == "admin");
        let impersonated_by = session.impersonated_by.clone();

        let tab_content: AnyElement = match app.active_tab {
            DashboardTab::Overview => Self::render_overview(app, user, session, cx).into_any_element(),
            DashboardTab::Admin => Self::render_admin(app, user, cx).into_any_element(),
        };

        v_flex()
            .w_full()
            .gap_6()
            // Top App Header
            .child(
                h_flex()
                    .justify_between()
                    .items_center()
                    .pb_4()
                    .border_b_1()
                    .border_color(border)
                    .child(
                        v_flex()
                            .gap_1()
                            .child(div().text_xl().font_bold().child("uni-auth Desktop"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(muted_fg)
                                    .child("Better-Auth GPUI Native Client"),
                            ),
                    )
                    .child(
                        h_flex()
                            .items_center()
                            .gap_3()
                            .child(Badge::new().child(format!("Role: {role_str}")))
                            .child(
                                Button::new("sign-out-btn")
                                    .danger()
                                    .outline()
                                    .label("Sign Out")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.sign_out(window, cx);
                                    })),
                            ),
                    ),
            )
            // Impersonation Banner
            .when_some(impersonated_by, |this, admin_id| {
                this.child(
                    h_flex()
                        .justify_between()
                        .items_center()
                        .p_4()
                        .rounded(radius)
                        .border_1()
                        .border_color(warning)
                        .bg(muted)
                        .child(
                            v_flex()
                                .gap_1()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_semibold()
                                        .child(format!("Impersonating {} ({})", user.name, user.email)),
                                )
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(muted_fg)
                                        .child(format!("Original Admin User ID: {admin_id}")),
                                ),
                        )
                        .child(
                            Button::new("stop-impersonating-btn")
                                .label("Stop Impersonating")
                                .outline()
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.stop_impersonating(window, cx);
                                })),
                        ),
                )
            })
            // Navigation Tabs
            .child(
                h_flex()
                    .gap_2()
                    .child(if app.active_tab == DashboardTab::Overview {
                        Button::new("nav-overview-btn")
                            .label("Account & Sessions")
                            .on_click(cx.listener(|_, _, _, _| {}))
                    } else {
                        Button::new("nav-overview-btn")
                            .label("Account & Sessions")
                            .outline()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.set_tab(DashboardTab::Overview, window, cx);
                            }))
                    })
                    .when(is_admin, |this| {
                        this.child(if app.active_tab == DashboardTab::Admin {
                            Button::new("nav-admin-btn")
                                .label(format!("Admin Console ({})", app.admin_users_total))
                                .on_click(cx.listener(|_, _, _, _| {}))
                        } else {
                            Button::new("nav-admin-btn")
                                .label(format!("Admin Console ({})", app.admin_users_total))
                                .outline()
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.set_tab(DashboardTab::Admin, window, cx);
                                }))
                        })
                    }),
            )
            .child(tab_content)
    }

    fn render_overview(
        app: &DesktopAuthApp,
        user: &UserWire,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;

        let is_calling_saas = app.is_calling_saas;
        let is_loading_sessions = app.is_loading_sessions;
        let email_verified_str = if user.email_verified { "Yes" } else { "No" };
        let role_str = user.role.as_deref().unwrap_or("user");

        let saas_transport: SharedString = app
            .saas_me_json
            .as_ref()
            .and_then(|j| j.get("transport").and_then(|v| v.as_str()))
            .unwrap_or("Bearer (Native Desktop / GPUI Keychain)")
            .to_string()
            .into();

        let saas_status: SharedString = app
            .saas_me_json
            .as_ref()
            .and_then(|j| j.get("status").and_then(|v| v.as_str()))
            .unwrap_or("authenticated")
            .to_string()
            .into();

        v_flex()
            .gap_6()
            // Profile & Protected SaaS Card
            .child(
                v_flex()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .child(
                        v_flex()
                            .gap_1()
                            .child(
                                div()
                                    .text_lg()
                                    .font_bold()
                                    .child(format!("Welcome, {}!", user.name)),
                            )
                            .child(div().text_sm().text_color(muted_fg).child(user.email.clone())),
                    )
                    .child(Separator::horizontal())
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_semibold()
                                            .child("Protected Endpoint: /api/saas/me"),
                                    )
                                    .child(
                                        h_flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(muted_fg)
                                                    .child("Transport:"),
                                            )
                                            .child(Badge::new().child(saas_transport)),
                                    ),
                            )
                            .child(
                                Button::new("test-saas-btn")
                                    .label(if is_calling_saas {
                                        "Loading..."
                                    } else {
                                        "Refresh"
                                    })
                                    .outline()
                                    .loading(is_calling_saas)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.call_saas_me(window, cx);
                                    })),
                            ),
                    )
                    .child(
                        v_flex()
                            .p_4()
                            .gap_2()
                            .rounded(radius)
                            .bg(muted)
                            .child(
                                h_flex()
                                    .justify_between()
                                    .text_xs()
                                    .child(
                                        h_flex()
                                            .gap_1()
                                            .child(div().text_color(muted_fg).child("Status:"))
                                            .child(div().font_semibold().child(saas_status)),
                                    )
                                    .child(
                                        h_flex()
                                            .gap_1()
                                            .child(div().text_color(muted_fg).child("Role:"))
                                            .child(div().font_semibold().child(role_str.to_string())),
                                    )
                                    .child(
                                        h_flex()
                                            .gap_1()
                                            .child(
                                                div().text_color(muted_fg).child("Email Verified:"),
                                            )
                                            .child(
                                                div().font_semibold().child(email_verified_str),
                                            ),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .justify_between()
                                    .text_xs()
                                    .child(
                                        h_flex()
                                            .gap_1()
                                            .child(div().text_color(muted_fg).child("Session ID:"))
                                            .child(div().font_semibold().child(format!(
                                                "{}...",
                                                &session.id[..12.min(session.id.len())]
                                            ))),
                                    )
                                    .child(
                                        h_flex()
                                            .gap_1()
                                            .child(div().text_color(muted_fg).child("Expires:"))
                                            .child(div().child(session.expires_at.to_string())),
                                    ),
                            ),
                    )
                    .child(
                        v_flex()
                            .gap_2()
                            .child(
                                h_flex()
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_xs()
                                            .font_semibold()
                                            .text_color(muted_fg)
                                            .child("Raw /api/saas/me JSON Payload"),
                                    )
                                    .child(
                                        Button::new("toggle-raw-json-btn")
                                            .label(if app.is_raw_json_open {
                                                "Hide JSON"
                                            } else {
                                                "Show JSON"
                                            })
                                            .outline()
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.toggle_raw_json(cx);
                                            })),
                                    ),
                            )
                            .when(app.is_raw_json_open, |this| {
                                this.child(
                                    div()
                                        .p_3()
                                        .rounded(radius)
                                        .border_1()
                                        .border_color(border)
                                        .bg(muted)
                                        .text_xs()
                                        .child(
                                            app.saas_me_result.clone().unwrap_or_else(|| {
                                                "Click 'Refresh' to fetch /api/saas/me.".into()
                                            }),
                                        ),
                                )
                            }),
                    ),
            )
            // Active Sessions Card
            .child(
                v_flex()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                div()
                                    .text_base()
                                    .font_semibold()
                                    .child(format!("Active Sessions ({})", app.active_sessions.len())),
                            )
                            .child(
                                Button::new("refresh-sessions-btn")
                                    .label(if is_loading_sessions {
                                        "Loading..."
                                    } else {
                                        "Refresh"
                                    })
                                    .outline()
                                    .loading(is_loading_sessions)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.refresh_sessions(window, cx);
                                    })),
                            ),
                    )
                    .child(if app.active_sessions.is_empty() {
                        div()
                            .p_3()
                            .rounded(radius)
                            .bg(muted)
                            .text_xs()
                            .text_color(muted_fg)
                            .child("No active sessions loaded.")
                    } else {
                        v_flex()
                            .gap_2()
                            .children(app.active_sessions.iter().map(|s| {
                                let s_id = s.id.clone();
                                let s_token = s.token.clone();
                                let is_current = s.id == session.id;
                                let ua = s.user_agent.as_deref().unwrap_or("Desktop Native App");
                                let ip = s.ip_address.as_deref().unwrap_or("127.0.0.1");

                                h_flex()
                                    .justify_between()
                                    .items_center()
                                    .p_3()
                                    .rounded(radius)
                                    .border_1()
                                    .border_color(border)
                                    .child(
                                        v_flex()
                                            .gap_1()
                                            .child(
                                                h_flex()
                                                    .items_center()
                                                    .gap_2()
                                                    .child(
                                                        div().font_semibold().text_xs().child(
                                                            format!(
                                                                "Session {}...",
                                                                &s.id[..8.min(s.id.len())]
                                                            ),
                                                        ),
                                                    )
                                                    .when(is_current, |this| {
                                                        this.child(
                                                            Badge::new().child("Current Device"),
                                                        )
                                                    }),
                                            )
                                            .child(div().text_xs().text_color(muted_fg).child(
                                                format!(
                                                    "Agent: {ua} | IP: {ip} | Expires: {}",
                                                    s.expires_at
                                                ),
                                            )),
                                    )
                                    .child(
                                        Button::new(format!("revoke-{s_id}"))
                                            .label("Revoke")
                                            .outline()
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.revoke_session(s_token.clone(), window, cx);
                                            })),
                                    )
                            }))
                    }),
            )
    }

    fn render_admin(
        app: &DesktopAuthApp,
        current_user: &UserWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;

        let create_form = Form::new()
            .child(
                Field::new()
                    .label("Full Name")
                    .child(Input::new(&app.admin_new_name_input)),
            )
            .child(
                Field::new()
                    .label("Email Address")
                    .child(Input::new(&app.admin_new_email_input)),
            )
            .child(
                Field::new()
                    .label("Initial Password")
                    .child(Input::new(&app.admin_new_password_input).mask_toggle()),
            );

        v_flex()
            .gap_6()
            // Create User Card
            .child(
                v_flex()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(div().text_base().font_semibold().child("Create User"))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child("Provision a new user via POST /api/auth/admin/create-user"),
                                    ),
                            )
                            .child(
                                Button::new("admin-role-toggle-btn")
                                    .outline()
                                    .label(format!("Role: {}", app.admin_new_role))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_admin_new_role(cx);
                                    })),
                            ),
                    )
                    .child(create_form)
                    .child(
                        Button::new("admin-create-user-btn")
                            .label("Create User")
                            .loading(app.is_creating_admin_user)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.admin_create_user(window, cx);
                            })),
                    ),
            )
            // User Directory Card
            .child(
                v_flex()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                div()
                                    .text_base()
                                    .font_semibold()
                                    .child(format!("Users Directory ({})", app.admin_users_total)),
                            )
                            .child(
                                Button::new("admin-refresh-users-btn")
                                    .outline()
                                    .loading(app.is_loading_admin_users)
                                    .label("Refresh / Filter")
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.refresh_admin_users(window, cx);
                                    })),
                            ),
                    )
                    .child(Input::new(&app.admin_search_input))
                    .child(if app.admin_users.is_empty() {
                        div()
                            .p_4()
                            .rounded(radius)
                            .bg(muted)
                            .text_xs()
                            .text_color(muted_fg)
                            .child("No users matched. Click 'Refresh / Filter' to reload.")
                    } else {
                        v_flex().gap_2().children(app.admin_users.iter().map(|u| {
                            let u_id = u.id.clone();
                            let u_id_role = u.id.clone();
                            let u_id_ban = u.id.clone();
                            let u_id_imp = u.id.clone();
                            let u_id_del = u.id.clone();

                            let is_self = u.id == current_user.id;
                            let role = u.role.as_deref().unwrap_or("user").to_string();
                            let next_role = if role == "admin" {
                                "user".to_string()
                            } else {
                                "admin".to_string()
                            };
                            let role_action_label = if role == "admin" {
                                "Set User"
                            } else {
                                "Make Admin"
                            };
                            let is_banned = u.banned.unwrap_or(false);
                            let ban_label = if is_banned { "Unban" } else { "Ban" };

                            h_flex()
                                .justify_between()
                                .items_center()
                                .p_3()
                                .rounded(radius)
                                .border_1()
                                .border_color(border)
                                .child(
                                    v_flex()
                                        .gap_1()
                                        .child(
                                            h_flex()
                                                .items_center()
                                                .gap_2()
                                                .child(
                                                    div()
                                                        .font_semibold()
                                                        .text_sm()
                                                        .child(u.name.clone()),
                                                )
                                                .child(Badge::new().child(role))
                                                .when(is_banned, |this| {
                                                    this.child(Badge::new().child("Banned"))
                                                })
                                                .when(is_self, |this| {
                                                    this.child(Badge::new().child("You"))
                                                }),
                                        )
                                        .child(
                                            div().text_xs().text_color(muted_fg).child(format!(
                                                "{} • Verified: {}",
                                                u.email,
                                                if u.email_verified { "Yes" } else { "No" }
                                            )),
                                        )
                                        .when_some(u.ban_reason.as_ref(), |this, reason| {
                                            this.child(
                                                div()
                                                    .text_xs()
                                                    .text_color(muted_fg)
                                                    .child(format!("Ban reason: {reason}")),
                                            )
                                        }),
                                )
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .child(
                                            Button::new(format!("role-{u_id}"))
                                                .outline()
                                                .label(role_action_label)
                                                .on_click(cx.listener(move |this, _, window, cx| {
                                                    this.admin_toggle_role(
                                                        u_id_role.clone(),
                                                        next_role.clone(),
                                                        window,
                                                        cx,
                                                    );
                                                })),
                                        )
                                        .when(!is_self, |this| {
                                            this.child(
                                                Button::new(format!("ban-{u_id}"))
                                                    .outline()
                                                    .label(ban_label)
                                                    .on_click(cx.listener(
                                                        move |this, _, window, cx| {
                                                            this.admin_toggle_ban(
                                                                u_id_ban.clone(),
                                                                is_banned,
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                            )
                                            .when(!is_banned, |this| {
                                                this.child(
                                                    Button::new(format!("imp-{u_id}"))
                                                        .outline()
                                                        .label("Impersonate")
                                                        .on_click(cx.listener(
                                                            move |this, _, window, cx| {
                                                                this.admin_impersonate(
                                                                    u_id_imp.clone(),
                                                                    window,
                                                                    cx,
                                                                );
                                                            },
                                                        )),
                                                )
                                            })
                                            .child(
                                                Button::new(format!("del-{u_id}"))
                                                    .danger()
                                                    .outline()
                                                    .label("Delete")
                                                    .on_click(cx.listener(
                                                        move |this, _, window, cx| {
                                                            this.admin_delete_user(
                                                                u_id_del.clone(),
                                                                window,
                                                                cx,
                                                            );
                                                        },
                                                    )),
                                            )
                                        }),
                                )
                        }))
                    }),
            )
    }
}
