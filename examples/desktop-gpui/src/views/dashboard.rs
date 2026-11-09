use auth_proto::{SessionWire, UserWire};
use gpui_kit::base::StyledExt;
use gpui_kit::component::button::ButtonVariants;
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::component::{
    badge::Badge,
    button::Button,
    scroll::ScrollableElement as _,
};
use gpui_kit::{
    div, px, rgb, Context, InteractiveElement as _, IntoElement, ParentElement as _, SharedString,
    Styled as _,
};

use crate::app::DesktopAuthApp;

pub struct DashboardView;

impl DashboardView {
    pub fn render(
        app: &DesktopAuthApp,
        user: &UserWire,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let is_calling_saas = app.is_calling_saas;
        let is_loading_sessions = app.is_loading_sessions;

        let email_verified_str = if user.email_verified { "Yes" } else { "No" };

        let saas_transport: SharedString = app.saas_me_json.as_ref()
            .and_then(|j| j.get("transport").and_then(|v| v.as_str()))
            .unwrap_or("Bearer (Native Desktop / GPUI Keychain)")
            .to_string()
            .into();

        let saas_status: SharedString = app.saas_me_json.as_ref()
            .and_then(|j| j.get("status").and_then(|v| v.as_str()))
            .unwrap_or("authenticated")
            .to_string()
            .into();

        div()
            .flex()
            .flex_col()
            .w(px(680.))
            .gap_6()
            // Top App Header matching Web React demo
            .child(
                div()
                    .flex()
                    .flex_col()
                    .pb_4()
                    .border_b_1()
                    .border_color(rgb(0x334155))
                    .gap_1()
                    .child(
                        div()
                            .text_2xl()
                            .font_bold()
                            .text_color(rgb(0x38bdf8))
                            .child("uni-auth Desktop Demo"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x94a3b8))
                            .child("Better-Auth GPUI Native Client running against Rust Axum Backend"),
                    ),
            )
            // Welcome & Account Card (Slate 800)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_6()
                    .gap_5()
                    .rounded_xl()
                    .border_1()
                    .border_color(rgb(0x334155))
                    .bg(rgb(0x1e293b))
                    .shadow_xl()
                    // Welcome row with Sign Out button
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        div()
                                            .text_xl()
                                            .font_bold()
                                            .text_color(rgb(0xf8fafc))
                                            .child(format!("Welcome, {}!", user.name)),
                                    )
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(rgb(0x94a3b8))
                                            .child(user.email.clone()),
                                    ),
                            )
                            .child(
                                Button::new("sign-out-btn")
                                    .danger()
                                    .label("Sign Out")
                                    .outline()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.sign_out(window, cx);
                                    })),
                            ),
                    )
                    // Protected SaaS API Response Section (matching Web React)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .p_4()
                            .gap_3()
                            .rounded_lg()
                            .border_1()
                            .border_color(rgb(0x334155))
                            .bg(rgb(0x0f172a))
                            // Header row with status dot and Refresh button
                            .child(
                                div()
                                    .flex()
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .w(px(8.))
                                                    .h(px(8.))
                                                    .rounded_full()
                                                    .bg(rgb(0x10b981)),
                                            )
                                            .child(
                                                div()
                                                    .font_semibold()
                                                    .text_sm()
                                                    .text_color(rgb(0x38bdf8))
                                                    .child("Protected API: /api/saas/me"),
                                            ),
                                    )
                                    .child(
                                        Button::new("test-saas-btn")
                                            .label(if is_calling_saas { "Loading..." } else { "Refresh" })
                                            .outline()
                                            .loading(is_calling_saas)
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.call_saas_me(window, cx);
                                            })),
                                    ),
                            )
                            // Transport pill badge
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(0x94a3b8))
                                            .child("Transport:"),
                                    )
                                    .child(
                                        div()
                                            .px_2()
                                            .py_1()
                                            .rounded_md()
                                            .bg(rgb(0x1e3a8a))
                                            .border_1()
                                            .border_color(rgb(0x2563eb))
                                            .text_xs()
                                            .font_semibold()
                                            .text_color(rgb(0x60a5fa))
                                            .child(saas_transport),
                                    ),
                            )
                            // 2-column Properties Grid
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .p_3()
                                    .gap_2()
                                    .rounded_md()
                                    .bg(rgb(0x1e293b))
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .text_xs()
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap_1()
                                                    .child(div().text_color(rgb(0x64748b)).child("Status: "))
                                                    .child(div().font_semibold().text_color(rgb(0x10b981)).child(saas_status)),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap_1()
                                                    .child(div().text_color(rgb(0x64748b)).child("Email Verified: "))
                                                    .child(div().font_semibold().text_color(if user.email_verified { rgb(0x10b981) } else { rgb(0xf59e0b) }).child(email_verified_str)),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .text_xs()
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap_1()
                                                    .child(div().text_color(rgb(0x64748b)).child("Session ID: "))
                                                    .child(div().font_semibold().text_color(rgb(0xcbd5e1)).child(format!("{}...", &session.id[..12.min(session.id.len())]))),
                                            )
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap_1()
                                                    .child(div().text_color(rgb(0x64748b)).child("Expires: "))
                                                    .child(div().text_color(rgb(0xcbd5e1)).child(session.expires_at.to_string())),
                                            ),
                                    ),
                            )
                            // Collapsible Raw Server Response JSON Block (matching Web React <details>/<summary>)
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .rounded_md()
                                    .bg(rgb(0x020617))
                                    .border_1()
                                    .border_color(rgb(0x1e293b))
                                    .child(
                                        div()
                                            .id("toggle-raw-json-summary")
                                            .flex()
                                            .items_center()
                                            .justify_between()
                                            .p_3()
                                            .cursor_pointer()
                                            .on_mouse_down(gpui_kit::MouseButton::Left, cx.listener(|this, _, _, cx| {
                                                this.toggle_raw_json(cx);
                                            }))
                                            .child(
                                                div()
                                                    .flex()
                                                    .items_center()
                                                    .gap_2()
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(rgb(0x64748b))
                                                            .child(if app.is_raw_json_open { "▼" } else { "▶" }),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .font_semibold()
                                                            .text_color(rgb(0x94a3b8))
                                                            .child("View Raw Server Response JSON"),
                                                    ),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(rgb(0x64748b))
                                                    .child(if app.is_raw_json_open { "Click to collapse" } else { "Click to expand" }),
                                            ),
                                    )
                                    .when(app.is_raw_json_open, |this| {
                                        this.child(
                                            div()
                                                .p_3()
                                                .border_t_1()
                                                .border_color(rgb(0x1e293b))
                                                .max_h(px(240.))
                                                .overflow_y_scrollbar()
                                                .child(
                                                    if let Some(res) = &app.saas_me_result {
                                                        div()
                                                            .text_xs()
                                                            .text_color(rgb(0xa5f3fc))
                                                            .child(res.clone())
                                                    } else {
                                                        div()
                                                            .text_xs()
                                                            .text_color(rgb(0x64748b))
                                                            .child("No data loaded. Click 'Refresh' to query /api/saas/me.")
                                                    },
                                                ),
                                        )
                                    }),
                            ),
                    )
                    // Active Sessions Section (matching Web React)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .child(
                                div()
                                    .flex()
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_base()
                                            .font_semibold()
                                            .text_color(rgb(0xf8fafc))
                                            .child(format!("Active Sessions ({})", app.active_sessions.len())),
                                    )
                                    .child(
                                        Button::new("refresh-sessions-btn")
                                            .label(if is_loading_sessions { "Loading..." } else { "Refresh" })
                                            .outline()
                                            .loading(is_loading_sessions)
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.refresh_sessions(window, cx);
                                            })),
                                    ),
                            )
                            .child(
                                if app.active_sessions.is_empty() {
                                    div()
                                        .p_3()
                                        .rounded_md()
                                        .bg(rgb(0x0f172a))
                                        .text_xs()
                                        .text_color(rgb(0x64748b))
                                        .child("No sessions loaded. Click 'Refresh' to query active sessions.")
                                } else {
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_2()
                                        .children(app.active_sessions.iter().map(|s| {
                                            let s_id = s.id.clone();
                                            let s_token = s.token.clone();
                                            let is_current = s.id == session.id;
                                            let ua = s.user_agent.as_deref().unwrap_or("Desktop Native App");
                                            let ip = s.ip_address.as_deref().unwrap_or("127.0.0.1");

                                            div()
                                                .flex()
                                                .justify_between()
                                                .items_center()
                                                .p_3()
                                                .rounded_lg()
                                                .border_1()
                                                .border_color(if is_current {
                                                    rgb(0x0284c7)
                                                } else {
                                                    rgb(0x334155)
                                                })
                                                .bg(rgb(0x0f172a))
                                                .child(
                                                    div()
                                                        .flex()
                                                        .flex_col()
                                                        .gap_1()
                                                        .child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_2()
                                                                .child(
                                                                    div()
                                                                        .font_semibold()
                                                                        .text_xs()
                                                                        .text_color(rgb(0xf8fafc))
                                                                        .child(format!("ID: {}...", &s.id[..8.min(s.id.len())])),
                                                                )
                                                                .when(is_current, |this| {
                                                                    this.child(
                                                                        Badge::new().child("Current Device (Native Desktop)"),
                                                                    )
                                                                }),
                                                        )
                                                        .child(
                                                            div()
                                                                .text_xs()
                                                                .text_color(rgb(0x64748b))
                                                                .child(format!("User Agent: {} | IP: {} | Expires: {}", ua, ip, s.expires_at)),
                                                        ),
                                                )
                                                .child(
                                                    Button::new(format!("revoke-{}", s_id))
                                                        .label("Revoke")
                                                        .outline()
                                                        .on_click(cx.listener(move |this, _, window, cx| {
                                                            this.revoke_session(s_token.clone(), window, cx);
                                                        })),
                                                )
                                        }))
                                },
                            ),
                    ),
            )
    }
}
