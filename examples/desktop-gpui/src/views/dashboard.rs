use auth_proto::{SessionWire, UserWire};
use gpui_kit::base::StyledExt;
use gpui_kit::component::button::ButtonVariants;
use gpui_kit::component::dialog::{
    Dialog, DialogAction, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
};
use gpui_kit::component::menu::{DropdownMenu, PopupMenuItem};
use gpui_kit::component::{
    alert::Alert,
    avatar::Avatar,
    button::Button,
    form::Field,
    input::Input,
    table::{Table, TableBody, TableCell, TableHead, TableHeader, TableRow},
    tag::Tag,
    ActiveTheme as _, Icon, IconName, Sizable as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::{
    div, px, Anchor, AnyElement, App, ClickEvent, ClipboardItem, Context, InteractiveElement as _,
    IntoElement, ParentElement as _, SharedString, StatefulInteractiveElement as _, Styled as _,
    Window,
};

use crate::app::{DashboardTab, DesktopAuthApp};

pub struct DashboardView;

impl DashboardView {
    fn format_time(dt: &time::OffsetDateTime) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
        )
    }

    pub fn render(
        app: &DesktopAuthApp,
        user: &UserWire,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let card_bg = cx.theme().background;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;

        let role_str = user.role.as_deref().unwrap_or("user");
        let is_admin = role_str.split(',').any(|r| r.trim() == "admin");
        let impersonated_by = session.impersonated_by.clone();

        let tab_content: AnyElement = match app.active_tab {
            DashboardTab::Overview => Self::render_overview(app, user, session, cx).into_any_element(),
            DashboardTab::Sessions => Self::render_sessions(app, session, cx).into_any_element(),
            DashboardTab::Admin => Self::render_admin(app, user, cx).into_any_element(),
            DashboardTab::Diagnostics => Self::render_diagnostics(app, session, cx).into_any_element(),
        };

        let app_view = cx.entity().clone();

        v_flex()
            .w_full()
            .max_w(px(940.))
            .gap_6()
            // Impersonation Banner
            .when_some(impersonated_by, |this, admin_id| {
                this.child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            Alert::warning(
                                "impersonation-alert",
                                format!(
                                    "Operating under identity {} ({}). Initiating Admin ID: {}",
                                    user.name, user.email, admin_id
                                ),
                            )
                            .title("Active Administrator Impersonation"),
                        )
                        .child(
                            Button::new("stop-impersonating-btn")
                                .warning()
                                .small()
                                .outline()
                                .label("Exit Impersonation")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.stop_impersonating(window, cx);
                                })),
                        ),
                )
            })
            // 4 Top KPI Metric Cards Grid
            .child(
                h_flex()
                    .gap_3()
                    .w_full()
                    // 1. Account Identity
                    .child(
                        div()
                            .flex_1()
                            .p_4()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_2()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().font_medium().text_color(muted_fg).child("Account Identity"))
                                            .child(if user.email_verified {
                                                Tag::success().small().outline().child("Verified")
                                            } else {
                                                Tag::warning().small().outline().child("Unverified")
                                            }),
                                    )
                                    .child(
                                        h_flex()
                                            .gap_2()
                                            .items_center()
                                            .min_w_0()
                                            .overflow_hidden()
                                            .child(Avatar::new().name(&user.name).small())
                                            .child(
                                                v_flex()
                                                    .min_w_0()
                                                    .overflow_hidden()
                                                    .gap_0()
                                                    .child(
                                                        div()
                                                            .font_bold()
                                                            .text_xs()
                                                            .whitespace_nowrap()
                                                            .text_ellipsis()
                                                            .overflow_hidden()
                                                            .child(user.name.clone()),
                                                    )
                                                    .child(
                                                        div()
                                                            .text_xs()
                                                            .text_color(muted_fg)
                                                            .whitespace_nowrap()
                                                            .text_ellipsis()
                                                            .overflow_hidden()
                                                            .child(user.email.clone()),
                                                    ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child(format!("UID: {}...", &user.id[..10.min(user.id.len())])),
                                    ),
                            ),
                    )
                    // 2. Role & Permissions
                    .child(
                        div()
                            .flex_1()
                            .p_4()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_2()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().font_medium().text_color(muted_fg).child("Role & Access"))
                                            .child(if is_admin {
                                                Tag::primary().small().child("admin")
                                            } else {
                                                Tag::secondary().small().child("user")
                                            }),
                                    )
                                    .child(
                                        div()
                                            .font_bold()
                                            .text_sm()
                                            .child(if is_admin { "Administrator" } else { "Standard Member" }),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child(if is_admin { "Full admin API privileges" } else { "Tenant standard profile" }),
                                    ),
                            ),
                    )
                    // 3. Session Transport
                    .child(
                        div()
                            .flex_1()
                            .p_4()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_2()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().font_medium().text_color(muted_fg).child("Auth Transport"))
                                            .child(Tag::info().small().outline().child("Keyring Bearer")),
                                    )
                                    .child(
                                        div()
                                            .font_bold()
                                            .text_sm()
                                            .child("OS Keychain Token"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child(format!("SID: {}...", &session.id[..10.min(session.id.len())])),
                                    ),
                            ),
                    )
                    // 4. Connected Devices
                    .child(
                        div()
                            .flex_1()
                            .p_4()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_2()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().font_medium().text_color(muted_fg).child("Active Devices"))
                                            .child(
                                                Button::new("manage-devices-btn")
                                                    .ghost()
                                                    .small()
                                                    .label("Manage")
                                                    .on_click(cx.listener(|this, _, window, cx| {
                                                        this.set_tab(DashboardTab::Sessions, window, cx);
                                                    })),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .font_bold()
                                            .text_sm()
                                            .child(format!("{} Active", app.active_sessions.len())),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child("Cross-client sessions"),
                                    ),
                            ),
                    ),
            )
            // Main Navigation Tabs Bar matching Web App (Image 0)
            .child(
                div()
                    .w_full()
                    .p_1()
                    .rounded(radius)
                    .bg(muted)
                    .border_1()
                    .border_color(border)
                    .child(
                        h_flex()
                            .gap_1()
                            .items_center()
                            // Tab 1: Overview & Security
                            .child({
                                let app_ov = app_view.clone();
                                Self::render_tab_trigger(
                                    "nav-overview-btn",
                                    IconName::LayoutDashboard,
                                    "Overview & Security",
                                    app.active_tab == DashboardTab::Overview,
                                    move |_, window, cx| {
                                        app_ov.update(cx, |this, cx| {
                                            this.set_tab(DashboardTab::Overview, window, cx);
                                        });
                                    },
                                    cx,
                                )
                            })
                            // Tab 2: Active Sessions (N)
                            .child({
                                let app_sess = app_view.clone();
                                Self::render_tab_trigger(
                                    "nav-sessions-btn",
                                    IconName::Network,
                                    format!("Active Sessions ({})", app.active_sessions.len()),
                                    app.active_tab == DashboardTab::Sessions,
                                    move |_, window, cx| {
                                        app_sess.update(cx, |this, cx| {
                                            this.set_tab(DashboardTab::Sessions, window, cx);
                                        });
                                    },
                                    cx,
                                )
                            })
                            // Tab 3: Admin Console (N)
                            .when(is_admin, |this| {
                                let app_adm = app_view.clone();
                                this.child(Self::render_tab_trigger(
                                    "nav-admin-btn",
                                    IconName::CircleUser,
                                    format!("Admin Console ({})", app.admin_users_total),
                                    app.active_tab == DashboardTab::Admin,
                                    move |_, window, cx| {
                                        app_adm.update(cx, |this, cx| {
                                            this.set_tab(DashboardTab::Admin, window, cx);
                                        });
                                    },
                                    cx,
                                ))
                            })
                            // Tab 4: API Diagnostics
                            .child({
                                let app_diag = app_view.clone();
                                Self::render_tab_trigger(
                                    "nav-diagnostics-btn",
                                    IconName::SquareTerminal,
                                    "API Diagnostics",
                                    app.active_tab == DashboardTab::Diagnostics,
                                    move |_, window, cx| {
                                        app_diag.update(cx, |this, cx| {
                                            this.set_tab(DashboardTab::Diagnostics, window, cx);
                                        });
                                    },
                                    cx,
                                )
                            }),
                    ),
            )
            // Active Tab Content
            .child(tab_content)
    }

    fn render_tab_trigger(
        id: &'static str,
        icon: IconName,
        label: impl Into<SharedString>,
        active: bool,
        on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
        cx: &Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let card_bg = cx.theme().background;
        let border = cx.theme().border;
        let muted_fg = cx.theme().muted_foreground;
        let fg = cx.theme().foreground;
        let radius = cx.theme().radius;
        let label_str = label.into();

        let base = div()
            .id(id)
            .px_3()
            .py_1p5()
            .rounded(radius)
            .font_medium()
            .text_xs()
            .flex()
            .items_center()
            .gap_1p5()
            .cursor_pointer();

        if active {
            base.bg(card_bg)
                .text_color(fg)
                .border_1()
                .border_color(border)
                .shadow_sm()
                .child(Icon::new(icon).small().text_color(cx.theme().primary))
                .child(label_str)
        } else {
            base.text_color(muted_fg)
                .hover(move |s| s.text_color(fg).bg(card_bg.opacity(0.4)))
                .child(Icon::new(icon).small())
                .child(label_str)
                .on_click(on_click)
        }
    }

    fn render_overview(
        app: &DesktopAuthApp,
        user: &UserWire,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let card_bg = cx.theme().background;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;

        let is_calling_saas = app.is_calling_saas;
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
            .w_full()
            .gap_6()
            // Profile & Protected SaaS Verification Card
            .child(
                v_flex()
                    .w_full()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .bg(card_bg)
                    .shadow_sm()
                    // Card Header with Refresh Action
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                v_flex()
                                    .gap_0p5()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_semibold()
                                            .child("Protected Endpoint Verification (/api/saas/me)"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child("Validates Bearer token propagation, role claims, and user identity in Rust Axum"),
                                    ),
                            )
                            .child(
                                Button::new("test-saas-btn")
                                    .label(if is_calling_saas {
                                        "Loading..."
                                    } else {
                                        "Refresh /api/saas/me"
                                    })
                                    .small()
                                    .outline()
                                    .loading(is_calling_saas)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.call_saas_me(window, cx);
                                    })),
                            ),
                    )
                    // 4-Parameter Status Summary Row
                    .child(
                        h_flex()
                            .gap_3()
                            .p_3()
                            .rounded(radius)
                            .bg(muted)
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Transport"))
                                            .child(Tag::secondary().small().outline().child(saas_transport)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Status"))
                                            .child(div().text_xs().font_semibold().child(saas_status)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Role"))
                                            .child(div().text_xs().font_semibold().child(role_str.to_string())),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Email Verified"))
                                            .child(div().text_xs().font_semibold().child(email_verified_str)),
                                    ),
                            ),
                    )
                    // Session Details Display
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .p_2p5()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .text_xs()
                            .child(
                                h_flex()
                                    .min_w_0()
                                    .overflow_hidden()
                                    .gap_2()
                                    .child(div().text_color(muted_fg).flex_shrink_0().child("Session ID:"))
                                    .child(
                                        div()
                                            .min_w_0()
                                            .overflow_hidden()
                                            .whitespace_nowrap()
                                            .text_ellipsis()
                                            .child(session.id.clone()),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .flex_shrink_0()
                                    .gap_2()
                                    .child(div().text_color(muted_fg).child("Expires:"))
                                    .child(div().child(Self::format_time(&session.expires_at))),
                            ),
                    ),
            )
    }

    fn render_sessions(
        app: &DesktopAuthApp,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let card_bg = cx.theme().background;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;
        let is_loading_sessions = app.is_loading_sessions;

        v_flex()
            .w_full()
            .gap_6()
            // Active Sessions Card
            .child(
                v_flex()
                    .w_full()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .bg(card_bg)
                    .shadow_sm()
                    // Card Header with Refresh
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                v_flex()
                                    .gap_0p5()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_semibold()
                                            .child(format!("Active Sessions ({})", app.active_sessions.len())),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child("Manage devices currently signed into your account"),
                                    ),
                            )
                            .child(
                                Button::new("refresh-sessions-btn")
                                    .label(if is_loading_sessions {
                                        "Loading..."
                                    } else {
                                        "Refresh Sessions"
                                    })
                                    .small()
                                    .outline()
                                    .loading(is_loading_sessions)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.refresh_sessions(window, cx);
                                    })),
                            ),
                    )
                    // Sessions Table
                    .child(if app.active_sessions.is_empty() {
                        div()
                            .p_6()
                            .rounded(radius)
                            .bg(muted)
                            .text_xs()
                            .text_color(muted_fg)
                            .text_center()
                            .child("No active sessions loaded.")
                            .into_any_element()
                    } else {
                        Table::new()
                            .w_full()
                            .child(
                                TableHeader::new().child(
                                    TableRow::new()
                                        .child(TableHead::new().w(px(130.)).min_w(px(130.)).flex_shrink_0().child("Session ID"))
                                        .child(TableHead::new().min_w(px(160.)).child("Client Device / User Agent"))
                                        .child(TableHead::new().w(px(150.)).min_w(px(150.)).flex_shrink_0().child("Expires"))
                                        .child(TableHead::new().w(px(120.)).min_w(px(120.)).flex_shrink_0().child("Status"))
                                        .child(TableHead::new().w(px(90.)).min_w(px(90.)).flex_shrink_0().text_right().child("Action")),
                                ),
                            )
                            .child(
                                TableBody::new().children(app.active_sessions.iter().map(|s| {
                                    let s_id = s.id.clone();
                                    let s_token = s.token.clone();
                                    let is_current = s.id == session.id;
                                    let ua = s.user_agent.as_deref().unwrap_or("Desktop Native App");
                                    let ip = s.ip_address.as_deref().unwrap_or("127.0.0.1");
                                    let exp_date = Self::format_time(&s.expires_at);

                                    TableRow::new()
                                        .child(
                                            TableCell::new()
                                                .w(px(130.))
                                                .min_w(px(130.))
                                                .flex_shrink_0()
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .whitespace_nowrap()
                                                        .text_ellipsis()
                                                        .text_xs()
                                                        .child(format!("{}...", &s.id[..8.min(s.id.len())])),
                                                ),
                                        )
                                        .child(
                                            TableCell::new()
                                                .min_w(px(160.))
                                                .child(
                                                    v_flex()
                                                        .w_full()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .gap_0()
                                                        .child(
                                                            div()
                                                                .w_full()
                                                                .min_w_0()
                                                                .overflow_hidden()
                                                                .font_medium()
                                                                .text_xs()
                                                                .whitespace_nowrap()
                                                                .text_ellipsis()
                                                                .child(ua.to_string()),
                                                        )
                                                        .child(
                                                            div()
                                                                .w_full()
                                                                .min_w_0()
                                                                .overflow_hidden()
                                                                .text_xs()
                                                                .text_color(muted_fg)
                                                                .whitespace_nowrap()
                                                                .text_ellipsis()
                                                                .child(format!("IP: {ip}")),
                                                        ),
                                                ),
                                        )
                                        .child(
                                            TableCell::new()
                                                .w(px(150.))
                                                .min_w(px(150.))
                                                .flex_shrink_0()
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .whitespace_nowrap()
                                                        .text_ellipsis()
                                                        .text_xs()
                                                        .text_color(muted_fg)
                                                        .child(exp_date),
                                                ),
                                        )
                                        .child(
                                            TableCell::new()
                                                .w(px(120.))
                                                .min_w(px(120.))
                                                .flex_shrink_0()
                                                .child(if is_current {
                                                    Tag::primary().small().child("Current Device")
                                                } else {
                                                    Tag::success().small().outline().child("Active")
                                                }),
                                        )
                                        .child(
                                            TableCell::new()
                                                .w(px(90.))
                                                .min_w(px(90.))
                                                .flex_shrink_0()
                                                .text_right()
                                                .child(
                                                    Button::new(format!("revoke-{s_id}"))
                                                        .label("Revoke")
                                                        .danger()
                                                        .small()
                                                        .outline()
                                                        .on_click(cx.listener(move |this, _, window, cx| {
                                                            this.revoke_session(s_token.clone(), window, cx);
                                                        })),
                                                ),
                                        )
                                })),
                            )
                            .into_any_element()
                    }),
            )
    }

    fn render_admin(
        app: &DesktopAuthApp,
        current_user: &UserWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let card_bg = cx.theme().background;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;

        let admin_count = app.admin_users.iter().filter(|u| u.role.as_deref() == Some("admin")).count();
        let banned_count = app.admin_users.iter().filter(|u| u.banned.unwrap_or(false)).count();
        let verified_count = app.admin_users.iter().filter(|u| u.email_verified).count();

        // Create User Modal Dialog (matching Image 2)
        let create_dialog = Dialog::new(cx)
            .trigger(
                Button::new("admin-open-create-user-dialog")
                    .primary()
                    .small()
                    .icon(IconName::Plus)
                    .label("New User"),
            )
            .overlay(true)
            .close_button(true)
            .overlay_closable(true)
            .content({
                let app_view = cx.entity().clone();
                let name_input = app.admin_new_name_input.clone();
                let email_input = app.admin_new_email_input.clone();
                let pass_input = app.admin_new_password_input.clone();
                let is_creating = app.is_creating_admin_user;
                let role = app.admin_new_role.clone();

                move |content, _, cx| {
                    let primary_color = cx.theme().primary;
                    let radius = cx.theme().radius;

                    content
                        .w(px(460.))
                        .child(
                            DialogHeader::new()
                                .p_5()
                                .child(
                                    h_flex()
                                        .gap_2p5()
                                        .items_center()
                                        .child(
                                            div()
                                                .p_1p5()
                                                .rounded(radius)
                                                .bg(primary_color.opacity(0.15))
                                                .text_color(primary_color)
                                                .child(Icon::new(IconName::CircleUser).small()),
                                        )
                                        .child(
                                            v_flex()
                                                .gap_0p5()
                                                .child(DialogTitle::new().child("Create New User"))
                                                .child(
                                                    DialogDescription::new().child(
                                                        "Provision an account directly via Better-Auth Admin API",
                                                    ),
                                                ),
                                        ),
                                ),
                        )
                        .child(
                            v_flex()
                                .px_5()
                                .pb_5()
                                .gap_3()
                                .child(
                                    Field::new()
                                        .label("Full Name")
                                        .child(Input::new(&name_input)),
                                )
                                .child(
                                    Field::new()
                                        .label("Email Address")
                                        .child(Input::new(&email_input)),
                                )
                                .child(
                                    Field::new()
                                        .label("Initial Password")
                                        .child(Input::new(&pass_input).mask_toggle()),
                                )
                                .child(
                                    Field::new()
                                        .label("Account Role")
                                        .child(
                                            Button::new("dialog-role-toggle-btn")
                                                .outline()
                                                .small()
                                                .label(format!("Role: {role}"))
                                                .on_click({
                                                    let app_view = app_view.clone();
                                                    move |_, _, cx| {
                                                        app_view.update(cx, |this, cx| {
                                                            this.toggle_admin_new_role(cx);
                                                        });
                                                    }
                                                }),
                                        ),
                                ),
                        )
                        .child(
                            DialogFooter::new()
                                .p_4()
                                .bg(cx.theme().muted)
                                .justify_end()
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .child(
                                            DialogClose::new().child(
                                                Button::new("cancel-create-user-btn")
                                                    .label("Cancel")
                                                    .outline()
                                                    .small(),
                                            ),
                                        )
                                        .child(
                                            DialogAction::new().child(
                                                Button::new("admin-create-user-btn")
                                                    .primary()
                                                    .small()
                                                    .icon(IconName::Plus)
                                                    .label("Create User")
                                                    .loading(is_creating),
                                            ),
                                        ),
                                ),
                        )
                }
            })
            .on_ok({
                let app_view = cx.entity().clone();
                move |_, window, cx| {
                    app_view.update(cx, |this, cx| {
                        this.admin_create_user(window, cx);
                    });
                    true
                }
            });

        v_flex()
            .w_full()
            .gap_6()
            // Stats Bar matching Image 1
            .child(
                h_flex()
                    .gap_3()
                    .w_full()
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().text_color(muted_fg).child("Total Accounts"))
                                            .child(Icon::new(IconName::User).small().text_color(cx.theme().primary)),
                                    )
                                    .child(div().text_xl().font_bold().child(app.admin_users_total.to_string())),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().text_color(muted_fg).child("Administrators"))
                                            .child(Icon::new(IconName::CircleUser).small().text_color(cx.theme().primary)),
                                    )
                                    .child(div().text_xl().font_bold().child(admin_count.to_string())),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().text_color(muted_fg).child("Verified Emails"))
                                            .child(Icon::new(IconName::CircleCheck).small().text_color(cx.theme().primary)),
                                    )
                                    .child(div().text_xl().font_bold().child(verified_count.to_string())),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .p_3()
                            .rounded(radius)
                            .border_1()
                            .border_color(border)
                            .bg(card_bg)
                            .shadow_sm()
                            .child(
                                v_flex()
                                    .gap_1()
                                    .child(
                                        h_flex()
                                            .justify_between()
                                            .items_center()
                                            .child(div().text_xs().text_color(muted_fg).child("Suspended / Banned"))
                                            .child(Icon::new(IconName::CircleAlert).small().text_color(cx.theme().danger)),
                                    )
                                    .child(div().text_xl().font_bold().child(banned_count.to_string())),
                            ),
                    ),
            )
            // User Directory Card (Header matching Image 1)
            .child(
                v_flex()
                    .w_full()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .bg(card_bg)
                    .shadow_sm()
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                h_flex()
                                    .gap_2p5()
                                    .items_center()
                                    .child(
                                        div()
                                            .p_1p5()
                                            .rounded(radius)
                                            .bg(cx.theme().primary.opacity(0.12))
                                            .text_color(cx.theme().primary)
                                            .child(Icon::new(IconName::CircleUser).small()),
                                    )
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(
                                                h_flex()
                                                    .gap_2()
                                                    .items_center()
                                                    .child(div().text_sm().font_semibold().child("User Directory"))
                                                    .child(Tag::secondary().small().child(app.admin_users_total.to_string())),
                                            )
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(muted_fg)
                                                    .child("Manage permissions, provision accounts, and impersonate sessions"),
                                            ),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .items_center()
                                    .child(
                                        div()
                                            .w(px(200.))
                                            .child(Input::new(&app.admin_search_input)),
                                    )
                                    .child(
                                        Button::new("admin-refresh-users-btn")
                                            .outline()
                                            .small()
                                            .icon(IconName::RefreshCw)
                                            .loading(app.is_loading_admin_users)
                                            .label("Refresh")
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.refresh_admin_users(window, cx);
                                            })),
                                    )
                                    .child(create_dialog),
                            ),
                    )
                    .child(if app.admin_users.is_empty() {
                        div()
                            .p_6()
                            .rounded(radius)
                            .bg(muted)
                            .text_xs()
                            .text_color(muted_fg)
                            .text_center()
                            .child("No users matched. Click 'Refresh' to reload.")
                            .into_any_element()
                    } else {
                        Table::new()
                            .w_full()
                            .child(
                                TableHeader::new().child(
                                    TableRow::new()
                                        .child(TableHead::new().min_w(px(180.)).child("User"))
                                        .child(TableHead::new().w(px(90.)).min_w(px(90.)).flex_shrink_0().child("Role"))
                                        .child(TableHead::new().w(px(100.)).min_w(px(100.)).flex_shrink_0().child("Status"))
                                        .child(TableHead::new().w(px(150.)).min_w(px(150.)).flex_shrink_0().text_right().child("Actions")),
                                ),
                            )
                            .child(
                                TableBody::new().children(app.admin_users.iter().map(|u| {
                                    let u_id = u.id.clone();
                                    let is_self = u.id == current_user.id;
                                    let role = u.role.as_deref().unwrap_or("user").to_string();
                                    let next_role = if role == "admin" {
                                        "user".to_string()
                                    } else {
                                        "admin".to_string()
                                    };
                                    let role_action_label = if role == "admin" {
                                        "Demote to User"
                                    } else {
                                        "Promote to Admin"
                                    };
                                    let is_banned = u.banned.unwrap_or(false);
                                    let app_view = cx.entity().clone();

                                    TableRow::new()
                                        .child(
                                            TableCell::new()
                                                .min_w(px(180.))
                                                .child(
                                                    h_flex()
                                                        .w_full()
                                                        .min_w_0()
                                                        .overflow_hidden()
                                                        .gap_2()
                                                        .items_center()
                                                        .child(Avatar::new().name(&u.name).small())
                                                        .child(
                                                            v_flex()
                                                                .w_full()
                                                                .min_w_0()
                                                                .overflow_hidden()
                                                                .gap_0()
                                                                .child(
                                                                    h_flex()
                                                                        .w_full()
                                                                        .min_w_0()
                                                                        .overflow_hidden()
                                                                        .gap_1p5()
                                                                        .items_center()
                                                                        .child(
                                                                            div()
                                                                                .min_w_0()
                                                                                .overflow_hidden()
                                                                                .font_medium()
                                                                                .text_xs()
                                                                                .whitespace_nowrap()
                                                                                .text_ellipsis()
                                                                                .child(u.name.clone()),
                                                                        )
                                                                        .when(is_self, |this| {
                                                                            this.child(Tag::secondary().small().outline().child("You"))
                                                                        }),
                                                                )
                                                                .child(
                                                                    div()
                                                                        .w_full()
                                                                        .min_w_0()
                                                                        .overflow_hidden()
                                                                        .text_xs()
                                                                        .text_color(muted_fg)
                                                                        .whitespace_nowrap()
                                                                        .text_ellipsis()
                                                                        .child(u.email.clone()),
                                                                ),
                                                        ),
                                                ),
                                        )
                                        .child(
                                            TableCell::new()
                                                .w(px(90.))
                                                .min_w(px(90.))
                                                .flex_shrink_0()
                                                .child(if role == "admin" {
                                                    Tag::primary().small().child("admin")
                                                } else {
                                                    Tag::secondary().small().child("user")
                                                }),
                                        )
                                        .child(
                                            TableCell::new()
                                                .w(px(100.))
                                                .min_w(px(100.))
                                                .flex_shrink_0()
                                                .child(if is_banned {
                                                    Tag::danger().small().child("Banned")
                                                } else {
                                                    Tag::success().small().outline().child("Active")
                                                }),
                                        )
                                        .child(
                                            TableCell::new()
                                                .w(px(150.))
                                                .min_w(px(150.))
                                                .flex_shrink_0()
                                                .text_right()
                                                .child(
                                                    div()
                                                        .w_full()
                                                        .flex()
                                                        .items_center()
                                                        .justify_end()
                                                        .gap_1p5()
                                                        .when(!is_self && !is_banned, |this| {
                                                            let u_imp = u_id.clone();
                                                            this.child(
                                                                Button::new(format!("imp-{u_id}"))
                                                                    .ghost()
                                                                    .small()
                                                                    .icon(IconName::CircleUser)
                                                                    .label("Impersonate")
                                                                    .on_click(cx.listener(move |this, _, window, cx| {
                                                                        this.admin_impersonate(u_imp.clone(), window, cx);
                                                                    })),
                                                            )
                                                        })
                                                        .child(
                                                            Button::new(format!("actions-{u_id}"))
                                                                .ghost()
                                                                .small()
                                                                .icon(IconName::Ellipsis)
                                                                .tooltip("Actions")
                                                                .dropdown_menu_with_anchor(Anchor::TopRight, move |menu, _window, _cx| {
                                                                    let app_role = app_view.clone();
                                                                    let u_role = u_id.clone();
                                                                    let n_role = next_role.clone();

                                                                    let mut m = menu
                                                                        .min_w(px(160.))
                                                                        .label("User Actions")
                                                                        .separator()
                                                                        .item(
                                                                            PopupMenuItem::new(role_action_label).on_click(
                                                                                move |_, window, cx| {
                                                                                    app_role.update(cx, |this, cx| {
                                                                                        this.admin_toggle_role(
                                                                                            u_role.clone(),
                                                                                            n_role.clone(),
                                                                                            window,
                                                                                            cx,
                                                                                        );
                                                                                    });
                                                                                },
                                                                            ),
                                                                        );

                                                                    if !is_self {
                                                                        if !is_banned {
                                                                            let app_imp = app_view.clone();
                                                                            let u_imp = u_id.clone();
                                                                            m = m.item(
                                                                                PopupMenuItem::new("Impersonate User").on_click(
                                                                                    move |_, window, cx| {
                                                                                        app_imp.update(cx, |this, cx| {
                                                                                            this.admin_impersonate(
                                                                                                u_imp.clone(),
                                                                                                window,
                                                                                                cx,
                                                                                            );
                                                                                        });
                                                                                    },
                                                                                ),
                                                                            );
                                                                        }

                                                                        let app_ban = app_view.clone();
                                                                        let u_ban = u_id.clone();
                                                                        let ban_action_label = if is_banned {
                                                                            "Unban Account"
                                                                        } else {
                                                                            "Suspend / Ban"
                                                                        };
                                                                        m = m.item(
                                                                            PopupMenuItem::new(ban_action_label).on_click(
                                                                                move |_, window, cx| {
                                                                                    app_ban.update(cx, |this, cx| {
                                                                                        this.admin_toggle_ban(
                                                                                            u_ban.clone(),
                                                                                            is_banned,
                                                                                            window,
                                                                                            cx,
                                                                                        );
                                                                                    });
                                                                                },
                                                                            ),
                                                                        );

                                                                        let app_del = app_view.clone();
                                                                        let u_del = u_id.clone();
                                                                        m = m.separator().item(
                                                                            PopupMenuItem::new("Delete User").on_click(
                                                                                move |_, window, cx| {
                                                                                    app_del.update(cx, |this, cx| {
                                                                                        this.admin_delete_user(
                                                                                            u_del.clone(),
                                                                                            window,
                                                                                            cx,
                                                                                        );
                                                                                    });
                                                                                },
                                                                            ),
                                                                        );
                                                                    }

                                                                    m
                                                                }),
                                                        ),
                                                ),
                                        )
                                })),
                            )
                            .into_any_element()
                    }),
            )
    }

    fn render_diagnostics(
        app: &DesktopAuthApp,
        session: &SessionWire,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let card_bg = cx.theme().background;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let radius = cx.theme().radius;
        let is_calling_saas = app.is_calling_saas;

        v_flex()
            .w_full()
            .gap_6()
            .child(
                v_flex()
                    .w_full()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .bg(card_bg)
                    .shadow_sm()
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(
                                h_flex()
                                    .gap_2p5()
                                    .items_center()
                                    .child(
                                        div()
                                            .p_1p5()
                                            .rounded(radius)
                                            .bg(cx.theme().primary.opacity(0.12))
                                            .text_color(cx.theme().primary)
                                            .child(Icon::new(IconName::SquareTerminal).small()),
                                    )
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_sm().font_semibold().child("API Diagnostics & Response Telemetry"))
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .text_color(muted_fg)
                                                    .child("Inspect live HTTP response payloads, token headers, and Axum claims"),
                                            ),
                                    ),
                            )
                            .child(
                                Button::new("diagnostics-refresh-btn")
                                    .label(if is_calling_saas {
                                        "Refreshing..."
                                    } else {
                                        "Refresh /api/saas/me"
                                    })
                                    .small()
                                    .outline()
                                    .icon(IconName::RefreshCw)
                                    .loading(is_calling_saas)
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.call_saas_me(window, cx);
                                    })),
                            ),
                    )
                    // Telemetry row
                    .child(
                        h_flex()
                            .gap_3()
                            .p_3()
                            .rounded(radius)
                            .bg(muted)
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Target Endpoint"))
                                            .child(div().text_xs().font_semibold().child("GET /api/saas/me")),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Transport"))
                                            .child(Tag::secondary().small().outline().child("Bearer (Keychain)")),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("HTTP Status"))
                                            .child(
                                                if app.saas_me_json.is_some() {
                                                    Tag::success().small().child("200 OK")
                                                } else {
                                                    Tag::warning().small().outline().child("Unverified")
                                                },
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        v_flex()
                                            .gap_0p5()
                                            .child(div().text_xs().text_color(muted_fg).child("Active Session ID"))
                                            .child(
                                                div()
                                                    .text_xs()
                                                    .font_semibold()
                                                    .child(format!("{}...", &session.id[..8.min(session.id.len())])),
                                            ),
                                    ),
                            ),
                    )
                    // Raw JSON payload viewer
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
                                            .child("Raw JSON Payload"),
                                    )
                                    .child(
                                        Button::new("diagnostics-copy-json-btn")
                                            .label("Copy Payload")
                                            .small()
                                            .outline()
                                            .on_click({
                                                let payload = app.saas_me_result.clone().unwrap_or_default();
                                                move |_, window, cx| {
                                                    cx.write_to_clipboard(ClipboardItem::new_string(payload.to_string()));
                                                    window.push_notification("Payload copied to clipboard", cx);
                                                }
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .p_4()
                                    .rounded(radius)
                                    .border_1()
                                    .border_color(border)
                                    .bg(muted)
                                    .text_xs()
                                    .child(
                                        app.saas_me_result.clone().unwrap_or_else(|| {
                                            "Click 'Refresh /api/saas/me' to inspect live server response.".into()
                                        }),
                                    ),
                            ),
                    ),
            )
    }
}
