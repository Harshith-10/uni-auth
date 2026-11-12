use uni_auth_client::AuthStatus;
use gpui_kit::base::StyledExt;
use gpui_kit::component::button::ButtonVariants;
use gpui_kit::component::{
    ActiveTheme as _, Sizable as _, avatar::Avatar, button::Button, h_flex, tag::Tag, v_flex,
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::{Context, IntoElement, ParentElement as _, Styled as _, div};

use crate::app::DesktopAuthApp;

pub struct NavbarView;

impl NavbarView {
    pub fn render(
        _app: &DesktopAuthApp,
        status: &AuthStatus,
        cx: &mut Context<DesktopAuthApp>,
    ) -> impl IntoElement {
        let border = cx.theme().border;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let success = cx.theme().success;
        let primary = cx.theme().primary;
        let primary_fg = cx.theme().primary_foreground;

        h_flex()
            .w_full()
            .px_6()
            .py_3()
            .border_b_1()
            .border_color(border)
            .justify_between()
            .items_center()
            // Brand & Status
            .child(
                h_flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .size_8()
                            .rounded_md()
                            .bg(primary)
                            .text_color(primary_fg)
                            .flex()
                            .items_center()
                            .justify_center()
                            .font_bold()
                            .text_xs()
                            .child("UA"),
                    )
                    .child(
                        v_flex()
                            .gap_0()
                            .child(
                                div().font_bold().text_sm().child("Uni-Auth Desktop")
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(muted_fg)
                                    .child("Native Client"),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_1()
                            .items_center()
                            .px_2()
                            .py_0p5()
                            .rounded_md()
                            .bg(muted)
                            .child(div().size_2().rounded_full().bg(success))
                            .child(div().text_xs().text_color(muted_fg).child("localhost:3000")),
                    ),
            )
            // Right Side Profile / Action
            .child(match status {
                AuthStatus::Authenticated { user, session } => {
                    let role_str = user.role.as_deref().unwrap_or("user");
                    let is_admin = role_str.split(',').any(|r| r.trim() == "admin");
                    let is_impersonating = session.impersonated_by.is_some();

                    h_flex()
                        .items_center()
                        .gap_3()
                        .when(is_impersonating, |this| {
                            this.child(Tag::warning().small().child("Impersonating"))
                        })
                        .child(Avatar::new().name(&user.name).small())
                        .child(
                            v_flex()
                                .gap_0()
                                .child(div().font_semibold().text_xs().child(user.name.clone()))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(muted_fg)
                                        .child(user.email.clone()),
                                ),
                        )
                        .child(if is_admin {
                            Tag::primary().small().child("admin")
                        } else {
                            Tag::secondary().small().child("user")
                        })
                        .child(
                            Button::new("sign-out-btn")
                                .danger()
                                .small()
                                .outline()
                                .label("Sign Out")
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.sign_out(window, cx);
                                })),
                        )
                        .into_any_element()
                }
                _ => h_flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Tag::secondary()
                            .small()
                            .outline()
                            .child("RFC 6749 Compliant"),
                    )
                    .into_any_element(),
            })
    }
}
