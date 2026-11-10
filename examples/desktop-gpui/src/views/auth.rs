use gpui_kit::base::StyledExt;
use gpui_kit::component::{
    button::Button,
    form::{Field, Form},
    input::Input,
    separator::Separator,
    ActiveTheme as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::{div, Context, IntoElement, ParentElement as _, SharedString, Styled as _};

use crate::app::{AuthMode, DesktopAuthApp};

pub struct AuthFormView;

impl AuthFormView {
    pub fn render(app: &DesktopAuthApp, cx: &mut Context<DesktopAuthApp>) -> impl IntoElement {
        let is_sign_up = app.mode == AuthMode::SignUp;
        let is_submitting = app.is_submitting;

        let border = cx.theme().border;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let danger = cx.theme().danger;
        let success = cx.theme().success;
        let radius = cx.theme().radius;

        let submit_label: SharedString = if is_sign_up {
            "Create Account".into()
        } else {
            "Sign In".into()
        };

        let mut form = Form::new();

        if is_sign_up {
            form = form.child(
                Field::new()
                    .label("Full Name")
                    .child(Input::new(&app.name_input)),
            );
        }

        form = form
            .child(
                Field::new()
                    .label("Email Address")
                    .child(Input::new(&app.email_input)),
            )
            .child(
                Field::new()
                    .label("Password")
                    .child(Input::new(&app.password_input).mask_toggle()),
            );

        v_flex()
            .w_full()
            .gap_6()
            .child(
                v_flex()
                    .pb_4()
                    .border_b_1()
                    .border_color(border)
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
                v_flex()
                    .p_6()
                    .gap_4()
                    .rounded(radius)
                    .border_1()
                    .border_color(border)
                    .child(
                        h_flex()
                            .gap_2()
                            .child(if !is_sign_up {
                                Button::new("tab-signin-btn")
                                    .label("Sign In")
                                    .on_click(cx.listener(|_, _, _, _| {}))
                            } else {
                                Button::new("tab-signin-btn")
                                    .label("Sign In")
                                    .outline()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_mode(cx);
                                    }))
                            })
                            .child(if is_sign_up {
                                Button::new("tab-signup-btn")
                                    .label("Sign Up")
                                    .on_click(cx.listener(|_, _, _, _| {}))
                            } else {
                                Button::new("tab-signup-btn")
                                    .label("Sign Up")
                                    .outline()
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.toggle_mode(cx);
                                    }))
                            }),
                    )
                    .child(form)
                    .when_some(app.error_message.as_ref(), |this, err| {
                        this.child(
                            div()
                                .p_3()
                                .rounded(radius)
                                .border_1()
                                .border_color(danger)
                                .text_xs()
                                .text_color(danger)
                                .child(format!("Error: {err}")),
                        )
                    })
                    .when_some(app.status_message.as_ref(), |this, msg| {
                        this.child(
                            div()
                                .p_3()
                                .rounded(radius)
                                .border_1()
                                .border_color(success)
                                .text_xs()
                                .text_color(success)
                                .child(msg.clone()),
                        )
                    })
                    .child(
                        Button::new("submit-auth-btn")
                            .label(submit_label)
                            .loading(is_submitting)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.submit_form(window, cx);
                            })),
                    )
                    .child(Separator::horizontal())
                    .child(
                        v_flex()
                            .gap_2()
                            .p_3()
                            .rounded(radius)
                            .bg(muted)
                            .child(
                                div()
                                    .text_xs()
                                    .font_semibold()
                                    .text_color(muted_fg)
                                    .child("Seeded Demo Accounts (click to fill)"),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        Button::new("demo-admin-btn")
                                            .label("Admin")
                                            .outline()
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.fill_demo_account(
                                                    "admin@example.com",
                                                    "admin12345",
                                                    window,
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(
                                        Button::new("demo-alice-btn")
                                            .label("Alice (User)")
                                            .outline()
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.fill_demo_account(
                                                    "alice@example.com",
                                                    "password123",
                                                    window,
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(
                                        Button::new("demo-bob-btn")
                                            .label("Bob (Unverified)")
                                            .outline()
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.fill_demo_account(
                                                    "bob@example.com",
                                                    "password123",
                                                    window,
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(
                                        Button::new("demo-banned-btn")
                                            .label("Banned")
                                            .outline()
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.fill_demo_account(
                                                    "banned@example.com",
                                                    "password123",
                                                    window,
                                                    cx,
                                                );
                                            })),
                                    ),
                            ),
                    )
                    .child(Separator::horizontal())
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new("social-oauth-google-btn")
                                    .label("Continue with Google")
                                    .outline()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.social_login("google", window, cx);
                                    })),
                            )
                            .child(
                                Button::new("social-oauth-github-btn")
                                    .label("Continue with GitHub")
                                    .outline()
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.social_login("github", window, cx);
                                    })),
                            ),
                    ),
            )
    }
}
