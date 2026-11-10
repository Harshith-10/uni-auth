use gpui_kit::base::StyledExt;
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::component::{
    button::Button,
    form::{Field, Form},
    input::Input,
    separator::Separator,
};
use gpui_kit::{
    div, px, rgb, Context, IntoElement, ParentElement as _, SharedString,
    Styled as _,
};

use crate::app::{AuthMode, DesktopAuthApp};

pub struct AuthFormView;

impl AuthFormView {
    pub fn render(app: &DesktopAuthApp, cx: &mut Context<DesktopAuthApp>) -> impl IntoElement {
        let is_sign_up = app.mode == AuthMode::SignUp;
        let is_submitting = app.is_submitting;

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

        div()
            .flex()
            .flex_col()
            .w(px(560.))
            .gap_6()
            // Sleek Header matching Web React demo
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
            // Main Card (Slate 800 background, Slate 700 border)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_6()
                    .gap_4()
                    .rounded_xl()
                    .border_1()
                    .border_color(rgb(0x334155))
                    .bg(rgb(0x1e293b))
                    .shadow_xl()
                    // Pill Tabs matching Web React: [ Sign In ] [ Sign Up ]
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .mb_2()
                            .child(
                                if !is_sign_up {
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
                                }
                            )
                            .child(
                                if is_sign_up {
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
                                }
                            ),
                    )
                    .child(form)
                    .when_some(app.error_message.as_ref(), |this, err| {
                        this.child(
                            div()
                                .p_3()
                                .rounded_md()
                                .bg(rgb(0x450a0a))
                                .border_1()
                                .border_color(rgb(0x991b1b))
                                .text_xs()
                                .text_color(rgb(0xfca5a5))
                                .child(format!("Error: {}", err)),
                        )
                    })
                    .when_some(app.status_message.as_ref(), |this, msg| {
                        this.child(
                            div()
                                .p_3()
                                .rounded_md()
                                .bg(rgb(0x064e3b))
                                .border_1()
                                .border_color(rgb(0x059669))
                                .text_xs()
                                .text_color(rgb(0x34d399))
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
                        Button::new("social-oauth-google-btn")
                            .label("Continue with Google (Browser Loopback)")
                            .outline()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.social_login("google", window, cx);
                            })),
                    )
                    .child(
                        Button::new("social-oauth-github-btn")
                            .label("Continue with GitHub (Browser Loopback)")
                            .outline()
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.social_login("github", window, cx);
                            })),
                    ),
            )
    }
}
