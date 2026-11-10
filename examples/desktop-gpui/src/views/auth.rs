use gpui_kit::base::StyledExt;
use gpui_kit::component::button::ButtonVariants;
use gpui_kit::component::{
    alert::Alert,
    button::Button,
    form::{Field, Form},
    input::Input,
    separator::Separator,
    tag::Tag,
    ActiveTheme as _, Sizable as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder;
use gpui_kit::{div, px, Context, IntoElement, ParentElement as _, SharedString, Styled as _};

use crate::app::{AuthMode, DesktopAuthApp};

pub struct AuthFormView;

impl AuthFormView {
    pub fn render(app: &DesktopAuthApp, cx: &mut Context<DesktopAuthApp>) -> impl IntoElement {
        let is_sign_up = app.mode == AuthMode::SignUp;
        let is_submitting = app.is_submitting;

        let border = cx.theme().border;
        let card_bg = cx.theme().background;
        let muted = cx.theme().muted;
        let muted_fg = cx.theme().muted_foreground;
        let primary = cx.theme().primary;
        let primary_fg = cx.theme().primary_foreground;
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
            .max_w(px(460.))
            .gap_6()
            .items_center()
            // Hero Title Banner
            .child(
                v_flex()
                    .gap_2()
                    .items_center()
                    .text_center()
                    .child(
                        Tag::primary()
                            .small()
                            .outline()
                            .child("Native GPUI • Better-Auth Protocol"),
                    )
                    .child(
                        div()
                            .text_2xl()
                            .font_extrabold()
                            .child("Universal Auth Portal"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(muted_fg)
                            .max_w(px(380.))
                            .child(
                                "Native desktop authentication demonstrating multi-session OS Keyring \
                                 tokens, role-based access control, and administrator impersonation.",
                            ),
                    ),
            )
            // Auth Card
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
                    // Card Header
                    .child(
                        h_flex()
                            .gap_2p5()
                            .items_center()
                            .child(
                                div()
                                    .size_7()
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
                                        div()
                                            .text_sm()
                                            .font_semibold()
                                            .child("Authentication"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(muted_fg)
                                            .child("Sign in with a demo account or register new credentials"),
                                    ),
                            ),
                    )
                    // Alerts
                    .when_some(app.error_message.as_ref(), |this, err| {
                        this.child(
                            Alert::error("auth-err", err.clone())
                                .title("Authentication Error"),
                        )
                    })
                    .when_some(app.status_message.as_ref(), |this, msg| {
                        this.child(
                            Alert::success("auth-msg", msg.clone())
                                .title("Status"),
                        )
                    })
                    // Segmented Mode Switcher
                    .child(
                        h_flex()
                            .w_full()
                            .p_1()
                            .gap_1()
                            .rounded(radius)
                            .bg(muted)
                            .child(
                                div()
                                    .flex_1()
                                    .child(if !is_sign_up {
                                        Button::new("tab-signin-btn")
                                            .primary()
                                            .small()
                                            .w_full()
                                            .label("Sign In")
                                            .on_click(cx.listener(|_, _, _, _| {}))
                                    } else {
                                        Button::new("tab-signin-btn")
                                            .ghost()
                                            .small()
                                            .w_full()
                                            .label("Sign In")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.toggle_mode(cx);
                                            }))
                                    }),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(if is_sign_up {
                                        Button::new("tab-signup-btn")
                                            .primary()
                                            .small()
                                            .w_full()
                                            .label("Create Account")
                                            .on_click(cx.listener(|_, _, _, _| {}))
                                    } else {
                                        Button::new("tab-signup-btn")
                                            .ghost()
                                            .small()
                                            .w_full()
                                            .label("Create Account")
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                this.toggle_mode(cx);
                                            }))
                                    }),
                            ),
                    )
                    // Form fields
                    .child(form)
                    // Submit button
                    .child(
                        Button::new("submit-auth-btn")
                            .primary()
                            .w_full()
                            .label(submit_label)
                            .loading(is_submitting)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.submit_form(window, cx);
                            })),
                    )
                    // Separator
                    .child(Separator::horizontal().label("Seeded Test Accounts (1-Click Fill)"))
                    // Seeded Demo Accounts (2x2 Grid)
                    .child(
                        v_flex()
                            .gap_2()
                            .w_full()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .w_full()
                                    .child(
                                        div()
                                            .flex_1()
                                            .child(
                                                Button::new("demo-admin-btn")
                                                    .outline()
                                                    .w_full()
                                                    .child(
                                                        v_flex()
                                                            .w_full()
                                                            .gap_0p5()
                                                            .child(
                                                                h_flex()
                                                                    .justify_between()
                                                                    .w_full()
                                                                    .items_center()
                                                                    .child(div().font_medium().text_xs().child("Admin"))
                                                                    .child(Tag::primary().small().child("admin")),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(muted_fg)
                                                                    .child("admin@example.com"),
                                                            ),
                                                    )
                                                    .on_click(cx.listener(|this, _, window, cx| {
                                                        this.fill_demo_account(
                                                            "admin@example.com",
                                                            "admin12345",
                                                            window,
                                                            cx,
                                                        );
                                                    })),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .child(
                                                Button::new("demo-alice-btn")
                                                    .outline()
                                                    .w_full()
                                                    .child(
                                                        v_flex()
                                                            .w_full()
                                                            .gap_0p5()
                                                            .child(
                                                                h_flex()
                                                                    .justify_between()
                                                                    .w_full()
                                                                    .items_center()
                                                                    .child(div().font_medium().text_xs().child("Alice"))
                                                                    .child(Tag::secondary().small().child("user")),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(muted_fg)
                                                                    .child("alice@example.com"),
                                                            ),
                                                    )
                                                    .on_click(cx.listener(|this, _, window, cx| {
                                                        this.fill_demo_account(
                                                            "alice@example.com",
                                                            "password123",
                                                            window,
                                                            cx,
                                                        );
                                                    })),
                                            ),
                                    ),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .w_full()
                                    .child(
                                        div()
                                            .flex_1()
                                            .child(
                                                Button::new("demo-bob-btn")
                                                    .outline()
                                                    .w_full()
                                                    .child(
                                                        v_flex()
                                                            .w_full()
                                                            .gap_0p5()
                                                            .child(
                                                                h_flex()
                                                                    .justify_between()
                                                                    .w_full()
                                                                    .items_center()
                                                                    .child(div().font_medium().text_xs().child("Bob"))
                                                                    .child(Tag::warning().small().child("unverified")),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(muted_fg)
                                                                    .child("bob@example.com"),
                                                            ),
                                                    )
                                                    .on_click(cx.listener(|this, _, window, cx| {
                                                        this.fill_demo_account(
                                                            "bob@example.com",
                                                            "password123",
                                                            window,
                                                            cx,
                                                        );
                                                    })),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .flex_1()
                                            .child(
                                                Button::new("demo-banned-btn")
                                                    .outline()
                                                    .w_full()
                                                    .child(
                                                        v_flex()
                                                            .w_full()
                                                            .gap_0p5()
                                                            .child(
                                                                h_flex()
                                                                    .justify_between()
                                                                    .w_full()
                                                                    .items_center()
                                                                    .child(div().font_medium().text_xs().child("Banned"))
                                                                    .child(Tag::danger().small().child("banned")),
                                                            )
                                                            .child(
                                                                div()
                                                                    .text_xs()
                                                                    .text_color(muted_fg)
                                                                    .child("banned@example.com"),
                                                            ),
                                                    )
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
                            ),
                    )
                    // Separator
                    .child(Separator::horizontal().label("Or continue with"))
                    // Social OAuth buttons
                    .child(
                        h_flex()
                            .gap_2()
                            .w_full()
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        Button::new("social-oauth-google-btn")
                                            .label("Google")
                                            .outline()
                                            .w_full()
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.social_login("google", window, cx);
                                            })),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .child(
                                        Button::new("social-oauth-github-btn")
                                            .label("GitHub")
                                            .outline()
                                            .w_full()
                                            .on_click(cx.listener(|this, _, window, cx| {
                                                this.social_login("github", window, cx);
                                            })),
                                    ),
                            ),
                    )
                    // Footer
                    .child(
                        div()
                            .pt_2()
                            .text_xs()
                            .text_color(muted_fg)
                            .text_center()
                            .child("Uni-Auth Native Engine • Keyring Storage • RFC 6749"),
                    ),
            )
    }
}
