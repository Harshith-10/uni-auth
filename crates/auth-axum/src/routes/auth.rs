use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::{
    AuthErrorResponse, SignInEmailRequest, SignOutRequest, SignUpEmailRequest,
};
use crate::cookies::{build_clear_session_cookie, build_session_cookie};
use crate::extract::extract_token_from_headers;
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

pub async fn sign_up_email(
    State(state): State<AuthState>,
    Json(payload): Json<SignUpEmailRequest>,
) -> Response {
    match state.service.sign_up_email(payload).await {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();

            if let Some(ref token) = res.token {
                let cookie = build_session_cookie(
                    &state.cookie_name,
                    token,
                    state.service.config().session_expires_in.whole_seconds(),
                    state.secure_cookies,
                    &state.same_site,
                );
                if let Ok(cookie_val) = cookie.parse() {
                    response.headers_mut().append(header::SET_COOKIE, cookie_val);
                }
                if let Ok(token_val) = token.parse() {
                    response
                        .headers_mut()
                        .insert("set-auth-token", token_val);
                }
            }

            response
        }
        Err(err) => error_to_response(err),
    }
}

pub async fn sign_in_email(
    State(state): State<AuthState>,
    Json(payload): Json<SignInEmailRequest>,
) -> Response {
    let callback_url = payload.callback_url.clone();
    match state.service.sign_in_email(payload).await {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();

            let cookie = build_session_cookie(
                &state.cookie_name,
                &res.token,
                state.service.config().session_expires_in.whole_seconds(),
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(cookie_val) = cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, cookie_val);
            }
            if let Ok(token_val) = res.token.parse() {
                response
                    .headers_mut()
                    .insert("set-auth-token", token_val);
            }

            if let Some(ref url) = callback_url {
                if let Ok(loc_val) = url.parse() {
                    response.headers_mut().insert(header::LOCATION, loc_val);
                }
            }

            response
        }
        Err(err) => error_to_response(err),
    }
}

pub async fn sign_out(
    State(state): State<AuthState>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let token = extract_token_from_headers(&headers, &state.cookie_name).unwrap_or_default();
    let body: Option<SignOutRequest> = if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(&bytes).ok()
    };

    match state.service.sign_out(&token, body).await {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res)).into_response();
            let clear_cookie = build_clear_session_cookie(
                &state.cookie_name,
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(cookie_val) = clear_cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, cookie_val);
            }
            response
        }
        Err(err) => error_to_response(err),
    }
}
