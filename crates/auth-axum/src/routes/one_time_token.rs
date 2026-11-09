use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::{AuthErrorResponse, OneTimeTokenVerifyRequest};
use crate::cookies::build_session_cookie;
use crate::extract::CurrentSession;
use crate::state::AuthState;

fn error_to_response(err: auth_core::AuthError) -> Response {
    let status_code = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = AuthErrorResponse::new(err.error_code(), err.to_string()).with_status(err.http_status());
    (status_code, Json(body)).into_response()
}

pub async fn generate_one_time_token(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    match state
        .service
        .generate_one_time_token(&current_session.session.token)
        .await
    {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => error_to_response(err),
    }
}

pub async fn verify_one_time_token(
    State(state): State<AuthState>,
    Json(payload): Json<OneTimeTokenVerifyRequest>,
) -> Response {
    match state.service.verify_one_time_token(&payload.token).await {
        Ok(res) => {
            let signed_token = state.service.sign_token(&res.session.token);
            let mut response = (StatusCode::OK, Json(res)).into_response();

            let cookie = build_session_cookie(
                &state.cookie_name,
                &signed_token,
                state.service.config().session_expires_in.whole_seconds(),
                state.secure_cookies,
                &state.same_site,
            );
            if let Ok(cookie_val) = cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, cookie_val);
            }
            if let Ok(token_val) = signed_token.parse() {
                response
                    .headers_mut()
                    .insert("set-auth-token", token_val);
            }

            response
        }
        Err(err) => error_to_response(err),
    }
}
