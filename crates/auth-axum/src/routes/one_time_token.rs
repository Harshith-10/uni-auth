use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error_to_response;
use crate::extract::CurrentSession;
use crate::state::AuthState;
use auth_core::{AuthError, OneTimeTokenServiceExt};
use auth_proto::OneTimeTokenVerifyRequest;

pub async fn generate_one_time_token(
    State(state): State<AuthState>,
    current_session: CurrentSession,
) -> Response {
    if let Some(plugin) = state.service.one_time_token() {
        if plugin.config.disable_client_request {
            return error_to_response(AuthError::bad_request(
                "BAD_REQUEST",
                "Client requests are disabled",
            ));
        }
    }

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
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();
            let disable_cookie = state
                .service
                .one_time_token()
                .map(|p| p.config.disable_set_session_cookie)
                .unwrap_or(false);
            if !disable_cookie {
                state.attach_session_cookie(&mut response, &res.session.token, true, None);
            }
            response
        }
        Err(err) => error_to_response(err),
    }
}
