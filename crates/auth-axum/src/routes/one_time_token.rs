use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use auth_proto::OneTimeTokenVerifyRequest;
use crate::error_to_response;
use crate::extract::CurrentSession;
use crate::state::AuthState;

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
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();
            state.attach_session_cookie(&mut response, &res.session.token, true, None);
            response
        }
        Err(err) => error_to_response(err),
    }
}
