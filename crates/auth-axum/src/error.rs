//! Axum HTTP error response integration for `AuthError`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use auth_core::AuthError;
use auth_proto::AuthErrorResponse;

/// Wrapper around `AuthError` implementing Axum's `IntoResponse` trait.
#[derive(Debug)]
pub struct ApiError(pub AuthError);

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        Self(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status_u16 = self.0.http_status();
        let status = StatusCode::from_u16(status_u16)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = AuthErrorResponse::new(self.0.error_code(), self.0.to_string())
            .with_status(status_u16);
        (status, Json(body)).into_response()
    }
}

/// Helper function to convert an `AuthError` into an Axum `Response`.
pub fn error_to_response(err: AuthError) -> Response {
    ApiError(err).into_response()
}
