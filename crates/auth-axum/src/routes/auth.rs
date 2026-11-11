use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::error_to_response;
use crate::extract::{extract_request_meta, extract_token_from_headers};
use crate::middleware::verify_trusted_origin;
use crate::state::AuthState;
use auth_proto::{SignInEmailRequest, SignOutRequest, SignUpEmailRequest};

pub async fn sign_up_email(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(payload): Json<SignUpEmailRequest>,
) -> Response {
    if let Err(err) = verify_trusted_origin(&headers, &state.trusted_origins) {
        return error_to_response(err);
    }

    if let Some(ref url) = payload.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(url, &state.trusted_origins) {
            return error_to_response(err);
        }
    }

    let remember_me = payload.remember_me.unwrap_or(true);
    let meta = extract_request_meta(&headers);

    match state.service.sign_up_email_with_meta(payload, meta).await {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();
            if let Some(ref raw_token) = res.token {
                state.attach_session_cookie(&mut response, raw_token, remember_me, None);
                if let Ok(Some(ses)) = state
                    .service
                    .adapter()
                    .find_session_by_token(raw_token)
                    .await
                {
                    if let Ok(Some(usr)) =
                        state.service.adapter().find_user_by_id(&res.user.id).await
                    {
                        response
                            .extensions_mut()
                            .insert(crate::state::NewSessionExt(ses, usr));
                    }
                }
            }
            response
        }
        Err(err) => error_to_response(err),
    }
}

pub async fn sign_in_email(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Json(payload): Json<SignInEmailRequest>,
) -> Response {
    if let Err(err) = verify_trusted_origin(&headers, &state.trusted_origins) {
        return error_to_response(err);
    }

    if let Some(ref url) = payload.callback_url {
        if let Err(err) = crate::middleware::validate_callback_url(url, &state.trusted_origins) {
            return error_to_response(err);
        }
    }

    let callback_url = payload.callback_url.clone();
    let remember_me = payload.remember_me.unwrap_or(true);
    let meta = extract_request_meta(&headers);

    match state.service.sign_in_email_with_meta(payload, meta).await {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res.clone())).into_response();
            state.attach_session_cookie(&mut response, &res.token, remember_me, None);
            if let Ok(Some(ses)) = state
                .service
                .adapter()
                .find_session_by_token(&res.token)
                .await
            {
                if let Ok(Some(usr)) = state.service.adapter().find_user_by_id(&res.user.id).await {
                    response
                        .extensions_mut()
                        .insert(crate::state::NewSessionExt(ses, usr));
                }
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
    if let Err(err) = verify_trusted_origin(&headers, &state.trusted_origins) {
        return error_to_response(err);
    }

    let token = extract_token_from_headers(&headers, &state.cookie_name).unwrap_or_default();
    let body: Option<SignOutRequest> = if bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(&bytes).ok()
    };

    match state.service.sign_out(&token, body).await {
        Ok(res) => {
            let mut response = (StatusCode::OK, Json(res)).into_response();
            state.clear_session_cookie(&mut response);
            response
        }
        Err(err) => error_to_response(err),
    }
}
