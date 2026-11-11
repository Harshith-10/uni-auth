use auth_proto::OkResponse;
use axum::Json;

pub async fn ok() -> Json<OkResponse> {
    Json(OkResponse::default())
}
