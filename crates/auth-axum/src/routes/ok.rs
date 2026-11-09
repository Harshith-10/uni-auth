use axum::Json;
use auth_proto::OkResponse;

pub async fn ok() -> Json<OkResponse> {
    Json(OkResponse::default())
}
