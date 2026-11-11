use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;

/// Query parameters for `GET /api/auth/error`.
#[derive(Debug, Deserialize)]
pub struct ErrorQuery {
    pub error: Option<String>,
    #[serde(default, alias = "error_description")]
    pub error_description: Option<String>,
}

/// `GET /api/auth/error`: Renders a standardized error page or JSON debug response.
pub async fn error_page(headers: HeaderMap, Query(query): Query<ErrorQuery>) -> Response {
    let error_code = query.error.as_deref().unwrap_or("UNKNOWN");
    let desc = query.error_description.as_deref().unwrap_or("");

    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);

    if accepts_json {
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "error": error_code,
                "error_description": desc,
            })),
        )
            .into_response();
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Authentication Error</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: #f9fafb; }}
        .card {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); max-width: 480px; width: 100%; }}
        h1 {{ color: #dc2626; margin-top: 0; font-size: 1.25rem; }}
        .code {{ background: #f3f4f6; padding: 0.25rem 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.875rem; }}
        p {{ color: #4b5563; line-height: 1.5; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Authentication Error</h1>
        <p><strong>Code:</strong> <span class="code">{}</span></p>
        <p>{}</p>
    </div>
</body>
</html>"#,
        html_escape(error_code),
        html_escape(desc)
    );

    (StatusCode::OK, Html(html)).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
