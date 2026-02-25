use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub(crate) fn build_cors_layer() -> CorsLayer {
    // CORS is primarily relevant for the GUI (dev server origin) and protects against drive-by
    // browser access to localhost APIs. We keep an allowlist by default.
    //
    // Override with HANDSHACKE_API_CORS_ORIGINS="origin1,origin2".
    let default_origins = "http://localhost:5173,http://127.0.0.1:5173,tauri://localhost";
    let raw =
        std::env::var("HANDSHACKE_API_CORS_ORIGINS").unwrap_or_else(|_| default_origins.into());

    let origins: Vec<HeaderValue> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let allow_origin = if origins.is_empty() {
        // Safe fallback: disable cross-origin access.
        AllowOrigin::predicate(|_, _| false)
    } else {
        AllowOrigin::list(origins)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
}

pub(crate) async fn require_bearer(
    State(token): State<std::sync::Arc<String>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    let Some(auth_header) = req.headers().get(AUTHORIZATION) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let expected = format!("Bearer {}", token.as_str());
    let auth_bytes = auth_str.as_bytes();
    let expected_bytes = expected.as_bytes();
    if auth_bytes.len() != expected_bytes.len() || !bool::from(auth_bytes.ct_eq(expected_bytes)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}
