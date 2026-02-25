use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::interval;

use super::types::{ConnectionResponse, SendRequest};
use super::ApiState;

pub(crate) async fn handle_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let s = state.app.get_connection_state().await;
    Ok(Json(ConnectionResponse {
        status: format!("{:?}", s.status),
        port: s.port,
        mode: s.mode.unwrap_or_else(|| "unknown".into()),
        peer: s.peer_address,
        resume_status: None,
    }))
}

pub(crate) async fn handle_send(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let Ok(bytes) = general_purpose::STANDARD.decode(&req.packet_b64) else {
        return StatusCode::BAD_REQUEST;
    };
    if bytes.len() < 4 {
        return StatusCode::BAD_REQUEST;
    }

    if let Some(tx_out) = state.app.get_tx_out().await {
        if tx_out.send(bytes).await.is_err() {
            return StatusCode::SERVICE_UNAVAILABLE;
        }
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

pub(crate) async fn handle_recv_sse(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let rx = state.streams.rx.clone();
    let mut ticker = interval(Duration::from_millis(5000));

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                maybe = async {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                } => {
                    if let Some(bytes) = maybe {
                        let ev = Event::default().data(general_purpose::STANDARD.encode(bytes));
                        yield Ok::<Event, Infallible>(ev);
                    } else {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    yield Ok::<Event, Infallible>(Event::default().event("keepalive").data("ok"));
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new())
        .into_response()
}
