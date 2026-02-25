use axum::{
    extract::{ConnectInfo, Extension},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use std::{net::SocketAddr, sync::Arc};

use crate::config::Config;
use crate::offer::OfferPayload;

use super::types::{SimultaneousOpenRequest, SimultaneousOpenResponse};
use super::ApiState;

/// Handle /v1/rendezvous/sync - Coordinate simultaneous open via relay
pub(crate) async fn handle_connect_sync(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SimultaneousOpenRequest>,
) -> Result<Json<SimultaneousOpenResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let cfg = Config::from_env();

    let offer_bytes = match general_purpose::STANDARD.decode(&req.my_offer) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: None,
                rendezvous_at: None,
                error: Some(format!("Invalid offer encoding: {}", e)),
            }));
        }
    };

    let my_offer: OfferPayload = match bincode::deserialize(&offer_bytes) {
        Ok(o) => o,
        Err(e) => {
            return Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: None,
                rendezvous_at: None,
                error: Some(format!("Invalid offer: {}", e)),
            }));
        }
    };

    let their_hash = match general_purpose::STANDARD.decode(&req.their_hash) {
        Ok(h) if h.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&h);
            hash
        }
        _ => {
            return Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: None,
                rendezvous_at: None,
                error: Some("Invalid hash: must be 32 bytes".to_string()),
            }));
        }
    };

    let result = crate::transport::wan_assist::coordination::try_simultaneous_or_sequential(
        &my_offer,
        their_hash,
        &[req.relay_onion],
        &cfg,
    )
    .await;

    match result {
        Ok(_conn) => Ok(Json(SimultaneousOpenResponse {
            success: true,
            offset_ms: my_offer.ntp_offset,
            rendezvous_at: Some(my_offer.timestamp + 30000),
            error: None,
        })),
        Err(e) => Ok(Json(SimultaneousOpenResponse {
            success: false,
            offset_ms: my_offer.ntp_offset,
            rendezvous_at: None,
            error: Some(e.to_string()),
        })),
    }
}
