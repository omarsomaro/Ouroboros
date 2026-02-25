use crate::config::{Config, PluggableTransportMode};

pub(crate) async fn handle_pluggable_protocols() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "protocols": ["none", "httpslike", "ftpdata", "dnstunnel", "websocket", "quic", "realtls"],
        "status": "experimental",
        "requires_external_infra": true,
        "warning": "Pluggable transports are experimental. RealTls/WebSocket require external server-side infrastructure. HTTP/2 and QUIC are mimicry-only (not full protocol implementations). If you are not operating that infrastructure, connections may fail or be fingerprintable."
    }))
}

pub(crate) async fn handle_pluggable_check() -> axum::Json<serde_json::Value> {
    let cfg = Config::from_env();
    let enabled = cfg.pluggable_transport != PluggableTransportMode::None;

    let status = if enabled {
        "requires_external_infrastructure"
    } else {
        "disabled"
    };

    let real_tls_status = match &cfg.pluggable_transport {
        PluggableTransportMode::RealTls(domain) if !domain.trim().is_empty() => "CONFIGURED",
        _ => "NOT_CONFIGURED",
    };

    let websocket_status = match cfg.pluggable_transport {
        PluggableTransportMode::WebSocket => "REQUIRES_EXTERNAL_INFRA",
        _ => "NOT_CONFIGURED",
    };

    let quic_status = match cfg.pluggable_transport {
        PluggableTransportMode::Quic => "MIMICRY_ONLY",
        _ => "NOT_CONFIGURED",
    };

    axum::Json(serde_json::json!({
        "pluggable_transport": {
            "enabled": enabled,
            "status": status,
            "checklist": {
                "real_tls": real_tls_status,
                "websocket": websocket_status,
                "http2": "EXPERIMENTAL_MIMICRY",
                "quic": quic_status
            }
        }
    }))
}
