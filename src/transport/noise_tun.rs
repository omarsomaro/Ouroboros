//! LEGACY: Replaced by session_noise.rs
//! This module is deprecated and will be removed.
// Legacy module: Noise is now a session upgrade layer, not a transport fallback.
use snow::Builder;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Error)]
pub enum NoiseTunError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise params parse: {0}")]
    ParamsParse(String),
    #[error("noise initiator: {0}")]
    Initiator(String),
    #[error("noise responder: {0}")]
    Responder(String),
    #[error("noise write: {0}")]
    Write(String),
    #[error("Noise handshake not completed (sim)")]
    HandshakeIncomplete,
}

type Result<T> = std::result::Result<T, NoiseTunError>;

/// Simula handshake Noise per fallback P2P
pub async fn simulate_noise_handshake(port: u16) -> Result<(UdpSocket, SocketAddr)> {
    // bind locale
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;

    // determinismo: peer usano stessa porta; si alternano tra "caller" e "responder"
    // euristica semplice: ultimo bit del port decide chi "chiama" per primo
    let i_am_caller = (port & 1) == 1;

    // costruiamo i due stati XX
    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|e: snow::Error| NoiseTunError::ParamsParse(e.to_string()))?;
    let builder = Builder::new(params);

    let mut noise_i = builder
        .build_initiator()
        .map_err(|e| NoiseTunError::Initiator(e.to_string()))?;
    let mut noise_r = builder
        .build_responder()
        .map_err(|e| NoiseTunError::Responder(e.to_string()))?;

    let peer = SocketAddrV4::new(Ipv4Addr::BROADCAST, port);

    // mini-rendezvous: chi "chiama" invia primi msg, l'altro risponde
    // NB: questo è un *placeholder* per dimostrare la pipeline; in prod implementa
    // una discovery deterministica o QR one-shot.

    let mut handshake_done = false;
    let mut buf = [0u8; 2048];

    for round in 0..6 {
        if i_am_caller == (round % 2 == 0) {
            // caller step: write_message
            let mut out = vec![0u8; 256];
            let len = noise_i
                .write_message(&[], &mut out)
                .map_err(|e| NoiseTunError::Write(e.to_string()))?;
            out.truncate(len);
            let _ = sock.send_to(&out, peer).await;
            tracing::debug!("Noise: sent message round {}", round);
        } else {
            // responder step: recv
            if let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await
            {
                let _ = noise_r.read_message(&buf[..n], &mut []);
                tracing::debug!("Noise: received message from {}", from);
                // opzionale: salva "from" come endpoint remoto
            }
        }
        sleep(Duration::from_millis(250)).await;
        // condizione di terminazione semplificata
        if round >= 4 { 
            handshake_done = true; 
            break; 
        }
    }

    if !handshake_done {
        return Err(NoiseTunError::HandshakeIncomplete);
    }

    // "peer_addr" fittizio: in prod, ricordati l'ultimo from valido
    let peer_addr = SocketAddr::from(([255, 255, 255, 255], port));
    tracing::info!("Noise handshake completed (simulated)");
    Ok((sock, peer_addr))
}
