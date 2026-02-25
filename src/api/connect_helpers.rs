use std::{sync::Arc, time::Duration};

use tokio::{
    sync::{mpsc, RwLock},
    time::timeout,
};

use crate::{
    config::{Config, DEFAULT_CHANNEL_CAPACITY, UDP_MAX_PACKET_SIZE},
    crypto::{deserialize_cipher_packet_with_limit, open, SessionKeyState, MAX_UDP_PACKET_BYTES},
    derive::RendezvousParams,
    protocol::Control,
    security::RateLimiter,
    state::AppState,
    transport::Connection,
};

use super::Streams;

pub(crate) async fn accept_wan_direct_and_spawn(
    sock: Arc<tokio::net::UdpSocket>,
    params: RendezvousParams,
    cfg: Config,
    state: AppState,
    streams: Streams,
    noise_role: crate::session_noise::NoiseRole,
) -> anyhow::Result<()> {
    let (peer, first_pkt) =
        match wait_for_first_handshake_packet(&sock, &params, cfg.wan_accept_timeout_ms).await {
            Ok(v) => v,
            Err(e) => {
                let mut s = state.get_connection_state().await;
                if s.mode.as_deref() == Some("wan")
                    && s.status == crate::state::ConnectionStatus::Connecting
                {
                    s.status = crate::state::ConnectionStatus::Disconnected;
                    s.mode = None;
                    s.peer_address = None;
                    state.set_connection_state(s).await;
                }
                return Err(e);
            }
        };
    let first = Arc::new(RwLock::new(Some(first_pkt)));
    let sock_send = sock.clone();
    let send = move |data: Vec<u8>| {
        let sock_send = sock_send.clone();
        async move {
            sock_send.send_to(&data, peer).await?;
            Ok::<(), anyhow::Error>(())
        }
    };
    let sock_recv = sock.clone();
    let recv = move || {
        let first = first.clone();
        let sock_recv = sock_recv.clone();
        async move {
            if let Some(pkt) = first.write().await.take() {
                return Ok::<Vec<u8>, anyhow::Error>(pkt);
            }
            loop {
                let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
                let (n, from) = sock_recv.recv_from(&mut buf).await?;
                if from != peer {
                    continue;
                }
                return Ok::<Vec<u8>, anyhow::Error>(buf[..n].to_vec());
            }
        }
    };

    let noise_params = crate::session_noise::classic_noise_params()?;
    let session_key = match crate::session_noise::run_noise_upgrade_io(
        noise_role,
        send,
        recv,
        &params.key_enc,
        params.tag16,
        params.tag8,
        noise_params,
        MAX_UDP_PACKET_BYTES,
    )
    .await
    {
        Ok(k) => k,
        Err(e) => {
            let mut s = state.get_connection_state().await;
            if s.mode.as_deref() == Some("wan")
                && s.status == crate::state::ConnectionStatus::Connecting
            {
                s.status = crate::state::ConnectionStatus::Disconnected;
                s.mode = None;
                s.peer_address = None;
                state.set_connection_state(s).await;
            }
            return Err(e.into());
        }
    };

    let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
    let rl = RateLimiter::new(
        cfg.rate_limit_capacity,
        cfg.rate_limit_max_requests,
        rl_duration,
    );

    let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    state.set_tx_out(tx_out.clone()).await;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    state.set_stop_tx(stop_tx).await;

    let updated_streams = Streams {
        tx: streams.tx,
        rx: streams.rx,
        tx_out,
    };

    let conn = Connection::Wan(sock.clone(), peer);
    let session_cipher = Arc::new(tokio::sync::RwLock::new(SessionKeyState::new(
        session_key,
        params.tag16,
        params.tag8,
        cfg.key_rotation_grace_ms(),
    )));
    let rotation_policy = cfg.key_rotation_policy();
    tracing::info!("Noise upgrade completed, session key installed");

    let stop_rx1 = stop_rx.clone();
    let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
        conn.clone(),
        updated_streams.clone(),
        session_cipher.clone(),
        rl,
        stop_rx1,
    )
    .await;

    let stop_rx2 = stop_rx.clone();
    let metrics = state.get_metrics().await;
    let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
        conn,
        rx_out,
        stop_rx2,
        metrics,
        session_cipher,
        rotation_policy,
        match noise_role {
            crate::session_noise::NoiseRole::Initiator => 0x01,
            crate::session_noise::NoiseRole::Responder => 0x02,
        },
    )
    .await;

    let mut s = state.get_connection_state().await;
    s.port = Some(params.port);
    s.mode = Some("wan".into());
    s.status = crate::state::ConnectionStatus::Connected;
    s.peer_address = Some(peer.to_string());
    state.set_connection_state(s).await;

    Ok(())
}

async fn wait_for_first_handshake_packet(
    sock: &tokio::net::UdpSocket,
    params: &RendezvousParams,
    timeout_ms: u64,
) -> anyhow::Result<(std::net::SocketAddr, Vec<u8>)> {
    let timeout_ms = timeout_ms.max(1);
    timeout(Duration::from_millis(timeout_ms), async {
        let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if crate::security::early_drop_packet(&buf[..n], params.tag16, params.tag8) {
                continue;
            }
            let pkt = match deserialize_cipher_packet_with_limit(&buf[..n], MAX_UDP_PACKET_BYTES) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let clear = match open(&params.key_enc, &pkt, params.tag16, params.tag8) {
                Some(c) => c,
                None => continue,
            };
            let ctrl: Control = match bincode::deserialize(&clear.data) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if matches!(ctrl, Control::NoiseHandshake(_)) {
                return Ok((from, buf[..n].to_vec()));
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("WAN listen timeout"))?
}
