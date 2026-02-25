use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::kad::{
    self,
    store::{MemoryStore, RecordStore},
    GetRecordOk, QueryId, QueryResult, Quorum, Record as KadRecord, RecordKey,
};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use tokio::sync::{mpsc, oneshot};

use super::{DiscoveryError, DiscoveryProvider, DiscoveryRecord, Result};

#[derive(Clone)]
pub struct KadDiscoveryProvider {
    tx: mpsc::Sender<Command>,
    local_peer_id: PeerId,
    listen_addr: Multiaddr,
}

impl KadDiscoveryProvider {
    pub async fn bind(
        listen_addr: SocketAddr,
        bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    ) -> Result<Self> {
        let has_bootstrap_peers = !bootstrap_peers.is_empty();
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = local_key.public().to_peer_id();

        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| DiscoveryError::Backend(format!("kademlia transport init failed: {e}")))?
            .with_behaviour(move |_| {
                let mut cfg =
                    kad::Config::new(libp2p::StreamProtocol::new("/handshacke/discovery/1.0.0"));
                cfg.set_query_timeout(Duration::from_secs(8));
                let store = MemoryStore::new(local_peer_id);
                let mut behaviour = kad::Behaviour::with_config(local_peer_id, store, cfg);
                behaviour.set_mode(Some(kad::Mode::Server));
                behaviour
            })
            .map_err(|e| DiscoveryError::Backend(format!("kademlia behaviour init failed: {e}")))?
            .build();

        swarm
            .listen_on(socket_to_multiaddr(listen_addr))
            .map_err(|e| DiscoveryError::Backend(format!("kademlia listen failed: {e}")))?;

        let (tx, rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();

        tokio::spawn(async move {
            run_kad_swarm(swarm, rx, ready_tx).await;
        });

        let listen_addr = tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .map_err(|_| DiscoveryError::Backend("kademlia startup timed out".to_string()))?
            .map_err(|_| {
                DiscoveryError::Backend("kademlia startup channel closed".to_string())
            })??;

        let provider = Self {
            tx,
            local_peer_id,
            listen_addr,
        };

        for (peer_id, addr) in bootstrap_peers {
            provider.add_peer(peer_id, addr).await?;
        }
        if has_bootstrap_peers {
            let _ = provider.bootstrap().await;
        }

        Ok(provider)
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn listen_addr(&self) -> Multiaddr {
        self.listen_addr.clone()
    }

    pub fn p2p_listen_addr(&self) -> Multiaddr {
        self.listen_addr
            .clone()
            .with(Protocol::P2p(self.local_peer_id))
    }

    pub async fn add_peer(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        let (respond_to, rx) = oneshot::channel();
        self.tx
            .send(Command::AddPeer {
                peer_id,
                addr,
                respond_to,
            })
            .await
            .map_err(|_| DiscoveryError::Backend("kademlia worker stopped".to_string()))?;
        rx.await.map_err(|_| {
            DiscoveryError::Backend("kademlia peer-add response dropped".to_string())
        })?
    }

    pub async fn bootstrap(&self) -> Result<()> {
        let (respond_to, rx) = oneshot::channel();
        self.tx
            .send(Command::Bootstrap { respond_to })
            .await
            .map_err(|_| DiscoveryError::Backend("kademlia worker stopped".to_string()))?;
        rx.await.map_err(|_| {
            DiscoveryError::Backend("kademlia bootstrap response dropped".to_string())
        })?
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for KadDiscoveryProvider {
    async fn announce(&self, space_hash: [u8; 32], record: DiscoveryRecord) -> Result<()> {
        let (respond_to, rx) = oneshot::channel();
        self.tx
            .send(Command::Announce {
                space_hash,
                record,
                respond_to,
            })
            .await
            .map_err(|_| DiscoveryError::Backend("kademlia worker stopped".to_string()))?;
        rx.await.map_err(|_| {
            DiscoveryError::Backend("kademlia announce response dropped".to_string())
        })?
    }

    async fn discover(&self, space_hash: [u8; 32], limit: usize) -> Result<Vec<SocketAddr>> {
        let (respond_to, rx) = oneshot::channel();
        self.tx
            .send(Command::Discover {
                space_hash,
                limit,
                respond_to,
            })
            .await
            .map_err(|_| DiscoveryError::Backend("kademlia worker stopped".to_string()))?;
        rx.await.map_err(|_| {
            DiscoveryError::Backend("kademlia discover response dropped".to_string())
        })?
    }
}

enum Command {
    Announce {
        space_hash: [u8; 32],
        record: DiscoveryRecord,
        respond_to: oneshot::Sender<Result<()>>,
    },
    Discover {
        space_hash: [u8; 32],
        limit: usize,
        respond_to: oneshot::Sender<Result<Vec<SocketAddr>>>,
    },
    AddPeer {
        peer_id: PeerId,
        addr: Multiaddr,
        respond_to: oneshot::Sender<Result<()>>,
    },
    Bootstrap {
        respond_to: oneshot::Sender<Result<()>>,
    },
}

struct PendingGet {
    limit: usize,
    endpoints: Vec<SocketAddr>,
    respond_to: oneshot::Sender<Result<Vec<SocketAddr>>>,
}

async fn run_kad_swarm(
    mut swarm: libp2p::Swarm<kad::Behaviour<MemoryStore>>,
    mut rx: mpsc::Receiver<Command>,
    ready_tx: oneshot::Sender<Result<Multiaddr>>,
) {
    let mut ready = Some(ready_tx);
    let mut pending_put: HashMap<QueryId, oneshot::Sender<Result<()>>> = HashMap::new();
    let mut pending_get: HashMap<QueryId, PendingGet> = HashMap::new();

    loop {
        tokio::select! {
            Some(cmd) = rx.recv() => {
                handle_command(cmd, &mut swarm, &mut pending_put, &mut pending_get);
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Ok(address));
                        }
                    }
                    SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed { id, result, .. }) => {
                        handle_query_event(id, result, &mut pending_put, &mut pending_get);
                    }
                    _ => {}
                }
            }
            else => break,
        }
    }

    if let Some(tx) = ready {
        let _ = tx.send(Err(DiscoveryError::Backend(
            "kademlia worker ended before startup".to_string(),
        )));
    }
}

fn handle_command(
    cmd: Command,
    swarm: &mut libp2p::Swarm<kad::Behaviour<MemoryStore>>,
    pending_put: &mut HashMap<QueryId, oneshot::Sender<Result<()>>>,
    pending_get: &mut HashMap<QueryId, PendingGet>,
) {
    match cmd {
        Command::Announce {
            space_hash,
            record,
            respond_to,
        } => {
            if record.ttl_ms == 0 {
                let _ = respond_to.send(Err(DiscoveryError::InvalidTtl(0)));
                return;
            }

            let payload = match serde_json::to_vec(&record) {
                Ok(payload) => payload,
                Err(e) => {
                    let _ = respond_to.send(Err(DiscoveryError::Backend(format!(
                        "kademlia record encode failed: {e}"
                    ))));
                    return;
                }
            };

            let key = RecordKey::new(&space_hash);
            let kad_record = KadRecord::new(key, payload);
            if let Err(e) = swarm.behaviour_mut().store_mut().put(kad_record.clone()) {
                let _ = respond_to.send(Err(DiscoveryError::Backend(format!(
                    "kademlia local store put failed: {e}"
                ))));
                return;
            }
            match swarm.behaviour_mut().put_record(kad_record, Quorum::One) {
                Ok(query_id) => {
                    pending_put.insert(query_id, respond_to);
                }
                Err(e) => {
                    let _ = respond_to.send(Err(DiscoveryError::Backend(format!(
                        "kademlia put_record failed: {e}"
                    ))));
                }
            }
        }
        Command::Discover {
            space_hash,
            limit,
            respond_to,
        } => {
            let query_id = swarm
                .behaviour_mut()
                .get_record(RecordKey::new(&space_hash));
            pending_get.insert(
                query_id,
                PendingGet {
                    limit,
                    endpoints: Vec::new(),
                    respond_to,
                },
            );
        }
        Command::AddPeer {
            peer_id,
            addr,
            respond_to,
        } => {
            swarm.behaviour_mut().add_address(&peer_id, addr.clone());
            let _ = swarm.dial(addr);
            let _ = respond_to.send(Ok(()));
        }
        Command::Bootstrap { respond_to } => match swarm.behaviour_mut().bootstrap() {
            Ok(_) => {
                let _ = respond_to.send(Ok(()));
            }
            Err(e) => {
                let _ = respond_to.send(Err(DiscoveryError::Backend(format!(
                    "kademlia bootstrap failed: {e}"
                ))));
            }
        },
    }
}

fn handle_query_event(
    id: QueryId,
    result: QueryResult,
    pending_put: &mut HashMap<QueryId, oneshot::Sender<Result<()>>>,
    pending_get: &mut HashMap<QueryId, PendingGet>,
) {
    match result {
        QueryResult::PutRecord(res) => {
            if let Some(tx) = pending_put.remove(&id) {
                let outcome = match res {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("quorum failed") {
                            Ok(())
                        } else {
                            Err(DiscoveryError::Backend(format!(
                                "kademlia put_record query failed: {e}"
                            )))
                        }
                    }
                };
                let _ = tx.send(outcome);
            }
        }
        QueryResult::GetRecord(res) => {
            let mut finalize: Option<Result<Vec<SocketAddr>>> = None;
            if let Some(pending) = pending_get.get_mut(&id) {
                match res {
                    Ok(GetRecordOk::FoundRecord(peer_record)) => {
                        if let Some(endpoint) = decode_record_endpoint(&peer_record.record.value) {
                            if !pending.endpoints.contains(&endpoint) {
                                pending.endpoints.push(endpoint);
                            }
                            if pending.endpoints.len() >= pending.limit {
                                let mut out = pending.endpoints.clone();
                                out.truncate(pending.limit);
                                finalize = Some(Ok(out));
                            }
                        }
                    }
                    Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                        let mut out = pending.endpoints.clone();
                        out.truncate(pending.limit);
                        finalize = Some(Ok(out));
                    }
                    Err(e) => {
                        finalize = Some(Err(DiscoveryError::Backend(format!(
                            "kademlia get_record query failed: {e}"
                        ))));
                    }
                }
            }
            if let Some(done) = finalize {
                if let Some(pending) = pending_get.remove(&id) {
                    let _ = pending.respond_to.send(done);
                }
            }
        }
        _ => {}
    }
}

fn decode_record_endpoint(value: &[u8]) -> Option<SocketAddr> {
    let record = serde_json::from_slice::<DiscoveryRecord>(value).ok()?;
    if is_fresh_record(&record) {
        Some(record.endpoint)
    } else {
        None
    }
}

fn is_fresh_record(record: &DiscoveryRecord) -> bool {
    if record.ttl_ms == 0 {
        return false;
    }
    let now = now_unix_ms();
    let expires_at = record.observed_at_ms.saturating_add(record.ttl_ms);
    expires_at >= now.saturating_sub(1_000)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn socket_to_multiaddr(addr: SocketAddr) -> Multiaddr {
    match addr.ip() {
        IpAddr::V4(ip) => format!("/ip4/{ip}/tcp/{}", addr.port())
            .parse()
            .expect("valid IPv4 multiaddr"),
        IpAddr::V6(ip) => format!("/ip6/{ip}/tcp/{}", addr.port())
            .parse()
            .expect("valid IPv6 multiaddr"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration, Instant};

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn kad_discovery_multinode_roundtrip() {
        let node_a = KadDiscoveryProvider::bind("127.0.0.1:0".parse().unwrap(), Vec::new())
            .await
            .unwrap();
        let node_b = KadDiscoveryProvider::bind(
            "127.0.0.1:0".parse().unwrap(),
            vec![(node_a.local_peer_id, node_a.p2p_listen_addr())],
        )
        .await
        .unwrap();
        let node_c = KadDiscoveryProvider::bind(
            "127.0.0.1:0".parse().unwrap(),
            vec![(node_b.local_peer_id, node_b.p2p_listen_addr())],
        )
        .await
        .unwrap();

        node_a
            .add_peer(node_b.local_peer_id, node_b.p2p_listen_addr())
            .await
            .unwrap();
        node_b
            .add_peer(node_c.local_peer_id, node_c.p2p_listen_addr())
            .await
            .unwrap();
        node_c
            .add_peer(node_a.local_peer_id, node_a.p2p_listen_addr())
            .await
            .unwrap();

        let _ = node_a.bootstrap().await;
        let _ = node_b.bootstrap().await;
        let _ = node_c.bootstrap().await;

        let space = [0x5Au8; 32];
        let endpoint: SocketAddr = "198.51.100.44:7444".parse().unwrap();

        node_a
            .announce(
                space,
                DiscoveryRecord {
                    endpoint,
                    observed_at_ms: now_unix_ms(),
                    ttl_ms: 60_000,
                },
            )
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let found = node_c.discover(space, 8).await.unwrap_or_default();
            if found.contains(&endpoint) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "expected endpoint {endpoint} to be discoverable via Kademlia"
            );
            sleep(Duration::from_millis(250)).await;
        }
    }
}
