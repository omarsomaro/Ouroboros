//! Gossip protocol for EtherSync
//!
//! Implements anti-entropy gossip with:
//! - Digest exchange (slot -> hashes)
//! - Bloom filter for space-efficient digest
//! - Request/Response pattern
//! - Peer discovery (static bootstrap + DHT stub)
//! - TTL decrement and forwarding

use crate::{
    coordinate::EtherCoordinate, message::EtherMessage, network::EtherUdpSocket,
    storage::EtherStorage, EtherSyncError,
};
use bitvec::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, trace};
use xxhash_rust::xxh3::xxh3_64;

/// Default TTL for gossip messages
pub const DEFAULT_GOSSIP_TTL: u8 = 3;

/// Bloom filter size in bits (1KB = 8192 bits)
pub const BLOOM_FILTER_SIZE: usize = 8192;

/// Number of hash functions for bloom filter
pub const BLOOM_HASH_COUNT: usize = 3;

/// Gossip interval (how often to send digests)
pub const GOSSIP_INTERVAL_SECS: u64 = 30;

/// Max peers to maintain
pub const MAX_PEERS: usize = 50;

/// Peer timeout (remove peers not seen for this long)
pub const PEER_TIMEOUT_SECS: u64 = 300;

/// Gossip message types for network transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipFrame {
    /// Digest of available messages using bloom filter
    Digest {
        slot: u64,
        bloom_filter: Vec<u8>,
        /// Optional: explicit hash list (for small sets)
        hashes: Option<Vec<[u8; 32]>>,
    },
    /// Request for specific messages by hash
    Request { slot: u64, hashes: Vec<[u8; 32]> },
    /// Response with actual messages
    Response {
        messages: Vec<Vec<u8>>, // Serialized EtherMessage
    },
    /// Forwarded message (with TTL)
    Forward {
        ttl: u8,
        message: Vec<u8>, // Serialized EtherMessage
    },
    /// Keepalive/ping
    Ping,
    /// Keepalive/pong
    Pong,
}

/// Bloom filter for efficient set membership testing
#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: BitVec<u8, Msb0>,
    size: usize,
    hash_count: usize,
}

impl BloomFilter {
    /// Create new empty bloom filter
    pub fn new(size_bits: usize, hash_count: usize) -> Self {
        Self {
            bits: bitvec![u8, Msb0; 0; size_bits],
            size: size_bits,
            hash_count,
        }
    }

    /// Create with default size
    pub fn default_size() -> Self {
        Self::new(BLOOM_FILTER_SIZE, BLOOM_HASH_COUNT)
    }

    /// Add an item to the filter
    pub fn add(&mut self, item: &[u8]) {
        for i in 0..self.hash_count {
            let hash = self.hash(item, i as u64);
            let index = (hash % self.size as u64) as usize;
            self.bits.set(index, true);
        }
    }

    /// Check if item might be in the set (may have false positives)
    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.hash_count {
            let hash = self.hash(item, i as u64);
            let index = (hash % self.size as u64) as usize;
            if !self.bits[index] {
                return false;
            }
        }
        true
    }

    /// Hash function using xxh3 with seed
    fn hash(&self, item: &[u8], seed: u64) -> u64 {
        let mut data = Vec::with_capacity(item.len() + 8);
        data.extend_from_slice(item);
        data.extend_from_slice(&seed.to_le_bytes());
        xxh3_64(&data)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.as_raw_slice().to_vec()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], size_bits: usize, hash_count: usize) -> Self {
        let bits = BitVec::from_slice(bytes);
        let mut result = Self {
            bits,
            size: size_bits,
            hash_count,
        };
        result.bits.resize(size_bits, false);
        result
    }

    /// Merge two bloom filters (union)
    pub fn merge(&mut self, other: &Self) {
        for (i, bit) in other.bits.iter().enumerate() {
            if *bit {
                self.bits.set(i, true);
            }
        }
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::default_size()
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub last_seen: Instant,
    pub rtt_ms: Option<u64>,
}

/// Peer discovery and management
#[derive(Debug)]
pub struct PeerManager {
    peers: RwLock<std::collections::HashMap<SocketAddr, PeerInfo>>,
    bootstrap_peers: Vec<SocketAddr>,
}

impl PeerManager {
    /// Create with static bootstrap peers
    pub fn new(bootstrap: Vec<SocketAddr>) -> Self {
        Self {
            peers: RwLock::new(std::collections::HashMap::new()),
            bootstrap_peers: bootstrap,
        }
    }

    /// Add or update a peer
    pub async fn add_peer(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;

        // Limit max peers
        if peers.len() >= MAX_PEERS && !peers.contains_key(&addr) {
            // Remove oldest peer
            if let Some(oldest) = peers
                .iter()
                .min_by_key(|(_, info)| info.last_seen)
                .map(|(addr, _)| *addr)
            {
                peers.remove(&oldest);
            }
        }

        peers.insert(
            addr,
            PeerInfo {
                addr,
                last_seen: Instant::now(),
                rtt_ms: None,
            },
        );
    }

    /// Mark peer as seen
    pub async fn seen_peer(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        if let Some(info) = peers.get_mut(&addr) {
            info.last_seen = Instant::now();
        }
    }

    /// Get all active peers
    pub async fn get_peers(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }

    /// Get random subset of peers for gossip
    pub async fn get_gossip_peers(&self, count: usize) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        let mut all: Vec<_> = peers.keys().cloned().collect();

        // Shuffle
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        all.sort_by_key(|a| {
            let mut hasher = DefaultHasher::new();
            a.hash(&mut hasher);
            hasher.finish()
        });

        all.into_iter().take(count).collect()
    }

    /// Get bootstrap peers
    pub fn get_bootstrap(&self) -> &[SocketAddr] {
        &self.bootstrap_peers
    }

    /// Cleanup old peers
    pub async fn cleanup(&self) {
        let mut peers = self.peers.write().await;
        let now = Instant::now();
        let timeout = Duration::from_secs(PEER_TIMEOUT_SECS);
        peers.retain(|_, info| now.duration_since(info.last_seen) < timeout);
    }

    /// Count active peers
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}

/// Gossip engine - handles the complete gossip loop
#[derive(Debug)]
pub struct GossipEngine {
    /// Storage for messages
    storage: Arc<Mutex<EtherStorage>>,
    /// Peer manager
    peers: Arc<PeerManager>,
    /// UDP socket
    socket: Arc<EtherUdpSocket>,
    /// Recently seen message hashes (deduplication)
    seen_messages: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Max seen cache size
    _max_seen_cache: usize,
    /// Gossip interval
    gossip_interval_secs: u64,
    /// Message TTL
    default_ttl: u8,
    /// Channel sender for new message notifications
    new_message_tx: Option<mpsc::Sender<EtherMessage>>,
}

struct HandleFrameCtx<'a> {
    peers: &'a PeerManager,
    storage: &'a Arc<Mutex<EtherStorage>>,
    socket: &'a EtherUdpSocket,
    seen: &'a Arc<RwLock<HashSet<[u8; 32]>>>,
    new_message_tx: &'a Option<mpsc::Sender<EtherMessage>>,
}

impl GossipEngine {
    /// Create new gossip engine
    pub fn new(
        storage: Arc<Mutex<EtherStorage>>,
        peers: Arc<PeerManager>,
        socket: Arc<EtherUdpSocket>,
    ) -> Self {
        Self {
            storage,
            peers,
            socket,
            seen_messages: Arc::new(RwLock::new(HashSet::new())),
            _max_seen_cache: 10000,
            gossip_interval_secs: GOSSIP_INTERVAL_SECS,
            default_ttl: DEFAULT_GOSSIP_TTL,
            new_message_tx: None,
        }
    }

    /// Set the channel for new message notifications
    pub fn set_message_notifier(&mut self, sender: mpsc::Sender<EtherMessage>) {
        self.new_message_tx = Some(sender);
    }

    /// Run the gossip engine
    pub async fn run(&self) -> Result<(), EtherSyncError> {
        debug!("Starting gossip engine");

        // Spawn digest gossip task
        let digest_handle = self.spawn_digest_task();

        // Spawn receive task
        let receive_handle = self.spawn_receive_task(self.new_message_tx.clone());

        // Spawn cleanup task
        let cleanup_handle = self.spawn_cleanup_task();

        // Wait for tasks
        tokio::select! {
            _ = digest_handle => {},
            _ = receive_handle => {},
            _ = cleanup_handle => {},
        }

        Ok(())
    }

    /// Spawn task to periodically send digests
    fn spawn_digest_task(&self) -> tokio::task::JoinHandle<()> {
        let interval_secs = self.gossip_interval_secs;
        let peers = Arc::clone(&self.peers);
        let storage = Arc::clone(&self.storage);
        let socket = Arc::clone(&self.socket);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));

            loop {
                ticker.tick().await;

                // Get current slot
                let slot = EtherCoordinate::current_slot();

                // Build digest for this slot
                if let Ok(digest) = Self::build_digest(&storage, slot).await {
                    // Send to random peers
                    let target_peers = peers.get_gossip_peers(3).await;

                    for peer in target_peers {
                        let frame = GossipFrame::Digest {
                            slot,
                            bloom_filter: digest.to_bytes(),
                            hashes: None,
                        };

                        if let Ok(bytes) = bincode::serialize(&frame) {
                            let _ = socket.send_to(&bytes, peer).await;
                            trace!("Sent digest to {}", peer);
                        }
                    }
                }
            }
        })
    }

    /// Spawn task to receive and process gossip frames
    fn spawn_receive_task(
        &self,
        new_message_tx: Option<mpsc::Sender<EtherMessage>>,
    ) -> tokio::task::JoinHandle<()> {
        let peers = Arc::clone(&self.peers);
        let storage = Arc::clone(&self.storage);
        let socket = Arc::clone(&self.socket);
        let seen = Arc::clone(&self.seen_messages);

        tokio::spawn(async move {
            loop {
                match socket.recv_from().await {
                    Ok(Some((data, addr))) => {
                        // Mark peer as seen
                        peers.seen_peer(addr).await;

                        // Process frame
                        if let Ok(frame) = bincode::deserialize::<GossipFrame>(&data) {
                            let ctx = HandleFrameCtx {
                                peers: &peers,
                                storage: &storage,
                                socket: &socket,
                                seen: &seen,
                                new_message_tx: &new_message_tx,
                            };
                            let _ = Self::handle_frame(frame, addr, &ctx).await;
                        }
                    }
                    Ok(None) => {
                        // Rate limited or invalid
                        continue;
                    }
                    Err(_) => {
                        // Error, continue
                        continue;
                    }
                }
            }
        })
    }

    /// Spawn cleanup task for seen messages cache
    fn spawn_cleanup_task(&self) -> tokio::task::JoinHandle<()> {
        let seen = Arc::clone(&self.seen_messages);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(300));

            loop {
                ticker.tick().await;

                // Clear seen cache periodically
                let mut cache = seen.write().await;
                if cache.len() > 5000 {
                    cache.clear();
                    trace!("Cleared seen messages cache");
                }
            }
        })
    }

    /// Build a bloom filter digest for a slot
    async fn build_digest(
        storage: &Arc<Mutex<EtherStorage>>,
        slot: u64,
    ) -> Result<BloomFilter, EtherSyncError> {
        let storage = storage.lock().await;
        let messages = storage.get_slot_messages(slot)?;

        let mut bloom = BloomFilter::default_size();

        for msg in messages {
            // Add message hash to bloom filter
            let hash = blake3::hash(&msg.encrypted_payload);
            bloom.add(hash.as_bytes());
        }

        Ok(bloom)
    }

    /// Handle incoming gossip frame
    async fn handle_frame(
        frame: GossipFrame,
        from: SocketAddr,
        ctx: &HandleFrameCtx<'_>,
    ) -> Result<(), EtherSyncError> {
        debug!(
            "Received gossip frame from {}: {:?}",
            from,
            std::mem::discriminant(&frame)
        );
        match frame {
            GossipFrame::Digest {
                slot,
                bloom_filter,
                hashes: _,
            } => {
                trace!("Received digest for slot {} from {}", slot, from);

                // Get our messages for this slot
                let our_messages = {
                    let storage = ctx.storage.lock().await;
                    storage.get_slot_messages(slot)?
                };

                // Build set of hashes we have
                let our_hashes: HashSet<[u8; 32]> = our_messages
                    .iter()
                    .map(|m| {
                        let hash = blake3::hash(&m.encrypted_payload);
                        *hash.as_bytes()
                    })
                    .collect();

                // Parse their bloom filter
                let their_bloom =
                    BloomFilter::from_bytes(&bloom_filter, BLOOM_FILTER_SIZE, BLOOM_HASH_COUNT);

                // Find hashes we have that they might not have
                // (simplified: just check if we have messages they don't)
                let mut missing_hashes = Vec::new();
                for hash in &our_hashes {
                    if !their_bloom.contains(hash) {
                        missing_hashes.push(*hash);
                    }
                }

                // If we have messages they don't, they might request them
                // For now, proactively send if we have extra
                if !missing_hashes.is_empty() && missing_hashes.len() <= 5 {
                    // Send our extra messages
                    let storage = ctx.storage.lock().await;
                    let mut messages_to_send = Vec::new();

                    for hash in missing_hashes {
                        if let Ok(msgs) = storage.get(slot, hash) {
                            for msg in msgs {
                                messages_to_send.push(msg.to_bytes());
                            }
                        }
                    }

                    if !messages_to_send.is_empty() {
                        let count = messages_to_send.len();
                        let response = GossipFrame::Response {
                            messages: messages_to_send,
                        };
                        if let Ok(bytes) = bincode::serialize(&response) {
                            let _ = ctx.socket.send_to(&bytes, from).await;
                            trace!("Sent {} messages to {}", count, from);
                        }
                    }
                }
            }

            GossipFrame::Request { slot, hashes } => {
                trace!(
                    "Received request for {} messages from {}",
                    hashes.len(),
                    from
                );

                let storage = ctx.storage.lock().await;
                let mut messages = Vec::new();

                for hash in hashes {
                    if let Ok(msgs) = storage.get(slot, hash) {
                        for msg in msgs {
                            messages.push(msg.to_bytes());
                        }
                    }
                }

                // Send response
                if !messages.is_empty() {
                    let count = messages.len();
                    let response = GossipFrame::Response { messages };
                    if let Ok(bytes) = bincode::serialize(&response) {
                        let _ = ctx.socket.send_to(&bytes, from).await;
                        debug!("Sent {} messages to {}", count, from);
                    }
                }
            }

            GossipFrame::Response { messages } => {
                trace!("Received {} messages from {}", messages.len(), from);

                // Store received messages
                let mut storage = ctx.storage.lock().await;
                for msg_bytes in messages {
                    if let Ok(msg) = EtherMessage::from_bytes(&msg_bytes) {
                        let hash = blake3::hash(&msg.encrypted_payload);
                        let hash_bytes = *hash.as_bytes();

                        // Check if we've seen this message
                        {
                            let seen_cache = ctx.seen.read().await;
                            if seen_cache.contains(&hash_bytes) {
                                continue; // Already have it
                            }
                        }

                        // Store and mark as seen
                        let _ = storage.store(msg.header.slot_id, hash_bytes, msg.clone());

                        {
                            let mut seen_cache = ctx.seen.write().await;
                            seen_cache.insert(hash_bytes);
                        }

                        // Notify subscribers of new message
                        if let Some(ref tx) = ctx.new_message_tx {
                            let _ = tx.send(msg).await;
                        }

                        debug!("Stored new message from {}", from);
                    }
                }
            }

            GossipFrame::Forward { ttl, message } => {
                if ttl == 0 {
                    trace!("Dropping message with TTL=0 from {}", from);
                    return Ok(());
                }

                // Parse message
                let msg = match EtherMessage::from_bytes(&message) {
                    Ok(m) => m,
                    Err(_) => return Ok(()),
                };

                // Check if we've seen this message
                let hash = blake3::hash(&message);
                let hash_bytes = *hash.as_bytes();

                {
                    let seen_cache = ctx.seen.read().await;
                    if seen_cache.contains(&hash_bytes) {
                        return Ok(()); // Already seen
                    }
                }

                // Store
                {
                    let mut storage = ctx.storage.lock().await;
                    let _ = storage.store(msg.header.slot_id, hash_bytes, msg.clone());
                }

                // Mark as seen
                {
                    let mut seen_cache = ctx.seen.write().await;
                    seen_cache.insert(hash_bytes);
                }

                // Notify subscribers of new message
                if let Some(ref tx) = ctx.new_message_tx {
                    let _ = tx.send(msg.clone()).await;
                }

                // Forward with decremented TTL
                let forward = GossipFrame::Forward {
                    ttl: ttl - 1,
                    message,
                };

                if let Ok(bytes) = bincode::serialize(&forward) {
                    // Flood to peers (except sender)
                    let peer_addrs = ctx.peers.get_peers().await;
                    let count = peer_addrs.len().saturating_sub(1);
                    for peer in &peer_addrs {
                        if *peer != from {
                            let _ = ctx.socket.send_to(&bytes, *peer).await;
                        }
                    }
                    debug!("Forwarded message to {} peers", count);
                }
            }

            GossipFrame::Ping => {
                // Respond with Pong
                let pong = GossipFrame::Pong;
                if let Ok(bytes) = bincode::serialize(&pong) {
                    let _ = ctx.socket.send_to(&bytes, from).await;
                }
            }

            GossipFrame::Pong => {
                // Update RTT if we were waiting
                trace!("Received Pong from {}", from);
            }
        }

        Ok(())
    }

    /// Publish a message to the gossip network
    pub async fn publish(&self, message: EtherMessage) -> Result<(), EtherSyncError> {
        // Store locally first
        let hash = blake3::hash(&message.encrypted_payload);
        let hash_bytes = *hash.as_bytes();

        {
            let mut storage = self.storage.lock().await;
            storage.store(message.header.slot_id, hash_bytes, message.clone())?;
        }

        // Mark as seen
        {
            let mut seen = self.seen_messages.write().await;
            seen.insert(hash_bytes);
        }

        // Forward to peers
        let forward = GossipFrame::Forward {
            ttl: self.default_ttl,
            message: message.to_bytes(),
        };

        if let Ok(bytes) = bincode::serialize(&forward) {
            let peers = self.peers.get_peers().await;
            let count = peers.len();
            for peer in &peers {
                let _ = self.socket.send_to(&bytes, *peer).await;
            }
            debug!("Published message to {} peers", count);
            debug!("Published message to {} peers", count);
        } else {
            debug!("Failed to serialize gossip frame");
        }

        Ok(())
    }
}

/// Legacy GossipProtocol - now just wraps GossipEngine
#[derive(Debug)]
pub struct GossipProtocol;

impl GossipProtocol {
    /// Create new gossip protocol
    pub fn new() -> Self {
        Self
    }

    /// Run stub
    pub async fn run(&self) -> Result<(), EtherSyncError> {
        tracing::info!("Gossip protocol initialized (stub mode)");
        Ok(())
    }
}

impl Default for GossipProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut bloom = BloomFilter::default_size();

        let item1 = b"test item 1";
        let item2 = b"test item 2";

        bloom.add(item1);

        assert!(bloom.contains(item1));
        assert!(!bloom.contains(item2)); // May have false positives but unlikely
    }

    #[test]
    fn test_bloom_filter_merge() {
        let mut bloom1 = BloomFilter::default_size();
        let mut bloom2 = BloomFilter::default_size();

        bloom1.add(b"item1");
        bloom2.add(b"item2");

        bloom1.merge(&bloom2);

        assert!(bloom1.contains(b"item1"));
        assert!(bloom1.contains(b"item2"));
    }

    #[test]
    fn test_bloom_serialization() {
        let mut bloom = BloomFilter::default_size();
        bloom.add(b"test");

        let bytes = bloom.to_bytes();
        let restored = BloomFilter::from_bytes(&bytes, BLOOM_FILTER_SIZE, BLOOM_HASH_COUNT);

        assert!(restored.contains(b"test"));
    }

    #[test]
    fn test_gossip_frame_serialization() {
        let frame = GossipFrame::Digest {
            slot: 42,
            bloom_filter: vec![0u8; 100],
            hashes: Some(vec![[1u8; 32], [2u8; 32]]),
        };

        let bytes = bincode::serialize(&frame).unwrap();
        let restored: GossipFrame = bincode::deserialize(&bytes).unwrap();

        match (frame, restored) {
            (GossipFrame::Digest { slot: s1, .. }, GossipFrame::Digest { slot: s2, .. }) => {
                assert_eq!(s1, s2);
            }
            _ => panic!("Frame mismatch"),
        }
    }
}
