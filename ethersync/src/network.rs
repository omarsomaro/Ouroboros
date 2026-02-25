//! UDP networking layer for EtherSync
//!
//! Provides connectionless UDP transport for EtherMessage frames with:
//! - Automatic socket binding on ephemeral port
//! - Frame encoding with length-prefix for message boundaries
//! - Async send/receive with tokio
//! - Per-peer rate limiting

use crate::{message::EtherMessage, EtherSyncError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// Maximum UDP payload size (standard MTU-safe value)
pub const MAX_UDP_PAYLOAD: usize = 1400;

/// Maximum frame size (length prefix + payload)
pub const MAX_FRAME_SIZE: usize = MAX_UDP_PAYLOAD + 4;

/// Default rate limit: max packets per peer per interval
pub const DEFAULT_RATE_LIMIT_PACKETS: u32 = 100;

/// Default rate limit interval
pub const DEFAULT_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

/// Frame encoder/decoder for UDP boundaries
///
/// Format: [4 bytes: payload length (big-endian)] [payload bytes]
pub struct FrameCodec;

impl FrameCodec {
    /// Encode a payload into a frame
    ///
    /// Returns None if payload exceeds MAX_UDP_PAYLOAD
    pub fn encode(payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() > MAX_UDP_PAYLOAD {
            return None;
        }

        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&((payload.len() as u32).to_be_bytes()));
        frame.extend_from_slice(payload);
        Some(frame)
    }

    /// Decode a frame from a UDP datagram
    ///
    /// Returns (consumed_bytes, payload) if a complete frame is found
    /// Returns (0, empty) if more data needed (shouldn't happen with UDP)
    /// Returns (consumed_bytes, empty) if frame invalid (should skip)
    pub fn decode(data: &[u8]) -> (usize, Vec<u8>) {
        if data.len() < 4 {
            // Incomplete length prefix - malformed UDP packet
            return (data.len(), Vec::new()); // Consume and discard
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

        if length > MAX_UDP_PAYLOAD {
            // Oversized frame - consume and discard
            return (data.len(), Vec::new());
        }

        if data.len() < 4 + length {
            // Truncated frame - consume and discard
            return (data.len(), Vec::new());
        }

        let payload = data[4..4 + length].to_vec();
        (4 + length, payload)
    }
}

/// Rate limiter for UDP packets per peer
#[derive(Debug)]
pub struct RateLimiter {
    /// Max packets allowed per interval
    max_packets: u32,
    /// Rate limit interval
    interval: Duration,
    /// Per-peer state: (count, window start)
    peers: HashMap<SocketAddr, (u32, Instant)>,
}

impl RateLimiter {
    /// Create new rate limiter with default settings
    pub fn new() -> Self {
        Self {
            max_packets: DEFAULT_RATE_LIMIT_PACKETS,
            interval: DEFAULT_RATE_LIMIT_INTERVAL,
            peers: HashMap::new(),
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_packets: u32, interval: Duration) -> Self {
        Self {
            max_packets,
            interval,
            peers: HashMap::new(),
        }
    }

    /// Check if packet from addr should be allowed
    ///
    /// Returns true if within rate limit, false if exceeded
    pub fn check(&mut self, addr: SocketAddr) -> bool {
        let now = Instant::now();

        match self.peers.get_mut(&addr) {
            Some((count, window_start)) => {
                if now.duration_since(*window_start) >= self.interval {
                    // New window
                    *count = 1;
                    *window_start = now;
                    true
                } else if *count < self.max_packets {
                    // Within window, increment
                    *count += 1;
                    true
                } else {
                    // Rate limited
                    false
                }
            }
            None => {
                // First packet from this peer
                self.peers.insert(addr, (1, now));
                true
            }
        }
    }

    /// Clean up expired peer entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let interval = self.interval * 2; // Keep entries for 2 intervals
        self.peers
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < interval);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// UDP socket wrapper for EtherSync networking
#[derive(Debug)]
pub struct EtherUdpSocket {
    /// Bound UDP socket
    socket: Arc<UdpSocket>,
    /// Local bind address
    local_addr: SocketAddr,
    /// Rate limiter (shared for incoming)
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl EtherUdpSocket {
    /// Bind to an ephemeral UDP port (0.0.0.0:0)
    ///
    /// Returns socket bound on a random available port
    pub async fn bind_ephemeral() -> Result<Self, EtherSyncError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to bind UDP socket: {}", e))
        })?;

        let local_addr = socket.local_addr().map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to get local address: {}", e))
        })?;

        debug!("UDP socket bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
        })
    }

    /// Bind to specific address
    pub async fn bind(addr: SocketAddr) -> Result<Self, EtherSyncError> {
        let socket = UdpSocket::bind(addr).await.map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to bind UDP socket to {}: {}", addr, e))
        })?;

        let local_addr = socket.local_addr().map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to get local address: {}", e))
        })?;

        debug!("UDP socket bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new())),
        })
    }

    /// Get local socket address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send an EtherMessage to a peer
    ///
    /// # Arguments
    /// * `message` - The message to send
    /// * `dest` - Destination address
    pub async fn send_message(
        &self,
        message: &EtherMessage,
        dest: SocketAddr,
    ) -> Result<(), EtherSyncError> {
        let payload = message.to_bytes();

        let frame = FrameCodec::encode(&payload).ok_or_else(|| {
            EtherSyncError::NetworkError(format!(
                "Message too large: {} bytes (max {})",
                payload.len(),
                MAX_UDP_PAYLOAD
            ))
        })?;

        self.socket.send_to(&frame, dest).await.map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to send UDP packet: {}", e))
        })?;

        trace!("Sent {} bytes to {}", frame.len(), dest);
        Ok(())
    }

    /// Send raw bytes to a peer (for gossip, etc.)
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<(), EtherSyncError> {
        let frame = FrameCodec::encode(data).ok_or_else(|| {
            EtherSyncError::NetworkError(format!(
                "Payload too large: {} bytes (max {})",
                data.len(),
                MAX_UDP_PAYLOAD
            ))
        })?;

        self.socket.send_to(&frame, dest).await.map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to send UDP packet: {}", e))
        })?;

        Ok(())
    }

    /// Receive a message from the socket
    ///
    /// Returns (message, sender_address) if successful
    /// Rate-limited peers are silently dropped
    pub async fn recv_message(&self) -> Result<Option<(EtherMessage, SocketAddr)>, EtherSyncError> {
        let mut buf = vec![0u8; MAX_FRAME_SIZE];

        let (len, addr) = self.socket.recv_from(&mut buf).await.map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to receive UDP packet: {}", e))
        })?;

        buf.truncate(len);

        // Check rate limit
        {
            let mut limiter = self.rate_limiter.lock().await;
            if !limiter.check(addr) {
                warn!("Rate limit exceeded for {}", addr);
                return Ok(None);
            }
        }

        // Decode frame
        let (_, payload) = FrameCodec::decode(&buf);

        if payload.is_empty() {
            trace!("Received malformed/empty frame from {}", addr);
            return Ok(None);
        }

        // Parse EtherMessage
        match EtherMessage::from_bytes(&payload) {
            Ok(msg) => {
                debug!("Received valid message from {}", addr);
                Ok(Some((msg, addr)))
            }
            Err(e) => {
                trace!("Failed to parse message from {}: {:?}", addr, e);
                Ok(None) // Silently drop invalid messages
            }
        }
    }

    /// Receive raw bytes (for gossip protocol)
    ///
    /// Returns (data, sender_address) if within rate limit
    pub async fn recv_from(&self) -> Result<Option<(Vec<u8>, SocketAddr)>, EtherSyncError> {
        let mut buf = vec![0u8; MAX_FRAME_SIZE];

        let (len, addr) = self.socket.recv_from(&mut buf).await.map_err(|e| {
            EtherSyncError::NetworkError(format!("Failed to receive UDP packet: {}", e))
        })?;

        buf.truncate(len);

        // Check rate limit
        {
            let mut limiter = self.rate_limiter.lock().await;
            if !limiter.check(addr) {
                return Ok(None);
            }
        }

        // Decode frame
        let (_, payload) = FrameCodec::decode(&buf);

        if payload.is_empty() {
            return Ok(None);
        }

        Ok(Some((payload, addr)))
    }

    /// Run periodic cleanup of rate limiter state
    ///
    /// Should be called periodically (e.g., every 60 seconds)
    pub async fn cleanup_rate_limiter(&self) {
        let mut limiter = self.rate_limiter.lock().await;
        limiter.cleanup();
    }

    /// Clone the socket handle for use in multiple tasks
    pub fn clone_socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Get a clone of the rate limiter arc
    pub fn rate_limiter(&self) -> Arc<Mutex<RateLimiter>> {
        Arc::clone(&self.rate_limiter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_codec_roundtrip() {
        let payload = b"hello world test payload";
        let encoded = FrameCodec::encode(payload).unwrap();

        let (consumed, decoded) = FrameCodec::decode(&encoded);

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_frame_codec_oversized() {
        let oversized = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert!(FrameCodec::encode(&oversized).is_none());
    }

    #[test]
    fn test_frame_codec_max_size() {
        let max = vec![0u8; MAX_UDP_PAYLOAD];
        assert!(FrameCodec::encode(&max).is_some());
    }

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let mut limiter = RateLimiter::with_limits(5, Duration::from_secs(1));
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        for _ in 0..5 {
            assert!(limiter.check(addr), "Should allow packets under limit");
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::with_limits(3, Duration::from_secs(1));
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        for _ in 0..3 {
            assert!(limiter.check(addr));
        }
        assert!(!limiter.check(addr), "Should block over limit");
        assert!(!limiter.check(addr), "Should still block");
    }

    #[test]
    fn test_rate_limiter_resets_after_interval() {
        use std::thread;

        let mut limiter = RateLimiter::with_limits(2, Duration::from_millis(50));
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Exhaust limit
        assert!(limiter.check(addr));
        assert!(limiter.check(addr));
        assert!(!limiter.check(addr));

        // Wait for reset
        thread::sleep(Duration::from_millis(60));

        // Should work again
        assert!(limiter.check(addr), "Should reset after interval");
    }

    #[tokio::test]
    async fn test_udp_socket_bind_ephemeral() {
        let socket = EtherUdpSocket::bind_ephemeral().await.unwrap();
        let addr = socket.local_addr();

        assert!(addr.port() > 0);
        // Allow both 0.0.0.0 (all interfaces) and 127.0.0.1 (localhost)
        let ip = addr.ip().to_string();
        assert!(ip == "0.0.0.0" || ip == "127.0.0.1");
    }

    #[tokio::test]
    async fn test_udp_socket_send_receive_message() {
        // Bind to localhost for testing to avoid "invalid address" errors
        let socket_a = EtherUdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let socket_b = EtherUdpSocket::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let addr_b = socket_b.local_addr();

        // Create a test message
        let msg = EtherMessage::new("test-pass", 1, b"hello", 0, 1).unwrap();

        // Spawn receive task for B
        let recv_task = tokio::spawn(async move { socket_b.recv_message().await.unwrap() });

        // Give time for B to start listening
        tokio::time::sleep(Duration::from_millis(10)).await;

        // A sends to B
        socket_a.send_message(&msg, addr_b).await.unwrap();

        // B should receive
        let received = tokio::time::timeout(Duration::from_secs(1), recv_task)
            .await
            .unwrap()
            .unwrap();

        assert!(received.is_some());
        let (received_msg, _sender) = received.unwrap();
        assert_eq!(received_msg.header.slot_id, msg.header.slot_id);
    }

    #[tokio::test]
    async fn test_udp_socket_rate_limiting() {
        let socket = EtherUdpSocket::bind_ephemeral().await.unwrap();
        let _addr = socket.local_addr();

        // Override with very strict limit
        {
            let mut limiter = socket.rate_limiter.lock().await;
            *limiter = RateLimiter::with_limits(2, Duration::from_secs(60));
        }

        // Simulate rate limit check for same address
        let test_addr: SocketAddr = "192.168.1.1:1234".parse().unwrap();

        {
            let mut limiter = socket.rate_limiter.lock().await;
            assert!(limiter.check(test_addr));
            assert!(limiter.check(test_addr));
            assert!(!limiter.check(test_addr), "Should be rate limited");
        }
    }
}
