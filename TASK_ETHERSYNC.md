# Task: Create ethersync crate

Create a new Rust crate at `ethersync/` for connectionless messaging (EtherSync protocol).

## 1. Create ethersync/ Structure

```
ethersync/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── coordinate.rs    # EtherCoordinate derivation
    ├── message.rs       # EtherMessage framing
    ├── gossip.rs        # Gossip protocol (stub)
    ├── storage.rs       # Local storage (stub)
    └── node.rs          # EtherNode (stub)
```

## 2. ethersync/Cargo.toml

```toml
[package]
name = "ethersync"
version = "0.1.0"
edition = "2021"

[dependencies]
ouroboros-crypto = { path = "../ouroboros-crypto" }
tokio = { version = "1.37", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
thiserror = "1.0"
tracing = "0.1"
bytes = "1.6"
chrono = { version = "0.4", features = ["serde"] }

[features]
default = []
handshake-fallback = []  # STUB - for future integration with handshacke
```

## 3. src/lib.rs

```rust
pub mod coordinate;
pub mod message;
pub mod gossip;
pub mod storage;
pub mod node;

pub use coordinate::{EtherCoordinate, derive_coordinate};
pub use message::EtherMessage;
pub use node::EtherNode;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EtherSyncError {
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("derivation failed")]
    DerivationFailed,
    #[error("invalid slot")]
    InvalidSlot,
    #[error("storage error: {0}")]
    StorageError(String),
    #[error("network error: {0}")]
    NetworkError(String),
}
```

## 4. src/coordinate.rs

Implement EtherCoordinate derivation from passphrase + slot + subspace.

```rust
use ouroboros_crypto::derive::{canonicalize_passphrase, derive_salt_from_passphrase, hkdf_expand_array};
use crate::EtherSyncError;

pub const SLOT_DURATION_SECONDS: u64 = 300; // 5 minutes
pub const LOOKBACK_SLOTS: usize = 12;        // 1 hour
pub const FUTURE_SLOTS: usize = 2;           // 10 minutes

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EtherCoordinate {
    /// Hash of canonicalized passphrase (identifies the "space")
    pub space_hash: [u8; 32],
    /// Temporal slot (time-based)
    pub slot: u64,
    /// Subspace identifier (for multi-channel within same passphrase)
    pub subspace: u64,
    /// Entropy for collision resistance (derived deterministically)
    pub entropy: [u8; 16],
}

impl EtherCoordinate {
    /// Derive coordinate from passphrase, slot, and subspace
    pub fn derive(passphrase: &str, slot: u64, subspace: u64) -> Result<Self, EtherSyncError> {
        // 1. Canonicalize passphrase
        // 2. Derive space_hash using Blake3
        // 3. Derive entropy using HKDF
        // 4. Return EtherCoordinate
    }
    
    /// Derive coordinate for current time slot
    pub fn derive_current(passphrase: &str, subspace: u64) -> Result<Self, EtherSyncError> {
        // Get current slot from timestamp
    }
    
    /// Calculate slot from Unix timestamp
    pub fn slot_from_timestamp(timestamp_secs: u64) -> u64 {
        timestamp_secs / SLOT_DURATION_SECONDS
    }
    
    /// Get current slot
    pub fn current_slot() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::slot_from_timestamp(now)
    }
    
    /// Get lookback window (slots to scan)
    pub fn lookback_window(current_slot: u64) -> Vec<u64> {
        // Return current_slot - LOOKBACK_SLOTS .. current_slot + FUTURE_SLOTS
    }
}

/// Convenience function to derive coordinate
pub fn derive_coordinate(passphrase: &str, slot: u64, subspace: u64) -> Result<EtherCoordinate, EtherSyncError> {
    EtherCoordinate::derive(passphrase, slot, subspace)
}

#[cfg(test)]
mod tests {
    // Test determinism
    // Test different passphrase = different coordinate
    // Test slot calculation
    // Test lookback window
}
```

## 5. src/message.rs

EtherMessage structure for connectionless messaging.

```rust
use serde::{Deserialize, Serialize};

/// EtherMessage header (unencrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtherMessageHeader {
    pub version: u8,
    pub slot_id: u64,
    pub coordinate_hash: [u8; 32],
    pub fragment_index: u16,
    pub total_fragments: u16,
    pub ttl: u8,
}

/// Complete EtherMessage (header + encrypted payload)
#[derive(Debug, Clone)]
pub struct EtherMessage {
    pub header: EtherMessageHeader,
    pub encrypted_payload: Vec<u8>,
    pub nonce: [u8; 24],
    pub auth_tag: [u8; 16],
}

impl EtherMessage {
    /// Create new message (encrypts payload)
    pub fn new(
        passphrase: &str,
        slot: u64,
        payload: &[u8],
        fragment_idx: u16,
        total_fragments: u16,
    ) -> Result<Self, crate::EtherSyncError> {
        // Derive encryption key from passphrase + slot
        // Encrypt payload with XChaCha20-Poly1305
        // Build header
    }
    
    /// Decrypt and verify message
    pub fn decrypt(&self, passphrase: &str) -> Result<Vec<u8>, crate::EtherSyncError> {
        // Derive key and decrypt
    }
    
    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        // Binary serialization
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::EtherSyncError> {
        // Binary deserialization
    }
}

#[cfg(test)]
mod tests {
    // Test roundtrip encrypt/decrypt
    // Test fragmentation
    // Test serialization
}
```

## 6. src/gossip.rs (Stub)

```rust
//! Gossip protocol for EtherSync
//! STUB - Full implementation in future phase

use crate::EtherSyncError;

/// Gossip message types
#[derive(Debug, Clone)]
pub enum GossipMessage {
    /// Digest of available messages
    Digest { slot: u64, message_hashes: Vec<[u8; 32]> },
    /// Request for specific messages
    Request { slot: u64, hashes: Vec<[u8; 32]> },
    /// Response with messages
    Response { messages: Vec<crate::message::EtherMessage> },
    /// Keepalive
    Ping,
    Pong,
}

/// Gossip protocol handler
#[derive(Debug)]
pub struct GossipProtocol {
    // STUB
}

impl GossipProtocol {
    pub fn new() -> Self {
        Self {}
    }
    
    pub async fn run(&self) -> Result<(), EtherSyncError> {
        tracing::info!("Gossip protocol stub - full implementation pending");
        Ok(())
    }
}
```

## 7. src/storage.rs (Stub)

```rust
//! Local storage for EtherSync messages
//! STUB - Full implementation in future phase

use crate::{message::EtherMessage, EtherSyncError};
use std::collections::HashMap;

/// Local message storage
#[derive(Debug, Default)]
pub struct EtherStorage {
    // STUB: In-memory storage for now
    messages: HashMap<(u64, [u8; 32]), Vec<EtherMessage>>,
}

impl EtherStorage {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn store(&mut self, slot: u64, hash: [u8; 32], message: EtherMessage) -> Result<(), EtherSyncError> {
        self.messages.entry((slot, hash)).or_default().push(message);
        Ok(())
    }
    
    pub fn get(&self, slot: u64, hash: [u8; 32]) -> Option<&Vec<EtherMessage>> {
        self.messages.get(&(slot, hash))
    }
    
    pub fn get_slot_messages(&self, slot: u64) -> Vec<&EtherMessage> {
        // Return all messages for given slot
        self.messages
            .iter()
            .filter(|((s, _), _)| *s == slot)
            .flat_map(|(_, msgs)| msgs.iter())
            .collect()
    }
}
```

## 8. src/node.rs (Stub)

```rust
//! EtherNode - main interface for EtherSync
//! STUB - Full implementation in future phase

use crate::{
    coordinate::EtherCoordinate,
    gossip::GossipProtocol,
    message::EtherMessage,
    storage::EtherStorage,
    EtherSyncError,
};
use tokio::sync::mpsc;

/// EtherNode configuration
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bind_addr: String,
    pub max_storage_per_slot: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".to_string(),
            max_storage_per_slot: 1000,
        }
    }
}

/// EtherNode - main entry point for EtherSync protocol
#[derive(Debug)]
pub struct EtherNode {
    config: NodeConfig,
    storage: EtherStorage,
    gossip: GossipProtocol,
}

impl EtherNode {
    /// Create new EtherNode
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            storage: EtherStorage::new(),
            gossip: GossipProtocol::new(),
        }
    }
    
    /// Publish a message to the ether
    pub async fn publish(
        &self,
        passphrase: &str,
        payload: &[u8],
    ) -> Result<EtherMessage, EtherSyncError> {
        tracing::info!("Publish stub - full implementation pending");
        let slot = EtherCoordinate::current_slot();
        EtherMessage::new(passphrase, slot, payload, 0, 1)
    }
    
    /// Subscribe to messages for a passphrase
    pub async fn subscribe(
        &self,
        passphrase: &str,
    ) -> Result<mpsc::Receiver<EtherMessage>, EtherSyncError> {
        tracing::info!("Subscribe stub - full implementation pending");
        let (tx, rx) = mpsc::channel(100);
        // STUB: Would spawn background task to scan slots
        Ok(rx)
    }
    
    /// Run the node (gossip, storage, etc.)
    pub async fn run(&self) -> Result<(), EtherSyncError> {
        tracing::info!("EtherNode running (stub mode)");
        self.gossip.run().await
    }
}

#[cfg(feature = "handshake-fallback")]
pub mod handshake_stub {
    //! STUB for future handshacke integration
    pub struct HandshakeFallbackStub;
}
```

## 9. Verification

After creation, verify:
```bash
cargo build -p ethersync
cargo test -p ethersync
cargo doc -p ethersync
```

## 10. Update Workspace

Add to root Cargo.toml:
```toml
[workspace]
members = ["ouroboros-crypto", "ethersync"]
```

## Notes

- ALL crypto MUST use ouroboros-crypto (derive, aead, hash)
- Keep it minimal - stubs for complex features (gossip, storage, networking)
- EtherCoordinate is the KEY type - deterministic coordinate derivation
- Message encryption uses same XChaCha20-Poly1305 as handshacke
