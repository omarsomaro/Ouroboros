pub mod coordinate;
pub mod erasure_coding;
pub mod gossip;
pub mod message;
pub mod network;
pub mod node;
pub mod storage;

pub use coordinate::{derive_coordinate, EtherCoordinate};
pub use message::EtherMessage;
pub use network::{EtherUdpSocket, FrameCodec, RateLimiter};
pub use node::{EtherNode, NodeConfig};

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
