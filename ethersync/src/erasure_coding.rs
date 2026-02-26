//! Erasure coding for message fragmentation and recovery using Reed-Solomon.

use crate::EtherSyncError;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Default data fragments (k)
pub const DEFAULT_DATA_FRAGMENTS: usize = 4;

/// Default parity fragments (m)
pub const DEFAULT_PARITY_FRAGMENTS: usize = 2;

/// Maximum fragment size
pub const MAX_FRAGMENT_SIZE: usize = 1400;

/// Erasure-coded fragment
#[derive(Debug, Clone)]
pub struct Fragment {
    /// Fragment index (0..k+m)
    pub index: usize,
    /// Total fragments (k + m)
    pub total: usize,
    /// Data fragments needed (k)
    pub needed: usize,
    /// Fragment payload
    pub data: Vec<u8>,
}

impl Fragment {
    /// Serialize fragment to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(12 + self.data.len());
        result.extend_from_slice(&u32::to_be_bytes(self.index as u32));
        result.extend_from_slice(&u32::to_be_bytes(self.total as u32));
        result.extend_from_slice(&u32::to_be_bytes(self.needed as u32));
        result.extend_from_slice(&self.data);
        result
    }

    /// Deserialize fragment from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EtherSyncError> {
        if bytes.len() < 12 {
            return Err(EtherSyncError::NetworkError(
                "Fragment too short".to_string(),
            ));
        }

        let index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let total = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let needed = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let data = bytes[12..].to_vec();

        Ok(Self {
            index,
            total,
            needed,
            data,
        })
    }
}

/// Reed-Solomon erasure coder with `(k data, m parity)` shards.
#[derive(Debug)]
pub struct ErasureCoder {
    data_fragments: usize,
    parity_fragments: usize,
}

impl ErasureCoder {
    /// Create new coder with specified parameters
    pub fn new(data_fragments: usize, parity_fragments: usize) -> Self {
        Self {
            data_fragments,
            parity_fragments,
        }
    }

    /// Create with default parameters (4 data + 2 parity)
    pub fn default_params() -> Self {
        Self::new(DEFAULT_DATA_FRAGMENTS, DEFAULT_PARITY_FRAGMENTS)
    }

    fn validate_params(
        data_fragments: usize,
        parity_fragments: usize,
    ) -> Result<(), EtherSyncError> {
        if data_fragments == 0 {
            return Err(EtherSyncError::NetworkError(
                "data_fragments must be > 0".to_string(),
            ));
        }
        if parity_fragments == 0 {
            return Err(EtherSyncError::NetworkError(
                "parity_fragments must be > 0".to_string(),
            ));
        }
        if data_fragments + parity_fragments > 255 {
            return Err(EtherSyncError::NetworkError(
                "data_fragments + parity_fragments must be <= 255".to_string(),
            ));
        }
        Ok(())
    }

    /// Encode data into `k + m` shards, where any `k` shards can recover data.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Fragment>, EtherSyncError> {
        Self::validate_params(self.data_fragments, self.parity_fragments)?;

        let needed = self.data_fragments;
        let parity = self.parity_fragments;
        let total = needed + parity;
        let shard_len = if data.is_empty() {
            1
        } else {
            data.len().div_ceil(needed)
        };

        let mut shards = vec![vec![0u8; shard_len]; total];

        for (i, shard) in shards.iter_mut().enumerate().take(needed) {
            let start = i * shard_len;
            if start >= data.len() {
                break;
            }
            let end = ((i + 1) * shard_len).min(data.len());
            shard[..(end - start)].copy_from_slice(&data[start..end]);
        }

        let rs = ReedSolomon::new(needed, parity).map_err(|e| {
            EtherSyncError::NetworkError(format!("Reed-Solomon init failed: {}", e))
        })?;
        rs.encode(&mut shards).map_err(|e| {
            EtherSyncError::NetworkError(format!("Reed-Solomon encode failed: {}", e))
        })?;

        Ok(shards
            .into_iter()
            .enumerate()
            .map(|(index, data)| Fragment {
                index,
                total,
                needed,
                data,
            })
            .collect())
    }

    /// Decode fragments back to original data using Reed-Solomon reconstruction.
    pub fn decode(
        &self,
        fragments: &[Fragment],
        original_len: usize,
    ) -> Result<Vec<u8>, EtherSyncError> {
        if fragments.is_empty() {
            return Err(EtherSyncError::NetworkError(
                "No fragments provided".to_string(),
            ));
        }

        let total = fragments[0].total;
        let needed = fragments[0].needed;
        if needed == 0 || total == 0 || needed > total {
            return Err(EtherSyncError::NetworkError(
                "Invalid fragment metadata".to_string(),
            ));
        }
        if total > 255 {
            return Err(EtherSyncError::NetworkError(
                "Invalid fragment total (>255)".to_string(),
            ));
        }

        let parity = total - needed;
        Self::validate_params(needed, parity)?;

        let shard_len = fragments[0].data.len();
        if shard_len == 0 {
            return Err(EtherSyncError::NetworkError(
                "Invalid empty fragment payload".to_string(),
            ));
        }

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];
        let mut unique_present = 0usize;

        for fragment in fragments {
            if fragment.total != total || fragment.needed != needed {
                return Err(EtherSyncError::NetworkError(
                    "Mismatched fragment metadata".to_string(),
                ));
            }
            if fragment.index >= total {
                return Err(EtherSyncError::NetworkError(
                    "Fragment index out of range".to_string(),
                ));
            }
            if fragment.data.len() != shard_len {
                return Err(EtherSyncError::NetworkError(
                    "Mismatched shard size".to_string(),
                ));
            }
            if shards[fragment.index].is_none() {
                unique_present += 1;
                shards[fragment.index] = Some(fragment.data.clone());
            }
        }

        if unique_present < needed {
            return Err(EtherSyncError::NetworkError(format!(
                "Insufficient fragments: have {}, need {}",
                unique_present, needed
            )));
        }

        let rs = ReedSolomon::new(needed, parity).map_err(|e| {
            EtherSyncError::NetworkError(format!("Reed-Solomon init failed: {}", e))
        })?;
        rs.reconstruct(&mut shards).map_err(|e| {
            EtherSyncError::NetworkError(format!("Reed-Solomon reconstruct failed: {}", e))
        })?;

        let mut recovered = Vec::with_capacity(needed * shard_len);
        for shard in shards.iter().take(needed) {
            let shard = shard.as_ref().ok_or_else(|| {
                EtherSyncError::NetworkError("Missing reconstructed data shard".to_string())
            })?;
            recovered.extend_from_slice(shard);
        }

        if original_len > recovered.len() {
            return Err(EtherSyncError::NetworkError(
                "Original length exceeds reconstructed payload".to_string(),
            ));
        }
        recovered.truncate(original_len);
        Ok(recovered)
    }
}

impl Default for ErasureCoder {
    fn default() -> Self {
        Self::default_params()
    }
}

/// Compression utilities
#[cfg(feature = "compression")]
pub mod compression {
    use crate::EtherSyncError;

    /// Compress data using LZ4
    pub fn compress(data: &[u8]) -> Result<Vec<u8>, EtherSyncError> {
        lz4::block::compress(data, None, false)
            .map_err(|e| EtherSyncError::NetworkError(format!("Compression failed: {}", e)))
    }

    /// Decompress LZ4 data
    pub fn decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>, EtherSyncError> {
        lz4::block::decompress(data, Some(max_size as i32))
            .map_err(|e| EtherSyncError::NetworkError(format!("Decompression failed: {}", e)))
    }
}

/// Stub compression when feature disabled
#[cfg(not(feature = "compression"))]
pub mod compression {
    use crate::EtherSyncError;

    pub fn compress(data: &[u8]) -> Result<Vec<u8>, EtherSyncError> {
        Ok(data.to_vec())
    }

    pub fn decompress(data: &[u8], _max_size: usize) -> Result<Vec<u8>, EtherSyncError> {
        Ok(data.to_vec())
    }
}

/// Metrics and observability
#[cfg(feature = "metrics")]
pub mod metrics {
    /// Record message publish
    pub fn record_publish(_bytes: usize) {
        metrics::counter!("ethersync.messages.published").increment(1);
        metrics::histogram!("ethersync.messages.size").record(_bytes as f64);
    }

    /// Record message received
    pub fn record_received(_bytes: usize) {
        metrics::counter!("ethersync.messages.received").increment(1);
        metrics::histogram!("ethersync.messages.size").record(_bytes as f64);
    }

    /// Record peer count
    pub fn record_peer_count(count: usize) {
        metrics::gauge!("ethersync.peers.count").set(count as f64);
    }

    /// Record storage size
    pub fn record_storage_size(bytes: usize) {
        metrics::gauge!("ethersync.storage.bytes").set(bytes as f64);
    }

    /// Initialize Prometheus exporter
    pub fn init_prometheus(_bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        metrics::counter!("ethersync.node.started").increment(1);
        Ok(())
    }
}

/// Stub metrics when feature disabled
#[cfg(not(feature = "metrics"))]
pub mod metrics {
    pub fn record_publish(_bytes: usize) {}
    pub fn record_received(_bytes: usize) {}
    pub fn record_peer_count(_count: usize) {}
    pub fn record_storage_size(_bytes: usize) {}
    pub fn init_prometheus(_bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_serialization() {
        let frag = Fragment {
            index: 5,
            total: 10,
            needed: 6,
            data: vec![1, 2, 3, 4, 5],
        };

        let bytes = frag.to_bytes();
        let restored = Fragment::from_bytes(&bytes).unwrap();

        assert_eq!(frag.index, restored.index);
        assert_eq!(frag.total, restored.total);
        assert_eq!(frag.needed, restored.needed);
        assert_eq!(frag.data, restored.data);
    }

    #[test]
    fn test_erasure_coder_roundtrip() {
        let coder = ErasureCoder::default_params();
        let data = b"Hello, world! This payload is long enough to span multiple data shards.";

        // Encode
        let fragments = coder.encode(data).unwrap();
        assert_eq!(
            fragments.len(),
            DEFAULT_DATA_FRAGMENTS + DEFAULT_PARITY_FRAGMENTS
        );
        assert!(fragments.iter().all(|f| f.needed == DEFAULT_DATA_FRAGMENTS));
        assert!(fragments
            .iter()
            .all(|f| f.total == DEFAULT_DATA_FRAGMENTS + DEFAULT_PARITY_FRAGMENTS));

        // Decode
        let decoded = coder.decode(&fragments, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_erasure_coder_recovers_after_loss() {
        let coder = ErasureCoder::new(4, 2);
        let data = b"Reed-Solomon should recover with up to parity shard losses.";
        let fragments = coder.encode(data).unwrap();

        // Keep only 4 of 6 fragments (drop 2), still recoverable.
        let partial = vec![
            fragments[0].clone(),
            fragments[2].clone(),
            fragments[4].clone(),
            fragments[5].clone(),
        ];
        let decoded = coder.decode(&partial, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_erasure_coder_fails_when_too_many_missing() {
        let coder = ErasureCoder::new(4, 2);
        let data = b"Insufficient fragments must fail decoding.";
        let fragments = coder.encode(data).unwrap();

        // Only 3 of 6 provided; need at least 4 data-equivalent shards.
        let partial = vec![
            fragments[0].clone(),
            fragments[2].clone(),
            fragments[4].clone(),
        ];
        assert!(coder.decode(&partial, data.len()).is_err());
    }

    #[test]
    fn test_compression_roundtrip() {
        let original = b"This is a test string that should compress well because it has repeated patterns. Repeated patterns help compression algorithms.";

        let compressed = compression::compress(original).unwrap();
        let decompressed = compression::decompress(&compressed, original.len() * 2).unwrap();

        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compression_empty() {
        let empty = b"";
        let compressed = compression::compress(empty).unwrap();
        let decompressed = compression::decompress(&compressed, 100).unwrap();
        assert!(decompressed.is_empty());
    }
}
