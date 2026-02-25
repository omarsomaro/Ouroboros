use ouroboros_crypto::derive::{
    canonicalize_passphrase, derive_salt_from_passphrase, hkdf_expand_array,
};
use ouroboros_crypto::hash::blake3_hash;

use crate::EtherSyncError;

pub const SLOT_DURATION_SECONDS: u64 = 300;
pub const LOOKBACK_SLOTS: usize = 12;
pub const FUTURE_SLOTS: usize = 2;

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
        let passphrase_bytes = canonicalize_passphrase(passphrase);
        if passphrase_bytes.is_empty() {
            return Err(EtherSyncError::InvalidPassphrase);
        }

        let space_hash = blake3_hash(&passphrase_bytes);
        let salt = derive_salt_from_passphrase(&passphrase_bytes)
            .map_err(|_| EtherSyncError::DerivationFailed)?;

        let mut ikm = Vec::with_capacity(32 + 8 + 8);
        ikm.extend_from_slice(&space_hash);
        ikm.extend_from_slice(&slot.to_be_bytes());
        ikm.extend_from_slice(&subspace.to_be_bytes());

        let entropy =
            hkdf_expand_array::<16>(&ikm, Some(&salt), b"ethersync/coordinate/entropy/v1")
                .map_err(|_| EtherSyncError::DerivationFailed)?;

        Ok(Self {
            space_hash,
            slot,
            subspace,
            entropy,
        })
    }

    /// Derive coordinate for current time slot
    pub fn derive_current(passphrase: &str, subspace: u64) -> Result<Self, EtherSyncError> {
        Self::derive(passphrase, Self::current_slot(), subspace)
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
        let start = current_slot.saturating_sub(LOOKBACK_SLOTS as u64);
        let end = current_slot.saturating_add(FUTURE_SLOTS as u64);
        (start..=end).collect()
    }
}

/// Convenience function to derive coordinate
pub fn derive_coordinate(
    passphrase: &str,
    slot: u64,
    subspace: u64,
) -> Result<EtherCoordinate, EtherSyncError> {
    EtherCoordinate::derive(passphrase, slot, subspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let a = EtherCoordinate::derive("test passphrase", 1234, 7).unwrap();
        let b = EtherCoordinate::derive("test passphrase", 1234, 7).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrases_produce_different_coordinates() {
        let a = EtherCoordinate::derive("passphrase-a", 42, 1).unwrap();
        let b = EtherCoordinate::derive("passphrase-b", 42, 1).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn slot_from_timestamp_uses_five_minute_buckets() {
        assert_eq!(EtherCoordinate::slot_from_timestamp(0), 0);
        assert_eq!(EtherCoordinate::slot_from_timestamp(299), 0);
        assert_eq!(EtherCoordinate::slot_from_timestamp(300), 1);
        assert_eq!(EtherCoordinate::slot_from_timestamp(601), 2);
    }

    #[test]
    fn lookback_window_spans_past_and_future_slots() {
        let window = EtherCoordinate::lookback_window(100);
        assert_eq!(window.first().copied(), Some(88));
        assert_eq!(window.last().copied(), Some(102));
        assert_eq!(window.len(), LOOKBACK_SLOTS + FUTURE_SLOTS + 1);
    }

    #[test]
    fn lookback_window_saturates_at_zero() {
        let window = EtherCoordinate::lookback_window(2);
        assert_eq!(window.first().copied(), Some(0));
        assert_eq!(window.last().copied(), Some(4));
    }
}
