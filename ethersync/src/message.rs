use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use ouroboros_crypto::aead::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt};
use ouroboros_crypto::derive::{
    canonicalize_passphrase, derive_salt_from_passphrase, hkdf_expand_array,
};
use ouroboros_crypto::hash::blake3_hash;
use ouroboros_crypto::random::fill_random;

use crate::coordinate::EtherCoordinate;
use crate::EtherSyncError;

const MESSAGE_VERSION: u8 = 1;
const DEFAULT_TTL: u8 = 3;
const NONCE_LEN: usize = 24;
const AUTH_TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + 8 + 32 + 2 + 2 + 1;
const PAYLOAD_LENGTH_FIELD_LEN: usize = 4;

/// EtherMessage header (unencrypted)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EtherMessageHeader {
    pub version: u8,
    pub slot_id: u64,
    pub coordinate_hash: [u8; 32],
    pub fragment_index: u16,
    pub total_fragments: u16,
    pub ttl: u8,
}

/// Complete EtherMessage (header + encrypted payload)
#[derive(Debug, Clone, PartialEq, Eq)]
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
        if total_fragments == 0 || fragment_idx >= total_fragments {
            return Err(EtherSyncError::NetworkError(
                "invalid fragment metadata".to_string(),
            ));
        }

        let key = derive_message_key(passphrase, slot)?;
        let coordinate_hash = derive_coordinate_hash(passphrase, slot)?;

        let header = EtherMessageHeader {
            version: MESSAGE_VERSION,
            slot_id: slot,
            coordinate_hash,
            fragment_index: fragment_idx,
            total_fragments,
            ttl: DEFAULT_TTL,
        };

        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce).map_err(|_| {
            EtherSyncError::NetworkError("failed to generate random nonce".to_string())
        })?;

        let aad = serialize_header(&header);
        let ciphertext_and_tag = xchacha20poly1305_encrypt(&key, &nonce, payload, &aad)
            .map_err(|_| EtherSyncError::NetworkError("message encryption failed".to_string()))?;

        if ciphertext_and_tag.len() < AUTH_TAG_LEN {
            return Err(EtherSyncError::NetworkError(
                "ciphertext shorter than auth tag".to_string(),
            ));
        }

        let payload_len = ciphertext_and_tag.len() - AUTH_TAG_LEN;
        let mut encrypted_payload = ciphertext_and_tag;
        let tag_bytes = encrypted_payload.split_off(payload_len);

        let mut auth_tag = [0u8; AUTH_TAG_LEN];
        auth_tag.copy_from_slice(&tag_bytes);

        Ok(Self {
            header,
            encrypted_payload,
            nonce,
            auth_tag,
        })
    }

    /// Decrypt and verify message
    pub fn decrypt(&self, passphrase: &str) -> Result<Vec<u8>, crate::EtherSyncError> {
        let expected_coordinate_hash = derive_coordinate_hash(passphrase, self.header.slot_id)?;
        if expected_coordinate_hash != self.header.coordinate_hash {
            return Err(EtherSyncError::NetworkError(
                "coordinate hash mismatch".to_string(),
            ));
        }

        let key = derive_message_key(passphrase, self.header.slot_id)?;
        let aad = serialize_header(&self.header);

        let mut ciphertext_and_tag =
            Vec::with_capacity(self.encrypted_payload.len() + AUTH_TAG_LEN);
        ciphertext_and_tag.extend_from_slice(&self.encrypted_payload);
        ciphertext_and_tag.extend_from_slice(&self.auth_tag);

        xchacha20poly1305_decrypt(&key, &self.nonce, &ciphertext_and_tag, &aad)
            .map_err(|_| EtherSyncError::NetworkError("message decryption failed".to_string()))
    }

    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(
            HEADER_LEN
                + NONCE_LEN
                + AUTH_TAG_LEN
                + PAYLOAD_LENGTH_FIELD_LEN
                + self.encrypted_payload.len(),
        );

        out.extend_from_slice(&serialize_header(&self.header));
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.auth_tag);
        out.put_u32(self.encrypted_payload.len() as u32);
        out.extend_from_slice(&self.encrypted_payload);
        out.to_vec()
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::EtherSyncError> {
        let min_len = HEADER_LEN + NONCE_LEN + AUTH_TAG_LEN + PAYLOAD_LENGTH_FIELD_LEN;
        if bytes.len() < min_len {
            return Err(EtherSyncError::NetworkError(
                "message frame too short".to_string(),
            ));
        }

        let mut cursor = Bytes::copy_from_slice(bytes);
        let header = EtherMessageHeader {
            version: cursor.get_u8(),
            slot_id: cursor.get_u64(),
            coordinate_hash: {
                let mut hash = [0u8; 32];
                cursor.copy_to_slice(&mut hash);
                hash
            },
            fragment_index: cursor.get_u16(),
            total_fragments: cursor.get_u16(),
            ttl: cursor.get_u8(),
        };

        if header.total_fragments == 0 || header.fragment_index >= header.total_fragments {
            return Err(EtherSyncError::NetworkError(
                "invalid fragment metadata in frame".to_string(),
            ));
        }

        let nonce = {
            let mut nonce = [0u8; NONCE_LEN];
            cursor.copy_to_slice(&mut nonce);
            nonce
        };

        let auth_tag = {
            let mut tag = [0u8; AUTH_TAG_LEN];
            cursor.copy_to_slice(&mut tag);
            tag
        };

        let payload_len = cursor.get_u32() as usize;
        if cursor.remaining() != payload_len {
            return Err(EtherSyncError::NetworkError(
                "message payload length mismatch".to_string(),
            ));
        }

        let mut encrypted_payload = vec![0u8; payload_len];
        cursor.copy_to_slice(&mut encrypted_payload);

        Ok(Self {
            header,
            encrypted_payload,
            nonce,
            auth_tag,
        })
    }
}

fn derive_message_key(passphrase: &str, slot: u64) -> Result<[u8; 32], EtherSyncError> {
    let passphrase_bytes = canonicalize_passphrase(passphrase);
    if passphrase_bytes.is_empty() {
        return Err(EtherSyncError::InvalidPassphrase);
    }

    let salt = derive_salt_from_passphrase(&passphrase_bytes)
        .map_err(|_| EtherSyncError::DerivationFailed)?;

    let mut info = b"ethersync/message/key/v1".to_vec();
    info.extend_from_slice(&slot.to_be_bytes());

    hkdf_expand_array::<32>(&passphrase_bytes, Some(&salt), &info)
        .map_err(|_| EtherSyncError::DerivationFailed)
}

fn derive_coordinate_hash(passphrase: &str, slot: u64) -> Result<[u8; 32], EtherSyncError> {
    let coordinate = EtherCoordinate::derive(passphrase, slot, 0)?;
    let mut encoded = Vec::with_capacity(32 + 8 + 8 + 16);
    encoded.extend_from_slice(&coordinate.space_hash);
    encoded.extend_from_slice(&coordinate.slot.to_be_bytes());
    encoded.extend_from_slice(&coordinate.subspace.to_be_bytes());
    encoded.extend_from_slice(&coordinate.entropy);
    Ok(blake3_hash(&encoded))
}

fn serialize_header(header: &EtherMessageHeader) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0] = header.version;
    buf[1..9].copy_from_slice(&header.slot_id.to_be_bytes());
    buf[9..41].copy_from_slice(&header.coordinate_hash);
    buf[41..43].copy_from_slice(&header.fragment_index.to_be_bytes());
    buf[43..45].copy_from_slice(&header.total_fragments.to_be_bytes());
    buf[45] = header.ttl;
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let message =
            EtherMessage::new("very secret passphrase", 1337, b"hello ether", 0, 1).unwrap();
        let plaintext = message.decrypt("very secret passphrase").unwrap();
        assert_eq!(plaintext, b"hello ether");
    }

    #[test]
    fn wrong_passphrase_fails_decrypt() {
        let message = EtherMessage::new("correct passphrase", 7, b"payload", 0, 1).unwrap();
        let decrypted = message.decrypt("wrong passphrase");
        assert!(decrypted.is_err());
    }

    #[test]
    fn preserves_fragment_metadata() {
        let message = EtherMessage::new("fragment passphrase", 55, b"frag data", 1, 3).unwrap();
        assert_eq!(message.header.fragment_index, 1);
        assert_eq!(message.header.total_fragments, 3);
    }

    #[test]
    fn binary_serialization_roundtrip() {
        let message =
            EtherMessage::new("serialize passphrase", 222, b"serialize me", 0, 1).unwrap();
        let frame = message.to_bytes();
        let parsed = EtherMessage::from_bytes(&frame).unwrap();

        assert_eq!(parsed.header, message.header);
        assert_eq!(parsed.nonce, message.nonce);
        assert_eq!(parsed.auth_tag, message.auth_tag);
        assert_eq!(parsed.encrypted_payload, message.encrypted_payload);
        assert_eq!(
            parsed.decrypt("serialize passphrase").unwrap(),
            b"serialize me"
        );
    }
}
