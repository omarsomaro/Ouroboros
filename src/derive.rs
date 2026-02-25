use crate::config::{MAX_PORT, MIN_EPHEMERAL_PORT};
use ouroboros_crypto::derive::{
    argon2id_derive, canonicalize_passphrase, derive_salt_from_passphrase, hkdf_expand_array,
};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct RendezvousParams {
    pub port: u16,
    pub key_enc: [u8; 32],
    pub key_mac: [u8; 32],
    pub tag16: u16,
    pub tag8: u8,
    pub version: u8,
}

#[derive(Debug, Error)]
pub enum DeriveError {
    #[error("derive salt failed: {0}")]
    SaltDerivation(String),
    #[error("argon2 hash failed: {0}")]
    Argon2(String),
    #[error("hkdf expand failed: {0}")]
    Hkdf(String),
    #[error("hmac init failed")]
    HmacInit,
}

type Result<T> = std::result::Result<T, DeriveError>;

/// Deriva parametri deterministici da una passphrase con Argon2id hardening
/// CRITICAL: Mantiene determinismo (stessa passphrase = stessi parametri)
#[allow(dead_code)]
pub(crate) fn derive_from_passphrase(passphrase: &str) -> Result<RendezvousParams> {
    derive_from_passphrase_v2(passphrase)
}

pub fn derive_from_secret(passphrase: &SecretString) -> Result<RendezvousParams> {
    derive_from_passphrase_v2(passphrase.expose_secret())
}

/// V2: Argon2id + HKDF deterministico (production-ready)
/// Standard mode: usa salt deterministico per determinismo passphrase
pub fn derive_from_passphrase_v2(passphrase: &str) -> Result<RendezvousParams> {
    derive_from_passphrase_v2_with_salt(passphrase, None)
}

/// V2 Stealth mode: usa ephemeral salt per port randomization
/// Salva il salt in offer.per_ephemeral_salt per recostruire stessi parametri
pub fn derive_from_passphrase_v2_stealth(
    passphrase: &str,
    salt_override: &[u8; 16],
) -> Result<(RendezvousParams, [u8; 16])> {
    // Se salt_override è fornito, usa quello (per recostruire)
    // Altrimenti, genera random (per creare nuovo)
    let salt_to_use = if salt_override.iter().any(|&b| b != 0) {
        *salt_override
    } else {
        let mut new_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);
        new_salt
    };

    let params = derive_from_passphrase_v2_with_salt(passphrase, Some(&salt_to_use))?;
    Ok((params, salt_to_use))
}

/// Core V2 derivation with optional salt override
fn derive_from_passphrase_v2_with_salt(
    passphrase: &str,
    salt_override: Option<&[u8; 16]>,
) -> Result<RendezvousParams> {
    // Canonical bytes: NFC + newline canonicalization + no trim
    let mut pass_bytes = canonicalize_passphrase(passphrase);

    // 1. Derive salt: deterministico se salt_override None, altrimenti usa override
    let salt_bytes = if let Some(salt) = salt_override {
        *salt
    } else {
        derive_salt_from_passphrase(&pass_bytes)
            .map_err(|e| DeriveError::SaltDerivation(e.to_string()))?
    };

    // 2. Argon2id con parametri bilanciati (memory_kb=8192, iterations=3, parallelism=1)
    let master_key = argon2id_derive(&pass_bytes, &salt_bytes, 8192, 3, 1, 32)
        .map_err(|e| DeriveError::Argon2(e.to_string()))?;

    // 3. HKDF expansion
    let port_key: [u8; 2] = hkdf_expand_array(master_key.as_slice(), None, b"hs/port/v2")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;
    let key_enc: [u8; 32] = hkdf_expand_array(master_key.as_slice(), None, b"hs/enc/v2")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;
    let key_mac: [u8; 32] = hkdf_expand_array(master_key.as_slice(), None, b"hs/mac/v2")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;
    let tag: [u8; 2] = hkdf_expand_array(master_key.as_slice(), None, b"hs/tag/v2")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;

    // 4. Calcola parametri
    let port =
        MIN_EPHEMERAL_PORT + (u16::from_be_bytes(port_key) % (MAX_PORT - MIN_EPHEMERAL_PORT));
    let tag16 = u16::from_be_bytes(tag);
    let tag8 = derive_tag8_from_key(&key_enc)?;

    let result = RendezvousParams {
        port,
        key_enc,
        key_mac,
        tag16,
        tag8,
        version: 2,
    };

    // 5. Zeroize
    use zeroize::Zeroize;
    pass_bytes.zeroize();

    Ok(result)
}

/// V1: Backward compatibility (solo SHA256+HKDF)
#[allow(dead_code)]
pub fn derive_from_passphrase_v1(passphrase: &str) -> Result<RendezvousParams> {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let seed = hasher.finalize();

    let port_key: [u8; 2] = hkdf_expand_array(&seed, None, b"hs/port/v1")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;
    let key_enc: [u8; 32] = hkdf_expand_array(&seed, None, b"hs/enc/v1")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;
    let key_mac: [u8; 32] = hkdf_expand_array(&seed, None, b"hs/mac/v1")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;
    let tag: [u8; 2] = hkdf_expand_array(&seed, None, b"hs/tag/v1")
        .map_err(|e| DeriveError::Hkdf(e.to_string()))?;

    let port =
        MIN_EPHEMERAL_PORT + (u16::from_be_bytes(port_key) % (MAX_PORT - MIN_EPHEMERAL_PORT));
    let tag16 = u16::from_be_bytes(tag);
    let tag8 = derive_tag8_from_key(&key_enc)?;

    Ok(RendezvousParams {
        port,
        key_enc,
        key_mac,
        tag16,
        tag8,
        version: 1,
    })
}

pub(crate) fn derive_tag8_from_key(key_enc: &[u8; 32]) -> Result<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key_enc).map_err(|_| DeriveError::HmacInit)?;
    mac.update(b"hs/tag8/v1");
    let full = mac.finalize().into_bytes();
    // Anti-ambiguity guard: tag8 must never equal PROTOCOL_VERSION_V1,
    // so byte[2] == PROTOCOL_VERSION_V1 uniquely signals a legacy V1 frame.
    let mut tag8 = full[0];
    if tag8 == crate::crypto::PROTOCOL_VERSION_V1 {
        tag8 = full[1];
        if tag8 == crate::crypto::PROTOCOL_VERSION_V1 {
            tag8 = full[2] ^ 0x5a;
            if tag8 == crate::crypto::PROTOCOL_VERSION_V1 {
                tag8 ^= 0xff;
            }
        }
    }
    Ok(tag8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism_v2() {
        // Test V2 (Argon2id) determinism
        let params1 = derive_from_passphrase_v2("gattosegreto123").unwrap();
        let params2 = derive_from_passphrase_v2("gattosegreto123").unwrap();

        assert_eq!(params1.port, params2.port);
        assert_eq!(params1.key_enc, params2.key_enc);
        assert_eq!(params1.key_mac, params2.key_mac);
        assert_eq!(params1.tag16, params2.tag16);
        assert_eq!(params1.tag8, params2.tag8);
        assert_eq!(params1.version, 2);

        let params3 = derive_from_passphrase_v2("passworddiversa").unwrap();
        assert_ne!(params1.port, params3.port);
        assert_ne!(params1.tag16, params3.tag16);
        assert_ne!(params1.tag8, params3.tag8);
    }

    #[test]
    fn test_determinism_v1_compatibility() {
        // Test V1 (SHA256) still works
        let params1 = derive_from_passphrase_v1("gattosegreto123").unwrap();
        let params2 = derive_from_passphrase_v1("gattosegreto123").unwrap();

        assert_eq!(params1.port, params2.port);
        assert_eq!(params1.key_enc, params2.key_enc);
        assert_eq!(params1.version, 1);
    }

    #[test]
    fn test_v1_v2_different() {
        // V1 e V2 devono produrre parametri diversi (diversi domini)
        let params_v1 = derive_from_passphrase_v1("test123").unwrap();
        let params_v2 = derive_from_passphrase_v2("test123").unwrap();

        assert_ne!(params_v1.port, params_v2.port);
        assert_ne!(params_v1.key_enc, params_v2.key_enc);
        assert_ne!(params_v1.tag16, params_v2.tag16);
        assert_ne!(params_v1.tag8, params_v2.tag8);
        assert_eq!(params_v1.version, 1);
        assert_eq!(params_v2.version, 2);
    }

    #[test]
    fn test_port_range() {
        for i in 0..100 {
            let params = derive_from_passphrase(&format!("test{}", i)).unwrap();
            assert!(params.port >= MIN_EPHEMERAL_PORT);
            assert!(params.port < MAX_PORT);
        }
    }
}
