use thiserror::Error;

pub mod aead;
pub mod derive;
pub mod hash;
pub mod kdf;
pub mod pq;
pub mod random;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("kdf failed")]
    KdfFailed,
    #[error("argon2 failed")]
    Argon2Failed,
    #[error("random generation failed")]
    RandomFailed,
    #[error("post-quantum feature is disabled")]
    FeatureDisabled,
}
