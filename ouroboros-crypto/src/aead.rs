use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::CryptoError;

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::{xchacha20poly1305_decrypt, xchacha20poly1305_encrypt};

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let plaintext = b"ouroboros-crypto aead";
        let aad = b"associated-data";

        let ciphertext = xchacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let key = [3u8; 32];
        let nonce = [4u8; 24];
        let plaintext = b"integrity protected";

        let ciphertext = xchacha20poly1305_encrypt(&key, &nonce, plaintext, b"aad-a").unwrap();
        let decrypted = xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, b"aad-b");

        assert!(decrypted.is_err());
    }
}
