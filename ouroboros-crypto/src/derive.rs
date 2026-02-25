use crate::CryptoError;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Espansione HKDF-SHA256 generica
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Sale opzionale (None = salt vuoto)
/// * `info` - Context information (domain separation)
/// * `out_len` - Lunghezza output desiderata
pub fn hkdf_expand(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if out_len == 0 {
        return Err(CryptoError::InvalidInput("out_len must be > 0"));
    }
    if out_len > 255 * 32 {
        return Err(CryptoError::InvalidInput(
            "out_len too large for HKDF-SHA256",
        ));
    }

    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = Zeroizing::new(vec![0u8; out_len]);
    hkdf.expand(info, output.as_mut_slice())
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(output)
}

/// Deriva array di byte di lunghezza fissa
///
/// Helper per derivare chiavi/chiavi MAC di dimensione fissa
pub fn hkdf_expand_array<const N: usize>(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; N], CryptoError> {
    let expanded = hkdf_expand(ikm, salt, info, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(&expanded);
    Ok(array)
}

/// Deriva salt deterministico da una passphrase
///
/// Utile per rendere Argon2 deterministico (stessa passphrase = stesso salt)
pub fn derive_salt_from_passphrase(passphrase_bytes: &[u8]) -> Result<[u8; 16], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"ouroboros/derive-salt/v1"), passphrase_bytes);
    let mut out = [0u8; 16];
    hkdf.expand(b"ouroboros/salt/v1", &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(out)
}

/// Argon2id con parametri configurabili
///
/// # Arguments
/// * `password` - Password input
/// * `salt` - Sale (16 bytes raccomandati)
/// * `memory_kb` - Memoria in KB (es. 8192, 19456)
/// * `iterations` - Iterazioni (es. 3)
/// * `parallelism` - Parallelismo (es. 1)
/// * `out_len` - Lunghezza output
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if out_len == 0 {
        return Err(CryptoError::InvalidInput("out_len must be > 0"));
    }

    let params = argon2::Params::new(memory_kb, iterations, parallelism, Some(out_len))
        .map_err(|_| CryptoError::Argon2Failed)?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = Zeroizing::new(vec![0u8; out_len]);
    argon2
        .hash_password_into(password, salt, output.as_mut_slice())
        .map_err(|_| CryptoError::Argon2Failed)?;
    Ok(output)
}

/// Argon2id con parametri di default bilanciati (Handshacke mode)
///
/// Usa: memory_kb=19456, iterations=2, parallelism=1
pub fn argon2id_derive_standard(
    password: &[u8],
    salt: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    argon2id_derive(password, salt, 19456, 2, 1, out_len)
}

/// Argon2id con parametri minimali (testing/development mode)
///
/// Usa: memory_kb=8192, iterations=1, parallelism=1
pub fn argon2id_derive_minimal(
    password: &[u8],
    salt: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    argon2id_derive(password, salt, 8192, 1, 1, out_len)
}

/// Canonicalizza passphrase per derivazione deterministica
///
/// Applica:
/// - Rimuove BOM (\u{FEFF})
/// - Normalizza newline (\r\n → \n, \r → \n)
/// - Rimuove trailing newlines
/// - NFC Unicode normalization
pub fn canonicalize_passphrase(passphrase: &str) -> Vec<u8> {
    use unicode_normalization::UnicodeNormalization;

    // Rimuove BOM
    let s = passphrase.strip_prefix('\u{FEFF}').unwrap_or(passphrase);

    // Normalizza newline
    let s = s.replace("\r\n", "\n").replace('\r', "\n");

    // Rimuove trailing newlines
    let s = s.trim_end_matches('\n');

    // NFC Unicode normalization
    let nfc: String = s.nfc().collect();

    nfc.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_deterministic() {
        let ikm = b"test input key material";
        let salt = b"test salt";
        let info = b"test domain";

        let a = hkdf_expand(ikm, Some(salt), info, 32).unwrap();
        let b = hkdf_expand(ikm, Some(salt), info, 32).unwrap();

        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn hkdf_expand_different_info_different_output() {
        let ikm = b"same input";
        let salt = b"same salt";

        let a = hkdf_expand(ikm, Some(salt), b"domain A", 32).unwrap();
        let b = hkdf_expand(ikm, Some(salt), b"domain B", 32).unwrap();

        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn hkdf_expand_array_fixed_size() {
        let result: [u8; 64] = hkdf_expand_array(b"ikm", None, b"info").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn derive_salt_deterministic() {
        let pass = b"my passphrase";
        let a = derive_salt_from_passphrase(pass).unwrap();
        let b = derive_salt_from_passphrase(pass).unwrap();

        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn derive_salt_different_pass_different_salt() {
        let a = derive_salt_from_passphrase(b"pass A").unwrap();
        let b = derive_salt_from_passphrase(b"pass B").unwrap();

        assert_ne!(a, b);
    }

    #[test]
    fn argon2id_derives_expected_length() {
        let salt = derive_salt_from_passphrase(b"test").unwrap();
        let out = argon2id_derive_standard(b"password", &salt, 32).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn argon2id_deterministic_with_same_salt() {
        let salt = [1u8; 16];
        let a = argon2id_derive_minimal(b"password", &salt, 32).unwrap();
        let b = argon2id_derive_minimal(b"password", &salt, 32).unwrap();

        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn argon2id_rejects_zero_output() {
        let salt = [1u8; 16];
        let result = argon2id_derive_standard(b"password", &salt, 0);
        assert!(result.is_err());
    }

    #[test]
    fn canonicalize_passphrase_basic() {
        let s = "hello world";
        let result = canonicalize_passphrase(s);
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn canonicalize_passphrase_nfc() {
        // 'é' può essere rappresentato come U+00E9 oppure U+0065 U+0301 (e + accento)
        let s = "caf\u{0065}\u{0301}"; // c a f e + combining acute accent
        let result = canonicalize_passphrase(s);
        assert_eq!(result, "caf\u{00e9}".as_bytes()); // deve diventare U+00E9 precomposto
    }

    #[test]
    fn canonicalize_passphrase_newlines() {
        let s = "line1\r\nline2\rline3\n";
        let result = canonicalize_passphrase(s);
        assert_eq!(result, b"line1\nline2\nline3"); // normalizzato e senza trailing newline
    }

    #[test]
    fn canonicalize_passphrase_bom() {
        let s = "\u{FEFF}content";
        let result = canonicalize_passphrase(s);
        assert_eq!(result, b"content");
    }

    #[test]
    fn full_derivation_workflow() {
        // Simula il workflow di Handshacke
        let passphrase = "test passphrase";

        // 1. Canonicalizza
        let pass_bytes = canonicalize_passphrase(passphrase);

        // 2. Deriva salt deterministico
        let salt = derive_salt_from_passphrase(&pass_bytes).unwrap();

        // 3. Argon2id per master key
        let master_key = argon2id_derive_minimal(&pass_bytes, &salt, 32).unwrap();

        // 4. HKDF expand per sottokiavi
        let port_key: [u8; 2] = hkdf_expand_array(&master_key, None, b"port").unwrap();
        let enc_key: [u8; 32] = hkdf_expand_array(&master_key, None, b"enc").unwrap();

        assert_eq!(port_key.len(), 2);
        assert_eq!(enc_key.len(), 32);
    }
}
