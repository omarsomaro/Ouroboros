use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::CryptoError;

pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if output_len == 0 {
        return Err(CryptoError::InvalidInput("output_len must be > 0"));
    }

    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = Zeroizing::new(vec![0u8; output_len]);
    hkdf.expand(info, output.as_mut_slice())
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(output)
}

pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if output_len == 0 {
        return Err(CryptoError::InvalidInput("output_len must be > 0"));
    }

    let params =
        Params::new(19_456, 2, 1, Some(output_len)).map_err(|_| CryptoError::Argon2Failed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = Zeroizing::new(vec![0u8; output_len]);
    argon2
        .hash_password_into(password, salt, output.as_mut_slice())
        .map_err(|_| CryptoError::Argon2Failed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{argon2id, hkdf_sha256};

    #[test]
    fn hkdf_derives_expected_length() {
        let out = hkdf_sha256(b"ikm", Some(b"salt"), b"info", 32).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn hkdf_same_inputs_same_outputs() {
        let a = hkdf_sha256(b"ikm", Some(b"salt"), b"ctx", 42).unwrap();
        let b = hkdf_sha256(b"ikm", Some(b"salt"), b"ctx", 42).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn argon2id_derives_expected_length() {
        let out = argon2id(b"correct horse battery staple", b"saltysalt", 32).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn argon2id_rejects_zero_output() {
        let res = argon2id(b"pw", b"saltysalt", 0);
        assert!(res.is_err());
    }
}
