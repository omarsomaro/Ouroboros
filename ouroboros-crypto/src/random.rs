use zeroize::Zeroizing;

use crate::CryptoError;

pub fn random_bytes(length: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut output = Zeroizing::new(vec![0u8; length]);
    fill_random(output.as_mut_slice())?;
    Ok(output)
}

pub fn fill_random(buffer: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buffer).map_err(|_| CryptoError::RandomFailed)
}

pub fn random_array_32() -> Result<[u8; 32], CryptoError> {
    let mut output = [0u8; 32];
    fill_random(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{fill_random, random_array_32, random_bytes};

    #[test]
    fn random_bytes_returns_expected_length() {
        let bytes = random_bytes(48).unwrap();
        assert_eq!(bytes.len(), 48);
    }

    #[test]
    fn fill_random_succeeds() {
        let mut data = [0u8; 16];
        fill_random(&mut data).unwrap();
        assert_eq!(data.len(), 16);
    }

    #[test]
    fn random_array_32_returns_32_bytes() {
        let bytes = random_array_32().unwrap();
        assert_eq!(bytes.len(), 32);
    }
}
