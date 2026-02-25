use sha2::{Digest, Sha256, Sha512};

pub fn blake3_hash(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

pub fn sha256_hash(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    digest.into()
}

pub fn sha512_hash(input: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(input);
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::{blake3_hash, sha256_hash, sha512_hash};

    #[test]
    fn blake3_has_fixed_size() {
        let digest = blake3_hash(b"ouroboros");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256_hash(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha512_has_fixed_size() {
        let digest = sha512_hash(b"ouroboros");
        assert_eq!(digest.len(), 64);
    }
}
