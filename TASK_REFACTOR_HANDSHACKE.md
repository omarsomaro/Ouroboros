# Task: Refactor handshacke to use ouroboros-crypto

Update the handshacke crate to use ouroboros-crypto instead of direct crypto dependencies.

## 1. Update handshacke/Cargo.toml

Remove duplicate crypto dependencies that are now in ouroboros-crypto:
- Remove: hkdf, sha2, chacha20poly1305, chacha20, blake3, argon2, rand (partial)
- Keep: x25519-dalek, aead, hmac, secrecy, zeroize (needed for Noise protocol)
- Add: ouroboros-crypto = { path = "../ouroboros-crypto" }

## 2. Refactor handshacke/src/derive.rs

Replace direct crypto calls with ouroboros_crypto::derive::*:

```rust
use ouroboros_crypto::derive::{
    canonicalize_passphrase, derive_salt_from_passphrase, 
    hkdf_expand_array, argon2id_derive_standard
};

// Keep: RendezvousParams struct (it's protocol-specific)
// Keep: derive_from_passphrase_v2(), derive_from_passphrase_v1()
// Keep: derive_tag8_from_key(), derive_from_passphrase_v2_stealth()

// But replace internals:
// - canonicalize_passphrase_bytes() -> use ouroboros_crypto::derive::canonicalize_passphrase
// - derive_argon2_salt_v2() -> use ouroboros_crypto::derive::derive_salt_from_passphrase
// - HKDF calls -> use ouroboros_crypto::derive::hkdf_expand_array
// - Argon2 calls -> use ouroboros_crypto::derive::argon2id_derive_standard
```

## 3. Refactor handshacke/src/crypto.rs

Replace with ouroboros_crypto::aead::*:

```rust
use ouroboros_crypto::aead::{
    xchacha20poly1305_encrypt, xchacha20poly1305_decrypt
};
use ouroboros_crypto::hash::{blake3_hash, sha256_hash};

// Keep: pad_to_mtu(), hash_offer()
// Replace: encrypt/decrypt implementations with ouroboros_crypto calls
```

## 4. Update other files

In src/session_noise.rs, src/protocol.rs, src/protocol_assist.rs, etc.:
- Replace `use crate::crypto::*` with `use ouroboros_crypto::*` where appropriate
- Keep Noise protocol logic (uses x25519-dalek, snow crate)

## 5. Critical Requirements

- ALL existing tests must still pass
- Determinism must be preserved (same passphrase = same RendezvousParams)
- Do NOT change logic, only replace crypto primitive calls
- Keep x25519-dalek and snow (Noise) - these stay in handshacke

## 6. Verification

After changes, run:
```bash
cargo build -p handshacke
cargo test -p handshacke
```

All tests must pass, especially:
- derive::tests::test_determinism_v2
- derive::tests::test_v1_v2_different
- All protocol tests

## 7. Note on Compatibility

The ouroboros_crypto::derive functions produce the SAME output as the original implementations:
- HKDF-SHA256 with same IKM/salt/info = same output
- Argon2id with same params = same output
- Canonicalization = same NFC+BOM+newline handling

So handshacke behavior should be identical after refactoring.
