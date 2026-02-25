# Task: Create ouroboros-crypto crate

Create a new Rust crate at `ouroboros-crypto/` with concrete cryptographic primitives.

## Files to Create

### 1. ouroboros-crypto/Cargo.toml
```toml
[package]
name = "ouroboros-crypto"
version = "0.1.0"
edition = "2021"

[dependencies]
chacha20poly1305 = "0.10"
hkdf = "0.12"
sha2 = "0.10"
blake3 = "1.5"
argon2 = "0.5"
rand = "0.8"
zeroize = { version = "1.7", features = ["zeroize_derive"] }
thiserror = "1.0"
pqcrypto-kyber = { version = "0.8", optional = true }
pqcrypto-traits = { version = "0.3", optional = true }

[features]
default = []
post-quantum = ["dep:pqcrypto-kyber", "dep:pqcrypto-traits"]
```

### 2. ouroboros-crypto/src/lib.rs
Create error type and module declarations.

### 3. ouroboros-crypto/src/aead.rs
XChaCha20-Poly1305 wrapper functions.

### 4. ouroboros-crypto/src/kdf.rs
HKDF-SHA256 and Argon2 wrappers.

### 5. ouroboros-crypto/src/hash.rs
Blake3 and SHA2 wrappers.

### 6. ouroboros-crypto/src/random.rs
Secure random generation.

### 7. ouroboros-crypto/src/pq.rs
Post-quantum crypto (Kyber), feature-gated.

## Requirements
- ZERO business logic
- Concrete functions (no traits for public API)
- Zeroize awareness
- Inline tests in each module
- Must compile with `cargo build -p ouroboros-crypto`
- Must pass `cargo test -p ouroboros-crypto`

Run the cargo commands and report results.
