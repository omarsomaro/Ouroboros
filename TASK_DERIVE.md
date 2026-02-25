# Task: Aggiungi modulo derive.rs a ouroboros-crypto

Aggiungi a ouroboros-crypto/src/derive.rs con primitivi di derivazione generici.

## Da Implementare

### 1. ouroboros-crypto/src/derive.rs

```rust
// Primitivi di derivazione generici per Handshacke ed EtherSync

use crate::CryptoError;
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
    // Usa hkdf crate, output in Zeroizing<Vec<u8>>
}

/// Deriva salt deterministico da una passphrase
/// 
/// Utile per rendere Argon2 deterministico (stessa passphrase = stesso salt)
pub fn derive_salt_from_passphrase(passphrase_bytes: &[u8]) -> Result<[u8; 16], CryptoError> {
    // HKDF con salt fisso "ouroboros/derive-salt/v1"
    // Domain: "ouroboros/salt/v1"
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
    // Parametri configurabili per permettere sia uso leggero che sicuro
}

/// Argon2id con parametri di default bilanciati (Handshacke mode)
pub fn argon2id_derive_standard(
    password: &[u8],
    salt: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // memory_kb=19456, iterations=2, parallelism=1
}

/// Canonicalizza passphrase per derivazione deterministica
/// 
/// Applica:
/// - Rimuove BOM (\u{FEFF})
/// - Normalizza newline (\\r\\n → \\n, \\r → \\n)
/// - Rimuove trailing newlines
/// - NFC Unicode normalization
pub fn canonicalize_passphrase(passphrase: &str) -> Vec<u8> {
    // Implementa canonicalizzazione completa
}

/// Deriva array di byte di lunghezza fissa
/// 
/// Helper per derivare chiavi/chiavi MAC di dimensione fissa
pub fn hkdf_expand_array<const N: usize>(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; N], CryptoError> {
    // Espande in array di dimensione fissa
}

#[cfg(test)]
mod tests {
    // Test determinismo
    // Test domain separation (stesso IKM, info diversa = output diverso)
    // Test canonicalizzazione
    // Test argon2id con parametri vari
}
```

### 2. Aggiorna ouroboros-crypto/src/lib.rs

Aggiungi:
```rust
pub mod derive;
```

### 3. Requisiti

- Tutti gli output sensibili devono essere `Zeroizing<Vec<u8>>` o `[u8; N]`
- Error handling con `CryptoError` esistente
- Test completi per determinismo e domain separation
- Niente tipi specifici di protocollo (no RendezvousParams, no EtherCoordinate)

### 4. Verifica Finale

```bash
cargo build -p ouroboros-crypto
cargo test -p ouroboros-crypto
cargo test -p ouroboros-crypto --features post-quantum
```

## Nota

Questo modulo fornisce i mattoni per:
- handshacke/src/derive.rs → costruisce RendezvousParams
- ethersync/src/coordinate.rs → costruisce EtherCoordinate

Ma non include i tipi specifici.
