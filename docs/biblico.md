# BIBLIA ARCHITETTURALE - OUROBOROS P2P ECOSYSTEM

**Versione**: 1.0  
**Data**: 2025-02-22  
**Autore**: Analisi Architetturale Professionale  
**Stato**: State of the Art P2P Architecture Analysis

---

## NOTE DI ALLINEAMENTO (2026-02-23)

Questo documento resta valido come visione architetturale, ma alcune metriche numeriche sono storiche.
Per il piano operativo aggiornato usare:

- `docs/state_of_the_art_checklist.md` (checklist eseguibile con priorita/DoD)
- `docs/future.md` (specifica EtherSync in modalita living document)

---

## INDICE

1. [Visione e Filosofia](#1-visione-e-filosofia)
2. [Architettura Macro](#2-architettura-macro)
3. [Analisi Crate per Crate](#3-analisi-crate-per-crate)
4. [Flusso di Dati Dettagliato](#4-flusso-di-dati-dettagliato)
5. [Pattern Architetturali](#5-pattern-architetturali)
6. [Sicurezza e Crittografia](#6-sicurezza-e-crittografia)
7. [Performance e Ottimizzazioni](#7-performance-e-ottimizzazioni)
8. [Testing e Qualità](#8-testing-e-qualità)
9. [Roadmap State of the Art](#9-roadmap-state-of-the-art)
10. [Conclusioni](#10-conclusioni)

---

## 1. VISIONE E FILOSOFIA

### 1.1 Il Problema che Risolve

Ouroboros risolve il problema fondamentale della **comunicazione P2P senza infrastruttura centralizzata**:

- **No server discovery**: I peer si trovano tramite derivazione deterministica da passphrase
- **No DNS**: Nessun dipendenza da sistemi di nomi centralizzati
- **No PKI**: Nessuna autorità di certificazione
- **No contemporaneità richiesta**: EtherSync permette comunicazione asincrona

### 1.2 Principi Guida

1. **Determinismo Matematico**: Stessa passphrase = stessi parametri di rete, sempre
2. **Zero Trust**: Ogni connessione è autenticata via Noise Protocol
3. **Privacy by Design**: Tor integration, DPI evasion, metadata minimization
4. **Resilienza**: Multiple strategie di trasporto con fallback automatico
5. **Modularità**: Componenti intercambiabili, feature flags granulari

### 1.3 Differenziazione Competitiva

| Progetto | Centralizzato | P2P Puro | Async | Post-Quantum | DPI Evasion |
|----------|--------------|----------|-------|--------------|-------------|
| Signal | ❌ Parzialmente | ❌ | ❌ | ❌ | ❌ |
| Briar | ✅ | ✅ | ✅ | ❌ | ✅ |
| Tox | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Ouroboros** | ✅ **100%** | ✅ | ✅ **EtherSync** | ✅ **Opzionale** | ✅ **Pluggable** |

---

## 2. ARCHITETTURA MACRO

### 2.1 Diagramma Architetturale Completo

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              WORKSPACE OUROBOROS                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                         CRATE: handshacke                               │   │
│  │                    (P2P Connection-Oriented Daemon)                     │   │
│  │                        ~6,500 righe di codice                           │   │
│  ├─────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                          │   │
│  │   ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────┐  │   │
│  │   │   API LAYER     │  │   CORE LAYER    │  │    TRANSPORT LAYER     │  │   │
│  │   │   (axum HTTP)   │  │                 │  │                        │  │   │
│  │   │                 │  │  • derive.rs    │  │  • LAN (UDP broadcast) │  │   │
│  │   │  Endpoints:     │  │  • offer.rs     │  │  • WAN Direct (UPnP)   │  │   │
│  │   │  /v1/connect    │  │  • crypto.rs    │  │  • WAN Assist (relay)  │  │   │
│  │   │  /v1/send       │  │  • session_     │  │  • Tor (SOCKS5)        │  │   │
│  │   │  /v1/recv       │  │    noise.rs     │  │  • QUIC (optional)     │  │   │
│  │   │  /v1/offer      │  │  • protocol*.rs │  │  • WebRTC (optional)   │  │   │
│  │   │  /v1/qr/*       │  │  • resume.rs    │  │  • Pluggable (DPI)     │  │   │
│  │   │                 │  │                 │  │                        │  │   │
│  │   │  2,076 righe    │  │  ~2,000 righe   │  │  ~7,000 righe          │  │   │
│  │   └─────────────────┘  └─────────────────┘  └────────────────────────┘  │   │
│  │                                                                          │   │
│  │   ┌─────────────────┐  ┌─────────────────┐  ┌────────────────────────┐  │   │
│  │   │  STATE LAYER    │  │ SECURITY LAYER  │  │    UTILITY LAYER       │  │   │
│  │   │                 │  │                 │  │                        │  │   │
│  │   │ • AppState      │  │ • rate_limiting │  │ • config.rs            │  │   │
│  │   │ • Connection    │  │ • time_valid    │  │ • chunk.rs             │  │   │
│  │   │   tracking      │  │ • replay.rs     │  │ • onion.rs             │  │   │
│  │   │ • Metrics       │  │ • early_drop    │  │ • phrase.rs            │  │   │
│  │   │                 │  │                 │  │ • cli/                 │  │   │
│  │   └─────────────────┘  └─────────────────┘  └────────────────────────┘  │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                            │
│                                    │ dipende da                                  │
│  ┌─────────────────────────────────┴─────────────────────────────────────────┐   │
│  │                      CRATE: ouroboros-crypto                              │   │
│  │               (Cryptographic Primitives Library)                          │   │
│  │                         ~600 righe di codice                              │   │
│  ├─────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │   │
│  │  │   derive.rs  │  │   aead.rs    │  │   hash.rs    │  │    pq.rs     │  │   │
│  │  │   261 righe  │  │   74 righe   │  │   43 righe   │  │   88 righe   │  │   │
│  │  │              │  │              │  │              │  │              │  │   │
│  │  │ • Argon2id   │  │ • XChaCha20  │  │ • Blake3     │  │ • Kyber1024  │  │   │
│  │  │ • HKDF-SHA256│  │ • Poly1305   │  │ • SHA256     │  │ • Hybrid PQ  │  │   │
│  │  │ • Canonical  │  │ • AEAD       │  │ • SHA512     │  │   (optional) │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │   │
│  │                                                                          │   │
│  │  Feature: post-quantum (opzionale, abilita Kyber)                        │   │
│  │  Zero business logic - solo primitivi matematici                         │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                    ▲                                            │
│                                    │ dipende da                                  │
│  ┌─────────────────────────────────┴─────────────────────────────────────────┐   │
│  │                      CRATE: ethersync                                     │   │
│  │           (Connectionless Gossip Protocol)                                │   │
│  │                         ~3,500 righe di codice                            │   │
│  ├─────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                          │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │   │
│  │  │                    GOSSIP ENGINE (775 righe)                      │   │   │
│  │  │                                                                  │   │   │
│  │  │  • Anti-Entropy Protocol        • Bloom Filter (1KB, 3 hashes)  │   │   │
│  │  │  • Digest Exchange              • TTL Forwarding                │   │   │
│  │  │  • Request/Response             • Peer Management (max 50)      │   │   │
│  │  │                                                                  │   │   │
│  │  └──────────────────────────────────────────────────────────────────┘   │   │
│  │                                                                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │   │
│  │  │   node.rs    │  │  network.rs  │  │  storage.rs  │  │ message.rs   │  │   │
│  │  │   584 righe  │  │   483 righe  │  │   320 righe  │  │  276 righe   │  │   │
│  │  │              │  │              │  │              │  │              │  │   │
│  │  │ • EtherNode  │  │ • UDP socket │  │ • SQLite     │  │ • Encryption │  │   │
│  │  │ • publish()  │  │ • Framing    │  │ • In-memory  │  │ • Fragments  │  │   │
│  │  │ • subscribe()│  │ • Rate limit │  │ • Slot-based │  │ • Serialize  │  │   │
│  │  │ • run()      │  │ • Async I/O  │  │ • Queries    │  │ • Deserialize│  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │   │
│  │                                                                          │   │
│  │  ┌──────────────┐  ┌──────────────────────────────────────────────────┐  │   │
│  │  │coordinate.rs │  │        erasure_coding.rs (264 righe)              │  │   │
│  │  │   130 righe  │  │                                                  │  │   │
│  │  │              │  │  • Stub per Reed-Solomon (futuro)                │  │   │
│  │  │ • Time slots │  │  • Compressione LZ4 (feature)                    │  │   │
│  │  │ • Derivation │  │  • Metrics Prometheus (feature)                  │  │   │
│  │  │ • LOOKBACK   │  │                                                  │  │   │
│  │  └──────────────┘  └──────────────────────────────────────────────────┘  │   │
│  │                                                                          │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Flusso di Dipendenze

```
┌─────────────────────────────────────────────────────────────────┐
│                    FLUSSO DIPENDENZE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ouroboros-crypto                                               │
│       │                                                         │
│       ├──► handshacke (usato per derive, crypto)                │
│       │                                                         │
│       └──► ethersync (usato per derive, crypto, hash)           │
│                     │                                           │
│                     └──► handshacke (integrazione opzionale)    │
│                                                                 │
│  Dipendenze Esterne Comuni:                                     │
│  • tokio (async runtime)                                       │
│  • serde (serialization)                                       │
│  • tracing (logging)                                           │
│  • thiserror/anyhow (error handling)                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Configurazione Workspace

**Problema Architetturale**: Il workspace è **ibrido** (non convenzionale).

```toml
# Cargo.toml root
[package]                       # Crate handshacke (root)
name = "handshacke"
version = "0.1.0"
edition = "2021"

[dependencies]
# ... 40+ dipendenze
ouroboros-crypto = { path = "./ouroboros-crypto" }  # Dipendenza path

[workspace]                     # Workspace members
members = ["ethersync", "ouroboros-crypto"]
resolver = "2"
```

**Analisi**:
- ✅ Funziona correttamente
- ⚠️ Confusione: `handshacke` è sia crate root che membro implicito
- ⚠️ `ethersync` dipende da `ouroboros-crypto` ma non da `handshacke`
- ✅ Nessuna dipendenza circolare

---

## 3. ANALISI CRATE PER CRATE

### 3.1 OUROBOROS-CRYPTO: La Fondazione Matematica

**Responsabilità**: Primitivi crittografici puri, zero business logic.

#### 3.1.1 Struttura Moduli

| File | Righe | Responsabilità |
|------|-------|----------------|
| `lib.rs` | 26 | Definizione `CryptoError` |
| `derive.rs` | 261 | Argon2id, HKDF, canonicalizzazione |
| `aead.rs` | 74 | XChaCha20-Poly1305 |
| `hash.rs` | 43 | Blake3, SHA256, SHA512 |
| `kdf.rs` | 72 | HKDF utilities |
| `random.rs` | 49 | OsRng wrapper |
| `pq.rs` | 88 | Kyber1024 (feature-gated) |

**Totale**: 613 righe di codice crittografico testato.

#### 3.1.2 API Pubblica Dettagliata

```rust
// derive.rs - Primitivi di derivazione
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_kb: u32,
    iterations: u32,
    parallelism: u32,
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

pub fn hkdf_expand_array<const N: usize>(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; N], CryptoError>;

pub fn canonicalize_passphrase(passphrase: &str) -> Vec<u8>;
pub fn derive_salt_from_passphrase(passphrase: &[u8]) -> Result<[u8; 16], CryptoError>;

// aead.rs - Cifratura autenticata
pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError>;

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError>;

// hash.rs - Funzioni di hash
pub fn blake3_hash(input: &[u8]) -> [u8; 32];
pub fn sha256_hash(input: &[u8]) -> [u8; 32];
pub fn sha512_hash(input: &[u8]) -> [u8; 64];

// pq.rs - Post-quantum (feature-gated)
pub fn kyber1024_keypair() -> Result<KyberKeypair, CryptoError>;
pub fn kyber1024_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CryptoError>;
pub fn kyber1024_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
```

#### 3.1.3 Design Pattern

**Zeroization Automatica**:
```rust
use zeroize::Zeroizing;

pub fn argon2id_derive(...) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut output = Zeroizing::new(vec![0u8; output_len]);
    // ... computazione ...
    Ok(output)  // Auto-zeroize al drop
}
```

**Feature Gating Post-Quantum**:
```rust
#[cfg(feature = "post-quantum")]
pub fn kyber1024_keypair() -> Result<KyberKeypair, CryptoError> {
    // Implementazione reale
}

#[cfg(not(feature = "post-quantum"))]
pub fn kyber1024_keypair() -> Result<KyberKeypair, CryptoError> {
    Err(CryptoError::FeatureDisabled)
}
```

#### 3.1.4 Test Coverage

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn hkdf_same_inputs_same_outputs() { ... }
    
    #[test]
    fn argon2id_derives_expected_length() { ... }
    
    #[test]
    fn encrypt_decrypt_roundtrip() { ... }
    
    #[test]
    fn sha256_matches_known_vector() { ... }
    
    #[cfg(feature = "post-quantum")]
    #[test]
    fn kyber_roundtrip_shared_secret_matches() { ... }
}
```

**Coverage**: 13 test unitari, tutti passanti.

---

### 3.2 HANDSHACKE: Il Motore Connection-Oriented

**Responsabilità**: Comunicazione P2P sincrona con NAT traversal e Noise Protocol.

#### 3.2.1 Struttura Moduli Principali

| Modulo | Righe | Responsabilità | Complessità |
|--------|-------|----------------|-------------|
| `api.rs` | 2,076 | HTTP REST API | 🔴 Alta |
| `transport/` | 7,045 | Multi-trasporto | 🔴 Alta |
| `session_noise.rs` | 697 | Noise handshake | 🟡 Media |
| `crypto.rs` | 683 | Wrapper crittografia | 🟡 Media |
| `protocol_assist_v5.rs` | 592 | Relay protocol v5 | 🟡 Media |
| `config.rs` | 516 | Configurazione | 🟢 Bassa |
| `derive.rs` | 221 | Derivazione parametri | 🟢 Bassa |
| `state.rs` | 270 | Stato applicazione | 🟢 Bassa |

**Totale**: ~13,000 righe (inclusi transport).

#### 3.2.2 Analisi API Layer (api.rs)

**Endpoint HTTP**:

```rust
// POST /v1/connect - Stabilisce connessione P2P
async fn post_connect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConnectionRequest>,
) -> Result<Json<ConnectResponse>, ApiError>;

// POST /v1/send - Invia messaggio cifrato
async fn post_send(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendRequest>,
) -> Result<Json<SendResponse>, ApiError>;

// GET /v1/recv - SSE stream per messaggi in arrivo
async fn get_recv(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>>;

// POST /v1/offer - Genera OfferPayload
async fn post_offer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OfferRequest>,
) -> Result<Json<OfferResponse>, ApiError>;

// POST /v1/qr/hybrid - Genera QR ibrido
async fn post_qr_hybrid(
    State(state): State<Arc<AppState>>,
    Json(req): Json<QrRequest>,
) -> Result<Json<QrResponse>, ApiError>;
```

**Problema**: `api.rs` è un **monolite** (2,076 righe). Contiene:
- Definizione endpoint
- Implementazione handler
- Logica business
- Serializzazione/deserializzazione

**Soluzione State of the Art**: Separare in:
```
api/
├── mod.rs          # Router definition
├── handlers/       # Endpoint handlers
│   ├── connect.rs
│   ├── send.rs
│   └── ...
├── models/         # Request/Response DTOs
│   ├── request.rs
│   └── response.rs
└── middleware/     # Auth, CORS, etc.
    └── auth.rs
```

#### 3.2.3 Analisi Transport Layer

**Struttura Directory**:

```
transport/
├── mod.rs                    # Connection enum, establish_connection()
├── tasks.rs                  # Core logic (798 righe)
├── ice.rs                    # ICE multipath racing (505 righe)
├── pluggable.rs              # DPI evasion (692 righe)
├── wan_assist.rs             # Relay assist (577 righe)
├── nat_detection.rs          # NAT type detection (556 righe)
├── multipath.rs              # Multipath coordination (364 righe)
├── stun.rs                   # STUN client (286 righe)
├── stealth.rs                # Stealth mode (222 righe)
├── quic_rfc9000.rs           # QUIC transport (196 righe)
├── webrtc.rs                 # WebRTC transport (301 righe)
├── tcp_hole_punch.rs         # TCP hole punching (180 righe)
├── icmp_hole_punch.rs        # ICMP hole punching (279 righe)
├── wan_direct.rs             # UPnP/NAT-PMP (325 righe)
├── wan_tor.rs                # Tor SOCKS5 (180 righe)
├── lan.rs                    # LAN broadcast (140 righe)
├── dandelion.rs              # Dandelion routing (90 righe)
├── guaranteed.rs             # Guaranteed relay (90 righe)
├── framing.rs                # Message framing (90 righe)
├── io.rs                     # IO utilities (90 righe)
├── noise_tun.rs              # TUN interface (71 righe)
├── wan/                      # WAN submodules
│   ├── mod.rs
│   ├── wan_direct.rs
│   └── wan_tor.rs
├── wan_assist/               # Assist submodules
│   └── ...
└── pluggable/                # Pluggable submodules
    ├── http2_mimic.rs
    ├── mimicry.rs
    ├── quic_mimic.rs
    ├── real_tls.rs
    └── ws_mimic.rs
```

**Connection Enum** (Strategy Pattern):

```rust
pub enum Connection {
    Lan(Arc<UdpSocket>, SocketAddr),
    Wan(Arc<UdpSocket>, SocketAddr),
    WanTorStream { reader, writer },
    WanTcpStream { reader, writer, peer },
    Quic(Arc<QuinnTransport>),
    WebRtc(Arc<WebRtcTransport>),
}

impl Connection {
    pub async fn send(&self, data: &[u8]) -> Result<()>;
    pub async fn recv(&self) -> Result<Vec<u8>>;
    pub fn is_stream(&self) -> bool;
    pub fn is_tor_stream(&self) -> bool;
}
```

**Problema**: Aggiungere un nuovo trasporto richiede:
1. Modificare `Connection` enum
2. Aggiornare tutti i `match` sul enum
3. Modificare `establish_connection()`
4. Aggiornare feature flags

**Soluzione State of the Art**: Trait-based:
```rust
pub trait Transport: Send + Sync {
    async fn connect(&self, params: &RendezvousParams) -> Result<Box<dyn Connection>>;
    fn priority(&self) -> u8;
    fn name(&self) -> &'static str;
}

pub struct TransportRegistry {
    transports: Vec<Box<dyn Transport>>,
}
```

#### 3.2.4 Analisi Session Noise (session_noise.rs)

**Responsabilità**: Noise Protocol XX handshake.

```rust
pub struct NoiseSession {
    state: snow::StatelessTransportState,
    role: NoiseRole,
}

impl NoiseSession {
    pub async fn handshake_xx(
        connection: &mut Connection,
        params: &RendezvousParams,
        role: RoleHint,
    ) -> Result<Self>;
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

**Pattern**: XX handshake (mutua autenticazione senza PKI).

**Post-Quantum Hybrid**:
```rust
#[cfg(feature = "pq")]
pub async fn handshake_xx_hybrid(
    connection: &mut Connection,
    params: &RendezvousParams,
    role: RoleHint,
) -> Result<Self> {
    // X25519 + Kyber1024
    // Fallback a X25519 se Kyber fallisce
}
```

---

### 3.3 ETHERSYNC: Il Motore Connectionless

**Responsabilità**: Comunicazione asincrona via gossip protocol.

#### 3.3.1 Struttura Moduli

| Modulo | Righe | Responsabilità | Complessità |
|--------|-------|----------------|-------------|
| `gossip.rs` | 775 | Gossip engine | 🔴 Alta |
| `node.rs` | 584 | EtherNode API | 🟡 Media |
| `network.rs` | 483 | UDP networking | 🟡 Media |
| `storage.rs` | 320 | SQLite storage | 🟡 Media |
| `message.rs` | 276 | Message crypto | 🟡 Media |
| `erasure_coding.rs` | 264 | Fragments + compression | 🟢 Bassa |
| `coordinate.rs` | 130 | Time-slot derivation | 🟢 Bassa |
| `lib.rs` | 28 | Re-exports | 🟢 Bassa |

**Totale**: 2,860 righe.

#### 3.3.2 Gossip Protocol Dettagliato

**Architettura Anti-Entropy**:

```
┌─────────────────────────────────────────────────────────────┐
│                    GOSSIP PROTOCOL                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────┐  │
│  │   Node A     │◄────►│   Network    │◄────►│  Node B  │  │
│  │              │      │              │      │          │  │
│  │ ┌──────────┐ │      │              │      │ ┌────────┐ │  │
│  │ │ Storage  │ │      │   Digest     │      │ │Storage │ │  │
│  │ │ Slot 100 │─┼──────┼──► Bloom     │──────┼►│Slot 100│ │  │
│  │ │ Slot 101 │─┼──────┼──► Filter     │──────┼►│Slot 101│ │  │
│  │ └──────────┘ │      │              │      │ └────────┘ │  │
│  └──────────────┘      └──────────────┘      └──────────┘  │
│                                                             │
│  Flusso:                                                    │
│  1. A invia Digest(slot, bloom_filter) a B                  │
│  2. B confronta con proprio storage                         │
│  3. B invia Request(slot, missing_hashes) ad A              │
│  4. A invia Response(messages) a B                          │
│  5. B salva messaggi e inoltra con TTL decrementato         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Implementazione GossipEngine**:

```rust
pub struct GossipEngine {
    storage: Arc<Mutex<EtherStorage>>,
    peers: Arc<PeerManager>,
    socket: Arc<EtherUdpSocket>,
    seen_messages: Arc<RwLock<HashSet<[u8; 32]>>>,
    max_seen_cache: usize,
    gossip_interval_secs: u64,
    default_ttl: u8,
}

impl GossipEngine {
    pub async fn run(&self) -> Result<(), EtherSyncError> {
        // Spawn 3 task paralleli
        let digest_handle = self.spawn_digest_task();
        let receive_handle = self.spawn_receive_task();
        let cleanup_handle = self.spawn_cleanup_task();
        
        tokio::select! {
            _ = digest_handle => {},
            _ = receive_handle => {},
            _ = cleanup_handle => {},
        }
        Ok(())
    }
    
    async fn handle_frame(
        &self,
        frame: GossipFrame,
        from: SocketAddr,
    ) -> Result<(), EtherSyncError> {
        match frame {
            GossipFrame::Digest { slot, bloom_filter, .. } => {
                // Anti-entropy: confronta bloom filter
                let missing = self.find_missing_messages(slot, bloom_filter).await?;
                if !missing.is_empty() {
                    self.request_messages(from, slot, missing).await?;
                }
            }
            GossipFrame::Request { slot, hashes } => {
                // Invia messaggi richiesti
                let messages = self.fetch_messages(slot, hashes).await?;
                self.send_response(from, messages).await?;
            }
            GossipFrame::Response { messages } => {
                // Salva messaggi ricevuti
                self.store_messages(messages).await?;
                // Forward con TTL decrementato
                self.forward_messages(messages, from).await?;
            }
            GossipFrame::Forward { ttl, message } => {
                if ttl > 0 {
                    self.store_and_forward(message, ttl - 1, from).await?;
                }
            }
            GossipFrame::Ping => self.send_pong(from).await?,
            GossipFrame::Pong => {},
        }
        Ok(())
    }
}
```

**Bloom Filter**:

```rust
pub struct BloomFilter {
    bits: BitVec<u8, Msb0>,  // 1KB = 8192 bits
    size: usize,
    hash_count: usize,        // 3 hash functions
}

impl BloomFilter {
    pub fn add(&mut self, item: &[u8]) {
        for i in 0..self.hash_count {
            let hash = xxh3_64(&[item, &i.to_le_bytes()].concat());
            let index = (hash % self.size as u64) as usize;
            self.bits.set(index, true);
        }
    }
    
    pub fn contains(&self, item: &[u8]) -> bool {
        // May have false positives, never false negatives
        for i in 0..self.hash_count {
            let hash = xxh3_64(&[item, &i.to_le_bytes()].concat());
            let index = (hash % self.size as u64) as usize;
            if !self.bits[index] {
                return false;
            }
        }
        true
    }
}
```

#### 3.3.3 EtherNode API

```rust
pub struct EtherNode {
    config: NodeConfig,
    storage: Arc<Mutex<EtherStorage>>,
    socket: Arc<EtherUdpSocket>,
    gossip: GossipEngine,
    peers: Arc<PeerManager>,
    subscriptions: Arc<RwLock<Vec<Subscription>>>,
}

impl EtherNode {
    /// Crea nuovo nodo
    pub async fn new(config: NodeConfig) -> Result<Self, EtherSyncError>;
    
    /// Pubblica messaggio nello spazio condiviso
    pub async fn publish(
        &self,
        passphrase: &str,
        payload: &[u8],
    ) -> Result<EtherMessage, EtherSyncError>;
    
    /// Sottoscrivi a passphrase
    pub async fn subscribe(
        &self,
        passphrase: &str,
    ) -> Result<mpsc::Receiver<EtherMessage>, EtherSyncError>;
    
    /// Avvia nodo con tutti i task
    pub async fn run(&self, shutdown_rx: watch::Receiver<bool>) -> Result<(), EtherSyncError>;
}
```

---

## 4. FLUSSO DI DATI DETTAGLIATO

### 4.1 Handshacke: Connessione Completa

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLUSSO CONNESSIONE HANDSHACKE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  UTENTE                          SISTEMA                                    │
│    │                                │                                       │
│    │ POST /v1/connect              │                                       │
│    │ { passphrase: "xyz" }         │                                       │
│    ├──────────────────────────────►│                                       │
│    │                                │                                       │
│    │                                ├─► derive_from_passphrase("xyz")      │
│    │                                │   └── RendezvousParams {             │
│    │                                │         port: 49234,                 │
│    │                                │         key_enc: [u8; 32],            │
│    │                                │         key_mac: [u8; 32],            │
│    │                                │         tag16: 12345                  │
│    │                                │       }                               │
│    │                                │                                       │
│    │                                ├─► establish_connection(params)       │
│    │                                │   ├── try_lan_broadcast()            │
│    │                                │   ├── try_wan_direct_upnp()          │
│    │                                │   ├── try_stun_hole_punch()          │
│    │                                │   └── try_tor_fallback()             │
│    │                                │                                       │
│    │                                ├─► Connection::Wan(socket, addr)      │
│    │                                │                                       │
│    │                                ├─► NoiseSession::handshake_xx()        │
│    │                                │   ├── XX handshake pattern            │
│    │                                │   ├── X25519 key exchange             │
│    │                                │   └── [optional] Kyber1024 hybrid     │
│    │                                │                                       │
│    │                                ├─► SessionKeyState {                   │
│    │                                │       cipher: XChaCha20-Poly1305      │
│    │                                │     }                                 │
│    │                                │                                       │
│    │ 200 OK                         │                                       │
│    │ { session_id: "abc" }          │                                       │
│    │◄──────────────────────────────┤                                       │
│    │                                │                                       │
│    │ POST /v1/send                │                                       │
│    │ { session_id: "abc",           │                                       │
│    │   message: "Hello" }           │                                       │
│    ├──────────────────────────────►│                                       │
│    │                                ├─► SessionKeyState::encrypt()          │
│    │                                │   └── Ciphertext + Nonce + Tag        │
│    │                                │                                       │
│    │                                ├─► Connection::send()                   │
│    │                                │   └── UDP/TCP/Tor frame               │
│    │                                │                                       │
│    │ 200 OK                         │                                       │
│    │◄──────────────────────────────┤                                       │
│    │                                │                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 EtherSync: Pubblicazione e Ricezione

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FLUSSO PUBBLICAZIONE ETHERSYNC                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  NODO A                          RETE                          NODO B       │
│    │                              │                              │          │
│    │ publish("secret", "Hello")   │                              │          │
│    ├─────────────────────────────►│                              │          │
│    │                              │                              │          │
│    ├─► Derive coordinate          │                              │          │
│    │   slot = current_time / 300  │                              │          │
│    │   space_hash = blake3(pass)  │                              │          │
│    │                              │                              │          │
│    ├─► Encrypt message            │                              │          │
│    │   key = HKDF(passphrase)     │                              │          │
│    │   nonce = random(24)         │                              │          │
│    │   ciphertext = XChaCha20()   │                              │          │
│    │                              │                              │          │
│    ├─► Store locally              │                              │          │
│    │   SQLite: (slot, hash, msg)  │                              │          │
│    │                              │                              │          │
│    │ GossipFrame::Forward         │                              │          │
│    │ { ttl: 3, message }          │                              │          │
│    ├──────────────────────────────┼─────────────────────────────►│          │
│    │                              │                              │          │
│    │                              │                              ├─► Verify
│    │                              │                              │   hash
│    │                              │                              ├─► Store
│    │                              │                              │   SQLite
│    │                              │                              ├─► Match
│    │                              │                              │   subs
│    │                              │                              ├─► Notify
│    │                              │                              │   channel
│    │                              │                              │          │
│    │                              │ GossipFrame::Forward         │          │
│    │                              │ { ttl: 2, message }          │          │
│    │                              ├─────────────────────────────►│ (altri   │
│    │                              │                              │  peers)  │
│    │                              │                              │          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. PATTERN ARCHITETTURALI

### 5.1 Pattern Identificati

#### 5.1.1 Layered Architecture

```
┌─────────────────────────────────────┐
│  Presentation Layer (API/GUI)       │  ← axum, Tauri
├─────────────────────────────────────┤
│  Application Layer (Business Logic) │  ← offer generation, session mgmt
├─────────────────────────────────────┤
│  Session Layer (Security)           │  ← Noise handshake, key rotation
├─────────────────────────────────────┤
│  Transport Layer (Networking)       │  ← UDP, TCP, Tor, QUIC
├─────────────────────────────────────┤
│  Crypto Layer (Primitives)          │  ← ouroboros-crypto
└─────────────────────────────────────┘
```

#### 5.1.2 Strategy Pattern (Transport)

```rust
// Implementazione attuale: Enum-based
pub enum Connection { Lan(...), Wan(...), Tor(...), ... }

// Implementazione ideale: Trait-based
pub trait Transport: Send + Sync {
    async fn connect(&self, params: &RendezvousParams) -> Result<Box<dyn Connection>>;
    fn priority(&self) -> u8;
}

pub struct TransportRegistry {
    transports: Vec<Box<dyn Transport>>,
}
```

#### 5.1.3 Actor Model (Async Tasks)

```rust
// Ogni componente gira in task separato
tokio::spawn(async move {
    // Gossip task
});

tokio::spawn(async move {
    // Receive task
});

tokio::spawn(async move {
    // Sweep task
});
```

#### 5.1.4 Shared State (Arc<RwLock<T>>)

```rust
pub struct EtherNode {
    storage: Arc<Mutex<EtherStorage>>,
    peers: Arc<PeerManager>,
    subscriptions: Arc<RwLock<Vec<Subscription>>>,
}
```

### 5.2 Pattern di Sicurezza

#### 5.2.1 Defense in Depth

1. **Early Drop**: Pacchetti invalidi scartati prima del parsing
2. **Rate Limiting**: Token bucket per peer
3. **Time Validation**: Protezione clock skew
4. **Replay Protection**: Sliding window per sequence numbers
5. **Constant-Time**: Confronto segreti in tempo costante

#### 5.2.2 Zero Trust

- Ogni connessione autenticata via Noise XX
- Nessun trust implicito tra peer
- Certificate pinning per TLS (pluggable)

---

## 6. SICUREZZA E CRITTOGRAFIA

### 6.1 Algoritmi Crittografici

| Scopo | Algoritmo | Implementazione |
|-------|-----------|-----------------|
| KDF | Argon2id | `argon2` crate |
| KDF | HKDF-SHA256 | `hkdf` crate |
| AEAD | XChaCha20-Poly1305 | `chacha20poly1305` crate |
| Hash | Blake3 | `blake3` crate |
| Hash | SHA256/512 | `sha2` crate |
| KX | X25519 | `x25519-dalek` crate |
| PQ KEM | Kyber1024 | `pqcrypto-kyber` crate (optional) |
| Protocol | Noise_XX_25519_ChaChaPoly_BLAKE2s | `snow` crate |

### 6.2 Post-Quantum Security

**Hybrid Mode**:
```
Classic: X25519
Post-Quantum: Kyber1024
Combined: X25519 || Kyber1024 → HKDF → Session Key
```

**Fallback**: Se Kyber fallisce, usa solo X25519.

### 6.3 Threat Model

| Minaccia | Mitigazione |
|----------|-------------|
| Man-in-the-Middle | Noise XX handshake |
| Replay Attack | Nonce sequences + replay window |
| Traffic Analysis | Tor integration, DPI evasion |
| DoS | Rate limiting, early drop, bloom filters |
| Key Compromise | Forward secrecy (Noise), key rotation |
| Quantum Computer | Kyber1024 hybrid (optional) |

---

## 7. PERFORMANCE E OTTIMIZZAZIONI

### 7.1 Metriche Attuali

| Metrica | Valore |
|---------|--------|
| Compilazione debug | ~30s |
| Compilazione release | ~2min |
| Test suite | 146 test in ~10s |
| Binary size (release) | ~15MB |
| Memory footprint | ~50MB (idle) |

### 7.2 Ottimizzazioni Implementate

1. **LTO (Link Time Optimization)**: `lto = "fat"`
2. **Codegen Units**: `codegen-units = 1`
3. **Panic**: `panic = "abort"`
4. **Strip**: `strip = "symbols"`
5. **Opt-level**: `opt-level = "z"` (size)

### 7.3 Bottleneck Identificati

1. **Transport Layer**: 7,045 righe in un solo modulo
2. **API Layer**: 2,076 righe monolitiche
3. **Feature Flags**: Compilazione condizionale complessa

---

## 8. TESTING E QUALITÀ

### 8.1 Test Suite Completa

```
Test Summary:
├── ouroboros-crypto:  13 test ✅
│   ├── derive: determinism, salt generation
│   ├── aead: roundtrip, wrong key
│   ├── hash: known vectors
│   └── pq: feature gating
│
├── handshacke:        89 test ✅
│   ├── crypto: encryption, nonce sequences
│   ├── derive: v1/v2 compatibility, determinism
│   ├── transport: LAN, WAN, Tor, hole punching
│   ├── protocol: assist v4/v5
│   └── integration: multipath
│
├── ethersync:         44 test ✅
│   ├── coordinate: derivation, slots
│   ├── message: encrypt/decrypt, serialize
│   ├── network: framing, rate limiting
│   ├── gossip: bloom filter, peer management
│   ├── integration: node creation, publish
│   └── e2e: 2-node communication (3 test)
│
└── TOTAL:            146 test ✅
```

### 8.2 Coverage

- **Unit test**: ~60%
- **Integration test**: ~30%
- **E2E test**: ~10%

---

## 9. ROADMAP STATE OF THE ART

### 9.1 Priorità Alta (Prossimi 3 mesi)

#### 9.1.1 Separazione Transport Layer

```
workspace/
├── handshacke-transport/     # Nuovo crate
│   ├── src/
│   │   ├── lib.rs
│   │   ├── registry.rs       # TransportRegistry
│   │   ├── traits.rs         # Transport trait
│   │   └── implementations/
│   │       ├── lan.rs
│   │       ├── wan_direct.rs
│   │       ├── wan_tor.rs
│   │       ├── quic.rs
│   │       └── webrtc.rs
│   └── Cargo.toml
│
└── handshacke/               # Dipende da handshacke-transport
```

**Benefici**:
- Compilazione incrementale
- Test isolati
- API stabile

#### 9.1.2 Definizione API Pubblica

```rust
// src/prelude.rs
pub mod prelude {
    // Solo API pubblica stabile
    pub use crate::config::Config;
    pub use crate::derive::{derive_from_secret, RendezvousParams};
    pub use crate::offer::{OfferPayload, RoleHint};
    pub use crate::transport::{Connection, TransportRegistry};
    
    // NON esporre:
    // - api::* (implementazione)
    // - transport::* (dettagli)
    // - crypto::* (wrapper interni)
}
```

#### 9.1.3 Erasure Coding Completo

Implementare Reed-Solomon per frammentazione messaggi:

```rust
pub struct ReedSolomonCoder {
    data_shards: usize,      // k
    parity_shards: usize,    // m
    coder: ReedSolomon,
}

impl ReedSolomonCoder {
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Shard>, Error>;
    pub fn decode(&self, shards: &[Shard]) -> Result<Vec<u8>, Error>;
}
```

### 9.2 Priorità Media (3-6 mesi)

#### 9.2.1 DHT Peer Discovery

Integrare libp2p-kad per bootstrap automatico:

```rust
pub struct DhtDiscovery {
    kad: Kademlia<MemoryStore>,
    bootstrap_nodes: Vec<Multiaddr>,
}

impl DhtDiscovery {
    pub async fn discover_peers(&self, space_hash: &[u8; 32]) -> Vec<SocketAddr>;
}
```

#### 9.2.2 Unificazione Error Types

```rust
// handshacke-errors/src/lib.rs
#[derive(Debug, thiserror::Error)]
pub enum HandshackeError {
    #[error("crypto error: {0}")]
    Crypto(#[from] ouroboros_crypto::CryptoError),
    
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
```

### 9.3 Priorità Bassa (6+ mesi)

#### 9.3.1 Formal Verification

- Verificare crittografia con Kani o Creusot
- Proprietà: determinismo, assenza di panic, zeroize corretto

#### 9.3.2 WebAssembly Target

Compilare ouroboros-crypto per WASM (browser/Node.js):

```toml
[target.wasm32-unknown-unknown.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

---

## 10. CONCLUSIONI

### 10.1 Punti di Forza

1. **Architettura Modulare**: Separazione chiara tra crypto, sync, async
2. **Sicurezza Robusta**: Noise Protocol, post-quantum optional, DPI evasion
3. **Test Coverage**: 146 test passanti, E2E funzionanti
4. **Performance**: Ottimizzato per size e velocità
5. **Flessibilità**: Feature flags granulari, multi-trasporto

### 10.2 Debito Tecnico

1. **Esposizione Eccessiva**: `pub use *::*` in `lib.rs`
2. **Monolite Transport**: 7,045 righe in un modulo
3. **Inconsistenza Errori**: `anyhow` vs `thiserror`
4. **Documentazione**: Moduli interni poco documentati

### 10.3 Valutazione Complessiva

| Aspetto | Rating | Note |
|---------|--------|------|
| Funzionalità | ⭐⭐⭐⭐⭐ | Completa e funzionante |
| Architettura | ⭐⭐⭐⭐ | Buona, ma migliorabile |
| Sicurezza | ⭐⭐⭐⭐⭐ | State of the art |
| Performance | ⭐⭐⭐⭐ | Ottimizzato |
| Manutenibilità | ⭐⭐⭐ | Debito tecnico presente |
| Documentazione | ⭐⭐⭐ | API docs mancanti |

**Overall**: ⭐⭐⭐⭐ (4/5)

Il progetto è **solido e pronto per produzione**, ma richiede refactoring architetturale per raggiungere lo "state of the art" assoluto.

---

## APPENDICE A: STATISTICHE CODICE

```
Linguaggio       File    Righe    Commenti   Blank
-------------------------------------------------
Rust             85      17,000   ~2,000     ~3,000
Markdown         12      3,500    -          -
TOML             4       400      -          -
-------------------------------------------------
Totale           101     20,900   ~2,000     ~3,000
```

## APPENDICE B: DIPENDENZE ESTERNE

```
Totale crate dipendenti: ~150
- Direct dependencies: ~40
- Indirect dependencies: ~110

Categorie:
- Async runtime: tokio, futures
- HTTP: axum, hyper, tower
- Crypto: chacha20poly1305, x25519-dalek, snow, blake3
- Serialization: serde, serde_json, bincode
- Network: socket2, igd, natpmp, tokio-socks
- Optional: quinn, webrtc, pqcrypto-kyber
```

---

*Fine Documento*
