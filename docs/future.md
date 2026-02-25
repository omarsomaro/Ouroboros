# EtherSync Protocol Specification

## Reality Check (2026-02-23)

This file started as a specification draft. Parts of the protocol are now implemented in the repository:

- Implemented crates/modules: `ethersync/src/{coordinate.rs,message.rs,network.rs,gossip.rs,node.rs,storage.rs}`
- Existing tests: integration and e2e suites under `ethersync/tests/`
- Still pending from this spec: production-grade DHT discovery and full Reed-Solomon erasure coding

Use this file as a living design document, not as a pure future-only roadmap.

## Executive Summary

**EtherSync** è un protocollo di comunicazione **connectionless deterministico** che elimina il concetto stesso di "connessione" tra peer. Invece di stabilire canali di comunicazione, i messaggi "esistono" in uno spazio astratto condiviso derivato deterministicamente da una passphrase, permettendo comunicazione asincrona pura senza handshake, senza stato di connessione, e senza necessità di contemporaneità online.

---

## 1. Core Philosophy

### 1.1 Il Problema delle Connessioni Tradizionali

I protocolli P2P tradizionali (incluso Handshacke classico) richiedono:
- Handshake iniziale
- Stato di connessione mantenuto
- Peer contemporaneamente online
- Routing point-to-point

### 1.2 Il Paradigma EtherSync

**"Il messaggio esiste indipendentemente dall'esistenza del destinatario"**

- Nessuna connessione da stabilire
- Nessun handshake
- Nessun requisito di contemporaneità
- I messaggi persistono nello "spazio condiviso"
- La comunicazione è un'operazione di "pubblicazione/osservazione"

---

## 2. Spazio Astratto Deterministico

### 2.1 Concetto di "Ether Space"

L'Ether Space è uno spazio multidimensionale astratto dove:
- Ogni punto è identificato da coordinate deterministiche
- I messaggi sono "pubblicati" in coordinate specifiche
- Chiunque conosca le coordinate può "osservare" i messaggi
- Lo spazio è infinito ma navigabile deterministicamente

### 2.2 Derivazione delle Coordinate

```
Passphrase + Timestamp/Slot → Coordinate nello spazio

Coordinate = (Dimension_X, Dimension_Y, Dimension_Z, Temporal_Slot)

Dove:
- Dimension_X = HKDF(passphrase, "ethersync/x")
- Dimension_Y = HKDF(passphrase, "ethersync/y") 
- Dimension_Z = HKDF(passphrase, "ethersync/z")
- Temporal_Slot = floor(current_time / SLOT_DURATION)
```

### 2.3 Temporal Slotting

Il tempo è diviso in slot discreti (es. 5 minuti):
- **Current Slot**: Slot temporale attuale
- **Lookback Window**: N slot precedenti da scansionare
- **Future Buffer**: M slot futuri per messaggi programmati

```rust
pub const SLOT_DURATION_SECONDS: u64 = 300; // 5 minuti
pub const LOOKBACK_SLOTS: usize = 12;        // 1 ora di storia
pub const FUTURE_SLOTS: usize = 2;           // 10 minuti futuro
```

---

## 3. Architettura del Protocollo

### 3.1 Layer Stack

```
┌─────────────────────────────────────────┐
│         Application Layer               │
│    (Messaggi applicativi cifrati)       │
├─────────────────────────────────────────┤
│         Ether Layer                     │
│    (Frammentazione, routing etereo)     │
├─────────────────────────────────────────┤
│         Coordinate Layer                │
│    (Derivazione slot, indirizzamento)   │
├─────────────────────────────────────────┤
│         Persistence Layer               │
│    (Storage distribuito, gossip)        │
├─────────────────────────────────────────┤
│         Transport Layer                 │
│    (UDP, TCP, Tor, ecc.)                │
└─────────────────────────────────────────┘
```

### 3.2 Componenti Principali

#### 3.2.1 EtherNode

Ogni peer è un **EtherNode** che:
- Partecipa alla rete di storage distribuito
- Mantiene un "horizon" di messaggi noti
- Esegue "sweeps" periodici degli slot temporali
- Propaga messaggi via gossip

#### 3.2.2 EtherMessage

```rust
pub struct EtherMessage {
    // Header (non cifrato)
    pub version: u8,
    pub slot_id: u64,
    pub coordinate_hash: [u8; 32], // Hash delle coordinate complete
    pub fragment_index: u16,
    pub total_fragments: u16,
    pub ttl: u8, // Time-to-live in hop
    
    // Payload (cifrato)
    pub encrypted_payload: Vec<u8>,
    pub nonce: [u8; 24],
    
    // Protezione integrità
    pub auth_tag: [u8; 16],
}
```

#### 3.2.3 EtherCoordinate

```rust
pub struct EtherCoordinate {
    pub passphrase_hash: [u8; 32], // Identifica lo "spazio"
    pub slot: u64,
    pub subspace: u64, // Per multi-canale nella stessa passphrase
    pub entropy: [u8; 16], // Salt per collision resistance
}
```

---

## 4. Meccanismo di Comunicazione

### 4.1 Pubblicazione di un Messaggio (Sender)

```
1. Deriva EtherCoordinate da (passphrase, current_slot, subspace)
2. Cifra il payload con chiave derivata dalla passphrase
3. Frammenta se necessario (max 1KB per frammento)
4. Per ogni frammento:
   a. Crea EtherMessage
   b. Calcola coordinate di storage
   c. "Pubblica" nel proprio storage locale
   d. Propaga via gossip ai peer connessi
5. Continua a propagare per TTL hop
```

### 4.2 Ricezione di Messaggi (Receiver)

```
1. Calcola gli slot di interesse (lookback + current + future)
2. Per ogni slot:
   a. Deriva le EtherCoordinate
   b. Interroga il proprio storage locale
   c. Richiede ai peer connessi (gossip query)
3. Ricostruisce i frammenti
4. Decifra il payload
5. Verifica integrità e autenticità
```

### 4.3 Gossip Protocol

**Anti-entropy Gossip**:
- Ogni nodo mantiene un "horizon" di hash dei messaggi conosciuti
- Scambi periodici con peer: "Ho questi messaggi per questi slot"
- Richiesta differenziale: "Dammi i messaggi che ho perso"
- Propagazione esponenziale con TTL

```rust
pub struct GossipDigest {
    pub slot: u64,
    pub message_hashes: Vec<[u8; 32]>,
    pub timestamp: u64,
}
```

---

## 5. Storage Distribuito

### 5.1 Modello di Persistenza

**Nessun server centrale** - Storage completamente distribuito:

```
Ogni nodo memorizza:
- Messaggi per i propri slot di interesse
- Messaggi "vicini" (slot correlati)
- Messaggi con TTL > 0 (in transit)
- Indice per lookup rapido
```

### 5.2 Local Storage

```rust
pub struct EtherStorage {
    // Key: (slot, coordinate_hash)
    // Value: Vec<EtherMessage> (frammenti)
    messages: HashMap<(u64, [u8; 32]), Vec<EtherMessage>>,
    
    // Indice per lookup rapido
    slot_index: BTreeMap<u64, HashSet<[u8; 32]>>,
    
    // Configurazione
    max_storage_per_slot: usize,
    ttl_default: u8,
}
```

### 5.3 Garbage Collection

- Slot più vecchi di LOOKBACK_SLOTS vengono eliminati
- Messaggi con TTL=0 e non richiesti vengono droppati
- LRU cache per slot ad alta frequenza

---

## 6. Sicurezza e Privacy

### 6.1 Proprietà di Sicurezza

**Confidentiality**: 
- Payload cifrato con XChaCha20-Poly1305
- Chiave derivata da HKDF(passphrase)
- Nonce deterministici per evitare collisioni

**Integrity**:
- Auth tag AEAD su ogni frammento
- Hash delle coordinate per binding

**Anonimity**:
- Nessun identificatore del sender nel messaggio
- Coordinate derivate dalla passphrase condivisa
- Gossip anonimo (solo hash, non contenuti)

**Plausible Deniability**:
- Ogni nodo memorizza messaggi di molti slot
- Impossibile dimostrare che un nodo è sender/receiver
- Storage "mimetico" - tutti i nodi sembrano uguali

### 6.2 Protezione contro Attacchi

**Sybil Attack**:
- Proof-of-work leggero su ogni messaggio
- Rate limiting per slot
- Reputazione dei peer nel gossip

**Eclipse Attack**:
- Bootstrap multi-source
- DHT per peer discovery
- Randomizzazione delle connessioni

**Storage Exhaustion**:
- Limiti per slot
- Prioritizzazione LRU
- TTL automatico

---

## 7. Ottimizzazioni

### 7.1 Bloom Filters per Gossip

Invece di scambiare liste di hash, usare Bloom Filters:
- Spazio ridotto per digest
- Falsi positivi accettabili (richiesta ridondante)
- Merge efficiente

### 7.2 Erasure Coding

Per messaggi grandi, usare Reed-Solomon:
- K frammenti originali
- N frammenti di parity
- Recupero con qualsiasi K frammenti
- Ridondanza senza duplicazione

### 7.3 Predictive Prefetching

```rust
// Se un utente sta leggendo slot N, 
// prefetch slot N+1, N+2 in background
pub async fn prefetch_upcoming_slots(&self, current_slot: u64) {
    for slot in current_slot..=current_slot + FUTURE_SLOTS {
        self.warm_slot_cache(slot).await;
    }
}
```

---

## 8. Integrazione con Handshacke

### 8.1 Modalità di Operazione

**EtherSync** può operare in tre modalità:

1. **Standalone**: Solo EtherSync, nessuna connessione tradizionale
2. **Hybrid**: EtherSync + Handshacke classico (fallback)
3. **Bridge**: EtherSync come layer di signaling per Handshacke

### 8.2 API Proposta

```rust
// Nuovo modulo: src/ether/
pub mod ether {
    pub struct EtherNode;
    pub struct EtherMessage;
    pub struct EtherCoordinate;
    
    impl EtherNode {
        pub async fn publish(
            &self, 
            passphrase: &str, 
            payload: &[u8]
        ) -> Result<EtherMessageId>;
        
        pub async fn subscribe(
            &self, 
            passphrase: &str
        ) -> Result<mpsc::Receiver<EtherMessage>>;
        
        pub async fn sweep_slot(
            &self, 
            slot: u64
        ) -> Result<Vec<EtherMessage>>;
    }
}
```

### 8.3 Feature Flag

```toml
[features]
default = ["quic"]
full = ["quic", "webrtc", "pq", "ether"]
ether = ["dep:reed-solomon", "dep:bloomfilter"]
```

---

## 9. Casi d'Uso

### 9.1 Comunicazione Asincrona

Alice e Bob non devono mai essere online contemporaneamente:
- Alice pubblica messaggio nello slot 100
- Bob, online 2 ore dopo, legge slot 95-105
- Bob trova il messaggio e risponde nello slot 110

### 9.2 Dead Drop Digitale

Pubblicazione di informazioni in coordinate note:
- Coordinate derivate da passphrase pubblica
- Chiunque conosca la passphrase può leggere
- Nessun server, nessun log, nessuna traccia

### 9.3 Whistleblowing

Fonte pubblica in coordinate specifiche:
- Passphrase condivisa via canale sicuro
- Informazioni pubblicate in slot programmati
- Ricezione anonima da parte del giornalista

### 9.4 Mesh Messaging

Reti mesh dove i nodi sono raramente connessi:
- Messaggi propagano via gossip
- Ogni nodo è relay involontario
- Consegna garantita entro TTL

---

## 10. Confronto con Esistenti

| Feature | Handshacke | EtherSync | Signal | Briar |
|---------|-----------|-----------|---------|-------|
| Connectionless | ❌ | ✅ | ❌ | ❌ |
| No contemporaneità | ❌ | ✅ | ❌ | ✅ |
| No server | ✅ | ✅ | ❌ | ✅ |
| Gossip-based | ❌ | ✅ | ❌ | ✅ |
| Deterministic | ✅ | ✅ | ❌ | ❌ |
| DPI Resistance | ✅ | ✅ | ⚠️ | ✅ |
| Post-Quantum | ✅ | ✅ | ❌ | ❌ |

---

## 11. Implementazione Roadmap

### Fase 1: Core (MVP)
- [ ] Strutture dati base (EtherMessage, EtherCoordinate)
- [ ] Derivazione coordinate da passphrase
- [ ] Storage locale con SQLite
- [ ] Gossip protocol base

### Fase 2: Networking
- [ ] UDP transport per gossip
- [ ] Bootstrap DHT
- [ ] Peer discovery
- [ ] Rate limiting e DoS protection

### Fase 3: Ottimizzazioni
- [ ] Bloom filters
- [ ] Erasure coding
- [ ] Predictive prefetching
- [ ] Compressione

### Fase 4: Integrazione
- [ ] API REST
- [ ] Integrazione GUI Tauri
- [ ] Feature flag
- [ ] Testing estensivo

---

## 12. Considerazioni Teoriche

### 12.1 Cap Theorem

EtherSync sacrifica **Consistency** per **Availability** e **Partition Tolerance**:
- Messaggi possono arrivare in ordine diverso
- Duplicati possibili (idempotenza necessaria)
- Conflitti risolti per timestamp

### 12.2 Latency vs Storage Trade-off

- Più nodi = più storage distribuito = latenza ridotta
- Meno nodi = meno storage = latenza aumentata
- TTL bilancia tra affidabilità e overhead

### 12.3 Scalabilità

- O(n) storage per n slot attivi
- O(log n) lookup con indici
- O(1) derivazione coordinate
- Gossip O(sqrt(n)) per n nodi

---

## 13. Conclusione

EtherSync rappresenta un **paradigma shift** nella comunicazione P2P:
- Elimina il concetto di connessione
- Abbraccia l'asincronia totale
- Mantiene determinismo e sicurezza
- Zero infrastruttura

**"Non ci connettiamo. Esistiamo nello stesso spazio."**

---

## Appendice A: Esempi di Codice

### A.1 Pubblicazione

```rust
use handshacke::ether::*;

#[tokio::main]
async fn main() -> Result<()> {
    let node = EtherNode::new().await?;
    
    let message = b"Hello from the ether!";
    let msg_id = node.publish("shared-secret-passphrase", message).await?;
    
    println!("Published: {:?}", msg_id);
    Ok(())
}
```

### A.2 Ricezione

```rust
use handshacke::ether::*;

#[tokio::main]
async fn main() -> Result<()> {
    let node = EtherNode::new().await?;
    let mut rx = node.subscribe("shared-secret-passphrase").await?;
    
    while let Some(msg) = rx.recv().await {
        println!("Received: {:?}", String::from_utf8_lossy(&msg.payload));
    }
    
    Ok(())
}
```

### A.3 Dead Drop

```rust
// Pubblicazione in coordinate specifiche
let coordinate = EtherCoordinate::derive(
    "public-drop-passphrase",
    slot: 1000,
    subspace: 42
);

node.publish_to_coordinate(coordinate, secret_data).await?;

// Lettura da coordinate specifiche
let messages = node.scan_coordinate(coordinate).await?;
```

---

## Appendice B: Formato Messaggi

### B.1 EtherMessage (Binary)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  RSV  |                    Slot ID                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Slot ID (continued)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Coordinate Hash (32 bytes)                +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Fragment Idx  | Total Frags   | TTL   |      RSV              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Nonce (24 bytes)                          +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                      Auth Tag (16 bytes)                       +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                      Encrypted Payload (variable)              /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### B.2 Gossip Message

```rust
pub enum GossipMessage {
    Digest {
        slot: u64,
        bloom_filter: Vec<u8>,
    },
    Request {
        slot: u64,
        missing_hashes: Vec<[u8; 32]>,
    },
    Response {
        messages: Vec<EtherMessage>,
    },
    Ping,
    Pong,
}
```

---

*Document Version: 1.0*
*Last Updated: 2025-02-19*
*Status: Living specification and implementation roadmap*
