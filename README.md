# Handshacke

Deterministic P2P communication without servers.

Handshacke is a P2P communication system that uses deterministic cryptographic rendezvous to establish secure connections without any central servers, DNS lookups, or traditional discovery protocols.

Repository: https://github.com/omarsomaro/HANDSHAKE
License: MIT
Latest Version: 0.1.0

## Key Features

- Zero-discovery P2P (shared passphrase rendezvous)
- Deterministic parameter derivation (port, keys, tags)
- Transport cascade: LAN -> WAN (UPnP/NAT-PMP) -> Tor fallback
- ICE multipath racing (best path wins)
- STUN discovery + QR/offer enrichment (public endpoint hints)
- Hybrid QR (resume token + deterministic fallback)
- Memory-safe crypto: XChaCha20-Poly1305 + HMAC with key zeroization
- Early-drop filtering + rate limiting (DoS resistance)
- Replay protection (sliding window)
- Key rotation with grace window
- Multi-protocol DPI evasion: Real TLS, WebSocket, HTTP/2/QUIC mimicry (experimental)
- Optional QUIC (RFC 9000) and WebRTC DataChannel
- Optional post-quantum hybrid key exchange (feature: pq) with classic fallback
- Desktop GUI (Tauri) with guided connection flows
- Threat model and security analysis in docs
- Pluggable transport framework (experimental, requires external infra for some modes)
- IPv6-first dual-stack support
- TCP fallback when UDP is blocked (target connect)

## What This Product Is

Handshacke is a privacy-first communication stack with two complementary engines:

- `Handshacke` mode: deterministic one-to-one secure session setup (chat/control channel style).
- `EtherSync` mode: connectionless shared spaces for asynchronous broadcast and chunked file sharing.

In practice, this means you can run:

- direct private peer sessions when you need low-latency interaction (`Handshacke`)
- resilient shared drop-spaces when peers are not always online together (`EtherSync`)

No central rendezvous server is required in the normal flow.

## Handshacke vs EtherSync (Use Cases)

### Handshacke (session mode)
Use when two peers need a live encrypted connection.

Typical use cases:
- secure operator-to-operator control channel
- direct private chat between two devices
- one-shot private data exchange with QR pairing
- restrictive networks where Tor/relay fallback is needed

Connection model:
- deterministic rendezvous from shared passphrase
- transport cascade: LAN -> WAN hole punching -> Assist/Relay -> Tor fallback
- final result is a point-to-point encrypted session

### EtherSync Space (connectionless mode)
Use when you need a shared encrypted space instead of a fixed live session.

Typical use cases:
- team "dropbox" without central cloud
- delayed collaboration (publish now, receive as peers sync)
- chunked file fan-out in private passphrase-derived spaces
- lightweight broadcast-style coordination

Connection model:
- passphrase derives a shared space identifier
- UDP gossip + peer links replicate encrypted payloads
- no single permanent session is required between all participants

## Product Positioning (Short Pitch)

Handshacke gives you secure private connectivity without managing servers.
EtherSync extends that with private asynchronous spaces for messages and files.
Together, they cover both real-time peer sessions and offline-tolerant shared distribution.

## Installation

### Requirements
- Rust 1.70+
- Network access (no firewall blocking required ports)
- Node.js 18+ (only for the GUI)

### Build from Source
```
git clone https://github.com/omarsomaro/HANDSHAKE.git
cd HANDSHAKE
cargo build --release
```

Binaries:
- target/release/handshacke (daemon)
- target/release/hs-cli (CLI client)

### Pre-built Binaries
Coming soon.

## Quick Start

### 1) Headless (daemon + CLI/API)

Build and run the daemon:
```
cargo run --release
```

API starts on http://127.0.0.1:3000

Send messages with the CLI (two terminals, same passphrase):
```
# Terminal 1
cargo run --bin hs-cli -- "mysecretpassphrase" "Hello from peer A!"

# Terminal 2
cargo run --bin hs-cli -- "mysecretpassphrase" "Hello back from peer B!"
```

### 2) Desktop GUI (Tauri)

The GUI launches the daemon as a sidecar. You need the daemon binary in the Tauri bin folder:

```
# Build the core binary
cargo build --release

# Copy into the Tauri sidecar location
# Windows: copy target/release/handshacke.exe -> ui/src-tauri/bin/handshacke.exe
# macOS/Linux: copy target/release/handshacke -> ui/src-tauri/bin/handshacke

cd ui
npm install
npm run dev
```

## GUI Quick Guide (Recommended)

The GUI is the easiest way to use the product end-to-end.
It starts/stops the daemon, keeps token auth in RAM, and exposes guided modes.

### 1) Start the app

1. Open desktop app (`npm run dev` during development build).
2. Click `Start daemon`.
3. Choose your flow mode.

### 2) Choose the right flow

- `Classic`: automatic cascade (LAN/WAN/Assist/Tor). Good default when both peers know the passphrase.
- `Offer QR`: easiest pairing with a QR envelope (no passphrase inside QR).
- `Hybrid QR`: best reconnection UX (resume token + fallback offer).
- `Target`: connect to a known `ip:port` or `.onion`.
- `Phrase`: Tor-first invite flow for privacy-first setup.
- `Guaranteed`: relay-centric deterministic connectivity.
- `EtherSync Space`: shared asynchronous space for messages + chunked files.

### 3) Handshacke flow in GUI (2 peers)

Host:
1. Set passphrase
2. Generate `Offer` or `Hybrid QR`
3. Share QR with client

Client:
1. Scan/paste QR
2. Connect
3. Verify status panel reaches connected state

### 4) EtherSync flow in GUI

1. Open `EtherSync Space` mode
2. Start EtherSync node
3. Add peer addresses (optional but recommended for first bootstrap)
4. Enter passphrase and `Join space`
5. Publish text or select file and publish chunked transfer
6. Monitor live events and download reconstructed received files

Operational note:
- anyone with the same EtherSync passphrase can join the same space.
- keep passphrases private and rotate them per project/context.

### 3) Web Client (legacy/debug)

Open client.html in your browser and use the same passphrase on two instances.

## Library Usage

```rust
use handshacke::prelude::*;

let cfg = Config::from_env();
// Use establish_connection_from_offer(...) or connect_to(...) based on your flow.
```

## API Endpoints

Security note: the API is not designed to be exposed without authentication. Keep it bound to 127.0.0.1 unless you explicitly accept the risk.

See SECURITY.md for API security considerations.

Connection Management
- POST /v1/connect - Establish P2P connection
- GET /v1/status - Get connection status
- POST /v1/disconnect - Close connection
- POST /v1/offer - Generate Offer payload
- POST /v1/qr/hybrid - Generate Hybrid QR (resume + fallback)
- POST /v1/phrase/open - Open Tor phrase flow
- POST /v1/phrase/join - Join Tor phrase flow
- GET /v1/phrase/status - Phrase status
- POST /v1/phrase/close - Close phrase flow
- POST /v1/rendezvous/sync - Relay-assisted rendezvous sync
- GET /v1/pluggable/check - Pluggable transport status checklist

Messaging
- GET /v1/recv - SSE stream for incoming messages
- POST /v1/send - Send encrypted packet

EtherSync Space
- POST /v1/ethersync/start - Start local EtherSync node
- POST /v1/ethersync/stop - Stop local EtherSync node
- GET /v1/ethersync/status - EtherSync runtime status
- POST /v1/ethersync/peers/add - Add bootstrap/runtime peer
- POST /v1/ethersync/spaces/join - Join a passphrase-derived space
- POST /v1/ethersync/spaces/publish - Publish message/payload to a space
- POST /v1/ethersync/files/publish - Publish a file in chunked envelopes
- GET /v1/ethersync/events - SSE stream for EtherSync events/messages

Crypto Operations
- POST /v1/set_passphrase - Set encryption passphrase
- POST /v1/seal - Encrypt data to packet
- POST /v1/open - Decrypt packet to data
- GET /v1/metrics - In-memory diagnostics (RAM-only)

## Security

See docs/threat_model_visibility.md for visibility analysis by transport layer.

See docs/casestudy.md for academic security analysis.

See SECURITY.md for vulnerability reporting and security policy.

Key Security Properties
- Content confidentiality (Noise + XChaCha20-Poly1305)
- Perfect forward secrecy (Noise)
- Zero persistence (keys in RAM only)
- DoS resistance (early-drop + rate limiting)

Security Trade-offs
- LAN: exposed to local network
- UPnP/NAT-PMP: gateway sees mappings
- Tor: strong anonymity, higher latency
- Relay: centralized metadata (use via Tor to hide IP)

## How It Works

1) Deterministic parameters

```rust
// Both peers derive identical parameters from the shared passphrase
let params = derive_from_passphrase("shared_secret");
```

2) Transport cascade
- LAN: UDP broadcast discovery
- WAN: UPnP/NAT-PMP port forwarding
- Tor: stream fallback when direct WAN fails
- STUN: public endpoint discovery and hole punching (QR/offer aware)
- TCP fallback: when UDP is blocked (target connect)

Optional transports
- QUIC (RFC 9000): framed stream over UDP
- WebRTC DataChannel: browser-compatible transport

Pluggable transports (experimental)
- Real TLS, WebSocket, QUIC, HTTP/2 mimicry
- External infrastructure required for Real TLS and most mimicry modes
- See `docs/pluggable_integration.md`

3) Message flow
```
[Message] -> Encrypt -> Tag + Nonce + Ciphertext -> UDP -> Peer
[Peer] -> Tag Filter -> Rate Limit -> Decrypt -> Replay Check -> Display
```

## QR Flows (Why They Matter)

Handshacke uses QR payloads to make rendezvous **fast, explicit, and hard to misconfigure**.  
The QR is never your passphrase. It is a **time‑limited rendezvous envelope** that carries
endpoints and parameters so two peers can align quickly.

### Offer QR (endpoint-based)
- **Purpose**: simple pairing without typing IPs.
- **Contents**: endpoints + rendezvous params (no passphrase).
- **Use when**: you want quick pairing and can re-scan if needed.

### Hybrid QR (resume + fallback)
- **Purpose**: best UX and fastest re-join.
- **Contents**: resume token + deterministic offer (fallback).
- **Use when**: you want a stable, repeatable reconnection flow.

### Phrase QR (Tor invite)
- **Purpose**: privacy-first pairing.
- **Contents**: Tor invite string only (no passphrase).
- **Use when**: you want Tor-only rendezvous and privacy.

**Important**: If direct connect fails (NAT/firewall), the most reliable flow is **Hybrid/Offer QR + Tor relay**.

## Network Compatibility

- LAN: direct UDP broadcast
- Home networks: UPnP automatic port forwarding
- Corporate/CGNAT: NAT-PMP fallback
- Restrictive NATs: Symmetric NAT fast-path to relay/Tor
- UDP blocked: TCP fallback
- IPv4/IPv6: dual-stack (IPv6-first)
- Censorship: Tor integration available
- Interoperability: optional QUIC and WebRTC transports

## Architecture

- docs/architecture.md
- docs/transport_matrix.md
- docs/feature_flags.md
- docs/gui_flows.md
- docs/discovery_dht.md
- docs/performance.md
- docs/fuzzing.md
- docs/release_provenance.md
- docs/release_process.md
- docs/wasm.md
- docs/formal_methods.md

## Performance

- Early drop filtering at line speed
- RAM-only operation
- Direct UDP when possible (no relay servers unless Tor)

## Development

See CONTRIBUTING.md for contribution guidelines.

### Development Setup
```
# Setup hooks
git config commit.gpgsign true  # If using GPG
cargo install cargo-audit  # For security audits
```

Feature policy:
- `default` = safe profile (`quic`)
- `full` = `quic,webrtc,pq`

### Running Tests
```
# Unit tests
cargo test

# Feature combinations
cargo test --no-default-features
cargo test --no-default-features --features full
cargo test --no-default-features --features pq
cargo test --no-default-features --features quic
cargo test --no-default-features --features webrtc

# Check code quality
cargo fmt -- --check
cargo clippy -- -D warnings

# Security audit
cargo audit
```

See docs/testing.md for the full test matrix and ignored tests.

## License

MIT License - See LICENSE

## Contributing

Contributions welcome. Please read CONTRIBUTING.md.

## Security

For security issues, see SECURITY.md. Do NOT report vulnerabilities in public issues.

## Issues

Report bugs via https://github.com/omarsomaro/HANDSHAKE/issues

## Roadmap

- Pre-built binaries for major platforms
- Mobile app (iOS/Android)
- Plugin system for custom transports
- Performance benchmarks
- GUI polish and onboarding improvements

## Mission

Handshacke enables private, serverless communication that respects user privacy and resists censorship.

## References

- docs/threat_model_visibility.md - Operational threat model
- docs/casestudy.md - Academic security analysis
- docs/testing.md - Test matrix and ignored tests
- docs/discovery_dht.md - Discovery abstraction and DHT integration roadmap
- docs/performance.md - Reproducible benchmark suite and performance budgets
- docs/fuzzing.md - Continuous fuzzing targets and local workflow
- docs/release_provenance.md - Release artifact provenance, SBOM, and checksum verification
- docs/release_process.md - Stable/nightly channels and release runbook
- docs/wasm.md - WASM compile support for `ouroboros-crypto`
- docs/formal_methods.md - Property-based verification pilot for crypto/session invariants
- SECURITY.md - Security policy

---

Repository: https://github.com/omarsomaro/HANDSHAKE
Issues: https://github.com/omarsomaro/HANDSHAKE/issues
Security: security@handshake-p2p.dev
