# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Handshacke P2P communication framework
- Deterministic P2P communication without servers
- Multi-transport NAT traversal (LAN, UPnP, STUN, Relay, Tor)
- Noise protocol encryption (XChaCha20-Poly1305)
- Real TLS DPI evasion
- WebSocket/QUIC/HTTP2 mimicry
- TCP and ICMP hole punching
- Academic security case study
- Operational threat model analysis
- QUIC RFC9000 transport module (optional)
- WebRTC DataChannel transport module (optional)
- Hybrid post-quantum key exchange module (optional)
- Feature flags for heavy dependencies
- High-level integration tests (crypto/Noise/QUIC/WebRTC)
- Architecture and feature flag documentation
- GitHub Actions CI workflow
- Release workflow with packaged binaries, CycloneDX SBOM export, SHA256SUMS, keyless cosign signatures, and artifact provenance attestation
- Reproducible performance harness (`perf_suite`) with nightly CI budget checks
- Continuous fuzzing setup (`cargo-fuzz`) with offer/protocol/frame parser targets
- Stable/nightly release channel process with documented runbook and nightly artifact workflow
- Feature policy updated: safe default profile (`quic`) and explicit `full` profile (`quic,webrtc,pq`)
- Security policy/process hardening: explicit coordinated disclosure workflow and reporter intake checklist
- Added WASM CI compile path for `ouroboros-crypto` (`wasm32-unknown-unknown`)
- UI architecture refactor started: `App.tsx` reduced to shell and feature module moved under `ui/src/features/app/`
- UI state slices added under `ui/src/features/app/stateSlices.ts` for system/connection/flow configuration domains
- Added formal-methods pilot via property-based invariants (`tests/property_crypto_invariants.rs`)
- Added discovery abstraction baseline (`src/discovery.rs`) with DHT integration roadmap (`docs/discovery_dht.md`)
- Discovery multi-node propagation baseline added via `FederatedDiscovery` and config discovery knobs
- Discovery service API and deterministic discovery-space hash derivation added for DHT wiring
- `ouroboros-crypto` randomness backend switched to `getrandom` for improved wasm portability
- `ouroboros-crypto` wasm32 target validated (`cargo check` + `cargo test --no-run`)
- Discovery bootstrap parsing hardening added (`parse_bootstrap_peers`: skip invalid + deduplicate)

### Security
- Initial security audit completed
- See [docs/threat_model_visibility.md](docs/threat_model_visibility.md) for details

## [0.1.0] - 2025-01-22

### Initial Release
- Core P2P communication engine
- Multi-transport coordination (ICE)
- Cryptographic handshake via Noise protocol
- Initial command-line interface
- Basic documentation

[Unreleased]: https://github.com/omarsomaro/handshake/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/omarsomaro/handshake/releases/tag/v0.1.0
