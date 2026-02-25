# Error Model

Status: Draft v1 (2026-02-24)

## Goal

Use domain-specific typed errors (`thiserror`) inside core modules, and reserve `anyhow` for process/application boundaries (CLI, API server bootstrap, top-level orchestration).

## Rules

1. Domain modules return `Result<T, DomainError>` and define a local `*Error` enum.
2. Domain errors must be descriptive and stable enough for tests and logs.
3. Boundary layers may convert with `?` into `anyhow::Result<T>`.
4. Avoid new ad-hoc `anyhow!("...")` in core/domain code.

## Current migration

- Completed:
  - `src/derive.rs` now uses `DeriveError` (`thiserror`) instead of `anyhow`.
  - `src/offer.rs` now uses `OfferError` (`thiserror`) instead of `anyhow`.
  - `src/crypto.rs` now uses `CryptoError` (`thiserror`) instead of `anyhow`.
  - `src/crypto/post_quantum.rs` now uses `PostQuantumError` (`thiserror`) instead of `anyhow`.
  - `src/onion.rs` now uses `OnionError` (`thiserror`) instead of `anyhow`.
  - `src/phrase.rs` now uses `PhraseError` (`thiserror`) instead of `anyhow`.
  - `src/protocol_assist.rs` now uses `ProtocolAssistError` (`thiserror`) instead of `anyhow`.
  - `src/protocol_assist_v5.rs` now uses `ProtocolAssistV5Error` (`thiserror`) instead of `anyhow`.
  - `src/resume.rs` now uses `ResumeError` (`thiserror`) instead of `anyhow`.
  - `src/security/time_validation.rs` now uses `TimeValidationError` (`thiserror`) instead of `anyhow`.
  - `src/session_noise.rs` now uses `SessionNoiseError` (`thiserror`) instead of `anyhow`.
  - `src/transport/lan.rs` now uses `LanError` (`thiserror`) instead of `anyhow`.
  - `src/transport/nat_detection.rs` now uses `NatDetectionError` (`thiserror`) instead of `anyhow`.
  - `src/transport/stun.rs` now uses `StunError` (`thiserror`) instead of `anyhow`.
  - `src/transport/wan_direct.rs` now uses `WanDirectError` (`thiserror`) instead of `anyhow`.
  - `src/transport/wan.rs` now uses `WanError` (`thiserror`) instead of `anyhow`.
  - `src/transport/stealth.rs` now uses `StealthError` (`thiserror`) instead of `anyhow`.
  - `src/transport/assist_inbox.rs` now uses `AssistInboxError` (`thiserror`) instead of `anyhow`.
  - `src/transport/tcp_hole_punch.rs` now uses `TcpHolePunchError` (`thiserror`) instead of `anyhow`.
  - `src/transport/icmp_hole_punch.rs` now uses `IcmpHolePunchError` (`thiserror`) instead of `anyhow`.
  - `src/transport/noise_tun.rs` now uses `NoiseTunError` (`thiserror`) instead of `anyhow`.
  - `src/transport/ice.rs` now uses `IceError` (`thiserror`) instead of `anyhow`.
  - `src/transport/multipath.rs` now uses `MultipathError` (`thiserror`) instead of `anyhow`.
  - `src/transport/wan_tor.rs` now uses `WanTorError` (`thiserror`) instead of `anyhow`.
  - `src/transport/quic_rfc9000.rs` now uses `QuicError` (`thiserror`) instead of `anyhow`.
  - `src/transport/webrtc.rs` now uses `WebRtcError` (`thiserror`) instead of `anyhow`.
  - `src/transport/io.rs` now uses `TransportIoError` (`thiserror`) instead of `anyhow`.
  - `src/transport/guaranteed.rs` now uses `GuaranteedError` (`thiserror`) at module boundary and `TransportIoError` for relay I/O.
  - `src/transport/wan_assist.rs` now uses `WanAssistError` (`thiserror`) instead of `anyhow`.
  - `src/transport/pluggable/mimicry.rs` now uses `MimicryError` (`thiserror`) instead of `anyhow`.
  - `src/transport/pluggable/http2_mimic.rs` now uses `MimicryError` instead of `anyhow`.
  - `src/transport/pluggable/quic_mimic.rs` now uses `MimicryError` instead of `anyhow`.
  - `src/transport/pluggable/ws_mimic.rs` now uses `MimicryError` instead of `anyhow`.
  - `src/transport/mod.rs` no longer imports `anyhow`; it uses a local boxed boundary error alias.
  - `src/transport/tasks.rs` no longer uses `anyhow::Result` in rotation helpers.
  - `src/transport/pluggable.rs` no longer imports `anyhow`; it uses a local boxed error alias.
  - `src/transport/pluggable/real_tls.rs` no longer imports `anyhow`; it uses a local boxed error alias.
  - `src/tor/managed.rs` now uses `ManagedTorError` (`thiserror`) instead of `anyhow`.
  - API boundary conversion added: `From<OfferError> for ApiError`.
- Pending:
  - Process/boundary modules still intentionally using `anyhow` (`src/main.rs`, CLI, API bootstrap, top-level state orchestration).

Current scan snapshot (2026-02-24):
- `transport_anyhow_hits=0`
- `src_anyhow_hits=29`
  - Process/boundary modules still intentionally using `anyhow` (`src/main.rs`, CLI, API bootstrap, top-level state orchestration).

## Suggested rollout

1. Migrate crypto/derive/offer first (stable protocol surface).
2. Migrate transport modules by family (LAN/WAN/Tor/Assist/Pluggable).
3. Keep API handlers converting domain errors to `ApiError` at boundaries.
4. Add regression tests for representative error paths after each migration chunk.
