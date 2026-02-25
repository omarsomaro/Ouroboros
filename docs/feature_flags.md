# Feature Flags

This project uses optional feature flags to keep the core lightweight and allow
opt-in transport and PQ dependencies.

## Default features
By default the crate enables:
- quic

The default profile is intentionally conservative: it excludes `webrtc` and `pq`
to reduce attack/dependency surface for first deploy.

Use full profile when you explicitly want all optional transports/crypto:
```
cargo build --no-default-features --features full
```

You can disable them with:
```
cargo test --no-default-features
```

## Available features
- `quic`
  - Enables QUIC RFC9000 transport via `quinn` + `rcgen`
  - Module: `transport::quic_rfc9000`

- `full`
  - Convenience profile: enables `quic,webrtc,pq`

- `webrtc`
  - Enables WebRTC DataChannel transport via `webrtc`
  - Module: `transport::webrtc`

- `pq`
  - Enables Kyber hybrid primitives and Noise HFS params
  - Module: `crypto::post_quantum`
  - Noise uses PQ only on stream transports
  - If PQ fails/unavailable, classic XX is used as fallback

## Suggested builds
- Safe default: `cargo build`
- Core only: `cargo build --no-default-features`
- Full profile: `cargo build --no-default-features --features full`
- QUIC only: `cargo build --no-default-features --features quic`
- WebRTC only: `cargo build --no-default-features --features webrtc`
- PQ only: `cargo build --no-default-features --features pq`
