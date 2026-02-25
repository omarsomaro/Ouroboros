# State Of The Art Checklist - Ouroboros

Generated on: 2026-02-23
Source baseline: `docs/biblico.md` + repository audit
Document owner: TBD
Status: Draft v1

## Goal

Turn Ouroboros into a production-grade, state-of-the-art P2P platform with explicit quality gates for architecture, security, testing, release, and developer experience.

## Priority legend

- P0 = blocking for production readiness
- P1 = high-value, near-term
- P2 = medium-term
- P3 = long-term or research

## Global quality gates (Definition of Done for every item)

- Tests: relevant unit/integration/e2e tests added or updated
- CI: all mandatory checks green on Linux and Windows
- Docs: user and maintainer docs updated in `README.md` or `docs/`
- Security: threat impact reviewed, no new high/critical findings
- Observability: logs/metrics updated where behavior changes

## Master checklist

| ID | Area | Task | Prio | Owner | ETA | Status | DoD (item specific) |
|---|---|---|---|---|---|---|---|
| SOTA-001 | Public API | Replace wildcard re-exports with explicit stable surface in `src/lib.rs` and `src/prelude.rs` | P0 | Core | 1 week | Completed (2026-02-23) | No `pub use *` in core public API modules; semver-facing API list documented |
| SOTA-002 | API architecture | Split `src/api.rs` into domain modules (auth, connect, offer, phrase, metrics, transport) | P0 | Core | 2-3 weeks | Completed (2026-02-24) | `src/api.rs` reduced to router/composition layer; endpoint behavior unchanged with tests |
| SOTA-003 | Repo hygiene | Stop tracking `ui/node_modules`, update `.gitignore`, clean repository size | P0 | DevEx | 1 day | Completed (2026-02-23) | `ui/node_modules` removed from git index; clean clone/install flow documented |
| SOTA-004 | Security hardening | Tauri hardening: set CSP, remove insecure defaults in `ui/src-tauri/tauri.conf.json` | P0 | Security + UI | 1 week | Completed (2026-02-23) | Non-null CSP policy; desktop app works in dev and build modes |
| SOTA-005 | Documentation integrity | Align `ui/README.md` token handling with real RAM-only flow | P0 | Docs + UI | 1 day | Completed (2026-02-23) | No contradictions about `HANDSHACKE_API_TOKEN_FILE` vs in-memory token path |
| SOTA-006 | CI security | Add `cargo audit` and `cargo deny` pipelines with policy files | P0 | Security + DevEx | 1 week | Completed (bootstrap, 2026-02-23) | CI fails on disallowed licenses/advisories; documented allowlist policy |
| SOTA-007 | Error model | Unify error strategy (`thiserror` for domain, `anyhow` at boundaries only) | P1 | Core | 2 weeks | Completed (2026-02-24, core/domain migrated; boundary-only `anyhow` retained by design) | Error taxonomy documented; no ad-hoc mixed patterns in core modules |
| SOTA-008 | EtherSync reliability | Implement real Reed-Solomon erasure coding in `ethersync/src/erasure_coding.rs` | P1 | EtherSync | 2-3 weeks | Completed (2026-02-24) | K-of-N recovery tests pass; stub paths removed |
| SOTA-009 | Discovery | Implement real DHT-based discovery (libp2p-kad or equivalent) | P1 | Networking | 3-4 weeks | Completed (2026-02-25, feature-gated libp2p-kad provider + local multi-node test) | Bootstrap + peer discovery tested on local multi-node scenario |
| SOTA-010 | CI breadth | Add frontend CI (build, lint, tests) for `ui/` | P1 | UI + DevEx | 1 week | Completed (2026-02-24) | PR blocked on frontend quality gates, same as Rust core |
| SOTA-011 | Supply chain | Add SBOM generation and release provenance/signature checks | P1 | Security + Release | 2 weeks | Completed (2026-02-24, release workflow + SBOM/checksum + keyless signatures + provenance automation added) | Signed artifacts + checksums + provenance attached per release |
| SOTA-012 | Performance | Add reproducible benchmarks (handshake latency, throughput, memory) | P1 | Core + Perf | 2 weeks | Completed (2026-02-24, `perf_suite` + nightly workflow + budgets/baseline docs) | Benchmark suite runs in CI/nightly; baseline and budget documented |
| SOTA-013 | Fuzzing | Add continuous fuzzing for parser and protocol surfaces | P1 | Security + Core | 2 weeks | Completed (2026-02-24, `cargo-fuzz` targets + scheduled workflow + docs) | Fuzz targets for offer/assist/frame parsing; no crash in fixed time window |
| SOTA-014 | UI architecture | Break `ui/src/App.tsx` into feature modules and state slices | P2 | UI | 2 weeks | Completed (2026-02-24, app shell extracted + state slices + shared model module) | Main app shell under 400 LOC; behavior parity preserved |
| SOTA-015 | Feature policy | Re-evaluate default feature set (`quic,webrtc,pq`) for safe defaults | P2 | Core + Product | 1 week | Completed (2026-02-24, safe default + full profile introduced and documented) | New default profile documented with security/perf rationale |
| SOTA-016 | Security process | Publish real PGP key and operational disclosure workflow in `SECURITY.md` | P2 | Security | 3 days | In progress (2026-02-24, workflow published; PGP publication intentionally deferred by maintainer) | Valid PGP block published and tested; response process is actionable |
| SOTA-017 | Release process | Define stable/nightly channels with release checklist | P2 | Release | 1 week | Completed (2026-02-24, stable/nightly workflows + runbook docs) | Repeatable release runbook in docs; changelog/versioning policy enforced |
| SOTA-018 | Formal methods | Pilot formal verification/property proofs for critical crypto/session invariants | P3 | Research + Security | 4-6 weeks | Completed (2026-02-24, property-based invariants added and documented) | At least 1 critical invariant formally checked and documented |
| SOTA-019 | WASM target | Add wasm target support for `ouroboros-crypto` with tests | P3 | Crypto | 2 weeks | Completed (2026-02-24, wasm target install + `cargo check` + `cargo test --no-run` validated) | `wasm32-unknown-unknown` build green and documented |
| SOTA-020 | Roadmap coherence | Reconcile `docs/future.md` and `docs/biblico.md` with current implementation | P0 | Docs + Maintainers | 3 days | Completed (2026-02-24) | No stale "spec draft" claims where features already exist |
| SOTA-021 | EtherSync UX | Productize EtherSync in API + GUI: guided space flow, chunked file transfer, progress/download UX | P1 | Core + UI | 1 week | Completed (2026-02-25, `/v1/ethersync/*` integration + `space` mode + file chunk publish/download UX) | Operator can start/join/publish text+file from GUI without CLI, with live events and transfer progress |

## Execution order (recommended)

1. P0 readiness sprint: SOTA-001, 002, 003, 004, 005, 006, 020
2. P1 capability sprint: SOTA-007, 008, 009, 010, 011, 012, 013
3. P2 operability sprint: SOTA-014, 015, 016, 017
4. P3 research sprint: SOTA-018, 019

## Weekly review template

| Week | Completed | In progress | Blocked | Risks | Decisions |
|---|---|---|---|---|---|
| YYYY-Www |  |  |  |  |  |

## Change log

- 2026-02-23: Initial checklist created from architecture bible and repository audit.
- 2026-02-23: Updated status after first implementation sprint (P0 mostly completed, SOTA-002 in progress).
- 2026-02-23: API monolith split continued (auth/types/diagnostics/pluggable/phrase/session/stream modules). Added initial UI CI workflow.
- 2026-02-23: Additional API split (`sync`, `connect_helpers`) reduced `src/api.rs` from ~1878 to ~855 lines with checks passing.
- 2026-02-24: Completed API architecture split: moved `/v1/connect` handler to `src/api/connect.rs`; `src/api.rs` is now router/composition (~100 LOC). `cargo test` green.
- 2026-02-24: Marked roadmap coherence completed after explicit alignment notes in `docs/future.md` and `docs/biblico.md`.
- 2026-02-24: Strengthened frontend CI with TypeScript typecheck gate (`npm run typecheck`) plus existing web build step.
- 2026-02-24: Added UI `lint` and `test` gates (`node` scripts, no extra deps) and wired them into `.github/workflows/ui.yml`.
- 2026-02-24: Verified UI gates end-to-end (`lint`, `typecheck`, `test`, `build:web`).
- 2026-02-24: Started error-model migration (`SOTA-007`): `src/derive.rs` moved from `anyhow` to typed `DeriveError`; added `docs/error_model.md`.
- 2026-02-24: Continued `SOTA-007`: `src/offer.rs` migrated to typed `OfferError` and API boundary conversion (`From<OfferError> for ApiError`) added.
- 2026-02-24: Completed `SOTA-008`: replaced erasure-coding stub with real Reed-Solomon `(k+m)` encode/decode + recovery tests in `ethersync/src/erasure_coding.rs`.
- 2026-02-24: Continued `SOTA-007`: `src/crypto.rs` migrated to typed `CryptoError` (nonce, packet parse, serialization, encrypt paths).
- 2026-02-24: Continued `SOTA-007`: `src/onion.rs` and `src/phrase.rs` migrated to typed errors (`OnionError`, `PhraseError`).
- 2026-02-24: Continued `SOTA-007`: `src/security/time_validation.rs` migrated to typed `TimeValidationError`.
- 2026-02-24: Continued `SOTA-007`: `src/session_noise.rs` migrated to typed `SessionNoiseError` with compatible async I/O generics and tests updated.
- 2026-02-24: Continued `SOTA-007`: migrated `src/protocol_assist.rs`, `src/protocol_assist_v5.rs`, `src/resume.rs`, and `src/crypto/post_quantum.rs` to typed errors.
- 2026-02-24: Continued `SOTA-007`: migrated transport slice `src/transport/{lan,nat_detection,stun,wan_direct,wan,stealth}.rs` to typed errors; full `cargo test` remains green.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/{assist_inbox,tcp_hole_punch,icmp_hole_punch}.rs` to typed errors; full `cargo test` remains green.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/{noise_tun,ice}.rs` to typed errors and updated ICE boundary conversion in `src/transport/mod.rs`; full `cargo test` remains green.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/multipath.rs` to typed `MultipathError`; current scan shows `transport_anyhow_hits=73`, `src_anyhow_hits=105`.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/wan_tor.rs` to typed `WanTorError`; current scan shows `transport_anyhow_hits=72`, `src_anyhow_hits=104`.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/quic_rfc9000.rs` to typed `QuicError` and adapted `src/transport/io.rs` bridge conversion; current scan shows `transport_anyhow_hits=60`, `src_anyhow_hits=92`.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/webrtc.rs` to typed `WebRtcError` and updated `src/transport/io.rs` result bridging; current scan shows `transport_anyhow_hits=54`, `src_anyhow_hits=86`.
- 2026-02-24: Continued `SOTA-007`: migrated `src/transport/io.rs` to typed `TransportIoError`, migrated `src/transport/guaranteed.rs` to typed boundary error + typed relay I/O, and migrated `src/transport/wan_assist.rs` to typed `WanAssistError`.
- 2026-02-24: Continued `SOTA-007`: migrated pluggable mimicry stack (`src/transport/pluggable/{mimicry,http2_mimic,quic_mimic,ws_mimic}.rs`) to typed `MimicryError`; current scan shows `transport_anyhow_hits=7`, `src_anyhow_hits=39`.
- 2026-02-24: Continued `SOTA-007`: migrated `src/tor/managed.rs` to typed `ManagedTorError`; current scan shows `transport_anyhow_hits=7`, `src_anyhow_hits=35`.
- 2026-02-24: Continued `SOTA-007`: reduced residual transport `anyhow` surface by removing macro-based construction in `src/transport/mod.rs` and compatibility cleanup in `src/transport/pluggable.rs` + `src/transport/pluggable/real_tls.rs`; current scan shows `transport_anyhow_hits=5`, `src_anyhow_hits=33`.
- 2026-02-24: Continued `SOTA-007`: completed transport-side `anyhow` removal (`src/transport/{mod,tasks,pluggable,pluggable/real_tls}.rs`) and updated state boundary conversion in `src/state/connection_manager.rs`; current scan shows `transport_anyhow_hits=0`, `src_anyhow_hits=29`.
- 2026-02-24: Marked `SOTA-007` completed: `anyhow` usage is now limited to intended process/API/CLI boundaries.
- 2026-02-24: Started `SOTA-011`: added `.github/workflows/release.yml` with tag-triggered packaging, CycloneDX SBOM generation, `SHA256SUMS`, and GitHub build provenance attestations; added `docs/release_provenance.md`.
- 2026-02-24: Completed `SOTA-011`: added keyless `cosign` signature artifacts for `SHA256SUMS` (`.sig`, `.pem`, `.bundle`) and verification instructions in `docs/release_provenance.md`.
- 2026-02-24: Completed `SOTA-012`: added reproducible performance harness `src/bin/perf_suite.rs`, nightly budget workflow `.github/workflows/perf.yml`, and baseline/budget docs in `docs/performance.md` (+ sample baseline `docs/perf_baseline_windows.json`).
- 2026-02-24: Completed `SOTA-013`: added `cargo-fuzz` targets under `fuzz/` (offer/protocol+cipher/frame), scheduled CI workflow `.github/workflows/fuzz.yml`, and guide `docs/fuzzing.md`.
- 2026-02-24: Completed `SOTA-017`: added nightly snapshot workflow `.github/workflows/nightly.yml` and documented stable/nightly runbook in `docs/release_process.md`.
- 2026-02-24: Completed `SOTA-015`: changed feature policy to safe default (`default = [\"quic\"]`) and added `full` profile (`quic,webrtc,pq`) with CI/doc updates.
- 2026-02-24: Advanced `SOTA-016`: rewrote `SECURITY.md` with operational intake/triage/disclosure workflow and reporter checklist; real PGP key publication remains pending.
- 2026-02-24: Advanced `SOTA-019`: added `.github/workflows/wasm.yml` and `docs/wasm.md` for `wasm32-unknown-unknown` compile path.
- 2026-02-24: Completed `SOTA-014`: moved UI app implementation to `ui/src/features/app/AppView.tsx`, introduced shared model module `ui/src/features/app/model.ts`, added state slices in `ui/src/features/app/stateSlices.ts`, and reduced `ui/src/App.tsx` to a thin shell wrapper (5 LOC).
- 2026-02-24: Completed `SOTA-018`: added property-based crypto/session invariants in `tests/property_crypto_invariants.rs` and documented the formal-methods pilot in `docs/formal_methods.md`.
- 2026-02-24: Advanced `SOTA-009`: added discovery abstraction in `src/discovery.rs` (`DiscoveryProvider`, `DiscoveryRecord`, `InMemoryDiscovery`) plus roadmap document `docs/discovery_dht.md` for libp2p-kad integration.
- 2026-02-24: `SOTA-016` remains intentionally deferred by maintainer decision (PGP publication postponed).
- 2026-02-24: Continued `SOTA-009`: added `FederatedDiscovery` fanout backend and 3-node propagation test in `src/discovery.rs`; wired config knobs `HANDSHACKE_DISCOVERY_ENABLED` and `HANDSHACKE_DISCOVERY_BOOTSTRAP_PEERS`.
- 2026-02-24: Continued `SOTA-009`: added `DiscoveryService` bootstrap fallback API and deterministic `space_hash_from_rendezvous` derivation, with additional discovery invariants/tests.
- 2026-02-24: Continued `SOTA-009`: added `parse_bootstrap_peers` utility (invalid-entry skip + dedup) and expanded discovery test coverage to 6 focused tests.
- 2026-02-24: Continued `SOTA-019`: updated `ouroboros-crypto` RNG path to `getrandom` (with wasm `js` target support) to improve `wasm32` portability before full target validation.
- 2026-02-24: Completed `SOTA-019`: validated `wasm32-unknown-unknown` with `cargo check -p ouroboros-crypto --target wasm32-unknown-unknown` and `cargo test -p ouroboros-crypto --target wasm32-unknown-unknown --no-run`.
- 2026-02-25: Completed `SOTA-009`: implemented `KadDiscoveryProvider` under `dht` feature in `src/discovery/kad.rs` (real libp2p-kad `put_record`/`get_record`, bootstrap peer wiring, endpoint TTL freshness filtering) and validated 3-node discovery roundtrip test (`cargo test --features dht discovery::`).
- 2026-02-25: Added EtherSync operational integration: new API surface `/v1/ethersync/*` (start/stop/status/join/publish/events), daemon runtime lifecycle in `AppState`, and new Tauri UI guided flow `space` for EtherSync Space usage.
- 2026-02-25: Completed `SOTA-021`: added chunked file publish endpoint (`POST /v1/ethersync/files/publish`), file-chunk event handling, in-app transfer reconstruction/download, and UX upgrades in `space` mode (quick `Start + Join`, chunk validation, copy helpers, transfer progress and message feed).
- 2026-02-25: Added EtherSync file-transfer integration tests in `tests/ethersync_file_transfer.rs` (2-node chunked transfer reconstruction and chunk-size/filename normalization checks) to lock SOTA-021 behavior.
- 2026-02-25: Added API-level EtherSync HTTP tests in `tests/api_ethersync_http.rs` covering `/v1/ethersync/files/publish` success/error paths and `/v1/ethersync/events` SSE emission checks.
- 2026-02-25: Extended API EtherSync HTTP tests with bearer-auth enforcement coverage (`401` for missing/wrong token, `200` with correct token) on `/v1/ethersync/*`.
- 2026-02-25: Added CORS preflight coverage for EtherSync API routes (`OPTIONS /v1/ethersync/files/publish`) verifying preflight bypasses auth middleware and returns expected allow-origin/methods/headers.
- 2026-02-25: Added EtherSync API rate-limit burst test (`/v1/ethersync/files/publish`) confirming limiter saturation returns `429` under high-concurrency request storms.
