# WASM Support (`ouroboros-crypto`)

Current target path:

```bash
cargo check -p ouroboros-crypto --target wasm32-unknown-unknown
```

Install target first:

```bash
rustup target add wasm32-unknown-unknown
```

CI coverage:

- Workflow: `.github/workflows/wasm.yml`
- Triggered on changes under `ouroboros-crypto/**`

## Scope

Initial scope is compile validation (`cargo check`) for `wasm32-unknown-unknown`.
Runtime/browser integration tests can be added as a follow-up once compile path is stable.

## Portability notes

- `ouroboros-crypto` randomness now uses `getrandom`, with wasm `js` support enabled
  for `wasm32` targets.

## Validation snapshot

Validated on 2026-02-24:

- `cargo check -p ouroboros-crypto --target wasm32-unknown-unknown`
- `cargo test -p ouroboros-crypto --target wasm32-unknown-unknown --no-run`
