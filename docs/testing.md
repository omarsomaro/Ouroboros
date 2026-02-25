# Testing

## Unit tests
```
cargo test
```

## Feature combinations
```
cargo test --no-default-features
cargo test --no-default-features --features full
cargo test --no-default-features --features pq
cargo test --no-default-features --features quic
cargo test --no-default-features --features webrtc
```

## Ignored tests
Some tests require a real ICE/UDP environment and are marked ignored:
```
cargo test --test high_level_webrtc -- --ignored
```

## Performance suite
Run reproducible performance checks:
```
cargo run --release --bin perf_suite -- --output perf-metrics.json
```

Enforce performance budgets:
```
cargo run --release --bin perf_suite -- --check-budgets --output perf-metrics.json
```

## Fuzzing
See `docs/fuzzing.md` for full workflow.
Quick start:
```
cargo fuzz run fuzz_offer_decode -- -max_total_time=60
```
