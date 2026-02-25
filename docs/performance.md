# Performance Benchmarks

This project includes a reproducible benchmark harness:

```bash
cargo run --release --bin perf_suite -- --output perf-metrics.json
```

To enforce budgets:

```bash
cargo run --release --bin perf_suite -- --check-budgets --output perf-metrics.json
```

## Metrics covered

- deterministic derive latency (`derive_from_passphrase_v2`)
- in-memory Noise XX handshake latency (`run_noise_upgrade_io`)
- symmetric crypto throughput (`seal_with_nonce` + `open`)
- Linux memory high-water-mark delta (`VmHWM`) during run

## Current budgets

- `derive_avg_ms <= 300.0`
- `noise_handshake_avg_ms <= 120.0`
- `crypto_throughput_mib_s >= 10.0`
- `memory_hwm_delta_kib <= 131072`

## CI integration

- Nightly workflow: `.github/workflows/perf.yml`
- Output artifact: `perf-metrics.json`
- Budget check is enforced in the workflow (`--check-budgets`)

## Notes

- Memory high-water-mark metric is Linux-specific; on non-Linux platforms it is omitted.
- This suite is tuned for reproducibility, not for micro-architectural maximum throughput.
- Example baseline snapshot from this repository is stored in `docs/perf_baseline_windows.json`.
