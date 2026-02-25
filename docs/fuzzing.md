# Fuzzing

Continuous fuzzing is configured in `.github/workflows/fuzz.yml`.

## Targets

- `fuzz_offer_decode`: offer decode/verify/encode paths
- `fuzz_protocol_and_cipher`: control/assist/cipher deserialization and MAC verification paths
- `fuzz_frame_len`: frame length parsing/validation in transport framing

## Local usage

Install tool:

```bash
cargo install cargo-fuzz --locked
```

Run a target for 60 seconds:

```bash
cargo fuzz run fuzz_offer_decode -- -max_total_time=60
```

Other targets:

```bash
cargo fuzz run fuzz_protocol_and_cipher -- -max_total_time=60
cargo fuzz run fuzz_frame_len -- -max_total_time=60
```

## Notes

- Fuzzing uses nightly Rust via `cargo-fuzz`.
- CI fuzz jobs are time-boxed; increase `-max_total_time` for deeper local campaigns.
