# Formal Methods Pilot

This repository includes a property-based verification pilot for crypto/session invariants.

Test file:

- `tests/property_crypto_invariants.rs`

Verified invariants:

1. Cipher roundtrip correctness:
   - For arbitrary keys/tags/payloads, `seal_with_nonce` followed by `open` returns original payload.
2. Nonce sequence safety:
   - `NonceSeq::next_nonce_and_seq()` is strictly monotonic in sequence number.
   - Produced nonces are unique across sampled sequence window.

Run:

```bash
cargo test --test property_crypto_invariants
```

This is a formal-methods pilot (property checking), not a full theorem-proving workflow.
