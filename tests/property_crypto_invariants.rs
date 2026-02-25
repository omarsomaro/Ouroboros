use handshacke::crypto::{open, seal_with_nonce, ClearPayload, NonceSeq, NONCE_DOMAIN_APP};
use proptest::array::uniform32;
use proptest::collection::vec;
use proptest::prelude::*;
use std::collections::HashSet;

proptest! {
    #[test]
    fn prop_cipher_roundtrip_preserves_payload(
        key in uniform32(any::<u8>()),
        tag16 in any::<u16>(),
        tag8 in any::<u8>(),
        payload in vec(any::<u8>(), 0..1024)
    ) {
        let mut nonce_seq = NonceSeq::new(&key, NONCE_DOMAIN_APP, 0x01).expect("nonce seq");
        let (nonce, seq) = nonce_seq.next_nonce_and_seq().expect("nonce");
        let clear = ClearPayload {
            ts_ms: 0,
            seq,
            data: payload.clone(),
        };

        let pkt = seal_with_nonce(&key, tag16, tag8, &clear, &nonce).expect("seal");
        let opened = open(&key, &pkt, tag16, tag8).expect("open");

        prop_assert_eq!(opened.seq, seq);
        prop_assert_eq!(opened.data, payload);
    }
}

proptest! {
    #[test]
    fn prop_nonce_seq_is_monotonic_and_unique(
        key in uniform32(any::<u8>()),
        domain in any::<u8>(),
        role in any::<u8>()
    ) {
        let mut ns = NonceSeq::new(&key, domain, role).expect("nonce seq");
        let mut prev_seq = 0u64;
        let mut seen = HashSet::new();

        for _ in 0..64 {
            let (nonce, seq) = ns.next_nonce_and_seq().expect("next nonce");
            prop_assert!(seq > prev_seq);
            prev_seq = seq;
            prop_assert!(seen.insert(nonce));
        }
    }
}
