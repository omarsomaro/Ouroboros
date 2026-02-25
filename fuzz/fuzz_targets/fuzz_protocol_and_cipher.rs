#![no_main]

use bincode::Options;
use handshacke::crypto::{
    deserialize_cipher_packet_with_limit, open, serialize_cipher_packet, MAX_TCP_FRAME_BYTES,
};
use handshacke::protocol::Control;
use handshacke::protocol_assist::{compute_assist_mac, AssistGo, AssistRequest};
use handshacke::protocol_assist_v5::{
    compute_assist_go_mac_v5, compute_assist_mac_v5, verify_assist_go_mac_v5, verify_assist_mac_v5,
    AssistGoV5, AssistRequestV5,
};
use libfuzzer_sys::fuzz_target;

fn bounded_opts() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_TCP_FRAME_BYTES)
}

fuzz_target!(|data: &[u8]| {
    let key = [0x11u8; 32];

    if let Ok(pkt) = deserialize_cipher_packet_with_limit(data, MAX_TCP_FRAME_BYTES) {
        let _ = open(&key, &pkt, pkt.tag16, pkt.tag8);
        let _ = serialize_cipher_packet(&pkt);
    }

    if let Ok(ctrl) = bounded_opts().deserialize::<Control>(data) {
        let _ = bincode::serialize(&ctrl);
    }

    if let Ok(req) = bounded_opts().deserialize::<AssistRequest>(data) {
        let _ = compute_assist_mac(&key, &req);
    }
    let _ = bounded_opts().deserialize::<AssistGo>(data);

    if let Ok(req_v5) = bounded_opts().deserialize::<AssistRequestV5>(data) {
        let _ = compute_assist_mac_v5(&key, &req_v5);
        let _ = verify_assist_mac_v5(&key, &req_v5);
    }
    if let Ok(go_v5) = bounded_opts().deserialize::<AssistGoV5>(data) {
        let _ = compute_assist_go_mac_v5(&key, &go_v5);
        let _ = verify_assist_go_mac_v5(&key, &go_v5);
    }
});
