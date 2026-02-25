#![no_main]

use handshacke::transport::framing::{parse_frame_len, validate_frame_len};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let len = data.len();
    let _ = validate_frame_len(len);

    if data.len() >= 4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[..4]);
        let _ = parse_frame_len(buf);
    }
});
