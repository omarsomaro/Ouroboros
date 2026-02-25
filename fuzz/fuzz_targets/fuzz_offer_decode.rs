#![no_main]

use base64::{engine::general_purpose, Engine as _};
use handshacke::offer::OfferPayload;
use handshacke::security::time_validation::TimeValidator;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let candidate = if data.first().map(|b| (b & 1) == 0).unwrap_or(false) {
        general_purpose::URL_SAFE_NO_PAD.encode(data)
    } else {
        String::from_utf8_lossy(data).into_owned()
    };

    if let Ok(offer) = OfferPayload::decode(&candidate) {
        let validator = TimeValidator::new();
        let _ = offer.verify(&validator);
        let _ = offer.encode();
        let _ = offer.tor_onion_addr();
    }
});
