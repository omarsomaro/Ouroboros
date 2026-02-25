use thiserror::Error;

const MIN_V3_ONION_LEN: usize = 56;
const MAX_V3_ONION_LEN: usize = 62;
const ONION_SUFFIX: &str = ".onion";

#[derive(Debug, Error)]
pub enum OnionError {
    #[error("{0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, OnionError>;

pub fn validate_onion_addr(target: &str) -> Result<()> {
    let _ = parse_onion_addr(target)?;
    Ok(())
}

pub fn parse_onion_addr(target: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(OnionError::Invalid(
            "Tor address must include port: address.onion:port".to_string(),
        ));
    }

    let port_str = parts[0];
    let host = parts[1];

    let port: u16 = port_str
        .parse()
        .map_err(|_| OnionError::Invalid("Invalid port in Tor address".to_string()))?;
    if port == 0 {
        return Err(OnionError::Invalid(
            "Invalid port in Tor address (cannot be 0)".to_string(),
        ));
    }

    if !host.ends_with(ONION_SUFFIX) {
        return Err(OnionError::Invalid(
            "Tor address must end with .onion".to_string(),
        ));
    }

    let host_no_suffix = host.trim_end_matches(ONION_SUFFIX);
    if host_no_suffix.len() < MIN_V3_ONION_LEN {
        return Err(OnionError::Invalid(format!(
            "Invalid v3 onion length: {} chars (minimum {})",
            host_no_suffix.len(),
            MIN_V3_ONION_LEN
        )));
    }
    if host_no_suffix.len() > MAX_V3_ONION_LEN {
        return Err(OnionError::Invalid(format!(
            "Invalid v3 onion length: {} chars (maximum {})",
            host_no_suffix.len(),
            MAX_V3_ONION_LEN
        )));
    }
    if !host_no_suffix
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '2'..='7'))
    {
        return Err(OnionError::Invalid(
            "Invalid onion address characters (expected base32 lowercase: a-z, 2-7)".to_string(),
        ));
    }

    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    prop_compose! {
        fn onion_host()(len in MIN_V3_ONION_LEN..=MAX_V3_ONION_LEN)
            (chars in prop::collection::vec(prop::sample::select(ALPHABET), len)) -> String {
            chars.into_iter().map(|c| c as char).collect()
        }
    }

    proptest! {
        #[test]
        fn parse_roundtrip_onion(host in onion_host(), port in 1u16..=u16::MAX) {
            let target = format!("{}.onion:{}", host, port);
            let (parsed_host, parsed_port) = parse_onion_addr(&target).unwrap();
            prop_assert_eq!(parsed_host, format!("{}.onion", host));
            prop_assert_eq!(parsed_port, port);
        }
    }

    #[test]
    fn parse_rejects_missing_port() {
        let err = parse_onion_addr("abcd.onion").unwrap_err();
        assert!(err.to_string().contains("port"));
    }
}
