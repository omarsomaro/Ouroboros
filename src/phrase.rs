use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const INVITE_PREFIX: &str = "hs1:";

#[derive(Debug, Error)]
pub enum PhraseError {
    #[error("invalid invite prefix")]
    InvalidPrefix,
    #[error("invite base64: {0}")]
    Base64(String),
    #[error("invite json: {0}")]
    Json(String),
}

type Result<T> = std::result::Result<T, PhraseError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct PhraseInvite {
    pub ver: u8,
    pub product: String,
    pub policy: String,
    pub onion: String,
    pub virt_port: u16,
}

impl PhraseInvite {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(|e| PhraseError::Json(e.to_string()))?;
        let b64 = general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("{}{}", INVITE_PREFIX, b64))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let b64 = s
            .strip_prefix(INVITE_PREFIX)
            .ok_or(PhraseError::InvalidPrefix)?;
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| PhraseError::Base64(e.to_string()))?;
        let invite =
            serde_json::from_slice(&bytes).map_err(|e| PhraseError::Json(e.to_string()))?;
        Ok(invite)
    }
}
