//! TCP framing: length-prefix protocol for sending packets over streams
//!
//! Format: [4-byte BE length][payload]
//! Guards against memory bombs with MAX_FRAME limit.

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum frame size (1MB) to prevent memory bombs
pub const MAX_FRAME: usize = crate::crypto::MAX_TCP_FRAME_BYTES as usize;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("frame too large: {0} bytes (max {1})")]
    FrameTooLarge(usize, usize),
    #[error("invalid frame: zero length")]
    ZeroLength,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("connection closed during frame read")]
    ConnectionClosedDuringRead,
    #[error("failed to write frame length: {0}")]
    WriteLength(String),
    #[error("failed to write frame payload: {0}")]
    WritePayload(String),
    #[error("failed to flush stream: {0}")]
    Flush(String),
    #[error("failed to read frame length: {0}")]
    ReadLength(String),
    #[error("failed to read frame payload: {0}")]
    ReadPayload(String),
}

type Result<T> = std::result::Result<T, FramingError>;

/// Validate frame length against protocol constraints.
pub fn validate_frame_len(len: usize) -> Result<usize> {
    if len == 0 {
        return Err(FramingError::ZeroLength);
    }
    if len > MAX_FRAME {
        return Err(FramingError::FrameTooLarge(len, MAX_FRAME));
    }
    Ok(len)
}

/// Parse a 4-byte big-endian frame length and validate it.
pub fn parse_frame_len(len_buf: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(len_buf) as usize;
    validate_frame_len(len)
}

/// Write a framed message: [4-byte BE length][payload]
pub async fn write_frame<S>(stream: &mut S, data: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    validate_frame_len(data.len())?;

    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| FramingError::WriteLength(e.to_string()))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| FramingError::WritePayload(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| FramingError::Flush(e.to_string()))?;

    Ok(())
}

/// Read a framed message, returns payload
///
/// Returns Err on:
/// - EOF during read (connection closed)
/// - len == 0 (invalid frame)
/// - len > MAX_FRAME (memory bomb protection)
pub async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];

    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(FramingError::ConnectionClosed);
        }
        Err(e) => return Err(FramingError::ReadLength(e.to_string())),
    }

    let len = parse_frame_len(len_buf)?;

    let mut payload = vec![0u8; len];
    match stream.read_exact(&mut payload).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(FramingError::ConnectionClosedDuringRead);
        }
        Err(e) => return Err(FramingError::ReadPayload(e.to_string())),
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_frame_constant() {
        assert_eq!(MAX_FRAME, 1_048_576);
    }
}
