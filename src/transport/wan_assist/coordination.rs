//! Coordination module for WAN assist simultaneous open
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoordinationError {}

type Result<T> = std::result::Result<T, CoordinationError>;

/// Coordinates simultaneous open between two peers via relay
pub async fn coordinate_simultaneous_open() -> Result<()> {
    Ok(())
}
