use std::future::Future;
use std::pin::Pin;

use thiserror::Error;

use super::Connection;

#[derive(Debug, Error)]
pub enum TransportIoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("framing error: {0}")]
    Framing(#[from] crate::transport::framing::FramingError),
    #[error("quic transport error: {0}")]
    Quic(String),
    #[error("webrtc transport error: {0}")]
    WebRtc(String),
    #[error("relay transport error: {0}")]
    Relay(String),
}

pub type IoResult<T> = std::result::Result<T, TransportIoError>;

/// Transport IO abstraction for sending/receiving raw frames.
pub trait TransportIo: Send + Sync {
    fn max_packet_limit(&self) -> u64;
    fn rate_limit_addr(&self) -> std::net::SocketAddr;
    fn send<'a>(&'a self, data: Vec<u8>)
        -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + 'a>>;
    fn recv<'a>(&'a self) -> Pin<Box<dyn Future<Output = IoResult<Vec<u8>>> + Send + 'a>>;
}

/// Adapter that exposes Connection as TransportIo without changing core logic.
pub struct ConnectionIo {
    conn: Connection,
}

impl ConnectionIo {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

impl TransportIo for ConnectionIo {
    fn max_packet_limit(&self) -> u64 {
        match &self.conn {
            Connection::WebRtc(_) => crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES as u64,
            _ if self.conn.is_stream() => crate::crypto::MAX_TCP_FRAME_BYTES,
            _ => crate::crypto::MAX_UDP_PACKET_BYTES,
        }
    }

    fn rate_limit_addr(&self) -> std::net::SocketAddr {
        self.conn
            .peer_addr()
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    fn send<'a>(
        &'a self,
        data: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = IoResult<()>> + Send + 'a>> {
        let conn = self.conn.clone();
        Box::pin(async move {
            match conn {
                Connection::Lan(sock, addr) | Connection::Wan(sock, addr) => {
                    sock.send_to(&data, addr).await?;
                }
                Connection::WanTorStream { writer, .. } => {
                    let mut guard = writer.lock().await;
                    crate::transport::framing::write_frame(&mut *guard, &data).await?;
                }
                Connection::WanTcpStream { writer, .. } => {
                    let mut guard = writer.lock().await;
                    crate::transport::framing::write_frame(&mut *guard, &data).await?;
                }
                Connection::Quic(quic) => {
                    quic.send(&data)
                        .await
                        .map_err(|e| TransportIoError::Quic(e.to_string()))?;
                }
                Connection::WebRtc(webrtc) => {
                    webrtc
                        .send(&data)
                        .await
                        .map_err(|e| TransportIoError::WebRtc(e.to_string()))?;
                }
            }
            Ok(())
        })
    }

    fn recv<'a>(&'a self) -> Pin<Box<dyn Future<Output = IoResult<Vec<u8>>> + Send + 'a>> {
        let conn = self.conn.clone();
        Box::pin(async move {
            match conn {
                Connection::Lan(sock, _) | Connection::Wan(sock, _) => {
                    let mut buf = vec![0u8; crate::config::UDP_MAX_PACKET_SIZE];
                    let (n, _) = sock.recv_from(&mut buf).await?;
                    Ok(buf[..n].to_vec())
                }
                Connection::WanTorStream { reader, .. } => {
                    let mut guard = reader.lock().await;
                    crate::transport::framing::read_frame(&mut *guard)
                        .await
                        .map_err(Into::into)
                }
                Connection::WanTcpStream { reader, .. } => {
                    let mut guard = reader.lock().await;
                    crate::transport::framing::read_frame(&mut *guard)
                        .await
                        .map_err(Into::into)
                }
                Connection::Quic(quic) => quic
                    .recv()
                    .await
                    .map_err(|e| TransportIoError::Quic(e.to_string())),
                Connection::WebRtc(webrtc) => webrtc
                    .recv()
                    .await
                    .map_err(|e| TransportIoError::WebRtc(e.to_string())),
            }
        })
    }
}
