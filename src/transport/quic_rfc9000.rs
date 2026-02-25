#[cfg(feature = "quic")]
mod imp {
    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::RootCertStore;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use thiserror::Error;
    use tokio::sync::Mutex;

    #[derive(Debug, Error)]
    pub enum QuicError {
        #[error("address parse error: {0}")]
        AddrParse(#[from] std::net::AddrParseError),
        #[error("QUIC endpoint error: {0}")]
        Endpoint(String),
        #[error("QUIC connect failed: {0}")]
        Connect(String),
        #[error("QUIC endpoint closed")]
        EndpointClosed,
        #[error("QUIC accept failed: {0}")]
        Accept(String),
        #[error("QUIC open_bi failed: {0}")]
        OpenBi(String),
        #[error("QUIC send stream missing")]
        SendStreamMissing,
        #[error("QUIC framed send failed: {0}")]
        FramedSend(String),
        #[error("QUIC accept_bi failed: {0}")]
        AcceptBi(String),
        #[error("QUIC recv stream missing")]
        RecvStreamMissing,
        #[error("QUIC framed recv failed: {0}")]
        FramedRecv(String),
        #[error("QUIC local_addr failed: {0}")]
        LocalAddr(String),
        #[error("certificate generation failed: {0}")]
        CertGen(String),
        #[error("certificate serialization failed: {0}")]
        CertSerialize(String),
        #[error("server config failed: {0}")]
        ServerConfig(String),
        #[error("root cert add failed: {0}")]
        RootCert(String),
        #[error("client config failed: {0}")]
        ClientConfig(String),
        #[error("Invalid certificate DER")]
        InvalidCertificateDer,
    }

    type Result<T> = std::result::Result<T, QuicError>;

    #[derive(Clone)]
    pub struct QuinnTransport {
        endpoint: Arc<Endpoint>,
        connection: Arc<quinn::Connection>,
        send: Arc<Mutex<Option<quinn::SendStream>>>,
        recv: Arc<Mutex<Option<quinn::RecvStream>>>,
        peer: SocketAddr,
    }

    impl QuinnTransport {
        pub async fn connect(
            addr: SocketAddr,
            server_name: &str,
            client_config: ClientConfig,
        ) -> Result<Self> {
            let bind: SocketAddr = "[::]:0".parse()?;
            let mut endpoint =
                Endpoint::client(bind).map_err(|e| QuicError::Endpoint(e.to_string()))?;
            endpoint.set_default_client_config(client_config);

            let connection = endpoint
                .connect(addr, server_name)
                .map_err(|e| QuicError::Connect(e.to_string()))?
                .await
                .map_err(|e| QuicError::Connect(e.to_string()))?;

            Ok(Self {
                endpoint: Arc::new(endpoint),
                connection: Arc::new(connection),
                send: Arc::new(Mutex::new(None)),
                recv: Arc::new(Mutex::new(None)),
                peer: addr,
            })
        }

        pub async fn accept(bind: SocketAddr, server_config: ServerConfig) -> Result<Self> {
            let endpoint = Endpoint::server(server_config, bind)
                .map_err(|e| QuicError::Endpoint(e.to_string()))?;
            let connecting = endpoint.accept().await.ok_or(QuicError::EndpointClosed)?;
            let connection = connecting
                .await
                .map_err(|e| QuicError::Accept(e.to_string()))?;
            let peer = connection.remote_address();

            Ok(Self {
                endpoint: Arc::new(endpoint),
                connection: Arc::new(connection),
                send: Arc::new(Mutex::new(None)),
                recv: Arc::new(Mutex::new(None)),
                peer,
            })
        }

        pub async fn send(&self, data: &[u8]) -> Result<()> {
            // Lazy-open a local bidirectional stream on first send.
            let mut guard = self.send.lock().await;
            if guard.is_none() {
                let (send, _recv) = self
                    .connection
                    .open_bi()
                    .await
                    .map_err(|e| QuicError::OpenBi(e.to_string()))?;
                *guard = Some(send);
            }

            let send = guard.as_mut().ok_or(QuicError::SendStreamMissing)?;
            crate::transport::framing::write_frame(send, data)
                .await
                .map_err(|e| QuicError::FramedSend(e.to_string()))
        }

        pub async fn recv(&self) -> Result<Vec<u8>> {
            // Lazy-accept a peer-initiated bidirectional stream on first receive.
            let mut guard = self.recv.lock().await;
            if guard.is_none() {
                let (_send, recv) = self
                    .connection
                    .accept_bi()
                    .await
                    .map_err(|e| QuicError::AcceptBi(e.to_string()))?;
                *guard = Some(recv);
            }

            let recv = guard.as_mut().ok_or(QuicError::RecvStreamMissing)?;
            crate::transport::framing::read_frame(recv)
                .await
                .map_err(|e| QuicError::FramedRecv(e.to_string()))
        }

        pub fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        pub fn local_addr(&self) -> Result<SocketAddr> {
            self.endpoint
                .local_addr()
                .map_err(|e| QuicError::LocalAddr(e.to_string()))
        }
    }

    pub fn make_self_signed_configs(
        server_name: &str,
    ) -> Result<(ServerConfig, ClientConfig, Vec<u8>)> {
        let cert = generate_simple_self_signed(vec![server_name.to_string()])
            .map_err(|e| QuicError::CertGen(e.to_string()))?;
        let cert_der = cert
            .serialize_der()
            .map_err(|e| QuicError::CertSerialize(e.to_string()))?;
        let key_der = cert.serialize_private_key_der();

        let cert_chain = vec![CertificateDer::from(cert_der.clone())];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
        let server_config = ServerConfig::with_single_cert(cert_chain.clone(), key)
            .map_err(|e| QuicError::ServerConfig(e.to_string()))?;

        let mut roots = RootCertStore::empty();
        roots
            .add(cert_chain[0].clone())
            .map_err(|e| QuicError::RootCert(e.to_string()))?;
        let client_config = ClientConfig::with_root_certificates(roots.into())
            .map_err(|e| QuicError::ClientConfig(e.to_string()))?;

        Ok((server_config, client_config, cert_der))
    }

    pub fn make_client_config_from_der(cert_der: &[u8]) -> Result<ClientConfig> {
        let mut roots = RootCertStore::empty();
        let cert = CertificateDer::from(cert_der.to_vec());
        if roots.add(cert).is_err() {
            return Err(QuicError::InvalidCertificateDer);
        }
        let client_config = ClientConfig::with_root_certificates(roots.into())
            .map_err(|e| QuicError::ClientConfig(e.to_string()))?;
        Ok(client_config)
    }
}

#[cfg(not(feature = "quic"))]
mod imp {
    use std::net::SocketAddr;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum QuicError {
        #[error("quic feature disabled; enable with --features quic")]
        FeatureDisabled,
    }

    type Result<T> = std::result::Result<T, QuicError>;

    #[derive(Clone, Debug)]
    pub struct ClientConfig;

    #[derive(Clone, Debug)]
    pub struct ServerConfig;

    #[derive(Clone)]
    pub struct QuinnTransport;

    impl QuinnTransport {
        pub async fn connect(
            _addr: SocketAddr,
            _server_name: &str,
            _client_config: ClientConfig,
        ) -> Result<Self> {
            Err(QuicError::FeatureDisabled)
        }

        pub async fn accept(_bind: SocketAddr, _server_config: ServerConfig) -> Result<Self> {
            Err(QuicError::FeatureDisabled)
        }

        pub async fn send(&self, _data: &[u8]) -> Result<()> {
            Err(QuicError::FeatureDisabled)
        }

        pub async fn recv(&self) -> Result<Vec<u8>> {
            Err(QuicError::FeatureDisabled)
        }

        pub fn peer_addr(&self) -> SocketAddr {
            SocketAddr::from(([0, 0, 0, 0], 0))
        }

        pub fn local_addr(&self) -> Result<SocketAddr> {
            Err(QuicError::FeatureDisabled)
        }
    }

    pub fn make_self_signed_configs(
        _server_name: &str,
    ) -> Result<(ServerConfig, ClientConfig, Vec<u8>)> {
        Err(QuicError::FeatureDisabled)
    }

    pub fn make_client_config_from_der(_cert_der: &[u8]) -> Result<ClientConfig> {
        Err(QuicError::FeatureDisabled)
    }
}

pub use imp::*;
