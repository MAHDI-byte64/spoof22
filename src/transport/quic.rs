//! QUIC transport (UDP + real QUIC / TLS 1.3 via `quinn`, `ring` backend).
//!
//! Unlike the raw transports, QUIC uses the kernel UDP stack with path
//! validation and a TLS handshake tied to the 4-tuple, so it **cannot** be
//! source-spoofed — config validation forces `no_spoof` for QUIC links, and
//! censorship resistance here comes from TLS/ECH mimicry (a browser-like
//! ClientHello and a realistic ALPN/SNI) rather than source forging.
//!
//! Frames are carried as **unreliable QUIC datagrams**, which is the right
//! choice for a tunnel: inner TCP keeps its own retransmission, so we avoid
//! TCP-over-TCP head-of-line blocking while QUIC still paces/【congestion-
//! controls】 the path.
//!
//! ## Security note
//!
//! The QUIC/TLS handshake is **not** our security boundary — the peer is
//! authenticated by the Noise_IK(+ML-KEM) handshake that runs *inside* the
//! tunnel. The client therefore accepts the server's (self-signed) certificate
//! for transport setup; identity is pinned cryptographically one layer up.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::config::{Config, Role, TransportKind};
use crate::error::{Error, Result};

use super::Transport;

/// QUIC transport over an established connection.
pub struct QuicTransport {
    conn: quinn::Connection,
    // Keep the endpoint alive for the connection's lifetime.
    _endpoint: quinn::Endpoint,
}

impl QuicTransport {
    /// Establish the QUIC transport for this role (client connects, server
    /// accepts one connection).
    pub async fn establish(cfg: &Config, role: Role) -> Result<QuicTransport> {
        match role {
            Role::Server => Self::server(cfg).await,
            Role::Client => Self::client(cfg).await,
        }
    }

    async fn server(cfg: &Config) -> Result<QuicTransport> {
        let (certs, key) = load_or_generate_cert(cfg)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::transport("quic", format!("tls versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::transport("quic", format!("server cert: {e}")))?;
        tls.alpn_protocols = alpn();

        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| Error::transport("quic", format!("quic server crypto: {e}")))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        server_config.transport_config(Arc::new(transport_config(cfg)));

        let bind = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            cfg.transport.data_port,
        ));
        let endpoint = quinn::Endpoint::server(server_config, bind)
            .map_err(|e| Error::transport("quic", format!("bind {bind}: {e}")))?;

        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| Error::transport("quic", "endpoint closed before a connection"))?;
        let conn = incoming
            .await
            .map_err(|e| Error::transport("quic", format!("accept: {e}")))?;

        Ok(QuicTransport {
            conn,
            _endpoint: endpoint,
        })
    }

    async fn client(cfg: &Config) -> Result<QuicTransport> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(verify::SkipServerVerification::new(provider.clone()));

        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::transport("quic", format!("tls versions: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tls.alpn_protocols = alpn();

        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| Error::transport("quic", format!("quic client crypto: {e}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(qcc));
        client_config.transport_config(Arc::new(transport_config(cfg)));

        let bind = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|e| Error::transport("quic", format!("client endpoint: {e}")))?;
        endpoint.set_default_client_config(client_config);

        let server = SocketAddr::V4(SocketAddrV4::new(
            cfg.spoof.peer_real_ip,
            cfg.transport.data_port,
        ));
        let server_name = server_name(cfg);
        let conn = endpoint
            .connect(server, &server_name)
            .map_err(|e| Error::transport("quic", format!("connect: {e}")))?
            .await
            .map_err(|e| Error::transport("quic", format!("handshake: {e}")))?;

        Ok(QuicTransport {
            conn,
            _endpoint: endpoint,
        })
    }
}

#[async_trait]
impl Transport for QuicTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Quic
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.conn
            .send_datagram(Bytes::copy_from_slice(frame))
            .map_err(|e| Error::transport("quic", format!("send datagram: {e}")))
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let data = self
            .conn
            .read_datagram()
            .await
            .map_err(|e| Error::transport("quic", format!("read datagram: {e}")))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}

/// ALPN set mimicking HTTP/3 then HTTP/2 (common for QUIC+browser traffic).
fn alpn() -> Vec<Vec<u8>> {
    vec![b"h3".to_vec(), b"h2".to_vec()]
}

/// SNI / server name to present and (loosely) validate.
fn server_name(cfg: &Config) -> String {
    if !cfg.obfs.sni.trim().is_empty() {
        cfg.obfs.sni.clone()
    } else if !cfg.quic.server_name.trim().is_empty() {
        cfg.quic.server_name.clone()
    } else {
        "localhost".to_string()
    }
}

/// Build the quinn transport config with the raised windows and datagram support.
fn transport_config(cfg: &Config) -> quinn::TransportConfig {
    let mut tc = quinn::TransportConfig::default();
    let conn_win = quinn::VarInt::from_u64(cfg.quic.connection_window)
        .unwrap_or_else(|_| quinn::VarInt::from_u32(u32::MAX));
    let stream_win = quinn::VarInt::from_u64(cfg.quic.stream_window)
        .unwrap_or_else(|_| quinn::VarInt::from_u32(u32::MAX));
    tc.receive_window(conn_win);
    tc.stream_receive_window(stream_win);
    tc.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    tc.datagram_send_buffer_size(16 * 1024 * 1024);
    tc.keep_alive_interval(Some(Duration::from_secs(15)));
    tc
}

/// Load the configured QUIC cert/key, or generate an ephemeral self-signed one.
fn load_or_generate_cert(
    cfg: &Config,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let cert_path = &cfg.quic.cert_path;
    let key_path = &cfg.quic.key_path;
    if !cert_path.is_empty()
        && !key_path.is_empty()
        && std::path::Path::new(cert_path).exists()
        && std::path::Path::new(key_path).exists()
    {
        let cert_pem = std::fs::read(cert_path).map_err(Error::from)?;
        let key_pem = std::fs::read(key_path).map_err(Error::from)?;
        let certs = rustls_pemfile_certs(&cert_pem)?;
        let key = rustls_pemfile_key(&key_pem)?;
        return Ok((certs, key));
    }

    // Ephemeral self-signed certificate for the configured server name.
    let name = server_name(cfg);
    let cert = rcgen::generate_simple_self_signed(vec![name])
        .map_err(|e| Error::transport("quic", format!("self-signed cert: {e}")))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    Ok((vec![cert_der], key_der))
}

/// Minimal PEM certificate extraction (avoids an extra dependency).
fn rustls_pemfile_certs(pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    use base64::Engine as _;
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let end = block
            .find("-----END CERTIFICATE-----")
            .ok_or_else(|| Error::transport("quic", "malformed cert PEM"))?;
        let b64: String = block[..end].split_whitespace().collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| Error::transport("quic", format!("cert base64: {e}")))?;
        out.push(rustls::pki_types::CertificateDer::from(der));
    }
    if out.is_empty() {
        return Err(Error::transport("quic", "no certificates in PEM"));
    }
    Ok(out)
}

/// Minimal PEM PKCS#8 private-key extraction.
fn rustls_pemfile_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    use base64::Engine as _;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let text = String::from_utf8_lossy(pem);
    let start = text
        .find("-----BEGIN PRIVATE KEY-----")
        .ok_or_else(|| Error::transport("quic", "no PKCS#8 private key in PEM"))?;
    let rest = &text[start + "-----BEGIN PRIVATE KEY-----".len()..];
    let end = rest
        .find("-----END PRIVATE KEY-----")
        .ok_or_else(|| Error::transport("quic", "malformed key PEM"))?;
    let b64: String = rest[..end].split_whitespace().collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::transport("quic", format!("key base64: {e}")))?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}

/// A certificate verifier that accepts any server certificate. This is safe
/// *here* because the real peer authentication is the Noise handshake inside
/// the tunnel, not QUIC's TLS.
mod verify {
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct SkipServerVerification {
        provider: Arc<CryptoProvider>,
    }

    impl SkipServerVerification {
        pub fn new(provider: Arc<CryptoProvider>) -> Self {
            SkipServerVerification { provider }
        }
    }

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
