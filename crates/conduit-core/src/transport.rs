//! QUIC transport: endpoint setup, connection establishment, pairing-code derivation,
//! and the per-session `Hello` exchange (`docs/PROTOCOL.md` §2).
//!
//! TLS setup is deliberately unusual: both sides present self-signed certificates and
//! the rustls verifiers accept *any* well-formed certificate. That is not "no
//! security" — the TLS handshake still yields an encrypted channel bound to exactly
//! those certificates; trust is then decided one layer up by comparing the presented
//! certificate's fingerprint against the TOFU pin store (or running the pairing-code
//! flow for unknown peers). See `identity.rs`.
//!
//! Every endpoint is simultaneously client and server — peers are symmetric.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::DigitallySignedStruct;
use tokio::sync::Mutex;

use crate::identity::{DeviceIdentity, Fingerprint};
use crate::protocol::{Capabilities, DeviceId, Hello};
use crate::wire::{self, ByeReason, ControlMessage, ALPN};
use crate::{Error, Result};

/// Fixed SNI label sent on connect. Never verified — identity is the pinned
/// certificate fingerprint, not a DNS name.
pub const SERVER_NAME: &str = "conduit";

const KEEP_ALIVE_SECS: u64 = 5;

/// A bound QUIC endpoint that can both dial out and accept inbound peers.
pub struct ConduitEndpoint {
    endpoint: quinn::Endpoint,
    identity: Arc<DeviceIdentity>,
}

impl ConduitEndpoint {
    /// Bind on `addr` (port 0 picks a free port). The same socket serves inbound and
    /// outbound connections.
    pub fn bind(identity: Arc<DeviceIdentity>, addr: SocketAddr) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = identity.cert_der();
        let key = identity.key_der();

        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(Arc::new(AcceptAnyCert::new(provider.clone())))
            .with_single_cert(vec![cert.clone()], key.clone_key())?;
        server_tls.alpn_protocols = vec![ALPN.to_vec()];

        let quic_server = QuicServerConfig::try_from(server_tls)
            .map_err(|e| Error::Crypto(format!("QUIC server config: {e}")))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        server_config.transport_config(transport_config());

        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert::new(provider)))
            .with_client_auth_cert(vec![cert], key)?;
        client_tls.alpn_protocols = vec![ALPN.to_vec()];

        let quic_client = QuicClientConfig::try_from(client_tls)
            .map_err(|e| Error::Crypto(format!("QUIC client config: {e}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
        client_config.transport_config(transport_config());

        let mut endpoint = quinn::Endpoint::server(server_config, addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, identity })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Dial a peer and complete the `Hello` exchange. The returned session is
    /// encrypted but not yet *trusted* — the caller must check the pin store and, for
    /// unknown peers, run the pairing-code confirmation before transferring anything.
    pub async fn connect(&self, addr: SocketAddr) -> Result<PeerSession> {
        let conn = self.endpoint.connect(addr, SERVER_NAME)?.await?;
        PeerSession::establish(conn, &self.identity, Side::Initiator).await
    }

    /// Accept the next inbound connection and complete the `Hello` exchange.
    /// Returns `None` once the endpoint is closed. Same trust caveat as [`connect`].
    pub async fn accept(&self) -> Option<Result<PeerSession>> {
        let incoming = self.endpoint.accept().await?;
        Some(async {
            let conn = incoming.await?;
            PeerSession::establish(conn, &self.identity, Side::Responder).await
        }
        .await)
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"endpoint closed");
    }
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    // Keep the connection alive while a human reads the pairing code on both screens.
    t.keep_alive_interval(Some(std::time::Duration::from_secs(KEEP_ALIVE_SECS)));
    // Flow-control windows sized for a multi-Gbps direct link. quinn's defaults
    // (1.25 MB per stream) stall a worker mid-chunk: each data stream must keep at
    // least one whole chunk (4 MiB default) in flight, with headroom, and the
    // connection window must cover all parallel streams at once.
    t.stream_receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024));
    t.receive_window(quinn::VarInt::from_u32(256 * 1024 * 1024));
    t.send_window(256 * 1024 * 1024);
    Arc::new(t)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Dialed the connection; opens the control stream and speaks `Hello` first.
    Initiator,
    /// Accepted the connection; answers the initiator's `Hello`.
    Responder,
}

/// What the `Hello` exchange revealed about the peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub device_id: DeviceId,
    pub name: String,
    pub fingerprint: Fingerprint,
    pub capabilities: Capabilities,
}

/// An established, encrypted session with the `Hello` exchange done. Trust is the
/// caller's next move (pin check or pairing) — see the module docs.
pub struct PeerSession {
    pub(crate) conn: quinn::Connection,
    pub peer: PeerInfo,
    /// Control-stream send half. Shared because progress ticks, resend requests, and
    /// completion notices are written from different tasks during a transfer.
    pub(crate) control_send: Arc<Mutex<quinn::SendStream>>,
    /// Control-stream receive half. Exactly one reader at a time — the transfer
    /// engine takes it out when a transfer starts.
    control_recv: std::sync::Mutex<Option<quinn::RecvStream>>,
}

impl PeerSession {
    async fn establish(
        conn: quinn::Connection,
        identity: &DeviceIdentity,
        side: Side,
    ) -> Result<Self> {
        let fingerprint = peer_fingerprint(&conn)?;

        let ours = Hello::new(
            identity.device_id,
            identity.device_name.clone(),
            Capabilities::RESUME,
        );

        // Initiator opens the control stream and speaks first; the responder's
        // accept_bi only fires once the initiator has written.
        let (mut send, mut recv, theirs) = match side {
            Side::Initiator => {
                let (mut send, mut recv) = conn.open_bi().await?;
                wire::write_frame(&mut send, &ControlMessage::Hello(ours)).await?;
                let theirs = read_hello(&mut recv).await?;
                (send, recv, theirs)
            }
            Side::Responder => {
                let (mut send, mut recv) = conn.accept_bi().await?;
                let theirs = read_hello(&mut recv).await?;
                wire::write_frame(&mut send, &ControlMessage::Hello(ours)).await?;
                (send, recv, theirs)
            }
        };

        if let Err(e) = theirs.check_compatible() {
            let _ = wire::write_frame(
                &mut send,
                &ControlMessage::Bye {
                    reason: ByeReason::VersionMismatch,
                },
            )
            .await;
            let _ = recv.stop(0u32.into());
            conn.close(1u32.into(), b"version mismatch");
            return Err(e);
        }

        Ok(Self {
            conn,
            peer: PeerInfo {
                device_id: theirs.device_id,
                name: theirs.device_name,
                fingerprint,
                capabilities: theirs.capabilities,
            },
            control_send: Arc::new(Mutex::new(send)),
            control_recv: std::sync::Mutex::new(Some(recv)),
        })
    }

    /// Hand the control-stream receive half to the (single) transfer driver.
    pub(crate) fn control_recv_take(&self) -> Result<quinn::RecvStream> {
        self.control_recv
            .lock()
            .expect("control_recv mutex poisoned")
            .take()
            .ok_or_else(|| {
                Error::Protocol("the control stream is already driving a transfer".into())
            })
    }

    /// 6-digit pairing code derived from the TLS exporter, so both ends of *this*
    /// channel — and only this channel — compute the same digits. A MITM would sit on
    /// two different TLS sessions and produce two different codes.
    pub fn pairing_code(&self) -> Result<String> {
        let mut bytes = [0u8; 4];
        self.conn
            .export_keying_material(&mut bytes, b"conduit-pair", b"")
            .map_err(|_| Error::Crypto("TLS exporter unavailable".into()))?;
        Ok(format!("{:06}", u32::from_le_bytes(bytes) % 1_000_000))
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Politely end the session (e.g. the user rejected the pairing code).
    pub async fn bye(self, reason: ByeReason) {
        {
            let mut send = self.control_send.lock().await;
            let _ = wire::write_frame(&mut send, &ControlMessage::Bye { reason }).await;
            let _ = send.finish();
        }
        self.conn.close(0u32.into(), b"bye");
    }
}

async fn read_hello(recv: &mut quinn::RecvStream) -> Result<Hello> {
    match wire::read_frame::<ControlMessage>(recv).await? {
        Some(ControlMessage::Hello(h)) => Ok(h),
        Some(other) => Err(Error::Protocol(format!(
            "expected Hello, got {other:?}"
        ))),
        None => Err(Error::Connection(
            "peer closed the control stream before Hello".into(),
        )),
    }
}

/// Fingerprint of the certificate the peer presented in the TLS handshake.
fn peer_fingerprint(conn: &quinn::Connection) -> Result<Fingerprint> {
    let identity = conn
        .peer_identity()
        .ok_or_else(|| Error::Crypto("peer presented no certificate".into()))?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| Error::Crypto("unexpected peer identity type".into()))?;
    let cert = certs
        .first()
        .ok_or_else(|| Error::Crypto("peer certificate chain is empty".into()))?;
    Ok(Fingerprint::of_cert_der(cert.as_ref()))
}

/// Accepts any syntactically valid certificate on both the client and server side of
/// the handshake, while still enforcing that the peer *proves possession* of its key
/// (signature checks stay real). Trust is decided above TLS via fingerprint pinning.
#[derive(Debug)]
struct AcceptAnyCert {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyCert {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for AcceptAnyCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
