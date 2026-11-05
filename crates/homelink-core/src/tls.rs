//! QUIC/TLS 1.3 setup with mutual authentication by pinned device IDs.
//!
//! - The client only accepts a host whose certificate hash matches the invite.
//! - The host accepts any client certificate during the handshake, then checks
//!   the client's device ID against its allowlist before reading any data.
//!
//! The handshake signature proves the peer holds the key in its certificate,
//! so the certificate hash is a sound identity.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use homelink_proto::{DeviceId, ALPN};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::identity::{device_id, Identity};

pub const KEEP_ALIVE: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STREAMS_PER_CONNECTION: u32 = 512;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport(keep_alive: bool) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("valid idle timeout")));
    t.max_concurrent_bidi_streams(MAX_STREAMS_PER_CONNECTION.into());
    t.max_concurrent_uni_streams(0u32.into());
    if keep_alive {
        t.keep_alive_interval(Some(KEEP_ALIVE));
    }
    Arc::new(t)
}

pub fn server_config(identity: &Identity) -> Result<quinn::ServerConfig> {
    let p = provider();
    let mut cfg = rustls::ServerConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyClientCert { provider: p }))
        .with_single_cert(vec![identity.cert.clone()], identity.key())?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(cfg)?));
    server.transport_config(transport(false));
    Ok(server)
}

pub fn client_config(identity: &Identity, host_id: DeviceId) -> Result<quinn::ClientConfig> {
    let p = provider();
    let mut cfg = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedHost { provider: p, host_id }))
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key())?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(cfg)?));
    client.transport_config(transport(true));
    Ok(client)
}

/// Device ID of the remote side of an established connection.
pub fn peer_id(conn: &quinn::Connection) -> Result<DeviceId> {
    let any = conn.peer_identity().ok_or_else(|| anyhow!("peer sent no certificate"))?;
    let certs = any
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    let cert = certs.first().ok_or_else(|| anyhow!("peer sent no certificate"))?;
    Ok(device_id(cert))
}

#[derive(Debug)]
struct PinnedHost {
    provider: Arc<CryptoProvider>,
    host_id: DeviceId,
}

impl ServerCertVerifier for PinnedHost {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if crate::ct_eq(&device_id(end_entity), &self.host_id) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct AnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
