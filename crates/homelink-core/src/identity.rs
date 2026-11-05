//! Each device has a self-signed certificate. Its SHA-256 is the device ID.

use anyhow::{Context, Result};
use homelink_proto::{DeviceId, SERVER_NAME};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct Identity {
    pub cert: CertificateDer<'static>,
    key_der: Vec<u8>,
    pub id: DeviceId,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let ck = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
            .context("generating device certificate")?;
        let cert = ck.cert.der().clone();
        let key_der = ck.key_pair.serialize_der();
        Ok(Self::from_parts(cert.to_vec(), key_der))
    }

    pub fn from_parts(cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        let id = device_id(&cert_der);
        Identity { cert: CertificateDer::from(cert_der), key_der, id }
    }

    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    pub(crate) fn key_der(&self) -> &[u8] {
        &self.key_der
    }
}

pub fn device_id(cert_der: &[u8]) -> DeviceId {
    let d = ring::digest::digest(&ring::digest::SHA256, cert_der);
    d.as_ref().try_into().expect("sha256 is 32 bytes")
}
