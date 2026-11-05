//! homelink engine: device identity, storage, host proxy, client and SOCKS5,
//! port mapping and reachability checks. Shared by the CLI and the desktop app.
//!
//! The client connects directly to the host's forwarded UDP port over QUIC
//! (TLS 1.3, both sides pinned by device key). There are no relays.

pub mod client;
pub mod host;
pub mod identity;
pub mod natpmp;
pub mod netfilter;
pub mod portmap;
pub mod reach;
pub mod socks;
mod splice;
pub mod store;
pub mod stun;
pub mod sysproxy;
pub mod tls;

pub use homelink_proto as proto;
pub use splice::Traffic;

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Cryptographically secure random bytes.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system random number generator failed");
    b
}

/// Constant-time equality for secrets.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
