//! "Can people reach me?" checks for the host: CGNAT and double-NAT detection.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::{portmap, stun};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// Router has the public IP: port forwarding should work.
    Forwardable,
    /// The ISP shares one public IP between customers.
    Cgnat,
    /// There's a second router in front of this one.
    DoubleNat,
    /// Couldn't ask the router (no UPnP); forwarding may still work.
    Unknown,
    NoInternet,
}

impl Verdict {
    pub fn describe(self) -> &'static str {
        match self {
            Verdict::Forwardable => "Your router has a public IP address, so port forwarding should work.",
            Verdict::Cgnat => "Your internet provider uses CGNAT (a shared address), so port forwarding can't work. Ask your provider for a public IPv4 address.",
            Verdict::DoubleNat => "There are two routers between this computer and the internet. Forward the port on both, or put the first one in bridge mode.",
            Verdict::Unknown => "Couldn't check the router automatically (UPnP is off). Forward the port by hand and test from another network.",
            Verdict::NoInternet => "Couldn't reach the internet to check your public address.",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub lan_ip: Option<IpAddr>,
    pub public_ip: Option<IpAddr>,
    pub router_wan_ip: Option<IpAddr>,
    pub upnp: bool,
    pub verdict: Verdict,
}

pub fn judge(public_ip: Option<IpAddr>, router_wan_ip: Option<IpAddr>) -> Verdict {
    let Some(public) = public_ip else { return Verdict::NoInternet };
    match router_wan_ip {
        None => Verdict::Unknown,
        Some(IpAddr::V4(w)) if w.octets()[0] == 100 && (w.octets()[1] & 0xc0) == 64 => Verdict::Cgnat,
        Some(IpAddr::V4(w)) if w.is_private() => Verdict::DoubleNat,
        Some(w) if w != public => Verdict::Cgnat,
        Some(_) => Verdict::Forwardable,
    }
}

pub async fn check() -> Report {
    let lan_ip = portmap::lan_ip();
    let (public_ip, gw) = tokio::join!(stun::public_ip(), portmap::find_gateway());
    let (upnp, router_wan_ip) = match gw {
        Ok(gw) => (true, gw.get_external_ip().await.ok()),
        Err(_) => (false, None),
    };
    Report { lan_ip, public_ip, router_wan_ip, upnp, verdict: judge(public_ip, router_wan_ip) }
}

/// Re-checks the public IP in the background. Stops when dropped.
pub struct PublicIpWatch {
    pub ip: watch::Receiver<Option<IpAddr>>,
    task: JoinHandle<()>,
}

impl PublicIpWatch {
    /// `initial` is the address already known (if any); checks every `every`.
    pub fn start(initial: Option<IpAddr>, every: Duration) -> Self {
        let (tx, ip) = watch::channel(initial);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                // Keep the last known address if the check fails (e.g. offline).
                if let Some(now) = stun::public_ip().await {
                    tx.send_if_modified(|cur| {
                        let changed = *cur != Some(now);
                        *cur = Some(now);
                        changed
                    });
                }
            }
        });
        PublicIpWatch { ip, task }
    }

    pub fn current(&self) -> Option<IpAddr> {
        *self.ip.borrow()
    }
}

impl Drop for PublicIpWatch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        let ip = |s: &str| Some(s.parse().unwrap());
        assert_eq!(judge(None, None), Verdict::NoInternet);
        assert_eq!(judge(ip("203.0.113.5"), None), Verdict::Unknown);
        assert_eq!(judge(ip("203.0.113.5"), ip("203.0.113.5")), Verdict::Forwardable);
        assert_eq!(judge(ip("203.0.113.5"), ip("100.96.1.2")), Verdict::Cgnat);
        assert_eq!(judge(ip("203.0.113.5"), ip("192.168.1.1")), Verdict::DoubleNat);
        assert_eq!(judge(ip("203.0.113.5"), ip("198.51.100.9")), Verdict::Cgnat);
    }
}
