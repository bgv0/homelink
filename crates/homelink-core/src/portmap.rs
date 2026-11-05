//! Automatic port forwarding (UPnP-IGD, then NAT-PMP), kept alive in the background.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::natpmp;

const LEASE: Duration = Duration::from_secs(3600);
const RETRY: Duration = Duration::from_secs(300);
const DESCRIPTION: &str = "homelink";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapState {
    Trying,
    Mapped { external_ip: Option<IpAddr> },
    /// The router didn't offer UPnP/NAT-PMP or refused; forward the port by hand.
    Unavailable(String),
}

/// This machine's LAN address on the route to `target`. Sends no packets.
pub fn local_ip_towards(target: SocketAddr) -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(target).ok()?;
    Some(s.local_addr().ok()?.ip())
}

/// This machine's LAN address on the default route.
pub fn lan_ip() -> Option<IpAddr> {
    local_ip_towards(SocketAddr::from(([1, 1, 1, 1], 53)))
}

pub async fn find_gateway() -> Result<Gateway<Tokio>, String> {
    let opts = SearchOptions { timeout: Some(Duration::from_secs(3)), ..Default::default() };
    search_gateway(opts).await.map_err(|e| format!("no UPnP router found ({e})"))
}

async fn map_once(gw: &Gateway<Tokio>, port: u16) -> Result<Option<IpAddr>, String> {
    let local_ip = local_ip_towards(gw.addr).ok_or("can't find this computer's LAN address")?;
    let local = SocketAddr::new(local_ip, port);
    let first = gw
        .add_port(PortMappingProtocol::UDP, port, local, LEASE.as_secs() as u32, DESCRIPTION)
        .await;
    if first.is_err() {
        // Some routers only accept permanent leases.
        gw.add_port(PortMappingProtocol::UDP, port, local, 0, DESCRIPTION)
            .await
            .map_err(|e| format!("router refused the port mapping ({e})"))?;
    }
    Ok(gw.get_external_ip().await.ok())
}

enum Mapping {
    Upnp(Gateway<Tokio>),
    NatPmp(Ipv4Addr),
}

impl Mapping {
    async fn remove(&self, port: u16) {
        match self {
            Mapping::Upnp(gw) => {
                let _ = gw.remove_port(PortMappingProtocol::UDP, port).await;
            }
            Mapping::NatPmp(gw) => {
                let _ = natpmp::map_udp(*gw, port, 0).await;
            }
        }
    }
}

/// Try UPnP, then NAT-PMP. Returns the mapping, the router's public IP if
/// known, and when to renew.
async fn try_map(port: u16) -> Result<(Mapping, Option<IpAddr>, Duration), String> {
    let upnp_err = match find_gateway().await {
        Ok(gw) => match map_once(&gw, port).await {
            Ok(ip) => return Ok((Mapping::Upnp(gw), ip, LEASE / 2)),
            Err(e) => e,
        },
        Err(e) => e,
    };
    let Some(gw) = natpmp::default_gateway() else { return Err(upnp_err) };
    match natpmp::map_udp(gw, port, LEASE.as_secs() as u32).await {
        Ok(m) if m.external_port == port => {
            let ip = natpmp::external_ip(gw).await.map(IpAddr::V4);
            let renew = Duration::from_secs((u64::from(m.lifetime) / 2).max(60));
            Ok((Mapping::NatPmp(gw), ip, renew))
        }
        Ok(m) => {
            natpmp::map_udp(gw, port, 0).await.ok();
            Err(format!(
                "router would only forward port {} instead of {port}",
                m.external_port
            ))
        }
        Err(e) => {
            debug!("NAT-PMP: {e}");
            Err(format!("{upnp_err} (NAT-PMP: {e})"))
        }
    }
}

pub struct PortMapper {
    pub state: watch::Receiver<MapState>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl PortMapper {
    /// Start trying to forward UDP `port`, renewing until stopped.
    pub fn start(port: u16) -> Self {
        let (tx, state) = watch::channel(MapState::Trying);
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut mapped: Option<Mapping> = None;
            loop {
                let wait = match try_map(port).await {
                    Ok((m, ip, renew)) => {
                        info!("forwarded UDP {port} ({})", match m { Mapping::Upnp(_) => "UPnP", Mapping::NatPmp(_) => "NAT-PMP" });
                        mapped = Some(m);
                        let _ = tx.send(MapState::Mapped { external_ip: ip });
                        renew
                    }
                    Err(e) => {
                        debug!("port mapping: {e}");
                        let _ = tx.send(MapState::Unavailable(e));
                        RETRY
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = &mut stop_rx => break,
                }
            }
            if let Some(m) = mapped {
                m.remove(port).await;
            }
        });
        PortMapper { state, stop: Some(stop_tx), task }
    }

    /// Remove the mapping and stop renewing.
    pub async fn stop(mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), &mut self.task).await;
    }
}
