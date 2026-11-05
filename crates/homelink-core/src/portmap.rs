//! Automatic port forwarding via UPnP-IGD, kept alive in the background.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{PortMappingProtocol, SearchOptions};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info};

const LEASE: Duration = Duration::from_secs(3600);
const RETRY: Duration = Duration::from_secs(300);
const DESCRIPTION: &str = "homelink";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapState {
    Trying,
    Mapped { external_ip: Option<IpAddr> },
    /// The router didn't offer UPnP or refused; forward the port by hand.
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
            let mut mapped_on: Option<Gateway<Tokio>> = None;
            loop {
                let result = match find_gateway().await {
                    Ok(gw) => match map_once(&gw, port).await {
                        Ok(ip) => {
                            mapped_on = Some(gw);
                            Ok(ip)
                        }
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                };
                let wait = match result {
                    Ok(ip) => {
                        info!("UPnP: forwarded UDP {port}");
                        let _ = tx.send(MapState::Mapped { external_ip: ip });
                        LEASE / 2
                    }
                    Err(e) => {
                        debug!("UPnP: {e}");
                        let _ = tx.send(MapState::Unavailable(e));
                        RETRY
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = &mut stop_rx => break,
                }
            }
            if let Some(gw) = mapped_on {
                let _ = gw.remove_port(PortMappingProtocol::UDP, port).await;
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
