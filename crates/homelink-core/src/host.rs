//! Host role: accept QUIC connections from paired devices and open outbound
//! TCP connections on their behalf. Needs no admin rights.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use homelink_proto::{close, short_id, DeviceId, Request, Status, Target};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::netfilter::is_local;
use crate::splice::{splice, Traffic};
use crate::store::{HostSettings, InviteLookup, Store};
use crate::tls;

/// Handshakes (and pairing attempts) from not-yet-known peers handled at once.
const MAX_PENDING_HANDSHAKES: usize = 32;
const MAX_CONNECTIONS_PER_DEVICE: usize = 8;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub struct PairRequest {
    pub id: DeviceId,
    pub name: String,
}

/// Asked whether a new device may pair. Resolve to `true` to allow.
pub type Approver =
    Arc<dyn Fn(PairRequest) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

pub fn auto_approve() -> Approver {
    Arc::new(|_| Box::pin(async { true }))
}

#[derive(Debug, Clone)]
pub enum HostEvent {
    Connected { id: DeviceId, name: String },
    Disconnected { id: DeviceId, name: String },
    Paired { id: DeviceId, name: String },
    PairDeclined { name: String },
    Revoked { id: DeviceId, name: String },
}

#[derive(Debug, Clone)]
pub struct HostOptions {
    pub bind: SocketAddr,
    pub allow_lan: bool,
    pub require_approval: bool,
    /// Extra addresses devices may not reach, e.g. the host's own public IP.
    pub blocked: Vec<IpAddr>,
    /// How often to re-read the device list to drop revoked devices.
    pub revoke_poll: Duration,
}

impl HostOptions {
    pub fn from_settings(s: &HostSettings) -> Self {
        HostOptions {
            bind: SocketAddr::from(([0, 0, 0, 0], s.port)),
            allow_lan: s.allow_lan,
            require_approval: s.require_approval,
            blocked: Vec::new(),
            revoke_poll: Duration::from_secs(2),
        }
    }
}

struct LiveConn {
    id: DeviceId,
    name: String,
    conn: quinn::Connection,
}

struct Shared {
    store: Store,
    opts: HostOptions,
    approver: Approver,
    events: broadcast::Sender<HostEvent>,
    traffic: Arc<Traffic>,
    live: Mutex<HashMap<usize, LiveConn>>,
    handshakes: Arc<Semaphore>,
}

impl Shared {
    fn emit(&self, e: HostEvent) {
        let _ = self.events.send(e);
    }
}

pub struct HostHandle {
    pub local_addr: SocketAddr,
    pub traffic: Arc<Traffic>,
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl HostHandle {
    pub fn subscribe(&self) -> broadcast::Receiver<HostEvent> {
        self.shared.events.subscribe()
    }

    /// Devices with at least one live connection: (id, name).
    pub fn online(&self) -> Vec<(DeviceId, String)> {
        let live = self.shared.live.lock().unwrap();
        let mut v: Vec<_> = live.values().map(|l| (l.id, l.name.clone())).collect();
        v.sort();
        v.dedup();
        v
    }

    pub async fn shutdown(self) {
        self.endpoint.close(close::SHUTDOWN.into(), b"host stopped");
        for t in &self.tasks {
            t.abort();
        }
        let _ = timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
    }
}

pub async fn start(store: Store, opts: HostOptions, approver: Approver) -> Result<HostHandle> {
    let identity = store.identity()?;
    let endpoint = quinn::Endpoint::server(tls::server_config(&identity)?, opts.bind)
        .with_context(|| format!("could not open UDP port {}, is something else using it?", opts.bind.port()))?;
    let local_addr = endpoint.local_addr()?;
    let (events, _) = broadcast::channel(64);
    let traffic = Arc::new(Traffic::default());
    let shared = Arc::new(Shared {
        store,
        opts,
        approver,
        events,
        traffic: traffic.clone(),
        live: Mutex::new(HashMap::new()),
        handshakes: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
    });
    info!("host listening on {local_addr}, device {}", short_id(&identity.id));

    let accept = tokio::spawn(accept_loop(endpoint.clone(), shared.clone()));
    let watcher = tokio::spawn(revoke_watcher(shared.clone()));
    Ok(HostHandle { local_addr, traffic, endpoint, shared, tasks: vec![accept, watcher] })
}

async fn accept_loop(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = shared.handshakes.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, shared, permit).await {
                debug!("connection ended: {e:#}");
            }
        });
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    shared: Arc<Shared>,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let conn = timeout(HANDSHAKE_TIMEOUT, incoming.accept()?).await??;
    let id = tls::peer_id(&conn)?;
    let known = shared.store.devices()?.into_iter().find(|d| d.device_id() == Some(id));
    match known {
        Some(device) => {
            drop(permit);
            let count = shared.live.lock().unwrap().values().filter(|l| l.id == id).count();
            if count >= MAX_CONNECTIONS_PER_DEVICE {
                conn.close(close::TOO_MANY.into(), b"too many connections");
                return Ok(());
            }
            serve_device(conn, id, device.name, shared).await;
        }
        None => {
            pair_unknown(conn, id, &shared).await?;
            drop(permit);
        }
    }
    Ok(())
}

async fn pair_unknown(conn: quinn::Connection, id: DeviceId, shared: &Shared) -> Result<()> {
    if shared.store.invites()?.is_empty() {
        conn.close(close::NOT_PAIRED.into(), b"not paired");
        return Ok(());
    }
    let (mut send, mut recv) = timeout(REQUEST_TIMEOUT, conn.accept_bi()).await??;
    let req = timeout(REQUEST_TIMEOUT, Request::read(&mut recv)).await??;
    let Request::Pair { secret, name } = req else {
        conn.close(close::NOT_PAIRED.into(), b"not paired");
        return Ok(());
    };
    let status = match shared.store.take_invite(&secret) {
        Ok(_) => {
            let approved = !shared.opts.require_approval
                || timeout(APPROVAL_TIMEOUT, (shared.approver)(PairRequest { id, name: name.clone() }))
                    .await
                    .unwrap_or(false);
            if approved {
                shared.store.add_device(&id, &name)?;
                info!("paired {name} ({})", short_id(&id));
                shared.emit(HostEvent::Paired { id, name });
                Status::Ok
            } else {
                shared.emit(HostEvent::PairDeclined { name });
                Status::Rejected
            }
        }
        Err(InviteLookup::Expired) => Status::Expired,
        Err(InviteLookup::Unknown) => {
            warn!("pairing attempt with an unknown invite code");
            Status::Denied
        }
    };
    send.write_all(&[status as u8]).await?;
    let _ = send.finish();
    // Give the client time to read the answer; it closes the connection itself.
    let _ = timeout(Duration::from_secs(5), conn.closed()).await;
    conn.close(close::PAIR_DONE.into(), b"pairing done");
    Ok(())
}

async fn serve_device(conn: quinn::Connection, id: DeviceId, name: String, shared: Arc<Shared>) {
    let key = conn.stable_id();
    shared
        .live
        .lock()
        .unwrap()
        .insert(key, LiveConn { id, name: name.clone(), conn: conn.clone() });
    debug!("{name} connected from {}", conn.remote_address());
    shared.emit(HostEvent::Connected { id, name: name.clone() });

    while let Ok((send, recv)) = conn.accept_bi().await {
        let shared = shared.clone();
        tokio::spawn(handle_stream(send, recv, shared));
    }

    shared.live.lock().unwrap().remove(&key);
    shared.emit(HostEvent::Disconnected { id, name });
}

async fn handle_stream(mut send: quinn::SendStream, mut recv: quinn::RecvStream, shared: Arc<Shared>) {
    let req = match timeout(REQUEST_TIMEOUT, Request::read(&mut recv)).await {
        Ok(Ok(r)) => r,
        _ => {
            let _ = send.write_all(&[Status::BadRequest as u8]).await;
            let _ = send.finish();
            return;
        }
    };
    match req {
        // Already paired: re-pairing is a no-op.
        Request::Pair { .. } => {
            let _ = send.write_all(&[Status::Ok as u8]).await;
            let _ = send.finish();
        }
        Request::Connect(target) => match open_target(&target, &shared.opts).await {
            Ok(tcp) => {
                if send.write_all(&[Status::Ok as u8]).await.is_ok() {
                    splice(send, recv, tcp, &shared.traffic, false).await;
                }
            }
            Err(status) => {
                debug!("connect to {target} failed: {}", status.describe());
                let _ = send.write_all(&[status as u8]).await;
                let _ = send.finish();
            }
        },
    }
}

/// Resolve and connect, refusing local-network destinations unless allowed.
pub(crate) async fn open_target(target: &Target, opts: &HostOptions) -> Result<TcpStream, Status> {
    let addrs: Vec<SocketAddr> = match target {
        Target::Addr(a) => vec![*a],
        Target::Domain(d, port) => match timeout(DIAL_TIMEOUT, tokio::net::lookup_host((d.as_str(), *port))).await {
            Ok(Ok(it)) => it.collect(),
            _ => Vec::new(),
        },
    };
    if addrs.is_empty() {
        return Err(Status::Unreachable);
    }
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| opts.allow_lan || !(is_local(a.ip()) || opts.blocked.contains(&a.ip())))
        .collect();
    if allowed.is_empty() {
        return Err(Status::Blocked);
    }
    for a in allowed {
        if let Ok(Ok(s)) = timeout(DIAL_TIMEOUT, TcpStream::connect(a)).await {
            return Ok(s);
        }
    }
    Err(Status::Unreachable)
}

async fn revoke_watcher(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(shared.opts.revoke_poll);
    loop {
        tick.tick().await;
        let Ok(devices) = shared.store.devices() else { continue };
        let allowed: Vec<DeviceId> = devices.iter().filter_map(|d| d.device_id()).collect();
        let mut live = shared.live.lock().unwrap();
        live.retain(|_, l| {
            if allowed.contains(&l.id) {
                return true;
            }
            l.conn.close(close::REVOKED.into(), b"device removed");
            shared.emit(HostEvent::Revoked { id: l.id, name: l.name.clone() });
            false
        });
    }
}
