//! Host role: accept connections from paired devices and open outbound TCP
//! connections on their behalf. Needs no admin rights.
//!
//! Two transports on the same port number:
//! - QUIC over UDP (preferred): one connection per device, one stream per
//!   proxied TCP connection.
//! - TLS over TCP (fallback for networks that block UDP): one TLS connection
//!   per proxied TCP connection. Same certificates, pairing and allowlist.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use std::collections::HashSet;

use homelink_proto::{close, encode_udp_frame, read_udp_frame, short_id, DeviceId, Request, Status, Target};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::netfilter::is_local;
use crate::splice::{splice, Traffic};
use crate::store::{HostSettings, InviteLookup, Store};
use crate::tls;

/// Handshakes (and pairing attempts) from not-yet-known peers handled at once.
const MAX_PENDING_HANDSHAKES: usize = 32;
const MAX_CONNECTIONS_PER_DEVICE: usize = 8;
/// Authenticated TLS-over-TCP connections open at once (one per proxied connection).
const MAX_TCP_CONNECTIONS: usize = 1024;
/// TCP connections still in the TLS handshake. Kept small and separate so
/// strangers can't use up the slots paired devices need.
const MAX_TCP_HANDSHAKES: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// A UDP relay with no traffic either way for this long is closed.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// Remote peers one UDP relay remembers (replies from others are dropped).
const UDP_MAX_PEERS: usize = 4096;

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

struct LiveTcp {
    id: DeviceId,
    name: String,
    stop: Arc<Notify>,
}

struct Shared {
    store: Store,
    opts: HostOptions,
    approver: Approver,
    events: broadcast::Sender<HostEvent>,
    traffic: Arc<Traffic>,
    live: Mutex<HashMap<usize, LiveConn>>,
    live_tcp: Mutex<HashMap<u64, LiveTcp>>,
    next_tcp: AtomicU64,
    handshakes: Arc<Semaphore>,
    tcp_handshakes: Arc<Semaphore>,
    tcp_slots: Arc<Semaphore>,
}

impl Shared {
    fn emit(&self, e: HostEvent) {
        let _ = self.events.send(e);
    }

    fn known_device(&self, id: &DeviceId) -> Result<Option<String>> {
        Ok(self
            .store
            .devices()?
            .into_iter()
            .find(|d| d.device_id().as_ref() == Some(id))
            .map(|d| d.name))
    }
}

pub struct HostHandle {
    pub local_addr: SocketAddr,
    /// Whether the TCP fallback listener is running (false if the TCP port was taken).
    pub tcp_enabled: bool,
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
        let mut v: Vec<_> = {
            let live = self.shared.live.lock().unwrap();
            live.values().map(|l| (l.id, l.name.clone())).collect()
        };
        v.extend(self.shared.live_tcp.lock().unwrap().values().map(|l| (l.id, l.name.clone())));
        v.sort();
        v.dedup();
        v
    }

    pub async fn shutdown(self) {
        self.endpoint.close(close::SHUTDOWN.into(), b"host stopped");
        for t in &self.tasks {
            t.abort();
        }
        for l in self.shared.live_tcp.lock().unwrap().values() {
            l.stop.notify_one();
        }
        let _ = timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
    }
}

pub async fn start(store: Store, opts: HostOptions, approver: Approver) -> Result<HostHandle> {
    let identity = store.identity()?;
    let endpoint = quinn::Endpoint::server(tls::server_config(&identity)?, opts.bind).with_context(|| {
        format!("could not open UDP port {}, is something else using it?", opts.bind.port())
    })?;
    let local_addr = endpoint.local_addr()?;
    // TCP fallback on the same port number. Not fatal if it's taken.
    let tcp = match TcpListener::bind(local_addr).await {
        Ok(l) => Some(l),
        Err(e) => {
            warn!("TCP fallback disabled: couldn't open TCP port {}: {e}", local_addr.port());
            None
        }
    };
    let acceptor = TlsAcceptor::from(Arc::new(tls::server_tls(&identity)?));

    let (events, _) = broadcast::channel(64);
    let traffic = Arc::new(Traffic::default());
    let shared = Arc::new(Shared {
        store,
        opts,
        approver,
        events,
        traffic: traffic.clone(),
        live: Mutex::new(HashMap::new()),
        live_tcp: Mutex::new(HashMap::new()),
        next_tcp: AtomicU64::new(1),
        handshakes: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
        tcp_handshakes: Arc::new(Semaphore::new(MAX_TCP_HANDSHAKES)),
        tcp_slots: Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS)),
    });
    info!("host listening on {local_addr}, device {}", short_id(&identity.id));

    let mut tasks = vec![
        tokio::spawn(accept_loop(endpoint.clone(), shared.clone())),
        tokio::spawn(revoke_watcher(shared.clone())),
    ];
    let tcp_enabled = tcp.is_some();
    if let Some(listener) = tcp {
        tasks.push(tokio::spawn(tcp_accept_loop(listener, acceptor, shared.clone())));
    }
    Ok(HostHandle { local_addr, tcp_enabled, traffic, endpoint, shared, tasks })
}

// ---------------------------------------------------------------------------
// Pairing (shared by both transports)
// ---------------------------------------------------------------------------

async fn decide_pairing(id: DeviceId, secret: &[u8; 32], name: String, shared: &Shared) -> Result<Status> {
    Ok(match shared.store.take_invite(secret) {
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
    })
}

// ---------------------------------------------------------------------------
// QUIC
// ---------------------------------------------------------------------------

async fn accept_loop(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        // Under load, make new peers prove their address (stateless retry)
        // before spending anything on them; this defeats spoofed floods.
        if shared.handshakes.available_permits() < MAX_PENDING_HANDSHAKES / 2
            && !incoming.remote_address_validated()
        {
            let _ = incoming.retry();
            continue;
        }
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
    match shared.known_device(&id)? {
        Some(name) => {
            drop(permit);
            let count = shared.live.lock().unwrap().values().filter(|l| l.id == id).count();
            if count >= MAX_CONNECTIONS_PER_DEVICE {
                conn.close(close::TOO_MANY.into(), b"too many connections");
                return Ok(());
            }
            serve_device(conn, id, name, shared).await;
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
    let status = decide_pairing(id, &secret, name, shared).await?;
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
        tokio::spawn(serve_request(recv, send, shared));
    }

    shared.live.lock().unwrap().remove(&key);
    shared.emit(HostEvent::Disconnected { id, name });
}

// ---------------------------------------------------------------------------
// TLS over TCP
// ---------------------------------------------------------------------------

async fn tcp_accept_loop(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<Shared>) {
    loop {
        let tcp = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                debug!("tcp accept: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let Ok(pending) = shared.tcp_handshakes.clone().try_acquire_owned() else { continue };
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(tcp, acceptor, shared, pending).await {
                debug!("tcp connection ended: {e:#}");
            }
        });
    }
}

async fn handle_tcp(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    shared: Arc<Shared>,
    pending: OwnedSemaphorePermit,
) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await??;
    let id = tls::peer_id_from_certs(tls.get_ref().1.peer_certificates())?;
    let (mut r, mut w) = tokio::io::split(tls);

    let Some(name) = shared.known_device(&id)? else {
        // Unknown device: only a pairing request with a live invite is
        // accepted. It keeps its handshake slot until done.
        let _pending = pending;
        let req = timeout(REQUEST_TIMEOUT, Request::read(&mut r)).await??;
        let status = match req {
            Request::Pair { secret, name } if !shared.store.invites()?.is_empty() => {
                decide_pairing(id, &secret, name, &shared).await?
            }
            Request::Pair { .. } => Status::Denied,
            Request::Connect(_) | Request::Udp => Status::NotPaired,
        };
        reply(&mut w, status).await?;
        let _ = w.shutdown().await;
        return Ok(());
    };

    // Paired device: move from a handshake slot to a regular one.
    drop(pending);
    let Ok(_slot) = shared.tcp_slots.clone().try_acquire_owned() else { return Ok(()) };
    let key = shared.next_tcp.fetch_add(1, Ordering::Relaxed);
    let stop = Arc::new(Notify::new());
    shared
        .live_tcp
        .lock()
        .unwrap()
        .insert(key, LiveTcp { id, name, stop: stop.clone() });
    tokio::select! {
        _ = serve_request(r, w, shared.clone()) => {}
        _ = stop.notified() => {}
    }
    shared.live_tcp.lock().unwrap().remove(&key);
    Ok(())
}

// ---------------------------------------------------------------------------
// One proxied connection (both transports)
// ---------------------------------------------------------------------------

async fn reply<W: AsyncWrite + Unpin>(w: &mut W, status: Status) -> std::io::Result<()> {
    w.write_all(&[status as u8]).await?;
    w.flush().await
}

async fn serve_request<R, W>(mut recv: R, mut send: W, shared: Arc<Shared>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let req = match timeout(REQUEST_TIMEOUT, Request::read(&mut recv)).await {
        Ok(Ok(r)) => r,
        _ => {
            let _ = reply(&mut send, Status::BadRequest).await;
            let _ = send.shutdown().await;
            return;
        }
    };
    match req {
        // Already paired: re-pairing is a no-op.
        Request::Pair { .. } => {
            let _ = reply(&mut send, Status::Ok).await;
            let _ = send.shutdown().await;
        }
        Request::Udp => {
            if reply(&mut send, Status::Ok).await.is_ok() {
                udp_relay(recv, send, &shared).await;
            }
        }
        Request::Connect(target) => match open_target(&target, &shared.opts).await {
            Ok(tcp) => {
                if reply(&mut send, Status::Ok).await.is_ok() {
                    splice(recv, send, tcp, &shared.traffic, true).await;
                }
            }
            Err(status) => {
                debug!("connect to {target} failed: {}", status.describe());
                let _ = reply(&mut send, status).await;
                let _ = send.shutdown().await;
            }
        },
    }
}

fn allowed(ip: IpAddr, opts: &HostOptions) -> bool {
    opts.allow_lan || !(is_local(ip) || opts.blocked.contains(&ip))
}

async fn recv_opt(sock: &Option<UdpSocket>, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    match sock {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// Relay UDP datagrams between a device and the internet. Destinations get
/// the same local-network rules as TCP; replies are only accepted from
/// addresses the device has sent to.
async fn udp_relay<R, W>(mut recv: R, mut send: W, shared: &Shared)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Ok(v4) = UdpSocket::bind("0.0.0.0:0").await else { return };
    let v6 = UdpSocket::bind("[::]:0").await.ok();
    let mut peers: HashSet<SocketAddr> = HashSet::new();
    let mut dns: HashMap<String, Option<IpAddr>> = HashMap::new();
    let mut buf4 = vec![0u8; 65_536];
    let mut buf6 = vec![0u8; 65_536];
    loop {
        tokio::select! {
            frame = timeout(UDP_IDLE, read_udp_frame(&mut recv)) => {
                let Ok(Ok(Some((target, payload)))) = frame else { break };
                let dest = match &target {
                    Target::Addr(a) => Some(*a),
                    Target::Domain(d, port) => {
                        if !dns.contains_key(d) && dns.len() < 1024 {
                            let ip = match timeout(DIAL_TIMEOUT, tokio::net::lookup_host((d.as_str(), *port))).await {
                                Ok(Ok(mut it)) => it.find(|a| a.is_ipv4()).map(|a| a.ip()),
                                _ => None,
                            };
                            dns.insert(d.clone(), ip);
                        }
                        dns.get(d).copied().flatten().map(|ip| SocketAddr::new(ip, *port))
                    }
                };
                let Some(dest) = dest.filter(|d| allowed(d.ip(), &shared.opts)) else { continue };
                let sock = if dest.is_ipv4() { Some(&v4) } else { v6.as_ref() };
                if let Some(sock) = sock {
                    if sock.send_to(&payload, dest).await.is_ok() {
                        shared.traffic.up.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        if peers.len() < UDP_MAX_PEERS {
                            peers.insert(dest);
                        }
                    }
                }
            }
            r = v4.recv_from(&mut buf4) => {
                let Ok((n, from)) = r else { continue };
                if !peers.contains(&from) { continue }
                let Some(frame) = encode_udp_frame(&Target::Addr(from), &buf4[..n]) else { continue };
                if send.write_all(&frame).await.is_err() || send.flush().await.is_err() { break }
                shared.traffic.down.fetch_add(n as u64, Ordering::Relaxed);
            }
            r = recv_opt(&v6, &mut buf6) => {
                let Ok((n, from)) = r else { continue };
                if !peers.contains(&from) { continue }
                let Some(frame) = encode_udp_frame(&Target::Addr(from), &buf6[..n]) else { continue };
                if send.write_all(&frame).await.is_err() || send.flush().await.is_err() { break }
                shared.traffic.down.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
    let _ = send.shutdown().await;
}

/// Resolve and connect, refusing local-network destinations unless allowed.
pub(crate) async fn open_target(target: &Target, opts: &HostOptions) -> Result<TcpStream, Status> {
    let addrs: Vec<SocketAddr> = match target {
        Target::Addr(a) => vec![*a],
        Target::Domain(d, port) => {
            match timeout(DIAL_TIMEOUT, tokio::net::lookup_host((d.as_str(), *port))).await {
                Ok(Ok(it)) => it.collect(),
                _ => Vec::new(),
            }
        }
    };
    if addrs.is_empty() {
        return Err(Status::Unreachable);
    }
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| allowed(a.ip(), opts))
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
        shared.live.lock().unwrap().retain(|_, l| {
            if allowed.contains(&l.id) {
                return true;
            }
            l.conn.close(close::REVOKED.into(), b"device removed");
            shared.emit(HostEvent::Revoked { id: l.id, name: l.name.clone() });
            false
        });
        shared.live_tcp.lock().unwrap().retain(|_, l| {
            if allowed.contains(&l.id) {
                return true;
            }
            l.stop.notify_one();
            false
        });
    }
}
