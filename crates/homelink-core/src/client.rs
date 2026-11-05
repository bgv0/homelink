//! Client role: a direct connection to one saved host.
//!
//! QUIC over UDP is tried first. If the host doesn't answer over UDP (some
//! networks block it), the client switches to TLS over TCP on the same port
//! number and tries QUIC again every few minutes.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use std::collections::HashMap;

use bytes::Bytes;
use homelink_proto::{
    close, encode_udp_datagram, parse_udp_datagram, sanitize_name, short_id, Invite, Request, Status, Target,
    SERVER_NAME,
};
use tokio::sync::mpsc;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::identity::Identity;
use crate::splice::Traffic;
use crate::store::SavedHost;
use crate::tls;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const APPROVAL_WAIT: Duration = Duration::from_secs(150);
/// How long to stay on TCP before trying QUIC again.
const RETRY_QUIC_AFTER: Duration = Duration::from_secs(300);

pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("can't find the host address '{0}'")]
    Resolve(String),
    #[error("the host at {0} didn't answer. Check it's sharing and its port is forwarded (UDP and TCP)")]
    Timeout(String),
    #[error("the host doesn't know this device (never paired, or it was removed)")]
    NotPaired,
    #[error("the host stopped sharing")]
    HostStopped,
    #[error("{}", .0.describe())]
    Status(Status),
    #[error("connection to the host failed: {0}")]
    Connection(String),
}

impl From<quinn::ConnectionError> for ClientError {
    fn from(e: quinn::ConnectionError) -> Self {
        use quinn::ConnectionError as E;
        match e {
            E::ApplicationClosed(ac) => {
                let code = ac.error_code.into_inner();
                if code == close::NOT_PAIRED as u64 || code == close::REVOKED as u64 {
                    ClientError::NotPaired
                } else if code == close::SHUTDOWN as u64 {
                    ClientError::HostStopped
                } else {
                    ClientError::Connection(ac.to_string())
                }
            }
            E::TimedOut => ClientError::Timeout("the host".into()),
            // A wrong host key shows up as a TLS failure.
            E::TransportError(t) => ClientError::Connection(format!(
                "{t} (if this persists, the host may have been reinstalled: ask for a new invite)"
            )),
            other => ClientError::Connection(other.to_string()),
        }
    }
}

impl From<quinn::WriteError> for ClientError {
    fn from(e: quinn::WriteError) -> Self {
        match e {
            quinn::WriteError::ConnectionLost(c) => c.into(),
            other => ClientError::Connection(other.to_string()),
        }
    }
}

impl From<quinn::ReadExactError> for ClientError {
    fn from(e: quinn::ReadExactError) -> Self {
        match e {
            quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(c)) => c.into(),
            other => ClientError::Connection(other.to_string()),
        }
    }
}

/// Resolve to an IPv4 address (v1 is IPv4-only).
async fn resolve(addr: &str, port: u16) -> Result<SocketAddr, ClientError> {
    let it = tokio::net::lookup_host((addr, port))
        .await
        .map_err(|_| ClientError::Resolve(addr.to_string()))?;
    it.into_iter()
        .find(|a| a.is_ipv4())
        .ok_or_else(|| ClientError::Resolve(addr.to_string()))
}

fn new_endpoint() -> Result<quinn::Endpoint, ClientError> {
    quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0)))
        .map_err(|e| ClientError::Connection(format!("can't open a UDP socket: {e}")))
}

async fn dial_quic(
    endpoint: &quinn::Endpoint,
    cfg: &quinn::ClientConfig,
    sa: SocketAddr,
) -> Result<quinn::Connection, ClientError> {
    let connecting = endpoint
        .connect_with(cfg.clone(), sa, SERVER_NAME)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    match timeout(CONNECT_TIMEOUT, connecting).await {
        Err(_) | Ok(Err(quinn::ConnectionError::TimedOut)) => Err(ClientError::Timeout(sa.to_string())),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(c)) => Ok(c),
    }
}

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Open a TLS-over-TCP connection to the host (one per proxied connection).
async fn dial_tcp(connector: &TlsConnector, sa: SocketAddr) -> Result<TlsStream, ClientError> {
    let tcp = match timeout(CONNECT_TIMEOUT, TcpStream::connect(sa)).await {
        Ok(Ok(s)) => s,
        _ => return Err(ClientError::Timeout(sa.to_string())),
    };
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(SERVER_NAME).expect("valid server name");
    match timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await {
        Err(_) => Err(ClientError::Timeout(sa.to_string())),
        Ok(Err(e)) => Err(ClientError::Connection(format!(
            "{e} (if this persists, the host may have been reinstalled: ask for a new invite)"
        ))),
        Ok(Ok(s)) => Ok(s),
    }
}

/// Send one request over a fresh TLS connection and read the status byte.
async fn tcp_request(
    connector: &TlsConnector,
    sa: SocketAddr,
    req: &Request,
    wait: Duration,
) -> Result<(Status, BoxWrite, BoxRead), ClientError> {
    let tls = dial_tcp(connector, sa).await?;
    let (mut r, mut w) = tokio::io::split(tls);
    let io = |e: std::io::Error| ClientError::Connection(e.to_string());
    w.write_all(&req.encode()).await.map_err(io)?;
    w.flush().await.map_err(io)?;
    let mut b = [0u8; 1];
    match timeout(wait, r.read_exact(&mut b)).await {
        Err(_) => return Err(ClientError::Status(Status::Unreachable)),
        // A host hanging up right after a good handshake means it refused us.
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            return Err(ClientError::NotPaired)
        }
        Ok(Err(e)) => return Err(io(e)),
        Ok(Ok(_)) => {}
    }
    let status = Status::from_byte(b[0]).ok_or_else(|| ClientError::Connection("unexpected reply from host".into()))?;
    Ok((status, Box::new(w), Box::new(r)))
}

type Routes = Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>;

/// QUIC datagram path for one UDP relay. Removed from the routing table
/// when dropped.
pub struct UdpDatagrams {
    conn: quinn::Connection,
    assoc: u32,
    rx: mpsc::Receiver<Bytes>,
    routes: Routes,
}

impl UdpDatagrams {
    /// Send as a QUIC datagram. Returns false if it doesn't fit (or the
    /// connection is gone), in which case send it as a stream frame.
    pub fn send(&self, addr: &Target, payload: &[u8]) -> bool {
        let pkt = encode_udp_datagram(self.assoc, addr, payload);
        self.conn.max_datagram_size().is_some_and(|m| pkt.len() <= m)
            && self.conn.send_datagram(Bytes::from(pkt)).is_ok()
    }

    /// Next datagram from the host: (source address, payload). None when the
    /// connection is gone.
    pub async fn recv(&mut self) -> Option<(Target, Vec<u8>)> {
        loop {
            let b = self.rx.recv().await?;
            if let Ok((_, src, payload)) = parse_udp_datagram(&b) {
                return Some((src, payload.to_vec()));
            }
        }
    }
}

impl Drop for UdpDatagrams {
    fn drop(&mut self) {
        self.routes.lock().unwrap().remove(&self.assoc);
    }
}

/// A UDP relay through the host: stream frames always work; QUIC datagrams
/// are used when available.
pub struct UdpTunnel {
    pub w: BoxWrite,
    pub r: BoxRead,
    pub datagrams: Option<UdpDatagrams>,
}

async fn dispatch_datagrams(conn: quinn::Connection, routes: Routes) {
    while let Ok(b) = conn.read_datagram().await {
        if b.len() < 4 {
            continue;
        }
        let assoc = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let tx = routes.lock().unwrap().get(&assoc).cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send(b);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Transport {
    Quic,
    Tcp,
}

pub struct Client {
    pub host: SavedHost,
    pub traffic: Arc<Traffic>,
    endpoint: quinn::Endpoint,
    cfg: quinn::ClientConfig,
    tcp: TlsConnector,
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
    /// Set while using TCP because QUIC didn't answer.
    tcp_since: Mutex<Option<Instant>>,
    force_tcp: bool,
    /// Last TCP connect time, as a stand-in for round-trip time (ms).
    tcp_rtt_ms: AtomicU64,
    routes: Routes,
}

impl Client {
    pub fn new(identity: &Identity, host: SavedHost) -> anyhow::Result<Self> {
        let host_id = host.device_id()?;
        Ok(Client {
            cfg: tls::client_config(identity, host_id)?,
            tcp: TlsConnector::from(Arc::new(tls::client_tls(identity, host_id)?)),
            host,
            traffic: Arc::new(Traffic::default()),
            endpoint: new_endpoint()?,
            conn: tokio::sync::Mutex::new(None),
            tcp_since: Mutex::new(None),
            force_tcp: false,
            tcp_rtt_ms: AtomicU64::new(0),
            routes: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Always use TLS over TCP (for testing, or networks known to block UDP).
    pub fn with_tcp_only(mut self) -> Self {
        self.force_tcp = true;
        self
    }

    fn on_tcp(&self) -> bool {
        self.force_tcp
            || self
                .tcp_since
                .lock()
                .unwrap()
                .is_some_and(|since| since.elapsed() < RETRY_QUIC_AFTER)
    }

    fn switch_to_tcp(&self) {
        *self.tcp_since.lock().unwrap() = Some(Instant::now());
    }

    pub fn transport(&self) -> Transport {
        if self.on_tcp() { Transport::Tcp } else { Transport::Quic }
    }

    async fn quic(&self) -> Result<quinn::Connection, ClientError> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let sa = resolve(&self.host.addr, self.host.port).await?;
        let c = dial_quic(&self.endpoint, &self.cfg, sa).await?;
        tokio::spawn(dispatch_datagrams(c.clone(), self.routes.clone()));
        *self.tcp_since.lock().unwrap() = None;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Make sure the host is reachable, picking QUIC or TCP.
    pub async fn check(&self) -> Result<Transport, ClientError> {
        if !self.on_tcp() {
            match self.quic().await {
                Ok(_) => return Ok(Transport::Quic),
                Err(ClientError::Timeout(_)) => {}
                Err(e) => return Err(e),
            }
        }
        let sa = resolve(&self.host.addr, self.host.port).await?;
        let start = Instant::now();
        let tls = dial_tcp(&self.tcp, sa).await?;
        self.tcp_rtt_ms.store(start.elapsed().as_millis() as u64 / 2, Ordering::Relaxed);
        drop(tls);
        if !self.force_tcp {
            self.switch_to_tcp();
        }
        Ok(Transport::Tcp)
    }

    /// Round-trip time, if connected.
    pub async fn rtt(&self) -> Option<Duration> {
        if self.on_tcp() {
            let ms = self.tcp_rtt_ms.load(Ordering::Relaxed);
            return (ms > 0).then(|| Duration::from_millis(ms));
        }
        let guard = self.conn.lock().await;
        guard.as_ref().filter(|c| c.close_reason().is_none()).map(|c| c.rtt())
    }

    /// Open a proxied TCP connection to `target` through the host.
    pub async fn open(&self, target: &Target) -> Result<(BoxWrite, BoxRead), ClientError> {
        self.open_request(&Request::Connect(target.clone())).await
    }

    /// Open a UDP relay through the host.
    pub async fn open_udp(&self) -> Result<UdpTunnel, ClientError> {
        let assoc = u32::from_be_bytes(crate::random_bytes());
        let req = Request::Udp { assoc };
        if !self.on_tcp() {
            match self.open_quic(&req).await {
                Ok((conn, send, recv)) => {
                    let (tx, rx) = mpsc::channel(256);
                    self.routes.lock().unwrap().insert(assoc, tx);
                    let datagrams = UdpDatagrams { conn, assoc, rx, routes: self.routes.clone() };
                    return Ok(UdpTunnel { w: Box::new(send), r: Box::new(recv), datagrams: Some(datagrams) });
                }
                Err(ClientError::Timeout(_)) => self.switch_to_tcp(),
                Err(e) => return Err(e),
            }
        }
        let (w, r) = self.open_tcp(&req).await?;
        Ok(UdpTunnel { w, r, datagrams: None })
    }

    async fn open_request(&self, req: &Request) -> Result<(BoxWrite, BoxRead), ClientError> {
        if !self.on_tcp() {
            match self.open_quic(req).await {
                Ok((_, s, r)) => return Ok((Box::new(s), Box::new(r))),
                Err(ClientError::Timeout(_)) => self.switch_to_tcp(),
                Err(e) => return Err(e),
            }
        }
        self.open_tcp(req).await
    }

    async fn open_quic(
        &self,
        req: &Request,
    ) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream), ClientError> {
        let mut last = None;
        for _ in 0..2 {
            let conn = self.quic().await?;
            match open_on(&conn, req).await {
                Ok((s, r)) => return Ok((conn, s, r)),
                // The connection may have just died: retry once on a fresh one.
                Err(e @ (ClientError::Connection(_) | ClientError::Timeout(_))) => {
                    conn.close(0u32.into(), b"retry");
                    last = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        // A connection that keeps failing mid-stream is treated like a
        // blocked network so we fall back to TCP.
        Err(match last.expect("loop ran") {
            ClientError::Connection(_) => ClientError::Timeout(self.host.addr.clone()),
            e => e,
        })
    }

    async fn open_tcp(&self, req: &Request) -> Result<(BoxWrite, BoxRead), ClientError> {
        let sa = resolve(&self.host.addr, self.host.port).await?;
        let start = Instant::now();
        let (status, w, r) = tcp_request(&self.tcp, sa, req, Duration::from_secs(15)).await?;
        self.tcp_rtt_ms.store((start.elapsed().as_millis() as u64 / 3).max(1), Ordering::Relaxed);
        match status {
            Status::Ok => Ok((w, r)),
            Status::NotPaired => Err(ClientError::NotPaired),
            s => Err(ClientError::Status(s)),
        }
    }

    pub async fn disconnect(&self) {
        if let Some(c) = self.conn.lock().await.take() {
            c.close(0u32.into(), b"bye");
        }
        let _ = timeout(Duration::from_secs(1), self.endpoint.wait_idle()).await;
    }
}

async fn open_on(
    conn: &quinn::Connection,
    req: &Request,
) -> Result<(quinn::SendStream, quinn::RecvStream), ClientError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&req.encode()).await?;
    let mut b = [0u8; 1];
    // The host answers after dialing, which can take up to its own timeout.
    match timeout(Duration::from_secs(15), recv.read_exact(&mut b)).await {
        Err(_) => return Err(ClientError::Status(Status::Unreachable)),
        Ok(r) => r?,
    }
    match Status::from_byte(b[0]) {
        Some(Status::Ok) => Ok((send, recv)),
        Some(s) => Err(ClientError::Status(s)),
        None => Err(ClientError::Connection("unexpected reply from host".into())),
    }
}

/// Pair with a host using an invite code. Waits while the host user approves.
/// Uses QUIC, or TLS over TCP if UDP doesn't get through.
pub async fn pair(
    identity: &Identity,
    invite: &Invite,
    device_name: &str,
    host_name: Option<&str>,
) -> Result<SavedHost, ClientError> {
    pair_with(identity, invite, device_name, host_name, false).await
}

/// Like [`pair`], but only over TCP (for tests and UDP-blocked networks).
pub async fn pair_tcp(
    identity: &Identity,
    invite: &Invite,
    device_name: &str,
    host_name: Option<&str>,
) -> Result<SavedHost, ClientError> {
    pair_with(identity, invite, device_name, host_name, true).await
}

async fn pair_with(
    identity: &Identity,
    invite: &Invite,
    device_name: &str,
    host_name: Option<&str>,
    tcp_only: bool,
) -> Result<SavedHost, ClientError> {
    if invite.expires <= crate::now_unix() {
        return Err(ClientError::Status(Status::Expired));
    }
    let sa = resolve(&invite.addr, invite.port).await?;
    let req = Request::Pair { secret: invite.secret, name: sanitize_name(device_name) };

    let quic_result = if tcp_only {
        Err(ClientError::Timeout(sa.to_string()))
    } else {
        pair_quic(identity, invite, sa, &req).await
    };
    let status = match quic_result {
        Err(ClientError::Timeout(_)) => {
            let tls = tls::client_tls(identity, invite.host_id).map_err(|e| ClientError::Connection(e.to_string()))?;
            let connector = TlsConnector::from(Arc::new(tls));
            let (status, mut w, _r) = tcp_request(&connector, sa, &req, APPROVAL_WAIT).await?;
            let _ = w.shutdown().await;
            status
        }
        other => other?,
    };
    match status {
        Status::Ok => Ok(SavedHost {
            name: host_name
                .map(sanitize_name)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("host-{}", short_id(&invite.host_id))),
            addr: invite.addr.clone(),
            port: invite.port,
            id: homelink_proto::id_hex(&invite.host_id),
        }),
        s => Err(ClientError::Status(s)),
    }
}

async fn pair_quic(identity: &Identity, invite: &Invite, sa: SocketAddr, req: &Request) -> Result<Status, ClientError> {
    let cfg = tls::client_config(identity, invite.host_id).map_err(|e| ClientError::Connection(e.to_string()))?;
    let endpoint = new_endpoint()?;
    let conn = dial_quic(&endpoint, &cfg, sa).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&req.encode()).await?;
    let mut b = [0u8; 1];
    let read = timeout(APPROVAL_WAIT, recv.read_exact(&mut b)).await;
    conn.close(close::PAIR_DONE.into(), b"done");
    let _ = timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    match read {
        Err(_) => return Err(ClientError::Status(Status::Rejected)),
        Ok(r) => r?,
    }
    Status::from_byte(b[0]).ok_or_else(|| ClientError::Connection("unexpected reply from host".into()))
}
