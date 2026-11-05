//! Client role: a direct QUIC connection to one saved host, reconnecting on demand.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use homelink_proto::{close, sanitize_name, short_id, Invite, Request, Status, Target, SERVER_NAME};
use tokio::time::timeout;

use crate::identity::Identity;
use crate::splice::Traffic;
use crate::store::SavedHost;
use crate::tls;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const APPROVAL_WAIT: Duration = Duration::from_secs(150);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("can't find the host address '{0}'")]
    Resolve(String),
    #[error("the host at {0} didn't answer. Check it's sharing, its port is forwarded, and this network allows UDP")]
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

async fn dial(
    endpoint: &quinn::Endpoint,
    cfg: &quinn::ClientConfig,
    addr: &str,
    port: u16,
) -> Result<quinn::Connection, ClientError> {
    let sa = resolve(addr, port).await?;
    let connecting = endpoint
        .connect_with(cfg.clone(), sa, SERVER_NAME)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    match timeout(CONNECT_TIMEOUT, connecting).await {
        Err(_) | Ok(Err(quinn::ConnectionError::TimedOut)) => {
            Err(ClientError::Timeout(format!("{addr}:{port}")))
        }
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(c)) => Ok(c),
    }
}

pub struct Client {
    pub host: SavedHost,
    pub traffic: Arc<Traffic>,
    endpoint: quinn::Endpoint,
    cfg: quinn::ClientConfig,
    conn: tokio::sync::Mutex<Option<quinn::Connection>>,
}

impl Client {
    pub fn new(identity: &Identity, host: SavedHost) -> anyhow::Result<Self> {
        let cfg = tls::client_config(identity, host.device_id()?)?;
        Ok(Client {
            host,
            traffic: Arc::new(Traffic::default()),
            endpoint: new_endpoint()?,
            cfg,
            conn: tokio::sync::Mutex::new(None),
        })
    }

    /// The live connection, dialing the host if needed.
    pub async fn connection(&self) -> Result<quinn::Connection, ClientError> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let c = dial(&self.endpoint, &self.cfg, &self.host.addr, self.host.port).await?;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Round-trip time of the current connection, if connected.
    pub async fn rtt(&self) -> Option<Duration> {
        let guard = self.conn.lock().await;
        guard.as_ref().filter(|c| c.close_reason().is_none()).map(|c| c.rtt())
    }

    /// Open a proxied TCP connection to `target` through the host.
    pub async fn open(
        &self,
        target: &Target,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), ClientError> {
        let mut last = None;
        for _ in 0..2 {
            let conn = self.connection().await?;
            match open_on(&conn, target).await {
                Ok(s) => return Ok(s),
                // The connection may have just died: retry once on a fresh one.
                Err(e @ (ClientError::Connection(_) | ClientError::Timeout(_))) => {
                    conn.close(0u32.into(), b"retry");
                    last = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("loop ran"))
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
    target: &Target,
) -> Result<(quinn::SendStream, quinn::RecvStream), ClientError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&Request::Connect(target.clone()).encode()).await?;
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
pub async fn pair(
    identity: &Identity,
    invite: &Invite,
    device_name: &str,
    host_name: Option<&str>,
) -> Result<SavedHost, ClientError> {
    if invite.expires <= crate::now_unix() {
        return Err(ClientError::Status(Status::Expired));
    }
    let cfg = tls::client_config(identity, invite.host_id)
        .map_err(|e| ClientError::Connection(e.to_string()))?;
    let endpoint = new_endpoint()?;
    let conn = dial(&endpoint, &cfg, &invite.addr, invite.port).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let req = Request::Pair { secret: invite.secret, name: sanitize_name(device_name) };
    send.write_all(&req.encode()).await?;
    let mut b = [0u8; 1];
    let read = timeout(APPROVAL_WAIT, recv.read_exact(&mut b)).await;
    conn.close(close::PAIR_DONE.into(), b"done");
    let _ = timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    match read {
        Err(_) => return Err(ClientError::Status(Status::Rejected)),
        Ok(r) => r?,
    }
    match Status::from_byte(b[0]) {
        Some(Status::Ok) => Ok(SavedHost {
            name: host_name
                .map(sanitize_name)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("host-{}", short_id(&invite.host_id))),
            addr: invite.addr.clone(),
            port: invite.port,
            id: homelink_proto::id_hex(&invite.host_id),
        }),
        Some(s) => Err(ClientError::Status(s)),
        None => Err(ClientError::Connection("unexpected reply from host".into())),
    }
}
