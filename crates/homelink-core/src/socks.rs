//! Local SOCKS5 server (CONNECT only, no auth). Bind it to 127.0.0.1 only.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use homelink_proto::{valid_domain, Status, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::debug;

use crate::client::{Client, ClientError};
use crate::splice::splice;

const REPLY_OK: u8 = 0;
const REPLY_GENERAL: u8 = 1;
const REPLY_NOT_ALLOWED: u8 = 2;
const REPLY_HOST_UNREACHABLE: u8 = 4;
const REPLY_CMD_UNSUPPORTED: u8 = 7;
const REPLY_ATYP_UNSUPPORTED: u8 = 8;

pub async fn serve(client: Arc<Client>, listener: TcpListener) -> Result<()> {
    loop {
        let sock = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                // Usually out of file handles: back off instead of giving up.
                debug!("socks accept: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, client).await {
                debug!("socks: {e:#}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, client: Arc<Client>) -> Result<()> {
    let target = timeout(Duration::from_secs(10), handshake(&mut sock)).await??;
    match client.open(&target).await {
        Ok((send, recv)) => {
            sock.write_all(&reply(REPLY_OK)).await?;
            splice(send, recv, sock, &client.traffic, false).await;
        }
        Err(e) => {
            debug!("socks: {target}: {e}");
            let code = match e {
                ClientError::Status(Status::Blocked) | ClientError::NotPaired => REPLY_NOT_ALLOWED,
                ClientError::Status(Status::Unreachable) => REPLY_HOST_UNREACHABLE,
                _ => REPLY_GENERAL,
            };
            sock.write_all(&reply(code)).await?;
        }
    }
    Ok(())
}

fn reply(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

async fn handshake(s: &mut TcpStream) -> Result<Target> {
    if s.read_u8().await? != 5 {
        bail!("not SOCKS5");
    }
    let n = s.read_u8().await? as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        bail!("client requires authentication");
    }
    s.write_all(&[5, 0]).await?;

    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        bail!("bad request version");
    }
    if h[1] != 1 {
        s.write_all(&reply(REPLY_CMD_UNSUPPORTED)).await?;
        bail!("only CONNECT is supported");
    }
    let target = match h[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            let port = s.read_u16().await?;
            Target::Addr(SocketAddr::new(Ipv4Addr::from(b).into(), port))
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            let port = s.read_u16().await?;
            Target::Addr(SocketAddr::new(Ipv6Addr::from(b).into(), port))
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
            let port = s.read_u16().await?;
            let d = String::from_utf8(b).unwrap_or_default();
            if let Ok(ip) = d.parse() {
                Target::Addr(SocketAddr::new(ip, port))
            } else if valid_domain(&d) {
                Target::Domain(d, port)
            } else {
                s.write_all(&reply(REPLY_GENERAL)).await?;
                bail!("invalid domain");
            }
        }
        _ => {
            s.write_all(&reply(REPLY_ATYP_UNSUPPORTED)).await?;
            bail!("unknown address type");
        }
    };
    if target.port() == 0 {
        s.write_all(&reply(REPLY_GENERAL)).await?;
        bail!("port 0");
    }
    Ok(target)
}
