//! Local SOCKS5 server (no auth): CONNECT and UDP ASSOCIATE.
//! Bind it to 127.0.0.1 only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use homelink_proto::{encode_target, encode_udp_frame, parse_target, read_udp_frame, valid_domain, Status, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::debug;

use crate::client::{Client, ClientError, UdpDatagrams, UdpTunnel};
use crate::splice::splice;

const REPLY_OK: u8 = 0;
const REPLY_GENERAL: u8 = 1;
const REPLY_NOT_ALLOWED: u8 = 2;
const REPLY_HOST_UNREACHABLE: u8 = 4;
const REPLY_CMD_UNSUPPORTED: u8 = 7;
const REPLY_ATYP_UNSUPPORTED: u8 = 8;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

enum Command {
    Connect(Target),
    UdpAssociate,
}

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

fn error_code(e: &ClientError) -> u8 {
    match e {
        ClientError::Status(Status::Blocked) | ClientError::NotPaired => REPLY_NOT_ALLOWED,
        ClientError::Status(Status::Unreachable) => REPLY_HOST_UNREACHABLE,
        _ => REPLY_GENERAL,
    }
}

async fn handle(mut sock: TcpStream, client: Arc<Client>) -> Result<()> {
    let cmd = timeout(Duration::from_secs(10), handshake(&mut sock)).await??;
    match cmd {
        Command::Connect(target) => match client.open(&target).await {
            Ok((send, recv)) => {
                sock.write_all(&reply(REPLY_OK)).await?;
                splice(recv, send, sock, &client.traffic, false).await;
            }
            Err(e) => {
                debug!("socks: {target}: {e}");
                sock.write_all(&reply(error_code(&e))).await?;
            }
        },
        Command::UdpAssociate => {
            let udp = UdpSocket::bind(SocketAddr::new(sock.local_addr()?.ip(), 0)).await?;
            let tunnel = match client.open_udp().await {
                Ok(s) => s,
                Err(e) => {
                    debug!("socks udp: {e}");
                    sock.write_all(&reply(error_code(&e))).await?;
                    return Ok(());
                }
            };
            sock.write_all(&reply_with(REPLY_OK, udp.local_addr()?)).await?;
            udp_associate(sock, udp, tunnel, &client).await;
        }
    }
    Ok(())
}

/// Relay between the app's UDP socket (SOCKS5 UDP request format) and the
/// host's UDP stream. Ends when the app closes its TCP control connection.
async fn udp_associate(mut control: TcpStream, udp: UdpSocket, tunnel: UdpTunnel, client: &Client) {
    let UdpTunnel { mut w, mut r, mut datagrams } = tunnel;
    let mut app: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65_536];
    let mut ctl = [0u8; 64];
    loop {
        tokio::select! {
            n = control.read(&mut ctl) => {
                if !matches!(n, Ok(n) if n > 0) { break }
            }
            got = udp.recv_from(&mut buf) => {
                let Ok((n, from)) = got else { continue };
                // Only the local app that opened this association may use it.
                if !from.ip().is_loopback() || app.is_some_and(|a| a != from) { continue }
                app = Some(from);
                // RSV(2) FRAG(1) ADDR PORT DATA; fragments aren't supported.
                if n < 4 || buf[2] != 0 { continue }
                let Ok((target, used)) = parse_target(&buf[3..n]) else { continue };
                if target.port() == 0 { continue }
                let payload = &buf[3 + used..n];
                let sent_as_datagram = datagrams.as_ref().is_some_and(|d| d.send(&target, payload));
                if !sent_as_datagram {
                    let Some(frame) = encode_udp_frame(&target, payload) else { continue };
                    if w.write_all(&frame).await.is_err() || w.flush().await.is_err() { break }
                }
                client.traffic.up.fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
            d = recv_datagram(&mut datagrams) => {
                let Some((src, payload)) = d else { continue };
                let Some(app) = app else { continue };
                send_to_app(&udp, app, &src, &payload, client).await;
            }
            frame = read_udp_frame(&mut r) => {
                let Ok(Some((src, payload))) = frame else { break };
                let Some(app) = app else { continue };
                send_to_app(&udp, app, &src, &payload, client).await;
            }
        }
    }
    let _ = w.shutdown().await;
}

/// Next QUIC datagram, or pending forever when datagrams aren't in use.
async fn recv_datagram(d: &mut Option<UdpDatagrams>) -> Option<(Target, Vec<u8>)> {
    let Some(dg) = d.as_mut() else { return std::future::pending().await };
    let got = dg.recv().await;
    if got.is_none() {
        *d = None; // connection gone; the stream path keeps working until it ends
    }
    got
}

/// Wrap a datagram in the SOCKS5 UDP header and send it to the app.
async fn send_to_app(udp: &UdpSocket, app: SocketAddr, src: &Target, payload: &[u8], client: &Client) {
    let mut out = vec![0, 0, 0];
    encode_target(&mut out, src);
    out.extend_from_slice(payload);
    if udp.send_to(&out, app).await.is_ok() {
        client.traffic.down.fetch_add(payload.len() as u64, Ordering::Relaxed);
    }
}

fn reply(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

fn reply_with(code: u8, bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![5, code, 0];
    let bound = match bound.ip() {
        // Some clients can't use an unspecified address; tell them loopback.
        IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound.port()),
        _ => bound,
    };
    encode_target(&mut out, &Target::Addr(bound));
    out
}

async fn handshake(s: &mut TcpStream) -> Result<Command> {
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
    let cmd = h[1];
    if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
        s.write_all(&reply(REPLY_CMD_UNSUPPORTED)).await?;
        bail!("unsupported SOCKS command {cmd}");
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
    if cmd == CMD_UDP_ASSOCIATE {
        // The address is only a hint of where the app will send from.
        return Ok(Command::UdpAssociate);
    }
    if target.port() == 0 {
        s.write_all(&reply(REPLY_GENERAL)).await?;
        bail!("port 0");
    }
    Ok(Command::Connect(target))
}
