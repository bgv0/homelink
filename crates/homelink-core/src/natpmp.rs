//! NAT-PMP (RFC 6886) port mapping, the fallback when UPnP isn't available.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

const PORT: u16 = 5351;
const OP_EXTERNAL_IP: u8 = 0;
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;

/// The default gateway's IPv4 address.
pub fn default_gateway() -> Option<Ipv4Addr> {
    netdev::get_default_gateway().ok()?.ipv4.into_iter().next()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    pub external_port: u16,
    /// Seconds the router granted.
    pub lifetime: u32,
}

fn result_text(code: u16) -> &'static str {
    match code {
        1 => "router doesn't support this NAT-PMP version",
        2 => "router has NAT-PMP turned off",
        3 => "router has no internet connection",
        4 => "router is out of mappings",
        5 => "router doesn't support this request",
        _ => "router refused",
    }
}

pub(crate) fn map_request(op: u8, internal: u16, external: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[1] = op;
    b[4..6].copy_from_slice(&internal.to_be_bytes());
    b[6..8].copy_from_slice(&external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

pub(crate) fn parse_map_response(b: &[u8], op: u8, internal: u16) -> Result<Mapped, String> {
    if b.len() < 16 || b[0] != 0 || b[1] != 128 + op {
        return Err("unexpected NAT-PMP reply".into());
    }
    let code = u16::from_be_bytes([b[2], b[3]]);
    if code != 0 {
        return Err(result_text(code).into());
    }
    if u16::from_be_bytes([b[8], b[9]]) != internal {
        return Err("NAT-PMP reply for another port".into());
    }
    Ok(Mapped {
        external_port: u16::from_be_bytes([b[10], b[11]]),
        lifetime: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
    })
}

pub(crate) fn parse_ip_response(b: &[u8]) -> Option<Ipv4Addr> {
    if b.len() < 12 || b[0] != 0 || b[1] != 128 + OP_EXTERNAL_IP || b[2] != 0 || b[3] != 0 {
        return None;
    }
    Some(Ipv4Addr::new(b[8], b[9], b[10], b[11]))
}

/// Send `req` and wait for a reply, retrying with growing timeouts (~2 s total).
async fn exchange(gateway: Ipv4Addr, req: &[u8]) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
    let addr = SocketAddr::from((gateway, PORT));
    let mut wait = Duration::from_millis(250);
    for _ in 0..4 {
        sock.send_to(req, addr).await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 64];
        if let Ok(Ok((n, from))) = timeout(wait, sock.recv_from(&mut buf)).await {
            if from.ip() == gateway {
                return Ok(buf[..n].to_vec());
            }
        }
        wait *= 2;
    }
    Err("no NAT-PMP router answered".into())
}

/// Ask the router to forward UDP `port` to this computer.
/// A `lifetime` of 0 removes the mapping.
pub async fn map_udp(gateway: Ipv4Addr, port: u16, lifetime: u32) -> Result<Mapped, String> {
    let reply = exchange(gateway, &map_request(OP_MAP_UDP, port, port, lifetime)).await?;
    parse_map_response(&reply, OP_MAP_UDP, port)
}

/// Same for TCP (the fallback transport).
pub async fn map_tcp(gateway: Ipv4Addr, port: u16, lifetime: u32) -> Result<Mapped, String> {
    let reply = exchange(gateway, &map_request(OP_MAP_TCP, port, port, lifetime)).await?;
    parse_map_response(&reply, OP_MAP_TCP, port)
}

pub async fn external_ip(gateway: Ipv4Addr) -> Option<Ipv4Addr> {
    let reply = exchange(gateway, &[0, OP_EXTERNAL_IP]).await.ok()?;
    parse_ip_response(&reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_parses() {
        assert_eq!(map_request(OP_MAP_UDP, 47420, 47420, 3600), [0, 1, 0, 0, 0xb9, 0x3c, 0xb9, 0x3c, 0, 0, 0x0e, 0x10]);
        assert_eq!(map_request(OP_MAP_TCP, 1, 1, 0)[1], 2);

        let mut ok = [0u8; 16];
        ok[1] = 129;
        ok[8..10].copy_from_slice(&47420u16.to_be_bytes());
        ok[10..12].copy_from_slice(&47420u16.to_be_bytes());
        ok[12..16].copy_from_slice(&7200u32.to_be_bytes());
        assert_eq!(parse_map_response(&ok, OP_MAP_UDP, 47420), Ok(Mapped { external_port: 47420, lifetime: 7200 }));
        assert!(parse_map_response(&ok, OP_MAP_UDP, 1).is_err(), "other port");
        assert!(parse_map_response(&ok, OP_MAP_TCP, 47420).is_err(), "wrong opcode");

        let mut refused = ok;
        refused[3] = 2;
        assert_eq!(parse_map_response(&refused, OP_MAP_UDP, 47420), Err("router has NAT-PMP turned off".into()));

        let ip = [0, 128, 0, 0, 0, 0, 0, 1, 203, 0, 113, 9];
        assert_eq!(parse_ip_response(&ip), Some(Ipv4Addr::new(203, 0, 113, 9)));
        assert_eq!(parse_ip_response(&ip[..8]), None);
    }
}
