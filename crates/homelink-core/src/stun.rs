//! Minimal STUN binding request, used only to learn this network's public IP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

pub const SERVERS: &[&str] = &["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
const MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// Public IPv4 address as seen by a STUN server, or None if none answered.
pub async fn public_ip() -> Option<IpAddr> {
    for server in SERVERS {
        if let Some(ip) = query(server).await {
            return Some(ip);
        }
    }
    None
}

async fn query(server: &str) -> Option<IpAddr> {
    let addr = tokio::net::lookup_host(server).await.ok()?.find(|a| a.is_ipv4())?;
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let txid: [u8; 12] = crate::random_bytes();
    let req = build_request(&txid);
    for _ in 0..2 {
        sock.send_to(&req, addr).await.ok()?;
        let mut buf = [0u8; 512];
        if let Ok(Ok((n, from))) = timeout(Duration::from_millis(1500), sock.recv_from(&mut buf)).await {
            if from == addr {
                if let Some(sa) = parse_response(&buf[..n], &txid) {
                    return Some(sa.ip());
                }
            }
        }
    }
    None
}

pub(crate) fn build_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&[0x00, 0x01]); // binding request
    b[4..8].copy_from_slice(&MAGIC);
    b[8..20].copy_from_slice(txid);
    b
}

pub(crate) fn parse_response(b: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if b.len() < 20 || b[0..2] != [0x01, 0x01] || b[4..8] != MAGIC || &b[8..20] != txid {
        return None;
    }
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let end = (20 + len).min(b.len());
    let mut i = 20;
    let mut mapped = None;
    while i + 4 <= end {
        let t = u16::from_be_bytes([b[i], b[i + 1]]);
        let l = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        let v = b.get(i + 4..i + 4 + l)?;
        match t {
            0x0020 => return parse_addr(v, Some(txid)),
            0x0001 => mapped = parse_addr(v, None),
            _ => {}
        }
        i += 4 + l.div_ceil(4) * 4;
    }
    mapped
}

fn parse_addr(v: &[u8], xor: Option<&[u8; 12]>) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC);
    if let Some(t) = xor {
        key[4..].copy_from_slice(t);
        port ^= 0x2112;
    }
    let x = |bytes: &[u8]| -> Vec<u8> {
        bytes
            .iter()
            .enumerate()
            .map(|(i, b)| if xor.is_some() { b ^ key[i] } else { *b })
            .collect()
    };
    let ip: IpAddr = match v[1] {
        1 if v.len() >= 8 => {
            let o: [u8; 4] = x(&v[4..8]).try_into().ok()?;
            Ipv4Addr::from(o).into()
        }
        2 if v.len() >= 20 => {
            let o: [u8; 16] = x(&v[4..20]).try_into().ok()?;
            Ipv6Addr::from(o).into()
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [9u8; 12];
        let ip = [203, 0, 113, 7];
        let port: u16 = 54321;
        let mut attr = vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x01];
        attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        attr.extend(ip.iter().zip(MAGIC).map(|(a, m)| a ^ m));
        let mut msg = vec![0x01, 0x01];
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC);
        msg.extend_from_slice(&txid);
        msg.extend_from_slice(&attr);
        assert_eq!(parse_response(&msg, &txid), Some("203.0.113.7:54321".parse().unwrap()));
        assert_eq!(parse_response(&msg, &[0u8; 12]), None, "wrong transaction id");
        assert_eq!(build_request(&txid)[0..2], [0, 1]);
    }
}
