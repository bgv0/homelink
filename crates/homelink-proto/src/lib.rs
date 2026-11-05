//! Wire format shared by the homelink host and client.
//!
//! Every QUIC bidirectional stream starts with one [`Request`] from the client,
//! answered by one [`Status`] byte from the host. After `Status::Ok` on a
//! connect request, the stream carries raw TCP bytes in both directions.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const ALPN: &[u8] = b"homelink/1";
pub const VERSION: u8 = 1;
pub const DEFAULT_PORT: u16 = 47420;
/// TLS server name used on the wire. Hosts are identified by key, not name.
pub const SERVER_NAME: &str = "homelink";
pub const MAX_NAME_LEN: usize = 64;

const KIND_CONNECT: u8 = 1;
const KIND_PAIR: u8 = 2;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;

/// QUIC connection close codes sent by the host.
pub mod close {
    pub const SHUTDOWN: u32 = 0;
    pub const NOT_PAIRED: u32 = 1;
    pub const REVOKED: u32 = 2;
    pub const TOO_MANY: u32 = 3;
    pub const PAIR_DONE: u32 = 4;
}

/// SHA-256 of a device's certificate.
pub type DeviceId = [u8; 32];
pub type Secret = [u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("unsupported protocol version {0}")]
    Version(u8),
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Addr(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Addr(a) => a.port(),
            Target::Domain(_, p) => *p,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Addr(a) => write!(f, "{a}"),
            Target::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Connect(Target),
    Pair { secret: Secret, name: String },
}

impl Request {
    /// Encode the request. Domains and names must already be valid
    /// (see [`valid_domain`] and [`sanitize_name`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VERSION];
        match self {
            Request::Connect(target) => {
                out.push(KIND_CONNECT);
                match target {
                    Target::Addr(SocketAddr::V4(a)) => {
                        out.push(ATYP_V4);
                        out.extend_from_slice(&a.ip().octets());
                    }
                    Target::Addr(SocketAddr::V6(a)) => {
                        out.push(ATYP_V6);
                        out.extend_from_slice(&a.ip().octets());
                    }
                    Target::Domain(d, _) => {
                        out.push(ATYP_DOMAIN);
                        out.push(d.len() as u8);
                        out.extend_from_slice(d.as_bytes());
                    }
                }
                out.extend_from_slice(&target.port().to_be_bytes());
            }
            Request::Pair { secret, name } => {
                out.push(KIND_PAIR);
                out.extend_from_slice(secret);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
            }
        }
        out
    }

    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, ProtoError> {
        let version = r.read_u8().await?;
        if version != VERSION {
            return Err(ProtoError::Version(version));
        }
        match r.read_u8().await? {
            KIND_CONNECT => {
                let target = match r.read_u8().await? {
                    ATYP_V4 => {
                        let mut b = [0u8; 4];
                        r.read_exact(&mut b).await?;
                        let port = r.read_u16().await?;
                        Target::Addr(SocketAddr::new(Ipv4Addr::from(b).into(), port))
                    }
                    ATYP_V6 => {
                        let mut b = [0u8; 16];
                        r.read_exact(&mut b).await?;
                        let port = r.read_u16().await?;
                        Target::Addr(SocketAddr::new(Ipv6Addr::from(b).into(), port))
                    }
                    ATYP_DOMAIN => {
                        let len = r.read_u8().await? as usize;
                        let mut b = vec![0u8; len];
                        r.read_exact(&mut b).await?;
                        let d = String::from_utf8(b)
                            .map_err(|_| ProtoError::Malformed("domain not utf-8"))?;
                        if !valid_domain(&d) {
                            return Err(ProtoError::Malformed("invalid domain"));
                        }
                        let port = r.read_u16().await?;
                        Target::Domain(d, port)
                    }
                    _ => return Err(ProtoError::Malformed("unknown address type")),
                };
                if target.port() == 0 {
                    return Err(ProtoError::Malformed("port 0"));
                }
                Ok(Request::Connect(target))
            }
            KIND_PAIR => {
                let mut secret = [0u8; 32];
                r.read_exact(&mut secret).await?;
                let len = r.read_u8().await? as usize;
                if len > MAX_NAME_LEN {
                    return Err(ProtoError::Malformed("name too long"));
                }
                let mut b = vec![0u8; len];
                r.read_exact(&mut b).await?;
                let name =
                    String::from_utf8(b).map_err(|_| ProtoError::Malformed("name not utf-8"))?;
                if sanitize_name(&name) != name {
                    return Err(ProtoError::Malformed("invalid name"));
                }
                Ok(Request::Pair { secret, name })
            }
            _ => Err(ProtoError::Malformed("unknown request kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    /// Wrong or unknown invite secret.
    Denied = 1,
    /// Host could not reach the destination.
    Unreachable = 2,
    /// Destination is on the host's local network and that's not allowed.
    Blocked = 3,
    BadRequest = 4,
    /// Invite has expired.
    Expired = 5,
    /// Host user declined the pairing.
    Rejected = 6,
}

impl Status {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Status::Ok,
            1 => Status::Denied,
            2 => Status::Unreachable,
            3 => Status::Blocked,
            4 => Status::BadRequest,
            5 => Status::Expired,
            6 => Status::Rejected,
            _ => return None,
        })
    }

    pub fn describe(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Denied => "the invite code is not valid (already used or wrong)",
            Status::Unreachable => "the host could not reach that address",
            Status::Blocked => "the host does not allow access to its local network",
            Status::BadRequest => "the host did not understand the request",
            Status::Expired => "the invite code has expired, ask for a new one",
            Status::Rejected => "the host declined the request",
        }
    }
}

/// Hostname check: ASCII letters, digits, `-`, `_` and `.`, 1..=253 bytes.
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && !d.starts_with('.')
        && !d.contains("..")
}

/// Strip control characters and cut to [`MAX_NAME_LEN`] bytes on a char boundary.
pub fn sanitize_name(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_NAME_LEN {
            break;
        }
        out.push(c);
    }
    out
}

pub fn id_hex(id: &DeviceId) -> String {
    hex::encode(id)
}

/// Short form for display, e.g. `3f2a-91c0`.
pub fn short_id(id: &DeviceId) -> String {
    let h = hex::encode(&id[..4]);
    format!("{}-{}", &h[..4], &h[4..])
}

pub fn parse_id(s: &str) -> Option<DeviceId> {
    let v = hex::decode(s.trim()).ok()?;
    v.try_into().ok()
}

const INVITE_PREFIX: &str = "homelink1-";

/// One-time code a host gives to a new device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub host_id: DeviceId,
    pub secret: Secret,
    /// Unix seconds.
    pub expires: u64,
    /// Hostname (e.g. DDNS) or IP literal.
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("this is not a homelink invite code")]
    NotAnInvite,
    #[error("the invite code is damaged or incomplete")]
    Damaged,
}

impl Invite {
    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(32 + 32 + 8 + 2 + 1 + self.addr.len());
        b.extend_from_slice(&self.host_id);
        b.extend_from_slice(&self.secret);
        b.extend_from_slice(&self.expires.to_be_bytes());
        b.extend_from_slice(&self.port.to_be_bytes());
        b.push(self.addr.len() as u8);
        b.extend_from_slice(self.addr.as_bytes());
        format!(
            "{INVITE_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        )
    }

    pub fn decode(s: &str) -> Result<Self, InviteError> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let body = s.strip_prefix(INVITE_PREFIX).ok_or(InviteError::NotAnInvite)?;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| InviteError::Damaged)?;
        if b.len() < 75 {
            return Err(InviteError::Damaged);
        }
        let host_id: DeviceId = b[0..32].try_into().unwrap();
        let secret: Secret = b[32..64].try_into().unwrap();
        let expires = u64::from_be_bytes(b[64..72].try_into().unwrap());
        let port = u16::from_be_bytes(b[72..74].try_into().unwrap());
        let len = b[74] as usize;
        if b.len() != 75 + len || port == 0 {
            return Err(InviteError::Damaged);
        }
        let addr = String::from_utf8(b[75..].to_vec()).map_err(|_| InviteError::Damaged)?;
        if !valid_host_addr(&addr) {
            return Err(InviteError::Damaged);
        }
        Ok(Invite { host_id, secret, expires, addr, port })
    }
}

/// An IP literal or a valid hostname.
pub fn valid_host_addr(a: &str) -> bool {
    a.parse::<IpAddr>().is_ok() || valid_domain(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(req: Request) {
        let bytes = req.encode();
        let got = Request::read(&mut &bytes[..]).await.unwrap();
        assert_eq!(got, req);
    }

    #[tokio::test]
    async fn requests_roundtrip() {
        roundtrip(Request::Connect(Target::Addr("1.2.3.4:443".parse().unwrap()))).await;
        roundtrip(Request::Connect(Target::Addr("[2001:db8::1]:80".parse().unwrap()))).await;
        roundtrip(Request::Connect(Target::Domain("example.com".into(), 443))).await;
        roundtrip(Request::Pair { secret: [7; 32], name: "Bob's Mac".into() }).await;
    }

    #[tokio::test]
    async fn rejects_malformed() {
        let bad: &[&[u8]] = &[
            &[2, 1, 1, 1, 2, 3, 4, 0, 80], // wrong version
            &[1, 9],                       // unknown kind
            &[1, 1, 7],                    // unknown atyp
            &[1, 1, 1, 1, 2, 3, 4, 0, 0],  // port 0
            &[1, 1, 3, 3, b'a', b' ', b'b', 0, 80], // bad domain
            &[1, 1, 1, 1, 2],              // truncated
        ];
        for b in bad {
            assert!(Request::read(&mut &b[..]).await.is_err(), "{b:?}");
        }
        let mut long_name = vec![1, 2];
        long_name.extend_from_slice(&[0; 32]);
        long_name.push(65);
        long_name.extend_from_slice(&[b'a'; 65]);
        assert!(Request::read(&mut &long_name[..]).await.is_err());
    }

    #[test]
    fn invite_roundtrip_and_damage() {
        let inv = Invite {
            host_id: [1; 32],
            secret: [2; 32],
            expires: 1_800_000_000,
            addr: "home.example.net".into(),
            port: DEFAULT_PORT,
        };
        let code = inv.encode();
        assert_eq!(Invite::decode(&code).unwrap(), inv);
        assert_eq!(Invite::decode(&format!("  {code}\n")).unwrap(), inv);
        assert!(matches!(Invite::decode("hello"), Err(InviteError::NotAnInvite)));
        assert!(Invite::decode(&code[..code.len() - 3]).is_err());
    }

    #[test]
    fn names_and_ids() {
        assert_eq!(sanitize_name("  a\u{7}b  "), "ab");
        assert_eq!(sanitize_name(&"é".repeat(40)).len(), 64);
        let id = [0xab; 32];
        assert_eq!(parse_id(&id_hex(&id)), Some(id));
        assert_eq!(short_id(&id), "abab-abab");
    }
}
