//! Addresses a paired device may not reach through the host unless the host
//! user turned on local network access.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_v4(v4);
            }
            is_local_v6(v6)
        }
    }
}

fn is_local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 shared address space
        || o[0] >= 240 // reserved
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
}

fn is_local_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
        || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site local (deprecated)
        || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64 can map to private v4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies() {
        for a in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.1.1", "100.96.0.1",
            "0.0.0.0", "255.255.255.255", "224.0.0.1", "::1", "fe80::1", "fd00::1",
            "::ffff:192.168.1.1", "64:ff9b::a00:1",
        ] {
            assert!(is_local(a.parse().unwrap()), "{a} should be local");
        }
        for a in ["1.1.1.1", "8.8.8.8", "100.128.0.1", "2606:4700::1111"] {
            assert!(!is_local(a.parse().unwrap()), "{a} should be public");
        }
    }
}
