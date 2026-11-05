//! Log file and the "Copy diagnostics" report.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub const LOG_FILE: &str = "homelink.log";
/// Rotate the log at startup once it passes this size (keeps one old file).
const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

/// Log to `homelink.log` in the data folder (GUI apps have no console).
pub fn init_logging(dir: &Path) {
    let path = dir.join(LOG_FILE);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
        let _ = std::fs::rename(&path, dir.join(format!("{LOG_FILE}.old")));
    }
    let filter = tracing_subscriber::EnvFilter::try_from_env("HOMELINK_LOG")
        .unwrap_or_else(|_| "warn,homelink_core=info,homelink_desktop=info".into());
    let file = std::fs::OpenOptions::new().create(true).append(true).open(&path);
    match file {
        Ok(f) => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .init(),
        Err(_) => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}

/// Last `n` lines of the log, with IP addresses masked.
pub fn log_tail(dir: &Path, n: usize) -> String {
    let text = std::fs::read_to_string(dir.join(LOG_FILE)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    mask_ips(&lines[start..].join("\n"))
}

/// Hide most of every IP address: `203.0.113.7` → `203.0.x.x`, IPv6 → `[IPv6]`.
pub fn mask_ips(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.is_empty() {
            return;
        }
        // Strip trailing punctuation like "1.2.3.4." or "::" at sentence ends.
        let trimmed = token.trim_end_matches(['.', ':']);
        let tail = &token[trimmed.len()..];
        let mask_v4 = |ip: Ipv4Addr| {
            let o = ip.octets();
            format!("{}.{}.x.x", o[0], o[1])
        };
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            out.push_str(&mask_v4(ip));
            out.push_str(tail);
        } else if let Some(ip) = trimmed
            .split_once(':')
            .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|(a, _)| a.parse::<Ipv4Addr>().ok())
        {
            // "1.2.3.4:5678"
            let port = &trimmed[trimmed.find(':').unwrap()..];
            out.push_str(&mask_v4(ip));
            out.push_str(port);
            out.push_str(tail);
        } else if trimmed.matches(':').count() >= 2 && trimmed.parse::<Ipv6Addr>().is_ok() {
            out.push_str("[IPv6]");
            out.push_str(tail);
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in text.chars() {
        if c.is_ascii_hexdigit() || c == '.' || c == ':' {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_addresses() {
        assert_eq!(mask_ips("from 203.0.113.7:47420 ok"), "from 203.0.x.x:47420 ok");
        assert_eq!(mask_ips("peer 2001:db8::1 left"), "peer [IPv6] left");
        assert_eq!(mask_ips("at 10.0.0.1."), "at 10.0.x.x.");
        assert_eq!(mask_ips("version 0.1.0 and 12:30"), "version 0.1.0 and 12:30");
        assert_eq!(mask_ips("deadbeef"), "deadbeef");
    }
}
