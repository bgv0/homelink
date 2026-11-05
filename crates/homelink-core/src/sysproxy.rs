//! Point the OS proxy setting at the local SOCKS5 server.
//!
//! Apps that follow the system proxy (browsers and most desktop apps) then go
//! through the host. Apps that ignore it don't; full-tunnel (TUN) mode is a
//! separate, later feature. A marker file records what we changed so a crash
//! can be undone on next start ([`recover`]).

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const MARKER: &str = "sysproxy.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    /// macOS network services we turned the SOCKS proxy on for.
    #[serde(default)]
    services: Vec<String>,
    /// Windows: previous ProxyServer / ProxyEnable values.
    #[serde(default)]
    prev_server: Option<String>,
    #[serde(default)]
    prev_enable: Option<u32>,
}

pub fn enable(dir: &Path, socks: SocketAddr) -> Result<()> {
    // Undo any earlier change first so we never lose the original settings.
    let _ = disable(dir);
    let saved = platform::enable(socks)?;
    std::fs::write(dir.join(MARKER), serde_json::to_vec(&saved)?)?;
    Ok(())
}

pub fn disable(dir: &Path) -> Result<()> {
    let path = dir.join(MARKER);
    let Ok(bytes) = std::fs::read(&path) else { return Ok(()) };
    let saved: Saved = serde_json::from_slice(&bytes).unwrap_or_default();
    platform::disable(&saved)?;
    std::fs::remove_file(&path).context("removing proxy marker")?;
    Ok(())
}

/// Undo a system proxy change left behind by a crash.
pub fn recover(dir: &Path) {
    if let Err(e) = disable(dir) {
        tracing::warn!("couldn't restore proxy settings: {e:#}");
    }
}

pub fn is_enabled(dir: &Path) -> bool {
    dir.join(MARKER).exists()
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use anyhow::bail;
    use std::process::Command;

    fn networksetup(args: &[&str]) -> Result<String> {
        let out = Command::new("/usr/sbin/networksetup").args(args).output()?;
        if !out.status.success() {
            bail!(
                "macOS refused to change network settings: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn services() -> Result<Vec<String>> {
        let out = networksetup(&["-listallnetworkservices"])?;
        Ok(out
            .lines()
            .skip(1) // "An asterisk (*) denotes that a network service is disabled."
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .map(str::to_string)
            .collect())
    }

    pub fn enable(socks: SocketAddr) -> Result<Saved> {
        let ip = socks.ip().to_string();
        let port = socks.port().to_string();
        let mut done = Vec::new();
        for svc in services()? {
            let r = networksetup(&["-setsocksfirewallproxy", &svc, &ip, &port])
                .and_then(|_| networksetup(&["-setsocksfirewallproxystate", &svc, "on"]));
            match r {
                Ok(_) => done.push(svc),
                Err(e) => {
                    disable(&Saved { services: done, ..Default::default() }).ok();
                    return Err(e);
                }
            }
        }
        Ok(Saved { services: done, ..Default::default() })
    }

    pub fn disable(saved: &Saved) -> Result<()> {
        for svc in &saved.services {
            networksetup(&["-setsocksfirewallproxystate", svc, "off"])?;
        }
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use anyhow::bail;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn reg(args: &[&str]) -> Result<String> {
        let out = Command::new("reg").args(args).creation_flags(CREATE_NO_WINDOW).output()?;
        if !out.status.success() {
            bail!("couldn't change proxy settings: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Value of a registry entry from `reg query` output, if present.
    fn query(name: &str) -> Option<String> {
        let out = reg(&["query", KEY, "/v", name]).ok()?;
        out.lines()
            .find(|l| l.trim_start().starts_with(name))
            .and_then(|l| l.split("    ").filter(|s| !s.trim().is_empty()).nth(2))
            .map(|s| s.trim().to_string())
    }

    pub fn enable(socks: SocketAddr) -> Result<Saved> {
        let prev_server = query("ProxyServer");
        let prev_enable = query("ProxyEnable")
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok());
        let server = format!("socks={socks}");
        reg(&["add", KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &server, "/f"])?;
        reg(&["add", KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"])?;
        Ok(Saved { prev_server, prev_enable, ..Default::default() })
    }

    pub fn disable(saved: &Saved) -> Result<()> {
        match &saved.prev_server {
            Some(s) => reg(&["add", KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", s, "/f"])?,
            None => reg(&["delete", KEY, "/v", "ProxyServer", "/f"]).unwrap_or_default(),
        };
        let enable = saved.prev_enable.unwrap_or(0).to_string();
        reg(&["add", KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", &enable, "/f"])?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod platform {
    use super::*;
    pub fn enable(_: SocketAddr) -> Result<Saved> {
        anyhow::bail!("system proxy is only supported on macOS and Windows")
    }
    pub fn disable(_: &Saved) -> Result<()> {
        Ok(())
    }
}
