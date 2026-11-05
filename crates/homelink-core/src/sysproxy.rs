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

/// Local destinations that skip the proxy, so the router page, printers and
/// other LAN devices keep working while connected. (Windows uses its own
/// WinINET syntax, see `override_list`.)
#[cfg(target_os = "macos")]
const BYPASS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "*.local",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

#[derive(Debug, Default, Serialize, Deserialize)]
struct Saved {
    /// macOS network services we turned the SOCKS proxy on for.
    #[serde(default)]
    services: Vec<String>,
    /// macOS: each service's bypass list before we changed it.
    #[serde(default)]
    prev_bypass: std::collections::HashMap<String, Vec<String>>,
    /// Windows: previous ProxyServer / ProxyEnable values.
    #[serde(default)]
    prev_server: Option<String>,
    #[serde(default)]
    prev_enable: Option<u32>,
    #[serde(default)]
    prev_override: Option<String>,
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

    fn bypass_list(svc: &str) -> Vec<String> {
        // Prints "There aren't any bypass domains set on <svc>." when empty.
        networksetup(&["-getproxybypassdomains", svc])
            .map(|out| {
                out.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.contains(' '))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_bypass(svc: &str, list: &[String]) -> Result<()> {
        let mut args = vec!["-setproxybypassdomains", svc];
        if list.is_empty() {
            args.push("Empty");
        } else {
            args.extend(list.iter().map(String::as_str));
        }
        networksetup(&args).map(|_| ())
    }

    pub fn enable(socks: SocketAddr) -> Result<Saved> {
        let ip = socks.ip().to_string();
        let port = socks.port().to_string();
        let mut saved = Saved::default();
        for svc in services()? {
            let prev = bypass_list(&svc);
            let mut list = prev.clone();
            for b in BYPASS {
                if !list.iter().any(|x| x == b) {
                    list.push(b.to_string());
                }
            }
            let r = set_bypass(&svc, &list)
                .and_then(|_| networksetup(&["-setsocksfirewallproxy", &svc, &ip, &port]))
                .and_then(|_| networksetup(&["-setsocksfirewallproxystate", &svc, "on"]));
            saved.prev_bypass.insert(svc.clone(), prev);
            saved.services.push(svc);
            if let Err(e) = r {
                disable(&saved).ok();
                return Err(e);
            }
        }
        Ok(saved)
    }

    pub fn disable(saved: &Saved) -> Result<()> {
        let mut first_err = None;
        for svc in &saved.services {
            let r = networksetup(&["-setsocksfirewallproxystate", svc, "off"]).map(|_| ());
            let r2 = match saved.prev_bypass.get(svc) {
                Some(prev) => set_bypass(svc, prev),
                None => Ok(()),
            };
            if let Err(e) = r.and(r2) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
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

    /// WinINET override list: our local ranges plus whatever was there.
    fn override_list(prev: Option<&str>) -> String {
        let mut items: Vec<String> = prev
            .unwrap_or("")
            .split(';')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let mut ours = vec![
            "<local>".to_string(),
            "localhost".into(),
            "127.*".into(),
            "10.*".into(),
            "192.168.*".into(),
            "169.254.*".into(),
        ];
        ours.extend((16..32).map(|n| format!("172.{n}.*")));
        for o in ours {
            if !items.contains(&o) {
                items.push(o);
            }
        }
        items.join(";")
    }

    fn restore(name: &str, prev: &Option<String>) -> Result<()> {
        match prev {
            Some(s) => reg(&["add", KEY, "/v", name, "/t", "REG_SZ", "/d", s, "/f"]).map(|_| ()),
            None => {
                let _ = reg(&["delete", KEY, "/v", name, "/f"]);
                Ok(())
            }
        }
    }

    pub fn enable(socks: SocketAddr) -> Result<Saved> {
        let prev_server = query("ProxyServer");
        let prev_override = query("ProxyOverride");
        let prev_enable = query("ProxyEnable")
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok());
        let saved = Saved { prev_server, prev_enable, prev_override, ..Default::default() };
        let server = format!("socks={socks}");
        let over = override_list(saved.prev_override.as_deref());
        let r = reg(&["add", KEY, "/v", "ProxyServer", "/t", "REG_SZ", "/d", &server, "/f"])
            .and_then(|_| reg(&["add", KEY, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", &over, "/f"]))
            .and_then(|_| reg(&["add", KEY, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"]));
        if let Err(e) = r {
            disable(&saved).ok();
            return Err(e);
        }
        Ok(saved)
    }

    pub fn disable(saved: &Saved) -> Result<()> {
        restore("ProxyServer", &saved.prev_server)?;
        restore("ProxyOverride", &saved.prev_override)?;
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
