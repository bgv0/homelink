//! Full-tunnel mode: all of this computer's traffic goes through the host.
//!
//! The app re-launches itself with admin rights in "helper" mode (macOS
//! password prompt, Windows UAC). The helper runs tun2proxy, which creates a
//! TUN device, points the default route and DNS at it, and forwards every TCP
//! connection to our local SOCKS5 server. The host's own IP is excluded so
//! the QUIC connection doesn't loop into the tunnel.
//!
//! The app and helper talk through small files in the data folder:
//! - `tun.heartbeat`: the app touches it every few seconds. If it goes stale
//!   (app quit or crashed), the helper tears the tunnel down and restores
//!   routes and DNS.
//! - `tun.status`: the helper writes `running`, `stopped`, `restored` or
//!   `error: ...`.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::task::JoinHandle;

pub const HELPER_FLAG: &str = "--tun-helper";
const HEARTBEAT: &str = "tun.heartbeat";
const STATUS: &str = "tun.status";
const HEARTBEAT_EVERY: Duration = Duration::from_secs(3);
const HEARTBEAT_STALE: Duration = Duration::from_secs(15);

fn read_status(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(STATUS)).ok().map(|s| s.trim().to_string())
}

fn write_status(dir: &Path, s: &str) {
    let _ = std::fs::write(dir.join(STATUS), s);
}

// ---------------------------------------------------------------------------
// Helper side (runs elevated)
// ---------------------------------------------------------------------------

struct HelperArgs {
    socks: Option<SocketAddr>,
    bypass: Vec<IpAddr>,
    dir: Option<PathBuf>,
    restore: bool,
}

fn parse_helper_args(args: &[String]) -> Result<HelperArgs, String> {
    let mut out = HelperArgs { socks: None, bypass: Vec::new(), dir: None, restore: false };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--socks" => out.socks = Some(value()?.parse().map_err(|_| "bad --socks")?),
            "--bypass" => out.bypass.push(value()?.parse().map_err(|_| "bad --bypass")?),
            "--dir" => out.dir = Some(PathBuf::from(value()?)),
            "--restore" => out.restore = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(out)
}

fn heartbeat_stale(dir: &Path) -> bool {
    std::fs::metadata(dir.join(HEARTBEAT))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_none_or(|age| age > HEARTBEAT_STALE)
}

/// Entry point when the app is started with [`HELPER_FLAG`]. Returns an exit code.
pub fn helper_main(args: &[String]) -> i32 {
    let args = match parse_helper_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("homelink tunnel helper: {e}");
            return 2;
        }
    };
    let Some(dir) = args.dir.clone() else {
        eprintln!("homelink tunnel helper: --dir is required");
        return 2;
    };
    // Windows looks for wintun.dll next to the app; make that the working dir too.
    if let Some(exe_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        let _ = std::env::set_current_dir(exe_dir);
    }
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            write_status(&dir, &format!("error: {e}"));
            return 1;
        }
    };
    let code = rt.block_on(run_helper(args, dir));
    // Let tproxy-config's restore task (spawned on drop) finish.
    rt.shutdown_timeout(Duration::from_secs(5));
    code
}

async fn run_helper(args: HelperArgs, dir: PathBuf) -> i32 {
    // Undo anything a previous helper left behind if it was killed.
    let _ = tproxy_config::tproxy_remove(None).await;
    if args.restore {
        write_status(&dir, "restored");
        return 0;
    }
    let Some(socks) = args.socks else {
        write_status(&dir, "error: --socks is required");
        return 2;
    };

    let mut targs = vec![
        "homelink".to_string(),
        "--proxy".into(),
        format!("socks5://{socks}"),
        "--setup".into(),
        // Names are resolved by the host: tun2proxy hands out placeholder IPs
        // and sends the hostname over SOCKS, so DNS can't leak.
        "--dns".into(),
        "virtual".into(),
    ];
    for ip in &args.bypass {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        targs.push("--bypass".into());
        targs.push(format!("{ip}/{prefix}"));
    }
    let t2p = match <tun2proxy::Args as clap::Parser>::try_parse_from(&targs) {
        Ok(a) => a,
        Err(e) => {
            write_status(&dir, &format!("error: {e}"));
            return 2;
        }
    };

    let token = tun2proxy::CancellationToken::new();
    tokio::spawn({
        let token = token.clone();
        let dir = dir.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if heartbeat_stale(&dir) {
                    token.cancel();
                    break;
                }
            }
        }
    });
    tokio::spawn({
        let token = token.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            token.cancel();
        }
    });

    write_status(&dir, "running");
    match tun2proxy::general_run_async(t2p, tun2proxy::DEFAULT_MTU, false, token).await {
        Ok(_) => {
            write_status(&dir, "stopped");
            0
        }
        Err(e) => {
            write_status(&dir, &format!("error: {e}"));
            1
        }
    }
}

// ---------------------------------------------------------------------------
// App side
// ---------------------------------------------------------------------------

/// A running full tunnel. Call [`Tunnel::stop`] to tear it down.
pub struct Tunnel {
    dir: PathBuf,
    beat: JoinHandle<()>,
}

fn touch(path: &Path) {
    let _ = std::fs::write(path, b"");
}

fn start_heartbeat(dir: &Path) -> JoinHandle<()> {
    let path = dir.join(HEARTBEAT);
    touch(&path);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEARTBEAT_EVERY).await;
            touch(&path);
        }
    })
}

impl Tunnel {
    /// Ask for admin rights and start routing everything through `socks`.
    /// `host_ip` is excluded from the tunnel.
    pub async fn start(dir: &Path, socks: SocketAddr, host_ip: IpAddr) -> Result<Tunnel, String> {
        let _ = std::fs::remove_file(dir.join(STATUS));
        let beat = start_heartbeat(dir);
        let args = vec![
            HELPER_FLAG.to_string(),
            "--socks".into(),
            socks.to_string(),
            "--bypass".into(),
            host_ip.to_string(),
            "--dir".into(),
            dir.display().to_string(),
        ];
        let launched = tokio::task::spawn_blocking(move || launch_elevated(&args))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
        if let Err(e) = launched {
            beat.abort();
            let _ = std::fs::remove_file(dir.join(HEARTBEAT));
            return Err(e);
        }
        let tunnel = Tunnel { dir: dir.to_path_buf(), beat };
        match wait_for(dir, &["running"], Duration::from_secs(20)).await {
            Ok(_) => {
                // Route setup failures show up within a moment of starting.
                tokio::time::sleep(Duration::from_secs(3)).await;
                match read_status(dir) {
                    Some(s) if s == "running" => Ok(tunnel),
                    Some(s) => {
                        tunnel.stop().await;
                        Err(helper_error(&s))
                    }
                    None => {
                        tunnel.stop().await;
                        Err("The tunnel helper stopped unexpectedly.".into())
                    }
                }
            }
            Err(e) => {
                tunnel.stop().await;
                Err(e)
            }
        }
    }

    pub async fn stop(self) {
        self.beat.abort();
        let _ = std::fs::remove_file(self.dir.join(HEARTBEAT));
        // The helper notices within a couple of seconds and restores the network.
        let _ = wait_for(&self.dir, &["stopped"], Duration::from_secs(8)).await;
    }

    /// Whether the helper reported a failure after starting.
    pub fn failed(&self) -> Option<String> {
        read_status(&self.dir).filter(|s| s.starts_with("error")).map(|s| helper_error(&s))
    }
}

fn helper_error(status: &str) -> String {
    format!(
        "Full tunnel failed: {}",
        status.strip_prefix("error:").unwrap_or(status).trim()
    )
}

/// Wait until the status file holds one of `want` (or an error).
async fn wait_for(dir: &Path, want: &[&str], limit: Duration) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if let Some(s) = read_status(dir) {
            if want.contains(&s.as_str()) {
                return Ok(s);
            }
            if s.starts_with("error") {
                return Err(helper_error(&s));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("The tunnel helper didn't start in time.".into());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Restore routes and DNS after a crash ("my internet stopped working").
pub async fn repair(dir: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(dir.join(STATUS));
    let args = vec![HELPER_FLAG.to_string(), "--restore".into(), "--dir".into(), dir.display().to_string()];
    tokio::task::spawn_blocking(move || launch_elevated(&args))
        .await
        .map_err(|e| e.to_string())??;
    wait_for(dir, &["restored"], Duration::from_secs(20)).await.map(|_| ())
}

#[cfg(target_os = "macos")]
fn launch_elevated(args: &[String]) -> Result<(), String> {
    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
    fn applescript_quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = shell_quote(&exe.display().to_string());
    for a in args {
        cmd.push(' ');
        cmd.push_str(&shell_quote(a));
    }
    // Run in the background so the prompt returns once the helper starts.
    cmd.push_str(" >/dev/null 2>&1 &");
    let script = format!(
        "do shell script {} with prompt {} with administrator privileges",
        applescript_quote(&cmd),
        applescript_quote("homelink needs your password to send all traffic through the host.")
    );
    let out = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else if String::from_utf8_lossy(&out.stderr).contains("-128") {
        Err("Cancelled.".into())
    } else {
        Err(format!("Couldn't get admin rights: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

#[cfg(windows)]
fn launch_elevated(args: &[String]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // PowerShell single-quoted strings escape ' as ''. Each argument is
    // wrapped in double quotes for the Windows command line.
    let ps = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let arg_list = args
        .iter()
        .map(|a| format!("\"{}\"", a.replace('"', "")))
        .collect::<Vec<_>>()
        .join(" ");
    let command = format!(
        "Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden",
        ps(&exe.display().to_string()),
        ps(&arg_list)
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("canceled") || err.contains("cancelled") {
            Err("Cancelled.".into())
        } else {
            Err(format!("Couldn't get admin rights: {}", err.trim()))
        }
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn launch_elevated(_: &[String]) -> Result<(), String> {
    Err("Full tunnel is only supported on macOS and Windows.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_helper_args() {
        let a: Vec<String> = ["--socks", "127.0.0.1:1080", "--bypass", "203.0.113.5", "--dir", "/tmp/x"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let p = parse_helper_args(&a).unwrap();
        assert_eq!(p.socks, Some("127.0.0.1:1080".parse().unwrap()));
        assert_eq!(p.bypass, vec!["203.0.113.5".parse::<IpAddr>().unwrap()]);
        assert!(!p.restore);
        assert!(parse_helper_args(&["--bogus".to_string()]).is_err());
        assert!(parse_helper_args(&["--socks".to_string()]).is_err());
    }

    #[test]
    fn builds_tun2proxy_args() {
        let a = ["homelink", "--proxy", "socks5://127.0.0.1:1080", "--setup", "--dns", "virtual", "--bypass", "203.0.113.5/32"];
        let parsed = <tun2proxy::Args as clap::Parser>::try_parse_from(a).unwrap();
        assert!(parsed.setup);
        assert_eq!(parsed.bypass.len(), 1);
    }

    #[test]
    fn stale_heartbeat() {
        let d = std::env::temp_dir().join(format!("hl-tun-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(heartbeat_stale(&d), "missing heartbeat is stale");
        touch(&d.join(HEARTBEAT));
        assert!(!heartbeat_stale(&d));
        let _ = std::fs::remove_dir_all(&d);
    }
}
