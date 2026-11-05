use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use homelink_core::client::{self, Client};
use homelink_core::host::{self, Approver, HostEvent, HostOptions, PairRequest};
use homelink_core::portmap::{MapState, PortMapper};
use homelink_core::proto::{self, short_id, Invite};
use homelink_core::store::{HostSettings, Store};
use homelink_core::{portmap, reach, socks, stun};

#[derive(Parser)]
#[command(name = "homelink", version, about = "Share your internet connection directly with your own devices")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Share this computer's internet connection (host).
    Host {
        /// UDP port to listen on (saved for next time).
        #[arg(long)]
        port: Option<u16>,
        /// DDNS hostname or fixed address to put in invites (saved). Empty clears it.
        #[arg(long)]
        address: Option<String>,
        /// Let connected devices reach this computer's local network (saved).
        #[arg(long)]
        allow_lan: Option<bool>,
        /// Try to forward the port automatically with UPnP (saved).
        #[arg(long)]
        upnp: Option<bool>,
        /// Pair new devices without asking (saved).
        #[arg(long)]
        auto_approve: Option<bool>,
    },
    /// Create a one-time invite code for a new device.
    Invite {
        /// Minutes until the code expires.
        #[arg(long, default_value_t = 15)]
        minutes: u64,
    },
    /// List devices allowed to use this host.
    Devices,
    /// Remove a device (give the start of its id).
    Revoke { id: String },
    /// Pair with a host using its invite code.
    Add {
        invite: String,
        /// Name to save the host under.
        #[arg(long)]
        name: Option<String>,
        /// Name the host will see for this device.
        #[arg(long)]
        device_name: Option<String>,
    },
    /// List saved hosts.
    Hosts,
    /// Forget a saved host.
    Remove { name: String },
    /// Change a saved host's address (e.g. after its IP changed).
    SetAddress {
        name: String,
        address: String,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Connect to a host and run a local SOCKS5 proxy.
    Connect {
        /// Saved host name (optional if there's only one).
        host: Option<String>,
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: SocketAddr,
    },
    /// Check whether this network can accept incoming connections.
    Check,
    /// Show this device's id and data folder.
    Id,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HOMELINK_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .init();
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let store = Store::open_default()?;
    match cli.cmd {
        Cmd::Host { port, address, allow_lan, upnp, auto_approve } => {
            let mut s = store.settings()?;
            if let Some(p) = port {
                if p == 0 {
                    bail!("port must be 1-65535");
                }
                s.port = p;
            }
            if let Some(a) = address {
                if a.is_empty() {
                    s.public_addr = None;
                } else if proto::valid_host_addr(&a) {
                    s.public_addr = Some(a);
                } else {
                    bail!("'{a}' isn't a valid hostname or IP address");
                }
            }
            if let Some(v) = allow_lan {
                s.allow_lan = v;
            }
            if let Some(v) = upnp {
                s.upnp = v;
            }
            if let Some(v) = auto_approve {
                s.require_approval = !v;
            }
            store.save_settings(&s)?;
            run_host(store, s).await
        }
        Cmd::Invite { minutes } => {
            let s = store.settings()?;
            let addr = match s.public_addr.clone() {
                Some(a) => a,
                None => stun::public_ip()
                    .await
                    .context("couldn't detect your public IP; set one with `homelink host --address`")?
                    .to_string(),
            };
            let id = store.identity()?.id;
            let inv = store.create_invite(id, addr.clone(), s.port, minutes.max(1) * 60)?;
            println!("Invite code (single use, expires in {minutes} min):\n\n{}\n", inv.encode());
            println!("It points to {addr}:{}. On the other device run: homelink add <code>", s.port);
            Ok(())
        }
        Cmd::Devices => {
            let devices = store.devices()?;
            if devices.is_empty() {
                println!("No devices yet. Create an invite with `homelink invite`.");
            }
            for d in devices {
                let id = d.device_id().map(|i| short_id(&i)).unwrap_or_default();
                println!("{id}  {}", d.name);
            }
            Ok(())
        }
        Cmd::Revoke { id } => {
            let gone = store.revoke(&id)?;
            match gone.first() {
                Some(d) => println!("Removed {}. A running host disconnects it within seconds.", d.name),
                None => println!("No device matches '{id}'."),
            }
            Ok(())
        }
        Cmd::Add { invite, name, device_name } => {
            let inv = Invite::decode(&invite)?;
            let identity = store.identity()?;
            let device_name = device_name.unwrap_or_else(computer_name);
            println!("Contacting {}:{} ... the host may need to approve this device.", inv.addr, inv.port);
            let name = name.or_else(|| store.host_by_id(&inv.host_id).map(|h| h.name));
            let saved = client::pair(&identity, &inv, &device_name, name.as_deref()).await?;
            println!("Paired. Saved as '{}'. Connect with: homelink connect", saved.name);
            store.save_host(saved)?;
            Ok(())
        }
        Cmd::Hosts => {
            let hosts = store.hosts()?;
            if hosts.is_empty() {
                println!("No saved hosts. Add one with `homelink add <invite code>`.");
            }
            for h in hosts {
                println!("{}  {}:{}", h.name, h.addr, h.port);
            }
            Ok(())
        }
        Cmd::Remove { name } => {
            if store.remove_host(&name)? {
                println!("Forgot {name}.");
            } else {
                println!("No saved host called {name}.");
            }
            Ok(())
        }
        Cmd::SetAddress { name, address, port } => {
            let current = store.find_host(Some(&name))?;
            store.update_host_address(&name, &address, port.unwrap_or(current.port))?;
            println!("{name} now points to {address}:{}.", port.unwrap_or(current.port));
            Ok(())
        }
        Cmd::Connect { host, socks: socks_addr } => {
            if !socks_addr.ip().is_loopback() {
                bail!("the SOCKS proxy must listen on 127.0.0.1 or ::1");
            }
            let saved = store.find_host(host.as_deref())?;
            let client = Arc::new(Client::new(&store.identity()?, saved)?);
            let transport = client.check().await?;
            let listener = tokio::net::TcpListener::bind(socks_addr)
                .await
                .with_context(|| format!("couldn't listen on {socks_addr}"))?;
            let via = match transport {
                client::Transport::Quic => "",
                client::Transport::Tcp => " over TCP (UDP seems blocked here)",
            };
            println!("Connected to {}{via}. SOCKS5 proxy on {socks_addr} (Ctrl-C to stop).", client.host.name);
            tokio::select! {
                r = socks::serve(client.clone(), listener) => r?,
                _ = tokio::signal::ctrl_c() => {}
            }
            client.disconnect().await;
            Ok(())
        }
        Cmd::Check => {
            println!("Checking ...");
            let r = reach::check().await;
            let show = |ip: Option<IpAddr>| ip.map(|i| i.to_string()).unwrap_or_else(|| "unknown".into());
            println!("This computer (LAN):  {}", show(r.lan_ip));
            println!("Public address:       {}", show(r.public_ip));
            let auto = match (r.upnp, r.natpmp) {
                (true, _) => "available (UPnP)",
                (false, true) => "available (NAT-PMP)",
                _ => "not available",
            };
            println!("Automatic forwarding: {auto}");
            println!("Router WAN address:   {}", show(r.router_wan_ip));
            println!("\n{}", r.verdict.describe());
            Ok(())
        }
        Cmd::Id => {
            let id = store.identity()?.id;
            println!("Device id: {} ({})", proto::id_hex(&id), short_id(&id));
            println!("Data folder: {}", store.dir().display());
            Ok(())
        }
    }
}

async fn run_host(store: Store, s: HostSettings) -> Result<()> {
    let mut opts = HostOptions::from_settings(&s);
    let public = stun::public_ip().await;
    if let Some(ip) = public {
        opts.blocked.push(ip);
    }
    let handle = host::start(store.clone(), opts, cli_approver()).await?;
    let ip_watch = reach::PublicIpWatch::start(public, std::time::Duration::from_secs(300));
    if s.public_addr.is_none() {
        let mut rx = ip_watch.ip.clone();
        let port = s.port;
        tokio::spawn(async move {
            while rx.changed().await.is_ok() {
                if let Some(ip) = *rx.borrow() {
                    println!(
                        "Your public address changed to {ip}. Devices need it: run `homelink set-address <host> {ip} --port {port}` on each, or send a new invite."
                    );
                }
            }
        });
    }
    let id = store.identity()?.id;
    println!(
        "Sharing on port {} ({}) (device {}).",
        handle.local_addr.port(),
        if handle.tcp_enabled { "UDP + TCP" } else { "UDP only: TCP port in use" },
        short_id(&id)
    );
    match (&s.public_addr, public) {
        (Some(a), _) => println!("Invites will point to {a}:{}.", s.port),
        (None, Some(ip)) => println!(
            "Public address: {ip}. Tip: set a DDNS name with --address so invites survive IP changes."
        ),
        (None, None) => println!("Couldn't detect a public address. Set one with --address."),
    }
    if !s.allow_lan {
        println!("Connected devices can't reach your local network (change with --allow-lan true).");
    }

    let mapper = s.upnp.then(|| PortMapper::start(s.port));
    if let Some(m) = &mapper {
        let mut state = m.state.clone();
        let port = s.port;
        tokio::spawn(async move {
            while state.changed().await.is_ok() {
                let msg = match &*state.borrow() {
                    MapState::Trying => continue,
                    MapState::Mapped { .. } => "Router: port forwarded automatically.".to_string(),
                    MapState::Unavailable(e) => format!(
                        "Router: {e}. Forward UDP and TCP {port} to {} on your router by hand.",
                        portmap::lan_ip().map(|i| i.to_string()).unwrap_or_else(|| "this computer".into())
                    ),
                };
                println!("{msg}");
            }
        });
    } else {
        println!("Forward UDP and TCP {} to this computer on your router.", s.port);
    }

    let mut events = handle.subscribe();
    tokio::spawn(async move {
        while let Ok(e) = events.recv().await {
            match e {
                HostEvent::Connected { name, .. } => println!("{name} connected."),
                HostEvent::Disconnected { name, .. } => println!("{name} disconnected."),
                HostEvent::Paired { name, .. } => println!("Paired new device: {name}."),
                HostEvent::PairDeclined { name } => println!("Declined pairing from {name}."),
                HostEvent::Revoked { name, .. } => println!("Removed {name}."),
            }
        }
    });

    println!("Create an invite in another terminal with `homelink invite`. Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    println!("Stopping ...");
    drop(ip_watch);
    handle.shutdown().await;
    if let Some(m) = mapper {
        m.stop().await;
    }
    Ok(())
}

/// Ask on the terminal, one prompt at a time.
fn cli_approver() -> Approver {
    let lock = Arc::new(Mutex::new(()));
    Arc::new(move |req: PairRequest| {
        let lock = lock.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let _g = lock.lock().unwrap();
                print!("\nAllow '{}' ({}) to use your connection? [y/N] ", req.name, short_id(&req.id));
                let _ = std::io::stdout().flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).is_ok()
                    && matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
            })
            .await
            .unwrap_or(false)
        })
    })
}

fn computer_name() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| proto::sanitize_name(s.trim().trim_end_matches(".local")))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "device".into())
}
