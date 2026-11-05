# homelink

Share your home internet connection with your own devices (or friends') through
a direct, encrypted connection. One app for **macOS and Windows**: either
computer can **Share** (host) or **Connect** (client).

```text
Client apps → system proxy or TUN → local SOCKS5 → QUIC, direct and encrypted
           → host's forwarded UDP port → host → internet
```

- No accounts, no relays, no servers in between. The client talks straight to
  the host's forwarded port.
- Devices join with a one-time invite code; the host approves each one and can
  remove it at any time.
- By default, connected devices can't reach the host's local network.

## Status

Early preview. It builds and its automated tests pass on macOS and Windows,
but it **hasn't been tried on real networks yet**. See [the plan](docs/PLAN.md).

## Requirements

- The host needs a public IPv4 address and port forwarding (UDP 47420 by
  default). homelink tries UPnP to forward the port automatically. **CGNAT
  connections can't host**; use *Network check* in the app to find out.
- Networks that block UDP (some schools, hotels, offices) can't connect yet.
- Speed is limited by the host's upload bandwidth.
- Firewalls: the Windows installer adds an inbound UDP rule for homelink. On
  macOS, if the firewall is on, allow incoming connections when asked.
- Connect has three modes:
  - **System proxy** (default, no password): browsers and most apps follow it,
    some apps and games don't.
  - **Full tunnel** (asks for your admin password each time): all TCP traffic
    and DNS go through the host. UDP apps (some games, video calls) don't work
    through it yet. On macOS, IPv6 isn't routed into the tunnel yet.
  - **SOCKS5 only**: point apps at 127.0.0.1:1080 yourself.
- If your internet stops working after homelink crashed in full-tunnel mode,
  use **Connect → Trouble? → Repair network settings**.

## Installing preview builds

Preview builds aren't signed by Apple or Microsoft yet, so the system warns:

- **macOS**: open the `.dmg`, drag homelink to Applications, open it once,
  then go to **System Settings → Privacy & Security** and click **Open Anyway**.
- **Windows**: if SmartScreen appears, click **More info → Run anyway**. The
  installer asks for admin rights once (to add the firewall rule).

## Using the app

1. On the host: **Share → Start sharing**. Check the router line says the port
   is forwarded (or forward UDP 47420 to the computer by hand).
2. **Invite a device**, copy the code, and send it to the other device.
3. On the other device: **Connect → Add a host**, paste the code. Approve it on
   the host.
4. Click **Connect**.

Tip: if your home IP changes, set a DDNS hostname in *Sharing settings* so
invites and saved hosts keep working.

## Command line

```sh
homelink host                 # share (Ctrl-C to stop)
homelink invite               # one-time code
homelink add <code>           # on the other device
homelink connect              # SOCKS5 on 127.0.0.1:1080
homelink check                # CGNAT / UPnP check
homelink devices | revoke <id> | hosts | remove <name> | id
```

## Building

```sh
cargo test --workspace
cargo run -p homelink-cli -- --help
cd apps/desktop/src-tauri && npx @tauri-apps/cli@2 build   # app + installer
```

Pushing a `v*` tag builds unsigned installers into a draft GitHub release.

## Layout

```text
crates/homelink-proto   wire format, invite codes
crates/homelink-core    host, client, SOCKS5, UPnP, system proxy
apps/desktop            Tauri app; full tunnel via tun2proxy (src-tauri/src/tunnel.rs)
crates/homelink-cli     `homelink` command
docs/                   plan and research notes
```

Never commit real credentials, invites or personal network details.
