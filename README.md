# homelink

Share your home internet connection with your own devices (or friends') through
a direct, encrypted connection. One app for **macOS and Windows**: either
computer can **Share** (host) or **Connect** (client).

```text
Client apps → system proxy → local SOCKS5 → QUIC, direct and encrypted
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
- Connect mode currently uses the system proxy setting: browsers and most apps
  follow it, but some apps and games don't. Full-tunnel mode is planned.

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
crates/homelink-cli     `homelink` command
apps/desktop            Tauri app (src-tauri = Rust, ui = HTML/CSS/JS)
docs/                   plan and research notes
```

Never commit real credentials, invites or personal network details.
