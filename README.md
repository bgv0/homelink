# homelink

> **Discontinued — 6 November 2026.** Development and maintenance have ended. This repository is archived and retained for historical reference. No further releases or support are planned.


Share your home internet connection with your own devices (or friends') through
a direct, encrypted connection. One app for **macOS and Windows**: either
computer can **Share** (host) or **Connect** (client).

```text
Client apps → system proxy or TUN → local SOCKS5
           → QUIC (or TLS over TCP if UDP is blocked), direct and encrypted
           → host's forwarded port → host → internet
```

- No accounts, no relays, no servers in between. The client talks straight to
  the host's forwarded port.
- Devices join with a one-time invite code; the host approves each one and can
  remove it at any time.
- By default, connected devices can't reach the host's local network.
- Free: no subscription, no paid services.

**New here? Follow the [setup guide](docs/SETUP.md)**: installing, port
forwarding, pairing and connecting, step by step.

## Status

Discontinued as of 6 November 2026. This project is no longer maintained.
The documentation below is historical and does not imply ongoing support.

### Last recorded development state

Early preview. It builds and its automated tests pass on macOS and Windows,
and it has been smoke-tested on one Mac (host and client on the same
machine), but it **hasn't been tried across real networks yet**. See
[the plan](docs/PLAN.md).

## Requirements

- The host needs a public IPv4 address and port forwarding (UDP and TCP 47420
  by default). homelink tries UPnP / NAT-PMP to forward them automatically. **CGNAT
  connections can't host**; use *Network check* in the app to find out.
- Clients use QUIC (UDP) and switch to TLS over TCP automatically on networks
  that block UDP (some schools, hotels, offices). TCP is a little slower to
  open each connection. Networks that only allow ports 80/443 still need the
  host's forwarded port to be one of those.
- Speed is limited by the host's upload bandwidth.
- Firewalls: the Windows installer adds inbound UDP and TCP rules for
  homelink. On macOS, if the firewall is on, allow incoming connections when
  asked.
- Connect has three modes:
  - **System proxy** (default, no password): browsers and most apps follow it,
    some apps and games don't.
  - **Full tunnel** (asks for your admin password each time): all traffic,
    TCP and UDP (games, calls), plus DNS goes through the host. IPv6 is
    switched off (macOS) or blocked by a temporary firewall rule (Windows)
    while the tunnel is up, so nothing goes around it.
  - **SOCKS5 only**: point apps at 127.0.0.1:1080 yourself (CONNECT and UDP
    ASSOCIATE).
- If your internet stops working after homelink crashed in full-tunnel mode,
  use **Connect → Trouble? → Repair network settings**.
- When asking for help, use **Copy diagnostics** (in *Network check* or
  *Trouble?*). It copies a text report with IP addresses partly hidden.

## Installing and using

See the **[setup guide](docs/SETUP.md)**. In short: install on both computers
(the apps aren't signed, so macOS and Windows warn once), check the host can
be reached, forward port 47420 (UDP and TCP) if the router doesn't do it
automatically, invite the other computer, and click **Connect**.

## Command line

```sh
homelink host                 # share (Ctrl-C to stop)
homelink invite               # one-time code
homelink add <code>           # on the other device
homelink connect              # SOCKS5 on 127.0.0.1:1080
homelink check                # CGNAT / UPnP / NAT-PMP check
homelink set-address <host> <addr>   # after a host's IP changed
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
crates/homelink-core    host, client, SOCKS5 (TCP + UDP), UPnP/NAT-PMP, system proxy
crates/homelink-cli     `homelink` command
apps/desktop            Tauri app; full tunnel via tun2proxy (src-tauri/src/tunnel.rs)
docs/                   plan and research notes
```

Never commit real credentials, invites or personal network details.

## Licence

Crates under `crates/` are MIT or Apache-2.0; the desktop app is
GPL-3.0-or-later. Details in [LICENSE.md](LICENSE.md); third-party software
in [THIRD-PARTY.md](THIRD-PARTY.md). Security reports: [SECURITY.md](SECURITY.md).
