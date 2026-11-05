# homelink

Share your home internet connection with your other devices, or your friends'
devices, through a simple app for **macOS and Windows**. Either computer can be
the host ("Share") or the client ("Connect").

## Status

Early development. See [the plan](docs/PLAN.md). No working app or installers
yet. The repository is private until the open-source release (plan Phase 6).

## How it will work

```text
Client apps → TUN → local SOCKS5 → QUIC (direct, no relays)
           → host's forwarded UDP port → host → internet
```

- The host needs **port forwarding** (automatic via UPnP/NAT-PMP when the router
  allows it, otherwise one manual rule) and **no admin rights**.
- Clients join with a one-time invite that the host approves. Devices can be revoked.
- By default, clients can't reach the host's local network.
- No accounts, no relays, no servers run by this project.

## Known limits

- Hosts behind **CGNAT** can't be reached. Ask your ISP for a public IPv4.
- Client networks that block UDP won't connect in v1.
- Speed is limited by the host's upload bandwidth.

## Layout

```text
crates/      Rust core, protocol, CLI (planned)
apps/desktop Tauri app for macOS and Windows (planned)
helpers/     client-side privileged helpers (planned)
docs/        plan and historical notes
```

Never commit real credentials, invites, personal network settings or captured
traffic. Use placeholders in examples.
