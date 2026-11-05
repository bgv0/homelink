# homelink plan

Written 2026-11-05. Status: PLAN ONLY. Nothing below has been implemented or tested yet.

**Direction:** a public, open-source app for **anyone who can port-forward**. One simple app on
**macOS and Windows**. Either machine can be the **host** ("share my internet")
or the **client** ("connect to a host"), in any combination: Mac→Win, Win→Mac,
Mac→Mac, Win→Win. Clients connect **directly** to the host's forwarded port.
**No relays and no project-run servers.**

Read this whole file before acting, including section 6 (operating rules).

---

## 1. Why this shape

- Port forwarding is the premise, so the client opens a **direct, encrypted
  connection** to the host PC's forwarded port. Nothing sits in between: no
  relay, no rendezvous server, no account.
- The host should need **no admin rights and no OS routing changes**. So the host
  is a user-space proxy: it accepts encrypted streams and opens ordinary outbound
  TCP connections. This works the same on Mac and Windows. A classic L3 VPN
  (WireGuard) would need NAT/IP forwarding on the host, which is painful on
  Windows and macOS.
- Only the **client** needs elevated rights, for the TUN device that captures
  system traffic.

### Known limits (state these in the README and in the app)

- **CGNAT**: hosts behind carrier-grade NAT cannot be reached by port forwarding.
  The app should detect this and say so clearly. Testing needs a host with a
  public IPv4 (Phase 0).
- **UDP-blocking client networks** (some schools, hotels, offices): QUIC won't
  connect. v1 accepts this. A TCP fallback is a later option (section 5).
- Speed is capped by the host's **upload** bandwidth.
- Changing home IPs: handled by a DDNS hostname or by re-sharing the invite
  (section 2, "Finding the host").

---

## 2. Architecture

```text
Client apps
  → TUN (client only, elevated helper)
  → local SOCKS5 on 127.0.0.1 (homelink client)
  → QUIC (iroh endpoint, relays DISABLED) → host public IP:port (forwarded UDP)
  → homelink host (paired-device allowlist, no admin needed)
  → outbound TCP from the host to the internet
```

### Components

- **Rust workspace**, one core shared by CLI and UI:
  - `homelink-proto`: wire header (version, target host:port), invite format,
    pairing messages. Pure and unit-tested.
  - `homelink-core`: endpoint setup, allowlist, pairing, host proxy loop,
    client SOCKS5, port mapping, reachability checks.
  - `homelink-cli`: `homelink host | client | invite | devices | revoke | status`.
  - `apps/desktop`: Tauri v2 app for both OSes.
  - Privileged helpers: macOS LaunchDaemon and a Windows service, client side only.
- **Transport**: iroh (pinned, 1.4.x at time of writing) with `RelayMode::Disabled`
  and no n0 DNS discovery. The host binds a **fixed UDP port** (default 47420,
  user-changeable). We still get QUIC, TLS 1.3, Ed25519 device keys and stream
  multiplexing, but nothing is sent to third-party servers. Verify in Phase 1
  that iroh with relays disabled and an explicit direct address works cleanly. If
  it fights us, fall back to plain `quinn` with raw-public-key TLS (same design).
- **Port forwarding help**:
  1. Try UPnP-IGD / NAT-PMP / PCP automatically (iroh ships a portmapper; check
     it can map our fixed port, or use the `igd-next` crate).
  2. If that fails, show a short guide: "Forward UDP 47420 to <this PC's LAN IP>",
     plus the LAN IP and a link to a router-specific guide.
  3. **CGNAT check**: get the router WAN IP (from UPnP if available) and the
     public IP (STUN to a well-known public STUN server, the only outside lookup).
     If the WAN IP is in 100.64.0.0/10 or doesn't match the public IP, show
     "Your ISP uses CGNAT, port forwarding won't work. Ask your ISP for a public IP."
  4. **Reachability test**: the host can't reliably test itself (hairpin NAT
     varies), so the app tells the user to test from a phone hotspot once, and
     the client shows a clear "host not reachable (port closed or UDP blocked)"
     error with a timeout of about 5 s instead of hanging.
- **Finding the host**: the invite contains the host's device ID, address and
  port. The address is a user-provided DDNS hostname if they have one (recommended
  in the UI), otherwise the current public IP. If the public IP changes and
  there's no DDNS, the host app shows "your address changed, re-share the invite"
  and clients accept an updated invite without re-pairing. Optional later:
  publish the address to the mainline DHT (pkarr), which iroh supports and which
  needs no project server. Evaluate after v1.
- **Pairing**: the host clicks "Invite a device" and gets an invite (text code + QR):
  device ID, address:port, a single-use secret, 15-minute expiry. The client
  pastes or scans it, connects, and sends the secret. The **host user approves**
  ("<device name> wants to connect: Allow / Deny"), on by default. The client's
  device ID goes into the allowlist. Revoking a device closes its live streams.
- **Host safety defaults** (this is now a public app):
  - Unknown device IDs are rejected at accept time, before any stream data is read.
  - **Block clients from reaching the host's LAN and loopback by default**
    (RFC1918, link-local, 127/8, ::1, ULA, the host's own addresses, and anything
    a DNS name resolves to in those ranges). There's a toggle, "Let connected
    devices reach my local network", off by default.
  - Per-device connection limits, idle timeouts, and handshake rate limiting
    for unauthenticated peers.
  - No logging of destinations by default. Logs hold only connection
    events and errors.
- **Client system-wide routing**:
  - TUN engine: evaluate **tun2proxy** (Rust, MIT/Apache, in-process, supports
    macOS and Windows/wintun) first, because it keeps one binary and a permissive
    licence. Fall back to sing-box (GPLv3, separate process) if tun2proxy fails
    the leak tests. The choice affects the licence (section 4, Phase 6).
  - Routing-loop exclusion: the QUIC socket to the host must bypass the TUN
    (route to host IP via the original gateway, or bind to the physical interface).
  - DNS goes through the tunnel (DoH/TCP via SOCKS). IPv6 is blocked inside the
    tunnel in v1, so it can't leak.
  - Clean disconnect restores routes and DNS. After a crash, the next start
    removes stale state (only what we changed).
- **Elevation**:
  - macOS: a LaunchDaemon helper registered with `SMAppService` (one admin prompt,
    once). It requires a signed app. Network Extension (`NEPacketTunnelProvider`)
    is the "proper" route but needs Swift and special entitlements, so we revisit
    it after v1.
  - Windows: a small Windows service (SYSTEM) installed by the installer owns the
    wintun adapter. The UI talks to it over a named pipe restricted to the
    installing user.
  - The host role never needs either helper.

### UI (same app on both OSes)

Tray / menu bar icon plus one small window with two tabs:

- **Share** (host): an on/off switch; status ("Reachable at home.example.net:47420",
  "UPnP mapped ✓", or a clear problem like "CGNAT detected" or "Port not
  forwarded"); "Invite a device" (code + QR); a device list (name, last seen,
  online, Revoke); "Start when I log in"; a "Local network access" toggle.
- **Connect** (client): saved hosts; a big Connect/Disconnect button; status
  (connected, RTT, throughput, "Your traffic exits from <host public IP>"); an
  "Add host" field for pasting or scanning an invite.
- Errors are written for non-technical users, and each one names a next step.
- "Copy diagnostics" produces a redacted report (no keys, no secrets, IPs masked).

### Not in v1

UDP proxying (QUIC/HTTP3 and games fall back to TCP), IPv6 egress, TCP fallback
transport, relays, mobile apps, Linux (the core should stay portable, but no
packaging), split tunnelling.

---

## 3. Platform matrix to support and test

| Host ↓ / Client → | macOS client | Windows client |
| --- | --- | --- |
| macOS host | ✓ | ✓ |
| Windows host | ✓ | ✓ |

Targets: macOS 13+ (Apple Silicon and Intel, universal build) and Windows 10/11 x64.
Windows ARM64 later.

---

## 4. Phases

Each phase ends with a gate. Don't start the next phase until the gate passes or
the user says to proceed. Report results plainly: "connected" isn't the same as
"egress verified", and that isn't the same as "throughput measured".

### Phase 0: Setup

1. Install Rust (rustup) on the Mac; on Windows, install Rust later in Phase 2
   (or cross-compile with `cargo-xwin`).
2. **Get a port-forwardable test host** (public IPv4, not CGNAT: router WAN IP
   must not be in 100.64.0.0/10). LAN-only testing is fine for Phases 1–3;
   external tests need such a host.

Gate 0: Rust installed, test-host route chosen.

### Phase 1: Transport spike (small Rust program, LAN first)

1. Minimal `spike` binary: host binds UDP 47420 with relays disabled; client
   connects with the host's device ID and `ip:port`; it echoes data and
   measures throughput.
2. Tests: same machine → LAN Mac↔Windows (both directions) → external over a
   forwarded port (phone hotspot client) once the Phase 0 test host exists.
3. Check the portmapper: can it map our fixed port via UPnP on the test router?
4. Record versions, results and any iroh friction in `docs/SPIKE-RESULTS.md`.
   If iroh's direct-only mode is awkward, try plain `quinn` here and choose.

Gate 1: direct QUIC works over LAN both ways, and externally through a forwarded
port. Throughput is close to the line rate (record numbers).

### Phase 2: Core and CLI (host + SOCKS client)

- Workspace layout:

  ```text
  Cargo.toml
  crates/homelink-proto/
  crates/homelink-core/
  crates/homelink-cli/
  apps/desktop/          (Phase 4)
  helpers/macos/  helpers/windows/   (Phase 3)
  docs/
  ```

- Config and keys go in per-user dirs (`~/Library/Application Support/homelink/`,
  `%APPDATA%\homelink\`). Key files get owner-only permissions. Never log keys
  or invite secrets.
- Host: pairing with approval (CLI prompt for now), allowlist, revoke, the LAN
  block list, limits and timeouts. Runs without admin on both OSes.
- Client: SOCKS5 CONNECT only on 127.0.0.1. Reject BIND / UDP ASSOCIATE.
- Port mapping, the CGNAT check and the STUN public-IP lookup live in core so the
  UI can show them.
- `status`: connected devices, RTT, bytes, mapping state, reachable address.
- Tests (`cargo test`, offline): proto round-trips and malformed-input rejection;
  in-process host + client through an echo server; unpaired/revoked/expired-invite
  rejection; LAN-block (client asks for 192.168.x.x or 127.0.0.1 and is refused);
  a hostname that resolves to a private IP is refused.
- CI: GitHub Actions building and testing on macos-latest and windows-latest.

Gate 2: tests are green on both OSes in CI; manual `curl --socks5-hostname`
through each host OS shows the host's egress IP.

### Phase 3: Client system-wide routing (both OSes)

1. Integrate tun2proxy (or sing-box as fallback) behind a `TunEngine` trait.
2. macOS helper (LaunchDaemon) and Windows service (wintun). Both expose a minimal
   authenticated local IPC: start/stop the tunnel with given SOCKS port and
   host IP. Nothing else.
3. Loop exclusion, DNS through the tunnel, IPv6 blocked, clean teardown, crash recovery.
4. Optional kill switch (off by default).

Gate 3, run on **both** client OSes: browser traffic exits from the host; no DNS
leak (leak-test site plus a packet capture on the physical NIC for port 53/853);
no IPv6 leak; disconnect restores networking; Wi‑Fi change and sleep/wake
reconnect; host down gives a clear error within about 5 s.

### Phase 4: Desktop app (Tauri v2)

- The UI from section 2. Tray icon on Windows, menu bar on macOS, plus the small window.
- The host role runs in the app's own process (no helper). An optional "Run host
  in background at login" uses a LaunchAgent on macOS and a per-user startup task
  on Windows, still with no admin.
- First-run flow: "What do you want to do? Share my internet / Connect to someone."
- Approval prompts appear as a native notification plus an in-app dialog.

Gate 4: someone who hasn't seen the project installs on two machines (any OS
combination) and connects using only the in-app guidance. Test all four
combinations in section 3.

### Phase 5: Packaging, signing, updates

- macOS: universal `.dmg`, **Developer ID signed and notarized**. This needs a
  paid Apple Developer account ($99/yr), and the user must enroll. It's required
  for `SMAppService` and to avoid Gatekeeper blocking.
- Windows: NSIS or MSI installer via Tauri, installing the service. Code signing:
  Azure Trusted Signing (about USD 10/month) or an OV certificate. Without it,
  SmartScreen warns, which is acceptable for early betas. User decides.
- Auto-update via the Tauri updater with signed update manifests on GitHub Releases.
- Reproducible release builds in GitHub Actions. No signing keys in the repo.

Gate 5: clean-machine installs on macOS 13/14/15 and Windows 10/11 with no
security warnings (or only the documented SmartScreen one if unsigned on Windows).

### Phase 6: Open-source release

1. Licence: MIT OR Apache-2.0 if tun2proxy is used (matches iroh). If sing-box is
   bundled, either license the project GPLv3 or ship sing-box as a separate,
   unmodified binary with its licence and source link. Decide in Phase 3.
2. Dependency licence audit (`cargo deny`), `SECURITY.md`, `CONTRIBUTING.md`,
   and a user README with the port-forward guide and the known limits from section 1.
3. Before making the repo public, scan the full history for secrets and
   personal network details (`gitleaks` or similar).
4. Responsible-use note: the host owner is responsible for traffic leaving their
   connection. Explain approval prompts and the LAN block in the docs.

---

## 5. Later (after v1)

- TCP fallback transport (TLS over TCP on the same forwarded port number) for
  UDP-blocking networks.
- Mainline-DHT address publishing so IP changes don't need a DDNS hostname or a new invite.
- UDP proxying, IPv6 egress, Linux packages, mobile clients, macOS Network Extension.

---

## 6. Operating rules

- Never commit keys, certificates, invites, pairing secrets, captured traffic,
  real IP addresses or personal network details. Local test material goes in
  `.homelink/` (gitignored). Check `git diff --cached` before every commit.
- Don't change router, firewall, DNS or power settings on test machines without asking.
- Before any network test, record which network each machine is on and whether
  another VPN holds the default route.
- Only claim what was tested: "connected", "egress verified" and "throughput
  measured" are different claims.
