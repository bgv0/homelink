# Research notes

## iroh and tools (GitHub releases, checked 2026-11-05)

| Tool | Latest | Published |
| --- | --- | --- |
| iroh (also iroh-relay, iroh-dns-server) | v1.4.1 | 2026-10-22 |
| dumbpipe | v0.40.1 | 2026-10-21 |
| sendme | v0.37.1 | 2026-10-21 |

Release pages: https://github.com/n0-computer/iroh/releases,
https://github.com/n0-computer/dumbpipe/releases, https://github.com/n0-computer/sendme/releases

## Why no public relays (https://docs.iroh.computer/relays/rate-limiting)

- n0 public relays are free, rate-limited per connection, intended for
  development/hobby use, not production; no SLA.
- Shared/dedicated relays are paid. Self-hosted `iroh-relay` is possible
  (rate limiting off by default) — a later option for CGNAT hosts.
