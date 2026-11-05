# Licensing

homelink is open source. Different parts use different licences:

| Part | Licence | Files |
| --- | --- | --- |
| Protocol, core engine, command-line tool (`crates/`) | MIT **or** Apache-2.0, at your option | [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE) |
| Desktop app (`apps/desktop/`) | GPL-3.0-or-later | [apps/desktop/LICENSE](apps/desktop/LICENSE) |

The desktop app is GPL because its full-tunnel mode uses `tun2proxy`, which
depends on the GPL-3.0 crate `socks5-impl`. The crates under `crates/` don't
use it and stay permissively licensed.

Third-party software and its licences: [THIRD-PARTY.md](THIRD-PARTY.md).

Unless you say otherwise, contributions are licensed under the same terms as
the part of the project they change.
