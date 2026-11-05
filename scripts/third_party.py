#!/usr/bin/env python3
"""Regenerate THIRD-PARTY.md from Cargo.lock: run `python3 scripts/third_party.py`."""
import json
import subprocess

meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked"]))
deps = sorted(
    (p for p in meta["packages"] if p["source"] is not None),
    key=lambda p: (p["name"], p["version"]),
)
lines = [
    "# Third-party software",
    "",
    "homelink is built on these open-source Rust crates (generated from",
    "`Cargo.lock` by `scripts/third_party.py`). Each is used under its own",
    "licence; licence texts are in each crate's source on crates.io.",
    "",
    "Windows installers also include **Wintun** (`wintun.dll`, WireGuard LLC),",
    "an unmodified prebuilt driver library loaded at runtime for full-tunnel",
    "mode, distributed under the Wintun Prebuilt Binaries License",
    "(`wintun-LICENSE.txt` next to the app).",
    "",
    "| Crate | Version | Licence |",
    "| --- | --- | --- |",
]
for p in deps:
    lines.append(f"| {p['name']} | {p['version']} | {p.get('license') or 'see crate'} |")
open("THIRD-PARTY.md", "w").write("\n".join(lines) + "\n")
print(f"wrote THIRD-PARTY.md ({len(deps)} crates)")
