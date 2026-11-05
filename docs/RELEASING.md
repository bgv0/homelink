# Releasing

## Preview builds (today)

Push a tag and GitHub Actions builds installers into a **draft** release:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

You can also run the *Release* workflow by hand (Actions tab → Release → Run
workflow); that makes a draft named `dev-<commit>`. Check the draft, then
publish it.

These builds are **unsigned** (macOS ad-hoc signed only), so users see
security warnings. The README explains how to get past them.

## Signing (when you're ready)

### macOS: Developer ID + notarization

Needed so macOS opens the app without warnings. Requires the Apple Developer
Program (USD 99/year).

1. Enroll at developer.apple.com, then create a **Developer ID Application**
   certificate (Xcode → Settings → Accounts → Manage Certificates, or the web
   portal) and export it with its private key as a `.p12` file.
2. Create an app-specific password at appleid.apple.com.
3. Add these GitHub repository secrets (Settings → Secrets and variables →
   Actions):
   - `APPLE_CERTIFICATE`: `base64 -i cert.p12 | pbcopy`
   - `APPLE_CERTIFICATE_PASSWORD`: the `.p12` export password
   - `APPLE_SIGNING_IDENTITY`: e.g. `Developer ID Application: Your Name (TEAMID)`
   - `APPLE_ID`, `APPLE_PASSWORD` (the app-specific password), `APPLE_TEAM_ID`
4. In `.github/workflows/release.yml`, give the macOS build step those secrets
   as environment variables (same names). The Tauri CLI then signs and
   notarizes automatically.
5. Remove `"signingIdentity": "-"` from `apps/desktop/src-tauri/tauri.conf.json`.

### Windows: code signing

Without it, SmartScreen warns on first install. Options:

- **Azure Trusted Signing** (about USD 10/month, needs an identity check):
  set `bundle.windows.signCommand` in `tauri.conf.json` to the
  `trusted-signing-cli` command and add the Azure credentials as secrets.
- An **OV/EV code-signing certificate** from a CA: set
  `bundle.windows.certificateThumbprint` and import the certificate on the
  runner first.

### Auto-update (after signing)

The Tauri updater needs its own key pair (`npx @tauri-apps/cli signer
generate`). Keep the private key in a `TAURI_SIGNING_PRIVATE_KEY` secret, put
the public key in `tauri.conf.json` (`plugins.updater.pubkey`), and point the
updater at a `latest.json` on GitHub Releases.

## Before making the repository public

- Pick the licence (currently MIT OR Apache-2.0 in `Cargo.toml`). Check
  dependency licences with `cargo deny check licenses`. Wintun's licence file
  ships with Windows builds.
- Scan history for secrets: `gitleaks detect`.
- Add `SECURITY.md` with a way to report vulnerabilities.
