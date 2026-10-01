<div align="center">

<img src="src-tauri/icons/128x128.png" width="88" height="88" alt="Ratspeak logo">

# Ratspeak

Ratspeak is a native desktop and mobile client for E2EE conversations over
Reticulum, a new type of mesh networking. Ratspeak gives you messaging, file/image sharing, voice calls and voice messages (experimental), Channels, LoRa capability, WiFi, BLE, TCP, offline messaging, turn-based games, and more.

[Click here for iOS TestFlight Public Beta!](https://testflight.apple.com/join/AzzW4Jg6)

[Docs](https://docs.ratspeak.org/) |
[Build from source](https://docs.ratspeak.org/docs/reference/building-from-source) |
[rsReticulum](https://github.com/ratspeak/rsReticulum) |
[rsLXMF](https://github.com/ratspeak/rsLXMF) |
[rsLXST](https://github.com/ratspeak/rsLXST)


[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87%2B-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](#current-state)

<img src="docs/readme/ratspeak-showcase.png" alt="Ratspeak running on desktop and mobile" width="100%">

###### *Note: Ratspeak is currently in ALPHA. If you are looking for a more stable<br> experience, waiting for a later stable release is recommended.*

</div>

## What It Is

Ratspeak is for private messaging when the normal internet is unavailable,
untrusted, or not the path you want to depend on. When your cell tower is down, when natural disaster hits, or when you just want an alternative. When you know the current system is broken.

It runs on
[Reticulum](https://github.com/ratspeak/rsReticulum) and [LXMF](https://github.com/ratspeak/rsLXMF), so conversations can happen
over regular internet, LoRa radios, WiFi, Bluetooth, there is no limit - if it can move data it can be a part of the mesh.

There is no Ratspeak account server, no central database, no hub where everything routes through by default. Your Reticulum identity is generated on
your device and becomes your address on the mesh, no personal information needed.

## Current State

Ratspeak is in experimental/alpha status. That means there are bugs, there are quirks, and things are not perfect. If something isn't working up to your standards, or at all, open an issue with the details needed to reproduce it. Useful, direct feedback helps us fix things faster.

Supported app targets are macOS, Windows, Linux, Android, and iOS. Public
desktop and Android packages will be linked from
[ratspeak.org/download.html](https://ratspeak.org/download.html) as they are
released. iOS does not have a public download yet; macOS is unsigned, and the
Windows MSIX still needs signing for BLE Peering support. These distribution
lanes are in progress.

## What You Get

- Account-free messaging over Reticulum.
- Full offline messaging support.
- Shared Channels, including local history, member presence, and optional hub
  hosting.
- Local Network, TCP, RNode/LoRa support, Bluetooth Peering, and more.
- Contacts, discovered peers, path requests, interface status, propagation
  status, and transport health in the app.
- Activity tools for understanding network and messaging events without
  leaving the app.
- Experimental peer-to-peer voice calls over [LXST](https://github.com/ratspeak/rsLXST)
  (contacts-only, 0-hop, native microphone/speaker).
- Experimental voice messages with local recording and playback.
- Chess, Tic-Tac-Toe, and Four in a Row.
- Built-in light/dark modes, selectable color themes, and adjustable text size.

## Install

Use the download page when public builds are available:
[ratspeak.org/download.html](https://ratspeak.org/download.html).

For setup help, see:

- [Install and Platform Setup](https://docs.ratspeak.org/docs/getting-started/install-and-platform-setup)
- [Your First Session](https://docs.ratspeak.org/docs/getting-started/your-first-session)
- [Troubleshooting](https://docs.ratspeak.org/docs/reference/troubleshooting)

## Build From Source

The full build guide is here:
[Building from Source](https://docs.ratspeak.org/docs/reference/building-from-source).
It covers desktop prerequisites, Android APKs, iOS signing, and the required
sibling checkout layout.

After installing the desktop prerequisites, the shortest local path is:

```bash
mkdir ratspeak-src
cd ratspeak-src
git clone https://github.com/ratspeak/rsReticulum
git clone https://github.com/ratspeak/rsLXMF
git clone https://github.com/ratspeak/lrgp-rs
git clone https://github.com/ratspeak/rsLXST   # experimental voice; skip with --no-default-features
git clone https://github.com/ratspeak/Ratspeak

cd Ratspeak
bash dashboard/build-css.sh
cd src-tauri
cargo tauri dev
```

To reproduce a tagged Ratspeak release starting with `v1.0.29`, check out the
Ratspeak `vX.Y.Z` tag and the matching annotated `ratspeak-vX.Y.Z` tag in each
of `rsReticulum`, `rsLXMF`, `rsLXST`, and `lrgp-rs`. The exact commits in
`Ratspeak/release/dependency-set.json` are authoritative; the coordinated tags
are permanent readable aliases for that graph. From the sibling layout above,
`node Ratspeak/scripts/release/source-integrity.mjs verify-tags` verifies every
component version, annotated tag, and exact commit before a build.

For a release bundle, run `cargo tauri build -- --locked` from
`Ratspeak/src-tauri`.
Desktop bundles land under `Ratspeak/src-tauri/target/release/bundle/`.

To build without the experimental voice stack and skip the rsLXST sibling,
pass `--no-default-features` to `cargo tauri dev` or `cargo tauri build`.

## Voice (experimental)

Voice calls run on [LXST](https://github.com/ratspeak/rsLXST) over Reticulum
links — no servers, no relays. The stack is new and intentionally narrow:

- Microphone and speaker access goes through the OS: `RECORD_AUDIO` and
  `MODIFY_AUDIO_SETTINGS` on Android, `NSMicrophoneUsageDescription` on
  macOS/iOS, the default audio device on Linux/Windows.
- Incoming calls are restricted to contacts on a cached 0-hop path. Calls
  from non-contacts are dropped before any audio path opens.
- Persistently rejected callers are blackholed (rate-limit reason) so they
  cannot keep ringing the device.
- The `lxst-voice` Cargo feature is on by default. Disable it with
  `cargo tauri dev --no-default-features` if you want to build Ratspeak
  without the voice stack.

Voice is experimental — expect rough edges. Codec quality, call setup,
ringtones, and platform audio routing are all subject to change.

## Ethereum (experimental, source builds only)

Ratspeak includes a default-off, unaudited Sepolia proof of concept behind the
`experimental-ethereum` Cargo feature. It is limited to native-ETH EIP-1559
transfers with fixed 21,000 gas, empty calldata, and the standard
`m/44'/60'/0'/0/0` account. Mainnet, contracts, arbitrary signing, private-key
import/export, and WebView access to recovery material are disabled.

The field client accepts Ethereum evidence only when the LXMF signature matches
its configured Ethereum service Contact, but transport delivery, service
replies, and RPC responses are not treated as Ethereum state. The current field path
can cross-check the same finalized Sepolia epoch and root through the fixed
ethPandaOps and ChainSafe checkpoint services, verifies each service and the
separate bootstrap service against Sepolia's genesis identity, and verifies
the downloaded light-client bootstrap locally before installing the anchor.
Manual checkpoint files remain an offline fallback and require explicit native
approval. Evidence is verified forward from the installed checkpoint, and
transaction success or failure is reported only after the exact finalized
receipt verifies locally. An unknown or stale balance is shown as `...`; `0`
is displayed only for a current verified zero-balance proof.

Linux selects an Ethereum service from profile-scoped, public-key-validated
Ratspeak Contacts. A source build or operator may configure one public test
service Contact for one-click onboarding; the user must still select and
review it. The current gateway daemon also requires the operator to provision
each allowed requester's public Contact card; open public enrollment is not yet
implemented. The Android preview still uses a native service-card file picker
instead of the Linux Contacts chooser. Linux and Android use native
wallet-custody and review surfaces; iOS custody is currently unavailable. The
repository contains the standalone
`ratspeak-eth-gatewayd` implementation for RPC access, proof construction, and
relay scheduling. One user-authorized, low-value Linux Sepolia lifecycle has
completed through the standalone daemon and a local shared Reticulum instance,
including exact finalized-receipt verification on the field device. Production
Rathole/systemd hosting and route-specific deployment validation are still
pending. No transport role grants
the gateway checkpoint or Ethereum authority, and automatic unknown-peer
discovery is not used.

This experimental branch currently depends on the companion
[`ethereum-propagation-api`](https://github.com/ChazSchmidt/rsLXMF/tree/ethereum-propagation-api)
rsLXMF branch at commit `9e3f55cebd3f8b491aaab73b69d2a2afef17bad1`.
Place that checkout at `../rsLXMF` before building; fork CI resolves the same
exact commit from the repository owner's rsLXMF fork.

Build the field application explicitly with:

```bash
cd src-tauri
cargo tauri dev --features experimental-ethereum
```

The integration has deterministic and adversarial test coverage, but the
wallet has not been audited. The demonstrated lifecycle is one Linux smoke
test, not a reliability or compatibility claim. Android native ceremonies,
live restart recovery, and physical Reticulum/LoRa paths still require real
system validation before production use.

## Platform Notes

- iOS does not support general USB serial. Ratspeak's signed iOS builds support
  Local Network and multicast discovery; users must still grant the normal iOS
  Local Network permission. Notifications require user permission, and
  background execution remains subject to iOS lifecycle limits.
- Windows Bluetooth Peer advertiser support needs the future signed MSIX lane.
- Linux Bluetooth Peer depends on BlueZ GATT server and LE advertising support.
- Voice calls require microphone permission per platform; the prompt is
  triggered the first time you place or answer a call.

## License

GNU Affero General Public License v3.0 or later. See [`LICENSE`](LICENSE).
