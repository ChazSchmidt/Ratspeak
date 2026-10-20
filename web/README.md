# Ratspeak Web experiment

Browser-first Reticulum/LXMF client in `ChazSchmidt/Ratspeak`, branch `experiment/ratspeak-web`. Only the independently deployable `web/` experiment changes. The messaging layout and warm theme adapt Ratspeak's own dashboard patterns; no third-party client implementation was forked. Farcaster remains an optional dialog.

## Run locally

```sh
cd web
npm ci
npm run dev
npm run build
npm test
```

Serve `dist/` from an HTTPS static host. This does not provide a Reticulum gateway: configure a compatible **wss://** gateway in the client. For a local loopback test, HTTP and **ws://** work. See [transport operation and test instructions](tests/TRANSPORT.md) for the included minimal WS-to-Reticulum TCP bridge, reference native node setup, origin restrictions, and TLS deployment boundaries. No public gateway is assumed or contacted automatically.

1. Create an identity with a passphrase of at least 12 characters, or unlock/import an existing one.
2. Export an encrypted backup. Losing both storage and backup means losing the identity; losing the passphrase makes its encrypted copies unusable.
3. Enter a gateway URL and connect. The client announces its public delivery address and display name.
4. Add a friend's 32-character LXMF address, select the contact, and send text. No Farcaster account is required.
5. Disconnect before changing gateways. Lock closes the network connection and clears the visible, in-memory message history. Reload requires unlocking again.

## Implemented and verified separately

- Browser UI for connection/disconnection, public discovery, generic contacts, sending and receiving LXMF text, and visible failures.
- Retained Reticulum/LXMF runtime using published `@reticulum/core` and `@reticulum/lxmf` 0.9.13 dependencies. The lockfile records exact package versions.
- Encrypted identity persistence in IndexedDB, unlock after reload, encrypted backup/import, and explicit confirmation before replacing a saved identity. PBKDF2-SHA-256 plus AES-256-GCM use Web Crypto; private key exports are encrypted before storage.
- Local Vite production build passes. Unit tests cover framing/origin enforcement, address and gateway validation, send limits/disconnect cleanup, encrypted identity round trips, address/signature continuity, random salt/nonce, and rejection of tampering, malformed backups, and wrong passphrases.
- Native transport integration passes: two independent JavaScript protocol stacks send via a real Python Reticulum TCP node; an independently implemented Python LXMF peer verifies a signature and returns a decryptable reply; reconnect preserves identity. The captured bridge packets do not contain the unique test plaintext marker. This is a bounded test, not a security audit.

**Not yet verified:** the actual two-browser UI milestone and real browser IndexedDB refresh tests. Chromium execution in the available test environment failed at local socket creation (`EPERM`); the elevated environment failed before execution. Build and Node protocol success are not browser success. `npm run test:browser` contains the real two-context, bidirectional UI/refresh test, ready for an environment with a working Chromium installation. Set `CHROMIUM_EXECUTABLE_PATH` if needed and `PYTHON` to the reference-test virtual environment. `tests/vault-browser.mjs` additionally tests encrypted IndexedDB and independent-context backup import against a running Vite server.

**Still experimental:** interoperability with Ratspeak's Rust implementation, public deployment/security review, offline/propagated delivery, attachments, delivery receipts, and Farcaster authentication/social graph discovery. The current send label means written to an encrypted Reticulum link, **not recipient delivery or reading**. The UI distinguishes verified incoming signatures from unverified senders; names remain self-declared.

## Privacy and limitations

- Private identities and decrypted message text stay client-side. Network transport carries encrypted LXMF, not an ordinary chat backend. The bridge has no identity keys or LXMF decryption logic.
- A gateway can observe source IPs, timing, traffic sizes, public announces/addresses, and network routing metadata. A malicious gateway can block or alter traffic. WSS protects the browser-to-gateway connection; LXMF encryption protects message content end to end.
- The hosting origin and delivered JavaScript remain trusted. Compromised hosting, dependencies, browser extensions, or an unlocked device can expose decrypted keys/messages. Encryption at rest does not solve this. Locking drops references, but JavaScript cannot guarantee immediate memory erasure.
- Messages are kept only in memory, not durable chat history. Contacts (including any self-declared FID binding) remain unencrypted localStorage metadata. Announcing makes the address/display name public on the connected network.
- Farcaster invitations are opt-in, public, and **unverified**. New invitation data uses the URL fragment so ordinary HTTP requests do not send it to the static host; anyone receiving the invitation can read/forward it. Linking a FID to an LXMF identity is sensitive correlation metadata, not anonymity. No directory, social login, analytics, or private-key upload is implemented.

## Licensing

Ratspeak is AGPL-3.0-or-later; retain its source and license notices. The Reticulum JavaScript packages declare EUPL-1.2. This experiment uses those published dependencies without copying another client's implementation. The EUPL compatibility appendix includes AGPLv3, but packaging/distribution obligations and compatibility should be reviewed before a public release; no legal clearance is claimed. Keep all applicable dependency notices with distributions and provide corresponding source as required.
