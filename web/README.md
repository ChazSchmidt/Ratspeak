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

**Browser milestone verified locally on 2026-10-20:** installed Chrome 155.0.8059.85 on Windows ran the real UI in two independent contexts, with separate disposable identities, through Python RNS 1.5.7's native TCP transport. A sent to B, B replied, incoming signatures were verified, and B delivered another verified message after A disconnected/reconnected. Both identities retained their addresses after refresh/unlock. The actual backup export/import controls worked in a third context, including refresh/unlock after import. Browser vault checks rejected wrong passphrases, malformed backups and authenticated ciphertext tampering while preserving the saved identity. See [the validation record](tests/BROWSER-VALIDATION.md) for evidence, the reconnect repair, and limits.

Run `npm run test:browser` to start the native peer, loopback bridge, Vite, browser UI tests, and vault browser checks together. Set `CHROMIUM_EXECUTABLE_PATH` to an installed Chromium browser and `PYTHON` to the reference-test virtual environment. `HEADED=1` shows the browser; `BROWSER_SCREENSHOT_DIR` optionally captures only disposable test UI outside the source tree. `node tests/vault-browser.mjs` also runs independently, starting Vite on port 5178 unless `VITE_TEST_URL` points to an existing test server. See [platform-specific commands](tests/TRANSPORT.md#browser-milestone).

**Still experimental:** interoperability with Ratspeak's Rust implementation, public deployment/security review, offline/propagated delivery, attachments, delivery receipts, and Farcaster authentication/social graph discovery. The current send label means written to an encrypted Reticulum link, **not recipient delivery or reading**. The UI distinguishes verified incoming signatures from unverified senders; names remain self-declared.

## Privacy and limitations

- Private identities and decrypted message text stay client-side. Network transport carries encrypted LXMF, not an ordinary chat backend. The bridge has no identity keys or LXMF decryption logic.
- A gateway can observe source IPs, timing, traffic sizes, public announces/addresses, and network routing metadata. A malicious gateway can block or alter traffic. WSS protects the browser-to-gateway connection; LXMF encryption protects message content end to end.
- The hosting origin and delivered JavaScript remain trusted. Compromised hosting, dependencies, browser extensions, or an unlocked device can expose decrypted keys/messages. Encryption at rest does not solve this. Locking drops references, but JavaScript cannot guarantee immediate memory erasure.
- Messages are kept only in memory, not durable chat history. Contacts (including any self-declared FID binding) remain unencrypted localStorage metadata. Announcing makes the address/display name public on the connected network.
- Farcaster invitations are opt-in, public, and **unverified**. New invitation data uses the URL fragment so ordinary HTTP requests do not send it to the static host; anyone receiving the invitation can read/forward it. Linking a FID to an LXMF identity is sensitive correlation metadata, not anonymity. No directory, persistent social login, analytics, or private-key upload is implemented. The separate optional SIWF experiment does not verify these invitation cards.

## Optional Farcaster experiment

The “Coming from Farcaster?” dialog includes a separate, lazy-loaded Sign In With Farcaster experiment. Explicit consent is required before any relay/RPC request. It verifies a short-lived account-signed association with the current LXMF address; it does not publish a directory entry or authenticate legacy invitation cards. Real-account end-to-end approval is **not yet verified**. Boundary tests and an official-SDK synthetic-signature test pass; these do not prove live account ownership. See [the auth protocol, privacy boundaries, and outstanding live test](docs/FARCASTER.md). No account sign-in is required for messaging.

## Licensing

Ratspeak is AGPL-3.0-or-later; retain its source and license notices. The Reticulum JavaScript packages declare EUPL-1.2. This experiment uses those published dependencies without copying another client's implementation. The EUPL compatibility appendix includes AGPLv3, but packaging/distribution obligations and compatibility should be reviewed before a public release; no legal clearance is claimed. Keep all applicable dependency notices with distributions and provide corresponding source as required.
