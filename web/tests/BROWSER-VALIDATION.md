# Local browser validation — 2026-10-20

Scope: `ChazSchmidt/Ratspeak`, branch `experiment/ratspeak-web`, starting from
`85e7611cdf9157eda5a181a09522c4d013273bf3`. Changes are confined to `web/`.
The isolated laptop checkout preserved other checkouts and generated only
disposable test identities. No private user identity or plaintext was uploaded.

## Environment

- Windows laptop, Node 24.19.0, installed Google Chrome 155.0.8059.85.
- Playwright 1.64.1; published `@reticulum/core` and `@reticulum/lxmf` 0.9.13.
- Isolated Python 3.12 environment: RNS 1.5.7 and LXMF 1.2.1 from PyPI.
- Native RNS TCP server, WebSocket packet bridge and Vite all bound to loopback.
- Browser checks ran with visible Chrome windows (`HEADED=1`), with screenshots
  inspected from the actual rendered UI at desktop and mobile widths.

## Browser result

`npm run test:browser`: **PASS**, exit 0. The completed visible-Chrome run reported:

```json
{"pass":true,"separateBrowserIdentities":true,"refreshUnlock":true,"wrongPassphraseLocked":true,"bidirectionalNativeLXMF":true,"incomingSignaturesVerified":true,"reconnect":true,"uiEncryptedExportImport":true,"plaintextAbsentFromBridgeFrames":true,"frameCount":54,"uncaughtPageErrors":0}
```

A and B had distinct LXMF identities in independent browser contexts. Both
refreshed, rejected an incorrect unlock passphrase while keeping Connect disabled,
then unlocked to the same address. A sent to B through the actual native Python
Reticulum transport, B replied, and the incoming rows showed verified signatures.
After A disconnected/reconnected, B sent another verified message to A.
All 54 captured raw bridge frames lacked the unique test plaintext marker.
This is a narrow regression check, not a cryptographic proof.

The real Export backup button downloaded an encrypted envelope; a third empty
context rejected its wrong passphrase, imported it through the file input with
the correct passphrase, and retained the same address after refresh/unlock.
Backups were processed only locally and were not committed or uploaded.

`node tests/vault-browser.mjs`: **PASS**, exit 0, including standalone Vite startup
and cleanup. Checks covered the actual IndexedDB encrypted envelope, vault and
backup wrong passphrases, malformed backup rejection, authenticated ciphertext
bit-flip rejection, preservation of the original saved identity after failed
imports, and independent-context import/save/refresh with address continuity.

Desktop (1440px) and mobile (390px) screenshots retained Ratspeak's warm palette,
sidebar/contact/chat structure and message bubbles. Signature and connection
labels were visible; mobile had no horizontal page overflow. Screenshots contain
only synthetic test text and disposable public addresses and remain outside the
repository. No layout redesign or native Android/iOS changes were made.

## Reconnect regression and repair

The expanded browser test first failed after the two-way exchange: B's next
message never appeared after A reconnected. `MessagingClient.disconnect()` had
removed/disconnected the interface before tearing down links, and only cleared
outbound cached links. An inbound reply link survived, while the remote browser
could reuse its stale outbound link.

The repair closes all active incoming/outgoing links before removing the bearer,
deduplicates links also present in the outbound cache, clears that cache, and
sets a disconnecting state during cleanup. The browser regression subsequently
passed. The unit regression asserts that both link directions close exactly
once before the interface is removed. The fix is preserved in local commit
`03ad6513c66c3ea53d4ac367dec1b6699e825c67`.

`npm test`: **11 passed, 0 failed** on the repaired adapter. `npm run build`:
**PASS**, 47 modules transformed. The initial restricted-sandbox unit attempt
failed the bridge test with `connect EACCES`; the authorized run with working
loopback sockets passed all 11. Browser runs used working local sockets.

`PYTHON=... node tests/transport-interop.mjs`: **PASS**, exit 0 on the repaired
adapter. The independent Python LXMF peer validated the sender signature and
returned a verified, decryptable echo; Node adapter pairs and reconnect also
passed. All 45 captured raw bridge frames lacked the test plaintext marker.

## Limits

This validates a local two-browser milestone and encrypted identity persistence.
It does not establish full security-audit coverage, public deployment readiness,
public-network reliability, Rust Ratspeak interoperability, offline propagation,
delivery receipts, or read receipts. Sending to an encrypted link remains distinct
from confirmed recipient delivery. No CI, release automation, public deployment,
third-party implementation fork, or authentication changes were introduced.
