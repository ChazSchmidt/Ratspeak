# Native UI comparison and browser validation - 2026-10-20

Corrective shell base: `f2a2be65da64c6d4341bd4ccb5ff0292bfac550f`.
Only `web/` changed. This supersedes the earlier shell's visual assessment below.

## Native reference and isolation

The reference is the actual `dashboard/index.html` at pinned native commit
`eb5f2df7e86696bf6b61691b598601cb20572d0b`, blob
`1a22aa83bf09e8ec66ce587f748b2bee74f0eee1`. The checked-out native file matches.
A disposable in-memory HTTP response disabled runtime startup scripts, removed
`checking-setup`, and selected the real Messages view. Native CSS was served in
`dashboard/build-css.sh` order; no native source was edited. Native `lxmf.js`
render functions populated comparison contacts and a conversation fixture;
Tauri event subscriptions and runtime side effects were disabled for the fixture.
The populated reference used disposable messages from the real browser run.

All 13 reused CSS modules, `fonts.css`, and four WOFF2 files match
`dashboard/static/` byte-for-byte. Both pages actually loaded Outfit and
JetBrains Mono (`document.fonts` status loaded), with zero failed asset requests.
The rat SVG, navigation, profile/search strip, chat and Contacts structures are
native markup/classes, not the earlier custom shell.

Tests used headless installed Chrome 155.0.8059.85, Playwright 1.64.1,
Node 24.19.0, RNS 1.5.7 and LXMF 1.2.1. An anonymous clone, disposable browser
contexts/identities and loopback-only transports isolated this work. Unpublished
harness copies remapped Vite/native-TCP/bridge to 15173/15242/19787, including
the bridge origin allowlist. Reference capture used 15174/15175. External page
requests were blocked; none were attempted. No camera/microphone API was used.
The existing live browser/server/profile and its ports were left untouched.
Screenshots and fixture data remain local outside the repository; none uploaded.

## Completed results

- Unit suite: **25 passed, 0 failed**. Production build: **PASS**, 1311 modules.
- Full browser/native transport regression after corrections: **PASS**, 61 frames,
  zero uncaught application errors. Two separate browser identities exchanged
  verified messages; refresh/unlock, wrong-password rejection, reconnect and
  actual encrypted export/import controls passed. The unique plaintext marker
  was absent from all captured bridge frames.
- Browser vault checks: **PASS** for encrypted IndexedDB envelopes, wrong vault
  and backup passwords, malformed/tampered backup rejection, saved identity
  preservation and independent-context import/save/refresh/address continuity.
- Independent Python LXMF echo regression: **PASS**, 45 frames, authenticated
  JavaScript/Python messages, reconnect and no test plaintext in bridge frames.
- Optional Farcaster smoke: **PASS**, zero external requests without consent,
  close/reopen consent reset, lock reset, no horizontal page/dialog overflow,
  zero optional page errors. No live Farcaster approval was attempted.
- Actual navigation, Contacts search/grouped rows/detail/Message action,
  per-recipient draft isolation, lock clearing both previews and saved drafts,
  mobile chat Back and Settings section/detail/Back: **PASS**.

## Visual findings

Paired screenshots were inspected at 1440x1000 and 390x844. At desktop, both
navigation rails measure 216px and conversation columns 280px. Both profile
strips measure 279x61.5 at (216,0), and search fields 259x40 at (226,67.5).
Contacts containers measure 1040px at x=308; the first grouped row has identical
bounds in both: (324,154.390625), 1008x58.046875. Mobile chat headers both measure
390x57, the detail view hides bottom navigation, and Back restores the list.
No horizontal document overflow appeared in the captured states.

The comparison found and corrected browser adapter defects: missing native empty
message icons, a 28px mobile profile avatar instead of 36px, an in-flow contact
sheet close button that added vertical space, Settings initially skipping its
mobile section list, and the native CSS's default gray chat-avatar presence dot.
The browser now suppresses that unsupported presence indicator. Native CSS and
fonts remain unchanged.

The result reuses native layouts but is not pixel-identical or feature-complete.
The desktop chat header is 66px versus 61px in the no-status native fixture,
because the browser shows the public address subtitle. It uses locale date/time
text rather than native Today/Yesterday labels, and explicit signature/link-write
labels can increase bubble height. Composer attachment/voice controls, delivery
menus, message actions and presence are absent; the bottom bar has fewer working
destinations. The browser contact sheet is shorter without unavailable route
fields, edit/block/remove actions. Settings retains native section/detail shells
with browser gateway/privacy content; Identity uses the encrypted browser vault.
No native delivered/read indicators are shown for a mere encrypted-link write.

A separate user-authorized short-text exchange with Ratspeak Android received a
signature-verified reply on this date, as reported by the supervising task. Its
phone version and broader interoperability remain unknown. This isolated suite
did not repeat or inspect that session. Attachments, offline propagation,
receipts, public-network reliability, full native parity and security-audit
coverage remain outside this evidence.

## Historical record: previous browser shell

The following records the earlier shell's behavior and reconnect repair.
Its palette/structure assessment was not a native-fidelity comparison and is
superseded by the measurements and differences above.

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
