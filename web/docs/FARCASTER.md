# Optional Farcaster ownership experiment

This is an isolated Sign In With Farcaster (SIWF) experiment, not a directory or
social graph integration. The default messaging experience must remain usable
without loading the optional auth UI or making any Farcaster requests.

## Integration

After mounting the existing Farcaster dialog, call:

```js
import { mountFarcasterOnboarding } from './farcaster-onboarding.js';
const onboarding = mountFarcasterOnboarding(document.getElementById('farcaster-dialog'), {
  getAddress: () => client?.address,
});
```

Call `onboarding.reset()` whenever the local identity locks or changes, and when
the dialog closes. The UI additionally checks identity continuity before and
after each asynchronous result. Nothing is stored in localStorage/IndexedDB,
and no auth response or account session is persisted. Importing/mounting the
module causes no auth relay or RPC request; explicit checkbox consent and the
Start button are required. Approval opens only when the user clicks its link.

## What is actually checked

The official MIT-licensed `@farcaster/auth-client` 0.7.1 validates the SIWE
signature, Farcaster FID resource, domain, nonce, Optimism chain ID 10, and
on-chain custody or authorized auth-address ownership. Ratspeak additionally
requires the exact signed URI containing its current LXMF address, not-before
and expiry values, and a recent issuance time. It ignores the relay's unsigned
FID, username, image, and profile claims. Requests use 24 random bytes, expire
after five minutes, and are consumed once. Cancellation and identity changes
invalidate outstanding results.

The SIWE URI is the application's origin/path with only a `ratspeak_lxmf` query
parameter. Existing invitation fragments, query parameters, and credentials are
not forwarded. This is an account-signed address association in the current
session, not proof that another contact owns its Reticulum private key. Old
self-declared cards are never upgraded to verified. A signed portable directory
record, independently verifiable contact import, durable listing, removal, and
social graph lookup remain future work.

## Services and privacy

The experiment uses https://relay.farcaster.xyz and https://mainnet.optimism.io.
No application API key, backend, account provisioning, or secret is required.
Availability, CORS, public RPC rate limits, and compatible Farcaster wallet
support must be checked in a live deployment. These are public third-party
services, not a private or decentralized directory. The relay/wallet learn the
signed FID/LXMF association and origin; RPC receives account-verification queries.
Service operators can observe IP addresses and timing. Ownership lookup trusts the configured Optimism RPC to report registry state correctly; this browser is not an independent chain light client. A malicious or stale RPC can misreport custody/auth-address authorization even though the SIWE signature is cryptographically checked. No Reticulum private key
or chat plaintext is sent. A compromised hosting origin can still replace the
JavaScript. zkTLS is not used because SIWF already provides a protocol-native
account signature and ownership check without scraping account sessions.

## Evidence and remaining test

`node --test tests/farcaster-auth.test.mjs` exercises consent, URI isolation,
nonce/domain/chain/time mismatch, cancellation, invalid verified FID, relay
failure, single-use completion, and pending state with deterministic SDK stubs.
These are boundary tests, NOT proof of live Farcaster ownership verification.
`tests/farcaster-sdk.test.mjs` additionally uses real ephemeral-account SIWE
signatures with the official verifier and an injected registry fixture; it
rejects signature, custody-FID, domain, nonce, and chain mismatches without any
network requests. This does not establish ownership of a live Farcaster FID.
A live test still needs a willing account holder to explicitly approve the
exact signed request in their Farcaster wallet and confirm the displayed FID
and LXMF address. Do not claim that end-to-end test has passed until recorded.

## Primary sources inspected

- https://github.com/farcasterxyz/auth-monorepo/tree/main/packages/auth-client
- https://github.com/farcasterxyz/auth-monorepo/blob/main/packages/auth-client/src/messages/verify.ts
- https://github.com/farcasterxyz/auth-monorepo/blob/main/apps/relay/src/handlers.ts
- https://github.com/farcasterxyz/auth-monorepo/blob/main/apps/relay/src/env.ts

The published npm 0.7.1 package implementation was also inspected, including
SIWE validation, `verifyAuthorizedSigner`, and `viemConnector` RPC behavior.
