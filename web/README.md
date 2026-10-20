# Ratspeak Web experiment

Standalone browser client experiment in `ChazSchmidt/Ratspeak`, branch `experiment/ratspeak-web`. No changes to Android, iOS or desktop. Core messaging is the priority; Farcaster migration lives in an optional dialog, not in the identity or messaging flow.

## Local development

```sh
cd web
npm install
npm run dev
npm run build
```

A HTTPS static host can serve the resulting `dist/`. **This is not ready for public identity onboarding.**

## Implemented first slice

- Browser-generated Reticulum identity and LXMF delivery destination using `@reticulum/core` + `@reticulum/lxmf`.
- Non-blocking "Coming from Farcaster?" dialog.
- Opt-in, **unverified** Farcaster FID + public destination invitations, import and local contact list.
- No hosted directory, backend, Farcaster API credentials, analytics, or server-side private keys.

## Missing before a public test

- Real browser-to-Reticulum connection and verified LXMF sending/receiving.
- Encrypted durable key storage and export/import. Keys currently vanish on refresh.
- Farcaster proof of account ownership and opt-in discovery against a social graph; currently self-declared invitations only.
- Security review and network interoperability tests with Ratspeak's Rust stack.
- Working local npm build and browser smoke test (not yet completed).

## Privacy model

Identity generation is local. The client must never upload private keys. Farcaster invitations contain *public* FIDs, handles and LXMF delivery addresses; link holders can read and forward them. Contacts are saved unencrypted in this browser's localStorage. A future relay may observe connection metadata, even if LXMF payloads are encrypted.

Third-party JavaScript dependencies and the hosting origin remain part of the browser trust boundary. Use secure HTTPS hosting and audit dependencies before inviting users.
