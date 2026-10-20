# Ratspeak Web experiment

An isolated browser-first experiment in `ChazSchmidt/Ratspeak`. It does not modify the native Android, iOS or desktop applications.

## Run locally

```sh
cd web
npm install
npm run dev
```

`npm run build` creates a static `dist/` directory that can be served on HTTPS hosting. **This is a prototype, not yet ready for public identity onboarding.**

## What works in this initial slice

- Real Reticulum identity generation with `@reticulum/core` and an LXMF destination with `@reticulum/lxmf`, all within the browser tab.
- Opt-in, self-declared Farcaster FID + public LXMF destination cards, embedded in copyable links.
- Import cards and list contacts in browser localStorage; **no account, directory, database or backend required**.
- Links to an existing third-party browser Reticulum messenger for exploration.

## Not implemented / important caveats

- **No actual LXMF send/receive or transport connection**. Real messaging will need a browser WebSocket interface and accessible TLS WebSocket bridge, or direct browser-supported radio.
- **Private identity keys are currently ephemeral**. Refreshing the page loses them. Do not onboard real users until encrypted export/import and/or durable secure storage is implemented and tested.
- **No Farcaster login or proof of FID ownership**. Contact card labels are self-declared and can be impersonated. Never present these as verified credentials.
- **No automatic follower matching**. The zero-backend approach relies on sharing links through existing channels. Matching Farcaster social graphs will require a data source and an opt-in searchable directory or privacy-preserving discovery protocol.
- Imported contacts are public FIDs and LXMF addresses saved in localStorage, not encrypted.
- The upstream Reticulum/LXMF JavaScript implementation and native Rust Ratspeak stack require interoperability tests.
- Before deployment, check the `@reticulum/core` and `@reticulum/lxmf` package compatibility and carry out a local build and browser smoke test.

## Intent

Keep experimental browser onboarding and Farcaster diaspora functionality outside DeFi Dude's maintained native app code. Reuse upstream protocol implementations where feasible, and avoid treating a web-based contact directory as a secure messenger.
