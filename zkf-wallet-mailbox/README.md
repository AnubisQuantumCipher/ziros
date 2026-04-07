# ZKF Wallet Mailbox

Compact mailbox contract scaffold for ZirOS wallet messaging on Midnight.

## What this package does

- Pins the same Compact toolchain versions used elsewhere in the repo.
- Compiles a wallet messaging mailbox contract schema under `contracts/compact/`.
- Provides a deployment manifest template that the wallet can consume once a mailbox contract is actually deployed.

## What this package does not do yet

- It does **not** make Rust wallet messaging transport operational by itself.
- The current wallet still reports mailbox transport as unavailable until a Rust-owned submit/query lane exists for posting and polling envelopes against the deployed contract.
- The contract schema is intentionally honest: it captures the wallet envelope fields and deployment shape now, without claiming that the end-to-end transport runtime is already finished.

## Scripts

- `npm run fetch-compactc`
- `npm run compile-contracts`
- `npm run typecheck`

## Envelope schema notes

The v1 contract records:

- sender/receiver fingerprints
- channel fingerprint
- message kind, sequence, epoch, posted time
- envelope hash
- fixed-width opaque envelope fields for nonce, ciphertext, ML-KEM ciphertext, sender identity public key, and sender signature

The fixed-width fields are sized for the current wallet-owned message envelope implementation in `zkf-wallet/src/messaging.rs`.
