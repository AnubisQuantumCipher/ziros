---
name: ziros-wallet-mac-finish
description: Finish the ZirOS Midnight Wallet macOS app with the approved Mac-first visual polish, using the real workspace build commands, proof-route checks, and visual-audit flows.
---

# ZirOS Wallet Mac Finish

Use this skill when working on the macOS wallet shell, approval flow presentation, overview hero surfaces, DUST-first UI, or Messages desktop polish.

## Repo truths

- App root: `/Users/sicarii/Desktop/ZirOS/zkf-wallet-app`
- Xcode project: `/Users/sicarii/Desktop/ZirOS/zkf-wallet-app/ZirOSWallet.xcodeproj`
- Project spec: `/Users/sicarii/Desktop/ZirOS/zkf-wallet-app/project.yml`
- Main view shell: `/Users/sicarii/Desktop/ZirOS/zkf-wallet-app/Sources/App/Views/ContentView.swift`
- Coordinator: `/Users/sicarii/Desktop/ZirOS/zkf-wallet-app/Sources/App/WalletCore/WalletCoordinator.swift`
- Shared visuals: `/Users/sicarii/Desktop/ZirOS/zkf-wallet-app/Sources/Shared`

## Commands

Run these from the repo root unless the task is narrower:

- `./.codex/setup.sh`
- `./.codex/actions/build-workspace.sh`
- `./.codex/actions/build-helper.sh`
- `./.codex/actions/build-mac-debug.sh`
- `./.codex/actions/run-mac-visual-audit.sh`

When the Xcode spec changes:

- `xcodegen generate --spec /Users/sicarii/Desktop/ZirOS/zkf-wallet-app/project.yml`

## Visual finish targets

- Locked state is a vault: motif, title, subtitle, one biometric CTA, no balances.
- Unlocked overview leads with NIGHT balance, privacy gauge, and DUST ring above the fold.
- Messages shows the crypto badge and DUST-forward messaging surfaces.
- DUST is its own hero dashboard, not a utility form.
- Approval sheet is amount-first, mono-heavy, and only the biometric button is blue.

## Acceptance

- `cargo build --workspace`
- `xcodebuild -project /Users/sicarii/Desktop/ZirOS/zkf-wallet-app/ZirOSWallet.xcodeproj -scheme ZirOSWallet -configuration Debug build`
- Mac visual audit states render cleanly for lock, overview, messages, DUST, transact, and approval.
- Proof route remains visible in settings and approval details.
- No UI polish weakens Rust-owned approval or proof-server gating.
