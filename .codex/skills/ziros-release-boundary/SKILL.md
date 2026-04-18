---
name: ziros-release-boundary
description: Preserve proof-first, source-private release behavior and keep local operator state out of release-grade evidence claims.
---

# ZirOS Release Boundary

- Default to local-only and source-private.
- Do not export `~/.hermes/**` as release evidence unless it is deliberately converted into repo-tracked generated artifacts.
- Keep release claims bound to proofs, digests, verifier assets, manifests, and forensics generated from the repo.
