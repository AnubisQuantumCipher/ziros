# ZirOS Neural Engine Operations

This document explains the Neural Engine and Core ML role in ZirOS.

## Scope

The Neural Engine lane in ZirOS is advisory control-plane infrastructure.

It is used for things like:

- scheduler hints
- backend ranking
- duration estimation
- anomaly scoring
- security-risk hints

It is not used for:

- proof validity
- verifier truth
- authorization truth
- replacing deterministic runtime policy

## Discovery Contract

Current model discovery order is:

1. `ZKF_*_MODEL`
2. `~/.zkf/models/*.mlpackage`
3. `target/coreml/*.mlpackage`

Repo-tracked fixture bundles live under:

```text
zkf-runtime/tests/fixtures/neural_engine/models/
```

Those fixtures are smoke-floor artifacts. Treat them as deterministic test
bundles, not as production-fresh operator models.

## Apple Silicon Relationship

Keep the runtime roles separate:

- Metal: authoritative proof acceleration
- Core ML / Neural Engine: advisory policy and scoring
- MLX local endpoints: preferred local assistant-model lane for the agent

For full machine setup and provider routing, read:

- [docs/agent/SETUP_APPLE_SILICON.md](agent/SETUP_APPLE_SILICON.md)
- [docs/agent/MEMORY_AND_LEARNING.md](agent/MEMORY_AND_LEARNING.md)

## Truth Rule

Model output must never be described as proof truth. Deterministic policy and
the proof/verifier boundary remain authoritative even when control-plane models
are present and healthy.
