# Wrapping Security

This document is the authoritative security model for ZKF proof wrapping, proof composition, and
runtime trust-lane behavior.

## Scope

This document covers:

- Native proof wrapping, especially `stark-to-groth16`
- Wrapper planning and execution through UMPG
- The distinction between cryptographic proofs, host attestations, and metadata-only composition
- What verifiers can rely on from proof bytes alone versus what operators must validate separately

This document does not redefine backend soundness. For base proof-system assumptions and witness
soundness, see [SECURITY.md](/Users/sicarii/Projects/ZK DEV/docs/SECURITY.md).

## Trust Tiers

The runtime uses three trust tiers:

- `cryptographic`
  - The claimed statement is enforced inside a proof system and checked by a verifier.
- `attestation`
  - The host validated something about the execution or source artifacts, but the claim is not
    fully re-enforced inside the outer proof.
- `metadata-only`
  - The runtime emitted provenance or routing metadata without a cryptographic or host-attested
    enforcement claim.

Trust only weakens as graphs compose. A graph that depends on any weaker lane inherits that weaker
trust model.

## What Is Cryptographically Enforced

These properties are in scope for cryptographic enforcement:

- Base backend proof validity for Groth16, Halo2/IPA, Plonky3/STARK, Nova, and HyperNova according
  to their native verification rules.
- The `stark-to-groth16` wrapper statement when the runtime selects a strict cryptographic lane on
  the certified host profile.
- The wrapper circuit’s arithmetic linkage to the inner proof statement, including the non-native
  arithmetic required by the FRI verifier circuit.
- The public inputs and verification-key commitments that are explicitly constrained by the wrapper
  circuit.

In strict cryptographic wrapping, a valid outer proof means the wrapped statement was enforced in
the outer circuit, not merely observed by the host.

## What Is Only Operationally Attested

These properties are operational claims, not proof statements:

- That a specific host executed the wrapper under a healthy Metal or Neural Engine environment.
- That a specific runtime plan, cache path, or dispatch strategy was used.
- That a source proof artifact, compiled artifact, or auxiliary bundle on disk matched a digest the
  host recorded.
- Any dashboard, telemetry, or certification metadata that is stored next to a proof artifact.

The Neural Engine control plane is also operational only. It can influence scheduling, backend
selection, advisory ETA/bound reporting, and anomaly reporting, but it never performs proof
arithmetic and it does not alter proof soundness.

## Wrapper Modes And Their Guarantees

### Strict Cryptographic Wrap

This is the highest-assurance wrapping lane.

- The outer proof is the security boundary.
- Host hardware policy is an admission-control requirement, not the proof claim itself.
- The verifier can trust the outer proof statement, assuming the backend and circuit are sound.
- Operator metadata is useful for provenance, but verifier acceptance must not depend on it.

### Attestation Wrap

Attestation wrap is weaker by design.

- The host confirms source proof and artifact relationships.
- The outer artifact may carry binding metadata and digests.
- The verifier cannot treat this as equivalent to an in-circuit recursive proof unless the wrapper
  statement is explicitly enforced by the proof system.

Attestation mode is acceptable for operator workflows and package plumbing, but not as a substitute
for cryptographic recursion when cryptographic composition is required.

### Metadata-Only Composition

Metadata-only composition is bookkeeping, not a proof.

- It can preserve provenance.
- It can support workflow orchestration.
- It must not be presented as algebraically binding recursion or secure aggregation.

## Verifier Requirements

Verifiers must distinguish between proof validation and operational validation.

Proof-side requirements:

- Verify the outer proof against the correct verification key and public inputs.
- Verify the correct wrapper/backend mode was used for the claimed security level.
- Require the original source proof when the wrapper scheme relies on recomputing a source-proof
  commitment outside the outer proof.

Out-of-band requirements:

- Validate artifact provenance, binary lineage, and certification reports separately from proof
  verification.
- Treat runtime traces, hardware telemetry, cache-hit metadata, and ANE model metadata as operator
  evidence only.
- Re-check any source proof digest or compiled-artifact digest that the workflow expects to bind,
  unless that binding is explicitly enforced inside the outer proof.

If an operator or verifier needs cryptographic composition, they must require the strict
cryptographic wrapper lane and reject attestation-only or metadata-only results.

## Hardware, Runtime, And Model Boundaries

Hardware acceleration does not create trust by itself.

- Metal acceleration can improve proving throughput.
- Neural Engine models can improve control-plane decisions.
- Direct-wrap caches can reduce repeated work.

None of these change the verifier contract. They only affect execution behavior and operator
evidence.

The runtime may reject strict wrapping on unsupported or unhealthy hardware profiles. That is a
fail-closed admission decision, not a soundness failure in an already-produced proof.

## Fallback And Failure Semantics

The runtime has two different classes of failure:

- Soundness-relevant failures
  - Invalid witness, invalid inner proof, invalid outer proof, or incorrect wrapper statement.
  - These must hard-fail proof generation or verification.
- Operational or policy failures
  - Missing strict certification, Metal health guard rejection, unavailable model sidecar, or
    Neural Engine quality-gate failure.
  - These may trigger a different lane, a heuristic fallback, or a refusal to use a strict route.

Important distinction:

- Wrapper-lane fallback or rejection does not mean a previously generated proof became unsound.
- It means the runtime refused to claim a stronger wrapping or production-readiness guarantee under
  the current host conditions.

For the Neural Engine lane specifically:

- Missing or rejected models fall back to deterministic heuristics.
- The control plane can only affect optimization decisions.
- It cannot weaken proof validity because it does not execute proof arithmetic.
- On CPU-only or no-Metal fallback paths, exported ETA must be treated as advisory only unless a
  conservative bound is explicitly present and the artifact does not label the path as
  `non-sla-fallback`.

## Composition Rules

Use these rules when describing a composed artifact:

- If every dependency is cryptographic, the composed trust claim may remain cryptographic.
- If any dependency is attestation-only, the composed trust claim is attestation at best.
- If any dependency is metadata-only, the composed trust claim is metadata-only.

Do not upgrade a weaker trust claim in documentation, CLI output, or release notes.

Current aggregation truth:

- Attestation/metadata composition is current, useful, and not algebraically binding.
- `Halo2IpaAccumulator` is the current cryptographic/algebraic-binding aggregation path.
- `CryptographicGroth16Aggregator` remains fail-closed roadmap work until the in-circuit BN254
  final exponentiation and Frobenius constraints are complete and validated.

## Operator Guidance

Operators should:

- Use strict cryptographic wrapping when the deliverable is meant to be verifier-facing.
- Reserve attestation wrapping for workflow compatibility and operational bundling.
- Keep certification evidence, runtime traces, and source-artifact digests for incident review, but
  do not treat them as substitutes for proof verification.
- Re-run wrapper certification when the shipped binary changes, because certification is tied to the
  current build.

For operational commands and host bring-up, see
[DEPLOYMENT.md](/Users/sicarii/Projects/ZK DEV/docs/DEPLOYMENT.md) and
[M4_MAX_OPERATOR_HANDOFF.md](/Users/sicarii/Projects/ZK DEV/docs/M4_MAX_OPERATOR_HANDOFF.md).
