# Swarm Blueprint Signoff

This file is the authoritative Section 29 signoff artifact for the swarm-defense
blueprint tranche. It maps Sections 23 through 29 to concrete repo evidence.

## Section 23: Boundary And Non-Interference

- Boundary record: `PROOF_BOUNDARY.md`
- Ledger claims:
  - `swarm.non_interference`
  - `swarm.kill_switch_equivalence`
  - `swarm.reputation_boundedness`
  - `swarm.escalation_monotonicity`
  - `swarm.gossip_boundedness`
  - `swarm.coordinator_compromise_resilience`
  - `swarm.sybil_probationary_threshold`
  - `swarm.admission_pow_cost`
  - `swarm.controller_delegation_equivalence`
  - `swarm.controller_no_artifact_mutation_surface`
  - `swarm.constant_time_eval_equivalence`
  - `swarm.jitter_detection_boundedness`
- Kani harnesses:
  - `zkf-runtime/src/verification_kani.rs`
  - `zkf-core/src/verification_kani.rs`
  - `zkf-distributed/src/verification_kani.rs`
- Runtime kill-switch regression:
  - `zkf-integration-tests/tests/soundness.rs`
- Side-channel hardening surface:
  - `zkf-core/src/proof_kernel.rs`
  - `zkf-runtime/src/swarm/sentinel.rs`

## Section 24: Builder Bureaucracy

- Builder implementation: `zkf-runtime/src/swarm/builder.rs`
- Required promotion path: `Candidate -> Validated -> Shadow -> Live`
- Signed promotion and rollback records:
  - `~/.zkf/swarm/promotions/`
  - `~/.zkf/swarm/rollbacks/`
- Regression evidence:
  - `zkf-runtime/src/swarm/builder.rs` unit tests
  - `rogue_builder_cannot_skip_candidate_validated_shadow_live` in
    `zkf-integration-tests/tests/swarm_blueprint_pressure.rs`

## Section 25: Consensus And Gossip Wall

- Distributed gossip/consensus implementation:
  - `zkf-distributed/src/swarm/diplomat.rs`
  - `zkf-distributed/src/swarm/consensus.rs`
  - `zkf-distributed/src/coordinator.rs`
  - `zkf-distributed/src/worker.rs`
- Median activation helper:
  - `zkf-runtime/src/swarm/queen.rs`
- Bounded gossip theorem:
  - `swarm.gossip_boundedness`
- Honest-majority coordinator resilience theorem:
  - `swarm.coordinator_compromise_resilience`
- Attestation propagation and persistence:
  - `MessageBody::AttestationChain`
  - `zkf-distributed/src/swarm/memory.rs`
- Regression evidence:
  - `gossip_flood_stays_within_local_and_heartbeat_caps`
  - `flash_mob_requires_two_thirds_and_causes_dos_not_math_corruption`

## Section 26: Identity, Reputation, And Operator Contract

- Identity hardening:
  - `zkf-distributed/src/swarm/identity.rs`
  - admission PoW on `HandshakeMsg.admission_pow_nonce`
- Reputation model and verification:
  - `zkf-distributed/src/swarm/reputation.rs`
- Probation and admission theorems:
  - `swarm.sybil_probationary_threshold`
  - `swarm.admission_pow_cost`
- CLI contract:
  - `zkf swarm reputation <peer_id>`
  - `zkf swarm reputation --all`
  - `zkf swarm reputation-log <peer_id>`
  - `zkf swarm reputation-log --all`
  - `zkf swarm reputation-verify <peer_id>`
  - `zkf swarm reputation-verify --all`
- Regression evidence:
  - `reputation_farming_buys_at_most_one_pre_activation_hit`
  - `network_partition_recovers_without_reconciliation_logic`
  - `key_theft_rotation_invalidates_old_identity_and_flags_auth_failure`
  - `zkf-cli/src/tests/swarm.rs`

## Section 27: Pressure Scenarios

Named deterministic regressions live in:

- `zkf-integration-tests/tests/swarm_blueprint_pressure.rs`

Required scenarios:

- `slow_poison_routes_to_control_plane_without_swarm_escalation`
- `flash_mob_requires_two_thirds_and_causes_dos_not_math_corruption`
- `reputation_farming_buys_at_most_one_pre_activation_hit`
- `gossip_flood_stays_within_local_and_heartbeat_caps`
- `rogue_builder_cannot_skip_candidate_validated_shadow_live`
- `network_partition_recovers_without_reconciliation_logic`
- `key_theft_rotation_invalidates_old_identity_and_flags_auth_failure`

## Section 28: Freeze Protocol

- Freeze record: `PROOF_BOUNDARY.md`
- Rocq proof runner: `scripts/run_rocq_proofs.sh`
- Proof audit: `scripts/proof_audit.py`
- Zero-pending gate:
  - `jq '[.entries[] | select(.status=="pending")] | length' zkf-ir-spec/verification-ledger.json`
- Closed runtime BlackBox gap:
  - `witness.blackbox_runtime_checks`
  - evidence: `zkf-backends/tests/verification_prop.rs`
- Additional sealed-core closure claims:
  - `swarm.controller_delegation_equivalence`
  - `swarm.controller_no_artifact_mutation_surface`
  - `swarm.constant_time_eval_equivalence`
  - `swarm.jitter_detection_boundedness`

## Section 29: Signoff Status

- Section 23: implemented and ledgered with controller-path, evaluator, and jitter closures
- Section 24: implemented and regression-covered
- Section 25: implemented with median activation and attestation fan-out persistence
- Section 26: implemented with probationary admission, PoW gating, and capped reputation earning
- Section 27: implemented as named deterministic regression harnesses
- Section 28: freeze protocol recorded with zero-pending acceptance bar
- Section 29: this document
