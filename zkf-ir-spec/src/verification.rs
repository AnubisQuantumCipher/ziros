use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationCheckerKind {
    Kani,
    Proptest,
    Lean,
    Rocq,
    #[serde(rename = "rocq+verus")]
    RocqVerus,
    Fstar,
    Verus,
    RefinedRust,
    ThrustChc,
    GeneratedProof,
    ExternalAssumption,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Pending,
    BoundedChecked,
    MechanizedLocal,
    MechanizedGenerated,
    HypothesisStated,
    AssumedExternal,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationAssuranceClass {
    MechanizedImplementationClaim,
    BoundedCheck,
    AttestationBackedLane,
    ModelOnlyClaim,
    TrustedProtocolTcb,
    HypothesisCarriedTheorem,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct VerificationLedgerEntry {
    pub theorem_id: String,
    pub title: String,
    pub scope: String,
    pub checker: VerificationCheckerKind,
    pub status: VerificationStatus,
    pub evidence_path: String,
    pub notes: String,
    pub trusted_assumptions: Vec<String>,
}

impl VerificationLedgerEntry {
    pub fn assurance_class(&self) -> VerificationAssuranceClass {
        if self.status == VerificationStatus::BoundedChecked {
            return VerificationAssuranceClass::BoundedCheck;
        }

        if self.status == VerificationStatus::HypothesisStated {
            return VerificationAssuranceClass::HypothesisCarriedTheorem;
        }

        if self.status == VerificationStatus::AssumedExternal {
            return if self.theorem_id.starts_with("protocol.") {
                VerificationAssuranceClass::TrustedProtocolTcb
            } else {
                VerificationAssuranceClass::HypothesisCarriedTheorem
            };
        }

        if self.theorem_id.starts_with("protocol.") {
            VerificationAssuranceClass::TrustedProtocolTcb
        } else if self.theorem_id.starts_with("model.") || self.theorem_id.starts_with("zir.lang.")
        {
            VerificationAssuranceClass::ModelOnlyClaim
        } else {
            VerificationAssuranceClass::MechanizedImplementationClaim
        }
    }
}

impl Serialize for VerificationLedgerEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct VerificationLedgerEntryExport<'a> {
            theorem_id: &'a str,
            title: &'a str,
            scope: &'a str,
            checker: &'a VerificationCheckerKind,
            status: &'a VerificationStatus,
            assurance_class: VerificationAssuranceClass,
            evidence_path: &'a str,
            notes: &'a str,
            trusted_assumptions: &'a [String],
        }

        VerificationLedgerEntryExport {
            theorem_id: &self.theorem_id,
            title: &self.title,
            scope: &self.scope,
            checker: &self.checker,
            status: &self.status,
            assurance_class: self.assurance_class(),
            evidence_path: &self.evidence_path,
            notes: &self.notes,
            trusted_assumptions: &self.trusted_assumptions,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationLedger {
    pub schema: String,
    pub entries: Vec<VerificationLedgerEntry>,
}

pub fn verification_ledger() -> VerificationLedger {
    VerificationLedger {
        schema: "zkf-verification-ledger-v7".to_string(),
        entries: vec![
            VerificationLedgerEntry {
                theorem_id: "ccs.fail_closed_conversion".to_string(),
                title: "CCS synthesis never drops unsupported constraints silently".to_string(),
                scope: "zkf-core::ccs".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/CcsProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `synthesize_ccs_program_fail_closed_ok` proves successful extracted CCS synthesis is only possible on the supported equal/boolean/range/recursive-marker subset, so lookup and non-lowered blackbox constraints are rejected fail-closed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "ccs.supported_conversion_soundness".to_string(),
                title: "Supported CCS conversion preserves the extracted canonical CCS shape"
                    .to_string(),
                scope: "zkf-core::ccs".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/CcsProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `synthesize_ccs_program_supported_conversion_ok` proves successful extracted CCS synthesis simultaneously establishes the supported-program precondition and the canonical three-matrix CCS/R1CS shape with preserved matrix dimensions and expected multisets."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "lowering.lookup_preservation_bounded".to_string(),
                title:
                    "Supported lookup lowering fixes the selector/value-table shell shape on the owned boundary"
                        .to_string(),
                scope: "zkf-backends::r1cs_lowering".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/LookupLoweringProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `lookup_lowering_witness_preservation_ok` fixes the supported selector/value-table shell contract over the ZKF-owned lowering path: selector count, boolean guards, equality constraints, and output bindings are exactly the ones admitted by the proof-facing lowering surface. The existing randomized regression tests remain as the concrete witness-preservation backstop over the shipped Rust lowering path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.audit_retains_original_on_digest_mismatch".to_string(),
                title:
                    "Audited compile retains the original program when the source and compiled digests differ"
                        .to_string(),
                scope: "zkf-backends::audited_backend".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/verus/audited_backend_verus.rs".to_string(),
                notes:
                    "Local Verus theorem `audited_compile_retains_original_on_digest_mismatch_ok` proves the digest-mismatch branch is fail-closed: after the audited compile gates pass, `original_program` is retained exactly when the source and compiled digests differ. The existing Rust tests remain as a shell-level backstop."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.plonky3_lowering_soundness".to_string(),
                title: "Plonky3 backend lowering preserves successful trace-row acceptance on the supported proof surface"
                    .to_string(),
                scope: "zkf-backends::proof_plonky3_surface".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/Plonky3Proofs.v".to_string(),
                notes:
                    "Local Rocq theorem `plonky3_lowering_witness_preservation_ok` proves every successful extracted `build_trace_row` call simultaneously establishes lowered-program validation and trace-row acceptance on the supported equal/boolean/range/div backend proof surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.poseidon_lowering_soundness".to_string(),
                title: "Poseidon BN254 width-4 backend lowering is mechanized on the shipped proof surface"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_hash_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxHashProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `poseidon_bn254_width4_lowering_sound_ok` proves the extracted backend proof kernel accepts exactly the BN254 width-4 Poseidon lowering surface and records the solver-derived auxiliary-witness mode used by the backend-local boundary."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.poseidon_aux_witness_soundness".to_string(),
                title: "Poseidon BN254 width-4 backend aux-witness mode is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_hash_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxHashProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `poseidon_bn254_width4_aux_witness_sound_ok` proves the extracted Poseidon backend proof kernel fixes the aux-witness relation to the shipped solver-derived completion mode."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.poseidon_pastafq_lowering_soundness".to_string(),
                title: "Poseidon PastaFq width-4 backend lowering is mechanized on the shipped proof surface"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_hash_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxHashProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `poseidon_pastafq_width4_lowering_sound_ok` proves the extracted backend proof kernel accepts exactly the PastaFq width-4 Poseidon lowering surface and records the solver-derived auxiliary-witness mode used by the backend-local boundary."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.poseidon_pastafq_aux_witness_soundness".to_string(),
                title: "Poseidon PastaFq width-4 backend aux-witness mode is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_hash_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxHashProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `poseidon_pastafq_width4_aux_witness_sound_ok` proves the extracted PastaFq Poseidon backend proof kernel fixes the aux-witness relation to the shipped solver-derived completion mode."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.sha256_lowering_soundness".to_string(),
                title: "SHA-256 bytes-to-digest backend lowering is mechanized on the shipped proof surface"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_hash_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxHashProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `sha256_bytes_to_digest_lowering_sound_ok` proves the extracted backend proof kernel accepts exactly the bytes-to-digest SHA-256 lowering surface with a fixed 32-byte digest output."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.sha256_aux_witness_soundness".to_string(),
                title: "SHA-256 bytes-to-digest backend aux-witness mode is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_hash_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxHashProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `sha256_bytes_to_digest_aux_witness_sound_ok` proves the extracted SHA-256 backend proof kernel fixes the aux-witness relation to the shipped solver-derived completion mode."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.ecdsa_secp256k1_lowering_soundness".to_string(),
                title: "ECDSA secp256k1 byte-ABI backend lowering surface is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_ecdsa_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxEcdsaProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `ecdsa_secp256k1_byte_abi_lowering_sound_ok` proves the extracted backend proof kernel accepts exactly the shipped BN254-backed `160 -> 1` secp256k1 byte ABI and preserves its boolean-result contract."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.ecdsa_secp256k1_aux_witness_soundness".to_string(),
                title: "ECDSA secp256k1 byte-ABI backend aux-witness mode is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_ecdsa_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxEcdsaProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `ecdsa_secp256k1_byte_abi_aux_witness_sound_ok` proves the extracted secp256k1 backend proof kernel fixes the aux-witness relation to the arithmetic completion mode attached to that byte-ABI surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.ecdsa_secp256r1_lowering_soundness".to_string(),
                title: "ECDSA secp256r1 byte-ABI backend lowering surface is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_ecdsa_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxEcdsaProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `ecdsa_secp256r1_byte_abi_lowering_sound_ok` proves the extracted backend proof kernel accepts exactly the shipped BN254-backed `160 -> 1` secp256r1 byte ABI and preserves its boolean-result contract."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.ecdsa_secp256r1_aux_witness_soundness".to_string(),
                title: "ECDSA secp256r1 byte-ABI backend aux-witness mode is mechanized locally"
                    .to_string(),
                scope: "zkf-backends::proof_blackbox_ecdsa_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxEcdsaProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `ecdsa_secp256r1_byte_abi_aux_witness_sound_ok` proves the extracted secp256r1 backend proof kernel fixes the aux-witness relation to the arithmetic completion mode attached to that byte-ABI surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.add_zero".to_string(),
                title: "Algebraic identity Add(0, x) = x".to_string(),
                scope: "zkf-ir-spec::formal".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-ir-spec/proofs/rocq/Normalization.v".to_string(),
                notes: "Checked locally with coqc / Rocq for the arithmetic identity lemma."
                    .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.mul_one".to_string(),
                title: "Algebraic identity Mul(1, x) = x".to_string(),
                scope: "zkf-ir-spec::formal".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-ir-spec/proofs/lean/Normalization.lean".to_string(),
                notes: "Checked locally with Lean for the arithmetic identity lemma."
                    .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.sub_zero".to_string(),
                title: "Algebraic identity Sub(x, 0) = x".to_string(),
                scope: "zkf-ir-spec::formal".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-ir-spec/proofs/lean/Normalization.lean".to_string(),
                notes: "Checked locally with Lean for the arithmetic identity lemma."
                    .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.idempotence_bounded".to_string(),
                title: "normalize is idempotent on the supported arithmetic ZIR subset"
                    .to_string(),
                scope: "zkf-core::normalize".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-ir-spec/proofs/lean/Normalization.lean".to_string(),
                notes:
                    "Lean theorem `normalization_supported_program_idempotent` proves the extracted supported arithmetic normalization surface is idempotent under deterministic signal and constraint ordering. The existing randomized normalization regressions remain as backstops."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.canonical_digest_stability_bounded".to_string(),
                title:
                    "normalize gives equivalent supported arithmetic ZIR programs the same canonical digest"
                        .to_string(),
                scope: "zkf-core::normalize".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-ir-spec/proofs/lean/Normalization.lean".to_string(),
                notes:
                    "Lean theorem `normalization_supported_program_digest_stable` proves the extracted supported arithmetic normalization surface assigns the same canonical digest to programs with the same normalized signal and constraint key bags. The existing randomized normalization regressions remain as backstops."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.witness_preservation_bounded".to_string(),
                title:
                    "normalize preserves satisfying witnesses for the supported arithmetic ZIR subset"
                        .to_string(),
                scope: "zkf-core::normalize".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/TransformProofs.v".to_string(),
                notes:
                    "This bounded regression row is now discharged by the same local Rocq theorem `normalize_supported_program_preserves_checks_ok` used for `normalization.witness_preservation`; the proptest remains as a randomized backstop over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "normalization.witness_preservation".to_string(),
                title:
                    "normalize preserves satisfying witnesses for the supported arithmetic ZIR subset"
                        .to_string(),
                scope: "zkf-core::normalize".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/TransformProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `normalize_supported_program_preserves_checks_ok` proves the extracted supported-program normalization pass preserves successful checking on the supported arithmetic ZIR subset. The existing proptest entry remains as randomized regression coverage over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "optimizer.ir_witness_preservation_bounded".to_string(),
                title:
                    "optimize_program preserves satisfying witnesses for the supported arithmetic IR subset"
                        .to_string(),
                scope: "zkf-core::optimizer".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/TransformProofs.v".to_string(),
                notes:
                    "This bounded regression row is now discharged by the same local Rocq theorem `optimize_supported_ir_program_preserves_checks_ok` used for `optimizer.ir_witness_preservation`; the proptest remains as a randomized backstop over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "optimizer.ir_witness_preservation".to_string(),
                title:
                    "optimize_program preserves satisfying witnesses for the supported arithmetic IR subset"
                        .to_string(),
                scope: "zkf-core::optimizer".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/TransformProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `optimize_supported_ir_program_preserves_checks_ok` proves the extracted supported-program IR optimizer preserves successful checking on the supported arithmetic IR subset. The existing proptest entry remains as randomized regression coverage over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "optimizer.zir_witness_preservation_bounded".to_string(),
                title:
                    "optimize_zir preserves satisfying witnesses for the supported arithmetic ZIR subset"
                        .to_string(),
                scope: "zkf-core::optimizer_zir".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/TransformProofs.v".to_string(),
                notes:
                    "This bounded regression row is now discharged by the same local Rocq theorem `optimize_supported_zir_program_preserves_checks_ok` used for `optimizer.zir_witness_preservation`; the proptest remains as a randomized backstop over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "optimizer.zir_witness_preservation".to_string(),
                title:
                    "optimize_zir preserves satisfying witnesses for the supported arithmetic ZIR subset"
                        .to_string(),
                scope: "zkf-core::optimizer_zir".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/TransformProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `optimize_supported_zir_program_preserves_checks_ok` proves the extracted supported-program ZIR optimizer preserves successful checking on the supported arithmetic ZIR subset. The existing proptest entry remains as randomized regression coverage over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "field.large_prime_runtime_generated".to_string(),
                title:
                    "BN254, BLS12-381 scalar, PastaFp, and PastaFq runtime arithmetic is bound to the manifest-pinned Fiat-generated modules"
                        .to_string(),
                scope: "zkf-core::field".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/FieldGenerationProvenance.v".to_string(),
                notes:
                    "Local Rocq theorem `large_prime_runtime_fiat_binding_ok` proves the runtime dispatch provenance boundary: strict proof lanes route only to the manifest-pinned generated BN254/BLS12-381/PastaFp/PastaFq modules, with no handwritten large-prime fallback. `scripts/regenerate_fiat_fields.sh --check` remains the freshness gate, while `scripts/run_montgomery_assurance.sh` is retained only as regression coverage over the shipped Rust backstops."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "field.bn254_strict_lane_generated".to_string(),
                title:
                    "The strict BN254 runtime lane proves the Montgomery reduction constant, final subtraction, canonical multiply/divide normalization, and exclusion boundary"
                        .to_string(),
                scope: "zkf-core::field".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/Bn254MontgomeryStrictLane.v".to_string(),
                notes:
                    "Local Rocq theorem `bn254_strict_lane_bug_class_closed_ok` specializes the shipped BN254 strict field lane and closes the Montgomery bug class directly: it proves the checked reduction constant, the missing-final-subtraction guard, canonical multiply/divide normalization on the admitted BN254 path, and the manifest-pinned exclusion of uncertified alternate Montgomery implementations. `scripts/run_montgomery_assurance.sh` remains in the tree only as a regression backstop over the shipped Rust corpora and exclusion checks."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "field.small_field_runtime_semantics".to_string(),
                title:
                    "Goldilocks, BabyBear, and Mersenne31 runtime normalization, arithmetic, and inverse behavior are mechanized locally"
                        .to_string(),
                scope: "zkf-core::field".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/KernelFieldEncodingProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `small_field_runtime_semantics_ok` packages the extracted `normalize`/`Add_f_add`/`Sub_f_sub`/`Mul_f_mul`/`Div_f_div` surfaces for Goldilocks, BabyBear, and Mersenne31 and proves they compute the canonical modular semantics of the shipped small-field runtime. The existing property tests in `zkf-core/src/field.rs` remain as regression backstops over the Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.kernel_expr_eval_relative_soundness".to_string(),
                title: "Extracted proof-kernel expression evaluation is sound relative to the abstract extracted field primitives"
                    .to_string(),
                scope: "zkf-core::proof_kernel".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/KernelProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `eval_expr_sound_relative_ok` proves every `Result_Ok` result satisfies the hand-written `ExprEval` relation over the extracted datatypes. The extracted field operators are concretized to canonical modular semantics in the Rocq workspace, so this theorem is now axiom-free."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.kernel_expr_eval_soundness".to_string(),
                title: "Proof-kernel expression evaluation matches the intended field semantics"
                    .to_string(),
                scope: "zkf-core::proof_kernel".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/KernelProofs.v".to_string(),
                notes:
                    "The same Rocq theorem `eval_expr_sound_relative_ok` now discharges intended field semantics because the extracted `normalize`/`Add_f_add`/`Sub_f_sub`/`Mul_f_mul`/`Div_f_div`/`PartialEq_f_eq` definitions are concretized to canonical modular arithmetic in the generated workspace."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.kernel_constraint_relative_soundness".to_string(),
                title: "Extracted proof-kernel program checking is sound relative to the abstract extracted field primitives"
                    .to_string(),
                scope: "zkf-core::proof_kernel".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/KernelProofs.v".to_string(),
                notes:
                    "Local Rocq lemmas culminating in `check_program_sound_relative_ok` prove successful equal/boolean/range/lookup checking satisfies `ProgramHolds`. The extracted field predicates and operators are concretized to canonical modular semantics in the Rocq workspace, so this proof is now axiom-free."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.kernel_constraint_soundness".to_string(),
                title: "Proof-kernel constraint checking is sound for equal, boolean, range, and lookup constraints"
                    .to_string(),
                scope: "zkf-core::proof_kernel".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/KernelProofs.v".to_string(),
                notes:
                    "The same Rocq theorem `check_program_sound_relative_ok` now discharges intended equal/boolean/range/lookup semantics because the extracted field comparison and predicate definitions are concretized to canonical modular arithmetic in the generated workspace."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.kernel_adapter_preservation".to_string(),
                title:
                    "Public witness adapter shell preserves the translated kernel bundle on the supported boundary"
                        .to_string(),
                scope: "zkf-core::witness".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/WitnessAdapterProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `witness_kernel_adapter_preservation_ok` proves the proof-facing witness-adapter shell preserves the translated kernel program, witness, signal names, constraint labels, and table-name bundle once the supported equal/boolean/range/lookup boundary has been formed. The existing randomized tests remain as the concrete backstop over the shipped Rust translation path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.blackbox_runtime_checks".to_string(),
                title: "Critical BlackBox lowering and auxiliary-witness surfaces are mechanized for the shipped Poseidon, SHA-256, and ECDSA runtime tranche"
                    .to_string(),
                scope: "zkf-core::witness".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/BlackboxRuntimeProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `blackbox_runtime_checks_critical_surface_ok` bundles the shipped Poseidon BN254 width-4, SHA-256 bytes-to-digest, ECDSA secp256k1, and ECDSA secp256r1 lowering and aux-witness theorems. The ECDSA byte-ABI semantics carried by that theorem include malformed-ABI fail-closed behavior, boolean result forcing, and low-S enforcement on the extracted proof surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.generate_witness_non_blackbox_soundness".to_string(),
                title: "Extraction-safe non-blackbox witness generation returns witnesses accepted by the proof kernel"
                    .to_string(),
                scope: "zkf-core::proof_witness_generation_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/WitnessGenerationProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `generate_non_blackbox_witness_sound_ok` proves the extracted non-blackbox solver wrapper only returns witnesses accepted by `check_program`, and the extracted runtime now concretely implements the supported first-milestone subset: constant/input seeding, assignment evaluation, hint propagation, affine single-missing equalities, lookup output inference, radix decomposition, and final kernel validation. Residual Kani no longer attempts to restate this subset because CBMC translation cost materially exceeds the additional assurance."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "witness.generate_witness_soundness".to_string(),
                title: "generate_witness produces satisfying witnesses for supported plans"
                    .to_string(),
                scope: "zkf-core::witness".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/rocq/WitnessGenerationProofs.v".to_string(),
                notes:
                    "For programs satisfying `supports_pure_witness_core`, the public `generate_witness` entrypoint now delegates directly to the extracted proof-facing generator `spec_generate_non_blackbox_witness_checked`, so Rocq theorem `generate_non_blackbox_witness_sound_ok` covers the shipped pure-core runtime path. BlackBox and external-solver-dependent witness enrichment remain tracked separately."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_typed_views".to_string(),
                title:
                    "Pure BufferBridgeCore typed-view gating preserves modeled aligned lane writes and rejects misaligned u64/u32 reinterpretation"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `buffer_typed_view_surface_ok` mechanizes the proof-core typed-view boundary over `BufferBridgeCoreModel`: alignment-eligible u64/u32 views expose exactly `len / word_size` modeled lanes after writes carrying the same payload tag, while misaligned requests fail closed with zero typed lanes. The existing Kani/proptest harnesses remain byte-level regression backstops over the shipped Rust views."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_spill_reload_roundtrip".to_string(),
                title:
                    "Pure BufferBridgeCore spill and reload preserve modeled slot identity, length, and payload tag"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `buffer_spill_reload_roundtrip_surface_ok` mechanizes the proof-core spill/reload surface: evict -> ensure_resident preserves the modeled slot id, byte length, payload tag, and resident-byte accounting for spillable slots. The existing Kani/proptest harnesses remain byte-level regression backstops over the shipped runtime shell."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_read_write_bounded".to_string(),
                title:
                    "Pure BufferBridgeCore read/write guards reject missing slots and oversized writes while mutable typed views roundtrip bounded u32 lanes"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `buffer_read_write_layout_validity_ok` mechanizes the proof-core allocate/write layout invariants, slot identity, and fail-closed missing-slot boundary for all states; the existing Kani harness `buffer_read_write_guards_and_mutable_typed_views_roundtrip` remains checked as concrete typed-lane supporting evidence."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_residency_transition_bounded".to_string(),
                title:
                    "Pure BufferBridgeCore eviction and reload transitions reject stale reads and preserve bounded resident-byte accounting"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `buffer_residency_transition_sound_ok` mechanizes legal eviction/reload state transitions, stale-read rejection while evicted, and resident-byte accounting monotonicity over the pure buffer proof model; the existing Kani harness remains checked as concrete transition evidence."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_resident_accounting_refinedrust".to_string(),
                title:
                    "BufferBridgeCore resident-byte increment arithmetic is checked by RefinedRust on the shipped proof surface"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge_core::resident_bytes_after_add".to_string(),
                checker: VerificationCheckerKind::RefinedRust,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "formal/refinedrust/runtime-buffer-bridge/STATUS.md"
                    .to_string(),
                notes:
                    "RefinedRust/Radium generated and Rocq-checked `buffer_bridge_core_resident_bytes_after_add_proof` for the shipped `resident_bytes_after_add` helper, and the pure `BufferBridgeCore` allocate/write/reload paths delegate resident-byte increment arithmetic through that helper. The claim is limited to exact `usize` addition under the explicit no-overflow precondition; eviction subtraction, filesystem spill behavior, GPU residency, and full typed-view semantics remain covered by the existing Verus/Kani/proptest buffer rows."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_alias_separation_bounded".to_string(),
                title:
                    "Pure BufferBridgeCore distinct slots remain alias-separated under mutation and free"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `buffer_alias_separation_sound_ok` mechanizes that mutating or freeing one proof-core slot preserves the payload/length state of distinct slots and leaves the freed slot fail-closed inaccessible; the existing Kani harness remains checked as concrete byte-level support."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_typed_views_bounded".to_string(),
                title:
                    "BufferBridge typed-view shell is promoted against the mechanized BufferBridgeCore aligned-lane surface"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "This row now points at the same local Verus theorem `buffer_typed_view_surface_ok` as `runtime.buffer_typed_views`, with the shipped `BufferBridge` shell kept under randomized regression in `zkf-runtime/tests/verification_prop.rs` to exercise the concrete allocation and pointer-alignment path. Filesystem and GPU residency details remain explicit shell boundaries outside this theorem."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.buffer_spill_reload_roundtrip_bounded".to_string(),
                title:
                    "BufferBridge spill/reload shell is promoted against the mechanized BufferBridgeCore residency-roundtrip surface"
                        .to_string(),
                scope: "zkf-runtime::buffer_bridge".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/buffer_bridge_core_verus.rs"
                    .to_string(),
                notes:
                    "This row now points at the same local Verus theorem `buffer_spill_reload_roundtrip_surface_ok` as `runtime.buffer_spill_reload_roundtrip`, with the shipped `BufferBridge` shell kept under randomized regression in `zkf-runtime/tests/verification_prop.rs` to exercise concrete spill-file and allocator behavior. Filesystem and GPU residency details remain explicit shell boundaries outside this theorem."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.graph_topological_order_soundness".to_string(),
                title:
                    "Execution graph core topological order is mechanized on the shipped DAG ordering surface"
                        .to_string(),
                scope: "zkf-runtime::graph_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_graph_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_graph_topological_order_soundness` mechanizes the execution-core topological-order contract: acyclic execution graphs produce an ordering containing exactly the graph node count, while cyclic graphs fail closed outside the theorem precondition."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.graph_trust_propagation_monotonicity".to_string(),
                title:
                    "Execution graph core trust propagation only weakens downstream trust lanes"
                        .to_string(),
                scope: "zkf-runtime::graph_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_graph_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_graph_trust_propagation_monotonicity` mechanizes the execution-core trust-weaken relation used by the shipped graph propagation pass."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.scheduler_placement_resolution".to_string(),
                title:
                    "Execution scheduler core placement resolution is deterministic from pure runtime inputs"
                        .to_string(),
                scope: "zkf-runtime::scheduler_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_scheduler_placement_resolution` mechanizes the pure placement-resolution surface used by the shipped scheduler core before any driver side effects occur."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.scheduler_gpu_fallback_fail_closed".to_string(),
                title:
                    "Execution scheduler core GPU fallbacks remain fail-closed to CPU execution"
                        .to_string(),
                scope: "zkf-runtime::scheduler_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_scheduler_gpu_fallback_fail_closed` mechanizes the shipped scheduler-core fallback rule that unavailable or rejected GPU dispatch never bypasses the CPU fail-closed lane."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.scheduler_trace_accounting".to_string(),
                title:
                    "Execution scheduler core trace accounting preserves node counters and fallback totals"
                        .to_string(),
                scope: "zkf-runtime::scheduler_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_scheduler_trace_accounting` mechanizes the shipped scheduler-core report aggregation relation between GPU, CPU, and fallback node counters."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.execution_context_artifact_state_machine".to_string(),
                title:
                    "Execution context core artifact ownership states are mechanized on the shipped runtime surface"
                        .to_string(),
                scope: "zkf-runtime::execution_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_context_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_execution_context_artifact_state_machine` mechanizes the shipped execution-core artifact-state lattice for primary and wrapped proof outputs."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.api_control_plane_request_projection".to_string(),
                title:
                    "Runtime API core projects control-plane requests deterministically from execution context state"
                        .to_string(),
                scope: "zkf-runtime::api_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_api_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_api_control_plane_request_projection` mechanizes the shipped API-core job-kind and control-plane projection surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.api_backend_candidate_selection".to_string(),
                title:
                    "Runtime API core backend candidate selection is mechanized on the shipped decision surface"
                        .to_string(),
                scope: "zkf-runtime::api_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_api_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_api_backend_candidate_selection` mechanizes the shipped API-core backend-candidate selection rules for compiled, program-only, and default fallback execution."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.api_batch_scheduler_determinism".to_string(),
                title:
                    "Runtime API core batch scheduler sizing is deterministic from requested and total job counts"
                        .to_string(),
                scope: "zkf-runtime::api_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_api_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_api_batch_scheduler_determinism` mechanizes the shipped CPU worker-pool sizing rule used by batch backend proving."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.adapter_backend_graph_emission".to_string(),
                title:
                    "Runtime adapter core backend graph emission preserves positive witness, transcript, and artifact layout sizes"
                        .to_string(),
                scope: "zkf-runtime::adapter_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_adapter_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_adapter_backend_graph_emission` mechanizes the shipped adapter-core backend graph sizing surface used before buffer allocation."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.adapter_wrapper_graph_emission".to_string(),
                title:
                    "Runtime adapter core wrapper graph emission preserves positive source, verifier, and proof layout sizes"
                        .to_string(),
                scope: "zkf-runtime::adapter_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_adapter_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_adapter_wrapper_graph_emission` mechanizes the shipped adapter-core wrapper graph sizing surface used before buffer allocation."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.hybrid_verification_soundness".to_string(),
                title:
                    "Runtime hybrid core verification decision remains the logical conjunction of primary and companion verification"
                        .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_verification_soundness` mechanizes the shipped hybrid-core verification decision surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "runtime.hybrid_replay_manifest_determinism".to_string(),
                title:
                    "Runtime hybrid core replay-manifest identity is deterministic on the shipped proof-facing surface"
                        .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_replay_manifest_determinism` mechanizes the shipped replay-manifest identity surface used by hybrid proof orchestration."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "frontend.acir_translation_differential_bounded".to_string(),
                title:
                    "Noir ACIR recheck wrapper preserves translated constraints against the ACVM witness boundary"
                        .to_string(),
                scope: "zkf-frontends::noir".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-frontends/proofs/rocq/NoirRecheckProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `noir_acir_recheck_wrapper_sound_ok` proves only the ZKF-owned wrapper contract around `validate_translated_constraints_against_acvm_witness`; it does not claim ACVM or translator semantics. The existing importer and execute-path regressions remain as a backstop over the shipped Rust path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "aggregation.halo2_ipa_accumulation_bounded".to_string(),
                title:
                    "Halo2 IPA aggregation binding accepts only complete batches before deferred recomputation"
                        .to_string(),
                scope: "zkf-backends::wrapping::halo2_ipa_accumulator".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/verus/groth16_boundary_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `halo2_ipa_accumulation_binding_surface_ok` mechanizes the shipped `halo2_ipa_binding_accepts` helper surface: only non-empty batches with matching proof-hash and bound-G counts and zero malformed points are admitted before deferred IPA/Groth16 recomputation starts."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.ntt_differential_bounded".to_string(),
                title:
                    "Lean NTT family theorem binds the shipped staged radix-2 kernels to the verified dispatch and exported kernel inventory"
                        .to_string(),
                scope: "zkf-metal::ntt".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/Ntt.lean".to_string(),
                notes:
                    "Lean theorem `ntt_family_exact_transform_sound` mechanizes the shipped NTT family surface used by the verified Metal lane: the Goldilocks, BabyBear, and BN254 kernels keep their program ids, operator labels, region layouts, barrier placements, binding kinds, source-path inventory, and reflection/workgroup policies synchronized with the generated inventory and the verified dispatch path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.ntt_bn254_butterfly_arithmetic_sound".to_string(),
                title:
                    "Lean BN254 butterfly theorem mechanizes the shipped Montgomery-domain NTT arithmetic for the attested `ntt_butterfly_bn254` kernel"
                        .to_string(),
                scope: "zkf-metal::ntt".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/Ntt.lean".to_string(),
                notes:
                    "Lean theorem `gpu_bn254_ntt_butterfly_arithmetic_sound` closes the first counted GPU arithmetic tranche: the admitted `ntt_butterfly_bn254` program is bound to the shipped BN254 helper shader plus entrypoint source set, the Montgomery reduction constant and final-subtraction bug class are pinned locally, and the active butterfly branch computes `a + w*b` and `a - w*b` over canonical BN254 Montgomery-domain values. The `ntt_small_bn254` and `ntt_hybrid_bn254` surfaces remain tracked by the structural NTT family row in this tranche."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.msm_differential_bounded".to_string(),
                title:
                    "Lean MSM family theorem binds the shipped bucket-chain kernels to the verified dispatch and exported kernel inventory"
                        .to_string(),
                scope: "zkf-metal::msm".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/Msm.lean".to_string(),
                notes:
                    "Lean theorem `msm_family_exact_pippenger_sound` mechanizes the shipped MSM family surface used by the verified Metal lane: the BN254 classic chain and the Pallas/Vesta classic-or-NAF surfaces keep their program ids, operator labels, region layouts, route tags, source-path inventory, and reflection/workgroup policies synchronized with the generated inventory and the verified dispatch path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.poseidon2_differential_bounded".to_string(),
                title:
                    "Lean Poseidon2 family theorem binds the shipped scalar and SIMD kernels to the verified dispatch and exported kernel inventory"
                        .to_string(),
                scope: "zkf-metal::poseidon2".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/Poseidon2.lean".to_string(),
                notes:
                    "Lean theorem `poseidon2_family_exact_permutation_sound` mechanizes the shipped Poseidon2 family surface used by the verified Metal lane: the width-16 Goldilocks and BabyBear scalar/SIMD kernels keep their operator labels, region layouts, source-path inventory, and reflection/workgroup policies synchronized with the generated inventory and the verified dispatch path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.hash_differential_bounded".to_string(),
                title:
                    "Lean hash family theorem binds the shipped batch-hash kernels to the verified dispatch and exported kernel inventory"
                        .to_string(),
                scope: "zkf-metal::hash".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/Hash.lean".to_string(),
                notes:
                    "Lean theorem `hash_family_exact_digest_sound` mechanizes the shipped hash-family surface used by the verified Metal lane: the SHA-256 and Keccak-256 kernels keep their operator labels, region layouts, source-path inventory, and reflection/workgroup policies synchronized with the generated inventory and the verified dispatch path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.launch_contract_sound".to_string(),
                title:
                    "Lean launch-contract theorem proves every verified Metal dispatch stays within the admitted launch inventory"
                        .to_string(),
                scope: "zkf-metal::launch_contracts".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/LaunchSafety.lean".to_string(),
                notes:
                    "Lean theorem `gpu_launch_contract_sound` packages the exported launch-safety lemmas over the generated GPU program inventory: every admitted verified-lane dispatch has bounded reads, bounded writes, non-overlapping write regions, and balanced barrier scopes, so the Rust host must emit only launch descriptors already admitted by the checked Lean inventory."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.buffer_layout_sound".to_string(),
                title:
                    "Lean memory-model theorem proves verified GPU buffer layouts, alias separation, and writeback regions are structurally sound"
                        .to_string(),
                scope: "zkf-metal::memory_model".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/MemoryModel.lean".to_string(),
                notes:
                    "Lean theorem `gpu_buffer_layout_sound` closes the verified Metal buffer boundary over the generated program inventory: declared read/write/shared regions are bounded, aligned, non-aliased where required, initialized-read footprints are declared, and output writeback regions remain explicit. The Rust marshalling and unsafe boundary checks continue to run via the dedicated Verus GPU workspace, but the promoted row is the Lean memory-model theorem."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.dispatch_schedule_sound".to_string(),
                title:
                    "Lean schedule theorem proves the verified Metal stage order and chunking refine the already mechanized GPU family semantics"
                        .to_string(),
                scope: "zkf-metal::proof_ir".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/CodegenSoundness.lean".to_string(),
                notes:
                    "Lean theorem `gpu_dispatch_schedule_sound` lifts the per-family kernel theorems to the host schedule boundary: the verified GPU whitelist uses only the exported lowering bindings, step ordering, and barrier placements that refine the shipped hash, Poseidon2, NTT, and BN254 classic MSM semantics, with no silent alternate schedule in verified mode."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.shader_bundle_provenance".to_string(),
                title:
                    "Lean artifact-binding theorem binds the verified GPU lane to pinned metallib, reflection, and pipeline-descriptor digests"
                        .to_string(),
                scope: "zkf-metal::proof_ir".to_string(),
                checker: VerificationCheckerKind::Lean,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-metal/proofs/lean/CodegenSoundness.lean".to_string(),
                notes:
                    "Lean theorem `gpu_shader_bundle_provenance` closes the shader-provenance gap over the checked GPU manifest: every lowering certificate carries the source digest set, metallib digest, reflection digest, pipeline-descriptor digest, and pinned Xcode/SDK identity for the shipped entrypoints, and the runtime verified lane rejects any drift before dispatch."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.runtime_fail_closed".to_string(),
                title:
                    "Verus theorem proves the verified GPU lane fails closed on unavailable devices, drift, and unsupported dispatches"
                        .to_string(),
                scope: "zkf-runtime::scheduler".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs"
                    .to_string(),
                notes:
                    "Verus theorem `gpu_runtime_fail_closed` proves the runtime never silently substitutes an unverified path for the pinned GPU lane: unavailable GPUs, runtime-compiled libraries, artifact-digest drift, and nodes outside the verified whitelist all resolve to explicit rejection instead of invisible CPU fallback."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gpu.cpu_gpu_partition_equivalence".to_string(),
                title:
                    "Verus theorem proves verified CPU/GPU placement preserves prover truth across the composed execution plan"
                        .to_string(),
                scope: "zkf-runtime::scheduler".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_scheduler_verus.rs"
                    .to_string(),
                notes:
                    "Verus theorem `gpu_cpu_gpu_partition_equivalence` proves the runtime’s verified placement partition composes the mechanized GPU subset with the verified CPU lane without changing verifier truth: GPU-eligible nodes stay on the attested whitelist, CPU-routed nodes remain on the CPU proof surface, and the combined execution plan preserves the same accepted statement through final proof generation."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.frame_transport_bounded".to_string(),
                title:
                    "Framed transport shell validates length prefixes and rejects oversized frames fail-closed"
                        .to_string(),
                scope: "zkf-distributed::transport::frame".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_transport_verus.rs".to_string(),
                notes:
                    "Local Verus theorem `frame_transport_shell_contract_ok` proves the ZKF-owned framed transport shell only accepts validated length prefixes and fail-closed oversized-frame rejection before payload decoding. The existing randomized regression tests remain as a shell-level backstop over the reader and writer implementations."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.lz4_chunk_roundtrip_bounded".to_string(),
                title:
                    "LZ4 chunk wrapper preserves the size-prefixed roundtrip or propagates wrapper errors at the shell boundary"
                        .to_string(),
                scope: "zkf-distributed::transfer::compression".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_transport_verus.rs".to_string(),
                notes:
                    "Local Verus theorem `lz4_chunk_wrapper_contract_ok` proves the ZKF wrapper around `lz4_flex` preserves the size-prefixed roundtrip-or-error contract at the shell boundary. This does not claim an LZ4 algorithm proof, and the existing randomized regressions remain as a backstop."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.integrity_digest_corruption_bounded".to_string(),
                title:
                    "Integrity digest wrapper rejects corruption at the ZKF boundary with algorithm-selected exact digest comparison"
                        .to_string(),
                scope: "zkf-distributed::transfer".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_transport_verus.rs".to_string(),
                notes:
                    "Local Verus theorem `integrity_digest_corruption_rejection_ok` mechanizes corruption rejection at the ZKF boundary and splits local FNV behavior from the SHA-256 wrapper/equality path. The theorem only covers the algorithm-selected exact digest comparison and does not restate a cryptographic SHA-256 proof; the existing randomized transfer tests remain as a backstop."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "wrapping.groth16_cached_shape_matrix_free_fail_closed".to_string(),
                title:
                    "Cached-shape Groth16 keeps the shipped debug gate off without matrices and rejects matrix-free satisfaction inspection"
                        .to_string(),
                scope: "zkf-backends::arkworks".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/verus/groth16_boundary_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `groth16_cached_shape_matrix_free_fail_closed_ok` mechanizes the shipped `should_debug_check_constraint_system_mode` and matrix-free satisfaction rejection surface: the cached-shape debug gate is off whenever `construct_matrices == false`, setup is rejected, and prove-mode matrix inspection only proceeds when matrices are explicitly constructed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "backend.groth16_matrix_equivalence_bounded".to_string(),
                title:
                    "Groth16 outlined-row expansion gives identical materialized, streaming, and draining matrices on the shipped helper surface"
                        .to_string(),
                scope: "zkf-backends::arkworks".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/verus/groth16_boundary_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `groth16_matrix_equivalence_surface_ok` mechanizes the shipped Groth16 outlined-row helper surface and proves the materialized, streaming, and draining builders expose the same `ConstraintMatricesModel` whenever the shared expanded-row summary is fixed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "setup.groth16_deterministic_production_gate".to_string(),
                title:
                    "Strict Groth16 setup policy rejects dev-deterministic provenance outside explicit development opt-in"
                        .to_string(),
                scope: "zkf-backends::lib_non_hax".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/verus/groth16_boundary_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `groth16_deterministic_production_gate_strict_ok` mechanizes the shipped strict Groth16 setup gate: imported trusted setup material, fully reported auto-ceremony setup, and streamed local-ceremony setup are admitted, while dev-deterministic derived setup provenance is rejected unless the caller explicitly opts into development mode."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.non_interference".to_string(),
                title: "Swarm defense does not alter successful proof outputs".to_string(),
                scope: "zkf-runtime::swarm".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `swarm_non_interference_ok` proves the extracted swarm controller artifact path either rejects fail-closed or returns the original successful artifact bytes unchanged, upgrading the prior bounded Kani tranche to a local mechanized wrapper theorem."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.builder_rule_state_machine".to_string(),
                title: "Swarm builder only admits rule-state transitions on the shipped lattice"
                    .to_string(),
                scope: "zkf-runtime::swarm_builder_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_builder_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_builder_rule_state_machine` proves candidate rules cannot jump directly to Shadow or Live and that the shipped shadow-observation transition function promotes or revokes exactly on the guarded observation and false-positive thresholds."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.entrypoint_signal_routing".to_string(),
                title: "Swarm entrypoint security signals route exactly on the exported context"
                    .to_string(),
                scope: "zkf-runtime::swarm_entrypoint_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_entrypoint_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_entrypoint_signal_routing` proves each shipped security indicator forces the exported security-signal predicate high, while the all-clear context keeps the predicate false."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.encrypted_gossip_non_interference".to_string(),
                title: "Encrypted Swarm gossip leaves successful proof artifacts unchanged"
                    .to_string(),
                scope: "zkf-runtime::proof_swarm_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `swarm_encrypted_gossip_non_interference_ok` proves the extracted encrypted-gossip helper still preserves the original successful artifact bytes on the shipped non-interference surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.encrypted_gossip_fail_closed".to_string(),
                title: "Encrypted Swarm gossip rejects negotiated plaintext threat intelligence"
                    .to_string(),
                scope: "zkf-runtime::proof_swarm_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `swarm_encrypted_gossip_fail_closed_ok` proves the extracted negotiated encrypted-gossip helper reduces acceptance to `negb plaintext_present`, so plaintext threat metadata on a negotiated channel is rejected fail-closed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.kill_switch_equivalence".to_string(),
                title:
                    "Disabled Swarm proof surface fixes activation at Dormant with no consensus or telemetry"
                        .to_string(),
                scope: "zkf-runtime::proof_swarm_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `disabled_surface_state_is_dormant_ok` proves the extracted disabled-swarm proof surface fixes both activation fields at `Dormant` and returns `false` for consensus and telemetry. This row is intentionally scoped to the proof-facing disabled-swarm helper surface rather than the broader environment configuration path."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.reputation_boundedness".to_string(),
                title: "Swarm reputation updates stay within the closed unit interval".to_string(),
                scope: "zkf-distributed::swarm::reputation".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `swarm_reputation_boundedness_ok` proves the extracted decayed-score and bounded-decay helpers always return values produced by the shipped unit-interval clamp, upgrading the prior bounded Kani tranche to a local mechanized wrapper theorem."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.escalation_monotonicity".to_string(),
                title:
                    "Cooldown tick helper is non-deescalating under active cooldown and drops at most one level otherwise"
                        .to_string(),
                scope: "zkf-runtime::swarm_queen_core".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorems `cooldown_tick_non_deescalating_ok` and `cooldown_tick_drops_at_most_one_level_ok` prove the extracted swarm-queen cooldown helper preserves the current level while cooldown is active and otherwise de-escalates by at most one step on the shipped activation lattice."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.weighted_network_pressure_median".to_string(),
                title:
                    "Swarm queen weighted-pressure helper returns a shipped sample or zero on empty input"
                        .to_string(),
                scope: "zkf-runtime::swarm_queen_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_queen_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_queen_escalation_cooldown_monotonicity` proves the shipped weighted-pressure helper returns zero on empty input and otherwise returns one of the exported sample values at the median index."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.sentinel_rate_limit_soundness".to_string(),
                title: "Swarm sentinel digest emission obeys the exported per-window rate gate"
                    .to_string(),
                scope: "zkf-runtime::swarm_sentinel_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_sentinel_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_sentinel_rate_limit_and_baseline_soundness` proves zero rate limits reject emission, due-zero canaries always fire, and an under-cap digest in the current window produces a next-window state."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.sentinel_baseline_soundness".to_string(),
                title: "Swarm sentinel baseline sealing only fires on fresh sealed observation boundaries"
                    .to_string(),
                scope: "zkf-runtime::swarm_sentinel_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_sentinel_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_sentinel_rate_limit_and_baseline_soundness` proves the shipped baseline-sealing predicate is false when the same observation count was already committed with a matching baseline digest."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.gossip_boundedness".to_string(),
                title:
                    "Bounded gossip-count helper returns the pending count capped by `max(1, gossip_max)`"
                        .to_string(),
                scope: "zkf-distributed::swarm_diplomat_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_diplomat_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_diplomat_gossip_and_root_determinism` proves the shipped diplomat gossip-count helper returns `pending_len` when it is below the exported cap and otherwise returns `max(1, gossip_max)`."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.warrior_quorum_soundness".to_string(),
                title: "Swarm warrior quorum and honeypot gates match the shipped diversity checks"
                    .to_string(),
                scope: "zkf-runtime::swarm_warrior_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_warrior_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_warrior_quorum_diversity_honeypot` proves low-activation paths do not require quorum, the shipped two-of-three threshold accepts while one-of-three rejects, and honeypot acceptance is equivalent to observing zero failing results."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.coordinator_acceptance_soundness".to_string(),
                title:
                    "Swarm coordinator acceptance preserves digest-prefix equality under the explicit attestation-honesty premise"
                        .to_string(),
                scope: "zkf-distributed::swarm_coordinator_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/distributed_coordinator_swarm_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_coordinator_acceptance_soundness` proves that, under the explicit attestation-honesty premise for the shipped output/trace agreement surface, the shipped coordinator acceptance helpers preserve digest-prefix equality and reduce attestation agreement to the conjunction of output and trace matches."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.protocol_digest_codec_determinism".to_string(),
                title:
                    "Swarm protocol digest codec roundtrip is deterministic on the shipped transport surface"
                        .to_string(),
                scope: "zkf-distributed::swarm_protocol_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_transport_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_transport_and_protocol_fail_closed` proves the shipped protocol digest codec roundtrip predicate is true on the proof surface used by the transport and protocol cores."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.consensus_two_thirds_threshold".to_string(),
                title: "Swarm consensus accepts exactly at the shipped two-thirds threshold"
                    .to_string(),
                scope: "zkf-distributed::swarm_consensus_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_consensus_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_consensus_two_thirds_threshold` proves the shipped quorum predicate accepts two-of-three and rejects two-of-four on the consensus core threshold surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.diplomat_intelligence_root_determinism".to_string(),
                title:
                    "Swarm diplomat intelligence-root derivation is deterministic on shipped leaf counts"
                        .to_string(),
                scope: "zkf-distributed::swarm_diplomat_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_diplomat_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_diplomat_gossip_and_root_determinism` proves the shipped diplomat intelligence-root helper returns `1` on empty input and otherwise preserves the sorted leaf count exactly."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.epoch_negotiation_fail_closed".to_string(),
                title:
                    "Swarm epoch negotiation only admits the shipped encrypted-gossip capability surface"
                        .to_string(),
                scope: "zkf-distributed::swarm_epoch_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_epoch_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_epoch_negotiation_fail_closed` proves the shipped epoch negotiation surface fails closed without remote epoch keys and that plaintext threat metadata is only exposed when the exported threat indicators are actually present."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.identity_bundle_pow_binding".to_string(),
                title:
                    "Swarm identity prefers the shipped hybrid bundle and binds admission proof-of-work difficulty"
                        .to_string(),
                scope: "zkf-distributed::swarm_identity_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_identity_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_identity_bundle_pow_binding` proves bundle-present identities prefer the hybrid bundle bytes and the shipped admission proof-of-work predicate accepts exactly when the leading-zero count meets the configured difficulty."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.memory_snapshot_identity".to_string(),
                title:
                    "Swarm memory snapshots preserve signing-byte length and chain-head identity under the explicit attestation-honesty premise"
                        .to_string(),
                scope: "zkf-distributed::swarm_memory_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_memory_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_memory_append_only_identity` proves that, under the explicit attestation-honesty premise for the shipped snapshot signature surface, the shipped memory snapshot signing-byte layout dominates the job identifier length and imported chain heads remain stable exactly when they match the exported head."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.transport_integrity_fail_closed".to_string(),
                title:
                    "Swarm transport rejects oversized frames and negotiated plaintext fail-open states"
                        .to_string(),
                scope: "zkf-distributed::swarm_transport_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_transport_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_transport_and_protocol_fail_closed` proves the shipped transport frame guard rejects lengths above the configured maximum and the encrypted-gossip surface rejects plaintext on negotiated channels."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.memory_append_only_convergence".to_string(),
                title: "Append-only Swarm memory snapshots preserve the exported prefix"
                    .to_string(),
                scope: "zkf-distributed::swarm_memory_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_memory_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_memory_append_only_identity` mechanizes the shipped append-only snapshot/import helper surface and proves exported memory-chain identity is preserved across authenticated snapshot extension and verified import."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.intelligence_root_convergence".to_string(),
                title: "Canonical Swarm intelligence ordering converges across insertion orders"
                    .to_string(),
                scope: "zkf-distributed::swarm_diplomat_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/verus/swarm_diplomat_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `swarm_diplomat_gossip_and_root_determinism` mechanizes the shipped sorted-leaf-count intelligence-root helper surface and proves the exported intelligence-root result is deterministic on the canonicalized leaf multiset."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.coordinator_compromise_resilience".to_string(),
                title:
                    "Three-input median activation helper preserves `Alert` under a two-alert one-dormant majority"
                        .to_string(),
                scope: "zkf-distributed::proof_swarm_reputation_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `median_activation_level_three_honest_majority_alert_ok` proves the extracted three-input median helper returns `Alert` for each permutation of two `Alert` inputs and one `Dormant` input."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.sybil_probationary_threshold".to_string(),
                title:
                    "Probationary peer score helper fixes the shipped probationary score at 35 basis points"
                        .to_string(),
                scope: "zkf-distributed::proof_swarm_reputation_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `probationary_peer_score_basis_points_is_capped_addition_ok` proves the extracted probationary-score helper returns the shipped 35 basis-point score for every raw gain input. This row is intentionally scoped to the proof-facing helper surface rather than the full rolling reputation process."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.admission_pow_cost".to_string(),
                title:
                    "Admission proof-of-work cost helper preserves the shipped per-admission unit-cost surface"
                        .to_string(),
                scope: "zkf-distributed::proof_swarm_reputation_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `admission_pow_total_cost_is_exact_product_ok` proves the extracted proof-facing admission-cost helper currently returns `unit_cost_seconds` on the shipped helper surface for every peer-count input. This row is intentionally scoped to that helper surface rather than a hardware benchmark or broader cluster economics claim."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.controller_delegation_equivalence".to_string(),
                title:
                    "Controller artifact helper matches the pure successful-artifact path on the shipped enable/reject surface"
                        .to_string(),
                scope: "zkf-runtime::proof_swarm_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `controller_artifact_path_matches_pure_helper_ok` proves the extracted controller artifact helper is extensionally equal to the pure successful-artifact preservation helper on the shipped enabled/reject boundary."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.controller_no_artifact_mutation_surface".to_string(),
                title: "Controller proof surface exposes zero artifact-mutation operations"
                    .to_string(),
                scope: "zkf-runtime::proof_swarm_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/SwarmProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `controller_artifact_mutation_surface_absent_ok` proves the extracted controller proof surface reports zero artifact-mutation operations."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.constant_time_eval_equivalence".to_string(),
                title:
                    "The shipped constant-time evaluator shell matches the production-called reference result-shape bridge"
                        .to_string(),
                scope: "zkf-core::proof_constant_time_bridge".to_string(),
                checker: VerificationCheckerKind::Fstar,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/fstar/ConstantTimeProofs.fst".to_string(),
                notes:
                    "Local F* theorem `eval_expr_constant_time_reference_result_equivalence` proves the production-called constant-time evaluator bridge and the production-called reference bridge return the same result-shape tree for every shipped expression shell. This row remains scoped to evaluator-shell schedule/result-shape equivalence rather than universal microarchitectural non-interference of backend arithmetic."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "swarm.jitter_detection_boundedness".to_string(),
                title:
                    "Sentinel jitter detection keeps variance and observation scores finite on Sentinel-owned probe buffers and timing inputs"
                        .to_string(),
                scope: "zkf-runtime::swarm::sentinel".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/swarm_sentinel_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `jitter_detection_timing_model_finite_ok` mechanizes the shipped `WelfordState` and `JitterState` timing surface, proving the variance, z-score, variance-delta score, and dedicated probe-buffer duration score stay finite and non-negative on Sentinel-owned timing inputs."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.alias_resolution_correctness_bounded".to_string(),
                title:
                    "Canonical input-key helper resolves an alias target or preserves the requested key"
                        .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `canonical_input_key_string_resolves_alias_ok` proves the extracted canonical-input-key helper returns the alias target when present and otherwise preserves the requested key."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.digest_mismatch_rejection_bounded".to_string(),
                title:
                    "Program digest guard rejects mismatched digests on the embedded app proof surface"
                        .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `program_digest_guard_rejects_mismatch_ok` proves the extracted program-digest guard returns `false` whenever the expected and found digests differ."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.error_propagation_completeness_bounded".to_string(),
                title: "Program mismatch field helper preserves the expected and found digests"
                    .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `program_mismatch_fields_preserve_expected_and_found_ok` proves the extracted mismatch-field helper preserves the exact expected and found digest strings."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.default_backend_validity_bounded".to_string(),
                title: "Default embedded backend helper is total over the shipped proof field enum"
                    .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `default_backend_for_proof_field_spec_total_ok` proves the extracted default-backend helper returns a concrete shipped backend for every proof-field constructor."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.powered_descent_euler_step_determinism".to_string(),
                title: "Powered descent Euler-step helper is deterministic on the shipped fixed-point surface"
                    .to_string(),
                scope: "zkf-runtime::proofs::verus::powered_descent_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/powered_descent_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `powered_descent_euler_step_is_deterministic` fixes the shipped fixed-point Euler update relation for velocity and position on the powered-descent finished-app proof surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.powered_descent_thrust_magnitude_sq_nonnegative".to_string(),
                title:
                    "Powered descent thrust-magnitude square stays non-negative on the shipped proof surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::powered_descent_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/powered_descent_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `powered_descent_thrust_magnitude_sq_is_nonnegative` mechanizes the non-negativity of the squared thrust magnitude witness used by the powered-descent throttle bound checks."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.powered_descent_glide_slope_squaring_soundness".to_string(),
                title:
                    "Powered descent glide-slope squaring fixes the non-negative squared cone side condition on the shipped proof surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::powered_descent_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/powered_descent_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `powered_descent_glide_slope_squaring_preserves_direction` fixes the non-negative squared-side-condition witness shape used by the powered-descent cone gate after altitude positivity and radial-witness normalization are established by the application surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.powered_descent_mass_positivity_under_bounded_burn".to_string(),
                title:
                    "Powered descent mass-update surface carries an explicit positive-next-mass side condition"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::powered_descent_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/powered_descent_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `powered_descent_mass_stays_positive_under_bounded_consumption` fixes the positive-next-mass side condition consumed by the powered-descent witness model after burn accounting has established the concrete next-step mass witness."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.powered_descent_running_min_monotonicity".to_string(),
                title:
                    "Powered descent running minimum altitude is monotonically non-increasing on the shipped proof surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::powered_descent_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/powered_descent_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `powered_descent_running_min_is_monotone_nonincreasing` fixes the shipped running-min update relation used for the public minimum-altitude output."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_surface_constants".to_string(),
                title:
                    "Reentry assurance surface constants fix the shipped transparent mission profile"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_surface_constants` fixes the theorem-first reentry surface constants: 256-step horizon, 5 public outputs, 1e6 fixed-point scale, and the shipped altitude/velocity bounds."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_accepted_profile_fits_goldilocks".to_string(),
                title:
                    "Reentry accepted arithmetic profile stays below the Goldilocks modulus at the published velocity and rho*v^2 bounds"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_accepted_profile_fits_goldilocks_modulus` fixes the accepted 10^3-profile headroom statement used by the shipped RK4 reentry lane."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_signed_bound_slack_soundness".to_string(),
                title:
                    "Reentry signed-bound slack witnesses reconstruct the shipped square-bound relation"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_signed_bound_slack_reconstructs` fixes the bound^2 - value^2 slack relation used by the reentry app's signed residual checks."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_signed_residual_split_soundness".to_string(),
                title:
                    "Reentry signed residual splits reconstruct the shipped positive-minus-negative form"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_signed_residual_split_reconstructs` fixes the positive-minus-negative residual decomposition used by the theorem-first reentry surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_floor_sqrt_bracketing".to_string(),
                title:
                    "Reentry floor-sqrt witnesses reconstruct the shipped heating-support relation"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_floor_sqrt_brackets_value` fixes the equal-plus-remainder and next-square support relation consumed by the reentry heating-support square-root witnesses."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_exact_division_soundness".to_string(),
                title:
                    "Reentry exact-division witnesses reconstruct the shipped quotient-remainder relations"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_exact_division_reconstructs` fixes the exact-division relation used throughout the reentry state-transition and thermal-support witness surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_heating_factorization_soundness".to_string(),
                title:
                    "Reentry heating witnesses reconstruct the shipped staged Sutton-Graves factorization"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_heating_rate_factorization_reconstructs` fixes the staged exact-division factorization used to derive the shipped peak-heating witness from `k_sg`, `sqrt(rho/r_n)`, and the fixed-point cubic-speed term."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_running_max_monotonicity".to_string(),
                title:
                    "Reentry running maxima are monotonically non-decreasing on the shipped proof surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_running_max_is_monotone` fixes the monotone running-maximum relation used for the peak dynamic-pressure and peak heating outputs."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_compliance_bit_boolean".to_string(),
                title:
                    "Reentry compliance receipts project a boolean compliance bit on the shipped proof surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_compliance_bit_is_boolean` fixes the 0/1 receipt semantics used by the theorem-first reentry assurance bundle."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_manifest_window_contains_signed_pack".to_string(),
                title:
                    "Reentry signer manifests bound signed-pack validity windows on the shipped operator surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_manifest_window_contains_signed_pack` fixes the manifest-window containment relation enforced by signed reentry mission-pack validation."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_receipt_projection_preserves_signed_digests".to_string(),
                title:
                    "Reentry receipt projection preserves the signed mission-pack and manifest digests"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_receipt_projection_preserves_signed_digests` fixes the digest and horizon equality relation carried from the signed mission pack + signer manifest into the public reentry assurance receipt."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_rk4_weighted_step_soundness".to_string(),
                title:
                    "Reentry RK4 weighted-step witnesses reconstruct the shipped sixth-step averaging relation"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_rk4_weighted_step_reconstructs` fixes the k1 + 2k2 + 2k3 + k4 = 6*delta + remainder relation used by the accepted RK4 reentry kernel."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_interpolation_band_soundness".to_string(),
                title:
                    "Reentry atmosphere and sine interpolation witnesses stay inside the selected private band"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_interpolation_respects_selected_band` fixes the selected-band interpolation relation used by the accepted atmosphere and sine surfaces."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_cosine_closure_soundness".to_string(),
                title:
                    "Reentry cosine witnesses close the accepted unit-circle relation against the selected sine lane"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_cosine_closure_tracks_unit_circle` fixes the floor-sqrt closure used to derive cosine from 1 - sin^2 in the accepted RK4 surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_abort_latch_monotonicity".to_string(),
                title:
                    "Reentry abort latches are sticky across the accepted nominal-or-abort branch"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_abort_latch_is_sticky` fixes the previous || trigger transition used by the accepted reentry abort latch."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_first_trigger_legality".to_string(),
                title:
                    "Reentry first-trigger witnesses mark exactly the abort-latch rising edge"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_first_trigger_marks_latch_rise` fixes the first_trigger = trigger && !previous_latch relation used by the accepted reentry abort semantics."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "app.reentry_abort_branch_mode_selection".to_string(),
                title:
                    "Reentry abort branches select exactly the nominal or abort-corridor mode on the accepted surface"
                        .to_string(),
                scope: "zkf-runtime::proofs::verus::reentry_assurance_verus".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/reentry_assurance_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reentry_abort_branch_selects_only_one_mode` fixes the boolean mode-selection relation for the accepted nominal-versus-abort corridor branch."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.and_verification_semantics_bounded".to_string(),
                title: "Hybrid verify decision helper remains logical AND over the two shipped legs"
                    .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_verification_soundness` mechanizes the shipped `hybrid_verify_decision` helper in `zkf-runtime::hybrid_core`: hybrid verification succeeds exactly when both shipped legs succeed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.transcript_hash_binding_bounded".to_string(),
                title:
                    "Recorded digest helper rejects missing or mismatched transcript-digest entries"
                        .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_verification_soundness` mechanizes the shipped `digest_matches_recorded_hash` helper in `zkf-runtime::hybrid_core`: the helper returns `false` when the recorded digest is missing or when the recorded bytes differ from the expected bytes."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.hardware_probe_rejection_bounded".to_string(),
                title: "Hardware probe helper rejects unhealthy or mismatched probe summaries"
                    .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_verification_soundness` mechanizes the shipped `hardware_probes_clean` helper in `zkf-runtime::hybrid_core`: the helper returns `false` whenever the summary reports either an unhealthy probe or a mismatch."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.primary_leg_outer_artifact_binding_bounded".to_string(),
                title:
                    "Primary-leg byte comparison helper rejects proof or verification-key divergence"
                        .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_verification_soundness` mechanizes the shipped `hybrid_primary_leg_byte_components_match` helper in `zkf-runtime::hybrid_core`: the helper returns `false` when either the proof bytes or verification-key bytes diverge."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.replay_manifest_determinism_bounded".to_string(),
                title:
                    "Replay manifest identity helper is deterministic on the shipped replay-manifest surface"
                        .to_string(),
                scope: "zkf-runtime::hybrid_core".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/runtime_execution_hybrid_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `runtime_hybrid_replay_manifest_determinism` mechanizes the shipped `replay_manifest_identity_is_deterministic` helper in `zkf-runtime::hybrid_core`: the helper is deterministic on the replay-id, transcript-hash, backend-route, hardware-profile, and stage-manifest digest components."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.ml_dsa_bundle_verification_bounded".to_string(),
                title:
                    "Hybrid swarm signature bundles require both Ed25519 and ML-DSA material before verification"
                        .to_string(),
                scope: "zkf-distributed::swarm::identity".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `hybrid_signature_material_complete_is_logical_and_ok` proves the extracted hybrid material gate is exactly the logical conjunction of Ed25519 and ML-DSA material presence on the shipped helper surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "hybrid.admission_pow_identity_bytes_bounded".to_string(),
                title:
                    "Hybrid admission proof-of-work binds to canonical hybrid identity bytes when a bundle is present"
                        .to_string(),
                scope: "zkf-distributed::swarm::identity".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `hybrid_admission_pow_identity_prefers_bundle_ok` proves the extracted admission proof-of-work identity-byte helper returns the bundle encoding whenever one is present and otherwise preserves the legacy key bytes."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.acceptance_soundness".to_string(),
                title:
                    "Distributed acceptance helper requires quorum gating and digest agreement under the explicit attestation-honesty premise"
                        .to_string(),
                scope: "zkf-distributed::coordinator".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `distributed_acceptance_surface_requires_all_preconditions_ok` proves that, under the explicit attestation-honesty premise for the shipped coordinator acceptance surface, distributed acceptance is exactly `attestation_matches && coordinator_requires_quorum_spec(...) && digests_agree`."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.hybrid_signature_verification".to_string(),
                title:
                    "Distributed hybrid bundle surface requires both public-key and signature bundle metadata"
                        .to_string(),
                scope: "zkf-distributed::swarm::identity".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmReputationProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `hybrid_bundle_surface_complete_is_logical_and_ok` proves the extracted signed-message helper requires both public-key bundle and signature bundle metadata before the hybrid verification surface continues."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.encrypted_gossip_tamper_rejection_bounded".to_string(),
                title: "Extracted encrypted-gossip negotiation helper rejects plaintext on negotiated links and any payload on unnegotiated links".to_string(),
                scope: "zkf-distributed::swarm::epoch".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmEpochProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `distributed_encrypted_gossip_fail_closed_ok` proves the extracted encrypted-gossip negotiation helper returns `!plaintext_present` on negotiated links and `!plaintext_present && !encrypted_payload_present` on unnegotiated links. Existing regressions continue to exercise bounded ciphertext tamper scenarios outside this helper proof."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "distributed.snapshot_authenticated_roundtrip_bounded".to_string(),
                title: "Extracted snapshot helpers preserve append-only prefixes and identical exported chain heads".to_string(),
                scope: "zkf-distributed::swarm::memory".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-distributed/proofs/rocq/SwarmEpochProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `snapshot_authenticated_roundtrip_helper_surface_ok` proves the extracted append-only prefix helper is always preserved and the extracted chain-head roundtrip helper returns `true` whenever the imported head matches the exported head exactly. Existing regressions continue to exercise bounded mutation and intelligence-root ordering outside this narrowed mechanized surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "pipeline.cli_runtime_path_composition".to_string(),
                title: "CLI/runtime transform pipeline preserves kernel acceptance on the supported arithmetic surface"
                    .to_string(),
                scope: "zkf-runtime::proof_runtime_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/rocq/RuntimePipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `cli_runtime_path_composition_ok` lifts the core `cli_runtime_pipeline_to_kernel_sound_ok` chain into the runtime wrapper surface, additionally discharging the shipped default-backend candidate gate used by the CLI/runtime prove path before kernel acceptance is claimed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "pipeline.embedded_default_path_composition".to_string(),
                title: "Embedded default transform pipeline preserves kernel acceptance on the supported arithmetic surface"
                    .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `embedded_default_path_composition_ok` lifts the core `embedded_default_pipeline_to_kernel_sound_ok` chain into the shipped embedded helper surface, discharging alias resolution, digest-byte equality gating, and default-backend selection before kernel acceptance is claimed."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "orbital.surface_constants".to_string(),
                title:
                    "Orbital fixed-point public surface constants are mechanized for the shipped five-body, thousand-step showcase"
                        .to_string(),
                scope: "zkf-runtime::orbital_fixed_point_spec".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/orbital_dynamics_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus proof `orbital_surface_constants` fixes the published orbital showcase surface exactly: five private bodies, one thousand Velocity-Verlet steps, thirty-five private inputs, five public outputs, and ten unordered body pairs."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "orbital.position_update_half_step_soundness".to_string(),
                title:
                    "Orbital fixed-point position updates reconstruct the admitted half-step residual relation exactly"
                        .to_string(),
                scope: "zkf-runtime::orbital_fixed_point_spec".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/orbital_dynamics_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus proof `orbital_position_update_reconstructs_exact_half_step` proves the public fixed-point position update surface is not merely deterministic: the committed next-position lane reconstructs the exact half-acceleration residual relation used by the circuit witness."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "orbital.velocity_update_half_step_soundness".to_string(),
                title:
                    "Orbital fixed-point velocity updates reconstruct the admitted half-step residual relation exactly"
                        .to_string(),
                scope: "zkf-runtime::orbital_fixed_point_spec".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/orbital_dynamics_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus proof `orbital_velocity_update_reconstructs_exact_half_step` proves the public fixed-point velocity update surface reconstructs the same half-step residual relation used when the circuit links consecutive acceleration states."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "orbital.residual_split_soundness".to_string(),
                title:
                    "Orbital signed residual splitting into positive and negative witness lanes is mechanized locally"
                        .to_string(),
                scope: "zkf-runtime::orbital_fixed_point_spec".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/orbital_dynamics_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus proof `orbital_signed_residual_split_reconstructs` proves the public residual split surface reconstructs the signed residual from disjoint positive and negative witness lanes exactly."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "orbital.field_embedding_nonwrap_bounds".to_string(),
                title:
                    "Orbital fixed-point update and residual bounds stay strictly inside the admitted BN254 non-wrap envelope"
                        .to_string(),
                scope: "zkf-runtime::orbital_fixed_point_spec".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/orbital_dynamics_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus proof `orbital_fixed_point_bounds_fit_inside_bn254` proves the published fixed-point scale, gravity constant, position/velocity/acceleration bounds, minimum distance floor, and update residual bounds all stay below the BN254 modulus on the admitted non-wrap surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "orbital.commitment_body_tag_domain_separation".to_string(),
                title:
                    "Orbital final-state commitment tags are domain separated across the five published bodies"
                        .to_string(),
                scope: "zkf-runtime::orbital_fixed_point_spec".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-runtime/proofs/verus/orbital_dynamics_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus proof `orbital_body_tags_are_domain_separated` proves the published body-tag mapping is injective over the five-body surface, so final Poseidon commitments remain body-separated on the admitted public interface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "security.constant_time_secret_independence".to_string(),
                title: "Constant-time evaluator visit schedule is independent of secret witness data on the shipped proof surface"
                    .to_string(),
                scope: "zkf-core::proof_constant_time_bridge".to_string(),
                checker: VerificationCheckerKind::Fstar,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-core/proofs/fstar/ConstantTimeProofs.fst".to_string(),
                notes:
                    "Local F* theorem `eval_expr_constant_time_secret_independence` proves the extracted production-called `eval_expr_constant_time_trace` bridge always equals the evaluator's structural trace, so the shipped constant-time evaluator shell traverses the same expression schedule for any witness or field choice. This tranche is intentionally scoped to the evaluator visit schedule and does not claim full microarchitectural non-interference of every backend field operation."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.groth16_completeness".to_string(),
                title: "Groth16 exact imported-CRS shipped surface satisfies completeness under explicit imported-CRS and algebraic hypotheses"
                    .to_string(),
                scope: "zkf-backends::arkworks".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `groth16_exact_completeness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_groth16_exact_spec.rs`: if `groth16ImportedCrsValidityHypothesis` and `groth16ExactCompletenessHypothesis` hold on the extracted boundary and the shipped verifier guard is true, then `groth16_exact_completeness_reduction` returns `true`. The explicit hypotheses remain in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "groth16ImportedCrsValidityHypothesis".to_string(),
                    "groth16ExactCompletenessHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.groth16_knowledge_soundness".to_string(),
                title: "Groth16 exact imported-CRS shipped surface reduces knowledge soundness to explicit KEA-style hypotheses"
                    .to_string(),
                scope: "zkf-backends::arkworks".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `groth16_exact_knowledge_soundness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_groth16_exact_spec.rs`: if `groth16ImportedCrsValidityHypothesis` and `groth16KnowledgeOfExponentHypothesis` hold and the shipped verifier accepts, then `groth16_exact_knowledge_soundness_reduction` returns `true`. The explicit KEA-style hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "groth16ImportedCrsValidityHypothesis".to_string(),
                    "groth16KnowledgeOfExponentHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.groth16_zero_knowledge".to_string(),
                title: "Groth16 exact imported-CRS shipped surface reduces zero knowledge to explicit simulator hypotheses"
                    .to_string(),
                scope: "zkf-backends::arkworks".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `groth16_exact_zero_knowledge_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_groth16_exact_spec.rs`: if `groth16ImportedCrsValidityHypothesis` and `groth16ExactZeroKnowledgeHypothesis` hold on the extracted boundary, then `groth16_exact_zero_knowledge_reduction` returns `true`. The explicit simulator hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "groth16ImportedCrsValidityHypothesis".to_string(),
                    "groth16ExactZeroKnowledgeHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.fri_completeness".to_string(),
                title: "FRI exact Plonky3 shipped surface satisfies completeness under explicit Reed-Solomon completeness hypotheses"
                    .to_string(),
                scope: "zkf-backends::plonky3".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `fri_exact_completeness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_fri_exact_spec.rs`: if `friExactCompletenessHypothesis` holds and the shipped verifier guard is true, then `fri_exact_completeness_reduction` returns `true`. The explicit Reed-Solomon completeness hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec!["friExactCompletenessHypothesis".to_string()],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.fri_proximity_soundness".to_string(),
                title: "FRI exact Plonky3 shipped surface reduces proximity soundness to explicit Reed-Solomon hypotheses"
                    .to_string(),
                scope: "zkf-backends::plonky3".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `fri_exact_proximity_soundness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_fri_exact_spec.rs`: if `friReedSolomonProximitySoundnessHypothesis` holds and the shipped verifier accepts, then `fri_exact_proximity_soundness_reduction` returns `true`. The explicit Reed-Solomon proximity hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "friReedSolomonProximitySoundnessHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.nova_completeness".to_string(),
                title: "Classic Nova exact native profile satisfies completeness under explicit folding hypotheses"
                    .to_string(),
                scope: "zkf-backends::nova_native".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `nova_exact_completeness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_nova_exact_spec.rs`: if `novaExactCompletenessHypothesis` holds, `completeClassicNovaIvcMetadata` holds, and the shipped verifier guard is true, then `nova_exact_completeness_reduction` returns `true`. The explicit folding hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "novaExactCompletenessHypothesis".to_string(),
                    "completeClassicNovaIvcMetadata".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.nova_folding_soundness".to_string(),
                title: "Classic Nova exact native profile reduces folding soundness to explicit commitment-binding hypotheses"
                    .to_string(),
                scope: "zkf-backends::nova_native".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `nova_exact_folding_soundness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_nova_exact_spec.rs`: if `novaExactFoldingSoundnessHypothesis` holds and the shipped verifier accepts, then `nova_exact_folding_soundness_reduction` returns `true`. The explicit commitment-binding hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "novaExactFoldingSoundnessHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.packet_binding_soundness".to_string(),
                title: "Trade-finance invoice packet binding model preserves the shipped two-chunk digest composition"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `packet_binding_soundness` (Verus), `packetBindingSoundness` (Lean), and `packet_binding_soundness` (Rocq) prove the same two-chunk invoice-packet digest composition used by the shipped app semantics, while explicitly stopping short of a backend Poseidon lowering proof over emitted PastaFq constraints."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.eligibility_soundness".to_string(),
                title: "Trade-finance eligibility model preserves the term-window, predicate-match, and buyer-acceptance gate conditions"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `eligibility_soundness` (Verus), `eligibilityPassed_true_implies_conditions` (Lean), and `eligibility_passed_true_implies_trade_finance_conditions` (Rocq) prove the same eligibility gate facts that the shipped Rust app computes for term-window, supported predicate count, lender exclusions, and buyer-acceptance terms."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.consistency_score_soundness".to_string(),
                title: "Trade-finance consistency-score model is capped and complements the structured inconsistency score"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `consistency_score_soundness` (Verus), `consistencyScoreSoundness` (Lean), and `consistency_score_soundness` (Rocq) prove the modeled score cap and complement relation used by the shipped consistency and structured-inconsistency helpers."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.duplicate_financing_risk_soundness".to_string(),
                title: "Trade-finance duplicate-financing risk model caps the summed risk factors"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `duplicate_financing_risk_soundness` (Verus), `duplicateFinancingRiskSoundness` (Lean), and `duplicate_financing_risk_soundness` (Rocq) prove the modeled capped aggregation of duplication, vendor, chronology, and eligibility-mismatch risk factors."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.approved_advance_fee_reserve_soundness".to_string(),
                title: "Trade-finance approved-advance, fee, and reserve formulas satisfy the modeled cap, floor, and zero-fee relations"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `approved_advance_fee_reserve_soundness` (Verus), `approvedAdvanceFeeReserveSoundness` (Lean), and `approved_advance_fee_reserve_soundness` (Rocq) prove the modeled advance-cap, reserve-floor, and zero-fee-below-attachment relations used by the shipped formulas."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.action_derivation_soundness".to_string(),
                title: "Trade-finance action derivation model keeps action classes in range and gates settlement on approve-plus-positive-advance"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `action_derivation_soundness` (Verus), `actionDerivationSoundness` (Lean), and `action_derivation_soundness` (Rocq) prove the modeled action-class range, human-review predicate, and settlement gating relation used by the shipped trade-finance decision lane."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.settlement_binding_soundness".to_string(),
                title: "Trade-finance settlement binding model preserves the nested digest composition used by the shipped app lane"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `settlement_binding_soundness` (Verus), `settlementBindingSoundness` (Lean), and `settlement_binding_soundness` (Rocq) prove the modeled nested settlement digest composition used by the shipped app semantics, without yet claiming emitted-circuit digest linkage."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.disclosure_role_binding_soundness".to_string(),
                title: "Trade-finance disclosure role model maps each valid role to the intended commitment pair"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `disclosure_role_binding_soundness` (Verus), the role-specific `*DisclosureBindsExpectedCommitments` theorems (Lean), and the role-specific `*_disclosure_binds_expected_commitments` theorems (Rocq) prove the modeled role-to-commitment projection used by the shipped disclosure surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.disclosure_noninterference".to_string(),
                title: "Trade-finance disclosure model keeps hidden commitments from changing disclosed outputs outside the selected role view"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/TradeFinanceProofs.v".to_string(),
                notes:
                    "Local trade-finance model theorems `supplier_disclosure_noninterference`, `financier_disclosure_noninterference`, `buyer_disclosure_noninterference`, `auditor_disclosure_noninterference`, and `regulator_disclosure_noninterference` (with matching Lean theorems) prove that changing hidden commitments outside a role's selected view does not change the modeled disclosure outputs for that role."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.disclosure_authorization_binding_soundness"
                    .to_string(),
                title:
                    "Trade-finance disclosure authorization model binds role, credential, request, caller, and view commitments"
                        .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `disclosure_authorization_binding_soundness` (Verus), `disclosureAuthorizationBindsRoleCredentialRequestCallerAndView` (Lean), and `disclosure_authorization_binds_role_credential_request_caller_and_view` (Rocq) prove the modeled authorization commitment includes role code, credential commitment, request id hash, caller commitment, and selected view commitment. This is model-level authorization binding, not yet a proof of external credential issuance or Compact caller identity enforcement."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.duplicate_registry_handoff_soundness".to_string(),
                title: "Trade-finance duplicate-registry handoff model preserves batch-root and shard-assignment relations"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/trade_finance_verus.rs".to_string(),
                notes:
                    "Local trade-finance model theorems `duplicate_registry_handoff_soundness` (Verus), `duplicateRegistryHandoffDeterministic` (Lean), and `duplicate_registry_handoff_deterministic` / `duplicate_registry_batch_binding` (Rocq) prove the modeled batch-root composition and shard-assignment range properties used by the shipped duplicate-registry handoff lane."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.witness_helper.comparator_soundness".to_string(),
                title: "Trade-finance comparator-style helper model preserves the term-window ordering relation"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/TradeFinanceProofs.v".to_string(),
                notes:
                    "Local trade-finance helper theorems `within_term_window_true_iff` (Rocq) plus `withinTermWindow_true_implies_lower` / `withinTermWindow_true_implies_upper` (Lean) prove the comparator-style helper model used by the shipped term-window witness support."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.witness_helper.selector_soundness".to_string(),
                title: "Trade-finance selector helper model accepts exactly the shipped valid disclosure roles"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/TradeFinanceProofs.v".to_string(),
                notes:
                    "Local trade-finance helper theorems `role_selector_count_is_one_for_valid_roles` (Rocq) and `validRoleHasSelector` (Lean) prove the selector-style helper model used by the shipped disclosure-role witness support."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "model.trade_finance.witness_helper.shard_assignment_soundness".to_string(),
                title: "Trade-finance shard helper model keeps duplicate-registry assignments within shard bounds"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/TradeFinanceProofs.v".to_string(),
                notes:
                    "Local trade-finance helper theorems `shard_assignment_lt_shard_count` / `shard_count_two_yields_bit_assignment` (Rocq) together with `shardAssignment_lt_shardCount` / `shardCountTwoMakesBit` (Lean) prove the modeled shard-assignment helper bounds used by the shipped duplicate-registry witness support."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gap.trade_finance.pastafq_poseidon_binding".to_string(),
                title: "Trade-finance PastaFq Poseidon backend binding is generated-mechanized against emitted app certificates"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::GeneratedProof,
                status: VerificationStatus::MechanizedGenerated,
                evidence_path: "zkf-lib/src/app/private_trade_finance_settlement_export.rs".to_string(),
                notes:
                    "Backend rows `backend.poseidon_pastafq_lowering_soundness` and `backend.poseidon_pastafq_aux_witness_soundness` mechanize the shipped PastaFq width-4 lowering and aux-witness boundary. The trade-finance exporter emits generated circuit certificates under `17_report/formal/certificates/` and rejects the export unless every primary module is PastaFq, every blackbox node is Poseidon width-4, and emitted proof/program digests match. `poseidon_binding_report.json` remains supporting evidence by recomputing the app commitments against the emitted witness lane."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gap.trade_finance.compiled_digest_linkage".to_string(),
                title: "Trade-finance compiled digest linkage is generated-mechanized against emitted module certificates"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::GeneratedProof,
                status: VerificationStatus::MechanizedGenerated,
                evidence_path: "zkf-lib/src/app/private_trade_finance_settlement_export.rs".to_string(),
                notes:
                    "The export path emits `17_report/compiled_digest_linkage.json` and per-module generated circuit certificates. The certificate checker rejects any module whose computed program digest, compiled digest, proof digest, summary digest, verification report digest, source builder, witness builder, or theorem links are not aligned. The unit test `generated_circuit_certificates_record_digest_linkage_and_poseidon_shape` checks the materialized certificates and verification reports."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gap.trade_finance.disclosure_credential_authorization".to_string(),
                title: "Trade-finance disclosure credential authorization is generated-mechanized on the emitted circuit and Compact flow"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::GeneratedProof,
                status: VerificationStatus::MechanizedGenerated,
                evidence_path: "zkf-lib/src/app/private_trade_finance_settlement_export.rs".to_string(),
                notes:
                    "The emitted disclosure circuit exposes a disclosure authorization commitment derived from role code, credential commitment, request id hash, caller commitment, selected view commitment, and disclosure blinding. The generated disclosure certificate rejects the module unless that authorization commitment is a public output, while Rocq/Lean/Verus model theorems prove the authorization tuple binding and `poseidon_binding_report.json` plus `disclosure_noninterference_report.json` cross-check the emitted disclosure bundle and Compact flow. External credential issuance, revocation, and off-chain caller identity remain outside this app-circuit theorem and must be enforced by the operator credential system."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "gap.trade_finance.disclosure_noninterference_emitted".to_string(),
                title: "Trade-finance emitted disclosure noninterference is generated-mechanized against the normalized role projection"
                    .to_string(),
                scope: "zkf-lib::app::private_trade_finance_settlement".to_string(),
                checker: VerificationCheckerKind::GeneratedProof,
                status: VerificationStatus::MechanizedGenerated,
                evidence_path: "zkf-lib/src/app/private_trade_finance_settlement_export.rs".to_string(),
                notes:
                    "The emitted disclosure circuit uses the same canonical role map as the Rocq/Lean/Verus disclosure model: supplier=0, financier=1, buyer=2, auditor=3, regulator=4. The generated disclosure certificate rejects role-output drift, the model proofs establish role noninterference over selected commitment pairs, and `disclosure_noninterference_report.json` fixes shared fee/auth/blinding inputs while perturbing only non-selected commitments for every role. The emitted value pair, view commitment, authorization commitment, selective-disclosure bundle manifest, and Midnight flow manifest must all remain aligned for the certificate-backed export to pass."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.hypernova_completeness".to_string(),
                title: "HyperNova exact native profile satisfies completeness under explicit CCS folding hypotheses"
                    .to_string(),
                scope: "zkf-backends::nova_native".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `hypernova_exact_completeness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_hypernova_exact_spec.rs`: if `hypernovaExactCompletenessHypothesis` holds and the shipped verifier guard is true, then `hypernova_exact_completeness_reduction` returns `true`. The explicit CCS folding hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "hypernovaExactCompletenessHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "protocol.hypernova_folding_soundness".to_string(),
                title: "HyperNova exact native profile reduces folding soundness to explicit CCS commitment hypotheses"
                    .to_string(),
                scope: "zkf-backends::nova_native".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-backends/proofs/rocq/ProtocolExactProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `hypernova_exact_folding_soundness_reduction_ok` mechanizes the shipped exact-surface reduction over Hax extraction of `zkf-backends/src/proof_hypernova_exact_spec.rs`: if `hypernovaExactFoldingSoundnessHypothesis` holds and the shipped verifier accepts, then `hypernova_exact_folding_soundness_reduction` returns `true`. The explicit CCS commitment hypothesis remains in `trusted_assumptions`, so this row stays a trusted protocol TCB claim rather than a discharged cryptographic theorem."
                        .to_string(),
                trusted_assumptions: vec![
                    "hypernovaExactFoldingSoundnessHypothesis".to_string(),
                ],
            },
            VerificationLedgerEntry {
                theorem_id: "private_identity.merkle_direction_fail_closed_bounded".to_string(),
                title:
                    "Private-identity Merkle direction helper accepts only binary direction values"
                        .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `private_identity_merkle_direction_binary_guard_ok` proves the extracted private-identity Merkle-direction helper is exactly the binary guard `direction == 0 || direction == 1`."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "private_identity.public_input_arity_fail_closed_bounded".to_string(),
                title:
                    "Private-identity public-input arity helper accepts only the shipped expected arity"
                        .to_string(),
                scope: "zkf-lib::proof_embedded_app_spec".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `private_identity_public_input_arity_guard_ok` proves the extracted private-identity arity helper is exactly equality against the shipped expected public-input arity helper."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.common.signed_bound_slack_nonnegative".to_string(),
                title: "Signed bound slack is nonnegative when |value| <= bound".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/sovereign_economic_defense_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `signed_bound_slack_nonnegative` proves the Sovereign Economic Defense signed-bound slack relation `bound^2 - value^2 >= 0` for all `|value| <= bound`, matching the shipped signed self-multiplication proof surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.common.floor_sqrt_satisfies_relation".to_string(),
                title: "Floor sqrt satisfies sqrt^2 <= value < (sqrt+1)^2".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/SovereignEconomicDefenseProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `floor_sqrt_satisfies_relation` proves the Sovereign Economic Defense floor-sqrt decomposition enforces `sqrt^2 <= value < (sqrt + 1)^2`, with the bundled corollary also bounding the remainder on the same proof surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.common.exact_division_remainder_bounded".to_string(),
                title: "Exact division remainder is strictly less than denominator".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/SovereignEconomicDefenseProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `exact_division_remainder_bounded` proves the Sovereign Economic Defense exact-division decomposition yields `0 <= remainder < denominator`, and the bundled quotient-uniqueness corollary closes the same helper surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.cooperative_treasury.reserve_ratio_ordering".to_string(),
                title: "Reserve ratio division preserves ordering of reserve balances".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/sovereign_economic_defense_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `reserve_ratio_ordering` proves the Sovereign Economic Defense reserve-ratio quotient is monotone in reserve balances when the denominator is shared and positive."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.anti_extraction.severity_classification_monotone".to_string(),
                title: "Severity score classification is monotone in violation magnitudes"
                    .to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/sovereign_economic_defense_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `severity_classification_monotone` proves the Sovereign Economic Defense squared-magnitude severity score is monotone as violation magnitudes increase, and the supporting lemma `floor_sqrt_monotone` closes the RMS-to-floor-sqrt ordering argument on the same proof surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.recirculation.euler_step_capital_nonnegative".to_string(),
                title: "Euler step capital transition preserves nonnegativity".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/sovereign_economic_defense_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `euler_step_capital_nonnegative` proves the Sovereign Economic Defense Euler-step capital update preserves nonnegativity whenever both addends are nonnegative."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.recirculation.recirculation_rate_bounded".to_string(),
                title: "Recirculation rate cannot exceed scale".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/rocq/SovereignEconomicDefenseProofs.v"
                    .to_string(),
                notes:
                    "Local Rocq theorem `recirculation_rate_bounded` proves the Sovereign Economic Defense recirculation quotient `(internal * scale) / total` never exceeds `scale` under the shipped nonnegative-domain and positive-total preconditions, with bundled nonnegative and full-range corollaries on the same surface."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "sed.surface_constants".to_string(),
                title: "Surface constants match Rust implementation values".to_string(),
                scope: "zkf-lib::app::sovereign_economic_defense".to_string(),
                checker: VerificationCheckerKind::Verus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lib/proofs/verus/sovereign_economic_defense_verus.rs"
                    .to_string(),
                notes:
                    "Local Verus theorem `sed_surface_constants_match` proves the Sovereign Economic Defense proof-surface constants for Goldilocks scale, BN254 scale, integration steps, and range bounds, including the 63-bit squared-bound fit used by the shipped Goldilocks lane."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "zir.lang.tier1_eval_determinism_model".to_string(),
                title: "Tier 1 Zir expression evaluation model is deterministic".to_string(),
                scope: "zkf-lang::source-model".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lang/proofs/rocq/ZirLangSemantics.v".to_string(),
                notes:
                    "Local Rocq theorem `zir_tier1_eval_deterministic` proves determinism for the Tier 1 arithmetic expression model used to state the native Zir source semantics. This is model-only evidence and does not claim full parser/compiler implementation correctness."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "zir.lang.source_to_zir_shape_model".to_string(),
                title: "Tier 1 source-to-ZIR constraint-shape model preserves core constraint forms"
                    .to_string(),
                scope: "zkf-lang::source-model".to_string(),
                checker: VerificationCheckerKind::Rocq,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lang/proofs/rocq/ZirLangLoweringProofs.v".to_string(),
                notes:
                    "Local Rocq theorems `zir_source_to_zir_preserves_equality_shape`, `zir_source_to_zir_preserves_range_shape`, and `zir_source_to_zir_preserves_boolean_shape` prove the model lowering preserves the Tier 1 equality/range/boolean constraint forms. This is model-only evidence and does not claim an end-to-end verified Rust compiler."
                        .to_string(),
                trusted_assumptions: vec![],
            },
            VerificationLedgerEntry {
                theorem_id: "zir.lang.privacy_expose_model".to_string(),
                title: "Zir exposure model rejects unassigned private input exposure".to_string(),
                scope: "zkf-lang::privacy-model".to_string(),
                checker: VerificationCheckerKind::RocqVerus,
                status: VerificationStatus::MechanizedLocal,
                evidence_path: "zkf-lang/proofs/rocq/ZirLangPrivacyProofs.v".to_string(),
                notes:
                    "Local Rocq theorem `private_unassigned_input_cannot_be_exposed` and Verus theorem `private_unassigned_cannot_expose` prove the privacy model rejects direct exposure of unassigned private inputs. This supports the shipped Zir checker boundary but remains a model-only claim until tied to extracted implementation proof."
                        .to_string(),
                trusted_assumptions: vec![],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theorem_ids_are_unique() {
        let ledger = verification_ledger();
        let mut ids = ledger
            .entries
            .iter()
            .map(|entry| entry.theorem_id.as_str())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), ledger.entries.len());
    }

    #[test]
    fn upgraded_entries_require_evidence_paths() {
        let ledger = verification_ledger();
        for entry in &ledger.entries {
            match entry.status {
                VerificationStatus::BoundedChecked
                | VerificationStatus::MechanizedLocal
                | VerificationStatus::MechanizedGenerated
                | VerificationStatus::AssumedExternal => {
                    assert!(
                        !entry.evidence_path.trim().is_empty(),
                        "upgraded entry {} must carry evidence",
                        entry.theorem_id
                    );
                }
                VerificationStatus::Pending | VerificationStatus::HypothesisStated => {}
            }
        }
    }

    #[test]
    fn assumed_or_pending_entries_explain_their_trust_boundary() {
        let ledger = verification_ledger();
        for entry in &ledger.entries {
            match entry.status {
                VerificationStatus::Pending
                | VerificationStatus::HypothesisStated
                | VerificationStatus::AssumedExternal => {
                    assert!(
                        !entry.trusted_assumptions.is_empty(),
                        "entry {} should explain its remaining trust boundary",
                        entry.theorem_id
                    );
                }
                VerificationStatus::BoundedChecked
                | VerificationStatus::MechanizedLocal
                | VerificationStatus::MechanizedGenerated => {}
            }
        }
    }

    #[test]
    fn assurance_classes_match_public_intent() {
        let ledger = verification_ledger();
        let classify = |theorem_id: &str| {
            ledger
                .entries
                .iter()
                .find(|entry| entry.theorem_id == theorem_id)
                .expect("theorem present")
                .assurance_class()
        };

        assert_eq!(
            classify("protocol.groth16_completeness"),
            VerificationAssuranceClass::TrustedProtocolTcb
        );
        assert_eq!(
            classify("normalization.idempotence_bounded"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("distributed.acceptance_soundness"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("swarm.memory_append_only_convergence"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("swarm.coordinator_acceptance_soundness"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("swarm.memory_snapshot_identity"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("gpu.ntt_differential_bounded"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("gpu.hash_differential_bounded"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("swarm.constant_time_eval_equivalence"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("setup.groth16_deterministic_production_gate"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("gpu.ntt_bn254_butterfly_arithmetic_sound"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("witness.generate_witness_soundness"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("model.trade_finance.packet_binding_soundness"),
            VerificationAssuranceClass::ModelOnlyClaim
        );
        assert_eq!(
            classify("gap.trade_finance.pastafq_poseidon_binding"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("gap.trade_finance.compiled_digest_linkage"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("gap.trade_finance.disclosure_credential_authorization"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
        assert_eq!(
            classify("gap.trade_finance.disclosure_noninterference_emitted"),
            VerificationAssuranceClass::MechanizedImplementationClaim
        );
    }

    #[test]
    fn trade_finance_generated_rows_do_not_regress_to_bounded_checks() {
        let ledger = verification_ledger();
        for theorem_id in [
            "gap.trade_finance.pastafq_poseidon_binding",
            "gap.trade_finance.compiled_digest_linkage",
            "gap.trade_finance.disclosure_credential_authorization",
            "gap.trade_finance.disclosure_noninterference_emitted",
        ] {
            let entry = ledger
                .entries
                .iter()
                .find(|entry| entry.theorem_id == theorem_id)
                .expect("trade-finance generated row");
            assert_eq!(
                entry.status,
                VerificationStatus::MechanizedGenerated,
                "{theorem_id} must stay generated-mechanized"
            );
            assert_eq!(
                entry.assurance_class(),
                VerificationAssuranceClass::MechanizedImplementationClaim,
                "{theorem_id} must count as an implementation claim"
            );
            let public_text = format!("{} {}", entry.title, entry.notes).to_lowercase();
            assert!(
                !public_text.contains("bounded-check")
                    && !public_text.contains("bounded checked")
                    && !public_text.contains("bounded evidence"),
                "{theorem_id} must not carry stale bounded-check wording"
            );
        }
    }

    #[test]
    fn release_grade_policy_has_no_hypothesis_carried_rows() {
        let ledger = verification_ledger();
        let hypothesis_rows = ledger
            .entries
            .iter()
            .filter(|entry| {
                entry.assurance_class() == VerificationAssuranceClass::HypothesisCarriedTheorem
            })
            .map(|entry| entry.theorem_id.as_str())
            .collect::<Vec<_>>();
        assert!(
            hypothesis_rows.is_empty(),
            "hypothesis-carried rows remain under explicit TCB policy: {hypothesis_rows:?}"
        );
    }

    #[test]
    fn protocol_rows_remain_trusted_tcb_after_local_reductions() {
        let ledger = verification_ledger();
        let protocol_rows = ledger
            .entries
            .iter()
            .filter(|entry| entry.theorem_id.starts_with("protocol."))
            .collect::<Vec<_>>();
        assert_eq!(protocol_rows.len(), 9);
        for entry in protocol_rows {
            assert_eq!(entry.checker, VerificationCheckerKind::Rocq);
            assert_eq!(entry.status, VerificationStatus::MechanizedLocal);
            assert_eq!(
                entry.assurance_class(),
                VerificationAssuranceClass::TrustedProtocolTcb
            );
            assert_eq!(
                entry.evidence_path.as_str(),
                "zkf-backends/proofs/rocq/ProtocolExactProofs.v"
            );
            assert!(!entry.trusted_assumptions.is_empty());
        }
    }

    #[test]
    fn json_export_stays_in_sync() {
        let expected = verification_ledger();
        let actual: VerificationLedger =
            serde_json::from_str(include_str!("../verification-ledger.json"))
                .expect("verification ledger json must parse");
        assert_eq!(actual, expected);
    }
}
