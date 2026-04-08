//! Backend capability matrix — single source of truth for what each backend can and cannot do.
//!
//! This data-driven model replaces hardcoded Swift computed properties and provides
//! machine-readable backend classification for AI tools, audit reports, and conformance testing.

use crate::FieldId;
use crate::artifact::BackendKind;
use serde::{Deserialize, Serialize};

/// Classification of backend support level based on hostile audit evidence.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportClass {
    /// Independent proof system with its own prover/verifier.
    Native,
    /// Routes to another backend's prover (honest metadata disclosure).
    Delegated,
    /// Requires IR modifications (e.g., range bit reduction) to work.
    Adapted,
    /// Listed in capabilities but fails at prove time.
    Broken,
    /// Feature is explicitly not supported.
    Unsupported,
    /// Experimental implementation; may be unstable.
    Experimental,
}

impl SupportClass {
    pub fn as_str(self) -> &'static str {
        match self {
            SupportClass::Native => "native",
            SupportClass::Delegated => "delegated",
            SupportClass::Adapted => "adapted",
            SupportClass::Broken => "broken",
            SupportClass::Unsupported => "unsupported",
            SupportClass::Experimental => "experimental",
        }
    }
}

impl std::fmt::Display for SupportClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// GPU acceleration status from hostile audit measurements.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GpuAcceleration {
    /// Whether the backend claims Metal GPU support.
    pub claimed: bool,
    /// Whether GPU is actually used (measured via gpu_busy_ratio).
    pub actual: bool,
    /// Which stages use GPU acceleration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
}

/// Full capability entry for a single backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilityEntry {
    pub backend: BackendKind,
    pub support_class: SupportClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegates_to: Option<BackendKind>,
    pub supported_fields: Vec<FieldId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_range_bits: Option<u32>,
    pub gpu_acceleration: GpuAcceleration,
    pub accepts_canonical_ir: bool,
    pub trusted_setup_required: bool,
    pub recursion_ready: bool,
    pub solidity_export: bool,
    pub proof_size_estimate: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_constraint_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_blackbox_ops: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_type: Option<SupportClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_compat_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_lookup_support: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_lowering_support: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_semantics: Option<String>,
    pub notes: String,
}

/// The complete capability matrix for all backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilityMatrix {
    /// Schema version for this matrix format.
    pub schema_version: u32,
    /// Audit date (ISO 8601).
    pub audit_date: String,
    /// All backend entries.
    pub entries: Vec<BackendCapabilityEntry>,
}

impl BackendCapabilityMatrix {
    /// Build the canonical capability matrix from the hostile audit data (2026-03-11).
    /// This is the single source of truth — Swift and all other consumers read from this.
    pub fn current() -> Self {
        let hypernova_native = cfg!(feature = "native-nova");
        let risc_zero_native = cfg!(feature = "native-risc-zero");
        let sp1_native = cfg!(feature = "native-sp1");
        Self {
            schema_version: 3,
            audit_date: "2026-03-11".into(),
            entries: vec![
                BackendCapabilityEntry {
                    backend: BackendKind::ArkworksGroth16,
                    support_class: SupportClass::Native,
                    delegates_to: None,
                    supported_fields: vec![FieldId::Bn254],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: true,
                        actual: true,
                        stages: vec![
                            "msm".into(), "ntt".into(), "field_ops".into(),
                        ],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: true,
                    recursion_ready: true,
                    solidity_export: true,
                    proof_size_estimate: "~128 bytes".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![
                        "poseidon".into(), "sha256".into(), "keccak256".into(), "pedersen".into(),
                        "ecdsa_secp256k1".into(), "ecdsa_secp256r1".into(), "schnorr_verify".into(),
                        "blake2s".into(), "scalar_mul_g1".into(), "point_add_g1".into(),
                        "pairing_check".into(),
                    ],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(true),
                    lookup_semantics: Some("arithmetic-lowering-required".into()),
                    aggregation_semantics: Some("single-proof-only".into()),
                    notes: "Independent Groth16 prover, ~250K gas EVM verification".into(),
                },
                BackendCapabilityEntry {
                    backend: BackendKind::Plonky3,
                    support_class: SupportClass::Native,
                    delegates_to: None,
                    supported_fields: vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: true,
                        actual: true,
                        stages: vec![
                            "ntt".into(), "fri".into(), "merkle".into(),
                            "poseidon2".into(), "field_ops".into(),
                        ],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: true,
                    solidity_export: false,
                    proof_size_estimate: "~13.5 KB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![
                        "poseidon".into(), "sha256".into(), "keccak256".into(),
                        "blake2s".into(),
                    ],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(true),
                    lookup_semantics: Some("arithmetic-lowering-required".into()),
                    aggregation_semantics: Some("single-proof-with-optional-wrapper".into()),
                    notes: "Independent STARK-FRI prover, fastest (~70ms)".into(),
                },
                BackendCapabilityEntry {
                    backend: BackendKind::Nova,
                    support_class: SupportClass::Native,
                    delegates_to: None,
                    supported_fields: vec![FieldId::Bn254, FieldId::PastaFp, FieldId::PastaFq],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: true,
                        actual: false,
                        stages: vec![],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: true,
                    solidity_export: false,
                    proof_size_estimate: "~1.77 MB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![
                        "poseidon".into(), "sha256".into(),
                    ],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(true),
                    lookup_semantics: Some("arithmetic-lowering-required".into()),
                    aggregation_semantics: Some("cryptographic-recursive-folding".into()),
                    notes: "Independent IVC folding prover, huge proof, slow verify (~16.5s)".into(),
                },
                BackendCapabilityEntry {
                    backend: BackendKind::Halo2,
                    support_class: SupportClass::Native,
                    delegates_to: None,
                    supported_fields: vec![FieldId::PastaFp],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: true,
                        actual: true,
                        stages: vec!["msm".into()],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: true,
                    solidity_export: false,
                    proof_size_estimate: "~3 KB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![
                        "poseidon".into(), "sha256".into(),
                    ],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(true),
                    lookup_semantics: Some("arithmetic-lowering-required".into()),
                    aggregation_semantics: Some("single-proof-only".into()),
                    notes: "Real IPA prover with automatic large-range lowering into 16-bit lookup chunks. Metal MSM is patched on macOS for the Pasta path; FFT/NTT hot paths remain CPU.".into(),
                },
                BackendCapabilityEntry {
                    backend: BackendKind::Halo2Bls12381,
                    support_class: SupportClass::Native,
                    delegates_to: None,
                    supported_fields: vec![FieldId::Bls12_381],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: false,
                        actual: false,
                        stages: vec![],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: false,
                    solidity_export: false,
                    proof_size_estimate: "~3 KB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![
                        "poseidon".into(), "sha256".into(),
                    ],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(true),
                    lookup_semantics: Some("arithmetic-lowering-required".into()),
                    aggregation_semantics: Some("single-proof-only".into()),
                    notes: "Real BLS12-381 Halo2 backend with trusted setup and CPU-classified hot paths.".into(),
                },
                BackendCapabilityEntry {
                    backend: BackendKind::HyperNova,
                    support_class: if hypernova_native {
                        SupportClass::Native
                    } else {
                        SupportClass::Delegated
                    },
                    delegates_to: if hypernova_native {
                        None
                    } else {
                        Some(BackendKind::Nova)
                    },
                    supported_fields: vec![FieldId::Bn254, FieldId::PastaFp, FieldId::PastaFq],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: true,
                        actual: false,
                        stages: vec![],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: true,
                    solidity_export: false,
                    proof_size_estimate: "~1.05 MB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![
                        "poseidon".into(), "sha256".into(),
                    ],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(true),
                    lookup_semantics: Some("arithmetic-lowering-required".into()),
                    aggregation_semantics: Some(if hypernova_native {
                        "cryptographic-recursive-multifolding".into()
                    } else {
                        "compat-delegated-surface".into()
                    }),
                    notes: if hypernova_native {
                        "Native HyperNova path compiled in via the Nova backend hypernova profile.".into()
                    } else {
                        "Routes to Nova with nova_profile='hypernova' config flag".into()
                    },
                },
                BackendCapabilityEntry {
                    backend: BackendKind::Sp1,
                    support_class: if sp1_native {
                        SupportClass::Native
                    } else {
                        SupportClass::Delegated
                    },
                    delegates_to: if sp1_native {
                        None
                    } else {
                        Some(BackendKind::Plonky3)
                    },
                    supported_fields: if sp1_native {
                        vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
                    } else {
                        vec![]
                    },
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: false,
                        actual: false,
                        stages: vec![],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: false,
                    solidity_export: false,
                    proof_size_estimate: "~13.5 KB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: Some("sp1-compat".into()),
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(false),
                    lookup_semantics: Some("not-supported-on-ir-constraints".into()),
                    aggregation_semantics: Some("zkvm-attestation".into()),
                    notes: if sp1_native {
                        "Native SP1 guest/ELF pipeline is compiled in; compatibility use should be explicit via sp1-compat.".into()
                    } else {
                        "Plonky3 compatibility shim, identical proof bytes to risc-zero".into()
                    },
                },
                BackendCapabilityEntry {
                    backend: BackendKind::RiscZero,
                    support_class: if risc_zero_native {
                        SupportClass::Native
                    } else {
                        SupportClass::Delegated
                    },
                    delegates_to: if risc_zero_native {
                        None
                    } else {
                        Some(BackendKind::Plonky3)
                    },
                    supported_fields: if risc_zero_native {
                        vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
                    } else {
                        vec![]
                    },
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: !risc_zero_native,
                        actual: !risc_zero_native,
                        stages: vec![],
                    },
                    accepts_canonical_ir: true,
                    trusted_setup_required: false,
                    recursion_ready: true,
                    solidity_export: false,
                    proof_size_estimate: "~13.5 KB".into(),
                    supported_constraint_kinds: vec![
                        "equal".into(), "boolean".into(), "range".into(), "black_box".into(),
                    ],
                    supported_blackbox_ops: vec![],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: Some("risc-zero-compat".into()),
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(false),
                    lookup_semantics: Some("not-supported-on-ir-constraints".into()),
                    aggregation_semantics: Some("zkvm-attestation".into()),
                    notes: if risc_zero_native {
                        "Native RISC Zero guest/ELF pipeline is compiled in; external-command and compat delegation remain fallback paths.".into()
                    } else {
                        "Plonky3 compatibility shim, identical proof bytes to sp1. Claims Metal via Plonky3 delegation.".into()
                    },
                },
                BackendCapabilityEntry {
                    backend: BackendKind::MidnightCompact,
                    support_class: SupportClass::Delegated,
                    delegates_to: None,
                    supported_fields: vec![FieldId::PastaFp, FieldId::PastaFq],
                    max_range_bits: None,
                    gpu_acceleration: GpuAcceleration {
                        claimed: false,
                        actual: false,
                        stages: vec![],
                    },
                    accepts_canonical_ir: false,
                    trusted_setup_required: false,
                    recursion_ready: false,
                    solidity_export: false,
                    proof_size_estimate: "Variable".into(),
                    supported_constraint_kinds: vec![],
                    supported_blackbox_ops: vec![],
                    implementation_type: None,
                    compiled_in: None,
                    toolchain_ready: None,
                    runtime_ready: None,
                    production_ready: None,
                    readiness: None,
                    readiness_reason: None,
                    operator_action: None,
                    explicit_compat_alias: None,
                    native_lookup_support: Some(false),
                    lookup_lowering_support: Some(false),
                    lookup_semantics: Some("not-supported-on-ir-constraints".into()),
                    aggregation_semantics: Some("single-proof-only".into()),
                    notes: "External Compact delegate, not exposed via prove API".into(),
                },
            ],
        }
    }

    /// Look up a specific backend's capability entry.
    pub fn entry_for(&self, backend: BackendKind) -> Option<&BackendCapabilityEntry> {
        self.entries.iter().find(|e| e.backend == backend)
    }

    /// Serialize the matrix to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("capability matrix serialization must succeed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_has_all_backends() {
        let matrix = BackendCapabilityMatrix::current();
        assert_eq!(matrix.entries.len(), 9);
    }

    #[test]
    fn groth16_is_native() {
        let matrix = BackendCapabilityMatrix::current();
        let entry = matrix.entry_for(BackendKind::ArkworksGroth16).unwrap();
        assert_eq!(entry.support_class, SupportClass::Native);
        assert!(entry.solidity_export);
        assert!(entry.trusted_setup_required);
    }

    #[test]
    fn halo2_bls_is_native() {
        let matrix = BackendCapabilityMatrix::current();
        let entry = matrix.entry_for(BackendKind::Halo2Bls12381).unwrap();
        assert_eq!(entry.support_class, SupportClass::Native);
        assert!(entry.accepts_canonical_ir);
    }

    #[test]
    fn halo2_is_native_and_accepts_canonical_ir() {
        let matrix = BackendCapabilityMatrix::current();
        let entry = matrix.entry_for(BackendKind::Halo2).unwrap();
        assert_eq!(entry.support_class, SupportClass::Native);
        assert_eq!(entry.max_range_bits, None);
        assert!(entry.accepts_canonical_ir);
    }

    #[test]
    fn sp1_matrix_matches_feature_build() {
        let matrix = BackendCapabilityMatrix::current();
        let entry = matrix.entry_for(BackendKind::Sp1).unwrap();
        if cfg!(feature = "native-sp1") {
            assert_eq!(entry.support_class, SupportClass::Native);
            assert_eq!(
                entry.supported_fields,
                vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
            );
            assert_eq!(entry.delegates_to, None);
        } else {
            assert_eq!(entry.support_class, SupportClass::Delegated);
            assert_eq!(entry.delegates_to, Some(BackendKind::Plonky3));
        }
    }

    #[test]
    fn halo2_reports_partial_gpu_acceleration() {
        let matrix = BackendCapabilityMatrix::current();
        let entry = matrix.entry_for(BackendKind::Halo2).unwrap();
        assert!(entry.gpu_acceleration.claimed);
        assert!(entry.gpu_acceleration.actual);
        assert_eq!(entry.gpu_acceleration.stages, vec!["msm".to_string()]);
    }

    #[test]
    fn risc_zero_matrix_matches_feature_build() {
        let matrix = BackendCapabilityMatrix::current();
        let entry = matrix.entry_for(BackendKind::RiscZero).unwrap();
        if cfg!(feature = "native-risc-zero") {
            assert_eq!(entry.support_class, SupportClass::Native);
            assert_eq!(
                entry.supported_fields,
                vec![FieldId::Goldilocks, FieldId::BabyBear, FieldId::Mersenne31]
            );
        } else {
            assert_eq!(entry.support_class, SupportClass::Delegated);
            assert_eq!(entry.delegates_to, Some(BackendKind::Plonky3));
        }
    }

    #[test]
    fn matrix_serializes_to_json() {
        let matrix = BackendCapabilityMatrix::current();
        let json = matrix.to_json();
        assert!(json.contains("arkworks-groth16"));
        assert!(json.contains("native"));
        assert!(json.contains("delegated"));
    }
}
