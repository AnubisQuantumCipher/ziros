#![allow(unexpected_cfgs)]

// Core modules — always available (including guest builds)
pub mod artifact;
pub mod credential;
pub mod dsl_types;
pub mod error;
pub mod field;
pub mod ir;
mod proof_ccs_spec;
mod proof_constant_time_spec;
mod proof_kernel;
mod proof_kernel_spec;
mod proof_transform_spec;
mod proof_witness_adapter_spec;
mod proof_witness_generation_spec;
pub mod stack_safe_json;
#[cfg(feature = "full")]
pub mod swarm_signer;
#[cfg(kani)]
mod verification_kani;
pub mod witness;

// Capability matrix and support class — always available
pub mod capability;
mod fiat_generated;

// Heavy modules — only available with the "full" feature (default)
#[cfg(feature = "full")]
pub mod acceleration;
#[cfg(feature = "full")]
pub mod aggregation;
#[cfg(feature = "full")]
pub mod artifact_v2;
#[cfg(feature = "full")]
pub mod audit;
#[cfg(feature = "full")]
pub mod benchmark;
#[cfg(feature = "full")]
pub mod ccs;
#[cfg(feature = "full")]
pub mod debugger;
#[cfg(feature = "full")]
pub mod diagnostics;
#[cfg(feature = "full")]
pub mod hir;
#[cfg(feature = "full")]
pub mod keystore;
#[cfg(feature = "full")]
pub mod lowering;
#[cfg(feature = "full")]
pub mod normalize;
#[cfg(feature = "full")]
pub mod optimizer;
#[cfg(feature = "full")]
pub mod optimizer_zir;
#[cfg(feature = "full")]
pub mod platform;
#[cfg(feature = "full")]
pub mod privacy;
#[cfg(feature = "full")]
pub mod recursion;
#[cfg(feature = "full")]
pub mod resources;
#[cfg(feature = "full")]
pub mod secure_random;
#[cfg(feature = "full")]
pub mod setup;
#[cfg(feature = "full")]
pub mod solver;
#[cfg(feature = "full")]
pub mod tooling;
#[cfg(feature = "full")]
pub mod type_check;
#[cfg(feature = "full")]
pub mod wrapping;
#[cfg(feature = "full")]
pub mod zir;

// Core re-exports — always available
pub use artifact::{
    ArtifactProvenance, BackendCapabilities, BackendKind, BackendMode, CompiledProgram,
    FrontendProvenance, HybridProofBundle, HybridProofLeg, HybridProofVerifierMetadata,
    HybridReplayGuard, PACKAGE_SCHEMA_VERSION, PackageFileRef, PackageManifest, PackageRunFiles,
    ProofArchiveMetadata, ProofArtifact, ProofSecurityProfile, StepMode,
};
pub use capability::{
    BackendCapabilityEntry, BackendCapabilityMatrix, GpuAcceleration, SupportClass,
};
pub use credential::{
    CredentialClaimsV1, CredentialProofBundleV1, IssuerSignedCredentialV1, PublicKeyBundle,
    SignatureBundle, SignatureScheme, bundle_has_required_signature_material,
    derive_subject_key_hash, signed_message_has_complete_bundle_surface, verify_bundle,
    verify_ed25519_signature, verify_ml_dsa_signature, verify_signed_message,
};
pub use error::{ZkfError, ZkfResult};
pub use field::{
    BigIntFieldBackend, BigIntFieldValue, FieldBackend, FieldElement, FieldId, FieldValue,
    mod_inverse_bigint, normalize_mod,
};
pub use ir::{
    BlackBoxOp, Constraint, Expr, Program, Signal, Visibility, WitnessAssignment, WitnessHint,
    WitnessHintKind, WitnessPlan,
};
pub use stack_safe_json::{
    from_reader as json_from_reader, from_slice as json_from_slice, to_vec as json_to_vec,
    to_vec_pretty as json_to_vec_pretty,
};
#[cfg(feature = "full")]
pub use swarm_signer::{ReadOnlySwarmSigner, SwarmIdentityKeyBackend};
pub use witness::{
    Witness, WitnessInputs, check_constraints, collect_public_inputs, ensure_witness_completeness,
    eval_expr, generate_partial_witness, generate_witness, generate_witness_unchecked,
};

// Full-only re-exports
#[cfg(feature = "full")]
pub use artifact_v2::{ArtifactKind, ZkfArtifactBundle};
#[cfg(feature = "full")]
pub use audit::{
    AUDIT_REPORT_VERSION, AuditCategory, AuditCheck, AuditFinding, AuditReport, AuditSeverity,
    AuditStatus, AuditSummary, audit_program, audit_program_with_capability_matrix,
};
#[cfg(feature = "full")]
pub use benchmark::{BenchmarkMetrics, BenchmarkReport, StatsAggregate};
#[cfg(feature = "full")]
pub use debugger::{
    ConstraintTrace, ConstraintTraceDetail, DebugOptions, DebugReport, ExprTrace,
    PoseidonTraceEntry, PoseidonTraceSignal, PoseidonTraceValue, SymbolicConstraint,
    SymbolicOrigin, SymbolicSignal, UnderconstrainedAnalysis, WitnessFlowEdge, WitnessFlowGraph,
    WitnessFlowNode, WitnessFlowStep, analyze_underconstrained, analyze_underconstrained_zir,
    build_witness_flow, build_witness_flow_zir, debug_program, debug_program_zir,
};
#[cfg(feature = "full")]
pub use diagnostics::{
    CircuitSummary, CircuitSummaryOptions, DiagnosticsReport, SignalVisibilitySummary,
    analyze_program, summarize_program,
};
#[cfg(feature = "full")]
pub use hir as hir_v1;
#[cfg(feature = "full")]
pub use lowering::hir_to_zir::lower_program as lower_hir_program_to_zir;
#[cfg(feature = "full")]
pub use lowering::{hir_to_zir, program_v2_to_zir, program_zir_to_v2};
#[cfg(feature = "full")]
pub use normalize::NormalizationReport;
#[cfg(feature = "full")]
pub use optimizer::{OptimizeReport, optimize_program, optimize_program_zir};
#[cfg(feature = "full")]
pub use optimizer_zir::{ZirOptimizeReport, optimize_zir};
#[cfg(feature = "full")]
pub use platform::{
    AppleChipFamily, CryptoExtensions, DeviceFormFactor, GpuCapability, NeuralEngineCapability,
    PlatformCapability, PlatformIdentity, PowerMode, ThermalEnvelope, platform_identity,
};
#[cfg(feature = "full")]
pub use privacy::{ExportMode, sanitize_artifact};
#[cfg(feature = "full")]
pub use recursion::{FieldAdapter, RecursionPlan, available_recursion_paths};
#[cfg(feature = "full")]
pub use resources::{MemoryPressure, PressureLevel, ResourceRecommendation, SystemResources};
#[cfg(feature = "full")]
pub use setup::{SecurityModel, SetupKind, SetupProvenance};
#[cfg(feature = "full")]
pub use solver::{
    NoopWitnessSolver, WitnessSolver, available_solvers, solve_and_validate_witness, solve_witness,
    solver_by_name,
};
#[cfg(feature = "full")]
pub use tooling::ToolRequirement;
#[cfg(feature = "full")]
pub use type_check::TypeError;
#[cfg(feature = "full")]
pub use zir as zir_v1;
