//! Typed GPU proof IR and checked manifest export.
//!
//! This module is the semantic source of truth for the mechanized Metal proof
//! surface. The data model is intentionally richer than the current ledger rows
//! so the host boundary, artifact manifests, Lean export, and future formal
//! proofs all share one typed description.

use crate::launch_contracts::{CurveFamily, FieldFamily, KernelFamily, MsmRouteClass};
use crate::shader_library;
use crate::verified_artifacts::{
    ExpectedKernelAttestation, ToolchainIdentity, current_toolchain_identity,
    expected_kernel_attestation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const GPU_CLAIM: &str = "end-to-end mechanized GPU lane from Rust inputs to GPU outputs, assuming the pinned Apple Metal stack executes the attested metallib and pipeline state correctly";
const GPU_ATTESTED_SURFACE_CLAIM: &str = "attested GPU surface from Rust inputs to GPU outputs, bound to the shipped metallib, reflection, and pipeline descriptors; certification status is carried per program by certified_claim";
const GPU_MANIFEST_SCHEMA: &str = "zkf-metal-gpu-proof-manifest-v3";
const GENERATED_LEAN_NAMESPACE: &str = "ZkfMetalProofs";
const GPU_TCB: &[&str] = &[
    "Lean",
    "Verus",
    "Apple Metal compiler",
    "Apple Metal driver/runtime",
    "Apple GPU hardware",
];

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericExpr {
    NatConst(usize),
    Symbol(String),
    Add(Box<NumericExpr>, Box<NumericExpr>),
    Sub(Box<NumericExpr>, Box<NumericExpr>),
    Mul(Box<NumericExpr>, Box<NumericExpr>),
    DivCeil(Box<NumericExpr>, Box<NumericExpr>),
    ModNat(Box<NumericExpr>, Box<NumericExpr>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BooleanExpr {
    Truth,
    EqExpr(NumericExpr, NumericExpr),
    GeExpr(NumericExpr, NumericExpr),
    LeExpr(NumericExpr, NumericExpr),
    IsPowerOfTwo(NumericExpr),
    IsMultipleOf(NumericExpr, usize),
    AllOf(Vec<BooleanExpr>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolDomain {
    pub name: String,
    pub min_value: usize,
    pub max_value: Option<usize>,
    pub non_zero: bool,
    pub power_of_two: bool,
    pub multiple_of: Option<usize>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadIndexMap {
    pub global_index: NumericExpr,
    pub lane_index: Option<NumericExpr>,
    pub batch_index: Option<NumericExpr>,
    pub guard: BooleanExpr,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRegionKind {
    GlobalInput,
    GlobalOutput,
    Shared,
    Constant,
    Scratch,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegionSlice {
    pub name: String,
    pub kind: MemoryRegionKind,
    pub start: NumericExpr,
    pub len: NumericExpr,
    pub bound: NumericExpr,
    pub element_bytes: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionOperator {
    Sha256MessageSchedule,
    Sha256CompressionRound,
    KeccakTheta,
    KeccakRhoPi,
    KeccakChiIota,
    Poseidon2ExternalRound,
    Poseidon2MatrixLayer,
    Poseidon2SBox,
    Poseidon2InternalRound,
    FieldAdd,
    FieldSub,
    FieldMul,
    FieldInvPrefix,
    FieldInvBackprop,
    NttBitReverse,
    NttButterflyStage,
    NttSmallTransform,
    NttHybridStage,
    PolyEval,
    PolyBatchEval,
    PolyQuotient,
    PolyCosetShift,
    FriFold,
    ConstraintEval,
    MsmBucketAssign,
    MsmBucketAccumulate,
    MsmBucketSegmentReduce,
    MsmBucketReduce,
    MsmWindowCombine,
    MsmBucketCount,
    MsmBucketScatter,
    MsmSortedAccumulate,
    LayoutWriteback,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelStep {
    pub name: String,
    pub operator: TransitionOperator,
    pub arithmetic_domain: String,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BarrierPoint {
    pub after_step: usize,
    pub scope: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoweringBinding {
    pub step_index: usize,
    pub entrypoint: String,
    pub source_path: String,
    pub library: String,
    pub binding_kind: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoweringCertificate {
    pub source_sha256: BTreeMap<String, String>,
    pub source_paths: Vec<String>,
    pub entrypoints: Vec<String>,
    pub toolchain: ToolchainIdentity,
    pub entrypoint_attestations: Vec<ExpectedKernelAttestation>,
    pub reflection_policy: String,
    pub workgroup_policy: String,
    pub step_bindings: Vec<LoweringBinding>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelProgram {
    pub theorem_id: String,
    pub program_id: String,
    pub family: KernelFamily,
    pub kernel: String,
    pub variant: String,
    pub field: Option<FieldFamily>,
    pub curve: Option<CurveFamily>,
    pub route: Option<MsmRouteClass>,
    pub index_map: ThreadIndexMap,
    pub symbols: Vec<SymbolDomain>,
    pub read_regions: Vec<RegionSlice>,
    pub write_regions: Vec<RegionSlice>,
    pub shared_regions: Vec<RegionSlice>,
    pub barriers: Vec<BarrierPoint>,
    pub steps: Vec<KernelStep>,
    pub lowering: LoweringCertificate,
    pub certified_claim: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FamilyProofManifest {
    pub schema: String,
    pub family: KernelFamily,
    pub claim: String,
    pub trusted_tcb: Vec<String>,
    pub programs: Vec<KernelProgram>,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn source_digest(relative_path: &str) -> String {
    let bytes = fs::read(repo_root().join(relative_path))
        .unwrap_or_else(|err| panic!("failed to read {relative_path}: {err}"));
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn source_digest_map(paths: &[&str]) -> BTreeMap<String, String> {
    paths
        .iter()
        .map(|path| ((*path).to_string(), source_digest(path)))
        .collect()
}

fn trusted_tcb() -> Vec<String> {
    GPU_TCB.iter().map(|item| (*item).to_string()).collect()
}

fn c(value: usize) -> NumericExpr {
    NumericExpr::NatConst(value)
}

fn symbol(name: &str) -> NumericExpr {
    NumericExpr::Symbol(name.to_string())
}

fn add(lhs: NumericExpr, rhs: NumericExpr) -> NumericExpr {
    NumericExpr::Add(Box::new(lhs), Box::new(rhs))
}

#[allow(dead_code)]
fn sub(lhs: NumericExpr, rhs: NumericExpr) -> NumericExpr {
    NumericExpr::Sub(Box::new(lhs), Box::new(rhs))
}

fn mul(lhs: NumericExpr, rhs: NumericExpr) -> NumericExpr {
    NumericExpr::Mul(Box::new(lhs), Box::new(rhs))
}

#[allow(dead_code)]
fn div_ceil(lhs: NumericExpr, rhs: NumericExpr) -> NumericExpr {
    NumericExpr::DivCeil(Box::new(lhs), Box::new(rhs))
}

#[allow(dead_code)]
fn mod_nat(lhs: NumericExpr, rhs: NumericExpr) -> NumericExpr {
    NumericExpr::ModNat(Box::new(lhs), Box::new(rhs))
}

#[allow(dead_code)]
fn truth() -> BooleanExpr {
    BooleanExpr::Truth
}

fn ge(lhs: NumericExpr, rhs: NumericExpr) -> BooleanExpr {
    BooleanExpr::GeExpr(lhs, rhs)
}

#[allow(dead_code)]
fn le(lhs: NumericExpr, rhs: NumericExpr) -> BooleanExpr {
    BooleanExpr::LeExpr(lhs, rhs)
}

#[allow(dead_code)]
fn eq(lhs: NumericExpr, rhs: NumericExpr) -> BooleanExpr {
    BooleanExpr::EqExpr(lhs, rhs)
}

fn is_power_of_two(expr: NumericExpr) -> BooleanExpr {
    BooleanExpr::IsPowerOfTwo(expr)
}

fn is_multiple_of(expr: NumericExpr, divisor: usize) -> BooleanExpr {
    BooleanExpr::IsMultipleOf(expr, divisor)
}

fn all_of(clauses: Vec<BooleanExpr>) -> BooleanExpr {
    BooleanExpr::AllOf(clauses)
}

fn domain(
    name: &str,
    min_value: usize,
    max_value: Option<usize>,
    non_zero: bool,
    power_of_two: bool,
    multiple_of: Option<usize>,
) -> SymbolDomain {
    SymbolDomain {
        name: name.to_string(),
        min_value,
        max_value,
        non_zero,
        power_of_two,
        multiple_of,
    }
}

fn region(
    name: &str,
    kind: MemoryRegionKind,
    start: NumericExpr,
    len: NumericExpr,
    bound: NumericExpr,
    element_bytes: usize,
) -> RegionSlice {
    RegionSlice {
        name: name.to_string(),
        kind,
        start,
        len,
        bound,
        element_bytes,
    }
}

fn step(
    name: &str,
    operator: TransitionOperator,
    arithmetic_domain: &str,
    reads: &[&str],
    writes: &[&str],
) -> KernelStep {
    KernelStep {
        name: name.to_string(),
        operator,
        arithmetic_domain: arithmetic_domain.to_string(),
        reads: reads.iter().map(|name| (*name).to_string()).collect(),
        writes: writes.iter().map(|name| (*name).to_string()).collect(),
    }
}

fn barrier(after_step: usize, scope: &str) -> BarrierPoint {
    BarrierPoint {
        after_step,
        scope: scope.to_string(),
    }
}

fn binding(
    step_index: usize,
    entrypoint: &str,
    source_path: &str,
    library: &str,
    binding_kind: &str,
) -> LoweringBinding {
    LoweringBinding {
        step_index,
        entrypoint: entrypoint.to_string(),
        source_path: source_path.to_string(),
        library: library.to_string(),
        binding_kind: binding_kind.to_string(),
    }
}

fn lowering(
    source_paths: &[&str],
    reflection_policy: &str,
    workgroup_policy: &str,
    step_bindings: Vec<LoweringBinding>,
) -> LoweringCertificate {
    let mut entrypoints = BTreeSet::new();
    let mut entrypoint_attestations = BTreeMap::new();
    for binding in &step_bindings {
        entrypoints.insert(binding.entrypoint.clone());
        entrypoint_attestations
            .entry((binding.library.clone(), binding.entrypoint.clone()))
            .or_insert_with(|| {
                expected_kernel_attestation(&binding.library, &binding.entrypoint).unwrap_or_else(
                    || {
                        panic!(
                            "missing verified kernel attestation for {}:{}",
                            binding.library, binding.entrypoint
                        )
                    },
                )
            });
    }
    LoweringCertificate {
        source_sha256: source_digest_map(source_paths),
        source_paths: source_paths
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
        entrypoints: entrypoints.into_iter().collect(),
        toolchain: current_toolchain_identity(),
        entrypoint_attestations: entrypoint_attestations.into_values().collect(),
        reflection_policy: reflection_policy.to_string(),
        workgroup_policy: workgroup_policy.to_string(),
        step_bindings,
    }
}

#[allow(clippy::too_many_arguments)]
fn program(
    theorem_id: &str,
    program_id: &str,
    family: KernelFamily,
    kernel: &str,
    variant: &str,
    field: Option<FieldFamily>,
    curve: Option<CurveFamily>,
    route: Option<MsmRouteClass>,
    index_map: ThreadIndexMap,
    symbols: Vec<SymbolDomain>,
    read_regions: Vec<RegionSlice>,
    write_regions: Vec<RegionSlice>,
    shared_regions: Vec<RegionSlice>,
    barriers: Vec<BarrierPoint>,
    steps: Vec<KernelStep>,
    lowering: LoweringCertificate,
    certified_claim: bool,
) -> KernelProgram {
    KernelProgram {
        theorem_id: theorem_id.to_string(),
        program_id: program_id.to_string(),
        family,
        kernel: kernel.to_string(),
        variant: variant.to_string(),
        field,
        curve,
        route,
        index_map,
        symbols,
        read_regions,
        write_regions,
        shared_regions,
        barriers,
        steps,
        lowering,
        certified_claim,
    }
}

fn hash_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("batch_count", 1, None, true, false, None),
        domain("message_index", 0, None, false, false, None),
        domain("input_len", 1, None, true, false, None),
        domain("input_bytes", 1, None, true, false, None),
        domain("output_bytes", 32, None, true, false, Some(32)),
    ]
}

fn hash_program(
    kernel: &str,
    variant: &str,
    source_path: &str,
    steps: Vec<KernelStep>,
) -> KernelProgram {
    let theorem_id = "gpu.hash_differential_bounded";
    let read_bound = symbol("input_bytes");
    let write_bound = symbol("output_bytes");
    let lowering = lowering(
        &[source_path, "zkf-metal/src/hash/mod.rs"],
        "SPIR-V reflection entrypoints must exactly match the shipped Metal hash entrypoint",
        "one thread per message; host threads-per-group capped at 256",
        steps
            .iter()
            .enumerate()
            .map(|(index, _)| binding(index, kernel, source_path, "hash_library", variant))
            .collect(),
    );
    program(
        theorem_id,
        kernel,
        KernelFamily::Hash,
        kernel,
        variant,
        Some(FieldFamily::Bytes),
        None,
        None,
        ThreadIndexMap {
            global_index: symbol("message_index"),
            lane_index: None,
            batch_index: Some(symbol("message_index")),
            guard: all_of(vec![
                ge(symbol("batch_count"), c(1)),
                ge(symbol("input_len"), c(1)),
                ge(symbol("output_bytes"), c(32)),
            ]),
        },
        hash_symbols(),
        vec![region(
            "inputs",
            MemoryRegionKind::GlobalInput,
            mul(symbol("message_index"), symbol("input_len")),
            symbol("input_len"),
            read_bound,
            1,
        )],
        vec![region(
            "digests",
            MemoryRegionKind::GlobalOutput,
            mul(symbol("message_index"), c(32)),
            c(32),
            write_bound,
            1,
        )],
        vec![],
        vec![],
        steps,
        lowering,
        true,
    )
}

fn hash_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::Hash,
        claim: GPU_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            hash_program(
                shader_library::kernels::BATCH_SHA256,
                "sha256_batch",
                "zkf-metal/src/shaders/sha256.metal",
                vec![
                    step(
                        "message_schedule",
                        TransitionOperator::Sha256MessageSchedule,
                        "bytes",
                        &["inputs"],
                        &["digests"],
                    ),
                    step(
                        "compression_rounds",
                        TransitionOperator::Sha256CompressionRound,
                        "bytes",
                        &["inputs"],
                        &["digests"],
                    ),
                    step(
                        "digest_writeback",
                        TransitionOperator::LayoutWriteback,
                        "layout",
                        &["digests"],
                        &["digests"],
                    ),
                ],
            ),
            hash_program(
                shader_library::kernels::BATCH_KECCAK256,
                "keccak256_batch",
                "zkf-metal/src/shaders/keccak256.metal",
                vec![
                    step(
                        "theta_phase",
                        TransitionOperator::KeccakTheta,
                        "bytes",
                        &["inputs"],
                        &["digests"],
                    ),
                    step(
                        "rho_pi_phase",
                        TransitionOperator::KeccakRhoPi,
                        "bytes",
                        &["digests"],
                        &["digests"],
                    ),
                    step(
                        "chi_iota_phase",
                        TransitionOperator::KeccakChiIota,
                        "bytes",
                        &["digests"],
                        &["digests"],
                    ),
                    step(
                        "digest_writeback",
                        TransitionOperator::LayoutWriteback,
                        "layout",
                        &["digests"],
                        &["digests"],
                    ),
                ],
            ),
        ],
    }
}

fn poseidon2_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("state_elements", 16, None, true, false, Some(16)),
        domain("round_constant_count", 1, None, true, false, None),
        domain("perm_index", 0, None, false, false, None),
        domain("lane_index", 0, Some(15), false, false, None),
    ]
}

fn poseidon2_program(kernel: &str, variant: &str, field: FieldFamily, simd: bool) -> KernelProgram {
    let source_path = "zkf-metal/src/shaders/poseidon2.metal";
    let steps = vec![
        step(
            "external_rounds",
            TransitionOperator::Poseidon2ExternalRound,
            "field",
            &["state", "round_constants", "matrix_diag"],
            &["state"],
        ),
        step(
            "matrix_layer",
            TransitionOperator::Poseidon2MatrixLayer,
            "field",
            &["state", "matrix_diag"],
            &["state"],
        ),
        step(
            "sbox_layer",
            TransitionOperator::Poseidon2SBox,
            "field",
            &["state"],
            &["state"],
        ),
        step(
            "internal_rounds",
            TransitionOperator::Poseidon2InternalRound,
            "field",
            &["state", "round_constants"],
            &["state"],
        ),
    ];
    let lowering = lowering(
        &[source_path, "zkf-metal/src/poseidon2/mod.rs"],
        "SPIR-V reflection entrypoints must match the scalar or SIMD Poseidon2 kernel exactly",
        "scalar path uses one thread per permutation; SIMD path uses 16 threads per permutation",
        steps
            .iter()
            .enumerate()
            .map(|(index, _)| {
                binding(
                    index,
                    kernel,
                    source_path,
                    "main_library",
                    if simd { "simd" } else { "scalar" },
                )
            })
            .collect(),
    );
    let state_bound = symbol("state_elements");
    let rc_bound = symbol("round_constant_count");
    let shared_regions = if simd {
        vec![region(
            "lane_scratch",
            MemoryRegionKind::Shared,
            c(0),
            c(16),
            c(16),
            if field == FieldFamily::BabyBear { 4 } else { 8 },
        )]
    } else {
        vec![]
    };
    let barriers = if simd {
        vec![barrier(1, "threadgroup")]
    } else {
        vec![]
    };
    program(
        "gpu.poseidon2_differential_bounded",
        kernel,
        KernelFamily::Poseidon2,
        kernel,
        variant,
        Some(field),
        None,
        None,
        ThreadIndexMap {
            global_index: if simd {
                add(mul(symbol("perm_index"), c(16)), symbol("lane_index"))
            } else {
                symbol("perm_index")
            },
            lane_index: if simd {
                Some(symbol("lane_index"))
            } else {
                None
            },
            batch_index: Some(symbol("perm_index")),
            guard: all_of(vec![
                ge(symbol("state_elements"), c(16)),
                is_multiple_of(symbol("state_elements"), 16),
                ge(symbol("round_constant_count"), c(1)),
            ]),
        },
        poseidon2_symbols(),
        vec![
            region(
                "state",
                MemoryRegionKind::GlobalInput,
                mul(symbol("perm_index"), c(16)),
                c(16),
                state_bound.clone(),
                if field == FieldFamily::BabyBear { 4 } else { 8 },
            ),
            region(
                "round_constants",
                MemoryRegionKind::Constant,
                c(0),
                symbol("round_constant_count"),
                rc_bound,
                if field == FieldFamily::BabyBear { 4 } else { 8 },
            ),
            region(
                "matrix_diag",
                MemoryRegionKind::Constant,
                c(0),
                c(16),
                c(16),
                if field == FieldFamily::BabyBear { 4 } else { 8 },
            ),
        ],
        vec![region(
            "state",
            MemoryRegionKind::GlobalOutput,
            mul(symbol("perm_index"), c(16)),
            c(16),
            symbol("state_elements"),
            if field == FieldFamily::BabyBear { 4 } else { 8 },
        )],
        shared_regions,
        barriers,
        steps,
        lowering,
        true,
    )
}

fn poseidon2_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::Poseidon2,
        claim: GPU_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            poseidon2_program(
                shader_library::kernels::POSEIDON2_GOLDILOCKS,
                "goldilocks_scalar",
                FieldFamily::Goldilocks,
                false,
            ),
            poseidon2_program(
                shader_library::kernels::POSEIDON2_GOLDILOCKS_SIMD,
                "goldilocks_simd",
                FieldFamily::Goldilocks,
                true,
            ),
            poseidon2_program(
                shader_library::kernels::POSEIDON2_BABYBEAR,
                "babybear_scalar",
                FieldFamily::BabyBear,
                false,
            ),
            poseidon2_program(
                shader_library::kernels::POSEIDON2_BABYBEAR_SIMD,
                "babybear_simd",
                FieldFamily::BabyBear,
                true,
            ),
        ],
    }
}

fn ntt_symbols(field: FieldFamily) -> Vec<SymbolDomain> {
    let element_bytes = match field {
        FieldFamily::BabyBear => Some(4),
        _ => Some(8),
    };
    vec![
        domain("height", 2, None, true, true, None),
        domain("width", 1, None, true, false, None),
        domain("row_index", 0, None, false, false, None),
        domain("column_index", 0, None, false, false, None),
        domain("twiddle_elements", 2, None, true, false, None),
        domain(
            "element_bytes",
            element_bytes.unwrap_or(8),
            element_bytes,
            true,
            false,
            None,
        ),
    ]
}

fn ntt_program(
    kernel: &str,
    variant: &str,
    field: FieldFamily,
    batched: bool,
    operator: TransitionOperator,
) -> KernelProgram {
    let source_path = if field == FieldFamily::Bn254Scalar {
        "zkf-metal/src/shaders/ntt_bn254.metal"
    } else if batched {
        "zkf-metal/src/shaders/ntt_radix2_batch.metal"
    } else {
        "zkf-metal/src/shaders/ntt_radix2.metal"
    };
    let steps = match operator {
        TransitionOperator::NttButterflyStage => vec![
            step(
                "butterfly_stage",
                TransitionOperator::NttButterflyStage,
                "field",
                &["values", "twiddles"],
                &["values"],
            ),
            step(
                "writeback",
                TransitionOperator::LayoutWriteback,
                "layout",
                &["values"],
                &["values"],
            ),
        ],
        TransitionOperator::NttSmallTransform => vec![
            step(
                "small_transform",
                TransitionOperator::NttSmallTransform,
                "field",
                &["values", "twiddles"],
                &["values"],
            ),
            step(
                "writeback",
                TransitionOperator::LayoutWriteback,
                "layout",
                &["values"],
                &["values"],
            ),
        ],
        TransitionOperator::NttHybridStage => vec![
            step(
                "hybrid_stage",
                TransitionOperator::NttHybridStage,
                "field",
                &["values", "twiddles"],
                &["values"],
            ),
            step(
                "writeback",
                TransitionOperator::LayoutWriteback,
                "layout",
                &["values"],
                &["values"],
            ),
        ],
        _ => vec![
            step(
                "bit_reverse",
                TransitionOperator::NttBitReverse,
                "layout",
                &["values"],
                &["values"],
            ),
            step(
                "butterfly_stage",
                TransitionOperator::NttButterflyStage,
                "field",
                &["values", "twiddles"],
                &["values"],
            ),
        ],
    };
    let source_paths = if field == FieldFamily::Bn254Scalar {
        vec![
            "zkf-metal/src/shaders/field_bn254_fr.metal",
            source_path,
            "zkf-metal/src/ntt/p3_adapter.rs",
            "zkf-metal/src/ntt/radix2.rs",
            "zkf-metal/src/ntt/bn254.rs",
        ]
    } else {
        vec![
            source_path,
            "zkf-metal/src/ntt/p3_adapter.rs",
            "zkf-metal/src/ntt/radix2.rs",
            "zkf-metal/src/ntt/bn254.rs",
        ]
    };
    let lowering = lowering(
        &source_paths,
        "SPIR-V reflection entrypoints must match the shipped single, batch, small, and hybrid NTT entrypoints",
        "one thread per butterfly with host-enforced buffer barriers between stages",
        steps
            .iter()
            .enumerate()
            .map(|(index, _)| binding(index, kernel, source_path, "main_library", variant))
            .collect(),
    );
    let element_bytes = if field == FieldFamily::BabyBear { 4 } else { 8 };
    program(
        "gpu.ntt_differential_bounded",
        kernel,
        KernelFamily::Ntt,
        kernel,
        variant,
        Some(field),
        None,
        None,
        ThreadIndexMap {
            global_index: if batched {
                add(
                    mul(symbol("row_index"), symbol("width")),
                    symbol("column_index"),
                )
            } else {
                symbol("row_index")
            },
            lane_index: None,
            batch_index: if batched {
                Some(symbol("column_index"))
            } else {
                None
            },
            guard: all_of(vec![
                ge(symbol("height"), c(2)),
                is_power_of_two(symbol("height")),
                ge(symbol("width"), c(1)),
                ge(symbol("twiddle_elements"), symbol("height")),
            ]),
        },
        ntt_symbols(field),
        vec![
            region(
                "values",
                MemoryRegionKind::GlobalInput,
                if batched {
                    add(
                        mul(symbol("row_index"), symbol("width")),
                        symbol("column_index"),
                    )
                } else {
                    symbol("row_index")
                },
                c(1),
                mul(symbol("height"), symbol("width")),
                element_bytes,
            ),
            region(
                "twiddles",
                MemoryRegionKind::Constant,
                c(0),
                symbol("twiddle_elements"),
                symbol("twiddle_elements"),
                element_bytes,
            ),
        ],
        vec![region(
            "values",
            MemoryRegionKind::GlobalOutput,
            if batched {
                add(
                    mul(symbol("row_index"), symbol("width")),
                    symbol("column_index"),
                )
            } else {
                symbol("row_index")
            },
            c(1),
            mul(symbol("height"), symbol("width")),
            element_bytes,
        )],
        vec![],
        if matches!(operator, TransitionOperator::NttButterflyStage) {
            vec![barrier(0, "buffers")]
        } else {
            vec![]
        },
        steps,
        lowering,
        true,
    )
}

fn ntt_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::Ntt,
        claim: GPU_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            ntt_program(
                shader_library::kernels::NTT_BUTTERFLY_GOLDILOCKS,
                "goldilocks_single",
                FieldFamily::Goldilocks,
                false,
                TransitionOperator::NttButterflyStage,
            ),
            ntt_program(
                shader_library::kernels::NTT_BUTTERFLY_GOLDILOCKS_BATCH,
                "goldilocks_batch",
                FieldFamily::Goldilocks,
                true,
                TransitionOperator::NttButterflyStage,
            ),
            ntt_program(
                shader_library::kernels::NTT_SMALL_GOLDILOCKS,
                "goldilocks_small",
                FieldFamily::Goldilocks,
                false,
                TransitionOperator::NttSmallTransform,
            ),
            ntt_program(
                shader_library::kernels::NTT_HYBRID_GOLDILOCKS,
                "goldilocks_hybrid",
                FieldFamily::Goldilocks,
                false,
                TransitionOperator::NttHybridStage,
            ),
            ntt_program(
                shader_library::kernels::NTT_BUTTERFLY_BABYBEAR,
                "babybear_single",
                FieldFamily::BabyBear,
                false,
                TransitionOperator::NttButterflyStage,
            ),
            ntt_program(
                shader_library::kernels::NTT_BUTTERFLY_BABYBEAR_BATCH,
                "babybear_batch",
                FieldFamily::BabyBear,
                true,
                TransitionOperator::NttButterflyStage,
            ),
            ntt_program(
                shader_library::kernels::NTT_BUTTERFLY_BN254,
                "bn254_single",
                FieldFamily::Bn254Scalar,
                false,
                TransitionOperator::NttButterflyStage,
            ),
            ntt_program(
                shader_library::kernels::NTT_SMALL_BN254,
                "bn254_small",
                FieldFamily::Bn254Scalar,
                false,
                TransitionOperator::NttSmallTransform,
            ),
            ntt_program(
                shader_library::kernels::NTT_HYBRID_BN254,
                "bn254_hybrid",
                FieldFamily::Bn254Scalar,
                false,
                TransitionOperator::NttHybridStage,
            ),
        ],
    }
}

fn field_ops_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("element_count", 1, None, true, false, None),
        domain("chunk_size", 1, None, true, false, None),
        domain("element_index", 0, None, false, false, None),
        domain("chunk_index", 0, None, false, false, None),
    ]
}

fn field_binary_program(
    kernel: &str,
    variant: &str,
    field: FieldFamily,
    operator: TransitionOperator,
) -> KernelProgram {
    let element_bytes = if field == FieldFamily::BabyBear { 4 } else { 8 };
    let source_path = "zkf-metal/src/shaders/batch_field_ops.metal";
    let steps = vec![step(variant, operator, "field", &["a", "b"], &["a"])];
    let lowering = lowering(
        &[source_path, "zkf-metal/src/field_ops.rs"],
        "SPIR-V reflection entrypoints must match the shipped batch field operation kernels exactly",
        "one thread per field element; host threads-per-group capped at 256",
        vec![binding(0, kernel, source_path, "main_library", variant)],
    );
    program(
        "gpu.field_ops_surface_attested",
        kernel,
        KernelFamily::FieldOps,
        kernel,
        variant,
        Some(field),
        None,
        None,
        ThreadIndexMap {
            global_index: symbol("element_index"),
            lane_index: None,
            batch_index: None,
            guard: ge(symbol("element_count"), c(1)),
        },
        field_ops_symbols(),
        vec![
            region(
                "a",
                MemoryRegionKind::GlobalInput,
                symbol("element_index"),
                c(1),
                symbol("element_count"),
                element_bytes,
            ),
            region(
                "b",
                MemoryRegionKind::GlobalInput,
                symbol("element_index"),
                c(1),
                symbol("element_count"),
                element_bytes,
            ),
        ],
        vec![region(
            "a",
            MemoryRegionKind::GlobalOutput,
            symbol("element_index"),
            c(1),
            symbol("element_count"),
            element_bytes,
        )],
        vec![],
        vec![],
        steps,
        lowering,
        false,
    )
}

fn field_inversion_program(
    kernel: &str,
    variant: &str,
    operator: TransitionOperator,
) -> KernelProgram {
    let source_path = "zkf-metal/src/shaders/batch_field_ops.metal";
    let (reads, writes) = match operator {
        TransitionOperator::FieldInvPrefix => (
            vec![region(
                "input",
                MemoryRegionKind::GlobalInput,
                mul(symbol("chunk_index"), symbol("chunk_size")),
                symbol("chunk_size"),
                symbol("element_count"),
                8,
            )],
            vec![region(
                "prefix",
                MemoryRegionKind::GlobalOutput,
                mul(symbol("chunk_index"), symbol("chunk_size")),
                symbol("chunk_size"),
                symbol("element_count"),
                8,
            )],
        ),
        TransitionOperator::FieldInvBackprop => (
            vec![
                region(
                    "input",
                    MemoryRegionKind::GlobalInput,
                    mul(symbol("chunk_index"), symbol("chunk_size")),
                    symbol("chunk_size"),
                    symbol("element_count"),
                    8,
                ),
                region(
                    "prefix",
                    MemoryRegionKind::GlobalInput,
                    mul(symbol("chunk_index"), symbol("chunk_size")),
                    symbol("chunk_size"),
                    symbol("element_count"),
                    8,
                ),
            ],
            vec![region(
                "output",
                MemoryRegionKind::GlobalOutput,
                mul(symbol("chunk_index"), symbol("chunk_size")),
                symbol("chunk_size"),
                symbol("element_count"),
                8,
            )],
        ),
        _ => unreachable!("field inversion program only supports inversion operators"),
    };
    let steps = vec![step(
        variant,
        operator,
        "field",
        &reads
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
        &writes
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
    )];
    let lowering = lowering(
        &[source_path, "zkf-metal/src/field_ops.rs"],
        "SPIR-V reflection entrypoints must match the shipped batch field inversion staging kernels exactly",
        "one thread per chunk; host threads-per-group capped at 256",
        vec![binding(0, kernel, source_path, "main_library", variant)],
    );
    program(
        "gpu.field_ops_surface_attested",
        kernel,
        KernelFamily::FieldOps,
        kernel,
        variant,
        Some(FieldFamily::Goldilocks),
        None,
        None,
        ThreadIndexMap {
            global_index: symbol("chunk_index"),
            lane_index: None,
            batch_index: None,
            guard: all_of(vec![
                ge(symbol("element_count"), c(1)),
                ge(symbol("chunk_size"), c(1)),
            ]),
        },
        field_ops_symbols(),
        reads,
        writes,
        vec![],
        vec![],
        steps,
        lowering,
        false,
    )
}

fn field_ops_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::FieldOps,
        claim: GPU_ATTESTED_SURFACE_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            field_binary_program(
                shader_library::kernels::BATCH_ADD_GOLDILOCKS,
                "goldilocks_add",
                FieldFamily::Goldilocks,
                TransitionOperator::FieldAdd,
            ),
            field_binary_program(
                shader_library::kernels::BATCH_SUB_GOLDILOCKS,
                "goldilocks_sub",
                FieldFamily::Goldilocks,
                TransitionOperator::FieldSub,
            ),
            field_binary_program(
                shader_library::kernels::BATCH_MUL_GOLDILOCKS,
                "goldilocks_mul",
                FieldFamily::Goldilocks,
                TransitionOperator::FieldMul,
            ),
            field_inversion_program(
                shader_library::kernels::BATCH_INV_PREFIX_GOLDILOCKS,
                "goldilocks_inv_prefix",
                TransitionOperator::FieldInvPrefix,
            ),
            field_inversion_program(
                shader_library::kernels::BATCH_INV_BACKPROP_GOLDILOCKS,
                "goldilocks_inv_backprop",
                TransitionOperator::FieldInvBackprop,
            ),
            field_binary_program(
                shader_library::kernels::BATCH_ADD_BABYBEAR,
                "babybear_add",
                FieldFamily::BabyBear,
                TransitionOperator::FieldAdd,
            ),
            field_binary_program(
                shader_library::kernels::BATCH_SUB_BABYBEAR,
                "babybear_sub",
                FieldFamily::BabyBear,
                TransitionOperator::FieldSub,
            ),
            field_binary_program(
                shader_library::kernels::BATCH_MUL_BABYBEAR,
                "babybear_mul",
                FieldFamily::BabyBear,
                TransitionOperator::FieldMul,
            ),
        ],
    }
}

fn poly_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("degree", 1, None, true, false, None),
        domain("point_count", 1, None, true, false, None),
        domain("poly_count", 1, None, true, false, None),
        domain("point_index", 0, None, false, false, None),
        domain("poly_index", 0, None, false, false, None),
        domain("coefficient_index", 0, None, false, false, None),
    ]
}

fn poly_program(
    theorem_id: &str,
    program_id: &str,
    kernel: &str,
    variant: &str,
    field: FieldFamily,
    operator: TransitionOperator,
) -> KernelProgram {
    let element_bytes = if field == FieldFamily::BabyBear { 4 } else { 8 };
    let source_path = "zkf-metal/src/shaders/poly_ops.metal";
    let (global_index, batch_index, reads, writes) = match operator {
        TransitionOperator::PolyEval => (
            symbol("point_index"),
            None,
            vec![
                region(
                    "coeffs",
                    MemoryRegionKind::Constant,
                    c(0),
                    symbol("degree"),
                    symbol("degree"),
                    element_bytes,
                ),
                region(
                    "points",
                    MemoryRegionKind::GlobalInput,
                    symbol("point_index"),
                    c(1),
                    symbol("point_count"),
                    element_bytes,
                ),
            ],
            vec![region(
                "output",
                MemoryRegionKind::GlobalOutput,
                symbol("point_index"),
                c(1),
                symbol("point_count"),
                element_bytes,
            )],
        ),
        TransitionOperator::PolyBatchEval => (
            add(
                mul(symbol("poly_index"), symbol("point_count")),
                symbol("point_index"),
            ),
            Some(symbol("poly_index")),
            vec![
                region(
                    "coeffs_flat",
                    MemoryRegionKind::Constant,
                    mul(symbol("poly_index"), symbol("degree")),
                    symbol("degree"),
                    mul(symbol("poly_count"), symbol("degree")),
                    8,
                ),
                region(
                    "points",
                    MemoryRegionKind::GlobalInput,
                    symbol("point_index"),
                    c(1),
                    symbol("point_count"),
                    8,
                ),
            ],
            vec![region(
                "output",
                MemoryRegionKind::GlobalOutput,
                add(
                    mul(symbol("poly_index"), symbol("point_count")),
                    symbol("point_index"),
                ),
                c(1),
                mul(symbol("poly_count"), symbol("point_count")),
                8,
            )],
        ),
        TransitionOperator::PolyQuotient => (
            symbol("point_index"),
            None,
            vec![region(
                "evals",
                MemoryRegionKind::GlobalInput,
                symbol("point_index"),
                c(1),
                symbol("point_count"),
                8,
            )],
            vec![region(
                "output",
                MemoryRegionKind::GlobalOutput,
                symbol("point_index"),
                c(1),
                symbol("point_count"),
                8,
            )],
        ),
        TransitionOperator::PolyCosetShift => (
            symbol("coefficient_index"),
            None,
            vec![region(
                "coeffs",
                MemoryRegionKind::GlobalInput,
                symbol("coefficient_index"),
                c(1),
                symbol("degree"),
                8,
            )],
            vec![region(
                "coeffs",
                MemoryRegionKind::GlobalOutput,
                symbol("coefficient_index"),
                c(1),
                symbol("degree"),
                8,
            )],
        ),
        _ => unreachable!("poly program only supports polynomial operators"),
    };
    let steps = vec![step(
        variant,
        operator,
        "field",
        &reads
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
        &writes
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
    )];
    let lowering = lowering(
        &[source_path, "zkf-metal/src/poly.rs"],
        "SPIR-V reflection entrypoints must match the shipped polynomial kernels exactly",
        "one thread per point or coefficient; host threads-per-group capped at 256",
        vec![binding(0, kernel, source_path, "main_library", variant)],
    );
    program(
        theorem_id,
        program_id,
        KernelFamily::Poly,
        kernel,
        variant,
        Some(field),
        None,
        None,
        ThreadIndexMap {
            global_index,
            lane_index: None,
            batch_index,
            guard: all_of(vec![
                ge(symbol("degree"), c(1)),
                ge(symbol("point_count"), c(1)),
                ge(symbol("poly_count"), c(1)),
            ]),
        },
        poly_symbols(),
        reads,
        writes,
        vec![],
        vec![],
        steps,
        lowering,
        false,
    )
}

fn poly_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::Poly,
        claim: GPU_ATTESTED_SURFACE_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            poly_program(
                "gpu.poly_surface_attested",
                "poly_eval_goldilocks",
                shader_library::kernels::POLY_EVAL_GOLDILOCKS,
                "goldilocks_eval",
                FieldFamily::Goldilocks,
                TransitionOperator::PolyEval,
            ),
            poly_program(
                "gpu.poly_surface_attested",
                "poly_batch_eval_goldilocks",
                shader_library::kernels::POLY_BATCH_EVAL_GOLDILOCKS,
                "goldilocks_batch_eval",
                FieldFamily::Goldilocks,
                TransitionOperator::PolyBatchEval,
            ),
            poly_program(
                "gpu.poly_surface_attested",
                "poly_quotient_goldilocks",
                shader_library::kernels::POLY_QUOTIENT_GOLDILOCKS,
                "goldilocks_quotient",
                FieldFamily::Goldilocks,
                TransitionOperator::PolyQuotient,
            ),
            poly_program(
                "gpu.poly_surface_attested",
                "poly_coset_shift_goldilocks",
                shader_library::kernels::POLY_COSET_SHIFT_GOLDILOCKS,
                "goldilocks_coset_shift",
                FieldFamily::Goldilocks,
                TransitionOperator::PolyCosetShift,
            ),
            poly_program(
                "gpu.poly_surface_attested",
                "poly_eval_babybear",
                shader_library::kernels::POLY_EVAL_BABYBEAR,
                "babybear_eval",
                FieldFamily::BabyBear,
                TransitionOperator::PolyEval,
            ),
        ],
    }
}

fn fri_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("output_count", 1, None, true, false, None),
        domain("element_index", 0, None, false, false, None),
    ]
}

fn fri_program(kernel: &str, variant: &str, field: FieldFamily) -> KernelProgram {
    let element_bytes = if field == FieldFamily::BabyBear { 4 } else { 8 };
    let source_path = "zkf-metal/src/shaders/fri.metal";
    let steps = vec![step(
        variant,
        TransitionOperator::FriFold,
        "field",
        &["evals", "inv_twiddles"],
        &["output"],
    )];
    let lowering = lowering(
        &[source_path, "zkf-metal/src/fri.rs"],
        "SPIR-V reflection entrypoints must match the shipped FRI fold kernels exactly",
        "one thread per folded evaluation; host threads-per-group capped at 256",
        vec![binding(0, kernel, source_path, "main_library", variant)],
    );
    program(
        "gpu.fri_surface_attested",
        kernel,
        KernelFamily::Fri,
        kernel,
        variant,
        Some(field),
        None,
        None,
        ThreadIndexMap {
            global_index: symbol("element_index"),
            lane_index: None,
            batch_index: None,
            guard: ge(symbol("output_count"), c(1)),
        },
        fri_symbols(),
        vec![
            region(
                "evals",
                MemoryRegionKind::GlobalInput,
                mul(symbol("element_index"), c(2)),
                c(2),
                mul(symbol("output_count"), c(2)),
                element_bytes,
            ),
            region(
                "inv_twiddles",
                MemoryRegionKind::Constant,
                symbol("element_index"),
                c(1),
                symbol("output_count"),
                element_bytes,
            ),
        ],
        vec![region(
            "output",
            MemoryRegionKind::GlobalOutput,
            symbol("element_index"),
            c(1),
            symbol("output_count"),
            element_bytes,
        )],
        vec![],
        vec![],
        steps,
        lowering,
        false,
    )
}

fn fri_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::Fri,
        claim: GPU_ATTESTED_SURFACE_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            fri_program(
                shader_library::kernels::FRI_FOLD_GOLDILOCKS,
                "goldilocks_fold",
                FieldFamily::Goldilocks,
            ),
            fri_program(
                shader_library::kernels::FRI_FOLD_BABYBEAR,
                "babybear_fold",
                FieldFamily::BabyBear,
            ),
        ],
    }
}

fn constraint_eval_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("row_count", 1, None, true, false, None),
        domain("trace_width", 1, None, true, false, None),
        domain("instruction_count", 1, None, true, false, None),
        domain("constraint_count", 1, None, true, false, None),
        domain("constant_count", 1, None, true, false, None),
        domain("row_index", 0, None, false, false, None),
    ]
}

fn constraint_eval_manifest() -> FamilyProofManifest {
    let source_path = "zkf-metal/src/shaders/constraint_eval.metal";
    let steps = vec![step(
        "goldilocks_constraint_eval",
        TransitionOperator::ConstraintEval,
        "field",
        &["trace", "bytecode", "constants"],
        &["output"],
    )];
    let lowering = lowering(
        &[source_path, "zkf-metal/src/constraint_eval.rs"],
        "SPIR-V reflection entrypoints must match the shipped constraint-eval kernel exactly",
        "one thread per row; host threads-per-group capped at 256",
        vec![binding(
            0,
            shader_library::kernels::CONSTRAINT_EVAL_GOLDILOCKS,
            source_path,
            "main_library",
            "goldilocks_constraint_eval",
        )],
    );
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::ConstraintEval,
        claim: GPU_ATTESTED_SURFACE_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![program(
            "gpu.constraint_eval_surface_attested",
            "constraint_eval_goldilocks",
            KernelFamily::ConstraintEval,
            shader_library::kernels::CONSTRAINT_EVAL_GOLDILOCKS,
            "goldilocks_constraint_eval",
            Some(FieldFamily::Goldilocks),
            None,
            None,
            ThreadIndexMap {
                global_index: symbol("row_index"),
                lane_index: None,
                batch_index: None,
                guard: all_of(vec![
                    ge(symbol("row_count"), c(1)),
                    ge(symbol("trace_width"), c(1)),
                    ge(symbol("instruction_count"), c(1)),
                    ge(symbol("constraint_count"), c(1)),
                    ge(symbol("constant_count"), c(1)),
                ]),
            },
            constraint_eval_symbols(),
            vec![
                region(
                    "trace",
                    MemoryRegionKind::GlobalInput,
                    mul(symbol("row_index"), symbol("trace_width")),
                    symbol("trace_width"),
                    mul(symbol("row_count"), symbol("trace_width")),
                    8,
                ),
                region(
                    "bytecode",
                    MemoryRegionKind::Constant,
                    c(0),
                    symbol("instruction_count"),
                    symbol("instruction_count"),
                    4,
                ),
                region(
                    "constants",
                    MemoryRegionKind::Constant,
                    c(0),
                    symbol("constant_count"),
                    symbol("constant_count"),
                    8,
                ),
            ],
            vec![region(
                "output",
                MemoryRegionKind::GlobalOutput,
                mul(symbol("row_index"), symbol("constraint_count")),
                symbol("constraint_count"),
                mul(symbol("row_count"), symbol("constraint_count")),
                8,
            )],
            vec![],
            vec![],
            steps,
            lowering,
            false,
        )],
    }
}

fn msm_common_symbols() -> Vec<SymbolDomain> {
    vec![
        domain("point_count", 1, None, true, false, None),
        domain("num_windows", 1, None, true, false, None),
        domain("num_buckets", 1, None, true, false, None),
        domain("segment_count", 1, None, true, false, None),
        domain("scalar_limbs", 4, Some(4), true, false, None),
        domain("base_limbs", 4, Some(4), true, false, None),
        domain("window_index", 0, None, false, false, None),
        domain("bucket_index", 0, None, false, false, None),
        domain("segment_index", 0, None, false, false, None),
        domain("point_index", 0, None, false, false, None),
        domain("point_start", 0, None, false, false, None),
        domain("segment_point_count", 1, None, true, false, None),
    ]
}

fn msm_read_regions(route: MsmRouteClass, stage: TransitionOperator) -> Vec<RegionSlice> {
    match stage {
        TransitionOperator::MsmBucketAssign => vec![region(
            "scalars",
            MemoryRegionKind::GlobalInput,
            mul(symbol("point_index"), symbol("scalar_limbs")),
            symbol("scalar_limbs"),
            mul(symbol("point_count"), symbol("scalar_limbs")),
            8,
        )],
        TransitionOperator::MsmBucketAccumulate => {
            let mut reads = vec![
                region(
                    "bases_x",
                    MemoryRegionKind::GlobalInput,
                    mul(symbol("point_index"), symbol("base_limbs")),
                    symbol("base_limbs"),
                    mul(symbol("point_count"), symbol("base_limbs")),
                    8,
                ),
                region(
                    "bases_y",
                    MemoryRegionKind::GlobalInput,
                    mul(symbol("point_index"), symbol("base_limbs")),
                    symbol("base_limbs"),
                    mul(symbol("point_count"), symbol("base_limbs")),
                    8,
                ),
                region(
                    "bucket_map",
                    if route == MsmRouteClass::Naf {
                        MemoryRegionKind::GlobalInput
                    } else {
                        MemoryRegionKind::Scratch
                    },
                    mul(symbol("point_index"), symbol("num_windows")),
                    symbol("num_windows"),
                    mul(symbol("point_count"), symbol("num_windows")),
                    4,
                ),
            ];
            if route != MsmRouteClass::Naf {
                reads.insert(
                    0,
                    region(
                        "scalars",
                        MemoryRegionKind::GlobalInput,
                        mul(symbol("point_index"), symbol("scalar_limbs")),
                        symbol("scalar_limbs"),
                        mul(symbol("point_count"), symbol("scalar_limbs")),
                        8,
                    ),
                );
            }
            reads
        }
        TransitionOperator::MsmBucketSegmentReduce => vec![region(
            "segment_buckets",
            MemoryRegionKind::GlobalInput,
            mul(
                add(
                    mul(
                        symbol("segment_index"),
                        mul(symbol("num_windows"), symbol("num_buckets")),
                    ),
                    symbol("bucket_index"),
                ),
                c(12),
            ),
            c(12),
            mul(
                mul(
                    mul(symbol("segment_count"), symbol("num_windows")),
                    symbol("num_buckets"),
                ),
                c(12),
            ),
            8,
        )],
        TransitionOperator::MsmBucketReduce => vec![region(
            "buckets",
            MemoryRegionKind::GlobalInput,
            mul(symbol("bucket_index"), c(12)),
            c(12),
            mul(mul(symbol("num_windows"), symbol("num_buckets")), c(12)),
            8,
        )],
        TransitionOperator::MsmWindowCombine => vec![region(
            "window_results",
            MemoryRegionKind::GlobalInput,
            mul(symbol("window_index"), c(12)),
            c(12),
            mul(symbol("num_windows"), c(12)),
            8,
        )],
        _ => vec![],
    }
}

fn msm_write_regions(stage: TransitionOperator) -> Vec<RegionSlice> {
    match stage {
        TransitionOperator::MsmBucketAssign => vec![region(
            "bucket_map",
            MemoryRegionKind::Scratch,
            mul(symbol("point_index"), symbol("num_windows")),
            symbol("num_windows"),
            mul(symbol("point_count"), symbol("num_windows")),
            4,
        )],
        TransitionOperator::MsmBucketAccumulate => vec![region(
            "buckets",
            MemoryRegionKind::GlobalOutput,
            mul(symbol("bucket_index"), c(12)),
            c(12),
            mul(mul(symbol("num_windows"), symbol("num_buckets")), c(12)),
            8,
        )],
        TransitionOperator::MsmBucketSegmentReduce => vec![region(
            "buckets",
            MemoryRegionKind::GlobalOutput,
            mul(symbol("bucket_index"), c(12)),
            c(12),
            mul(mul(symbol("num_windows"), symbol("num_buckets")), c(12)),
            8,
        )],
        TransitionOperator::MsmBucketReduce => vec![region(
            "window_results",
            MemoryRegionKind::GlobalOutput,
            mul(symbol("window_index"), c(12)),
            c(12),
            mul(symbol("num_windows"), c(12)),
            8,
        )],
        TransitionOperator::MsmWindowCombine => vec![region(
            "final_result",
            MemoryRegionKind::GlobalOutput,
            c(0),
            c(12),
            c(12),
            8,
        )],
        _ => vec![],
    }
}

fn msm_segmented_accumulate_read_regions(route: MsmRouteClass) -> Vec<RegionSlice> {
    let mut reads = vec![
        region(
            "bases_x",
            MemoryRegionKind::GlobalInput,
            mul(symbol("point_start"), symbol("base_limbs")),
            mul(symbol("segment_point_count"), symbol("base_limbs")),
            mul(symbol("point_count"), symbol("base_limbs")),
            8,
        ),
        region(
            "bases_y",
            MemoryRegionKind::GlobalInput,
            mul(symbol("point_start"), symbol("base_limbs")),
            mul(symbol("segment_point_count"), symbol("base_limbs")),
            mul(symbol("point_count"), symbol("base_limbs")),
            8,
        ),
        region(
            "bucket_map",
            if route == MsmRouteClass::Naf {
                MemoryRegionKind::GlobalInput
            } else {
                MemoryRegionKind::Scratch
            },
            mul(symbol("point_start"), symbol("num_windows")),
            mul(symbol("segment_point_count"), symbol("num_windows")),
            mul(symbol("point_count"), symbol("num_windows")),
            4,
        ),
    ];
    if route != MsmRouteClass::Naf {
        reads.insert(
            0,
            region(
                "scalars",
                MemoryRegionKind::GlobalInput,
                mul(symbol("point_start"), symbol("scalar_limbs")),
                mul(symbol("segment_point_count"), symbol("scalar_limbs")),
                mul(symbol("point_count"), symbol("scalar_limbs")),
                8,
            ),
        );
    }
    reads
}

#[allow(clippy::too_many_arguments)]
fn msm_program(
    theorem_id: &str,
    program_id: &str,
    kernel: &str,
    variant: &str,
    curve: CurveFamily,
    route: MsmRouteClass,
    stage: TransitionOperator,
    source_path: &str,
    library: &str,
) -> KernelProgram {
    let steps = vec![step(
        variant,
        stage.clone(),
        "curve_groups",
        &msm_read_regions(route, stage.clone())
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
        &msm_write_regions(stage.clone())
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
    )];
    let source_paths = if library == "bn254_msm_library" {
        vec![
            source_path,
            "zkf-metal/src/msm/mod.rs",
            "zkf-metal/src/msm/pippenger.rs",
            "zkf-metal/src/shaders/msm_sort.metal",
            "zkf-metal/src/shaders/msm_reduce.metal",
        ]
    } else if library == "pallas_msm_library" {
        vec![
            source_path,
            "zkf-metal/src/msm/mod.rs",
            "zkf-metal/src/msm/pallas_pippenger.rs",
        ]
    } else {
        vec![
            source_path,
            "zkf-metal/src/msm/mod.rs",
            "zkf-metal/src/msm/vesta_pippenger.rs",
        ]
    };
    let lowering = lowering(
        &source_paths,
        "SPIR-V reflection entrypoints must match the shipped MSM bucket and reduction kernels",
        "certified BN254 route is classic-only; Pallas and Vesta may use classic and NAF entrypoints",
        vec![binding(0, kernel, source_path, library, variant)],
    );
    program(
        theorem_id,
        program_id,
        KernelFamily::Msm,
        kernel,
        variant,
        None,
        Some(curve),
        Some(route),
        ThreadIndexMap {
            global_index: match stage {
                TransitionOperator::MsmBucketAssign => symbol("point_index"),
                TransitionOperator::MsmBucketAccumulate
                | TransitionOperator::MsmBucketSegmentReduce
                | TransitionOperator::MsmBucketReduce => symbol("bucket_index"),
                TransitionOperator::MsmWindowCombine => symbol("window_index"),
                _ => symbol("point_index"),
            },
            lane_index: None,
            batch_index: Some(symbol("window_index")),
            guard: all_of(vec![
                ge(symbol("point_count"), c(1)),
                ge(symbol("num_windows"), c(1)),
                ge(symbol("num_buckets"), c(1)),
            ]),
        },
        msm_common_symbols(),
        msm_read_regions(route, stage.clone()),
        msm_write_regions(stage),
        vec![],
        vec![],
        steps,
        lowering,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn msm_custom_program(
    theorem_id: &str,
    program_id: &str,
    kernel: &str,
    variant: &str,
    curve: CurveFamily,
    route: MsmRouteClass,
    stage: TransitionOperator,
    source_path: &str,
    library: &str,
    index_map: ThreadIndexMap,
    read_regions: Vec<RegionSlice>,
    write_regions: Vec<RegionSlice>,
) -> KernelProgram {
    let steps = vec![step(
        variant,
        stage.clone(),
        "curve_groups",
        &read_regions
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
        &write_regions
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
    )];
    let source_paths = vec![
        source_path,
        "zkf-metal/src/msm/mod.rs",
        "zkf-metal/src/msm/pippenger.rs",
        "zkf-metal/src/shaders/msm_sort.metal",
        "zkf-metal/src/shaders/msm_reduce.metal",
    ];
    let lowering = lowering(
        &source_paths,
        "SPIR-V reflection entrypoints must match the shipped MSM bucket and reduction kernels",
        "certified BN254 route is classic-only; Pallas and Vesta may use classic and NAF entrypoints",
        vec![binding(0, kernel, source_path, library, variant)],
    );
    program(
        theorem_id,
        program_id,
        KernelFamily::Msm,
        kernel,
        variant,
        None,
        Some(curve),
        Some(route),
        index_map,
        msm_common_symbols(),
        read_regions,
        write_regions,
        vec![],
        vec![],
        steps,
        lowering,
        true,
    )
}

fn msm_manifest() -> FamilyProofManifest {
    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::Msm,
        claim: GPU_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_bn254_classic_assign",
                "msm_bucket_assign",
                "classic_assign",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAssign,
                "zkf-metal/src/shaders/msm_bn254.metal",
                "bn254_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_bn254_classic_accumulate",
                "msm_bucket_acc",
                "classic_accumulate",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_bn254.metal",
                "bn254_msm_library",
            ),
            msm_custom_program(
                "gpu.msm_differential_bounded",
                "msm_bn254_classic_accumulate_segmented",
                "msm_bucket_acc_segmented",
                "classic_segmented_accumulate",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_bn254.metal",
                "bn254_msm_library",
                ThreadIndexMap {
                    global_index: symbol("bucket_index"),
                    lane_index: None,
                    batch_index: Some(symbol("window_index")),
                    guard: all_of(vec![
                        ge(symbol("point_count"), c(1)),
                        ge(symbol("num_windows"), c(1)),
                        ge(symbol("num_buckets"), c(1)),
                        ge(symbol("segment_point_count"), c(1)),
                        le(
                            add(symbol("point_start"), symbol("segment_point_count")),
                            symbol("point_count"),
                        ),
                    ]),
                },
                msm_segmented_accumulate_read_regions(MsmRouteClass::Classic),
                msm_write_regions(TransitionOperator::MsmBucketAccumulate),
            ),
            msm_custom_program(
                "gpu.msm_differential_bounded",
                "msm_bn254_classic_segment_reduce",
                "msm_bucket_segment_reduce",
                "classic_segment_reduce",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketSegmentReduce,
                "zkf-metal/src/shaders/msm_reduce.metal",
                "bn254_msm_library",
                ThreadIndexMap {
                    global_index: symbol("bucket_index"),
                    lane_index: None,
                    batch_index: Some(symbol("window_index")),
                    guard: all_of(vec![
                        ge(symbol("segment_count"), c(1)),
                        ge(symbol("num_windows"), c(1)),
                        ge(symbol("num_buckets"), c(1)),
                    ]),
                },
                msm_read_regions(
                    MsmRouteClass::Classic,
                    TransitionOperator::MsmBucketSegmentReduce,
                ),
                msm_write_regions(TransitionOperator::MsmBucketSegmentReduce),
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_bn254_classic_reduce",
                "msm_bucket_reduce",
                "classic_reduce",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketReduce,
                "zkf-metal/src/shaders/msm_reduce.metal",
                "bn254_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_bn254_classic_combine",
                "msm_window_combine",
                "classic_combine",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmWindowCombine,
                "zkf-metal/src/shaders/msm_reduce.metal",
                "bn254_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_pallas_classic_assign",
                "msm_bucket_assign",
                "classic_assign",
                CurveFamily::Pallas,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAssign,
                "zkf-metal/src/shaders/msm_pallas.metal",
                "pallas_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_pallas_classic_accumulate",
                "msm_bucket_acc",
                "classic_accumulate",
                CurveFamily::Pallas,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_pallas.metal",
                "pallas_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_pallas_naf_accumulate",
                "msm_bucket_acc_naf",
                "naf_accumulate",
                CurveFamily::Pallas,
                MsmRouteClass::Naf,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_pallas.metal",
                "pallas_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_vesta_classic_assign",
                "msm_bucket_assign",
                "classic_assign",
                CurveFamily::Vesta,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAssign,
                "zkf-metal/src/shaders/msm_vesta.metal",
                "vesta_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_vesta_classic_accumulate",
                "msm_bucket_acc",
                "classic_accumulate",
                CurveFamily::Vesta,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_vesta.metal",
                "vesta_msm_library",
            ),
            msm_program(
                "gpu.msm_differential_bounded",
                "msm_vesta_naf_accumulate",
                "msm_bucket_acc_naf",
                "naf_accumulate",
                CurveFamily::Vesta,
                MsmRouteClass::Naf,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_vesta.metal",
                "vesta_msm_library",
            ),
        ],
    }
}

#[allow(clippy::too_many_arguments)]
fn msm_aux_program(
    program_id: &str,
    kernel: &str,
    variant: &str,
    curve: CurveFamily,
    route: MsmRouteClass,
    stage: TransitionOperator,
    source_path: &str,
    source_paths: &[&str],
    library: &str,
    read_regions: Vec<RegionSlice>,
    write_regions: Vec<RegionSlice>,
) -> KernelProgram {
    let steps = vec![step(
        variant,
        stage.clone(),
        "curve_groups",
        &read_regions
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
        &write_regions
            .iter()
            .map(|region| region.name.as_str())
            .collect::<Vec<_>>(),
    )];
    let lowering = lowering(
        source_paths,
        "SPIR-V reflection entrypoints must match the shipped auxiliary MSM kernels exactly",
        "auxiliary MSM kernels are attested but not counted as certified family theorems",
        vec![binding(0, kernel, source_path, library, variant)],
    );
    program(
        "gpu.msm_aux_surface_attested",
        program_id,
        KernelFamily::MsmAux,
        kernel,
        variant,
        None,
        Some(curve),
        Some(route),
        ThreadIndexMap {
            global_index: match stage {
                TransitionOperator::MsmBucketCount | TransitionOperator::MsmBucketScatter => {
                    symbol("point_index")
                }
                TransitionOperator::MsmBucketAccumulate
                | TransitionOperator::MsmBucketSegmentReduce
                | TransitionOperator::MsmSortedAccumulate
                | TransitionOperator::MsmBucketReduce => symbol("bucket_index"),
                TransitionOperator::MsmWindowCombine => symbol("window_index"),
                TransitionOperator::MsmBucketAssign => symbol("point_index"),
                _ => symbol("point_index"),
            },
            lane_index: None,
            batch_index: Some(symbol("window_index")),
            guard: all_of(vec![
                ge(symbol("point_count"), c(1)),
                ge(symbol("num_windows"), c(1)),
                ge(symbol("num_buckets"), c(1)),
            ]),
        },
        msm_common_symbols(),
        read_regions,
        write_regions,
        vec![],
        vec![],
        steps,
        lowering,
        false,
    )
}

fn msm_sort_count_regions(map_name: &str) -> (Vec<RegionSlice>, Vec<RegionSlice>) {
    (
        vec![region(
            map_name,
            MemoryRegionKind::GlobalInput,
            mul(symbol("point_index"), symbol("num_windows")),
            symbol("num_windows"),
            mul(symbol("point_count"), symbol("num_windows")),
            4,
        )],
        vec![region(
            "bucket_counts",
            MemoryRegionKind::GlobalOutput,
            symbol("bucket_index"),
            c(1),
            mul(symbol("num_windows"), symbol("num_buckets")),
            4,
        )],
    )
}

fn msm_sort_scatter_regions(map_name: &str) -> (Vec<RegionSlice>, Vec<RegionSlice>) {
    (
        vec![
            region(
                map_name,
                MemoryRegionKind::GlobalInput,
                mul(symbol("point_index"), symbol("num_windows")),
                symbol("num_windows"),
                mul(symbol("point_count"), symbol("num_windows")),
                4,
            ),
            region(
                "bucket_offsets",
                MemoryRegionKind::GlobalInput,
                symbol("bucket_index"),
                c(1),
                mul(symbol("num_windows"), symbol("num_buckets")),
                4,
            ),
        ],
        vec![
            region(
                "write_cursors",
                MemoryRegionKind::GlobalOutput,
                symbol("bucket_index"),
                c(1),
                mul(symbol("num_windows"), symbol("num_buckets")),
                4,
            ),
            region(
                "sorted_indices",
                MemoryRegionKind::GlobalOutput,
                mul(symbol("point_index"), symbol("num_windows")),
                symbol("num_windows"),
                mul(symbol("point_count"), symbol("num_windows")),
                4,
            ),
        ],
    )
}

fn msm_sorted_acc_regions(route: MsmRouteClass) -> (Vec<RegionSlice>, Vec<RegionSlice>) {
    let sorted_name = if route == MsmRouteClass::Naf {
        "sorted_indices_naf"
    } else {
        "sorted_indices"
    };
    (
        vec![
            region(
                "bases_x",
                MemoryRegionKind::GlobalInput,
                mul(symbol("point_index"), symbol("base_limbs")),
                symbol("base_limbs"),
                mul(symbol("point_count"), symbol("base_limbs")),
                8,
            ),
            region(
                "bases_y",
                MemoryRegionKind::GlobalInput,
                mul(symbol("point_index"), symbol("base_limbs")),
                symbol("base_limbs"),
                mul(symbol("point_count"), symbol("base_limbs")),
                8,
            ),
            region(
                sorted_name,
                MemoryRegionKind::GlobalInput,
                mul(symbol("point_index"), symbol("num_windows")),
                symbol("num_windows"),
                mul(symbol("point_count"), symbol("num_windows")),
                4,
            ),
            region(
                "bucket_offsets",
                MemoryRegionKind::GlobalInput,
                symbol("bucket_index"),
                c(1),
                mul(symbol("num_windows"), symbol("num_buckets")),
                4,
            ),
            region(
                "bucket_counts",
                MemoryRegionKind::GlobalInput,
                symbol("bucket_index"),
                c(1),
                mul(symbol("num_windows"), symbol("num_buckets")),
                4,
            ),
        ],
        vec![region(
            "buckets",
            MemoryRegionKind::GlobalOutput,
            mul(symbol("bucket_index"), c(12)),
            c(12),
            mul(mul(symbol("num_windows"), symbol("num_buckets")), c(12)),
            8,
        )],
    )
}

fn msm_aux_manifest() -> FamilyProofManifest {
    let bn254_sources = &[
        "zkf-metal/src/shaders/msm_bn254.metal",
        "zkf-metal/src/shaders/msm_sort.metal",
        "zkf-metal/src/shaders/msm_reduce.metal",
        "zkf-metal/src/msm/mod.rs",
        "zkf-metal/src/msm/pippenger.rs",
    ];
    let pallas_sources = &[
        "zkf-metal/src/shaders/msm_pallas.metal",
        "zkf-metal/src/msm/mod.rs",
        "zkf-metal/src/msm/pallas_pippenger.rs",
    ];
    let vesta_sources = &[
        "zkf-metal/src/shaders/msm_vesta.metal",
        "zkf-metal/src/msm/mod.rs",
        "zkf-metal/src/msm/vesta_pippenger.rs",
    ];
    let (sort_count_reads, sort_count_writes) = msm_sort_count_regions("point_bucket_map");
    let (sort_scatter_reads, sort_scatter_writes) = msm_sort_scatter_regions("point_bucket_map");
    let (sort_count_naf_reads, sort_count_naf_writes) = msm_sort_count_regions("naf_map");
    let (sort_scatter_naf_reads, sort_scatter_naf_writes) = msm_sort_scatter_regions("naf_map");
    let (sorted_reads, sorted_writes) = msm_sorted_acc_regions(MsmRouteClass::Hybrid);
    let (sorted_naf_reads, sorted_naf_writes) = msm_sorted_acc_regions(MsmRouteClass::Naf);

    FamilyProofManifest {
        schema: GPU_MANIFEST_SCHEMA.to_string(),
        family: KernelFamily::MsmAux,
        claim: GPU_ATTESTED_SURFACE_CLAIM.to_string(),
        trusted_tcb: trusted_tcb(),
        programs: vec![
            msm_aux_program(
                "msm_bn254_simd_accumulate",
                "msm_bucket_acc_simd",
                "simd_accumulate",
                CurveFamily::Bn254,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_bn254.metal",
                bn254_sources,
                "bn254_msm_library",
                msm_read_regions(
                    MsmRouteClass::Classic,
                    TransitionOperator::MsmBucketAccumulate,
                ),
                msm_write_regions(TransitionOperator::MsmBucketAccumulate),
            ),
            msm_aux_program(
                "msm_bn254_sort_count",
                "msm_sort_count",
                "sort_count",
                CurveFamily::Bn254,
                MsmRouteClass::Hybrid,
                TransitionOperator::MsmBucketCount,
                "zkf-metal/src/shaders/msm_sort.metal",
                bn254_sources,
                "bn254_msm_library",
                sort_count_reads,
                sort_count_writes,
            ),
            msm_aux_program(
                "msm_bn254_sort_scatter",
                "msm_sort_scatter",
                "sort_scatter",
                CurveFamily::Bn254,
                MsmRouteClass::Hybrid,
                TransitionOperator::MsmBucketScatter,
                "zkf-metal/src/shaders/msm_sort.metal",
                bn254_sources,
                "bn254_msm_library",
                sort_scatter_reads,
                sort_scatter_writes,
            ),
            msm_aux_program(
                "msm_bn254_sorted_accumulate",
                "msm_bucket_acc_sorted",
                "sorted_accumulate",
                CurveFamily::Bn254,
                MsmRouteClass::Hybrid,
                TransitionOperator::MsmSortedAccumulate,
                "zkf-metal/src/shaders/msm_sort.metal",
                bn254_sources,
                "bn254_msm_library",
                sorted_reads,
                sorted_writes,
            ),
            msm_aux_program(
                "msm_bn254_naf_sort_count",
                "msm_sort_count_naf",
                "naf_sort_count",
                CurveFamily::Bn254,
                MsmRouteClass::Naf,
                TransitionOperator::MsmBucketCount,
                "zkf-metal/src/shaders/msm_sort.metal",
                bn254_sources,
                "bn254_msm_library",
                sort_count_naf_reads,
                sort_count_naf_writes,
            ),
            msm_aux_program(
                "msm_bn254_naf_sort_scatter",
                "msm_sort_scatter_naf",
                "naf_sort_scatter",
                CurveFamily::Bn254,
                MsmRouteClass::Naf,
                TransitionOperator::MsmBucketScatter,
                "zkf-metal/src/shaders/msm_sort.metal",
                bn254_sources,
                "bn254_msm_library",
                sort_scatter_naf_reads,
                sort_scatter_naf_writes,
            ),
            msm_aux_program(
                "msm_bn254_naf_sorted_accumulate",
                "msm_bucket_acc_sorted_naf",
                "naf_sorted_accumulate",
                CurveFamily::Bn254,
                MsmRouteClass::Naf,
                TransitionOperator::MsmSortedAccumulate,
                "zkf-metal/src/shaders/msm_sort.metal",
                bn254_sources,
                "bn254_msm_library",
                sorted_naf_reads,
                sorted_naf_writes,
            ),
            msm_aux_program(
                "msm_pallas_simd_accumulate",
                "msm_bucket_acc_simd",
                "simd_accumulate",
                CurveFamily::Pallas,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_pallas.metal",
                pallas_sources,
                "pallas_msm_library",
                msm_read_regions(
                    MsmRouteClass::Classic,
                    TransitionOperator::MsmBucketAccumulate,
                ),
                msm_write_regions(TransitionOperator::MsmBucketAccumulate),
            ),
            msm_aux_program(
                "msm_vesta_simd_accumulate",
                "msm_bucket_acc_simd",
                "simd_accumulate",
                CurveFamily::Vesta,
                MsmRouteClass::Classic,
                TransitionOperator::MsmBucketAccumulate,
                "zkf-metal/src/shaders/msm_vesta.metal",
                vesta_sources,
                "vesta_msm_library",
                msm_read_regions(
                    MsmRouteClass::Classic,
                    TransitionOperator::MsmBucketAccumulate,
                ),
                msm_write_regions(TransitionOperator::MsmBucketAccumulate),
            ),
        ],
    }
}

pub fn checked_gpu_proof_manifests() -> Vec<FamilyProofManifest> {
    vec![
        hash_manifest(),
        poseidon2_manifest(),
        ntt_manifest(),
        msm_manifest(),
        field_ops_manifest(),
        poly_manifest(),
        fri_manifest(),
        constraint_eval_manifest(),
        msm_aux_manifest(),
    ]
}

fn lean_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sanitize_lean_ident(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

fn lean_kernel_family(value: KernelFamily) -> &'static str {
    match value {
        KernelFamily::Hash => "KernelFamily.hash",
        KernelFamily::Poseidon2 => "KernelFamily.poseidon2",
        KernelFamily::Ntt => "KernelFamily.ntt",
        KernelFamily::Msm => "KernelFamily.msm",
        KernelFamily::FieldOps => "KernelFamily.fieldOps",
        KernelFamily::Poly => "KernelFamily.poly",
        KernelFamily::Fri => "KernelFamily.fri",
        KernelFamily::ConstraintEval => "KernelFamily.constraintEval",
        KernelFamily::MsmAux => "KernelFamily.msmAux",
    }
}

fn lean_field_family(value: FieldFamily) -> &'static str {
    match value {
        FieldFamily::Bytes => "FieldFamily.bytes",
        FieldFamily::Goldilocks => "FieldFamily.goldilocks",
        FieldFamily::BabyBear => "FieldFamily.babyBear",
        FieldFamily::Bn254Scalar => "FieldFamily.bn254Scalar",
        FieldFamily::PallasScalar => "FieldFamily.pallasScalar",
        FieldFamily::VestaScalar => "FieldFamily.vestaScalar",
    }
}

fn lean_curve_family(value: CurveFamily) -> &'static str {
    match value {
        CurveFamily::Bn254 => "CurveFamily.bn254",
        CurveFamily::Pallas => "CurveFamily.pallas",
        CurveFamily::Vesta => "CurveFamily.vesta",
    }
}

fn lean_msm_route(value: MsmRouteClass) -> &'static str {
    match value {
        MsmRouteClass::Classic => "MsmRoute.classic",
        MsmRouteClass::Naf => "MsmRoute.naf",
        MsmRouteClass::Hybrid => "MsmRoute.hybrid",
        MsmRouteClass::FullGpu => "MsmRoute.fullGpu",
        MsmRouteClass::Tensor => "MsmRoute.tensor",
    }
}

fn lean_memory_region_kind(value: &MemoryRegionKind) -> &'static str {
    match value {
        MemoryRegionKind::GlobalInput => "MemoryRegionKind.globalInput",
        MemoryRegionKind::GlobalOutput => "MemoryRegionKind.globalOutput",
        MemoryRegionKind::Shared => "MemoryRegionKind.shared",
        MemoryRegionKind::Constant => "MemoryRegionKind.constant",
        MemoryRegionKind::Scratch => "MemoryRegionKind.scratch",
    }
}

fn lean_transition_operator(value: &TransitionOperator) -> &'static str {
    match value {
        TransitionOperator::Sha256MessageSchedule => "TransitionOperator.sha256MessageSchedule",
        TransitionOperator::Sha256CompressionRound => "TransitionOperator.sha256CompressionRound",
        TransitionOperator::KeccakTheta => "TransitionOperator.keccakTheta",
        TransitionOperator::KeccakRhoPi => "TransitionOperator.keccakRhoPi",
        TransitionOperator::KeccakChiIota => "TransitionOperator.keccakChiIota",
        TransitionOperator::Poseidon2ExternalRound => "TransitionOperator.poseidon2ExternalRound",
        TransitionOperator::Poseidon2MatrixLayer => "TransitionOperator.poseidon2MatrixLayer",
        TransitionOperator::Poseidon2SBox => "TransitionOperator.poseidon2SBox",
        TransitionOperator::Poseidon2InternalRound => "TransitionOperator.poseidon2InternalRound",
        TransitionOperator::FieldAdd => "TransitionOperator.fieldAdd",
        TransitionOperator::FieldSub => "TransitionOperator.fieldSub",
        TransitionOperator::FieldMul => "TransitionOperator.fieldMul",
        TransitionOperator::FieldInvPrefix => "TransitionOperator.fieldInvPrefix",
        TransitionOperator::FieldInvBackprop => "TransitionOperator.fieldInvBackprop",
        TransitionOperator::NttBitReverse => "TransitionOperator.nttBitReverse",
        TransitionOperator::NttButterflyStage => "TransitionOperator.nttButterflyStage",
        TransitionOperator::NttSmallTransform => "TransitionOperator.nttSmallTransform",
        TransitionOperator::NttHybridStage => "TransitionOperator.nttHybridStage",
        TransitionOperator::PolyEval => "TransitionOperator.polyEval",
        TransitionOperator::PolyBatchEval => "TransitionOperator.polyBatchEval",
        TransitionOperator::PolyQuotient => "TransitionOperator.polyQuotient",
        TransitionOperator::PolyCosetShift => "TransitionOperator.polyCosetShift",
        TransitionOperator::FriFold => "TransitionOperator.friFold",
        TransitionOperator::ConstraintEval => "TransitionOperator.constraintEval",
        TransitionOperator::MsmBucketAssign => "TransitionOperator.msmBucketAssign",
        TransitionOperator::MsmBucketAccumulate => "TransitionOperator.msmBucketAccumulate",
        TransitionOperator::MsmBucketSegmentReduce => "TransitionOperator.msmBucketSegmentReduce",
        TransitionOperator::MsmBucketReduce => "TransitionOperator.msmBucketReduce",
        TransitionOperator::MsmWindowCombine => "TransitionOperator.msmWindowCombine",
        TransitionOperator::MsmBucketCount => "TransitionOperator.msmBucketCount",
        TransitionOperator::MsmBucketScatter => "TransitionOperator.msmBucketScatter",
        TransitionOperator::MsmSortedAccumulate => "TransitionOperator.msmSortedAccumulate",
        TransitionOperator::LayoutWriteback => "TransitionOperator.layoutWriteback",
    }
}

fn lean_numeric_expr(expr: &NumericExpr) -> String {
    match expr {
        NumericExpr::NatConst(value) => format!("NumericExpr.natConst {}", value),
        NumericExpr::Symbol(name) => format!("NumericExpr.symbol \"{}\"", lean_escape(name)),
        NumericExpr::Add(lhs, rhs) => {
            format!(
                "NumericExpr.add ({}) ({})",
                lean_numeric_expr(lhs),
                lean_numeric_expr(rhs)
            )
        }
        NumericExpr::Sub(lhs, rhs) => {
            format!(
                "NumericExpr.sub ({}) ({})",
                lean_numeric_expr(lhs),
                lean_numeric_expr(rhs)
            )
        }
        NumericExpr::Mul(lhs, rhs) => {
            format!(
                "NumericExpr.mul ({}) ({})",
                lean_numeric_expr(lhs),
                lean_numeric_expr(rhs)
            )
        }
        NumericExpr::DivCeil(lhs, rhs) => format!(
            "NumericExpr.divCeil ({}) ({})",
            lean_numeric_expr(lhs),
            lean_numeric_expr(rhs)
        ),
        NumericExpr::ModNat(lhs, rhs) => format!(
            "NumericExpr.modNat ({}) ({})",
            lean_numeric_expr(lhs),
            lean_numeric_expr(rhs)
        ),
    }
}

fn lean_boolean_expr(expr: &BooleanExpr) -> String {
    match expr {
        BooleanExpr::Truth => "BooleanExpr.truth".to_string(),
        BooleanExpr::EqExpr(lhs, rhs) => {
            format!(
                "BooleanExpr.eqExpr ({}) ({})",
                lean_numeric_expr(lhs),
                lean_numeric_expr(rhs)
            )
        }
        BooleanExpr::GeExpr(lhs, rhs) => {
            format!(
                "BooleanExpr.geExpr ({}) ({})",
                lean_numeric_expr(lhs),
                lean_numeric_expr(rhs)
            )
        }
        BooleanExpr::LeExpr(lhs, rhs) => {
            format!(
                "BooleanExpr.leExpr ({}) ({})",
                lean_numeric_expr(lhs),
                lean_numeric_expr(rhs)
            )
        }
        BooleanExpr::IsPowerOfTwo(value) => {
            format!("BooleanExpr.isPowerOfTwo ({})", lean_numeric_expr(value))
        }
        BooleanExpr::IsMultipleOf(value, divisor) => {
            format!(
                "BooleanExpr.isMultipleOf ({}) {}",
                lean_numeric_expr(value),
                divisor
            )
        }
        BooleanExpr::AllOf(clauses) => {
            let items = clauses.iter().map(lean_boolean_expr).collect::<Vec<_>>();
            format!("BooleanExpr.allOf [{}]", items.join(", "))
        }
    }
}

fn lean_symbol_domain(domain: &SymbolDomain) -> String {
    format!(
        "{{ name := \"{}\", minValue := {}, maxValue := {}, nonZero := {}, powerOfTwo := {}, multipleOf := {} }}",
        lean_escape(&domain.name),
        domain.min_value,
        lean_option_nat(domain.max_value),
        if domain.non_zero { "true" } else { "false" },
        if domain.power_of_two { "true" } else { "false" },
        lean_option_nat(domain.multiple_of)
    )
}

fn lean_thread_index_map(index_map: &ThreadIndexMap) -> String {
    format!(
        "{{ globalIndex := {}, laneIndex := {}, batchIndex := {}, guard := {} }}",
        lean_numeric_expr(&index_map.global_index),
        lean_option_numeric(index_map.lane_index.as_ref()),
        lean_option_numeric(index_map.batch_index.as_ref()),
        lean_boolean_expr(&index_map.guard)
    )
}

fn lean_region(region: &RegionSlice) -> String {
    format!(
        "{{ name := \"{}\", kind := {}, start := {}, len := {}, bound := {}, elementBytes := {} }}",
        lean_escape(&region.name),
        lean_memory_region_kind(&region.kind),
        lean_numeric_expr(&region.start),
        lean_numeric_expr(&region.len),
        lean_numeric_expr(&region.bound),
        region.element_bytes
    )
}

fn lean_step(step: &KernelStep) -> String {
    format!(
        "{{ name := \"{}\", operator := {}, arithmeticDomain := \"{}\", reads := [{}], writes := [{}] }}",
        lean_escape(&step.name),
        lean_transition_operator(&step.operator),
        lean_escape(&step.arithmetic_domain),
        step.reads
            .iter()
            .map(|value| format!("\"{}\"", lean_escape(value)))
            .collect::<Vec<_>>()
            .join(", "),
        step.writes
            .iter()
            .map(|value| format!("\"{}\"", lean_escape(value)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn lean_barrier(barrier: &BarrierPoint) -> String {
    format!(
        "{{ afterStep := {}, scope := \"{}\" }}",
        barrier.after_step,
        lean_escape(&barrier.scope)
    )
}

fn lean_binding(binding: &LoweringBinding) -> String {
    format!(
        "{{ stepIndex := {}, entrypoint := \"{}\", sourcePath := \"{}\", library := \"{}\", bindingKind := \"{}\" }}",
        binding.step_index,
        lean_escape(&binding.entrypoint),
        lean_escape(&binding.source_path),
        lean_escape(&binding.library),
        lean_escape(&binding.binding_kind)
    )
}

fn lean_attestation(argument: &ExpectedKernelAttestation) -> String {
    let args = argument
        .arguments
        .iter()
        .map(|arg| {
            format!(
                "{{ name := \"{}\", index := {}, kind := \"{}\", access := \"{}\" }}",
                lean_escape(&arg.name),
                arg.index,
                lean_escape(match arg.kind {
                    crate::verified_artifacts::ExpectedArgumentKind::Buffer => "buffer",
                    crate::verified_artifacts::ExpectedArgumentKind::ThreadgroupMemory => {
                        "threadgroup_memory"
                    }
                }),
                lean_escape(match arg.access {
                    crate::verified_artifacts::ExpectedBindingAccess::ReadOnly => "read_only",
                    crate::verified_artifacts::ExpectedBindingAccess::ReadWrite => "read_write",
                    crate::verified_artifacts::ExpectedBindingAccess::WriteOnly => "write_only",
                })
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ libraryId := \"{}\", entrypoint := \"{}\", metallibSha256 := \"{}\", reflectionSha256 := \"{}\", pipelineDescriptorSha256 := \"{}\", arguments := [{}] }}",
        lean_escape(&argument.library_id),
        lean_escape(&argument.entrypoint),
        lean_escape(&argument.metallib_sha256),
        lean_escape(&argument.reflection_sha256),
        lean_escape(&argument.pipeline_descriptor_sha256),
        args
    )
}

fn lean_lowering(lowering: &LoweringCertificate) -> String {
    let source_sha256 = lowering
        .source_sha256
        .iter()
        .map(|(path, digest)| format!("(\"{}\", \"{}\")", lean_escape(path), lean_escape(digest)))
        .collect::<Vec<_>>()
        .join(", ");
    let source_paths = lowering
        .source_paths
        .iter()
        .map(|path| format!("\"{}\"", lean_escape(path)))
        .collect::<Vec<_>>()
        .join(", ");
    let entrypoints = lowering
        .entrypoints
        .iter()
        .map(|entrypoint| format!("\"{}\"", lean_escape(entrypoint)))
        .collect::<Vec<_>>()
        .join(", ");
    let step_bindings = lowering
        .step_bindings
        .iter()
        .map(lean_binding)
        .collect::<Vec<_>>()
        .join(", ");
    let entrypoint_attestations = lowering
        .entrypoint_attestations
        .iter()
        .map(lean_attestation)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ sourceSha256 := [{}], sourcePaths := [{}], entrypoints := [{}], toolchainCompiler := \"{}\", toolchainXcode := \"{}\", toolchainSdk := \"{}\", entrypointAttestations := [{}], reflectionPolicy := \"{}\", workgroupPolicy := \"{}\", stepBindings := [{}] }}",
        source_sha256,
        source_paths,
        entrypoints,
        lean_escape(&lowering.toolchain.metal_compiler_version),
        lean_escape(&lowering.toolchain.xcode_version),
        lean_escape(&lowering.toolchain.sdk_version),
        entrypoint_attestations,
        lean_escape(&lowering.reflection_policy),
        lean_escape(&lowering.workgroup_policy),
        step_bindings
    )
}

fn lean_option_nat(value: Option<usize>) -> String {
    match value {
        Some(value) => format!("some {}", value),
        None => "none".to_string(),
    }
}

fn lean_option_numeric(value: Option<&NumericExpr>) -> String {
    match value {
        Some(value) => format!("some ({})", lean_numeric_expr(value)),
        None => "none".to_string(),
    }
}

fn lean_option_field(value: Option<FieldFamily>) -> String {
    match value {
        Some(value) => format!("some {}", lean_field_family(value)),
        None => "none".to_string(),
    }
}

fn lean_option_curve(value: Option<CurveFamily>) -> String {
    match value {
        Some(value) => format!("some {}", lean_curve_family(value)),
        None => "none".to_string(),
    }
}

fn lean_option_route(value: Option<MsmRouteClass>) -> String {
    match value {
        Some(value) => format!("some {}", lean_msm_route(value)),
        None => "none".to_string(),
    }
}

fn write_generated_lean_module(
    output_dir: &Path,
    manifests: &[FamilyProofManifest],
) -> std::io::Result<()> {
    let generated_dir = output_dir.join("Generated");
    fs::create_dir_all(&generated_dir)?;
    let mut out = String::new();
    out.push_str("namespace ");
    out.push_str(GENERATED_LEAN_NAMESPACE);
    out.push_str("\n\n");
    out.push_str("inductive KernelFamily where\n");
    out.push_str(
        "  | hash\n  | poseidon2\n  | ntt\n  | msm\n  | fieldOps\n  | poly\n  | fri\n  | constraintEval\n  | msmAux\n",
    );
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive FieldFamily where\n");
    out.push_str("  | bytes\n  | goldilocks\n  | babyBear\n  | bn254Scalar\n  | pallasScalar\n  | vestaScalar\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive CurveFamily where\n");
    out.push_str("  | bn254\n  | pallas\n  | vesta\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive MsmRoute where\n");
    out.push_str("  | classic\n  | naf\n  | hybrid\n  | fullGpu\n  | tensor\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive NumericExpr where\n");
    out.push_str("  | natConst (value : Nat)\n");
    out.push_str("  | symbol (name : String)\n");
    out.push_str("  | add (lhs rhs : NumericExpr)\n");
    out.push_str("  | sub (lhs rhs : NumericExpr)\n");
    out.push_str("  | mul (lhs rhs : NumericExpr)\n");
    out.push_str("  | divCeil (lhs rhs : NumericExpr)\n");
    out.push_str("  | modNat (lhs rhs : NumericExpr)\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive BooleanExpr where\n");
    out.push_str("  | truth\n");
    out.push_str("  | eqExpr (lhs rhs : NumericExpr)\n");
    out.push_str("  | geExpr (lhs rhs : NumericExpr)\n");
    out.push_str("  | leExpr (lhs rhs : NumericExpr)\n");
    out.push_str("  | isPowerOfTwo (value : NumericExpr)\n");
    out.push_str("  | isMultipleOf (value : NumericExpr) (divisor : Nat)\n");
    out.push_str("  | allOf (clauses : List BooleanExpr)\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure SymbolDomain where\n");
    out.push_str("  name : String\n");
    out.push_str("  minValue : Nat\n");
    out.push_str("  maxValue : Option Nat\n");
    out.push_str("  nonZero : Bool\n");
    out.push_str("  powerOfTwo : Bool\n");
    out.push_str("  multipleOf : Option Nat\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure ThreadIndexMap where\n");
    out.push_str("  globalIndex : NumericExpr\n");
    out.push_str("  laneIndex : Option NumericExpr\n");
    out.push_str("  batchIndex : Option NumericExpr\n");
    out.push_str("  guard : BooleanExpr\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive MemoryRegionKind where\n");
    out.push_str("  | globalInput\n  | globalOutput\n  | shared\n  | constant\n  | scratch\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure RegionSlice where\n");
    out.push_str("  name : String\n");
    out.push_str("  kind : MemoryRegionKind\n");
    out.push_str("  start : NumericExpr\n");
    out.push_str("  len : NumericExpr\n");
    out.push_str("  bound : NumericExpr\n");
    out.push_str("  elementBytes : Nat\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("inductive TransitionOperator where\n");
    out.push_str("  | sha256MessageSchedule\n");
    out.push_str("  | sha256CompressionRound\n");
    out.push_str("  | keccakTheta\n");
    out.push_str("  | keccakRhoPi\n");
    out.push_str("  | keccakChiIota\n");
    out.push_str("  | poseidon2ExternalRound\n");
    out.push_str("  | poseidon2MatrixLayer\n");
    out.push_str("  | poseidon2SBox\n");
    out.push_str("  | poseidon2InternalRound\n");
    out.push_str("  | fieldAdd\n");
    out.push_str("  | fieldSub\n");
    out.push_str("  | fieldMul\n");
    out.push_str("  | fieldInvPrefix\n");
    out.push_str("  | fieldInvBackprop\n");
    out.push_str("  | nttBitReverse\n");
    out.push_str("  | nttButterflyStage\n");
    out.push_str("  | nttSmallTransform\n");
    out.push_str("  | nttHybridStage\n");
    out.push_str("  | polyEval\n");
    out.push_str("  | polyBatchEval\n");
    out.push_str("  | polyQuotient\n");
    out.push_str("  | polyCosetShift\n");
    out.push_str("  | friFold\n");
    out.push_str("  | constraintEval\n");
    out.push_str("  | msmBucketAssign\n");
    out.push_str("  | msmBucketAccumulate\n");
    out.push_str("  | msmBucketReduce\n");
    out.push_str("  | msmWindowCombine\n");
    out.push_str("  | msmBucketCount\n");
    out.push_str("  | msmBucketScatter\n");
    out.push_str("  | msmSortedAccumulate\n");
    out.push_str("  | layoutWriteback\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure KernelStep where\n");
    out.push_str("  name : String\n");
    out.push_str("  operator : TransitionOperator\n");
    out.push_str("  arithmeticDomain : String\n");
    out.push_str("  reads : List String\n");
    out.push_str("  writes : List String\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure BarrierPoint where\n");
    out.push_str("  afterStep : Nat\n");
    out.push_str("  scope : String\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure LoweringBinding where\n");
    out.push_str("  stepIndex : Nat\n");
    out.push_str("  entrypoint : String\n");
    out.push_str("  sourcePath : String\n");
    out.push_str("  library : String\n");
    out.push_str("  bindingKind : String\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure ExpectedArgument where\n");
    out.push_str("  name : String\n");
    out.push_str("  index : Nat\n");
    out.push_str("  kind : String\n");
    out.push_str("  access : String\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure KernelAttestation where\n");
    out.push_str("  libraryId : String\n");
    out.push_str("  entrypoint : String\n");
    out.push_str("  metallibSha256 : String\n");
    out.push_str("  reflectionSha256 : String\n");
    out.push_str("  pipelineDescriptorSha256 : String\n");
    out.push_str("  arguments : List ExpectedArgument\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure LoweringCertificate where\n");
    out.push_str("  sourceSha256 : List (String × String)\n");
    out.push_str("  sourcePaths : List String\n");
    out.push_str("  entrypoints : List String\n");
    out.push_str("  toolchainCompiler : String\n");
    out.push_str("  toolchainXcode : String\n");
    out.push_str("  toolchainSdk : String\n");
    out.push_str("  entrypointAttestations : List KernelAttestation\n");
    out.push_str("  reflectionPolicy : String\n");
    out.push_str("  workgroupPolicy : String\n");
    out.push_str("  stepBindings : List LoweringBinding\n");
    out.push_str("deriving Repr\n\n");
    out.push_str("structure GeneratedProgram where\n");
    out.push_str("  theoremId : String\n");
    out.push_str("  programId : String\n");
    out.push_str("  family : KernelFamily\n");
    out.push_str("  kernel : String\n");
    out.push_str("  variant : String\n");
    out.push_str("  field : Option FieldFamily\n");
    out.push_str("  curve : Option CurveFamily\n");
    out.push_str("  route : Option MsmRoute\n");
    out.push_str("  indexMap : ThreadIndexMap\n");
    out.push_str("  symbols : List SymbolDomain\n");
    out.push_str("  readRegions : List RegionSlice\n");
    out.push_str("  writeRegions : List RegionSlice\n");
    out.push_str("  sharedRegions : List RegionSlice\n");
    out.push_str("  barriers : List BarrierPoint\n");
    out.push_str("  steps : List KernelStep\n");
    out.push_str("  lowering : LoweringCertificate\n");
    out.push_str("  certifiedClaim : Bool\n");
    out.push_str("deriving Repr\n\n");

    let mut family_lists: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for manifest in manifests {
        let family_name = match manifest.family {
            KernelFamily::Hash => "hashPrograms",
            KernelFamily::Poseidon2 => "poseidon2Programs",
            KernelFamily::Ntt => "nttPrograms",
            KernelFamily::Msm => "msmPrograms",
            KernelFamily::FieldOps => "fieldOpsPrograms",
            KernelFamily::Poly => "polyPrograms",
            KernelFamily::Fri => "friPrograms",
            KernelFamily::ConstraintEval => "constraintEvalPrograms",
            KernelFamily::MsmAux => "msmAuxPrograms",
        };
        let defs = family_lists.entry(family_name).or_default();
        for program in &manifest.programs {
            let def_name = sanitize_lean_ident(&program.program_id);
            defs.push(def_name.clone());
            out.push_str(&format!("def {} : GeneratedProgram :=\n", def_name));
            out.push_str("  {\n");
            out.push_str(&format!(
                "    theoremId := \"{}\"\n",
                lean_escape(&program.theorem_id)
            ));
            out.push_str(&format!(
                "    programId := \"{}\"\n",
                lean_escape(&program.program_id)
            ));
            out.push_str(&format!(
                "    family := {}\n",
                lean_kernel_family(program.family)
            ));
            out.push_str(&format!(
                "    kernel := \"{}\"\n",
                lean_escape(&program.kernel)
            ));
            out.push_str(&format!(
                "    variant := \"{}\"\n",
                lean_escape(&program.variant)
            ));
            out.push_str(&format!(
                "    field := {}\n",
                lean_option_field(program.field)
            ));
            out.push_str(&format!(
                "    curve := {}\n",
                lean_option_curve(program.curve)
            ));
            out.push_str(&format!(
                "    route := {}\n",
                lean_option_route(program.route)
            ));
            out.push_str(&format!(
                "    indexMap := {}\n",
                lean_thread_index_map(&program.index_map)
            ));
            out.push_str(&format!(
                "    symbols := [{}]\n",
                program
                    .symbols
                    .iter()
                    .map(lean_symbol_domain)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.push_str(&format!(
                "    readRegions := [{}]\n",
                program
                    .read_regions
                    .iter()
                    .map(lean_region)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.push_str(&format!(
                "    writeRegions := [{}]\n",
                program
                    .write_regions
                    .iter()
                    .map(lean_region)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.push_str(&format!(
                "    sharedRegions := [{}]\n",
                program
                    .shared_regions
                    .iter()
                    .map(lean_region)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.push_str(&format!(
                "    barriers := [{}]\n",
                program
                    .barriers
                    .iter()
                    .map(lean_barrier)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.push_str(&format!(
                "    steps := [{}]\n",
                program
                    .steps
                    .iter()
                    .map(lean_step)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.push_str(&format!(
                "    lowering := {}\n",
                lean_lowering(&program.lowering)
            ));
            out.push_str(&format!(
                "    certifiedClaim := {}\n",
                if program.certified_claim {
                    "true"
                } else {
                    "false"
                }
            ));
            out.push_str("  }\n\n");
        }
    }

    for family_name in [
        "hashPrograms",
        "poseidon2Programs",
        "nttPrograms",
        "msmPrograms",
        "fieldOpsPrograms",
        "polyPrograms",
        "friPrograms",
        "constraintEvalPrograms",
        "msmAuxPrograms",
    ] {
        let defs = family_lists.get(family_name).cloned().unwrap_or_default();
        out.push_str(&format!(
            "def {} : List GeneratedProgram := [{}]\n\n",
            family_name,
            defs.join(", ")
        ));
    }

    let all_programs = family_lists
        .values()
        .flatten()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "def allPrograms : List GeneratedProgram := [{}]\n\n",
        all_programs
    ));
    out.push_str("end ");
    out.push_str(GENERATED_LEAN_NAMESPACE);
    out.push('\n');
    fs::write(generated_dir.join("GpuPrograms.lean"), out)
}

pub fn export_checked_gpu_proof_artifacts(
    manifest_dir: &Path,
    lean_dir: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(manifest_dir)?;
    let manifests = checked_gpu_proof_manifests();
    for manifest in &manifests {
        let file_name = match manifest.family {
            KernelFamily::Hash => "hash.json",
            KernelFamily::Poseidon2 => "poseidon2.json",
            KernelFamily::Ntt => "ntt.json",
            KernelFamily::Msm => "msm.json",
            KernelFamily::FieldOps => "field_ops.json",
            KernelFamily::Poly => "poly.json",
            KernelFamily::Fri => "fri.json",
            KernelFamily::ConstraintEval => "constraint_eval.json",
            KernelFamily::MsmAux => "msm_aux.json",
        };
        fs::write(
            manifest_dir.join(file_name),
            serde_json::to_string_pretty(manifest).expect("manifest json"),
        )?;
    }
    write_generated_lean_module(lean_dir, &manifests)?;
    Ok(())
}
