// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

/// STARK-to-Groth16 wrapping: Plonky3 STARK proof → Arkworks Groth16 SNARK proof.
///
/// This module implements the full wrapping pipeline:
///
/// 1. Deserialize the Plonky3 STARK proof bytes using the exact type aliases.
/// 2. Extract FRI commitments, query openings, and Merkle paths from the proof.
/// 3. Build a `StarkProofWitness` from the real proof data.
/// 4. Construct a `FriVerifierCircuit` parametrized by the proof.
/// 5. Run Groth16 circuit-specific setup (cached by program digest).
/// 6. Generate a Groth16 proof of the FRI verification.
/// 7. Serialize and return a wrapped `ProofArtifact` with status "wrapped-v2".
///
/// The Groth16 proof can subsequently be verified with `verify_wrapped()`.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use once_cell::sync::Lazy;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeField64, TwoAdicField};
use p3_fri::TwoAdicFriPcs;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{Proof as StarkProof, StarkConfig};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::arkworks::{
    Groth16ProveShape, append_groth16_metal_metadata, build_groth16_prove_shape_to_path,
    create_local_groth16_proof, create_local_groth16_proof_with_cached_shape,
    create_local_groth16_setup_with_shape_path, load_streamed_groth16_prove_shape,
    streamed_groth16_shape_file_is_ready,
};
use crate::metal_runtime::{
    append_backend_runtime_metadata, append_default_metal_telemetry, copy_standard_metal_metadata,
};
use crate::{BoundedStringCache, bounded_cache_limit};
use zkf_core::wrapping::{
    ProofWrapper, WrapModeOverride, WrapperCachePrepareReport, WrapperExecutionPolicy,
    WrapperPreview,
};
use zkf_core::{
    BackendKind, CompiledProgram, PressureLevel, ProofArtifact, SystemResources, ZkfError,
    ZkfResult,
};

#[cfg(feature = "nova-compression")]
use super::fri_query_step::FriQueryWitness as NovaQueryWitness;
use super::fri_verifier_circuit::{
    FriCircuitParams, FriQueryWitness, FriVerifierCircuit, StarkProofWitness,
};
#[cfg(feature = "nova-compression")]
use super::nova_stark_compress::{
    CompressedStarkProof, NovaStarkCompressor, verify_compressed_stark_proof,
};
#[cfg(feature = "nova-compression")]
use super::nova_verifier_circuit::{NovaVerifierCircuit, public_inputs_for_compressed_proof};

// ---------------------------------------------------------------------------
// Plonky3 type aliases (must match plonky3.rs exactly for deserialization)
// ---------------------------------------------------------------------------

type GoldilocksHash = PaddingFreeSponge<Poseidon2Goldilocks<16>, 16, 8, 8>;
type GoldilocksCompress = TruncatedPermutation<Poseidon2Goldilocks<16>, 2, 8, 16>;
type GoldilocksValMmcs = MerkleTreeMmcs<
    <Goldilocks as Field>::Packing,
    <Goldilocks as Field>::Packing,
    GoldilocksHash,
    GoldilocksCompress,
    8,
>;
const ATOMIC_TEMP_STALE_AGE: Duration = Duration::from_secs(24 * 60 * 60);
type GoldilocksChallengeMmcs = ExtensionMmcs<Goldilocks, Goldilocks, GoldilocksValMmcs>;
type GoldilocksDft = Radix2DitParallel<Goldilocks>;
type GoldilocksPcs =
    TwoAdicFriPcs<Goldilocks, GoldilocksDft, GoldilocksValMmcs, GoldilocksChallengeMmcs>;
type GoldilocksChallenger =
    p3_challenger::DuplexChallenger<Goldilocks, Poseidon2Goldilocks<16>, 16, 8>;
type GoldilocksConfig = StarkConfig<GoldilocksPcs, Goldilocks, GoldilocksChallenger>;
type GoldilocksStarkProof = StarkProof<GoldilocksConfig>;

// ---------------------------------------------------------------------------
// Setup cache
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CachedSetup {
    pk: Arc<ProvingKey<Bn254>>,
    vk_bytes: Arc<Vec<u8>>,
    prove_shape: Option<Arc<Groth16ProveShape>>,
    pk_cache_format: &'static str,
    pk_cache_migrated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperCacheBundleFile {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperCacheBundleFiles {
    pub proving_key: WrapperCacheBundleFile,
    pub verifying_key: WrapperCacheBundleFile,
    pub prove_shape: WrapperCacheBundleFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperCacheBundleManifest {
    pub bundle_schema: String,
    pub wrapper: String,
    pub source_backend: BackendKind,
    pub target_backend: BackendKind,
    pub strategy: String,
    pub trust_model: String,
    pub cache_key: String,
    pub cache_state: String,
    pub source_program_digest: String,
    pub compiled_program_digest: String,
    pub hardware_profile: String,
    pub setup_cache_pk_format: String,
    pub shape_cache_ready: bool,
    pub files: WrapperCacheBundleFiles,
}

#[derive(Debug, Clone)]
struct DirectWrapCacheBundleExpectation {
    wrapper: String,
    source_backend: BackendKind,
    target_backend: BackendKind,
    strategy: String,
    trust_model: String,
    cache_key: String,
    source_program_digest: String,
    compiled_program_digest: String,
}

static SETUP_CACHE: Lazy<Mutex<BoundedStringCache<CachedSetup>>> = Lazy::new(|| {
    Mutex::new(BoundedStringCache::new(bounded_cache_limit(
        "ZKF_STARK_WRAP_SETUP_CACHE_LIMIT",
        1,
    )))
});
static WRAPPED_ARTIFACT_CACHE: Lazy<Mutex<BoundedStringCache<ProofArtifact>>> = Lazy::new(|| {
    Mutex::new(BoundedStringCache::new(bounded_cache_limit(
        "ZKF_STARK_WRAP_ARTIFACT_CACHE_LIMIT",
        2,
    )))
});

#[cfg(test)]
pub(crate) fn clear_test_caches() {
    if let Ok(mut cache) = SETUP_CACHE.lock() {
        cache.clear();
    }
    if let Ok(mut cache) = WRAPPED_ARTIFACT_CACHE.lock() {
        cache.clear();
    }
}

const DIRECT_WRAP_COMPLEXITY_UNIT: u64 = 50_000;
const DIRECT_WRAP_BYTES_PER_CONSTRAINT: u64 = 896;
const DIRECT_WRAP_PREP_REQUIRED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const DIRECT_WRAP_PREP_OVERRIDE_FLAG: &str = "--allow-large-direct-materialization";
const SETUP_PK_CACHE_MAGIC: &[u8; 8] = b"ZKFPK02\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WrapStrategy {
    DirectFriV2,
    #[allow(dead_code)]
    NovaCompressedV3,
}

impl WrapStrategy {
    fn as_str(self) -> &'static str {
        match self {
            Self::DirectFriV2 => "direct-fri-v2",
            Self::NovaCompressedV3 => "nova-compressed-v3",
        }
    }

    fn trust_model(self) -> &'static str {
        match self {
            Self::DirectFriV2 => "cryptographic",
            Self::NovaCompressedV3 => "attestation",
        }
    }

    fn trust_model_description(self) -> &'static str {
        match self {
            Self::DirectFriV2 => "full FRI verifier circuit is enforced inside the Groth16 wrapper",
            Self::NovaCompressedV3 => {
                "Groth16 binds a host-verified compressed Nova accumulator; FRI Merkle authentication remains off-circuit"
            }
        }
    }
}

#[derive(Debug, Clone)]
struct WrapPlan {
    strategy: WrapStrategy,
    estimated_constraints: u64,
    estimated_memory_bytes: u64,
    memory_budget_bytes: Option<u64>,
    low_memory_mode: bool,
    reason: String,
}

// ---------------------------------------------------------------------------
// Wrapper struct
// ---------------------------------------------------------------------------

/// Wraps a Plonky3 STARK proof inside a Groth16 SNARK proof.
pub struct StarkToGroth16Wrapper;

#[derive(Debug, Clone, Serialize)]
pub struct WrapBenchmarkReport {
    pub warm_cache: bool,
    pub parallelism: usize,
    pub wall_clock_ms: f64,
    pub mean_wrap_ms: f64,
    pub proof_engine: String,
    pub proof_semantics: String,
    pub prover_acceleration_scope: String,
    pub gpu_stage_coverage: String,
    pub metal_complete: bool,
    pub cpu_math_fallback_reason: String,
    pub export_scheme: String,
    pub metal_gpu_busy_ratio: f64,
    pub metal_stage_breakdown: String,
    pub metal_inflight_jobs: usize,
    pub metal_no_cpu_fallback: bool,
    pub metal_counter_source: String,
    pub metal_dispatch_circuit_open: bool,
    pub metal_dispatch_last_failure: String,
}

pub fn benchmark_cached_wrap_batch(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    parallelism: usize,
) -> ZkfResult<WrapBenchmarkReport> {
    let parallelism = parallelism.max(1);
    let wrapper = StarkToGroth16Wrapper;

    // Warm the setup cache so the benchmark isolates repeated wrap/prove work
    // instead of first-run key generation.
    wrapper.wrap_uncached(source_proof, source_compiled)?;

    let batch_start = Instant::now();
    let wrapped_artifacts = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(parallelism);
        for _ in 0..parallelism {
            handles.push(scope.spawn(|| wrapper.wrap_uncached(source_proof, source_compiled)));
        }
        let mut wrapped = Vec::with_capacity(parallelism);
        for handle in handles {
            wrapped.push(
                handle
                    .join()
                    .expect("cached wrap benchmark worker panicked")?,
            );
        }
        Ok::<_, ZkfError>(wrapped)
    })?;
    let wall_clock_ms = batch_start.elapsed().as_secs_f64() * 1_000.0;
    let sample = wrapped_artifacts.first().ok_or_else(|| {
        ZkfError::Backend("cached wrap benchmark produced no artifacts".to_string())
    })?;

    Ok(WrapBenchmarkReport {
        warm_cache: true,
        parallelism,
        wall_clock_ms,
        mean_wrap_ms: wall_clock_ms / parallelism as f64,
        proof_engine: sample
            .metadata
            .get("proof_engine")
            .cloned()
            .unwrap_or_else(|| "stark-export-wrapper".to_string()),
        proof_semantics: sample
            .metadata
            .get("proof_semantics")
            .cloned()
            .unwrap_or_else(|| "wrapped-fri-verifier-circuit".to_string()),
        prover_acceleration_scope: sample
            .metadata
            .get("prover_acceleration_scope")
            .cloned()
            .unwrap_or_else(|| "target-groth16-prover-only".to_string()),
        gpu_stage_coverage: sample
            .metadata
            .get("gpu_stage_coverage")
            .cloned()
            .unwrap_or_else(|| "{}".to_string()),
        metal_complete: parse_metadata_bool(&sample.metadata, "metal_complete").unwrap_or(false),
        cpu_math_fallback_reason: sample
            .metadata
            .get("cpu_math_fallback_reason")
            .cloned()
            .unwrap_or_else(|| "export-wrapper-not-primary-engine".to_string()),
        export_scheme: sample
            .metadata
            .get("export_scheme")
            .cloned()
            .unwrap_or_else(|| "groth16".to_string()),
        metal_gpu_busy_ratio: parse_metadata_f64(&sample.metadata, "metal_gpu_busy_ratio")
            .unwrap_or(0.0),
        metal_stage_breakdown: sample
            .metadata
            .get("metal_stage_breakdown")
            .cloned()
            .unwrap_or_else(|| "{}".to_string()),
        metal_inflight_jobs: parse_metadata_usize(&sample.metadata, "metal_inflight_jobs")
            .unwrap_or(0),
        metal_no_cpu_fallback: parse_metadata_bool(&sample.metadata, "metal_no_cpu_fallback")
            .unwrap_or(false),
        metal_counter_source: sample
            .metadata
            .get("metal_counter_source")
            .cloned()
            .unwrap_or_else(|| "not-measured".to_string()),
        metal_dispatch_circuit_open: parse_metadata_bool(
            &sample.metadata,
            "metal_dispatch_circuit_open",
        )
        .unwrap_or(false),
        metal_dispatch_last_failure: sample
            .metadata
            .get("metal_dispatch_last_failure")
            .cloned()
            .unwrap_or_default(),
    })
}

pub fn compress_nova_proof(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
) -> ZkfResult<ProofArtifact> {
    let wrapper = StarkToGroth16Wrapper;
    wrapper.wrap_with_policy(
        source_proof,
        source_compiled,
        WrapperExecutionPolicy {
            honor_env_overrides: false,
            allow_large_direct_materialization: false,
            force_mode: Some(WrapModeOverride::Nova),
        },
    )
}

impl ProofWrapper for StarkToGroth16Wrapper {
    fn source_backend(&self) -> BackendKind {
        BackendKind::Plonky3
    }

    fn target_backend(&self) -> BackendKind {
        BackendKind::ArkworksGroth16
    }

    fn wrap(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<ProofArtifact> {
        self.wrap_with_artifact_cache_and_policy(
            source_proof,
            source_compiled,
            true,
            WrapperExecutionPolicy::default(),
        )
    }

    fn wrap_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        policy: WrapperExecutionPolicy,
    ) -> ZkfResult<ProofArtifact> {
        self.wrap_with_artifact_cache_and_policy(source_proof, source_compiled, true, policy)
    }

    fn preview_wrap(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<Option<WrapperPreview>> {
        let (fri_params, plan) = self.preview_wrap_plan_with_policy(
            source_proof,
            source_compiled,
            WrapperExecutionPolicy::default(),
        )?;
        Ok(Some(Self::preview_from_plan(
            source_proof,
            &fri_params,
            &plan,
        )?))
    }

    fn preview_wrap_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        policy: WrapperExecutionPolicy,
    ) -> ZkfResult<Option<WrapperPreview>> {
        let (fri_params, plan) =
            self.preview_wrap_plan_with_policy(source_proof, source_compiled, policy)?;
        Ok(Some(Self::preview_from_plan(
            source_proof,
            &fri_params,
            &plan,
        )?))
    }

    fn prepare_wrap_cache_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        policy: WrapperExecutionPolicy,
    ) -> ZkfResult<Option<WrapperCachePrepareReport>> {
        Ok(Some(self.prepare_wrap_cache_with_policy_impl(
            source_proof,
            source_compiled,
            policy,
        )?))
    }

    fn verify_wrapped(&self, wrapped_proof: &ProofArtifact) -> ZkfResult<bool> {
        if wrapped_proof.backend != BackendKind::ArkworksGroth16 {
            return Err(ZkfError::InvalidArtifact(
                "wrapped proof must be ArkworksGroth16 backend".to_string(),
            ));
        }

        let status = wrapped_proof.metadata.get("status").map(|s| s.as_str());

        match status {
            Some("placeholder") => Err(ZkfError::InvalidArtifact(
                "wrapped proof has status 'placeholder' — this artifact was generated \
                 before the STARK-to-Groth16 pipeline was completed; re-wrap with the \
                 current version to produce a valid Groth16 proof"
                    .to_string(),
            )),
            Some("wrapped-v1") | Some("wrapped-v2") => verify_wrapped_groth16(wrapped_proof),
            Some("wrapped-v3") => {
                let groth16_ok = verify_wrapped_groth16(wrapped_proof)?;
                if !groth16_ok {
                    return Ok(false);
                }

                #[cfg(feature = "nova-compression")]
                {
                    let compressed = compressed_stark_proof_from_metadata(wrapped_proof)?;
                    let source_public_inputs =
                        parse_source_public_inputs_u64(&wrapped_proof.public_inputs)?;
                    verify_compressed_stark_proof(&compressed, &source_public_inputs)?;
                    let expected_public_inputs = public_inputs_for_compressed_proof(&compressed)
                        .map_err(ZkfError::InvalidArtifact)?;
                    let actual_public_inputs = reconstruct_public_inputs_for_verify(wrapped_proof)?;
                    if actual_public_inputs != expected_public_inputs {
                        return Err(ZkfError::InvalidArtifact(
                            "wrapped-v3 public inputs do not match the compressed Nova accumulator"
                                .to_string(),
                        ));
                    }
                    Ok(true)
                }

                #[cfg(not(feature = "nova-compression"))]
                {
                    Err(ZkfError::InvalidArtifact(
                        "wrapped-v3 verification requires the nova-compression feature".to_string(),
                    ))
                }
            }
            other => Err(ZkfError::InvalidArtifact(format!(
                "Unknown wrapped proof status: {:?}",
                other
            ))),
        }
    }
}

impl StarkToGroth16Wrapper {
    fn preview_wrap_plan_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        policy: WrapperExecutionPolicy,
    ) -> ZkfResult<(FriCircuitParams, WrapPlan)> {
        let fri_params = self.derive_fri_params(source_proof, source_compiled)?;
        let plan = choose_wrap_plan(&fri_params, policy)?;
        Ok((fri_params, plan))
    }

    fn derive_fri_params(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<FriCircuitParams> {
        Self::validate_wrap_inputs(source_proof, source_compiled)?;

        let p3_seed = plonky3_seed(&source_proof.program_digest);
        let mut fri_params = extract_fri_params(source_proof, p3_seed);

        if !source_compiled.program.constraints.is_empty()
            && let Ok(lowered) = crate::plonky3::lower_program(&source_compiled.program)
        {
            fri_params.trace_width = lowered.signal_order.len();
            fri_params.air_constraints = lowered.constraints;
            fri_params.public_signal_indices = lowered.public_signal_indices;
            fri_params.num_quotient_chunks = 1;
        }

        Ok(fri_params)
    }

    fn preview_from_plan(
        source_proof: &ProofArtifact,
        fri_params: &FriCircuitParams,
        plan: &WrapPlan,
    ) -> ZkfResult<WrapperPreview> {
        let cache_state = preview_cache_state(source_proof, fri_params, plan)?;
        Ok(WrapperPreview {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            planned_status: match plan.strategy {
                WrapStrategy::DirectFriV2 => "wrapped-v2".to_string(),
                WrapStrategy::NovaCompressedV3 => "wrapped-v3".to_string(),
            },
            strategy: plan.strategy.as_str().to_string(),
            trust_model: plan.strategy.trust_model().to_string(),
            trust_model_description: Some(plan.strategy.trust_model_description().to_string()),
            estimated_constraints: Some(plan.estimated_constraints),
            estimated_memory_bytes: Some(plan.estimated_memory_bytes),
            memory_budget_bytes: plan.memory_budget_bytes,
            low_memory_mode: Some(plan.low_memory_mode),
            prepare_required: cache_state.map(SetupCacheState::requires_prepare),
            setup_cache_state: cache_state.map(|state| state.as_str().to_string()),
            reason: Some(preview_reason(plan, cache_state)),
        })
    }

    fn prepare_wrap_cache_with_policy_impl(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        policy: WrapperExecutionPolicy,
    ) -> ZkfResult<WrapperCachePrepareReport> {
        let fri_params = self.derive_fri_params(source_proof, source_compiled)?;
        let plan = choose_wrap_plan(&fri_params, policy)?;
        let cache_state = if plan.strategy == WrapStrategy::DirectFriV2 {
            let cache_key = setup_cache_key(&source_proof.program_digest, &fri_params);
            let state = probe_setup_cache_state(&cache_key)?;
            Some((cache_key, state))
        } else {
            None
        };

        if let Some((_, state)) = cache_state.as_ref()
            && let Some(blocked) = blocked_large_direct_prepare_report(&plan, *state, policy)
        {
            return Ok(blocked);
        }

        let setup = match plan.strategy {
            WrapStrategy::DirectFriV2 => {
                let cache_key = cache_state
                    .as_ref()
                    .map(|(cache_key, _)| cache_key.clone())
                    .unwrap_or_else(|| setup_cache_key(&source_proof.program_digest, &fri_params));
                get_or_create_setup_cached(
                    &cache_key,
                    || direct_fri_setup_circuit(&fri_params),
                    || direct_fri_setup_circuit(&fri_params),
                )?
            }
            WrapStrategy::NovaCompressedV3 => {
                #[cfg(feature = "nova-compression")]
                {
                    let witness = build_witness_from_proof(
                        &source_proof.proof,
                        &source_proof.public_inputs,
                        &fri_params,
                    );
                    let source_public_inputs =
                        parse_source_public_inputs_u64(&source_proof.public_inputs)?;
                    let nova_queries = build_nova_query_witnesses(&witness, &fri_params)?;
                    let compressed = NovaStarkCompressor::compress(
                        nova_queries,
                        &source_public_inputs,
                        fri_params.merkle_tree_height,
                        fri_params.trace_width.max(1),
                        fri_params.num_fri_rounds,
                    )?;
                    let cache_key = nova_setup_cache_key(&source_proof.program_digest, &compressed);
                    get_or_create_setup_cached(
                        &cache_key,
                        || NovaVerifierCircuit::sizing_instance(compressed.num_queries),
                        || NovaVerifierCircuit::sizing_instance(compressed.num_queries),
                    )?
                }
                #[cfg(not(feature = "nova-compression"))]
                {
                    return Err(ZkfError::Backend(
                        "Nova-compressed wrapper path requires the nova-compression feature"
                            .to_string(),
                    ));
                }
            }
        };

        let final_cache_state = match plan.strategy {
            WrapStrategy::DirectFriV2 => {
                let cache_key = cache_state
                    .as_ref()
                    .map(|(cache_key, _)| cache_key.as_str())
                    .unwrap_or("");
                Some(probe_setup_cache_state(cache_key)?)
            }
            WrapStrategy::NovaCompressedV3 => None,
        };

        Ok(WrapperCachePrepareReport {
            wrapper: "stark-to-groth16".to_string(),
            source_backend: BackendKind::Plonky3,
            target_backend: BackendKind::ArkworksGroth16,
            strategy: plan.strategy.as_str().to_string(),
            trust_model: plan.strategy.trust_model().to_string(),
            setup_cache_ready: true,
            shape_cache_ready: Some(setup.prove_shape.is_some()),
            setup_cache_pk_format: Some(setup.pk_cache_format.to_string()),
            setup_cache_pk_migrated: setup.pk_cache_migrated,
            blocked: false,
            setup_cache_state: final_cache_state.map(|state| state.as_str().to_string()),
            blocked_reason: None,
            operator_action: None,
            detail: Some(plan.reason),
        })
    }

    fn validate_wrap_inputs(
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<()> {
        if source_proof.backend != BackendKind::Plonky3 {
            return Err(ZkfError::InvalidArtifact(format!(
                "STARK-to-Groth16 wrapper requires Plonky3 source proof, got {}",
                source_proof.backend
            )));
        }

        if source_compiled.backend != BackendKind::Plonky3 {
            return Err(ZkfError::InvalidArtifact(format!(
                "STARK-to-Groth16 wrapper requires Plonky3 compiled program, got {}",
                source_compiled.backend
            )));
        }

        Ok(())
    }

    fn wrap_uncached(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<ProofArtifact> {
        self.wrap_with_artifact_cache(source_proof, source_compiled, false)
    }

    fn wrap_with_artifact_cache(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        use_artifact_cache: bool,
    ) -> ZkfResult<ProofArtifact> {
        self.wrap_with_artifact_cache_and_policy(
            source_proof,
            source_compiled,
            use_artifact_cache,
            WrapperExecutionPolicy::default(),
        )
    }

    fn wrap_with_artifact_cache_and_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        use_artifact_cache: bool,
        policy: WrapperExecutionPolicy,
    ) -> ZkfResult<ProofArtifact> {
        Self::validate_wrap_inputs(source_proof, source_compiled)?;

        let mut wrapper_stages = serde_json::Map::new();

        let fri_params_start = Instant::now();
        let fri_params = self.derive_fri_params(source_proof, source_compiled)?;
        record_wrapper_stage(
            &mut wrapper_stages,
            "extract_fri_params",
            "cpu",
            fri_params_start.elapsed().as_secs_f64() * 1_000.0,
            1,
            false,
            Some("wrapper-parameter-derivation-not-metal"),
        );
        let plan_start = Instant::now();
        let plan = choose_wrap_plan(&fri_params, policy)?;
        record_wrapper_stage(
            &mut wrapper_stages,
            "plan_wrap_strategy",
            "cpu",
            plan_start.elapsed().as_secs_f64() * 1_000.0,
            1,
            false,
            Some(plan.reason.as_str()),
        );

        let artifact_cache_key =
            wrapped_artifact_cache_key(source_proof, source_compiled, &plan, policy)?;
        if use_artifact_cache {
            if let Some(artifact) = load_wrapped_artifact_from_memory(&artifact_cache_key)? {
                return Ok(mark_wrapped_artifact_cache_hit(artifact, "memory"));
            }
            if let Some(artifact) = load_wrapped_artifact_from_disk(&artifact_cache_key)? {
                store_wrapped_artifact_in_memory(&artifact_cache_key, &artifact)?;
                return Ok(mark_wrapped_artifact_cache_hit(artifact, "disk"));
            }
        }

        let witness_start = Instant::now();
        let witness = build_witness_from_proof(
            &source_proof.proof,
            &source_proof.public_inputs,
            &fri_params,
        );
        record_wrapper_stage(
            &mut wrapper_stages,
            "build_witness",
            "cpu",
            witness_start.elapsed().as_secs_f64() * 1_000.0,
            1,
            false,
            Some("wrapper-witness-build-not-metal"),
        );

        let artifact = if plan.strategy == WrapStrategy::DirectFriV2 {
            wrap_direct_fri_v2(
                source_proof,
                &fri_params,
                witness,
                &plan,
                &mut wrapper_stages,
                use_artifact_cache,
            )?
        } else {
            wrap_nova_compressed_v3(
                source_proof,
                &fri_params,
                &witness,
                &plan,
                &mut wrapper_stages,
                use_artifact_cache,
            )?
        };

        validate_wrapped_artifact_health(&artifact)?;

        if use_artifact_cache {
            persist_wrapped_artifact(&artifact_cache_key, &artifact)?;
            store_wrapped_artifact_in_memory(&artifact_cache_key, &artifact)?;
        }

        Ok(artifact)
    }
}

pub fn export_direct_wrap_cache_bundle(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    policy: WrapperExecutionPolicy,
    bundle_dir: &Path,
    hardware_profile: &str,
) -> ZkfResult<WrapperCacheBundleManifest> {
    let manifest = ready_direct_wrap_cache_bundle_manifest(
        source_proof,
        source_compiled,
        policy,
        hardware_profile,
    )?;
    let source_paths = direct_wrap_cache_source_paths(&manifest.cache_key)?;
    if bundle_dir.exists() {
        return Err(ZkfError::Backend(format!(
            "wrapper cache bundle path already exists: {}",
            bundle_dir.display()
        )));
    }
    write_dir_atomic(bundle_dir, |temp_dir| {
        let pk_dst = temp_dir.join(&manifest.files.proving_key.file_name);
        let vk_dst = temp_dir.join(&manifest.files.verifying_key.file_name);
        let shape_dst = temp_dir.join(&manifest.files.prove_shape.file_name);
        fs::copy(&source_paths.0, &pk_dst).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to export proving key cache into {}: {err}",
                pk_dst.display()
            ))
        })?;
        fs::copy(&source_paths.1, &vk_dst).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to export verifying key cache into {}: {err}",
                vk_dst.display()
            ))
        })?;
        fs::copy(&source_paths.2, &shape_dst).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to export prove-shape cache into {}: {err}",
                shape_dst.display()
            ))
        })?;
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|err| {
            ZkfError::Serialization(format!(
                "Failed to serialize wrapper cache bundle manifest: {err}"
            ))
        })?;
        fs::write(temp_dir.join("manifest.json"), manifest_bytes).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to write wrapper cache bundle manifest in {}: {err}",
                temp_dir.display()
            ))
        })?;
        Ok(())
    })?;
    Ok(manifest)
}

pub fn install_direct_wrap_cache_bundle(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    policy: WrapperExecutionPolicy,
    bundle_dir: &Path,
    hardware_profile: &str,
) -> ZkfResult<WrapperCacheBundleManifest> {
    let expected = direct_wrap_cache_bundle_expectation(source_proof, source_compiled, policy)?;
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to read wrapper cache bundle manifest {}: {err}",
            manifest_path.display()
        ))
    })?;
    let manifest: WrapperCacheBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|err| {
            ZkfError::Serialization(format!(
                "Failed to deserialize wrapper cache bundle manifest {}: {err}",
                manifest_path.display()
            ))
        })?;
    let _ = hardware_profile;
    validate_cache_bundle_manifest(&manifest, &expected)?;
    validate_bundle_file(bundle_dir, &manifest.files.proving_key)?;
    validate_bundle_file(bundle_dir, &manifest.files.verifying_key)?;
    validate_bundle_file(bundle_dir, &manifest.files.prove_shape)?;

    let (pk_path, vk_path, shape_path) = setup_disk_cache_paths(&expected.cache_key);
    copy_file_atomic(
        &bundle_dir.join(&manifest.files.proving_key.file_name),
        &pk_path,
        "proving key cache",
    )?;
    copy_file_atomic(
        &bundle_dir.join(&manifest.files.verifying_key.file_name),
        &vk_path,
        "verifying key cache",
    )?;
    copy_file_atomic(
        &bundle_dir.join(&manifest.files.prove_shape.file_name),
        &shape_path,
        "prove-shape cache",
    )?;
    let mut cache = SETUP_CACHE
        .lock()
        .map_err(|_| ZkfError::Backend("Setup cache lock poisoned".to_string()))?;
    cache.remove(&expected.cache_key);
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Helper: Plonky3 seed derivation (must match plonky3.rs)
// ---------------------------------------------------------------------------

fn verify_wrapped_groth16(wrapped_proof: &ProofArtifact) -> ZkfResult<bool> {
    let vk =
        VerifyingKey::<Bn254>::deserialize_compressed(wrapped_proof.verification_key.as_slice())
            .map_err(|e| {
                ZkfError::InvalidArtifact(format!("Failed to deserialize verifying key: {e}"))
            })?;
    let proof =
        Proof::<Bn254>::deserialize_compressed(wrapped_proof.proof.as_slice()).map_err(|e| {
            ZkfError::InvalidArtifact(format!("Failed to deserialize Groth16 proof: {e}"))
        })?;
    let public_inputs = reconstruct_public_inputs_for_verify(wrapped_proof)?;
    Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .map_err(|e| ZkfError::Backend(format!("Groth16 verification failed: {e}")))
}

fn choose_wrap_plan(
    params: &FriCircuitParams,
    policy: WrapperExecutionPolicy,
) -> ZkfResult<WrapPlan> {
    let resources = SystemResources::detect();
    harden_metal_runtime_for_pressure(&resources);
    let recommendation = resources.recommend();
    let certified_budget_bytes = certified_strict_wrap_budget_bytes(&resources);
    let metal_budget_bytes = metal_recommended_wrap_budget_bytes(&resources);
    let memory_budget_bytes = if certified_budget_bytes.is_some() {
        [certified_budget_bytes, metal_budget_bytes]
            .into_iter()
            .flatten()
            .filter(|bytes| *bytes > 0)
            .min()
    } else {
        [
            Some(recommendation.max_circuit_memory_bytes),
            metal_budget_bytes,
        ]
        .into_iter()
        .flatten()
        .filter(|bytes| *bytes > 0)
        .min()
    };
    let low_memory_mode = recommendation.low_memory_mode;

    let forced_mode = effective_wrap_mode(policy);

    let direct_constraints = estimate_direct_wrap_constraints(params);
    let direct_memory_bytes = direct_constraints.saturating_mul(DIRECT_WRAP_BYTES_PER_CONSTRAINT);
    let direct_fits_budget = memory_budget_bytes
        .map(|budget| direct_memory_bytes <= budget)
        .unwrap_or(!low_memory_mode);

    match forced_mode.as_str() {
        "auto" if direct_fits_budget => Ok(WrapPlan {
            strategy: WrapStrategy::DirectFriV2,
            estimated_constraints: direct_constraints,
            estimated_memory_bytes: direct_memory_bytes,
            memory_budget_bytes,
            low_memory_mode,
            reason: if certified_budget_bytes.is_some() {
                format!(
                    "direct FRI verifier circuit fits the certified strict-wrap budget for {}",
                    detected_hardware_profile_label(&resources)
                )
            } else {
                "direct FRI verifier circuit fits the detected circuit memory budget".to_string()
            },
        }),
        "auto" => {
            #[cfg(feature = "nova-compression")]
            {
                let budget_text = memory_budget_bytes
                    .map(|budget| budget.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                Ok(WrapPlan {
                    strategy: WrapStrategy::NovaCompressedV3,
                    estimated_constraints: 1_400,
                    estimated_memory_bytes: 256 * 1024 * 1024,
                    memory_budget_bytes,
                    low_memory_mode,
                    reason: format!(
                        "direct FRI verifier circuit estimate {} bytes exceeds budget {}; using Nova-compressed attestation path",
                        direct_memory_bytes, budget_text
                    ),
                })
            }

            #[cfg(not(feature = "nova-compression"))]
            {
                Err(ZkfError::Backend(format!(
                    "direct FRI verifier circuit estimate {} bytes exceeds the detected circuit budget {:?}; rebuild with the nova-compression feature or force ZKF_WRAP_MODE=direct on a higher-memory machine",
                    direct_memory_bytes, memory_budget_bytes
                )))
            }
        }
        "direct" => Ok(WrapPlan {
            strategy: WrapStrategy::DirectFriV2,
            estimated_constraints: direct_constraints,
            estimated_memory_bytes: direct_memory_bytes,
            memory_budget_bytes,
            low_memory_mode,
            reason: "forced via ZKF_WRAP_MODE=direct".to_string(),
        }),
        "nova" => {
            #[cfg(feature = "nova-compression")]
            {
                Ok(WrapPlan {
                    strategy: WrapStrategy::NovaCompressedV3,
                    estimated_constraints: 1_400,
                    estimated_memory_bytes: 256 * 1024 * 1024,
                    memory_budget_bytes,
                    low_memory_mode,
                    reason: "forced via ZKF_WRAP_MODE=nova".to_string(),
                })
            }

            #[cfg(not(feature = "nova-compression"))]
            {
                Err(ZkfError::Backend(
                    "ZKF_WRAP_MODE=nova requires the nova-compression feature".to_string(),
                ))
            }
        }
        other => Err(ZkfError::Backend(format!(
            "unknown ZKF_WRAP_MODE '{other}' (expected auto, direct, or nova)"
        ))),
    }
}

fn detected_hardware_profile_label(resources: &SystemResources) -> &'static str {
    if resources.unified_memory && resources.total_ram_bytes >= 48 * 1024 * 1024 * 1024 {
        "apple-silicon-m4-max-48gb"
    } else if resources.unified_memory {
        "apple-silicon-generic"
    } else {
        "cpu-only"
    }
}

fn certified_strict_wrap_budget_bytes(resources: &SystemResources) -> Option<u64> {
    if !resources.unified_memory {
        return None;
    }
    if resources.total_ram_bytes < 48 * 1024 * 1024 * 1024 {
        return None;
    }
    if matches!(
        resources.pressure.level,
        PressureLevel::High | PressureLevel::Critical
    ) {
        return None;
    }
    Some(36 * 1024 * 1024 * 1024)
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn harden_metal_runtime_for_pressure(resources: &SystemResources) {
    if let Some(ctx) = zkf_metal::global_context() {
        let _ = ctx.harden_for_pressure(resources.pressure.level);
    }
}

#[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
fn harden_metal_runtime_for_pressure(_resources: &SystemResources) {}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn metal_recommended_wrap_budget_bytes(resources: &SystemResources) -> Option<u64> {
    let ctx = zkf_metal::global_context()?;
    let recommended = ctx.recommended_working_set_size()? as u64;
    let allocated = ctx.current_allocated_size() as u64;
    let reserve = match resources.pressure.level {
        PressureLevel::Normal => 3 * 1024 * 1024 * 1024,
        PressureLevel::Elevated => 4 * 1024 * 1024 * 1024,
        PressureLevel::High => 6 * 1024 * 1024 * 1024,
        PressureLevel::Critical => 10 * 1024 * 1024 * 1024,
    };
    let steady_state_guard = (recommended / 16).max(reserve);
    Some(
        recommended
            .saturating_sub(allocated)
            .saturating_sub(steady_state_guard),
    )
}

#[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
fn metal_recommended_wrap_budget_bytes(_resources: &SystemResources) -> Option<u64> {
    None
}

fn estimate_direct_wrap_constraints(params: &FriCircuitParams) -> u64 {
    let trace_width = params.trace_width.max(1) as u64;
    let air_factor = if !params.air_constraints.is_empty() && params.trace_width > 0 {
        8
    } else {
        1
    };
    DIRECT_WRAP_COMPLEXITY_UNIT
        .saturating_mul(params.num_queries.max(1) as u64)
        .saturating_mul((params.merkle_tree_height + params.num_fri_rounds + 1) as u64)
        .saturating_mul(trace_width.saturating_add(air_factor))
}

fn ensure_direct_wrap_cache_ready_for_execution(cache_key: &str, plan: &WrapPlan) -> ZkfResult<()> {
    if plan.strategy != WrapStrategy::DirectFriV2
        || plan.estimated_memory_bytes < DIRECT_WRAP_PREP_REQUIRED_BYTES
    {
        return Ok(());
    }

    match probe_setup_cache_state(cache_key)? {
        SetupCacheState::Ready => Ok(()),
        SetupCacheState::Missing => Err(ZkfError::Backend(
            "strict direct wrapper setup cache is not prepared; run `zkf runtime prepare --proof <proof.json> --compiled <compiled.json>` on the certified host before `zkf wrap`".to_string(),
        )),
        SetupCacheState::FastMissingShape => Err(ZkfError::Backend(
            "strict direct wrapper prove-shape cache is missing; run `zkf runtime prepare --proof <proof.json> --compiled <compiled.json>` before `zkf wrap`".to_string(),
        )),
        SetupCacheState::LegacyCompressed => Err(ZkfError::Backend(
            "strict direct wrapper found a legacy compressed setup cache; run `zkf runtime prepare --proof <proof.json> --compiled <compiled.json>` to migrate it before `zkf wrap`".to_string(),
        )),
    }
}

fn wrap_direct_fri_v2(
    source_proof: &ProofArtifact,
    fri_params: &FriCircuitParams,
    witness: StarkProofWitness,
    plan: &WrapPlan,
    wrapper_stages: &mut serde_json::Map<String, serde_json::Value>,
    use_artifact_cache: bool,
) -> ZkfResult<ProofArtifact> {
    let cache_key = setup_cache_key(&source_proof.program_digest, fri_params);
    ensure_direct_wrap_cache_ready_for_execution(&cache_key, plan)?;
    let setup_start = Instant::now();
    let setup = get_or_create_setup_cached(
        &cache_key,
        || direct_fri_setup_circuit(fri_params),
        || direct_fri_setup_circuit(fri_params),
    )?;
    record_wrapper_stage(
        wrapper_stages,
        "setup_cache",
        "cpu",
        setup_start.elapsed().as_secs_f64() * 1_000.0,
        1,
        false,
        Some("groth16-setup-cache-not-metal"),
    );

    let public_inputs_start = Instant::now();
    let groth16_pub_inputs = collect_public_inputs_from_witness(&witness, fri_params)?;
    record_wrapper_stage(
        wrapper_stages,
        "extract_public_inputs",
        "cpu",
        public_inputs_start.elapsed().as_secs_f64() * 1_000.0,
        1,
        false,
        Some("public-input-extraction-not-metal"),
    );

    let circuit = FriVerifierCircuit::with_witness(witness, fri_params.clone());
    let proof_seed = deterministic_proof_seed(&source_proof.program_digest, &source_proof.proof);
    let mut rng = StdRng::from_seed(proof_seed);

    let prove_start = Instant::now();
    let (groth16_proof, groth16_dispatch) = if let Some(prove_shape) = setup.prove_shape.as_deref()
    {
        create_local_groth16_proof_with_cached_shape(
            setup.pk.as_ref(),
            circuit,
            &mut rng,
            prove_shape,
        )
    } else {
        create_local_groth16_proof(setup.pk.as_ref(), circuit, &mut rng)
    }
    .map_err(|e| ZkfError::Backend(format!("Groth16 prove failed: {e}")))?;
    let mut groth16_metal_metadata = BTreeMap::new();
    append_groth16_metal_metadata(&mut groth16_metal_metadata, groth16_dispatch);
    record_groth16_prove_stage(
        wrapper_stages,
        &groth16_metal_metadata,
        prove_start.elapsed().as_secs_f64() * 1_000.0,
    );

    let proof_bytes = serialize_groth16_proof(&groth16_proof)?;
    let pub_inputs_hex = serialize_fr_vec_hex(&groth16_pub_inputs)?;

    let mut metadata = base_wrapper_metadata(
        source_proof,
        wrapper_stages,
        use_artifact_cache,
        "wrapped-v2",
        "wrapped-fri-verifier-circuit",
        "fri-verifier-circuit",
        "circuit-replayed",
        plan,
    );
    metadata.insert(
        "proof_engine".to_string(),
        "stark-export-wrapper".to_string(),
    );
    metadata.insert(
        "prover_acceleration_scope".to_string(),
        "target-groth16-prover-only".to_string(),
    );
    metadata.insert(
        "wrapper_shape_cache".to_string(),
        setup.prove_shape.is_some().to_string(),
    );
    metadata.insert(
        "wrapper_setup_cache_pk_format".to_string(),
        setup.pk_cache_format.to_string(),
    );
    metadata.insert(
        "wrapper_setup_cache_pk_migrated".to_string(),
        setup.pk_cache_migrated.to_string(),
    );
    metadata.insert(
        "num_queries".to_string(),
        fri_params.num_queries.to_string(),
    );
    metadata.insert(
        "num_fri_rounds".to_string(),
        fri_params.num_fri_rounds.to_string(),
    );
    metadata.insert("log_degree".to_string(), fri_params.log_degree.to_string());
    metadata.insert(
        "merkle_tree_height".to_string(),
        fri_params.merkle_tree_height.to_string(),
    );
    metadata.insert(
        "poseidon2_seed".to_string(),
        fri_params.poseidon2_seed.to_string(),
    );
    metadata.insert("groth16_public_inputs_hex".to_string(), pub_inputs_hex);
    finalize_target_groth16_metadata(&mut metadata, &groth16_metal_metadata, wrapper_stages);

    Ok(ProofArtifact {
        backend: BackendKind::ArkworksGroth16,
        program_digest: source_proof.program_digest.clone(),
        proof: proof_bytes,
        verification_key: setup.vk_bytes.as_ref().clone(),
        public_inputs: source_proof.public_inputs.clone(),
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    })
}

#[cfg(feature = "nova-compression")]
fn wrap_nova_compressed_v3(
    source_proof: &ProofArtifact,
    fri_params: &FriCircuitParams,
    witness: &StarkProofWitness,
    plan: &WrapPlan,
    wrapper_stages: &mut serde_json::Map<String, serde_json::Value>,
    use_artifact_cache: bool,
) -> ZkfResult<ProofArtifact> {
    use base64::Engine;

    let source_public_inputs = parse_source_public_inputs_u64(&source_proof.public_inputs)?;
    let nova_queries = build_nova_query_witnesses(witness, fri_params)?;

    let compress_start = Instant::now();
    let compressed = NovaStarkCompressor::compress(
        nova_queries,
        &source_public_inputs,
        fri_params.merkle_tree_height,
        fri_params.trace_width.max(1),
        fri_params.num_fri_rounds,
    )?;
    record_wrapper_stage(
        wrapper_stages,
        "nova_compress",
        "cpu",
        compress_start.elapsed().as_secs_f64() * 1_000.0,
        1,
        false,
        Some("nova-ivc-compression-not-metal"),
    );

    let setup_start = Instant::now();
    let cache_key = nova_setup_cache_key(&source_proof.program_digest, &compressed);
    let setup = get_or_create_setup_cached(
        &cache_key,
        || NovaVerifierCircuit::sizing_instance(compressed.num_queries),
        || NovaVerifierCircuit::sizing_instance(compressed.num_queries),
    )?;
    record_wrapper_stage(
        wrapper_stages,
        "setup_cache",
        "cpu",
        setup_start.elapsed().as_secs_f64() * 1_000.0,
        1,
        false,
        Some("groth16-setup-cache-not-metal"),
    );

    let public_inputs_start = Instant::now();
    let groth16_pub_inputs =
        public_inputs_for_compressed_proof(&compressed).map_err(ZkfError::InvalidArtifact)?;
    record_wrapper_stage(
        wrapper_stages,
        "extract_public_inputs",
        "cpu",
        public_inputs_start.elapsed().as_secs_f64() * 1_000.0,
        1,
        false,
        Some("nova-accumulator-public-input-extraction-not-metal"),
    );

    let circuit = NovaVerifierCircuit::new(compressed.clone());
    let proof_seed = deterministic_proof_seed(&source_proof.program_digest, &source_proof.proof);
    let mut rng = StdRng::from_seed(proof_seed);

    let prove_start = Instant::now();
    let (groth16_proof, groth16_dispatch) = if let Some(prove_shape) = setup.prove_shape.as_deref()
    {
        create_local_groth16_proof_with_cached_shape(
            setup.pk.as_ref(),
            circuit,
            &mut rng,
            prove_shape,
        )
    } else {
        create_local_groth16_proof(setup.pk.as_ref(), circuit, &mut rng)
    }
    .map_err(|e| ZkfError::Backend(format!("Groth16 prove failed: {e}")))?;
    let mut groth16_metal_metadata = BTreeMap::new();
    append_groth16_metal_metadata(&mut groth16_metal_metadata, groth16_dispatch);
    record_groth16_prove_stage(
        wrapper_stages,
        &groth16_metal_metadata,
        prove_start.elapsed().as_secs_f64() * 1_000.0,
    );

    let proof_bytes = serialize_groth16_proof(&groth16_proof)?;
    let pub_inputs_hex = serialize_fr_vec_hex(&groth16_pub_inputs)?;
    let compressed_bytes = bincode::serialize(&compressed).map_err(|err| {
        ZkfError::Serialization(format!("Failed to serialize compressed Nova proof: {err}"))
    })?;

    let mut metadata = base_wrapper_metadata(
        source_proof,
        wrapper_stages,
        use_artifact_cache,
        "wrapped-v3",
        "wrapped-nova-accumulator-binding",
        "nova-compressed-attestation-binding",
        "host-verified-compressed-nova",
        plan,
    );
    metadata.insert(
        "proof_engine".to_string(),
        "stark-export-wrapper+nova".to_string(),
    );
    metadata.insert(
        "prover_acceleration_scope".to_string(),
        "nova-compression+target-groth16-prover".to_string(),
    );
    metadata.insert(
        "wrapper_shape_cache".to_string(),
        setup.prove_shape.is_some().to_string(),
    );
    metadata.insert(
        "wrapper_setup_cache_pk_format".to_string(),
        setup.pk_cache_format.to_string(),
    );
    metadata.insert(
        "wrapper_setup_cache_pk_migrated".to_string(),
        setup.pk_cache_migrated.to_string(),
    );
    metadata.insert(
        "num_queries".to_string(),
        fri_params.num_queries.to_string(),
    );
    metadata.insert(
        "num_fri_rounds".to_string(),
        fri_params.num_fri_rounds.to_string(),
    );
    metadata.insert("log_degree".to_string(), fri_params.log_degree.to_string());
    metadata.insert(
        "merkle_tree_height".to_string(),
        fri_params.merkle_tree_height.to_string(),
    );
    metadata.insert(
        "poseidon2_seed".to_string(),
        fri_params.poseidon2_seed.to_string(),
    );
    metadata.insert("groth16_public_inputs_hex".to_string(), pub_inputs_hex);
    metadata.insert("nova_pp_hash".to_string(), compressed.pp_hash.clone());
    metadata.insert(
        "nova_num_queries".to_string(),
        compressed.num_queries.to_string(),
    );
    metadata.insert(
        "nova_num_fri_rounds".to_string(),
        compressed.num_fri_rounds.to_string(),
    );
    metadata.insert(
        "nova_max_depth".to_string(),
        compressed.max_depth.to_string(),
    );
    metadata.insert(
        "nova_leaf_width".to_string(),
        compressed.leaf_width.to_string(),
    );
    metadata.insert(
        "nova_compressed_stark_b64".to_string(),
        base64::engine::general_purpose::STANDARD.encode(compressed_bytes),
    );
    finalize_target_groth16_metadata(&mut metadata, &groth16_metal_metadata, wrapper_stages);

    Ok(ProofArtifact {
        backend: BackendKind::ArkworksGroth16,
        program_digest: source_proof.program_digest.clone(),
        proof: proof_bytes,
        verification_key: setup.vk_bytes.as_ref().clone(),
        public_inputs: source_proof.public_inputs.clone(),
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    })
}

#[cfg(not(feature = "nova-compression"))]
fn wrap_nova_compressed_v3(
    _source_proof: &ProofArtifact,
    _fri_params: &FriCircuitParams,
    _witness: &StarkProofWitness,
    _plan: &WrapPlan,
    _wrapper_stages: &mut serde_json::Map<String, serde_json::Value>,
    _use_artifact_cache: bool,
) -> ZkfResult<ProofArtifact> {
    Err(ZkfError::Backend(
        "Nova-compressed wrapper path requires the nova-compression feature".to_string(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn base_wrapper_metadata(
    source_proof: &ProofArtifact,
    wrapper_stages: &serde_json::Map<String, serde_json::Value>,
    use_artifact_cache: bool,
    status: &str,
    proof_semantics: &str,
    wrapper_semantics: &str,
    source_verification_semantics: &str,
    plan: &WrapPlan,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    let resources = SystemResources::detect();
    append_default_metal_telemetry(&mut metadata);
    metadata.insert("wrapper".to_string(), "stark-to-groth16".to_string());
    metadata.insert(
        "source_backend".to_string(),
        source_proof.backend.to_string(),
    );
    metadata.insert(
        "source_digest".to_string(),
        source_proof.program_digest.clone(),
    );
    metadata.insert(
        "source_proof_size".to_string(),
        source_proof.proof.len().to_string(),
    );
    metadata.insert("status".to_string(), status.to_string());
    metadata.insert("curve".to_string(), "bn254".to_string());
    metadata.insert("scheme".to_string(), "groth16".to_string());
    metadata.insert("proof_semantics".to_string(), proof_semantics.to_string());
    metadata.insert(
        "blackbox_semantics".to_string(),
        "not-applicable-wrapper-circuit".to_string(),
    );
    metadata.insert(
        "wrapper_semantics".to_string(),
        wrapper_semantics.to_string(),
    );
    metadata.insert("export_scheme".to_string(), "groth16".to_string());
    metadata.insert("metal_complete".to_string(), "false".to_string());
    metadata.insert(
        "cpu_math_fallback_reason".to_string(),
        "export-wrapper-not-primary-engine".to_string(),
    );
    metadata.insert(
        "source_verification_semantics".to_string(),
        source_verification_semantics.to_string(),
    );
    metadata.insert("wrapper_cache_hit".to_string(), "false".to_string());
    metadata.insert(
        "wrapper_cache_source".to_string(),
        if use_artifact_cache {
            "miss".to_string()
        } else {
            "disabled".to_string()
        },
    );
    metadata.insert(
        "wrapper_strategy".to_string(),
        plan.strategy.as_str().to_string(),
    );
    metadata.insert(
        "trust_model".to_string(),
        plan.strategy.trust_model().to_string(),
    );
    metadata.insert(
        "trust_model_description".to_string(),
        plan.strategy.trust_model_description().to_string(),
    );
    metadata.insert(
        "umpg_estimated_constraints".to_string(),
        plan.estimated_constraints.to_string(),
    );
    metadata.insert(
        "umpg_estimated_memory_bytes".to_string(),
        plan.estimated_memory_bytes.to_string(),
    );
    metadata.insert(
        "umpg_memory_budget_bytes".to_string(),
        plan.memory_budget_bytes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    );
    metadata.insert(
        "umpg_low_memory_mode".to_string(),
        plan.low_memory_mode.to_string(),
    );
    metadata.insert("umpg_plan_reason".to_string(), plan.reason.clone());
    metadata.insert(
        "runtime_detected_hardware_profile".to_string(),
        detected_hardware_profile_label(&resources).to_string(),
    );
    metadata.insert(
        "metal_stage_breakdown".to_string(),
        serde_json::Value::Object(wrapper_stages.clone()).to_string(),
    );
    metadata
}

fn finalize_target_groth16_metadata(
    metadata: &mut BTreeMap<String, String>,
    groth16_metal_metadata: &BTreeMap<String, String>,
    wrapper_stages: &serde_json::Map<String, serde_json::Value>,
) {
    let mut runtime_metadata = BTreeMap::new();
    append_backend_runtime_metadata(&mut runtime_metadata, BackendKind::ArkworksGroth16);
    for (key, value) in groth16_metal_metadata {
        runtime_metadata.insert(key.clone(), value.clone());
    }

    if let Some(value) = groth16_metal_metadata.get("msm_accelerator").cloned() {
        metadata.insert("msm_accelerator".to_string(), value);
    }
    if let Some(value) = groth16_metal_metadata.get("gpu_stage_coverage").cloned() {
        metadata.insert("gpu_stage_coverage".to_string(), value);
    }
    if let Some(value) = groth16_metal_metadata.get("gpu_stage_busy_ratio").cloned() {
        metadata.insert("gpu_stage_busy_ratio".to_string(), value);
    }
    for key in [
        "qap_witness_map_engine",
        "qap_witness_map_reason",
        "qap_witness_map_parallelism",
        "qap_witness_map_fallback_state",
        "groth16_msm_engine",
        "groth16_msm_reason",
        "groth16_msm_parallelism",
        "groth16_msm_fallback_state",
        "groth16_msm_dispatch_failure",
    ] {
        if let Some(value) = groth16_metal_metadata.get(key).cloned() {
            metadata.insert(key.to_string(), value);
        }
    }
    copy_standard_metal_metadata(&runtime_metadata, metadata, None);
    metadata.insert(
        "metal_stage_breakdown".to_string(),
        serde_json::Value::Object(wrapper_stages.clone()).to_string(),
    );
    if let Some(source) = groth16_metal_metadata.get("metal_counter_source") {
        metadata.insert(
            "metal_counter_source".to_string(),
            format!("wrapper-stage-walltime+{source}"),
        );
    }
    for (key, value) in runtime_metadata {
        metadata.insert(format!("target_groth16_{key}"), value);
    }
}

fn record_groth16_prove_stage(
    wrapper_stages: &mut serde_json::Map<String, serde_json::Value>,
    groth16_metal_metadata: &BTreeMap<String, String>,
    duration_ms: f64,
) {
    let accelerator = groth16_metal_metadata
        .get("groth16_msm_engine")
        .map(String::as_str)
        .unwrap_or_else(|| {
            groth16_metal_metadata
                .get("msm_accelerator")
                .map(String::as_str)
                .unwrap_or("cpu")
        });
    record_wrapper_stage(
        wrapper_stages,
        "target_groth16_prove",
        if accelerator.starts_with("metal") {
            "metal"
        } else {
            "cpu"
        },
        duration_ms,
        parse_metadata_usize(groth16_metal_metadata, "metal_inflight_jobs").unwrap_or(1),
        groth16_metal_metadata
            .get("groth16_msm_fallback_state")
            .map(String::as_str)
            == Some("none"),
        groth16_metal_metadata
            .get("groth16_msm_reason")
            .map(String::as_str)
            .filter(|reason| *reason != "bn254-groth16-metal-msm"),
    );
    if let Some(stage_json) = groth16_metal_metadata
        .get("metal_stage_breakdown")
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
    {
        wrapper_stages.insert("target_groth16_internal".to_string(), stage_json);
    }
}

fn serialize_groth16_proof(proof: &Proof<Bn254>) -> ZkfResult<Vec<u8>> {
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| ZkfError::Serialization(format!("Failed to serialize Groth16 proof: {e}")))?;
    Ok(proof_bytes)
}

#[cfg(feature = "nova-compression")]
fn parse_source_public_inputs_u64(inputs: &[zkf_core::FieldElement]) -> ZkfResult<Vec<u64>> {
    inputs
        .iter()
        .map(|input| {
            input
                .to_decimal_string()
                .parse::<u64>()
                .map_err(|_| {
                    ZkfError::InvalidArtifact(
                        "Nova-compressed wrapper only supports Goldilocks public inputs that fit in u64"
                            .to_string(),
                    )
                })
        })
        .collect()
}

#[cfg(feature = "nova-compression")]
fn build_nova_query_witnesses(
    witness: &StarkProofWitness,
    params: &FriCircuitParams,
) -> ZkfResult<Vec<NovaQueryWitness>> {
    let mut queries = Vec::with_capacity(params.num_queries);

    for query in witness.queries.iter().take(params.num_queries) {
        let mut current = query.fri_composed_value;
        let mut x_values = Vec::with_capacity(params.num_fri_rounds);
        let mut f_evals_pos = Vec::with_capacity(params.num_fri_rounds);
        let mut f_evals_neg = Vec::with_capacity(params.num_fri_rounds);
        let mut f_evals_folded = Vec::with_capacity(params.num_fri_rounds);
        let mut folding_challenges = Vec::with_capacity(params.num_fri_rounds);

        for round in 0..params.num_fri_rounds {
            let sibling = query.fri_layer_odd_values.get(round).copied().unwrap_or(0);
            let next = query.fri_folded_values.get(round).copied().unwrap_or(0);
            let direction = query
                .fri_direction_bits
                .get(round)
                .copied()
                .unwrap_or(false);
            let (f_pos, f_neg) = if direction {
                (sibling, current)
            } else {
                (current, sibling)
            };

            x_values.push(query.fri_round_x_values.get(round).copied().unwrap_or(1));
            f_evals_pos.push(f_pos);
            f_evals_neg.push(f_neg);
            f_evals_folded.push(next);
            folding_challenges.push(witness.fri_alphas.get(round).copied().unwrap_or(0));
            current = next;
        }

        queries.push(NovaQueryWitness {
            query_index: query.query_index as u32,
            x_values,
            f_evals_pos,
            f_evals_neg,
            f_evals_folded,
            folding_challenges,
            merkle_path: query.merkle_siblings_8.clone(),
            round_commitments: witness
                .fri_commitment_roots_8
                .iter()
                .take(params.num_fri_rounds)
                .cloned()
                .collect(),
        });
    }

    if queries.len() != params.num_queries {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected {} query witnesses, found {}",
            params.num_queries,
            queries.len()
        )));
    }

    Ok(queries)
}

#[cfg(feature = "nova-compression")]
fn compressed_stark_proof_from_metadata(
    wrapped_proof: &ProofArtifact,
) -> ZkfResult<CompressedStarkProof> {
    use base64::Engine;

    let encoded = wrapped_proof
        .metadata
        .get("nova_compressed_stark_b64")
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "wrapped-v3 artifact missing 'nova_compressed_stark_b64' metadata".to_string(),
            )
        })?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| {
            ZkfError::InvalidArtifact(format!("Invalid base64 in nova_compressed_stark_b64: {e}"))
        })?;
    bincode::deserialize(&bytes).map_err(|e| {
        ZkfError::InvalidArtifact(format!(
            "Failed to deserialize compressed Nova proof metadata: {e}"
        ))
    })
}

fn record_wrapper_stage(
    stages: &mut serde_json::Map<String, serde_json::Value>,
    stage: &str,
    accelerator: &str,
    duration_ms: f64,
    inflight_jobs: usize,
    no_cpu_fallback: bool,
    fallback_reason: Option<&str>,
) {
    let mut value = serde_json::json!({
        "accelerator": accelerator,
        "duration_ms": duration_ms,
        "inflight_jobs": inflight_jobs,
        "no_cpu_fallback": no_cpu_fallback,
    });
    if let Some(reason) = fallback_reason
        && let serde_json::Value::Object(ref mut map) = value
    {
        map.insert(
            "fallback_reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
    stages.insert(stage.to_string(), value);
}

fn parse_metadata_usize(metadata: &BTreeMap<String, String>, key: &str) -> Option<usize> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
}

fn parse_metadata_bool(metadata: &BTreeMap<String, String>, key: &str) -> Option<bool> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<bool>().ok())
}

fn parse_metadata_f64(metadata: &BTreeMap<String, String>, key: &str) -> Option<f64> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn plonky3_seed(program_digest: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(program_digest.as_bytes());
    let hash = hasher.finalize();
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(seed_bytes)
}

// ---------------------------------------------------------------------------
// Helper: extract FRI params from proof metadata
// ---------------------------------------------------------------------------

fn extract_fri_params(source_proof: &ProofArtifact, p3_seed: u64) -> FriCircuitParams {
    // Try to deserialize the proof to get exact FRI parameters.
    if let Ok(stark_proof) = postcard::from_bytes::<GoldilocksStarkProof>(&source_proof.proof) {
        let degree_bits = stark_proof.degree_bits;
        let num_fri_rounds = stark_proof.opening_proof.commit_phase_commits.len();
        // These match create_test_fri_params in p3-fri (used by build_config_goldilocks):
        let log_blowup = 2;
        let num_queries = 2;
        let commit_pow_bits = 1;
        let query_pow_bits = 1;
        let merkle_tree_height = degree_bits + log_blowup;

        eprintln!(
            "extracted FRI params from proof: degree_bits={}, num_fri_rounds={}, merkle_height={}, num_queries={}",
            degree_bits, num_fri_rounds, merkle_tree_height, num_queries
        );

        return FriCircuitParams {
            num_queries,
            num_fri_rounds,
            log_degree: degree_bits,
            merkle_tree_height,
            poseidon2_seed: p3_seed,
            num_public_inputs: source_proof.public_inputs.len().max(1),
            commit_pow_bits,
            query_pow_bits,
            log_blowup,
            log_final_poly_len: 0,
            ..FriCircuitParams::default()
        };
    }

    // Fallback: parse from metadata or use defaults.
    let parse_meta = |key: &str, default: usize| -> usize {
        source_proof
            .metadata
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };

    FriCircuitParams {
        num_queries: parse_meta("fri_num_queries", 2),
        num_fri_rounds: parse_meta("fri_num_rounds", 2),
        log_degree: parse_meta("fri_log_degree", 4),
        merkle_tree_height: parse_meta("fri_merkle_height", 6),
        poseidon2_seed: p3_seed,
        num_public_inputs: source_proof
            .metadata
            .get("fri_num_public_inputs")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| source_proof.public_inputs.len().max(1)),
        commit_pow_bits: parse_meta("fri_commit_pow_bits", 1),
        query_pow_bits: parse_meta("fri_query_pow_bits", 1),
        log_blowup: parse_meta("fri_log_blowup", 2),
        log_final_poly_len: 0,
        ..FriCircuitParams::default()
    }
}

// ---------------------------------------------------------------------------
// Helper: build StarkProofWitness from raw proof bytes
// ---------------------------------------------------------------------------

fn build_witness_from_proof(
    proof_bytes: &[u8],
    public_inputs: &[zkf_core::FieldElement],
    params: &FriCircuitParams,
) -> StarkProofWitness {
    // Deserialize the real Plonky3 Goldilocks proof.
    if let Ok(stark_proof) = postcard::from_bytes::<GoldilocksStarkProof>(proof_bytes) {
        return extract_witness_from_stark_proof(&stark_proof, public_inputs, params);
    }

    // If deserialization fails, build a minimal witness from public inputs.
    // This path produces a witness that will satisfy circuit shape constraints
    // but may not produce a valid Groth16 proof for verification.
    let pub_inputs_u64: Vec<u64> = public_inputs
        .iter()
        .map(|fe| fe.to_decimal_string().parse::<u64>().unwrap_or(0))
        .collect();

    StarkProofWitness {
        fri_commitment_roots: vec![0u64; params.num_fri_rounds + 1],
        fri_alphas: vec![0u64; params.num_fri_rounds],
        queries: (0..params.num_queries)
            .map(|q| FriQueryWitness {
                merkle_siblings_8: vec![[0u64; 8]; params.merkle_tree_height],
                direction_bits: vec![false; params.merkle_tree_height],
                opened_value: 0,
                query_x: 1,
                query_index: q as u64,
                fri_layer_odd_values: vec![0; params.num_fri_rounds],
                fri_folded_values: vec![0; params.num_fri_rounds],
                fri_round_merkle_paths: Vec::new(),
                fri_direction_bits: vec![false; params.num_fri_rounds],
                fri_composed_value: 0,
                leaf_values: Vec::new(),
                fri_round_x_values: vec![1; params.num_fri_rounds],
            })
            .collect(),
        degree_bits: params.log_degree,
        public_inputs: pub_inputs_u64,
        ..Default::default()
    }
}

fn direct_fri_setup_circuit(params: &FriCircuitParams) -> FriVerifierCircuit {
    FriVerifierCircuit::for_setup(params.clone())
}

/// Extract a real StarkProofWitness from a deserialized Plonky3 proof.
fn extract_witness_from_stark_proof(
    proof: &GoldilocksStarkProof,
    public_inputs: &[zkf_core::FieldElement],
    params: &FriCircuitParams,
) -> StarkProofWitness {
    let degree_bits = proof.degree_bits;

    // Extract opened values from the proof
    let opened_trace_local: Vec<u64> = proof
        .opened_values
        .trace_local
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();

    let opened_trace_next: Vec<u64> = proof
        .opened_values
        .trace_next
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();

    let quotient_chunks: Vec<u64> = proof
        .opened_values
        .quotient_chunks
        .iter()
        .flat_map(|chunk| chunk.iter().map(|v| v.as_canonical_u64()))
        .collect();

    // Extract commitments as 8-element digests
    // Hash<Goldilocks, Goldilocks, 8> implements Into<[Goldilocks; 8]>
    use std::borrow::Borrow;
    let trace_commit_arr: &[Goldilocks; 8] = proof.commitments.trace.borrow();
    let trace_commitment: Vec<u64> = trace_commit_arr
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();

    let quotient_commit_arr: &[Goldilocks; 8] = proof.commitments.quotient_chunks.borrow();
    let quotient_commitment: Vec<u64> = quotient_commit_arr
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();

    // Extract FRI commitment roots as 8-element digests
    let fri_commitment_roots_8: Vec<[u64; 8]> = proof
        .opening_proof
        .commit_phase_commits
        .iter()
        .map(|commit| {
            let arr: &[Goldilocks; 8] = commit.borrow();
            std::array::from_fn(|i| arr[i].as_canonical_u64())
        })
        .collect();

    // Extract final polynomial coefficients and value
    let final_poly_coeffs: Vec<u64> = proof
        .opening_proof
        .final_poly
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect();
    let final_poly_value = final_poly_coeffs.first().copied().unwrap_or(0);

    // Extract PoW witnesses
    let commit_pow_witnesses: Vec<u64> = proof
        .opening_proof
        .commit_pow_witnesses
        .iter()
        .map(|w| w.as_canonical_u64())
        .collect();
    let query_pow_witness = proof.opening_proof.query_pow_witness.as_canonical_u64();

    let pub_inputs_u64: Vec<u64> = public_inputs
        .iter()
        .map(|fe| fe.to_decimal_string().parse::<u64>().unwrap_or(0))
        .collect();

    // Replay the Fiat-Shamir transcript natively to get alpha, zeta, fri_alpha, betas, query indices
    let (alpha, zeta, fri_batch_alpha, fri_betas, query_indices) = replay_fiat_shamir_transcript(
        params.poseidon2_seed,
        degree_bits,
        &trace_commitment,
        &quotient_commitment,
        &pub_inputs_u64,
        &fri_commitment_roots_8,
        params.num_queries,
        &commit_pow_witnesses,
        &final_poly_coeffs,
        query_pow_witness,
        params.commit_pow_bits,
        params.query_pow_bits,
        params.log_blowup,
        params.log_final_poly_len,
    );

    // Compute selector values from zeta
    let p = super::nonnative_goldilocks::GOLDILOCKS_PRIME as u128;
    let zeta_u128 = zeta as u128;
    let mut zeta_pow_n = zeta_u128;
    for _ in 0..degree_bits {
        zeta_pow_n = (zeta_pow_n * zeta_pow_n) % p;
    }
    let vanishing = if zeta_pow_n >= 1 {
        ((zeta_pow_n - 1) % p) as u64
    } else {
        ((zeta_pow_n + p - 1) % p) as u64
    };

    // inv_vanishing = modular_inverse(vanishing, p)
    let inv_vanishing = mod_inverse_goldilocks(vanishing);

    // is_first_row = vanishing / (n * (zeta - 1))
    let n = 1u64 << degree_bits;
    let zeta_minus_1 = if zeta >= 1 {
        ((zeta as u128 - 1) % p) as u64
    } else {
        ((zeta as u128 + p - 1) % p) as u64
    };
    let n_times_zm1 = ((n as u128 * zeta_minus_1 as u128) % p) as u64;
    let inv_n_zm1 = mod_inverse_goldilocks(n_times_zm1);
    let is_first_row = ((vanishing as u128 * inv_n_zm1 as u128) % p) as u64;

    // Legacy single-element commitment roots
    let fri_commitment_roots: Vec<u64> = fri_commitment_roots_8
        .iter()
        .map(|d| d[0])
        .chain(std::iter::once(0))
        .take(params.num_fri_rounds + 1)
        .collect();

    // FRI alphas from betas
    let fri_alphas: Vec<u64> = fri_betas.clone();

    // Extract per-query witnesses
    let num_available_queries = params
        .num_queries
        .min(proof.opening_proof.query_proofs.len());
    let queries: Vec<FriQueryWitness> = (0..params.num_queries)
        .map(|q| {
            let qi = query_indices.get(q).copied().unwrap_or(q as u64);
            if q < num_available_queries {
                extract_query_witness(
                    &proof.opening_proof.query_proofs[q],
                    &opened_trace_local,
                    &opened_trace_next,
                    &quotient_chunks,
                    params,
                    qi,
                    &fri_betas,
                    degree_bits,
                    zeta,
                    fri_batch_alpha,
                )
            } else {
                FriQueryWitness {
                    merkle_siblings_8: vec![[0u64; 8]; params.merkle_tree_height],
                    direction_bits: vec![false; params.merkle_tree_height],
                    opened_value: 0,
                    query_x: 1,
                    query_index: qi,
                    fri_layer_odd_values: vec![0; params.num_fri_rounds],
                    fri_folded_values: vec![0; params.num_fri_rounds],
                    fri_round_merkle_paths: Vec::new(),
                    fri_direction_bits: vec![false; params.num_fri_rounds],
                    fri_composed_value: 0,
                    leaf_values: Vec::new(),
                    fri_round_x_values: vec![1; params.num_fri_rounds],
                }
            }
        })
        .collect();

    StarkProofWitness {
        fri_commitment_roots,
        fri_alphas,
        queries,
        degree_bits,
        public_inputs: pub_inputs_u64,
        trace_local: opened_trace_local,
        trace_next: opened_trace_next,
        quotient_chunks,
        trace_commitment,
        quotient_commitment,
        zeta,
        alpha,
        is_first_row_at_zeta: is_first_row,
        inv_vanishing_at_zeta: inv_vanishing,
        final_poly_value,
        fri_commitment_roots_8,
        fri_batch_alpha,
        commit_pow_witnesses,
        query_pow_witness,
        final_poly: final_poly_coeffs,
    }
}

/// Replay the Plonky3 Fiat-Shamir transcript natively.
///
/// Returns (alpha, zeta, fri_batch_alpha, fri_betas, query_indices).
///
/// The transcript order matches `p3-uni-stark` v0.4.2 `verify()` →
/// `p3-fri` v0.4.2 `verify_fri()` exactly.
#[allow(clippy::too_many_arguments)]
fn replay_fiat_shamir_transcript(
    poseidon2_seed: u64,
    degree_bits: usize,
    trace_commitment: &[u64],
    quotient_commitment: &[u64],
    public_inputs: &[u64],
    fri_commitment_roots_8: &[[u64; 8]],
    num_queries: usize,
    commit_pow_witnesses: &[u64],
    final_poly: &[u64],
    query_pow_witness: u64,
    commit_pow_bits: usize,
    query_pow_bits: usize,
    log_blowup: usize,
    log_final_poly_len: usize,
) -> (u64, u64, u64, Vec<u64>, Vec<u64>) {
    use p3_challenger::{CanObserve, CanSample, CanSampleBits};
    use p3_field::PrimeCharacteristicRing;
    use rand09::SeedableRng;
    use rand09::rngs::SmallRng;

    let mut rng = SmallRng::seed_from_u64(poseidon2_seed);
    let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
    let mut challenger =
        p3_challenger::DuplexChallenger::<Goldilocks, Poseidon2Goldilocks<16>, 16, 8>::new(perm);

    // --- uni-stark verifier transcript (verifier.rs:278-308) ---

    // 1. observe(degree_bits)
    challenger.observe(Goldilocks::from_u64(degree_bits as u64));
    // 2. observe(degree_bits - is_zk) — is_zk=0 for ZKF, so same value
    challenger.observe(Goldilocks::from_u64(degree_bits as u64));
    // 3. observe(preprocessed_width = 0)
    challenger.observe(Goldilocks::ZERO);
    // 4. observe(trace_commitment[0..8])
    for &tc in trace_commitment {
        challenger.observe(Goldilocks::from_u64(tc));
    }
    // 5. observe_slice(public_inputs)
    for &pi in public_inputs {
        challenger.observe(Goldilocks::from_u64(pi));
    }
    // 6. sample → alpha (constraint combination challenge)
    let alpha: Goldilocks = challenger.sample();
    // 7. observe(quotient_commitment[0..8])
    for &qc in quotient_commitment {
        challenger.observe(Goldilocks::from_u64(qc));
    }
    // 8. sample → zeta (OOD evaluation point)
    let zeta: Goldilocks = challenger.sample();

    // --- pcs.verify → verify_fri transcript (fri/verifier.rs:84-140) ---

    // 9. sample → FRI batch alpha
    let fri_batch_alpha: Goldilocks = challenger.sample();

    // log_global_max_height = num_fri_rounds + log_blowup + log_final_poly_len
    let log_global_max_height = fri_commitment_roots_8.len() + log_blowup + log_final_poly_len;

    // 10. For each FRI commit round: observe commitment, check PoW, sample beta
    let mut fri_betas = Vec::with_capacity(fri_commitment_roots_8.len());
    for (round, root_8) in fri_commitment_roots_8.iter().enumerate() {
        // observe the commitment (8 Goldilocks elements = Hash<Goldilocks,Goldilocks,8>)
        for &elem in root_8 {
            challenger.observe(Goldilocks::from_u64(elem));
        }
        // check_witness(commit_pow_bits, witness) = observe(witness) + sample_bits(bits)
        if commit_pow_bits > 0 {
            let pow_w = commit_pow_witnesses.get(round).copied().unwrap_or(0);
            challenger.observe(Goldilocks::from_u64(pow_w));
            let _pow_check: usize = challenger.sample_bits(commit_pow_bits);
        }
        // sample beta
        let beta: Goldilocks = challenger.sample();
        fri_betas.push(beta.as_canonical_u64());
    }

    // 11. observe_slice(final_poly)
    for &fp in final_poly {
        challenger.observe(Goldilocks::from_u64(fp));
    }

    // 12. check_witness(query_pow_bits, query_pow_witness)
    if query_pow_bits > 0 {
        challenger.observe(Goldilocks::from_u64(query_pow_witness));
        let _pow_check: usize = challenger.sample_bits(query_pow_bits);
    }

    // 13. For each query: sample_bits(log_global_max_height) → index
    let query_indices: Vec<u64> = (0..num_queries)
        .map(|_| {
            let idx: usize = challenger.sample_bits(log_global_max_height);
            idx as u64
        })
        .collect();

    (
        alpha.as_canonical_u64(),
        zeta.as_canonical_u64(),
        fri_batch_alpha.as_canonical_u64(),
        fri_betas,
        query_indices,
    )
}

// ---------------------------------------------------------------------------
// Goldilocks native arithmetic helpers
// ---------------------------------------------------------------------------

const GL_P: u128 = super::nonnative_goldilocks::GOLDILOCKS_PRIME as u128;

fn goldilocks_add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % GL_P) as u64
}

fn goldilocks_sub(a: u64, b: u64) -> u64 {
    let (a128, b128) = (a as u128, b as u128);
    (if a128 >= b128 {
        a128 - b128
    } else {
        a128 + GL_P - b128
    } % GL_P) as u64
}

fn goldilocks_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % GL_P) as u64
}

fn goldilocks_pow(base: u64, exp: u64) -> u64 {
    let mut result = 1u128;
    let mut b = base as u128;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * b) % GL_P;
        }
        b = (b * b) % GL_P;
        e >>= 1;
    }
    result as u64
}

/// Compute modular inverse in Goldilocks field using Fermat's little theorem.
/// a^(-1) = a^(p-2) mod p
fn mod_inverse_goldilocks(a: u64) -> u64 {
    if a == 0 {
        return 0;
    }
    goldilocks_pow(a, super::nonnative_goldilocks::GOLDILOCKS_PRIME - 2)
}

/// Return the two-adic generator of order 2^bits in the Goldilocks field.
/// Goldilocks has 2-adicity 32 with root_of_unity = 7^((p-1)/2^32).
/// Generator for order 2^bits = root_of_unity ^ (2^(32-bits)).
fn goldilocks_two_adic_generator(bits: usize) -> u64 {
    // The primitive 2^32-th root of unity in Goldilocks.
    // p3_goldilocks uses this internally.
    let root_of_unity = p3_goldilocks::Goldilocks::two_adic_generator(32).as_canonical_u64();
    // Raise to 2^(32-bits) to get the generator of the subgroup of order 2^bits.
    let power = 1u64 << (32 - bits);
    goldilocks_pow(root_of_unity, power)
}

/// Bit-reverse `x` in a `bit_len`-bit field, matching p3_util::reverse_bits_len.
fn reverse_bits_len(x: usize, bit_len: usize) -> usize {
    if bit_len == 0 {
        return 0;
    }
    x.reverse_bits() >> (usize::BITS as usize - bit_len)
}

/// Goldilocks multiplicative generator (smallest generator of the full group).
/// In Plonky3 this is `Goldilocks::GENERATOR` = 7.
const GOLDILOCKS_MULTIPLICATIVE_GENERATOR: u64 = 7;

/// Compute the coset domain point for open_input:
///   x = GENERATOR * g_N^{reverse_bits_len(reduced_index, log_height)}
/// where GENERATOR=7 is the coset shift and g_N = two_adic_generator(log_height).
fn compute_coset_domain_point(reduced_index: usize, log_height: usize) -> u64 {
    let g = goldilocks_two_adic_generator(log_height);
    let rev_idx = reverse_bits_len(reduced_index, log_height);
    let g_pow = goldilocks_pow(g, rev_idx as u64);
    goldilocks_mul(GOLDILOCKS_MULTIPLICATIVE_GENERATOR, g_pow)
}

/// Compute fold_row matching Plonky3's TwoAdicFriFolding::fold_row exactly.
///
/// fold_row(index, log_height, beta, [e0, e1]):
///   subgroup_start = g_{log_height+1}^{reverse_bits_len(index, log_height)}
///   xs = [subgroup_start, -subgroup_start] (after reverse_slice_index_bits for arity=2)
///   result = e0 + (beta - xs[0]) * (e1 - e0) / (xs[1] - xs[0])
///
/// For arity=2, reverse_slice_index_bits swaps the two elements, so:
///   xs[0] = -subgroup_start, xs[1] = subgroup_start
fn fold_row(parent_index: usize, log_height: usize, beta: u64, e0: u64, e1: u64) -> u64 {
    let subgroup_start = goldilocks_pow(
        goldilocks_two_adic_generator(log_height + 1),
        reverse_bits_len(parent_index, log_height) as u64,
    );
    // After reverse_slice_index_bits for 2 elements: xs = [-subgroup_start, subgroup_start]
    let xs0 = goldilocks_sub(0, subgroup_start); // -subgroup_start
    let xs1 = subgroup_start;
    // e0 + (beta - xs0) * (e1 - e0) / (xs1 - xs0)
    let denom = goldilocks_sub(xs1, xs0); // = 2 * subgroup_start
    let inv_denom = mod_inverse_goldilocks(denom);
    let numer = goldilocks_mul(goldilocks_sub(beta, xs0), goldilocks_sub(e1, e0));
    goldilocks_add(e0, goldilocks_mul(numer, inv_denom))
}

/// Extract witness data from a single FRI query proof.
///
/// This implements the verifier's perspective of Plonky3 FRI:
/// 1. Extract leaf values from input_proof for Merkle verification
/// 2. Compute the alpha-composed reduced opening (FRI initial value)
/// 3. For each FRI round, handle even/odd swap and fold_row with correct domain points
#[allow(clippy::too_many_arguments)]
fn extract_query_witness(
    query_proof: &p3_fri::QueryProof<
        Goldilocks,
        GoldilocksChallengeMmcs,
        Vec<p3_commit::BatchOpening<<Goldilocks as Field>::Packing, GoldilocksValMmcs>>,
    >,
    opened_trace_local: &[u64],
    opened_trace_next: &[u64],
    quotient_chunks: &[u64],
    params: &FriCircuitParams,
    query_index: u64,
    fri_betas: &[u64],
    degree_bits: usize,
    zeta: u64,
    fri_batch_alpha: u64,
) -> FriQueryWitness {
    let height = params.merkle_tree_height;
    let num_rounds = params.num_fri_rounds;
    let log_blowup = params.log_blowup;
    let log_final_poly_len = params.log_final_poly_len;
    let log_global_max_height = num_rounds + log_blowup + log_final_poly_len;

    // --- Trace Merkle siblings from input_proof[0].opening_proof ---
    let siblings_8: Vec<[u64; 8]> = if let Some(batch_opening) = query_proof.input_proof.first() {
        batch_opening
            .opening_proof
            .iter()
            .map(|sibling_digest| std::array::from_fn(|i| sibling_digest[i].as_canonical_u64()))
            .collect()
    } else {
        vec![[0u64; 8]; height]
    };
    // Pad or truncate to expected height
    let siblings_8: Vec<[u64; 8]> = siblings_8
        .into_iter()
        .chain(std::iter::repeat([0u64; 8]))
        .take(height)
        .collect();

    // Direction bits derived from query index (for trace Merkle tree)
    let direction_bits: Vec<bool> = (0..height).map(|l| ((query_index >> l) & 1) == 1).collect();

    // --- Extract all leaf values from input_proof ---
    // The first batch is trace, second is quotient (if present).
    let mut all_leaf_values: Vec<u64> = Vec::new();

    // Trace leaf values (all columns at the query position)
    let trace_leaf_values: Vec<u64> = query_proof
        .input_proof
        .first()
        .and_then(|bo| bo.opened_values.first())
        .map(|row| row.iter().map(|v| v.as_canonical_u64()).collect())
        .unwrap_or_default();
    all_leaf_values.extend_from_slice(&trace_leaf_values);

    // First opened value (for backward compat / Merkle leaf hash)
    let opened_value = trace_leaf_values.first().copied().unwrap_or(0);

    // --- Compute alpha-composed reduced opening (open_input logic) ---
    // This matches p3-fri/verifier.rs open_input().
    // For is_zk=false with Plonky3:
    //   Batch 0 (trace): opened at (zeta, trace_local) and (zeta_next, trace_next)
    //   Batch 1 (quotient): opened at (zeta, quotient_chunks)
    let mut alpha_pow = 1u64; // alpha^0
    let mut reduced_opening = 0u64;

    // Trace batch: log_height = degree_bits + log_blowup
    let trace_log_height = degree_bits + log_blowup;
    let trace_bits_reduced = log_global_max_height - trace_log_height;
    let trace_reduced_index = (query_index as usize) >> trace_bits_reduced;
    let x_trace = compute_coset_domain_point(trace_reduced_index, trace_log_height);

    // zeta_next = zeta * g where g = two_adic_generator(degree_bits)
    let g_trace = goldilocks_two_adic_generator(degree_bits);
    let zeta_next = goldilocks_mul(zeta, g_trace);

    // Opening point 1: zeta, claimed values = trace_local
    {
        let quotient_z = mod_inverse_goldilocks(goldilocks_sub(zeta, x_trace));
        for (i, &p_at_z) in opened_trace_local.iter().enumerate() {
            let p_at_x = trace_leaf_values.get(i).copied().unwrap_or(0);
            let diff = goldilocks_sub(p_at_z, p_at_x);
            let term = goldilocks_mul(goldilocks_mul(alpha_pow, diff), quotient_z);
            reduced_opening = goldilocks_add(reduced_opening, term);
            alpha_pow = goldilocks_mul(alpha_pow, fri_batch_alpha);
        }
    }

    // Opening point 2: zeta_next, claimed values = trace_next
    {
        let quotient_z = mod_inverse_goldilocks(goldilocks_sub(zeta_next, x_trace));
        for (i, &p_at_z) in opened_trace_next.iter().enumerate() {
            let p_at_x = trace_leaf_values.get(i).copied().unwrap_or(0);
            let diff = goldilocks_sub(p_at_z, p_at_x);
            let term = goldilocks_mul(goldilocks_mul(alpha_pow, diff), quotient_z);
            reduced_opening = goldilocks_add(reduced_opening, term);
            alpha_pow = goldilocks_mul(alpha_pow, fri_batch_alpha);
        }
    }

    // Quotient batch: each quotient chunk is a separate matrix opened at zeta
    // In Plonky3, quotient chunks may have different heights due to domain splitting.
    // For simplicity with num_quotient_chunks=1, they share trace_log_height.
    if let Some(quotient_batch) = query_proof.input_proof.get(1) {
        // Each matrix in the quotient batch
        for (mat_idx, mat_opening) in quotient_batch.opened_values.iter().enumerate() {
            let mat_leaf_values: Vec<u64> =
                mat_opening.iter().map(|v| v.as_canonical_u64()).collect();
            all_leaf_values.extend_from_slice(&mat_leaf_values);

            // Quotient matrices use the same log_height as trace for is_zk=false
            let q_log_height = trace_log_height;
            let q_bits_reduced = log_global_max_height - q_log_height;
            let q_reduced_index = (query_index as usize) >> q_bits_reduced;
            let x_q = compute_coset_domain_point(q_reduced_index, q_log_height);

            let quotient_z = mod_inverse_goldilocks(goldilocks_sub(zeta, x_q));
            // claimed values from opened_values (the OOD evaluations)
            let num_qc_per_mat = if params.num_quotient_chunks > 0 { 1 } else { 0 };
            let qc_start = mat_idx * num_qc_per_mat;
            for (j, &p_at_x) in mat_leaf_values.iter().enumerate() {
                let p_at_z = quotient_chunks.get(qc_start + j).copied().unwrap_or(0);
                let diff = goldilocks_sub(p_at_z, p_at_x);
                let term = goldilocks_mul(goldilocks_mul(alpha_pow, diff), quotient_z);
                reduced_opening = goldilocks_add(reduced_opening, term);
                alpha_pow = goldilocks_mul(alpha_pow, fri_batch_alpha);
            }
        }
    }

    // Compute the domain point for FRI (the initial query_x before folding)
    // This is g_{log_global_max_height}^{reverse_bits_len(query_index, log_global_max_height)}
    // but we primarily need it for the circuit witness; the actual FRI folding
    // uses per-round domain points computed in fold_row.
    let query_x = goldilocks_pow(
        goldilocks_two_adic_generator(log_global_max_height),
        reverse_bits_len(query_index as usize, log_global_max_height) as u64,
    );

    // --- FRI folding with correct even/odd swap and fold_row ---
    let mut fri_layer_odd_values = Vec::with_capacity(num_rounds);
    let mut fri_folded_values = Vec::with_capacity(num_rounds);
    let mut fri_round_merkle_paths = Vec::with_capacity(num_rounds);
    let mut fri_direction_bits = Vec::with_capacity(num_rounds);
    let mut fri_round_x_values = Vec::with_capacity(num_rounds);

    let mut fri_index = query_index as usize;
    let mut f_current = reduced_opening;

    for round in 0..num_rounds {
        let log_folded_height = log_global_max_height - round - 1;

        // FRI sibling value
        let sibling_val = if round < query_proof.commit_phase_openings.len() {
            query_proof.commit_phase_openings[round]
                .sibling_value
                .as_canonical_u64()
        } else {
            0
        };

        // Even/odd swap based on LSB of fri_index (matches verifier.rs:271-274)
        let index_sibling = fri_index ^ 1;
        let lsb = index_sibling % 2; // if fri_index LSB=0, index_sibling LSB=1
        let e0 = if lsb == 0 { sibling_val } else { f_current };
        let e1 = if lsb == 0 { f_current } else { sibling_val };

        // Track direction for circuit
        fri_direction_bits.push((fri_index & 1) == 1);

        // Store the sibling value (f_odd in circuit parlance)
        fri_layer_odd_values.push(sibling_val);

        // Shift index to parent
        fri_index >>= 1;

        // fold_row with parent_index = fri_index, matching TwoAdicFriFolding
        let beta = fri_betas.get(round).copied().unwrap_or(0);
        let f_next = fold_row(fri_index, log_folded_height, beta, e0, e1);
        fri_folded_values.push(f_next);

        // Store the subgroup_start for this round (used as witness in circuit)
        let subgroup_start = goldilocks_pow(
            goldilocks_two_adic_generator(log_folded_height + 1),
            reverse_bits_len(fri_index, log_folded_height) as u64,
        );
        fri_round_x_values.push(subgroup_start);

        // FRI round commitment Merkle path
        let round_path: Vec<[u64; 8]> = if round < query_proof.commit_phase_openings.len() {
            query_proof.commit_phase_openings[round]
                .opening_proof
                .iter()
                .map(|sibling_digest| std::array::from_fn(|i| sibling_digest[i].as_canonical_u64()))
                .collect()
        } else {
            Vec::new()
        };
        fri_round_merkle_paths.push(round_path);

        f_current = f_next;
    }

    FriQueryWitness {
        merkle_siblings_8: siblings_8,
        direction_bits,
        opened_value,
        query_x,
        query_index,
        fri_layer_odd_values,
        fri_folded_values,
        fri_round_merkle_paths,
        fri_direction_bits,
        fri_composed_value: reduced_opening,
        leaf_values: all_leaf_values,
        fri_round_x_values,
    }
}

// ---------------------------------------------------------------------------
// Helper: Groth16 setup (with cache)
// ---------------------------------------------------------------------------

fn setup_cache_key(program_digest: &str, params: &FriCircuitParams) -> String {
    format!(
        "direct-shape-v3-{}-q{}-r{}-d{}-h{}-s{}-p{}-tw{}-ac{}-qc{}",
        program_digest,
        params.num_queries,
        params.num_fri_rounds,
        params.log_degree,
        params.merkle_tree_height,
        params.poseidon2_seed,
        params.num_public_inputs,
        params.trace_width,
        params.air_constraints.len(),
        params.num_quotient_chunks,
    )
}

#[cfg(feature = "nova-compression")]
fn nova_setup_cache_key(program_digest: &str, compressed: &CompressedStarkProof) -> String {
    format!(
        "{}-nova-q{}-r{}-d{}-w{}-pp{}",
        program_digest,
        compressed.num_queries,
        compressed.num_fri_rounds,
        compressed.max_depth,
        compressed.leaf_width,
        compressed.pp_hash,
    )
}

fn default_setup_disk_cache_base_root() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".zkf").join("cache"))
        .unwrap_or_else(std::env::temp_dir)
}

fn setup_disk_cache_root() -> PathBuf {
    std::env::var_os("ZKF_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_setup_disk_cache_base_root)
        .join("stark-to-groth16")
}

fn setup_disk_cache_paths(cache_key: &str) -> (PathBuf, PathBuf, PathBuf) {
    let digest = Sha256::digest(cache_key.as_bytes());
    let id = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = setup_disk_cache_root();
    (
        root.join(format!("{id}.pk")),
        root.join(format!("{id}.vk")),
        root.join(format!("{id}.shape")),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupCacheState {
    Missing,
    LegacyCompressed,
    FastMissingShape,
    Ready,
}

impl SetupCacheState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::LegacyCompressed => "legacy-compressed",
            Self::FastMissingShape => "fast-missing-shape",
            Self::Ready => "ready",
        }
    }

    fn requires_prepare(self) -> bool {
        !matches!(self, Self::Ready)
    }

    fn shape_cache_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    fn pk_format_hint(self) -> Option<&'static str> {
        match self {
            Self::Missing => None,
            Self::LegacyCompressed => Some("legacy-compressed-v1"),
            Self::FastMissingShape | Self::Ready => Some("fast-uncompressed-v2"),
        }
    }

    fn preview_detail(self) -> Option<&'static str> {
        match self {
            Self::Missing => Some(
                "strict direct wrap requires an operator cache warmup; run `zkf runtime prepare --proof <proof.json> --compiled <compiled.json>` before `zkf wrap`",
            ),
            Self::LegacyCompressed => Some(
                "strict direct wrap is blocked on a legacy setup cache migration; run `zkf runtime prepare --proof <proof.json> --compiled <compiled.json>` before `zkf wrap`",
            ),
            Self::FastMissingShape => Some(
                "strict direct wrap is blocked on prove-shape materialization; run `zkf runtime prepare --proof <proof.json> --compiled <compiled.json>` before `zkf wrap`",
            ),
            Self::Ready => None,
        }
    }
}

fn preview_cache_state(
    source_proof: &ProofArtifact,
    fri_params: &FriCircuitParams,
    plan: &WrapPlan,
) -> ZkfResult<Option<SetupCacheState>> {
    if plan.strategy != WrapStrategy::DirectFriV2
        || plan.estimated_memory_bytes < DIRECT_WRAP_PREP_REQUIRED_BYTES
    {
        return Ok(None);
    }

    let cache_key = setup_cache_key(&source_proof.program_digest, fri_params);
    Ok(Some(probe_setup_cache_state(&cache_key)?))
}

fn preview_reason(plan: &WrapPlan, cache_state: Option<SetupCacheState>) -> String {
    match cache_state.and_then(SetupCacheState::preview_detail) {
        Some(detail) => format!("{}; {}", plan.reason, detail),
        None => plan.reason.clone(),
    }
}

fn blocked_large_direct_prepare_report(
    plan: &WrapPlan,
    cache_state: SetupCacheState,
    policy: WrapperExecutionPolicy,
) -> Option<WrapperCachePrepareReport> {
    if plan.strategy != WrapStrategy::DirectFriV2
        || plan.estimated_memory_bytes < DIRECT_WRAP_PREP_REQUIRED_BYTES
        || !cache_state.requires_prepare()
        || policy.allow_large_direct_materialization
    {
        return None;
    }

    let blocked_reason = format!(
        "large strict direct wrapper cache preparation is disabled by default because setup_cache_state={} would materialize verifier setup data for an estimated {}-constraint circuit (memory_estimate={} bytes); install a prepared fast+shape cache or rerun `zkf runtime prepare {} --proof <proof.json> --compiled <compiled.json>` on the certified host if you accept high memory pressure",
        cache_state.as_str(),
        plan.estimated_constraints,
        plan.estimated_memory_bytes,
        DIRECT_WRAP_PREP_OVERRIDE_FLAG,
    );

    Some(WrapperCachePrepareReport {
        wrapper: "stark-to-groth16".to_string(),
        source_backend: BackendKind::Plonky3,
        target_backend: BackendKind::ArkworksGroth16,
        strategy: plan.strategy.as_str().to_string(),
        trust_model: plan.strategy.trust_model().to_string(),
        setup_cache_ready: false,
        shape_cache_ready: Some(cache_state.shape_cache_ready()),
        setup_cache_pk_format: cache_state.pk_format_hint().map(str::to_string),
        setup_cache_pk_migrated: false,
        blocked: true,
        setup_cache_state: Some(cache_state.as_str().to_string()),
        blocked_reason: Some(blocked_reason),
        operator_action: Some(format!(
            "install a prepared fast+shape cache, or rerun `zkf runtime prepare {} --proof <proof.json> --compiled <compiled.json>` on the certified host only if you accept high memory pressure",
            DIRECT_WRAP_PREP_OVERRIDE_FLAG,
        )),
        detail: Some(plan.reason.clone()),
    })
}

fn direct_wrap_cache_bundle_expectation(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    policy: WrapperExecutionPolicy,
) -> ZkfResult<DirectWrapCacheBundleExpectation> {
    StarkToGroth16Wrapper::validate_wrap_inputs(source_proof, source_compiled)?;
    let wrapper = StarkToGroth16Wrapper;
    let fri_params = wrapper.derive_fri_params(source_proof, source_compiled)?;
    let plan = choose_wrap_plan(&fri_params, policy)?;
    if plan.strategy != WrapStrategy::DirectFriV2 {
        return Err(ZkfError::Backend(format!(
            "wrapper cache bundles are only supported for strict direct-fri-v2 wraps, got strategy={}",
            plan.strategy.as_str()
        )));
    }
    let cache_key = setup_cache_key(&source_proof.program_digest, &fri_params);
    Ok(DirectWrapCacheBundleExpectation {
        wrapper: "stark-to-groth16".to_string(),
        source_backend: BackendKind::Plonky3,
        target_backend: BackendKind::ArkworksGroth16,
        strategy: plan.strategy.as_str().to_string(),
        trust_model: plan.strategy.trust_model().to_string(),
        cache_key,
        source_program_digest: source_proof.program_digest.clone(),
        compiled_program_digest: source_compiled.program_digest.clone(),
    })
}

fn ready_direct_wrap_cache_bundle_manifest(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    policy: WrapperExecutionPolicy,
    hardware_profile: &str,
) -> ZkfResult<WrapperCacheBundleManifest> {
    let expected = direct_wrap_cache_bundle_expectation(source_proof, source_compiled, policy)?;
    let cache_key = expected.cache_key.clone();
    let cache_state = probe_setup_cache_state(&cache_key)?;
    if cache_state != SetupCacheState::Ready {
        return Err(ZkfError::Backend(format!(
            "wrapper cache bundle export/install requires setup_cache_state=ready, found {}; run `zkf runtime prepare` on the certified host or install a prepared bundle first",
            cache_state.as_str()
        )));
    }
    let source_paths = direct_wrap_cache_source_paths(&cache_key)?;
    let files = WrapperCacheBundleFiles {
        proving_key: bundle_file_info("proving-key.bin", &source_paths.0)?,
        verifying_key: bundle_file_info("verifying-key.bin", &source_paths.1)?,
        prove_shape: bundle_file_info("prove-shape.bin", &source_paths.2)?,
    };

    Ok(WrapperCacheBundleManifest {
        bundle_schema: "zkf-wrapper-cache-bundle-v1".to_string(),
        wrapper: expected.wrapper,
        source_backend: expected.source_backend,
        target_backend: expected.target_backend,
        strategy: expected.strategy,
        trust_model: expected.trust_model,
        cache_key: expected.cache_key,
        cache_state: cache_state.as_str().to_string(),
        source_program_digest: expected.source_program_digest,
        compiled_program_digest: expected.compiled_program_digest,
        hardware_profile: hardware_profile.to_string(),
        setup_cache_pk_format: "fast-uncompressed-v2".to_string(),
        shape_cache_ready: true,
        files,
    })
}

fn direct_wrap_cache_source_paths(cache_key: &str) -> ZkfResult<(PathBuf, PathBuf, PathBuf)> {
    let (pk_path, vk_path, shape_path) = setup_disk_cache_paths(cache_key);
    if !pk_path.is_file() || !vk_path.is_file() || !shape_path.is_file() {
        return Err(ZkfError::Backend(format!(
            "wrapper cache bundle expects ready cache files for key {}",
            cache_key
        )));
    }
    Ok((pk_path, vk_path, shape_path))
}

fn bundle_file_info(file_name: &str, path: &Path) -> ZkfResult<WrapperCacheBundleFile> {
    let bytes = fs::read(path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to read wrapper cache file {}: {err}",
            path.display()
        ))
    })?;
    let size_bytes = u64::try_from(bytes.len()).map_err(|_| {
        ZkfError::Backend(format!(
            "Wrapper cache file is too large to describe on this platform: {}",
            path.display()
        ))
    })?;
    Ok(WrapperCacheBundleFile {
        file_name: file_name.to_string(),
        size_bytes,
        sha256: sha256_hex_bytes(&bytes),
    })
}

fn validate_cache_bundle_manifest(
    manifest: &WrapperCacheBundleManifest,
    expected: &DirectWrapCacheBundleExpectation,
) -> ZkfResult<()> {
    if manifest.bundle_schema != "zkf-wrapper-cache-bundle-v1" {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported wrapper cache bundle schema: {}",
            manifest.bundle_schema
        )));
    }
    if manifest.wrapper != expected.wrapper
        || manifest.source_backend != expected.source_backend
        || manifest.target_backend != expected.target_backend
        || manifest.strategy != expected.strategy
        || manifest.trust_model != expected.trust_model
    {
        return Err(ZkfError::InvalidArtifact(
            "wrapper cache bundle does not match the required strict direct wrapper lane"
                .to_string(),
        ));
    }
    if manifest.cache_key != expected.cache_key {
        return Err(ZkfError::InvalidArtifact(format!(
            "wrapper cache bundle cache_key mismatch: expected {}, found {}",
            expected.cache_key, manifest.cache_key
        )));
    }
    if manifest.source_program_digest != expected.source_program_digest
        || manifest.compiled_program_digest != expected.compiled_program_digest
    {
        return Err(ZkfError::InvalidArtifact(
            "wrapper cache bundle program digest does not match the requested proof/compiled inputs"
                .to_string(),
        ));
    }
    if manifest.cache_state != SetupCacheState::Ready.as_str()
        || !manifest.shape_cache_ready
        || manifest.setup_cache_pk_format != "fast-uncompressed-v2"
    {
        return Err(ZkfError::InvalidArtifact(
            "wrapper cache bundle is not a ready fast-uncompressed-v2 direct-wrap cache"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_bundle_file(bundle_dir: &Path, entry: &WrapperCacheBundleFile) -> ZkfResult<()> {
    let path = bundle_dir.join(&entry.file_name);
    let bytes = fs::read(&path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to read wrapper cache bundle file {}: {err}",
            path.display()
        ))
    })?;
    let actual_size = u64::try_from(bytes.len()).map_err(|_| {
        ZkfError::Backend(format!(
            "Wrapper cache bundle file is too large to describe on this platform: {}",
            path.display()
        ))
    })?;
    if actual_size != entry.size_bytes {
        return Err(ZkfError::InvalidArtifact(format!(
            "wrapper cache bundle file size mismatch for {}: expected {}, found {}",
            path.display(),
            entry.size_bytes,
            actual_size
        )));
    }
    let actual_sha256 = sha256_hex_bytes(&bytes);
    if actual_sha256 != entry.sha256 {
        return Err(ZkfError::InvalidArtifact(format!(
            "wrapper cache bundle digest mismatch for {}",
            path.display()
        )));
    }
    Ok(())
}

fn probe_setup_cache_state(cache_key: &str) -> ZkfResult<SetupCacheState> {
    let (pk_path, vk_path, shape_path) = setup_disk_cache_paths(cache_key);
    if !pk_path.is_file() || !vk_path.is_file() {
        return Ok(SetupCacheState::Missing);
    }
    let mut file = File::open(&pk_path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open proving key cache '{}' for probe: {err}",
            pk_path.display()
        ))
    })?;
    let mut header = [0u8; SETUP_PK_CACHE_MAGIC.len()];
    let is_fast_format = match file.read_exact(&mut header) {
        Ok(()) => header == *SETUP_PK_CACHE_MAGIC,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(err) => {
            return Err(ZkfError::Backend(format!(
                "Failed to read proving key cache header '{}': {err}",
                pk_path.display()
            )));
        }
    };
    if !is_fast_format {
        return Ok(SetupCacheState::LegacyCompressed);
    }
    if !streamed_groth16_shape_file_is_ready(&shape_path)? {
        return Ok(SetupCacheState::FastMissingShape);
    }
    Ok(SetupCacheState::Ready)
}

fn effective_wrap_mode(policy: WrapperExecutionPolicy) -> String {
    if let Some(mode) = policy.force_mode {
        return mode.as_str().to_string();
    }
    if !policy.honor_env_overrides {
        return "auto".to_string();
    }

    std::env::var("ZKF_WRAP_MODE")
        .unwrap_or_else(|_| "auto".to_string())
        .to_ascii_lowercase()
}

fn wrapped_artifact_cache_key(
    source_proof: &ProofArtifact,
    source_compiled: &CompiledProgram,
    plan: &WrapPlan,
    policy: WrapperExecutionPolicy,
) -> ZkfResult<String> {
    let mut hasher = Sha256::new();
    let wrap_mode = effective_wrap_mode(policy);
    let resources = SystemResources::detect();
    hasher.update(b"zkf-stark-to-groth16-artifact-cache-v2:");
    hasher.update(wrap_mode.as_bytes());
    hasher.update(b":");
    hasher.update(plan.strategy.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(plan.estimated_constraints.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(plan.estimated_memory_bytes.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(
        plan.memory_budget_bytes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string())
            .as_bytes(),
    );
    hasher.update(b":");
    hasher.update(detected_hardware_profile_label(&resources).as_bytes());
    hasher.update(b":");
    hasher.update(source_proof.program_digest.as_bytes());
    hasher.update(b":");
    hasher.update(source_compiled.program_digest.as_bytes());
    hasher.update(b":");
    hasher.update(&source_proof.proof);
    hasher.update(b":");
    let metadata_bytes = serde_json::to_vec(&source_proof.metadata).map_err(|err| {
        ZkfError::Serialization(format!(
            "Failed to serialize STARK wrapper source metadata for cache key: {err}"
        ))
    })?;
    hasher.update(&metadata_bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn wrapped_artifact_disk_cache_path(cache_key: &str) -> PathBuf {
    setup_disk_cache_root()
        .join("artifacts")
        .join(format!("{cache_key}.bin"))
}

fn wrapped_artifact_requires_certified_strict_health(metadata: &BTreeMap<String, String>) -> bool {
    metadata.get("status").map(String::as_str) == Some("wrapped-v2")
        && metadata.get("trust_model").map(String::as_str) == Some("cryptographic")
        && metadata.get("wrapper_strategy").map(String::as_str) == Some("direct-fri-v2")
        && metadata
            .get("runtime_detected_hardware_profile")
            .or_else(|| metadata.get("runtime_hardware_profile"))
            .map(String::as_str)
            == Some("apple-silicon-m4-max-48gb")
}

fn wrapped_artifact_is_certified_strict_healthy(metadata: &BTreeMap<String, String>) -> bool {
    if !wrapped_artifact_requires_certified_strict_health(metadata) {
        return true;
    }

    parse_metadata_bool(metadata, "metal_dispatch_circuit_open") == Some(false)
        && parse_metadata_bool(metadata, "target_groth16_metal_dispatch_circuit_open")
            == Some(false)
        && parse_metadata_bool(metadata, "metal_no_cpu_fallback") == Some(true)
        && metadata
            .get("qap_witness_map_fallback_state")
            .map(String::as_str)
            .unwrap_or("cpu-only")
            == "none"
        && metadata
            .get("metal_dispatch_last_failure")
            .map(String::as_str)
            .unwrap_or_default()
            .is_empty()
        && metadata
            .get("target_groth16_metal_dispatch_last_failure")
            .map(String::as_str)
            .unwrap_or_default()
            .is_empty()
        && metadata
            .get("groth16_msm_fallback_state")
            .map(String::as_str)
            .unwrap_or("cpu-only")
            == "none"
}

fn validate_wrapped_artifact_health(artifact: &ProofArtifact) -> ZkfResult<()> {
    if wrapped_artifact_is_certified_strict_healthy(&artifact.metadata) {
        return Ok(());
    }

    let metadata = &artifact.metadata;
    Err(ZkfError::Backend(format!(
        "certified strict wrap completed with degraded Metal execution; refusing artifact because the final run opened the Metal dispatch circuit or fell back to CPU (metal_dispatch_circuit_open={}, target_groth16_metal_dispatch_circuit_open={}, metal_no_cpu_fallback={}, qap_witness_map_fallback_state={}, groth16_msm_fallback_state={}, groth16_msm_reason={}, groth16_msm_dispatch_failure={}, metal_dispatch_last_failure={}, target_groth16_metal_dispatch_last_failure={})",
        metadata
            .get("metal_dispatch_circuit_open")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("target_groth16_metal_dispatch_circuit_open")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("metal_no_cpu_fallback")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("qap_witness_map_fallback_state")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("groth16_msm_fallback_state")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("groth16_msm_reason")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("groth16_msm_dispatch_failure")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("metal_dispatch_last_failure")
            .map(String::as_str)
            .unwrap_or("missing"),
        metadata
            .get("target_groth16_metal_dispatch_last_failure")
            .map(String::as_str)
            .unwrap_or("missing"),
    )))
}

fn load_wrapped_artifact_from_memory(cache_key: &str) -> ZkfResult<Option<ProofArtifact>> {
    let mut cache = WRAPPED_ARTIFACT_CACHE
        .lock()
        .map_err(|_| ZkfError::Backend("Wrapped artifact cache lock poisoned".to_string()))?;
    Ok(cache
        .get_cloned(cache_key)
        .map(upgrade_cached_wrapped_artifact_metadata)
        .filter(|artifact| wrapped_artifact_is_certified_strict_healthy(&artifact.metadata)))
}

fn store_wrapped_artifact_in_memory(cache_key: &str, artifact: &ProofArtifact) -> ZkfResult<()> {
    let mut cache = WRAPPED_ARTIFACT_CACHE
        .lock()
        .map_err(|_| ZkfError::Backend("Wrapped artifact cache lock poisoned".to_string()))?;
    cache.insert(cache_key.to_string(), artifact.clone());
    Ok(())
}

fn load_wrapped_artifact_from_disk(cache_key: &str) -> ZkfResult<Option<ProofArtifact>> {
    let path = wrapped_artifact_disk_cache_path(cache_key);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    match bincode::deserialize::<ProofArtifact>(&bytes) {
        Ok(artifact) => {
            let upgraded = upgrade_cached_wrapped_artifact_metadata(artifact);
            if !wrapped_artifact_is_certified_strict_healthy(&upgraded.metadata) {
                let _ = fs::remove_file(&path);
                return Ok(None);
            }
            let upgraded_bytes = bincode::serialize(&upgraded).map_err(|err| {
                ZkfError::Serialization(format!(
                    "Failed to serialize upgraded wrapped proof artifact cache entry: {err}"
                ))
            })?;
            if upgraded_bytes != bytes {
                fs::write(&path, upgraded_bytes).map_err(|e| {
                    ZkfError::Backend(format!(
                        "Failed to rewrite upgraded wrapped proof artifact cache: {e}"
                    ))
                })?;
            }
            Ok(Some(upgraded))
        }
        Err(_) => {
            let _ = fs::remove_file(&path);
            Ok(None)
        }
    }
}

fn persist_wrapped_artifact(cache_key: &str, artifact: &ProofArtifact) -> ZkfResult<()> {
    if !wrapped_artifact_is_certified_strict_healthy(&artifact.metadata) {
        return Ok(());
    }
    let path = wrapped_artifact_disk_cache_path(cache_key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            ZkfError::Backend(format!("Failed to create wrapped artifact cache dir: {e}"))
        })?;
    }
    let bytes = bincode::serialize(artifact).map_err(|err| {
        ZkfError::Serialization(format!(
            "Failed to serialize wrapped proof artifact cache entry: {err}"
        ))
    })?;
    fs::write(&path, bytes).map_err(|e| {
        ZkfError::Backend(format!("Failed to write wrapped proof artifact cache: {e}"))
    })?;
    Ok(())
}

fn mark_wrapped_artifact_cache_hit(mut artifact: ProofArtifact, source: &str) -> ProofArtifact {
    artifact = upgrade_cached_wrapped_artifact_metadata(artifact);
    artifact
        .metadata
        .insert("wrapper_cache_hit".to_string(), "true".to_string());
    artifact
        .metadata
        .insert("wrapper_cache_source".to_string(), source.to_string());
    artifact
}

fn upgrade_cached_wrapped_artifact_metadata(mut artifact: ProofArtifact) -> ProofArtifact {
    append_default_metal_telemetry(&mut artifact.metadata);

    let mut target_defaults = BTreeMap::new();
    append_default_metal_telemetry(&mut target_defaults);
    for (key, value) in target_defaults {
        artifact
            .metadata
            .entry(format!("target_groth16_{key}"))
            .or_insert(value);
    }

    if !artifact.metadata.contains_key("gpu_stage_busy_ratio")
        && let Some(value) = artifact
            .metadata
            .get("target_groth16_metal_gpu_busy_ratio")
            .cloned()
            .or_else(|| artifact.metadata.get("metal_gpu_busy_ratio").cloned())
    {
        artifact
            .metadata
            .insert("gpu_stage_busy_ratio".to_string(), value);
    }
    for (top_key, target_key) in [
        (
            "qap_witness_map_engine",
            "target_groth16_qap_witness_map_engine",
        ),
        (
            "qap_witness_map_parallelism",
            "target_groth16_qap_witness_map_parallelism",
        ),
    ] {
        if !artifact.metadata.contains_key(top_key)
            && let Some(value) = artifact.metadata.get(target_key).cloned()
        {
            artifact.metadata.insert(top_key.to_string(), value);
        }
    }
    if !artifact.metadata.contains_key("qap_witness_map_reason")
        && let Some(value) = artifact
            .metadata
            .get("target_groth16_qap_witness_map_reason")
            .cloned()
            .or_else(|| {
                artifact
                    .metadata
                    .get("target_groth16_metal_stage_breakdown")
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                    .and_then(|value| {
                        value
                            .get("witness_map")
                            .and_then(|stage| stage.get("fallback_reason"))
                            .and_then(serde_json::Value::as_str)
                            .map(ToOwned::to_owned)
                    })
            })
    {
        artifact
            .metadata
            .insert("qap_witness_map_reason".to_string(), value);
    }
    if !artifact
        .metadata
        .contains_key("qap_witness_map_fallback_state")
    {
        let state = match artifact
            .metadata
            .get("qap_witness_map_engine")
            .or_else(|| {
                artifact
                    .metadata
                    .get("target_groth16_qap_witness_map_engine")
            })
            .map(String::as_str)
        {
            Some(engine) if engine.starts_with("metal-") => "none",
            Some(engine) if engine.starts_with("hybrid-") => "partial-cpu-fallback",
            _ => "cpu-only",
        };
        artifact.metadata.insert(
            "qap_witness_map_fallback_state".to_string(),
            state.to_string(),
        );
    }
    if !artifact.metadata.contains_key("groth16_msm_engine")
        && let Some(value) = artifact.metadata.get("target_groth16_msm_accelerator")
    {
        let engine = if value == "metal" {
            "metal-bn254-msm"
        } else {
            "cpu-bn254-msm"
        };
        artifact
            .metadata
            .insert("groth16_msm_engine".to_string(), engine.to_string());
    }
    if !artifact.metadata.contains_key("groth16_msm_reason") {
        let reason = artifact
            .metadata
            .get("target_groth16_msm_fallback_reason")
            .cloned()
            .unwrap_or_else(|| {
                if artifact
                    .metadata
                    .get("target_groth16_msm_accelerator")
                    .is_some_and(|value| value == "metal")
                {
                    "bn254-groth16-metal-msm".to_string()
                } else {
                    "cpu-selected".to_string()
                }
            });
        artifact
            .metadata
            .insert("groth16_msm_reason".to_string(), reason);
    }
    if !artifact.metadata.contains_key("groth16_msm_parallelism") {
        let parallelism = artifact
            .metadata
            .get("target_groth16_metal_inflight_jobs")
            .cloned()
            .unwrap_or_else(|| "1".to_string());
        artifact
            .metadata
            .insert("groth16_msm_parallelism".to_string(), parallelism);
    }
    if !artifact.metadata.contains_key("groth16_msm_fallback_state") {
        let state =
            if parse_metadata_bool(&artifact.metadata, "target_groth16_metal_no_cpu_fallback")
                == Some(true)
            {
                "none"
            } else if artifact
                .metadata
                .get("target_groth16_msm_accelerator")
                .map(String::as_str)
                == Some("metal")
            {
                "partial-cpu-fallback"
            } else {
                "cpu-only"
            };
        artifact
            .metadata
            .insert("groth16_msm_fallback_state".to_string(), state.to_string());
    }

    artifact
}

fn load_setup_from_disk(cache_key: &str) -> ZkfResult<Option<CachedSetup>> {
    let (pk_path, vk_path, shape_path) = setup_disk_cache_paths(cache_key);
    if !pk_path.is_file() || !vk_path.is_file() {
        return Ok(None);
    }

    let vk_bytes = match fs::read(&vk_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };

    let (pk, loaded_legacy_pk_format) = match load_proving_key_from_disk(&pk_path)? {
        Some(value) => value,
        None => {
            let _ = fs::remove_file(&pk_path);
            let _ = fs::remove_file(&vk_path);
            let _ = fs::remove_file(&shape_path);
            return Ok(None);
        }
    };
    if !cached_vk_matches_pk(pk.as_ref(), vk_bytes.as_slice())? {
        let _ = fs::remove_file(&pk_path);
        let _ = fs::remove_file(&vk_path);
        let _ = fs::remove_file(&shape_path);
        return Ok(None);
    }
    if loaded_legacy_pk_format {
        persist_setup_to_disk(cache_key, pk.as_ref(), vk_bytes.as_ref())?;
    }

    let prove_shape = if !shape_path.is_file() {
        None
    } else {
        match load_streamed_groth16_prove_shape(&shape_path) {
            Ok(shape) => Some(Arc::new(shape)),
            Err(_) => {
                let _ = fs::remove_file(&shape_path);
                None
            }
        }
    };

    Ok(Some(CachedSetup {
        pk,
        vk_bytes: Arc::new(vk_bytes),
        prove_shape,
        pk_cache_format: "fast-uncompressed-v2",
        pk_cache_migrated: loaded_legacy_pk_format,
    }))
}

fn persist_setup_to_disk(
    cache_key: &str,
    pk: &ProvingKey<Bn254>,
    vk_bytes: &[u8],
) -> ZkfResult<()> {
    let (pk_path, vk_path, _) = setup_disk_cache_paths(cache_key);
    write_file_atomic(&pk_path, |file| {
        let mut pk_writer = BufWriter::new(file);
        pk_writer.write_all(SETUP_PK_CACHE_MAGIC).map_err(|e| {
            ZkfError::Backend(format!("Failed to write proving key cache header: {e}"))
        })?;
        pk.serialize_uncompressed(&mut pk_writer).map_err(|e| {
            ZkfError::Serialization(format!("Failed to serialize proving key: {e}"))
        })?;
        pk_writer
            .flush()
            .map_err(|e| ZkfError::Backend(format!("Failed to flush proving key cache: {e}")))?;
        Ok(())
    })?;
    write_file_atomic(&vk_path, |file| {
        file.write_all(vk_bytes)
            .map_err(|e| ZkfError::Backend(format!("Failed to write verifying key cache: {e}")))?;
        Ok(())
    })?;
    Ok(())
}

fn copy_file_atomic(source: &Path, destination: &Path, label: &str) -> ZkfResult<()> {
    write_file_atomic(destination, |file| {
        let mut source_file = File::open(source).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to open source {} {}: {err}",
                label,
                source.display()
            ))
        })?;
        std::io::copy(&mut source_file, file).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to copy {} into {}: {err}",
                label,
                destination.display()
            ))
        })?;
        Ok(())
    })
}

fn write_file_atomic<F>(path: &Path, write_fn: F) -> ZkfResult<()>
where
    F: FnOnce(&mut File) -> ZkfResult<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| {
        ZkfError::Backend(format!(
            "Failed to create cache dir {}: {e}",
            parent.display()
        ))
    })?;
    cleanup_stale_atomic_temp_siblings(path);

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cache.bin");
    let pid = std::process::id();

    for attempt in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                ZkfError::Backend(format!("Failed to get clock time for cache write: {e}"))
            })?
            .as_nanos();
        let temp_path = parent.join(format!(".{file_name}.tmp-{pid}-{nanos}-{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(mut file) => {
                if let Err(err) = write_fn(&mut file) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(err);
                }
                if let Err(err) = file.sync_all() {
                    let _ = fs::remove_file(&temp_path);
                    return Err(ZkfError::Backend(format!(
                        "Failed to sync cache file {}: {err}",
                        temp_path.display()
                    )));
                }
                drop(file);
                if let Err(err) = fs::rename(&temp_path, path) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(ZkfError::Backend(format!(
                        "Failed to atomically replace cache file {}: {err}",
                        path.display()
                    )));
                }
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
                cleanup_stale_atomic_temp_siblings(path);
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(ZkfError::Backend(format!(
                    "Failed to create temporary cache file {}: {err}",
                    temp_path.display()
                )));
            }
        }
    }

    Err(ZkfError::Backend(format!(
        "Failed to create temporary cache file for atomic write: {}",
        path.display()
    )))
}

fn cleanup_stale_atomic_temp_siblings(path: &Path) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => return,
    };
    let prefix = format!(".{file_name}.tmp-");
    let baseline_modified = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let now = SystemTime::now();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if !entry_name.starts_with(&prefix) {
            continue;
        }
        let entry_modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        let should_remove = if let Some(baseline) = baseline_modified {
            entry_modified
                .map(|modified| modified <= baseline)
                .unwrap_or(false)
        } else {
            entry_modified
                .and_then(|modified| now.duration_since(modified).ok())
                .map(|age| age >= ATOMIC_TEMP_STALE_AGE)
                .unwrap_or(false)
        };
        if should_remove {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn write_dir_atomic<F>(path: &Path, write_fn: F) -> ZkfResult<()>
where
    F: FnOnce(&Path) -> ZkfResult<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to create bundle parent dir {}: {err}",
            parent.display()
        ))
    })?;
    if path.exists() {
        return Err(ZkfError::Backend(format!(
            "bundle destination already exists: {}",
            path.display()
        )));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bundle");
    let pid = std::process::id();
    for attempt in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                ZkfError::Backend(format!("Failed to get clock time for bundle write: {err}"))
            })?
            .as_nanos();
        let temp_path = parent.join(format!(".{file_name}.tmp-{pid}-{nanos}-{attempt}"));
        match fs::create_dir(&temp_path) {
            Ok(()) => {
                if let Err(err) = write_fn(&temp_path) {
                    let _ = fs::remove_dir_all(&temp_path);
                    return Err(err);
                }
                if let Err(err) = fs::rename(&temp_path, path) {
                    let _ = fs::remove_dir_all(&temp_path);
                    return Err(ZkfError::Backend(format!(
                        "Failed to atomically install bundle dir {}: {err}",
                        path.display()
                    )));
                }
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(ZkfError::Backend(format!(
                    "Failed to create temporary bundle dir {}: {err}",
                    temp_path.display()
                )));
            }
        }
    }
    Err(ZkfError::Backend(format!(
        "Failed to create temporary bundle dir for atomic write: {}",
        path.display()
    )))
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn get_or_create_setup_cached<C, SetupFactory, ShapeFactory>(
    cache_key: &str,
    build_setup_circuit: SetupFactory,
    build_shape_circuit: ShapeFactory,
) -> ZkfResult<CachedSetup>
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr>,
    SetupFactory: FnOnce() -> C,
    ShapeFactory: FnOnce() -> C,
{
    let mut shape_builder = Some(build_shape_circuit);
    {
        let mut cache = SETUP_CACHE
            .lock()
            .map_err(|_| ZkfError::Backend("Setup cache lock poisoned".to_string()))?;
        if let Some(cached) = cache.get_cloned(cache_key) {
            return maybe_backfill_setup_shape(cache_key, cached, &mut shape_builder);
        }
    }

    if let Some(cached) = load_setup_from_disk(cache_key)? {
        let cached = maybe_backfill_setup_shape(cache_key, cached, &mut shape_builder)?;
        let mut cache = SETUP_CACHE
            .lock()
            .map_err(|_| ZkfError::Backend("Setup cache lock poisoned".to_string()))?;
        cache.insert(cache_key.to_string(), cached.clone());
        return Ok(cached);
    }

    let setup_circuit = build_setup_circuit();
    let seed = deterministic_setup_seed(cache_key);
    let mut rng = StdRng::from_seed(seed);
    let (_, _, shape_path) = setup_disk_cache_paths(cache_key);

    let (pk, prove_shape) =
        create_local_groth16_setup_with_shape_path(setup_circuit, &mut rng, &shape_path)
            .map_err(|e| ZkfError::Backend(format!("Groth16 setup failed: {e}")))?;
    let pk = Arc::new(pk);
    let prove_shape = Arc::new(prove_shape);

    let mut vk_bytes = Vec::new();
    pk.vk
        .serialize_compressed(&mut vk_bytes)
        .map_err(|e| ZkfError::Serialization(format!("Failed to serialize verifying key: {e}")))?;
    let vk_bytes = Arc::new(vk_bytes);
    persist_setup_to_disk(cache_key, pk.as_ref(), vk_bytes.as_ref())?;

    let cached = CachedSetup {
        pk: Arc::clone(&pk),
        vk_bytes: Arc::clone(&vk_bytes),
        prove_shape: Some(Arc::clone(&prove_shape)),
        pk_cache_format: "fast-uncompressed-v2",
        pk_cache_migrated: false,
    };

    {
        let mut cache = SETUP_CACHE
            .lock()
            .map_err(|_| ZkfError::Backend("Setup cache lock poisoned".to_string()))?;
        cache.insert(cache_key.to_string(), cached.clone());
    }

    Ok(cached)
}

fn maybe_backfill_setup_shape<C, ShapeFactory>(
    cache_key: &str,
    mut cached: CachedSetup,
    shape_builder: &mut Option<ShapeFactory>,
) -> ZkfResult<CachedSetup>
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr>,
    ShapeFactory: FnOnce() -> C,
{
    if cached.prove_shape.is_some() {
        return Ok(cached);
    }

    let build_shape_circuit = shape_builder.take().ok_or_else(|| {
        ZkfError::Backend(
            "Groth16 prove-shape builder was consumed before cache backfill".to_string(),
        )
    })?;
    let (_, _, shape_path) = setup_disk_cache_paths(cache_key);
    let prove_shape = Arc::new(build_groth16_prove_shape_to_path(
        build_shape_circuit(),
        &shape_path,
    )?);
    cached.prove_shape = Some(prove_shape);

    let mut cache = SETUP_CACHE
        .lock()
        .map_err(|_| ZkfError::Backend("Setup cache lock poisoned".to_string()))?;
    cache.insert(cache_key.to_string(), cached.clone());
    Ok(cached)
}

fn load_proving_key_from_disk(path: &PathBuf) -> ZkfResult<Option<(Arc<ProvingKey<Bn254>>, bool)>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let mut header = [0u8; SETUP_PK_CACHE_MAGIC.len()];
    let is_fast_format = match file.read_exact(&mut header) {
        Ok(()) => header == *SETUP_PK_CACHE_MAGIC,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => false,
        Err(err) => {
            return Err(ZkfError::Backend(format!(
                "Failed to read proving key cache header '{}': {err}",
                path.display()
            )));
        }
    };

    if !is_fast_format {
        file.seek(SeekFrom::Start(0)).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to rewind proving key cache '{}': {err}",
                path.display()
            ))
        })?;
    }

    let reader = BufReader::new(file);
    let pk = if is_fast_format {
        ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(reader)
    } else {
        // Setup caches are locally generated artifacts. Load the legacy format unchecked and
        // bind it back to the cached VK bytes in `load_setup_from_disk` before reuse/migration.
        ProvingKey::<Bn254>::deserialize_compressed_unchecked(reader)
    }
    .map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "Failed to deserialize cached proving key '{}': {err}",
            path.display()
        ))
    })?;

    Ok(Some((Arc::new(pk), !is_fast_format)))
}

fn cached_vk_matches_pk(pk: &ProvingKey<Bn254>, expected_vk_bytes: &[u8]) -> ZkfResult<bool> {
    let mut derived_vk_bytes = Vec::new();
    pk.vk
        .serialize_compressed(&mut derived_vk_bytes)
        .map_err(|e| {
            ZkfError::Serialization(format!(
                "Failed to serialize cached proving key verifying key for integrity check: {e}"
            ))
        })?;
    Ok(derived_vk_bytes == expected_vk_bytes)
}

// ---------------------------------------------------------------------------
// Helper: reconstruct public inputs for verification
// ---------------------------------------------------------------------------

fn reconstruct_public_inputs_for_verify(wrapped_proof: &ProofArtifact) -> ZkfResult<Vec<Fr>> {
    let hex = wrapped_proof
        .metadata
        .get("groth16_public_inputs_hex")
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "wrapped artifact missing 'groth16_public_inputs_hex' metadata field".to_string(),
            )
        })?;

    deserialize_fr_vec_hex(hex)
}

// ---------------------------------------------------------------------------
// Public input extraction and serialization
// ---------------------------------------------------------------------------

fn collect_public_inputs_from_witness(
    witness: &StarkProofWitness,
    params: &FriCircuitParams,
) -> ZkfResult<Vec<Fr>> {
    if witness.public_inputs.len() < params.num_public_inputs {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected {} public inputs in wrapper witness, found {}",
            params.num_public_inputs,
            witness.public_inputs.len()
        )));
    }

    let has_air = !params.air_constraints.is_empty() && params.trace_width > 0;
    if has_air && witness.trace_commitment.len() < 8 {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected 8 trace commitment elements in wrapper witness, found {}",
            witness.trace_commitment.len()
        )));
    }
    if has_air && witness.quotient_commitment.len() < 8 {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected 8 quotient commitment elements in wrapper witness, found {}",
            witness.quotient_commitment.len()
        )));
    }

    let mut public_inputs =
        Vec::with_capacity(params.num_public_inputs + if has_air { 16 } else { 0 });
    public_inputs.extend(
        witness
            .public_inputs
            .iter()
            .take(params.num_public_inputs)
            .copied()
            .map(Fr::from),
    );

    if has_air {
        public_inputs.extend(
            witness
                .trace_commitment
                .iter()
                .take(8)
                .copied()
                .map(Fr::from),
        );
        public_inputs.extend(
            witness
                .quotient_commitment
                .iter()
                .take(8)
                .copied()
                .map(Fr::from),
        );
    }

    Ok(public_inputs)
}

fn serialize_fr_vec_hex(inputs: &[Fr]) -> ZkfResult<String> {
    let mut all_bytes: Vec<u8> = Vec::with_capacity(inputs.len() * 32);
    for fr in inputs {
        let mut buf = Vec::new();
        fr.serialize_compressed(&mut buf)
            .map_err(|e| ZkfError::Serialization(format!("Failed to serialize Fr: {e}")))?;
        all_bytes.extend_from_slice(&buf);
    }
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&all_bytes))
}

fn deserialize_fr_vec_hex(encoded: &str) -> ZkfResult<Vec<Fr>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| ZkfError::InvalidArtifact(format!("Invalid base64 in public inputs: {e}")))?;

    if bytes.len() % 32 != 0 {
        return Err(ZkfError::InvalidArtifact(format!(
            "Public inputs byte length {} is not a multiple of 32",
            bytes.len()
        )));
    }

    bytes
        .chunks(32)
        .map(|chunk| {
            Fr::deserialize_compressed(chunk)
                .map_err(|e| ZkfError::InvalidArtifact(format!("Failed to deserialize Fr: {e}")))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Deterministic seed helpers
// ---------------------------------------------------------------------------

fn deterministic_setup_seed(cache_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-stark-to-groth16-setup-seed-v2:");
    hasher.update(cache_key.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn deterministic_proof_seed(program_digest: &str, proof_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-stark-to-groth16-proof-seed-v2:");
    hasher.update(program_digest.as_bytes());
    hasher.update(b":");
    hasher.update(proof_bytes);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arkworks::create_local_groth16_setup_with_shape;
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use zkf_core::{FieldElement, Program, WitnessPlan};

    fn wrap_mode_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // Tests serialize env mutation behind a process-wide mutex.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            // Tests serialize env mutation behind a process-wide mutex.
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                // Tests serialize env mutation behind a process-wide mutex.
                unsafe {
                    std::env::set_var(self.key, previous);
                }
            } else {
                // Tests serialize env mutation behind a process-wide mutex.
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn write_file_atomic_cleans_stale_temp_siblings() {
        let base = std::env::temp_dir().join(format!(
            "zkf-atomic-cleanup-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("temp dir");
        let cache_path = base.join("cache.bin");
        fs::write(&cache_path, b"old").expect("seed cache");
        let stale_path = base.join(".cache.bin.tmp-999999-1-0");
        fs::write(&stale_path, b"stale").expect("stale temp");

        write_file_atomic(&cache_path, |file| {
            file.write_all(b"fresh")
                .map_err(|err| ZkfError::Backend(err.to_string()))?;
            Ok(())
        })
        .expect("atomic write");

        assert!(!stale_path.exists(), "stale temp file should be removed");
        assert_eq!(fs::read(&cache_path).expect("cache bytes"), b"fresh");

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn setup_disk_cache_root_prefers_zkf_cache_dir() {
        let _guard = wrap_mode_lock().lock().unwrap();
        let _home = EnvVarGuard::set("HOME", "/tmp/zkf-home-ignored");
        let _cache = EnvVarGuard::set("ZKF_CACHE_DIR", "/tmp/zkf-cache-root");
        assert_eq!(
            setup_disk_cache_root(),
            PathBuf::from("/tmp/zkf-cache-root").join("stark-to-groth16")
        );
    }

    #[test]
    fn setup_disk_cache_root_defaults_to_home_cache_root() {
        let _guard = wrap_mode_lock().lock().unwrap();
        let home_root = std::env::temp_dir().join(format!(
            "zkf-home-cache-root-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let home_root_string = home_root.to_string_lossy().into_owned();
        let _home = EnvVarGuard::set("HOME", &home_root_string);
        let _cache = EnvVarGuard::remove("ZKF_CACHE_DIR");
        assert_eq!(
            setup_disk_cache_root(),
            home_root
                .join(".zkf")
                .join("cache")
                .join("stark-to-groth16")
        );
    }

    #[test]
    fn setup_disk_cache_root_falls_back_to_temp_without_home() {
        let _guard = wrap_mode_lock().lock().unwrap();
        let _home = EnvVarGuard::remove("HOME");
        let _cache = EnvVarGuard::remove("ZKF_CACHE_DIR");
        assert_eq!(
            setup_disk_cache_root(),
            std::env::temp_dir().join("stark-to-groth16")
        );
    }

    fn make_plonky3_proof_artifact(proof_data: Vec<u8>) -> ProofArtifact {
        let mut metadata = BTreeMap::new();
        // Keep the smoke-test wrapper circuit as small as possible. The real
        // proof-shape coverage lives in the dedicated transcript/circuit tests
        // below; this fixture only needs to exercise wrap + verify wiring.
        metadata.insert("fri_num_queries".to_string(), "1".to_string());
        metadata.insert("fri_num_rounds".to_string(), "0".to_string());
        metadata.insert("fri_log_degree".to_string(), "1".to_string());
        metadata.insert("fri_merkle_height".to_string(), "0".to_string());
        metadata.insert("fri_num_public_inputs".to_string(), "0".to_string());
        metadata.insert("fri_commit_pow_bits".to_string(), "0".to_string());
        metadata.insert("fri_query_pow_bits".to_string(), "0".to_string());
        metadata.insert("fri_log_blowup".to_string(), "0".to_string());
        ProofArtifact::new(
            BackendKind::Plonky3,
            "test-digest-abc123",
            proof_data,
            vec![],
            vec![],
        )
        .with_metadata(metadata)
    }

    #[derive(Clone)]
    struct TinySetupCircuit;

    impl ConstraintSynthesizer<Fr> for TinySetupCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let public = cs.new_input_variable(|| Ok(Fr::from(3u64)))?;
            let witness = cs.new_witness_variable(|| Ok(Fr::from(5u64)))?;
            let product = cs.new_witness_variable(|| Ok(Fr::from(15u64)))?;
            cs.enforce_constraint(
                LinearCombination::from(public),
                LinearCombination::from(witness),
                LinearCombination::from(product),
            )?;
            cs.enforce_constraint(
                LinearCombination::from(product),
                LinearCombination::from(Variable::One),
                LinearCombination::from(product),
            )?;
            Ok(())
        }
    }

    fn make_plonky3_compiled() -> CompiledProgram {
        CompiledProgram {
            backend: BackendKind::Plonky3,
            program: Program {
                name: "test".to_string(),
                field: zkf_core::FieldId::Goldilocks,
                signals: vec![],
                constraints: vec![],
                witness_plan: WitnessPlan::default(),
                ..Default::default()
            },
            program_digest: "test-digest-abc123".to_string(),
            compiled_data: None,
            metadata: BTreeMap::new(),
            original_program: None,
            lowering_report: None,
        }
    }

    fn wrapped_fixture() -> &'static ProofArtifact {
        static FIXTURE: OnceLock<ProofArtifact> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            serde_json::from_str(include_str!(
                "../../tests/fixtures/stark_to_groth16_wrapped_fixture.json"
            ))
            .expect("valid Stark-to-Groth16 wrapped fixture")
        })
    }

    #[test]
    fn wrapper_identifies_backends() {
        let wrapper = StarkToGroth16Wrapper;
        assert_eq!(wrapper.source_backend(), BackendKind::Plonky3);
        assert_eq!(wrapper.target_backend(), BackendKind::ArkworksGroth16);
    }

    #[test]
    fn strict_policy_ignores_wrap_mode_env_override() {
        let _guard = wrap_mode_lock().lock().unwrap();
        let _env = EnvVarGuard::set("ZKF_WRAP_MODE", "nova");
        let params = FriCircuitParams {
            num_queries: 1,
            num_fri_rounds: 1,
            merkle_tree_height: 1,
            trace_width: 1,
            air_constraints: vec![],
            ..FriCircuitParams::default()
        };

        let strict_plan = choose_wrap_plan(
            &params,
            WrapperExecutionPolicy {
                honor_env_overrides: false,
                allow_large_direct_materialization: false,
                force_mode: None,
            },
        )
        .expect("strict plan");
        assert_eq!(strict_plan.strategy, WrapStrategy::DirectFriV2);

        #[cfg(feature = "nova-compression")]
        {
            let attested_plan = choose_wrap_plan(
                &params,
                WrapperExecutionPolicy {
                    honor_env_overrides: true,
                    allow_large_direct_materialization: false,
                    force_mode: None,
                },
            )
            .expect("attested plan");
            assert_eq!(attested_plan.strategy, WrapStrategy::NovaCompressedV3);
        }
    }

    #[test]
    fn wrapper_rejects_wrong_source_backend() {
        let wrapper = StarkToGroth16Wrapper;
        let bad_proof = ProofArtifact::new(BackendKind::Halo2, "test", vec![], vec![], vec![]);
        let bad_compiled = CompiledProgram {
            backend: BackendKind::Plonky3,
            program: Program {
                name: "test".to_string(),
                field: zkf_core::FieldId::Goldilocks,
                signals: vec![],
                constraints: vec![],
                witness_plan: WitnessPlan::default(),
                ..Default::default()
            },
            program_digest: "test".to_string(),
            compiled_data: None,
            metadata: BTreeMap::new(),
            original_program: None,
            lowering_report: None,
        };
        assert!(wrapper.wrap(&bad_proof, &bad_compiled).is_err());
    }

    #[test]
    fn wrapper_rejects_wrong_compiled_backend() {
        let wrapper = StarkToGroth16Wrapper;
        let proof = ProofArtifact::new(BackendKind::Plonky3, "test", vec![1u8], vec![], vec![]);
        let bad_compiled = CompiledProgram {
            backend: BackendKind::Halo2,
            program: Program {
                name: "test".to_string(),
                field: zkf_core::FieldId::Goldilocks,
                signals: vec![],
                constraints: vec![],
                witness_plan: WitnessPlan::default(),
                ..Default::default()
            },
            program_digest: "test".to_string(),
            compiled_data: None,
            metadata: BTreeMap::new(),
            original_program: None,
            lowering_report: None,
        };
        assert!(wrapper.wrap(&proof, &bad_compiled).is_err());
    }

    #[test]
    #[ignore = "expensive export smoke; use wrap_then_verify fixture coverage and cached wrap benchmark for routine runs"]
    fn end_to_end_wrap_produces_wrapped_v2_artifact() {
        let wrapper = StarkToGroth16Wrapper;
        let proof_bytes: Vec<u8> = (0u8..64).collect();
        let source_proof = make_plonky3_proof_artifact(proof_bytes);
        let source_compiled = make_plonky3_compiled();

        let result = wrapper.wrap(&source_proof, &source_compiled);
        assert!(result.is_ok(), "wrap() should succeed: {:?}", result.err());

        let wrapped = result.unwrap();
        assert_eq!(wrapped.backend, BackendKind::ArkworksGroth16);
        assert_eq!(
            wrapped.metadata.get("status").map(|s| s.as_str()),
            Some("wrapped-v2"),
        );
        assert!(!wrapped.proof.is_empty());
        assert!(!wrapped.verification_key.is_empty());
        assert_eq!(wrapped.program_digest, source_proof.program_digest);
    }

    #[test]
    #[ignore = "expensive deterministic export smoke; run explicitly when touching wrapper proof generation"]
    fn wrap_is_deterministic() {
        let wrapper = StarkToGroth16Wrapper;
        let proof_bytes: Vec<u8> = (0u8..64).collect();

        let source_proof = make_plonky3_proof_artifact(proof_bytes);
        let source_compiled = make_plonky3_compiled();

        let wrapped1 = wrapper
            .wrap(&source_proof, &source_compiled)
            .expect("first wrap should succeed");
        let wrapped2 = wrapper
            .wrap(&source_proof, &source_compiled)
            .expect("second wrap should succeed");

        assert_eq!(
            wrapped1.proof, wrapped2.proof,
            "wrapping should be deterministic"
        );
    }

    #[test]
    fn cold_setup_cache_persists_and_backfills_prove_shape() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let cache_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "cold-setup"
            ));
            let cache_root_string = cache_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &cache_root_string);
            let _ = std::fs::remove_dir_all(&cache_root);
            SETUP_CACHE.lock().unwrap().clear();

            let cache_key = format!("test-prove-shape-{}", std::process::id());
            let (pk_path, _, shape_path) = setup_disk_cache_paths(&cache_key);
            assert!(!shape_path.exists());

            let first =
                get_or_create_setup_cached(&cache_key, || TinySetupCircuit, || TinySetupCircuit)
                    .unwrap();
            assert!(first.prove_shape.is_some());
            assert!(shape_path.is_file());
            let pk_bytes = std::fs::read(&pk_path).unwrap();
            assert_eq!(
                &pk_bytes[..SETUP_PK_CACHE_MAGIC.len()],
                SETUP_PK_CACHE_MAGIC
            );

            std::fs::remove_file(&shape_path).unwrap();
            SETUP_CACHE.lock().unwrap().clear();

            let second =
                get_or_create_setup_cached(&cache_key, || TinySetupCircuit, || TinySetupCircuit)
                    .unwrap();
            assert!(second.prove_shape.is_some());
            assert!(shape_path.is_file());
        });
    }

    #[test]
    fn legacy_setup_cache_is_migrated_to_fast_pk_format() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let cache_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "legacy-migration"
            ));
            let cache_root_string = cache_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &cache_root_string);
            let _ = std::fs::remove_dir_all(&cache_root);
            SETUP_CACHE.lock().unwrap().clear();

            let cache_key = format!("test-legacy-migrate-{}", std::process::id());
            let (pk_path, vk_path, shape_path) = setup_disk_cache_paths(&cache_key);
            if let Some(parent) = pk_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }

            let mut rng = StdRng::from_seed(deterministic_setup_seed(&cache_key));
            let (pk, _) =
                create_local_groth16_setup_with_shape(TinySetupCircuit, &mut rng).unwrap();
            let mut legacy_writer = BufWriter::new(File::create(&pk_path).unwrap());
            pk.serialize_compressed(&mut legacy_writer).unwrap();
            legacy_writer.flush().unwrap();
            let mut vk_bytes = Vec::new();
            pk.vk.serialize_compressed(&mut vk_bytes).unwrap();
            std::fs::write(&vk_path, &vk_bytes).unwrap();
            assert!(!shape_path.exists());

            let migrated =
                get_or_create_setup_cached(&cache_key, || TinySetupCircuit, || TinySetupCircuit)
                    .unwrap();
            assert!(migrated.prove_shape.is_some());
            let pk_bytes = std::fs::read(&pk_path).unwrap();
            assert_eq!(
                &pk_bytes[..SETUP_PK_CACHE_MAGIC.len()],
                SETUP_PK_CACHE_MAGIC
            );
            assert!(shape_path.is_file());
        });
    }

    #[test]
    fn mismatched_vk_cache_is_rebuilt_before_reuse() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let cache_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "vk-mismatch"
            ));
            let cache_root_string = cache_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &cache_root_string);
            let _ = std::fs::remove_dir_all(&cache_root);
            SETUP_CACHE.lock().unwrap().clear();

            let cache_key = format!("test-vk-mismatch-{}", std::process::id());
            let (pk_path, vk_path, shape_path) = setup_disk_cache_paths(&cache_key);
            let mut rng = StdRng::from_seed(deterministic_setup_seed(&cache_key));
            let (pk, _) =
                create_local_groth16_setup_with_shape(TinySetupCircuit, &mut rng).unwrap();
            let mut expected_vk_bytes = Vec::new();
            pk.vk.serialize_compressed(&mut expected_vk_bytes).unwrap();
            let mut corrupted_vk_bytes = expected_vk_bytes.clone();
            corrupted_vk_bytes[0] ^= 0x01;
            persist_setup_to_disk(&cache_key, &pk, &corrupted_vk_bytes).unwrap();
            assert!(!shape_path.exists());

            let rebuilt =
                get_or_create_setup_cached(&cache_key, || TinySetupCircuit, || TinySetupCircuit)
                    .unwrap();
            assert!(rebuilt.prove_shape.is_some());
            assert!(shape_path.is_file());
            assert_eq!(std::fs::read(&vk_path).unwrap(), expected_vk_bytes);
            let pk_bytes = std::fs::read(&pk_path).unwrap();
            assert_eq!(
                &pk_bytes[..SETUP_PK_CACHE_MAGIC.len()],
                SETUP_PK_CACHE_MAGIC
            );
        });
    }

    #[test]
    fn large_direct_wrap_requires_prepared_cache() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let cache_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "prep-required"
            ));
            let cache_root_string = cache_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &cache_root_string);
            let _ = std::fs::remove_dir_all(&cache_root);

            let cache_key = format!("test-prep-required-{}", std::process::id());
            let plan = WrapPlan {
                strategy: WrapStrategy::DirectFriV2,
                estimated_constraints: 39_900_000,
                estimated_memory_bytes: DIRECT_WRAP_PREP_REQUIRED_BYTES,
                memory_budget_bytes: Some(48 * 1024 * 1024 * 1024),
                low_memory_mode: false,
                reason: "test".to_string(),
            };
            let err = ensure_direct_wrap_cache_ready_for_execution(&cache_key, &plan).unwrap_err();
            assert!(err.to_string().contains("zkf runtime prepare"));
        });
    }

    #[test]
    fn large_direct_wrap_accepts_ready_fast_cache() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let cache_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "prep-ready"
            ));
            let cache_root_string = cache_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &cache_root_string);
            let _ = std::fs::remove_dir_all(&cache_root);
            SETUP_CACHE.lock().unwrap().clear();

            let cache_key = format!("test-prep-ready-{}", std::process::id());
            let _ =
                get_or_create_setup_cached(&cache_key, || TinySetupCircuit, || TinySetupCircuit)
                    .unwrap();
            let plan = WrapPlan {
                strategy: WrapStrategy::DirectFriV2,
                estimated_constraints: 39_900_000,
                estimated_memory_bytes: DIRECT_WRAP_PREP_REQUIRED_BYTES,
                memory_budget_bytes: Some(48 * 1024 * 1024 * 1024),
                low_memory_mode: false,
                reason: "test".to_string(),
            };
            ensure_direct_wrap_cache_ready_for_execution(&cache_key, &plan).unwrap();
        });
    }

    #[test]
    fn large_direct_preview_reports_prepare_requirement() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let cache_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "preview-required"
            ));
            let cache_root_string = cache_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &cache_root_string);
            let _ = std::fs::remove_dir_all(&cache_root);

            let source_proof = make_plonky3_proof_artifact(vec![1, 2, 3]);
            let fri_params = FriCircuitParams::default();
            let plan = WrapPlan {
                strategy: WrapStrategy::DirectFriV2,
                estimated_constraints: 39_900_000,
                estimated_memory_bytes: DIRECT_WRAP_PREP_REQUIRED_BYTES,
                memory_budget_bytes: Some(48 * 1024 * 1024 * 1024),
                low_memory_mode: false,
                reason: "direct FRI verifier circuit fits the certified strict-wrap budget"
                    .to_string(),
            };

            let preview =
                StarkToGroth16Wrapper::preview_from_plan(&source_proof, &fri_params, &plan)
                    .unwrap();
            assert_eq!(preview.prepare_required, Some(true));
            assert_eq!(preview.setup_cache_state.as_deref(), Some("missing"));
            assert!(
                preview
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("zkf runtime prepare")
            );
        });
    }

    #[test]
    fn large_direct_prepare_is_blocked_without_override() {
        let plan = WrapPlan {
            strategy: WrapStrategy::DirectFriV2,
            estimated_constraints: 39_900_000,
            estimated_memory_bytes: DIRECT_WRAP_PREP_REQUIRED_BYTES,
            memory_budget_bytes: Some(48 * 1024 * 1024 * 1024),
            low_memory_mode: false,
            reason: "direct FRI verifier circuit fits the certified strict-wrap budget".to_string(),
        };

        let report = blocked_large_direct_prepare_report(
            &plan,
            SetupCacheState::FastMissingShape,
            WrapperExecutionPolicy {
                honor_env_overrides: false,
                allow_large_direct_materialization: false,
                force_mode: None,
            },
        )
        .expect("blocked report");

        assert!(report.blocked);
        assert_eq!(
            report.setup_cache_state.as_deref(),
            Some("fast-missing-shape")
        );
        assert_eq!(report.shape_cache_ready, Some(false));
        assert!(
            report
                .blocked_reason
                .as_deref()
                .unwrap_or_default()
                .contains(DIRECT_WRAP_PREP_OVERRIDE_FLAG)
        );
    }

    #[test]
    fn large_direct_prepare_override_allows_materialization() {
        let plan = WrapPlan {
            strategy: WrapStrategy::DirectFriV2,
            estimated_constraints: 39_900_000,
            estimated_memory_bytes: DIRECT_WRAP_PREP_REQUIRED_BYTES,
            memory_budget_bytes: Some(48 * 1024 * 1024 * 1024),
            low_memory_mode: false,
            reason: "direct FRI verifier circuit fits the certified strict-wrap budget".to_string(),
        };

        let report = blocked_large_direct_prepare_report(
            &plan,
            SetupCacheState::FastMissingShape,
            WrapperExecutionPolicy {
                honor_env_overrides: false,
                allow_large_direct_materialization: true,
                force_mode: None,
            },
        );

        assert!(report.is_none());
    }

    #[test]
    fn direct_wrap_cache_bundle_exports_and_installs_across_roots() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let export_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "bundle-export"
            ));
            let install_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "bundle-install"
            ));
            let bundle_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "bundle-dir"
            ));
            let _ = std::fs::remove_dir_all(&export_root);
            let _ = std::fs::remove_dir_all(&install_root);
            let _ = std::fs::remove_dir_all(&bundle_root);

            let proof = make_plonky3_proof_artifact(vec![1, 2, 3]);
            let compiled = make_plonky3_compiled();
            let policy = WrapperExecutionPolicy {
                honor_env_overrides: false,
                allow_large_direct_materialization: false,
                force_mode: None,
            };

            {
                let export_root_string = export_root.to_string_lossy().into_owned();
                let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &export_root_string);
                SETUP_CACHE.lock().unwrap().clear();
                let wrapper = StarkToGroth16Wrapper;
                let fri_params = wrapper.derive_fri_params(&proof, &compiled).unwrap();
                let cache_key = setup_cache_key(&proof.program_digest, &fri_params);
                let _ = get_or_create_setup_cached(
                    &cache_key,
                    || direct_fri_setup_circuit(&fri_params),
                    || direct_fri_setup_circuit(&fri_params),
                )
                .unwrap();

                let manifest = export_direct_wrap_cache_bundle(
                    &proof,
                    &compiled,
                    policy,
                    &bundle_root,
                    "apple-silicon-m4-max-48gb",
                )
                .unwrap();
                assert_eq!(manifest.cache_state, "ready");
                assert!(bundle_root.join("manifest.json").is_file());
                assert!(bundle_root.join("proving-key.bin").is_file());
                assert!(bundle_root.join("verifying-key.bin").is_file());
                assert!(bundle_root.join("prove-shape.bin").is_file());
            }

            {
                let install_root_string = install_root.to_string_lossy().into_owned();
                let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &install_root_string);
                SETUP_CACHE.lock().unwrap().clear();
                let manifest = install_direct_wrap_cache_bundle(
                    &proof,
                    &compiled,
                    policy,
                    &bundle_root,
                    "apple-silicon-m4-max-48gb",
                )
                .unwrap();
                assert_eq!(manifest.cache_state, "ready");

                let wrapper = StarkToGroth16Wrapper;
                let fri_params = wrapper.derive_fri_params(&proof, &compiled).unwrap();
                let cache_key = setup_cache_key(&proof.program_digest, &fri_params);
                assert_eq!(
                    probe_setup_cache_state(&cache_key).unwrap(),
                    SetupCacheState::Ready
                );
            }
        });
    }

    #[test]
    fn direct_wrap_cache_bundle_rejects_digest_mismatch() {
        crate::with_serialized_heavy_backend_test(|| {
            let _guard = wrap_mode_lock().lock().unwrap();
            let export_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "bundle-mismatch-export"
            ));
            let install_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "bundle-mismatch-install"
            ));
            let bundle_root = std::env::temp_dir().join(format!(
                "zkf-shape-cache-{}-{}",
                std::process::id(),
                "bundle-mismatch-dir"
            ));
            let _ = std::fs::remove_dir_all(&export_root);
            let _ = std::fs::remove_dir_all(&install_root);
            let _ = std::fs::remove_dir_all(&bundle_root);

            let proof = make_plonky3_proof_artifact(vec![1, 2, 3]);
            let compiled = make_plonky3_compiled();
            let policy = WrapperExecutionPolicy {
                honor_env_overrides: false,
                allow_large_direct_materialization: false,
                force_mode: None,
            };

            {
                let export_root_string = export_root.to_string_lossy().into_owned();
                let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &export_root_string);
                SETUP_CACHE.lock().unwrap().clear();
                let wrapper = StarkToGroth16Wrapper;
                let fri_params = wrapper.derive_fri_params(&proof, &compiled).unwrap();
                let cache_key = setup_cache_key(&proof.program_digest, &fri_params);
                let _ = get_or_create_setup_cached(
                    &cache_key,
                    || direct_fri_setup_circuit(&fri_params),
                    || direct_fri_setup_circuit(&fri_params),
                )
                .unwrap();
                export_direct_wrap_cache_bundle(
                    &proof,
                    &compiled,
                    policy,
                    &bundle_root,
                    "apple-silicon-m4-max-48gb",
                )
                .unwrap();
            }

            let mismatched_compiled = CompiledProgram {
                program_digest: "different-compiled-digest".to_string(),
                ..compiled.clone()
            };
            let install_root_string = install_root.to_string_lossy().into_owned();
            let _env = EnvVarGuard::set("ZKF_CACHE_DIR", &install_root_string);
            SETUP_CACHE.lock().unwrap().clear();
            let err = install_direct_wrap_cache_bundle(
                &proof,
                &mismatched_compiled,
                policy,
                &bundle_root,
                "apple-silicon-m4-max-48gb",
            )
            .unwrap_err();
            assert!(err.to_string().contains("program digest"));
        });
    }

    #[test]
    fn verify_wrapped_rejects_placeholder() {
        let wrapper = StarkToGroth16Wrapper;
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "placeholder".to_string());
        let placeholder =
            ProofArtifact::new(BackendKind::ArkworksGroth16, "test", vec![], vec![], vec![])
                .with_metadata(metadata);
        assert!(wrapper.verify_wrapped(&placeholder).is_err());
    }

    #[test]
    fn verify_wrapped_rejects_wrong_backend() {
        let wrapper = StarkToGroth16Wrapper;
        let proof = ProofArtifact::new(BackendKind::Plonky3, "test", vec![], vec![], vec![]);
        assert!(wrapper.verify_wrapped(&proof).is_err());
    }

    #[test]
    fn wrap_then_verify() {
        crate::with_serialized_heavy_backend_test(|| {
            let wrapper = StarkToGroth16Wrapper;
            let wrapped = wrapped_fixture();

            assert_eq!(
                wrapped.metadata.get("wrapper").map(String::as_str),
                Some("stark-to-groth16")
            );
            assert_eq!(
                wrapped.metadata.get("status").map(String::as_str),
                Some("wrapped-v2")
            );
            assert_eq!(
                wrapped.metadata.get("scheme").map(String::as_str),
                Some("groth16")
            );
            assert_eq!(
                wrapped.metadata.get("proof_semantics").map(String::as_str),
                Some("wrapped-fri-verifier-circuit")
            );
            assert_eq!(
                wrapped
                    .metadata
                    .get("prover_acceleration_scope")
                    .map(String::as_str),
                Some("target-groth16-prover-only")
            );
            assert_eq!(
                wrapped
                    .metadata
                    .get("wrapper_semantics")
                    .map(String::as_str),
                Some("fri-verifier-circuit")
            );
            assert_eq!(wrapped.backend, BackendKind::ArkworksGroth16);
            assert!(!wrapped.proof.is_empty());
            assert!(!wrapped.verification_key.is_empty());
            assert!(wrapped.metadata.contains_key("groth16_public_inputs_hex"));
            assert!(wrapped.metadata.contains_key("metal_gpu_busy_ratio"));
            assert!(wrapped.metadata.contains_key("metal_stage_breakdown"));
            assert!(wrapped.metadata.contains_key("metal_inflight_jobs"));
            assert!(wrapped.metadata.contains_key("metal_no_cpu_fallback"));
            assert!(wrapped.metadata.contains_key("metal_counter_source"));
            assert!(wrapped.metadata.contains_key("metal_dispatch_circuit_open"));
            assert!(wrapped.metadata.contains_key("metal_dispatch_last_failure"));

            let result = wrapper.verify_wrapped(&wrapped);
            assert!(
                result.is_ok(),
                "verify_wrapped should not error: {:?}",
                result.err()
            );
            assert!(result.unwrap(), "fixture wrapped proof should verify");
        });
    }

    #[test]
    fn cached_artifact_metadata_migration_backfills_dispatch_fields() {
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v2".to_string());
        metadata.insert("metal_stage_breakdown".to_string(), "{}".to_string());
        metadata.insert(
            "metal_counter_source".to_string(),
            "fixture-precomputed".to_string(),
        );
        metadata.insert(
            "target_groth16_qap_witness_map_engine".to_string(),
            "ark-libsnark-reduction".to_string(),
        );
        metadata.insert(
            "target_groth16_qap_witness_map_parallelism".to_string(),
            "1".to_string(),
        );
        metadata.insert(
            "target_groth16_msm_accelerator".to_string(),
            "cpu".to_string(),
        );
        metadata.insert(
            "target_groth16_msm_fallback_reason".to_string(),
            "cpu-selected".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_gpu_busy_ratio".to_string(),
            "0.000".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_inflight_jobs".to_string(),
            "1".to_string(),
        );

        let upgraded = upgrade_cached_wrapped_artifact_metadata(
            ProofArtifact::new(
                BackendKind::ArkworksGroth16,
                "test",
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![],
            )
            .with_metadata(metadata),
        );

        assert_eq!(
            upgraded
                .metadata
                .get("metal_dispatch_circuit_open")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("metal_dispatch_last_failure")
                .map(String::as_str),
            Some("")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("target_groth16_metal_dispatch_circuit_open")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("target_groth16_metal_dispatch_last_failure")
                .map(String::as_str),
            Some("")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str),
            Some("ark-libsnark-reduction")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("qap_witness_map_parallelism")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str),
            Some("cpu-only")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("groth16_msm_engine")
                .map(String::as_str),
            Some("cpu-bn254-msm")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("groth16_msm_reason")
                .map(String::as_str),
            Some("cpu-selected")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("groth16_msm_parallelism")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str),
            Some("cpu-only")
        );
        assert_eq!(
            upgraded
                .metadata
                .get("gpu_stage_busy_ratio")
                .map(String::as_str),
            Some("0.000")
        );
    }

    #[test]
    fn finalize_target_groth16_metadata_lifts_witness_map_fields() {
        let mut metadata = BTreeMap::new();
        let mut groth16_metal_metadata = BTreeMap::new();
        groth16_metal_metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt+streamed-reduction".to_string(),
        );
        groth16_metal_metadata.insert(
            "qap_witness_map_reason".to_string(),
            "bn254-witness-map-metal-ntt".to_string(),
        );
        groth16_metal_metadata.insert("qap_witness_map_parallelism".to_string(), "8".to_string());
        groth16_metal_metadata.insert(
            "qap_witness_map_fallback_state".to_string(),
            "none".to_string(),
        );
        groth16_metal_metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        groth16_metal_metadata.insert(
            "groth16_msm_reason".to_string(),
            "bn254-groth16-metal-msm".to_string(),
        );
        groth16_metal_metadata.insert("groth16_msm_parallelism".to_string(), "4".to_string());
        groth16_metal_metadata.insert("groth16_msm_fallback_state".to_string(), "none".to_string());
        groth16_metal_metadata.insert("gpu_stage_busy_ratio".to_string(), "0.875".to_string());

        finalize_target_groth16_metadata(
            &mut metadata,
            &groth16_metal_metadata,
            &serde_json::Map::new(),
        );

        assert_eq!(
            metadata.get("qap_witness_map_engine").map(String::as_str),
            Some("metal-bn254-ntt+streamed-reduction")
        );
        assert_eq!(
            metadata.get("qap_witness_map_reason").map(String::as_str),
            Some("bn254-witness-map-metal-ntt")
        );
        assert_eq!(
            metadata
                .get("qap_witness_map_parallelism")
                .map(String::as_str),
            Some("8")
        );
        assert_eq!(
            metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str),
            Some("none")
        );
        assert_eq!(
            metadata.get("groth16_msm_engine").map(String::as_str),
            Some("metal-bn254-msm")
        );
        assert_eq!(
            metadata.get("groth16_msm_reason").map(String::as_str),
            Some("bn254-groth16-metal-msm")
        );
        assert_eq!(
            metadata.get("groth16_msm_parallelism").map(String::as_str),
            Some("4")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str),
            Some("none")
        );
        assert_eq!(
            metadata.get("gpu_stage_busy_ratio").map(String::as_str),
            Some("0.875")
        );
    }

    #[test]
    fn finalize_target_groth16_metadata_prefers_final_witness_map_fields() {
        let mut metadata = BTreeMap::new();
        let mut groth16_metal_metadata = BTreeMap::new();
        groth16_metal_metadata.insert(
            "qap_witness_map_engine".to_string(),
            "ark-streamed-reduction".to_string(),
        );
        groth16_metal_metadata.insert(
            "qap_witness_map_reason".to_string(),
            "bn254-witness-map-metal-dispatch-failed".to_string(),
        );
        groth16_metal_metadata.insert("qap_witness_map_parallelism".to_string(), "1".to_string());
        groth16_metal_metadata.insert(
            "qap_witness_map_fallback_state".to_string(),
            "cpu-only".to_string(),
        );
        groth16_metal_metadata.insert(
            "groth16_msm_engine".to_string(),
            "cpu-bn254-msm".to_string(),
        );
        groth16_metal_metadata.insert(
            "groth16_msm_reason".to_string(),
            "metal-dispatch-failed".to_string(),
        );
        groth16_metal_metadata.insert("groth16_msm_parallelism".to_string(), "1".to_string());
        groth16_metal_metadata.insert(
            "groth16_msm_fallback_state".to_string(),
            "partial-cpu-fallback".to_string(),
        );

        let wrapper_stages = serde_json::json!({
            "target_groth16_internal": {
                "witness_map": {
                    "accelerator": "metal-bn254-ntt+streamed-reduction",
                    "fallback_reason": "bn254-witness-map-metal-ntt",
                    "inflight_jobs": 8
                }
            }
        })
        .as_object()
        .cloned()
        .expect("object");

        finalize_target_groth16_metadata(&mut metadata, &groth16_metal_metadata, &wrapper_stages);

        assert_eq!(
            metadata.get("qap_witness_map_engine").map(String::as_str),
            Some("ark-streamed-reduction")
        );
        assert_eq!(
            metadata.get("qap_witness_map_reason").map(String::as_str),
            Some("bn254-witness-map-metal-dispatch-failed")
        );
        assert_eq!(
            metadata
                .get("qap_witness_map_parallelism")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str),
            Some("cpu-only")
        );
        assert_eq!(
            metadata.get("groth16_msm_engine").map(String::as_str),
            Some("cpu-bn254-msm")
        );
        assert_eq!(
            metadata.get("groth16_msm_reason").map(String::as_str),
            Some("metal-dispatch-failed")
        );
        assert_eq!(
            metadata.get("groth16_msm_parallelism").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str),
            Some("partial-cpu-fallback")
        );
    }

    #[test]
    fn certified_strict_artifact_health_rejects_dispatch_failure() {
        let mut metadata = BTreeMap::new();
        metadata.insert("status".to_string(), "wrapped-v2".to_string());
        metadata.insert("trust_model".to_string(), "cryptographic".to_string());
        metadata.insert("wrapper_strategy".to_string(), "direct-fri-v2".to_string());
        metadata.insert(
            "runtime_detected_hardware_profile".to_string(),
            "apple-silicon-m4-max-48gb".to_string(),
        );
        metadata.insert(
            "metal_dispatch_circuit_open".to_string(),
            "true".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_dispatch_circuit_open".to_string(),
            "true".to_string(),
        );
        metadata.insert(
            "metal_dispatch_last_failure".to_string(),
            "watchdog timeout".to_string(),
        );
        metadata.insert(
            "target_groth16_metal_dispatch_last_failure".to_string(),
            "watchdog timeout".to_string(),
        );
        metadata.insert("metal_no_cpu_fallback".to_string(), "false".to_string());
        metadata.insert(
            "groth16_msm_fallback_state".to_string(),
            "partial-cpu-fallback".to_string(),
        );

        assert!(!wrapped_artifact_is_certified_strict_healthy(&metadata));
    }

    #[test]
    #[ignore = "performance benchmark; run explicitly when tuning wrapper utilization"]
    fn cached_wrap_benchmark_reports_utilization_metadata() {
        let proof_bytes: Vec<u8> = (0u8..64).collect();
        let source_proof = make_plonky3_proof_artifact(proof_bytes);
        let source_compiled = make_plonky3_compiled();

        let report =
            benchmark_cached_wrap_batch(&source_proof, &source_compiled, 2).expect("benchmark");

        assert!(report.warm_cache);
        assert_eq!(report.parallelism, 2);
        assert!(report.wall_clock_ms >= 0.0);
        assert!(!report.prover_acceleration_scope.is_empty());
        assert!(!report.metal_stage_breakdown.is_empty());
        assert!(!report.metal_counter_source.is_empty());
        assert!(
            !report.metal_dispatch_last_failure.is_empty() || !report.metal_dispatch_circuit_open
        );
    }

    #[test]
    fn public_inputs_extraction_consistency() {
        crate::with_serialized_heavy_backend_test(|| {
            use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

            let p3_seed = plonky3_seed("test-digest-abc123");
            let params = FriCircuitParams {
                num_queries: 1,
                num_fri_rounds: 1,
                log_degree: 4,
                merkle_tree_height: 1,
                poseidon2_seed: p3_seed,
                num_public_inputs: 0,
                ..FriCircuitParams::default()
            };
            let proof_bytes: Vec<u8> = (0u8..64).collect();
            let witness = build_witness_from_proof(&proof_bytes, &[], &params);

            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit_for_cs = FriVerifierCircuit::with_witness(witness.clone(), params.clone());
            circuit_for_cs.generate_constraints(cs.clone()).unwrap();
            let instance_from_cs: Vec<Fr> = cs
                .borrow()
                .unwrap()
                .instance_assignment
                .clone()
                .into_iter()
                .skip(1)
                .collect();

            let instance_from_extract =
                collect_public_inputs_from_witness(&witness, &params).unwrap();

            assert_eq!(instance_from_cs.len(), instance_from_extract.len());
            for (i, (a, b)) in instance_from_cs
                .iter()
                .zip(instance_from_extract.iter())
                .enumerate()
            {
                assert_eq!(a, b, "public input {} should match", i);
            }
        });
    }

    #[test]
    fn plonky3_seed_is_deterministic() {
        let s1 = plonky3_seed("abc");
        let s2 = plonky3_seed("abc");
        assert_eq!(s1, s2);
    }

    #[test]
    fn plonky3_seed_differs_for_different_digests() {
        let s1 = plonky3_seed("abc");
        let s2 = plonky3_seed("def");
        assert_ne!(s1, s2);
    }

    /// Validate transcript replay against a real Plonky3 proof.
    /// Generates a proof, then compares our replay's alpha/zeta/betas/query_indices
    /// with a parallel native challenger replay.
    #[test]
    fn transcript_replay_matches_native_verifier() {
        crate::with_serialized_heavy_backend_test(|| {
            use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
            use p3_challenger::{CanObserve, CanSample, CanSampleBits};
            use p3_field::PrimeCharacteristicRing;
            use p3_fri::create_test_fri_params;
            use p3_matrix::Matrix;
            use p3_matrix::dense::RowMajorMatrix;
            use p3_uni_stark::{Proof as StarkProof, prove as stark_prove};
            use rand09::SeedableRng;
            use rand09::rngs::SmallRng;

            // Simple 2-column AIR: first row col[0] == PI[0], all rows col[0] == col[1]
            struct SimpleAir;
            impl<F> BaseAir<F> for SimpleAir {
                fn width(&self) -> usize {
                    2
                }
            }
            impl<AB: AirBuilderWithPublicValues> Air<AB> for SimpleAir {
                fn eval(&self, builder: &mut AB) {
                    let main = builder.main();
                    let local = main.row_slice(0).unwrap();
                    let pis = builder.public_values().to_vec();
                    builder
                        .when_first_row()
                        .assert_eq(local[0].clone(), pis[0].clone());
                    builder.assert_eq(local[0].clone(), local[1].clone());
                }
            }

            let seed = 12345u64;
            let mut rng = SmallRng::seed_from_u64(seed);
            let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
            let hash = GoldilocksHash::new(perm.clone());
            let compress = GoldilocksCompress::new(perm.clone());
            let val_mmcs = GoldilocksValMmcs::new(hash, compress);
            let challenge_mmcs = GoldilocksChallengeMmcs::new(val_mmcs.clone());
            let dft = GoldilocksDft::default();
            let fri_params = create_test_fri_params(challenge_mmcs, 0);
            let pcs = GoldilocksPcs::new(dft, val_mmcs, fri_params);
            let challenger = GoldilocksChallenger::new(perm.clone());
            let config = GoldilocksConfig::new(pcs, challenger);

            // Build 16-row trace
            let num_rows = 16usize;
            let mut trace_values = Vec::with_capacity(num_rows * 2);
            for _ in 0..num_rows {
                trace_values.push(Goldilocks::from_u64(42));
                trace_values.push(Goldilocks::from_u64(42));
            }
            let trace = RowMajorMatrix::new(trace_values, 2);
            let public_values = vec![Goldilocks::from_u64(42)];

            let proof: StarkProof<GoldilocksConfig> =
                stark_prove(&config, &SimpleAir, trace, &public_values);
            let proof_bytes = postcard::to_allocvec(&proof).unwrap();

            // Verify with native verifier
            assert!(p3_uni_stark::verify(&config, &SimpleAir, &proof, &public_values).is_ok());

            // Deserialize and extract all needed data
            let deser: GoldilocksStarkProof = postcard::from_bytes(&proof_bytes).unwrap();
            let degree_bits = deser.degree_bits;

            use std::borrow::Borrow;
            let trace_arr: &[Goldilocks; 8] = deser.commitments.trace.borrow();
            let trace_commitment: Vec<u64> =
                trace_arr.iter().map(|v| v.as_canonical_u64()).collect();
            let quot_arr: &[Goldilocks; 8] = deser.commitments.quotient_chunks.borrow();
            let quotient_commitment: Vec<u64> =
                quot_arr.iter().map(|v| v.as_canonical_u64()).collect();
            let fri_roots: Vec<[u64; 8]> = deser
                .opening_proof
                .commit_phase_commits
                .iter()
                .map(|c| {
                    let a: &[Goldilocks; 8] = c.borrow();
                    std::array::from_fn(|i| a[i].as_canonical_u64())
                })
                .collect();
            let commit_pow_w: Vec<u64> = deser
                .opening_proof
                .commit_pow_witnesses
                .iter()
                .map(|w| w.as_canonical_u64())
                .collect();
            let final_poly_c: Vec<u64> = deser
                .opening_proof
                .final_poly
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect();
            let query_pow_w = deser.opening_proof.query_pow_witness.as_canonical_u64();
            let pub_vals_u64 = vec![42u64];

            // Run OUR transcript replay
            let (our_alpha, our_zeta, our_fri_alpha, our_betas, our_indices) =
                replay_fiat_shamir_transcript(
                    seed,
                    degree_bits,
                    &trace_commitment,
                    &quotient_commitment,
                    &pub_vals_u64,
                    &fri_roots,
                    2, // num_queries = 2
                    &commit_pow_w,
                    &final_poly_c,
                    query_pow_w,
                    1,
                    1, // commit_pow_bits, query_pow_bits
                    2,
                    0, // log_blowup, log_final_poly_len
                );

            // Run NATIVE replay (exactly as Plonky3 verifier does)
            let mut native = GoldilocksChallenger::new(perm);
            // uni-stark transcript
            native.observe(Goldilocks::from_usize(degree_bits));
            native.observe(Goldilocks::from_usize(degree_bits)); // is_zk=0
            native.observe(Goldilocks::ZERO); // preprocessed_width=0
            native.observe(deser.commitments.trace.clone());
            native.observe_slice(&public_values);
            let native_alpha: Goldilocks = native.sample();
            native.observe(deser.commitments.quotient_chunks.clone());
            let native_zeta: Goldilocks = native.sample();
            // FRI transcript
            let native_fri_alpha: Goldilocks = native.sample();
            let log_global_max_height = fri_roots.len() + 2 + 0; // + log_blowup + log_final_poly_len
            let mut native_betas = Vec::new();
            for (comm, witness) in deser
                .opening_proof
                .commit_phase_commits
                .iter()
                .zip(&deser.opening_proof.commit_pow_witnesses)
            {
                native.observe(comm.clone());
                native.observe(*witness);
                let _: usize = native.sample_bits(1); // commit_pow_bits=1
                let beta: Goldilocks = native.sample();
                native_betas.push(beta.as_canonical_u64());
            }
            for &fp in &deser.opening_proof.final_poly {
                native.observe(fp);
            }
            native.observe(deser.opening_proof.query_pow_witness);
            let _: usize = native.sample_bits(1); // query_pow_bits=1
            let mut native_indices = Vec::new();
            for _ in 0..2 {
                let idx: usize = native.sample_bits(log_global_max_height);
                native_indices.push(idx as u64);
            }

            // Compare
            assert_eq!(our_alpha, native_alpha.as_canonical_u64(), "alpha mismatch");
            assert_eq!(our_zeta, native_zeta.as_canonical_u64(), "zeta mismatch");
            assert_eq!(
                our_fri_alpha,
                native_fri_alpha.as_canonical_u64(),
                "fri_alpha mismatch"
            );
            assert_eq!(our_betas, native_betas, "betas mismatch");
            assert_eq!(our_indices, native_indices, "query indices mismatch");

            eprintln!(
                "Transcript replay validated: degree_bits={}, {} FRI rounds, alpha={}, zeta={}, fri_alpha={}",
                degree_bits,
                fri_roots.len(),
                our_alpha,
                our_zeta,
                our_fri_alpha
            );
        });
    }

    /// Integration test: generate a real Plonky3 STARK proof with multi-row trace,
    /// extract witness, and verify the R1CS circuit is satisfied.
    ///
    /// This validates the entire pipeline: proof generation → deserialization →
    /// Fiat-Shamir transcript replay → FRI composition → circuit satisfaction.
    ///
    /// Uses p3-* public APIs directly to construct a 16-row trace with a simple
    /// 2-column AIR (column 0 = public input on first row, column 1 = copy).
    #[test]
    fn real_plonky3_proof_satisfies_r1cs_circuit() -> zkf_core::ZkfResult<()> {
        crate::with_serialized_heavy_backend_test(|| -> zkf_core::ZkfResult<()> {
            use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
            use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
            use p3_field::PrimeCharacteristicRing;
            use p3_fri::create_test_fri_params;
            use p3_matrix::Matrix;
            use p3_matrix::dense::RowMajorMatrix;
            use p3_uni_stark::{Proof as StarkProof, prove as stark_prove};
            use rand09::SeedableRng;
            use rand09::rngs::SmallRng;

            // A simple 2-column AIR: on first row, assert col[0] == public_input[0]
            // and col[0] == col[1].
            struct SimpleAir;
            impl<F> BaseAir<F> for SimpleAir {
                fn width(&self) -> usize {
                    2
                }
            }
            impl<AB: AirBuilderWithPublicValues> Air<AB> for SimpleAir {
                fn eval(&self, builder: &mut AB) {
                    let main = builder.main();
                    let local = main.row_slice(0).unwrap();
                    let pis = builder.public_values().to_vec();
                    // First row: col[0] == public_input[0]
                    builder
                        .when_first_row()
                        .assert_eq(local[0].clone(), pis[0].clone());
                    // All rows: col[0] == col[1]
                    builder.assert_eq(local[0].clone(), local[1].clone());
                }
            }

            // 1. Build config (replicating build_config_goldilocks)
            let seed = 12345u64;
            let mut rng = SmallRng::seed_from_u64(seed);
            let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
            let hash = GoldilocksHash::new(perm.clone());
            let compress = GoldilocksCompress::new(perm.clone());
            let val_mmcs = GoldilocksValMmcs::new(hash, compress);
            let challenge_mmcs = GoldilocksChallengeMmcs::new(val_mmcs.clone());
            let dft = GoldilocksDft::default();
            let fri_params = create_test_fri_params(challenge_mmcs, 0);
            let pcs = GoldilocksPcs::new(dft, val_mmcs, fri_params);
            let challenger = GoldilocksChallenger::new(perm);
            let config = GoldilocksConfig::new(pcs, challenger);

            // 2. Build a 16-row trace (2 columns, all rows = [42, 42])
            let num_rows = 16usize;
            let trace_width = 2;
            let mut trace_values = Vec::with_capacity(num_rows * trace_width);
            for _ in 0..num_rows {
                trace_values.push(Goldilocks::from_u64(42));
                trace_values.push(Goldilocks::from_u64(42));
            }
            let trace = RowMajorMatrix::new(trace_values, trace_width);

            // Public values: [42]
            let public_values = vec![Goldilocks::from_u64(42)];

            // 3. Generate STARK proof
            let proof: StarkProof<GoldilocksConfig> =
                stark_prove(&config, &SimpleAir, trace, &public_values);
            let proof_bytes = postcard::to_allocvec(&proof).expect("proof serialization");

            // Verify the STARK proof is valid first
            assert!(
                p3_uni_stark::verify(&config, &SimpleAir, &proof, &public_values).is_ok(),
                "native STARK verification should pass"
            );

            // 4. Deserialize and inspect proof shape
            let stark_proof_deser = postcard::from_bytes::<GoldilocksStarkProof>(&proof_bytes)
                .expect("proof deserialization should succeed");
            let degree_bits = stark_proof_deser.degree_bits;
            let num_fri_rounds = stark_proof_deser.opening_proof.commit_phase_commits.len();
            let log_blowup = 2; // from create_test_fri_params
            let merkle_tree_height = degree_bits + log_blowup;
            let num_queries = 2; // from create_test_fri_params

            eprintln!(
                "Proof shape: degree_bits={}, num_fri_rounds={}, merkle_height={}, num_queries={}",
                degree_bits, num_fri_rounds, merkle_tree_height, num_queries
            );
            assert!(
                degree_bits >= 1,
                "degree_bits should be >= 1 for multi-row trace"
            );

            // 5. Build FriCircuitParams matching the proof
            // The AIR has 1 constraint: col[0] - col[1] = 0 (the when_first_row public input
            // constraint is handled separately by the circuit's public input verification)
            let air_constraints = vec![crate::plonky3::AirExpr::Sub(
                Box::new(crate::plonky3::AirExpr::Signal(0)),
                Box::new(crate::plonky3::AirExpr::Signal(1)),
            )];

            let params = FriCircuitParams {
                num_queries,
                num_fri_rounds,
                log_degree: degree_bits,
                merkle_tree_height,
                poseidon2_seed: seed,
                num_public_inputs: 1,
                trace_width,
                air_constraints,
                public_signal_indices: vec![0], // col 0 is public
                num_quotient_chunks: 1,
                commit_pow_bits: 1,
                query_pow_bits: 1,
                log_blowup,
                log_final_poly_len: 0,
            };

            // 6. Build witness from the real proof
            let pub_inputs = vec![FieldElement::from_i64(42)];
            let circuit_witness = build_witness_from_proof(&proof_bytes, &pub_inputs, &params);

            // Sanity: check the witness was extracted from a real proof (not the dummy path)
            assert!(
                circuit_witness.trace_local.iter().any(|v| *v != 0),
                "witness should have non-zero trace values from real proof"
            );
            assert_eq!(circuit_witness.degree_bits, degree_bits);

            // 7. Build circuit and check constraint satisfaction
            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit = FriVerifierCircuit::with_witness(circuit_witness, params);
            circuit
                .generate_constraints(cs.clone())
                .expect("circuit generation should succeed");

            let num_constraints = cs.num_constraints();
            let num_variables = cs.num_witness_variables() + cs.num_instance_variables();
            eprintln!(
                "Real proof circuit: {} constraints, {} variables, degree_bits={}",
                num_constraints, num_variables, degree_bits
            );

            if !cs.is_satisfied().unwrap() {
                let constraint = cs.which_is_unsatisfied().unwrap();
                return Err(ZkfError::Backend(format!(
                    "R1CS circuit not satisfied. First unsatisfied constraint: {:?}",
                    constraint
                )));
            }
            Ok(())
        })
    }
}
