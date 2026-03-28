use crate::BackendEngine;
use crate::audited_backend::{audited_witness_for_proving, build_audited_compiled_program};
use crate::blackbox_gadgets;
use crate::blackbox_native::supported_blackbox_ops;
use crate::metal_runtime::append_backend_runtime_metadata_for_field;
pub(crate) use crate::proof_plonky3_spec::{AirExpr, LoweredProgram, lower_program};
use crate::proof_plonky3_spec::{
    build_trace_row, eval_air_expr_concrete as spec_eval_air_expr_concrete, max_safe_range_bits,
    parse_field_u64,
};
use crate::{GpuStage, GpuStageCoverage};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{FriParameters, TwoAdicFriPcs, create_test_fri_params};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge, SerializingHasher,
    TruncatedPermutation,
};
use p3_uni_stark::{
    Proof as StarkProof, StarkConfig, prove as stark_prove, verify as stark_verify,
};
use rand09::SeedableRng;
use rand09::rngs::SmallRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::any::TypeId;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldElement, FieldId, Program,
    ProofArtifact, Witness, ZkfError, ZkfResult, collect_public_inputs,
};

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
use zkf_metal::ntt::p3_adapter::{DftDispatch, MetalDft};

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
use zkf_metal::merkle::MetalMerkleTreeMmcs;

pub struct Plonky3Backend;

type Challenge<F> = F;
type MyHash<P> = PaddingFreeSponge<P, 16, 8, 8>;
type MyCompress<P> = TruncatedPermutation<P, 2, 8, 16>;

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
type ValMmcs<F, P> =
    MetalMerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash<P>, MyCompress<P>, 8>;

#[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
type ValMmcs<F, P> =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash<P>, MyCompress<P>, 8>;
type ChallengeMmcs<F, P> = ExtensionMmcs<F, Challenge<F>, ValMmcs<F, P>>;
type Challenger<F, P> = DuplexChallenger<F, P, 16, 8>;
type Pcs<F, P> = TwoAdicFriPcs<F, RuntimeDft<F>, ValMmcs<F, P>, ChallengeMmcs<F, P>>;
type Config<F, P> = StarkConfig<Pcs<F, P>, Challenge<F>, Challenger<F, P>>;
type Proof<F, P> = StarkProof<Config<F, P>>;

type M31Val = Mersenne31;
type M31Challenge = BinomialExtensionField<M31Val, 3>;
type M31ByteHash = Keccak256Hash;
type M31FieldHash = SerializingHasher<M31ByteHash>;
type M31Compress = CompressionFunctionFromHasher<M31ByteHash, 2, 32>;
type M31ValMmcs = MerkleTreeMmcs<M31Val, u8, M31FieldHash, M31Compress, 32>;
type M31ChallengeMmcs = ExtensionMmcs<M31Val, M31Challenge, M31ValMmcs>;
type M31Challenger = SerializingChallenger32<M31Val, HashChallenger<u8, M31ByteHash, 32>>;
type M31Pcs = CirclePcs<M31Val, M31ValMmcs, M31ChallengeMmcs>;
type M31Config = StarkConfig<M31Pcs, M31Challenge, M31Challenger>;
type M31Proof = StarkProof<M31Config>;

#[derive(Clone, Debug, Default)]
struct NttDispatchTracker {
    state: Arc<Mutex<NttDispatchState>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct NttDispatchState {
    used_metal: bool,
    fallback_reason: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
struct NttDispatchSummary {
    accelerator: &'static str,
    fallback_reason: Option<&'static str>,
}

#[derive(Clone)]
struct RuntimeDft<F> {
    inner: RuntimeDftInner<F>,
    tracker: Option<NttDispatchTracker>,
}

#[derive(Clone)]
enum RuntimeDftInner<F> {
    Cpu(Radix2DitParallel<F>),
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    Metal(MetalDft<F>),
}

struct ConfigBundle<F, P>
where
    F: Field + PrimeField64 + TwoAdicField + Send + Sync + 'static,
    P: CryptographicPermutation<[F; 16]>
        + CryptographicPermutation<[<F as Field>::Packing; 16]>
        + Clone
        + Send
        + Sync
        + 'static,
{
    config: Config<F, P>,
    ntt_tracker: Option<NttDispatchTracker>,
}

#[derive(Clone, Debug, Serialize)]
struct Plonky3StageTelemetry {
    accelerator: String,
    used_metal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_reason: Option<String>,
    trace_rows: usize,
    trace_width: usize,
}

#[derive(Clone, Debug)]
struct Plonky3RunTelemetry {
    coverage: GpuStageCoverage,
    metal_complete: bool,
    cpu_math_fallback_reason: Option<String>,
    metal_gpu_busy_ratio: f64,
    metal_stage_breakdown: String,
    metal_inflight_jobs: usize,
    metal_no_cpu_fallback: bool,
    metal_counter_source: &'static str,
    hash_accelerator: &'static str,
}

#[derive(Clone)]
struct ProgramAir {
    width: usize,
    constraints: Vec<AirExpr>,
    public_signal_indices: Vec<usize>,
}

impl NttDispatchTracker {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    fn record_unavailable(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.fallback_reason = Some("metal-unavailable");
        }
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    fn record_dispatch(&self, dispatch: DftDispatch) {
        if let Ok(mut state) = self.state.lock() {
            match dispatch {
                DftDispatch::Metal => {
                    state.used_metal = true;
                    state.fallback_reason = None;
                }
                DftDispatch::BelowThreshold if !state.used_metal => {
                    state.fallback_reason.get_or_insert("below-threshold");
                }
                DftDispatch::DispatchFailed if !state.used_metal => {
                    state.fallback_reason = Some("metal-dispatch-failed");
                }
                _ => {}
            }
        }
    }

    fn summary(&self) -> NttDispatchSummary {
        let state = self.state.lock().unwrap_or_else(|e| {
            eprintln!("[zkf-plonky3] NTT dispatch tracker mutex poisoned: {e}");
            e.into_inner()
        });
        NttDispatchSummary {
            accelerator: if state.used_metal { "metal" } else { "cpu" },
            fallback_reason: if state.used_metal {
                None
            } else {
                state.fallback_reason
            },
        }
    }
}

impl<F> Default for RuntimeDft<F>
where
    F: TwoAdicField + PrimeField64 + 'static,
{
    fn default() -> Self {
        Self::new(None)
    }
}

impl<F> RuntimeDft<F>
where
    F: TwoAdicField + PrimeField64 + 'static,
{
    fn new(tracker: Option<NttDispatchTracker>) -> Self {
        #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
        {
            if should_use_metal_ntt::<F>() {
                if let Some(metal) = MetalDft::<F>::new() {
                    return Self {
                        inner: RuntimeDftInner::Metal(metal),
                        tracker,
                    };
                }
                if let Some(observer) = &tracker {
                    observer.record_unavailable();
                }
            }
        }

        Self {
            inner: RuntimeDftInner::Cpu(Radix2DitParallel::default()),
            tracker,
        }
    }
}

impl<F> TwoAdicSubgroupDft<F> for RuntimeDft<F>
where
    F: TwoAdicField + PrimeField64 + 'static,
{
    type Evaluations = RowMajorMatrix<F>;

    fn dft_batch(&self, mat: RowMajorMatrix<F>) -> Self::Evaluations {
        let _ = &self.tracker;
        match &self.inner {
            RuntimeDftInner::Cpu(dft) => dft.dft_batch(mat).to_row_major_matrix(),
            #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
            RuntimeDftInner::Metal(dft) => {
                let (result, dispatch) = dft.dft_batch_with_dispatch(mat);
                if let Some(observer) = &self.tracker {
                    observer.record_dispatch(dispatch);
                }
                result
            }
        }
    }
}

fn should_use_metal_ntt<F: 'static>() -> bool {
    TypeId::of::<F>() == TypeId::of::<Goldilocks>() || TypeId::of::<F>() == TypeId::of::<BabyBear>()
}

impl ProgramAir {
    fn new(lowered: &LoweredProgram) -> Self {
        Self {
            width: lowered.signal_order.len(),
            constraints: lowered.constraints.clone(),
            public_signal_indices: lowered.public_signal_indices.clone(),
        }
    }
}

impl<F> BaseAir<F> for ProgramAir {
    fn width(&self) -> usize {
        self.width
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for ProgramAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let Some(local) = main.row_slice(0) else {
            return;
        };
        let pis = builder.public_values().to_vec();

        for (pi_idx, signal_idx) in self.public_signal_indices.iter().enumerate() {
            builder
                .when_first_row()
                .assert_eq(local[*signal_idx].clone(), pis[pi_idx]);
        }

        for constraint in &self.constraints {
            let value = eval_air_expr::<AB>(constraint, local.as_ref());
            builder.when_first_row().assert_zero(value);
        }
    }
}

impl BackendEngine for Plonky3Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::Plonky3
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Plonky3,
            mode: BackendMode::Native,
            trusted_setup: false,
            recursion_ready: true,
            transparent_setup: true,
            zkvm_mode: false,
            network_target: None,
            supported_blackbox_ops: supported_blackbox_ops(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec![
                "fri-goldilocks".to_string(),
                "fri-babybear".to_string(),
                "circle-mersenne31".to_string(),
            ],
            notes: "Plonky3 STARK backend with native field profiles: Goldilocks/BabyBear over FRI and Mersenne31 over Circle PCS. Supports Equal/Boolean constraints, range constraints via bit decomposition (field-safe bit cap), and division via derived quotient columns."
                .to_string(),
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        if !matches!(
            program.field,
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31
        ) {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message:
                    "plonky3 adapter currently supports Goldilocks, BabyBear, and Mersenne31 fields"
                        .to_string(),
            });
        }

        let raw_program = program.clone();
        let program = &blackbox_gadgets::lower_blackbox_program(program)?;
        let program = &blackbox_gadgets::lookup_lowering::lower_lookup_constraints(program)?;
        let lowered = lower_program(program)?;
        if lowered.signal_order.is_empty() {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message: "plonky3 adapter requires at least one signal column".to_string(),
            });
        }

        let mut compiled =
            build_audited_compiled_program(self.kind(), &raw_program, program.clone())?;
        compiled
            .metadata
            .insert("field".to_string(), program.field.as_str().to_string());
        compiled
            .metadata
            .insert("scheme".to_string(), "stark".to_string());
        compiled.metadata.insert(
            "pcs".to_string(),
            match program.field {
                FieldId::Mersenne31 => "circle",
                _ => "fri",
            }
            .to_string(),
        );
        compiled.metadata.insert(
            "trace_width".to_string(),
            lowered.signal_order.len().to_string(),
        );
        compiled.metadata.insert(
            "supported_constraints".to_string(),
            format!(
                "equal,boolean,range<={},division",
                max_safe_range_bits(program.field)
            ),
        );

        crate::metal_runtime::append_trust_metadata(
            &mut compiled.metadata,
            "native",
            "cryptographic",
            1,
        );

        Ok(compiled)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        ensure_compiled_backend(self.kind(), compiled)?;
        let enriched = audited_witness_for_proving(self.kind(), compiled, witness)?;
        let witness = &enriched;
        match compiled.program.field {
            FieldId::Goldilocks => prove_for_field::<Goldilocks, Poseidon2Goldilocks<16>>(
                compiled,
                witness,
                build_config_goldilocks,
            ),
            FieldId::BabyBear => prove_for_field::<BabyBear, Poseidon2BabyBear<16>>(
                compiled,
                witness,
                build_config_babybear,
            ),
            FieldId::Mersenne31 => prove_for_mersenne31(compiled, witness),
            other => Err(ZkfError::UnsupportedBackend {
                backend: BackendKind::Plonky3.to_string(),
                message: format!("field {other} is not supported by plonky3 adapter"),
            }),
        }
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        ensure_compiled_backend(self.kind(), compiled)?;

        if artifact.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "artifact backend is {}, expected {}",
                artifact.backend,
                self.kind()
            )));
        }

        if artifact.program_digest != compiled.program_digest {
            return Err(ZkfError::ProgramMismatch {
                expected: compiled.program_digest.clone(),
                found: artifact.program_digest.clone(),
            });
        }
        match compiled.program.field {
            FieldId::Goldilocks => verify_for_field::<Goldilocks, Poseidon2Goldilocks<16>>(
                compiled,
                artifact,
                build_config_goldilocks,
            ),
            FieldId::BabyBear => verify_for_field::<BabyBear, Poseidon2BabyBear<16>>(
                compiled,
                artifact,
                build_config_babybear,
            ),
            FieldId::Mersenne31 => verify_for_mersenne31(compiled, artifact),
            other => Err(ZkfError::UnsupportedBackend {
                backend: BackendKind::Plonky3.to_string(),
                message: format!("field {other} is not supported by plonky3 adapter"),
            }),
        }
    }
}

fn prove_for_field<F, P>(
    compiled: &CompiledProgram,
    witness: &Witness,
    config_builder: fn(u64) -> ConfigBundle<F, P>,
) -> ZkfResult<ProofArtifact>
where
    F: Field + PrimeField64 + TwoAdicField + Send + Sync + 'static,
    P: CryptographicPermutation<[F; 16]>
        + CryptographicPermutation<[<F as Field>::Packing; 16]>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let lowered = lower_program(&compiled.program)?;
    let air = ProgramAir::new(&lowered);
    let trace = ensure_gpu_heavy_trace_rows(
        build_trace::<F>(&lowered, witness, compiled.program.field)?,
        compiled.program.field,
    );
    let trace_height = trace.height();
    let trace_width = trace.width;
    let public_inputs = collect_public_inputs(&compiled.program, witness)?;
    let public_values = to_field_slice::<F>(&public_inputs, compiled.program.field)?;
    let seed = plonky3_seed(&compiled.program_digest);
    let config_bundle = config_builder(seed);

    let proof: Proof<F, P> = stark_prove(&config_bundle.config, &air, trace, &public_values);
    let proof_bytes =
        postcard::to_allocvec(&proof).map_err(|err| ZkfError::Serialization(err.to_string()))?;
    let verification_key = verification_key_fingerprint(
        &compiled.program_digest,
        compiled.program.field,
        lowered.signal_order.len(),
        &lowered.public_signal_indices,
    );

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "field".to_string(),
        compiled.program.field.as_str().to_string(),
    );
    metadata.insert("scheme".to_string(), "stark".to_string());
    metadata.insert("pcs".to_string(), "fri".to_string());
    metadata.insert("seed".to_string(), seed.to_string());
    let ntt_summary = config_bundle
        .ntt_tracker
        .as_ref()
        .map_or(ntt_cpu_summary(None), NttDispatchTracker::summary);
    append_ntt_metadata(&mut metadata, ntt_summary);
    append_backend_runtime_metadata_for_field(
        &mut metadata,
        BackendKind::Plonky3,
        Some(compiled.program.field),
    );
    append_actual_plonky3_run_metadata(
        &mut metadata,
        compiled.program.field,
        trace_height,
        trace_width,
        ntt_summary,
    );

    Ok(ProofArtifact {
        backend: BackendKind::Plonky3,
        program_digest: compiled.program_digest.clone(),
        proof: proof_bytes,
        verification_key,
        public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
    })
}

fn verify_for_field<F, P>(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
    config_builder: fn(u64) -> ConfigBundle<F, P>,
) -> ZkfResult<bool>
where
    F: Field + PrimeField64 + TwoAdicField + Send + Sync + 'static,
    P: CryptographicPermutation<[F; 16]>
        + CryptographicPermutation<[<F as Field>::Packing; 16]>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let lowered = lower_program(&compiled.program)?;
    let expected_vk = verification_key_fingerprint(
        &compiled.program_digest,
        compiled.program.field,
        lowered.signal_order.len(),
        &lowered.public_signal_indices,
    );
    if artifact.verification_key != expected_vk {
        return Err(ZkfError::InvalidArtifact(
            "plonky3 verification key fingerprint mismatch".to_string(),
        ));
    }

    let public_values = to_field_slice::<F>(&artifact.public_inputs, compiled.program.field)?;
    let seed = plonky3_seed(&compiled.program_digest);
    let config_bundle = config_builder(seed);
    let air = ProgramAir::new(&lowered);
    let proof: Proof<F, P> = postcard::from_bytes(artifact.proof.as_slice())
        .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
    Ok(stark_verify(&config_bundle.config, &air, &proof, &public_values).is_ok())
}

fn build_config_generic<F, P>(perm: P, poseidon2_seed: u64) -> ConfigBundle<F, P>
where
    F: Field + PrimeField64 + TwoAdicField + Send + Sync + 'static,
    P: CryptographicPermutation<[F; 16]>
        + CryptographicPermutation<[<F as Field>::Packing; 16]>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let hash: MyHash<P> = MyHash::new(perm.clone());
    let compress: MyCompress<P> = MyCompress::new(perm.clone());

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    let val_mmcs: ValMmcs<F, P> = ValMmcs::<F, P>::new_with_gpu(hash, compress, poseidon2_seed);

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    let val_mmcs: ValMmcs<F, P> = {
        let _ = poseidon2_seed;
        ValMmcs::<F, P>::new(hash, compress)
    };

    let challenge_mmcs: ChallengeMmcs<F, P> = ChallengeMmcs::new(val_mmcs.clone());
    let tracker = if should_use_metal_ntt::<F>() {
        Some(NttDispatchTracker::default())
    } else {
        None
    };
    let dft = RuntimeDft::<F>::new(tracker.clone());
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs: Pcs<F, P> = Pcs::new(dft, val_mmcs, fri_params);
    let challenger: Challenger<F, P> = Challenger::new(perm);
    ConfigBundle {
        config: Config::<F, P>::new(pcs, challenger),
        ntt_tracker: tracker,
    }
}

fn build_config_goldilocks(seed: u64) -> ConfigBundle<Goldilocks, Poseidon2Goldilocks<16>> {
    let mut rng = SmallRng::seed_from_u64(seed);
    build_config_generic::<Goldilocks, Poseidon2Goldilocks<16>>(
        Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng),
        seed,
    )
}

fn build_config_babybear(seed: u64) -> ConfigBundle<BabyBear, Poseidon2BabyBear<16>> {
    let mut rng = SmallRng::seed_from_u64(seed);
    build_config_generic::<BabyBear, Poseidon2BabyBear<16>>(
        Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng),
        seed,
    )
}

fn build_config_mersenne31(seed: u64) -> M31Config {
    let byte_hash = M31ByteHash {};
    let field_hash = M31FieldHash::new(byte_hash);
    let compress = M31Compress::new(byte_hash);
    let val_mmcs = M31ValMmcs::new(field_hash, compress);
    let challenge_mmcs = M31ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        num_queries: 40,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    let pcs = M31Pcs {
        mmcs: val_mmcs,
        fri_params,
        _phantom: PhantomData,
    };
    // The seed is folded into the challenger initial state to keep proof generation deterministic
    // and program-scoped while preserving Circle PCS semantics.
    let challenger = M31Challenger::from_hasher(seed.to_le_bytes().to_vec(), byte_hash);
    M31Config::new(pcs, challenger)
}

fn ntt_cpu_summary(fallback_reason: Option<&'static str>) -> NttDispatchSummary {
    NttDispatchSummary {
        accelerator: "cpu",
        fallback_reason,
    }
}

fn append_ntt_metadata(metadata: &mut BTreeMap<String, String>, summary: NttDispatchSummary) {
    metadata.insert(
        "ntt_accelerator".to_string(),
        summary.accelerator.to_string(),
    );
    if let Some(reason) = summary.fallback_reason {
        metadata.insert("ntt_fallback_reason".to_string(), reason.to_string());
    }
}

fn prove_for_mersenne31(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
    let lowered = lower_program(&compiled.program)?;
    let air = ProgramAir::new(&lowered);
    let trace = ensure_min_trace_rows(
        build_trace::<M31Val>(&lowered, witness, compiled.program.field)?,
        4,
    );
    let trace_height = trace.height();
    let trace_width = trace.width;
    let public_inputs = collect_public_inputs(&compiled.program, witness)?;
    let public_values = to_field_slice::<M31Val>(&public_inputs, compiled.program.field)?;
    let seed = plonky3_seed(&compiled.program_digest);
    let config = build_config_mersenne31(seed);

    let proof: M31Proof = stark_prove(&config, &air, trace, &public_values);
    let proof_bytes =
        postcard::to_allocvec(&proof).map_err(|err| ZkfError::Serialization(err.to_string()))?;
    let verification_key = verification_key_fingerprint(
        &compiled.program_digest,
        compiled.program.field,
        lowered.signal_order.len(),
        &lowered.public_signal_indices,
    );

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "field".to_string(),
        compiled.program.field.as_str().to_string(),
    );
    metadata.insert("scheme".to_string(), "stark".to_string());
    metadata.insert("pcs".to_string(), "circle".to_string());
    metadata.insert("seed".to_string(), seed.to_string());
    append_ntt_metadata(&mut metadata, ntt_cpu_summary(None));
    append_backend_runtime_metadata_for_field(
        &mut metadata,
        BackendKind::Plonky3,
        Some(compiled.program.field),
    );
    append_actual_plonky3_run_metadata(
        &mut metadata,
        compiled.program.field,
        trace_height,
        trace_width,
        ntt_cpu_summary(None),
    );

    Ok(ProofArtifact {
        backend: BackendKind::Plonky3,
        program_digest: compiled.program_digest.clone(),
        proof: proof_bytes,
        verification_key,
        public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
    })
}

fn verify_for_mersenne31(compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
    let lowered = lower_program(&compiled.program)?;
    let expected_vk = verification_key_fingerprint(
        &compiled.program_digest,
        compiled.program.field,
        lowered.signal_order.len(),
        &lowered.public_signal_indices,
    );
    if artifact.verification_key != expected_vk {
        return Err(ZkfError::InvalidArtifact(
            "plonky3 verification key fingerprint mismatch".to_string(),
        ));
    }

    let public_values = to_field_slice::<M31Val>(&artifact.public_inputs, compiled.program.field)?;
    let seed = plonky3_seed(&compiled.program_digest);
    let config = build_config_mersenne31(seed);
    let air = ProgramAir::new(&lowered);
    let proof: M31Proof = postcard::from_bytes(artifact.proof.as_slice())
        .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
    Ok(stark_verify(&config, &air, &proof, &public_values).is_ok())
}

fn build_trace<F>(
    lowered: &LoweredProgram,
    witness: &Witness,
    field: FieldId,
) -> ZkfResult<RowMajorMatrix<F>>
where
    F: PrimeField64,
{
    let row = build_trace_row(lowered, witness, field).map_err(ZkfError::from)?;
    let row = row.into_iter().map(F::from_u64).collect::<Vec<_>>();
    Ok(RowMajorMatrix::new(row, lowered.signal_order.len()))
}

fn ensure_min_trace_rows<F>(trace: RowMajorMatrix<F>, min_rows: usize) -> RowMajorMatrix<F>
where
    F: Clone + Send + Sync,
{
    if trace.height() >= min_rows {
        return trace;
    }
    let width = trace.width;
    if trace.height() == 0 {
        return trace;
    }
    let first_row = trace
        .row_slice(0)
        .expect("trace has rows but row_slice(0) is None")
        .to_vec();
    let mut values = Vec::with_capacity(width * min_rows);
    for _ in 0..min_rows {
        values.extend_from_slice(&first_row);
    }
    RowMajorMatrix::new(values, width)
}

fn ensure_gpu_heavy_trace_rows<F>(trace: RowMajorMatrix<F>, _field: FieldId) -> RowMajorMatrix<F>
where
    F: Clone + Send + Sync,
{
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        if matches!(_field, FieldId::Goldilocks | FieldId::BabyBear)
            && zkf_metal::global_context().is_some()
        {
            let thresholds = zkf_metal::current_thresholds();
            let min_rows = thresholds
                .ntt
                .max(thresholds.merkle)
                .max(4)
                .next_power_of_two();
            return ensure_min_trace_rows(trace, min_rows);
        }
    }

    trace
}

fn append_actual_plonky3_run_metadata(
    metadata: &mut BTreeMap<String, String>,
    field: FieldId,
    trace_height: usize,
    trace_width: usize,
    ntt_summary: NttDispatchSummary,
) {
    let telemetry = plonky3_run_telemetry(field, trace_height, trace_width, ntt_summary);
    metadata.insert(
        "gpu_stage_coverage".to_string(),
        serde_json::to_string(&telemetry.coverage).unwrap_or_else(|_| {
            "{\"coverage_ratio\":0.0,\"required_stages\":[],\"metal_stages\":[],\"cpu_stages\":[]}"
                .to_string()
        }),
    );
    metadata.insert(
        "metal_complete".to_string(),
        telemetry.metal_complete.to_string(),
    );
    match telemetry.cpu_math_fallback_reason {
        Some(reason) => {
            metadata.insert("cpu_math_fallback_reason".to_string(), reason);
        }
        None => {
            metadata.remove("cpu_math_fallback_reason");
        }
    }
    metadata.insert(
        "metal_gpu_busy_ratio".to_string(),
        telemetry.metal_gpu_busy_ratio.to_string(),
    );
    metadata.insert(
        "metal_stage_breakdown".to_string(),
        telemetry.metal_stage_breakdown,
    );
    metadata.insert(
        "metal_inflight_jobs".to_string(),
        telemetry.metal_inflight_jobs.to_string(),
    );
    metadata.insert(
        "metal_no_cpu_fallback".to_string(),
        telemetry.metal_no_cpu_fallback.to_string(),
    );
    metadata.insert(
        "metal_counter_source".to_string(),
        telemetry.metal_counter_source.to_string(),
    );
    metadata.insert(
        "hash_accelerator".to_string(),
        telemetry.hash_accelerator.to_string(),
    );
    metadata.insert(
        "poseidon2_accelerator".to_string(),
        telemetry.hash_accelerator.to_string(),
    );
    if telemetry.hash_accelerator == "cpu" {
        if let Some(reason) = plonky3_hash_merkle_fallback_reason(field, trace_height, trace_width)
        {
            metadata.insert("hash_fallback_reason".to_string(), reason.to_string());
            metadata.insert("poseidon2_fallback_reason".to_string(), reason.to_string());
        }
    } else {
        metadata.remove("hash_fallback_reason");
        metadata.remove("poseidon2_fallback_reason");
    }
}

fn plonky3_run_telemetry(
    field: FieldId,
    trace_height: usize,
    trace_width: usize,
    ntt_summary: NttDispatchSummary,
) -> Plonky3RunTelemetry {
    let required = plonky3_required_gpu_stages(field);
    let mut metal_stages = Vec::new();
    let mut cpu_stages = Vec::new();
    let ntt_uses_metal = ntt_summary.accelerator == "metal";
    let hash_uses_metal = plonky3_hash_merkle_uses_gpu(field, trace_height, trace_width);

    for stage in &required {
        let uses_metal = match stage {
            GpuStage::FftNtt => ntt_uses_metal,
            GpuStage::HashMerkle => hash_uses_metal,
            _ => false,
        };
        if uses_metal {
            metal_stages.push(stage.as_str().to_string());
        } else {
            cpu_stages.push(stage.as_str().to_string());
        }
    }

    let coverage_ratio = if required.is_empty() {
        0.0
    } else {
        metal_stages.len() as f64 / required.len() as f64
    };
    let required_stages = required
        .iter()
        .map(|stage| stage.as_str().to_string())
        .collect::<Vec<_>>();
    let stage_breakdown = {
        let mut stages = BTreeMap::new();
        stages.insert(
            GpuStage::FftNtt.as_str().to_string(),
            Plonky3StageTelemetry {
                accelerator: ntt_summary.accelerator.to_string(),
                used_metal: ntt_uses_metal,
                fallback_reason: ntt_summary.fallback_reason.map(str::to_string),
                trace_rows: trace_height,
                trace_width,
            },
        );
        if matches!(field, FieldId::Goldilocks | FieldId::BabyBear) {
            stages.insert(
                GpuStage::HashMerkle.as_str().to_string(),
                Plonky3StageTelemetry {
                    accelerator: if hash_uses_metal {
                        "metal".to_string()
                    } else {
                        "cpu".to_string()
                    },
                    used_metal: hash_uses_metal,
                    fallback_reason: plonky3_hash_merkle_fallback_reason(
                        field,
                        trace_height,
                        trace_width,
                    )
                    .map(str::to_string),
                    trace_rows: trace_height,
                    trace_width,
                },
            );
        }
        serde_json::to_string(&stages).unwrap_or_else(|_| "{}".to_string())
    };
    let metal_complete = !required_stages.is_empty() && cpu_stages.is_empty();
    let cpu_math_fallback_reason = if metal_complete {
        None
    } else {
        plonky3_cpu_math_fallback_reason(field, trace_height, trace_width, ntt_summary)
    };

    Plonky3RunTelemetry {
        coverage: GpuStageCoverage {
            coverage_ratio,
            required_stages,
            metal_stages: metal_stages.clone(),
            cpu_stages: cpu_stages.clone(),
        },
        metal_complete,
        cpu_math_fallback_reason,
        metal_gpu_busy_ratio: coverage_ratio,
        metal_stage_breakdown: stage_breakdown,
        metal_inflight_jobs: if metal_stages.is_empty() {
            0
        } else if metal_stages.len() > 1 {
            2
        } else {
            1
        },
        metal_no_cpu_fallback: !required.is_empty() && cpu_stages.is_empty(),
        metal_counter_source: "plonky3-dispatch+threshold-estimate-v1",
        hash_accelerator: if hash_uses_metal { "metal" } else { "cpu" },
    }
}

fn plonky3_required_gpu_stages(field: FieldId) -> Vec<GpuStage> {
    match field {
        FieldId::Goldilocks | FieldId::BabyBear => vec![GpuStage::FftNtt, GpuStage::HashMerkle],
        FieldId::Mersenne31 => Vec::new(),
        _ => Vec::new(),
    }
}

fn plonky3_cpu_math_fallback_reason(
    field: FieldId,
    trace_height: usize,
    trace_width: usize,
    ntt_summary: NttDispatchSummary,
) -> Option<String> {
    if field == FieldId::Mersenne31 {
        return Some("mersenne31-circle-path-remains-cpu-classified".to_string());
    }

    let mut reasons = Vec::new();
    if ntt_summary.accelerator != "metal" {
        reasons.push(format!(
            "{}({})",
            GpuStage::FftNtt.as_str(),
            ntt_summary.fallback_reason.unwrap_or("cpu")
        ));
    }
    if !plonky3_hash_merkle_uses_gpu(field, trace_height, trace_width) {
        reasons.push(format!(
            "{}({})",
            GpuStage::HashMerkle.as_str(),
            plonky3_hash_merkle_fallback_reason(field, trace_height, trace_width).unwrap_or("cpu")
        ));
    }
    if reasons.is_empty() {
        None
    } else {
        Some(format!("cpu-only-stages:{}", reasons.join(",")))
    }
}

fn plonky3_hash_merkle_uses_gpu(field: FieldId, trace_height: usize, trace_width: usize) -> bool {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        if !matches!(field, FieldId::Goldilocks | FieldId::BabyBear)
            || zkf_metal::global_context().is_none()
        {
            return false;
        }
        let thresholds = zkf_metal::current_thresholds();
        trace_height >= thresholds.merkle && trace_width <= 8
    }

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    {
        let _ = (field, trace_height, trace_width);
        false
    }
}

fn plonky3_hash_merkle_fallback_reason(
    field: FieldId,
    trace_height: usize,
    trace_width: usize,
) -> Option<&'static str> {
    if !matches!(field, FieldId::Goldilocks | FieldId::BabyBear) {
        return Some("field-not-metal-mmcs-backed");
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        if zkf_metal::global_context().is_none() {
            return Some("metal-unavailable");
        }
        if trace_width > 8 {
            return Some("trace-width-exceeds-metal-mmcs-limit");
        }
        if trace_height < zkf_metal::current_thresholds().merkle {
            return Some("below-threshold");
        }
        None
    }

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    {
        let _ = (trace_height, trace_width);
        Some("metal-feature-disabled")
    }
}

fn eval_air_expr<AB: AirBuilderWithPublicValues>(expr: &AirExpr, local: &[AB::Var]) -> AB::Expr {
    match expr {
        AirExpr::Const(value) => AB::Expr::from_u64(*value),
        AirExpr::Signal(index) => AB::Expr::from(local[*index].clone()),
        AirExpr::Add(values) => values.iter().fold(AB::Expr::ZERO, |acc, value| {
            acc + eval_air_expr::<AB>(value, local)
        }),
        AirExpr::Sub(left, right) => {
            eval_air_expr::<AB>(left, local) - eval_air_expr::<AB>(right, local)
        }
        AirExpr::Mul(left, right) => {
            eval_air_expr::<AB>(left, local) * eval_air_expr::<AB>(right, local)
        }
    }
}

#[allow(dead_code)]
pub(crate) fn eval_air_expr_concrete(expr: &AirExpr, row: &[u64], modulus: u64) -> u64 {
    spec_eval_air_expr_concrete(expr, row, modulus)
}

fn to_field_slice<F: PrimeField64>(values: &[FieldElement], field: FieldId) -> ZkfResult<Vec<F>> {
    values
        .iter()
        .map(|value| {
            parse_field_u64(value, field)
                .map(F::from_u64)
                .map_err(Into::into)
        })
        .collect()
}

fn ensure_compiled_backend(expected: BackendKind, compiled: &CompiledProgram) -> ZkfResult<()> {
    if compiled.backend != expected {
        return Err(ZkfError::InvalidArtifact(format!(
            "compiled backend is {}, expected {}",
            compiled.backend, expected
        )));
    }
    Ok(())
}

fn plonky3_seed(program_digest: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(program_digest.as_bytes());
    let hash = hasher.finalize();
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(seed_bytes)
}

fn verification_key_fingerprint(
    program_digest: &str,
    field: FieldId,
    width: usize,
    public_signal_indices: &[usize],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-plonky3-v1");
    hasher.update(program_digest.as_bytes());
    hasher.update(field.as_str().as_bytes());
    hasher.update(width.to_le_bytes());
    for index in public_signal_indices {
        hasher.update(index.to_le_bytes());
    }
    hasher.finalize().to_vec()
}

// --- NativeField implementations for Plonky3 field types ---

impl crate::native_field::NativeField for Goldilocks {
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        let val = parse_field_u64(fe, field)?;
        Ok(Goldilocks::from_u64(val))
    }

    fn to_field_element(&self) -> FieldElement {
        FieldElement::from_u64(self.as_canonical_u64())
    }

    fn field_id() -> FieldId {
        FieldId::Goldilocks
    }
}

impl crate::native_field::NativeField for BabyBear {
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        let val = parse_field_u64(fe, field)?;
        Ok(BabyBear::from_u64(val))
    }

    fn to_field_element(&self) -> FieldElement {
        FieldElement::from_u64(self.as_canonical_u64())
    }

    fn field_id() -> FieldId {
        FieldId::BabyBear
    }
}

impl crate::native_field::NativeField for Mersenne31 {
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        let val = parse_field_u64(fe, field)?;
        Ok(Mersenne31::from_u64(val))
    }

    fn to_field_element(&self) -> FieldElement {
        FieldElement::from_u64(self.as_canonical_u64())
    }

    fn field_id() -> FieldId {
        FieldId::Mersenne31
    }
}
