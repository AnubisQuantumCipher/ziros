use crate::BackendEngine;
use crate::audited_backend::{
    attach_r1cs_lowering_metadata, audited_witness_for_proving, build_audited_compiled_program,
    remember_unchecked_compile_gate_bypass,
};
use crate::blackbox_native::supported_blackbox_ops;
use crate::compat::NovaBackend as CompatNovaBackend;
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::r1cs_lowering::lower_program_for_backend;
use ff::Field;
use ff::PrimeField as FfPrimeField;
use nova_snark::frontend::gadgets::boolean::Boolean;
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::neutron::{
    PublicParams as HyperPublicParams, RecursiveSNARK as HyperRecursiveSnark,
};
use nova_snark::nova::{
    CompressedSNARK as ClassicCompressedSNARK, PublicParams as ClassicPublicParams,
    RecursiveSNARK as ClassicRecursiveSnark,
};
use nova_snark::provider::ipa_pc::EvaluationEngine;
use nova_snark::provider::msm::{
    PastaMetalMsmTelemetry, reset_pasta_metal_msm_telemetry, take_pasta_metal_msm_telemetry,
};
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use nova_snark::traits::Engine;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::snark::default_ck_hint;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, Constraint, Expr, FieldElement,
    FieldId, PressureLevel, Program, ProofArtifact, SystemResources, Witness, ZkfError, ZkfResult,
    collect_public_inputs,
};

pub struct NovaNativeBackend;

type PrimaryEngine = PallasEngine;
type SecondaryEngine = VestaEngine;
type PrimaryScalar = <PrimaryEngine as Engine>::Scalar;
type ClassicParams = ClassicPublicParams<PrimaryEngine, SecondaryEngine, IrStepCircuit>;
type ClassicRecursive = ClassicRecursiveSnark<PrimaryEngine, SecondaryEngine, IrStepCircuit>;
type HyperParams = HyperPublicParams<PrimaryEngine, SecondaryEngine, IrStepCircuit>;
type HyperRecursive = HyperRecursiveSnark<PrimaryEngine, SecondaryEngine, IrStepCircuit>;

type PrimarySpartan = RelaxedR1CSSNARK<PrimaryEngine, EvaluationEngine<PrimaryEngine>>;
type SecondarySpartan = RelaxedR1CSSNARK<SecondaryEngine, EvaluationEngine<SecondaryEngine>>;
type ClassicCompressed = ClassicCompressedSNARK<
    PrimaryEngine,
    SecondaryEngine,
    IrStepCircuit,
    PrimarySpartan,
    SecondarySpartan,
>;

const NOVA_NATIVE_MODE: &str = "recursive-snark-v2";
const LARGE_NOVA_SETUP_SIGNAL_THRESHOLD: usize = 250_000;
const LARGE_NOVA_SETUP_CONSTRAINT_THRESHOLD: usize = 250_000;
const FORTY_EIGHT_GIB: u64 = 48 * 1024 * 1024 * 1024;
const SIXTY_FOUR_GIB: u64 = 64 * 1024 * 1024 * 1024;

fn append_nova_metal_msm_metadata(
    metadata: &mut BTreeMap<String, String>,
    telemetry: &PastaMetalMsmTelemetry,
) {
    if !telemetry.metal_used() {
        return;
    }

    let runtime = crate::metal_runtime::metal_runtime_report();
    let msm_engine = format!("metal-pasta-msm/{}", telemetry.curves.join("+"));
    metadata.insert("msm_accelerator".to_string(), "metal".to_string());
    metadata.insert("nova_msm_engine".to_string(), msm_engine.clone());
    metadata.insert("best_msm_accelerator".to_string(), msm_engine);
    metadata.insert(
        "metal_gpu_busy_ratio".to_string(),
        runtime.metal_gpu_busy_ratio.to_string(),
    );
    metadata.insert(
        "metal_stage_breakdown".to_string(),
        serde_json::json!({
            "msm": {
                "accelerator": "metal-pasta-msm",
                "curves": telemetry.curves,
            }
        })
        .to_string(),
    );
    metadata.insert(
        "metal_inflight_jobs".to_string(),
        runtime.metal_inflight_jobs.to_string(),
    );
    metadata.insert(
        "metal_no_cpu_fallback".to_string(),
        (telemetry.used_curve("pallas") && telemetry.used_curve("vesta")).to_string(),
    );
    metadata.insert(
        "metal_counter_source".to_string(),
        runtime.metal_counter_source.clone(),
    );
    metadata.insert(
        "metal_dispatch_circuit_open".to_string(),
        runtime.metal_dispatch_circuit_open.to_string(),
    );
    metadata.insert(
        "metal_dispatch_last_failure".to_string(),
        runtime.metal_dispatch_last_failure.unwrap_or_default(),
    );
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum NovaProfile {
    Classic,
    HyperNova,
}

impl NovaProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::HyperNova => "hypernova",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "classic" | "nova" => Some(Self::Classic),
            "hypernova" | "hyper" => Some(Self::HyperNova),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct IrStepCircuit {
    program: Program,
    values: BTreeMap<String, FieldElement>,
    state_input_signal: String,
    state_output_signal: String,
    expected_state: Option<PrimaryScalar>,
}

impl IrStepCircuit {
    fn shape(program: Program) -> ZkfResult<Self> {
        let bindings = resolve_ivc_state_bindings(&program, false)?;
        let mut values = BTreeMap::new();
        for signal in &program.signals {
            let value = signal
                .constant
                .clone()
                .unwrap_or_else(|| FieldElement::from_i64(0));
            values.insert(signal.name.clone(), value);
        }
        // No expected_state constraint in the canonical shape — fold circuits
        // use `for_fold` (expected_state: None), so the shape must match.
        // Single-step `prove_native` uses `from_witness`, but the extra
        // constraint is harmless there because single-step verify never folds.
        Ok(Self {
            program,
            values,
            state_input_signal: bindings.input_signal,
            state_output_signal: bindings.output_signal,
            expected_state: None,
        })
    }

    fn from_witness(program: Program, witness: &Witness, _state: PrimaryScalar) -> ZkfResult<Self> {
        let bindings = resolve_ivc_state_bindings(&program, false)?;
        let mut values = BTreeMap::new();
        for signal in &program.signals {
            let value = witness
                .values
                .get(&signal.name)
                .or(signal.constant.as_ref())
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: signal.name.clone(),
                })?;
            values.insert(signal.name.clone(), value.clone());
        }
        // No expected_state constraint: the shape (used in PublicParams::setup) has
        // expected_state: None, so all step circuits must match that structure.
        // Nova's own verify already commits to z0/z_N; the extra constraint is redundant.
        Ok(Self {
            program,
            values,
            state_input_signal: bindings.input_signal,
            state_output_signal: bindings.output_signal,
            expected_state: None,
        })
    }

    /// Build a step circuit for IVC folding — no state commitment constraint.
    ///
    /// The `expected_state` equality constraint (`z[0] == z0`) is correct for
    /// single-step proving but causes the relaxed R1CS accumulator to become
    /// unsatisfiable when folding across N > 1 steps.  Nova's own IVC machinery
    /// commits to the initial / final state; the extra per-step constraint is
    /// both redundant and incompatible with multi-step folding.
    fn for_fold(program: Program, witness: &Witness) -> ZkfResult<Self> {
        let bindings = resolve_ivc_state_bindings(&program, true)?;
        let mut values = BTreeMap::new();
        for signal in &program.signals {
            let value = witness
                .values
                .get(&signal.name)
                .or(signal.constant.as_ref())
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: signal.name.clone(),
                })?;
            values.insert(signal.name.clone(), value.clone());
        }
        Ok(Self {
            program,
            values,
            state_input_signal: bindings.input_signal,
            state_output_signal: bindings.output_signal,
            expected_state: None,
        })
    }
}

impl StepCircuit<PrimaryScalar> for IrStepCircuit {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<PrimaryScalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<PrimaryScalar>],
    ) -> Result<Vec<AllocatedNum<PrimaryScalar>>, SynthesisError> {
        if z.len() != 1 {
            return Err(SynthesisError::Unsatisfiable(format!(
                "expected exactly one Nova step input, found {}",
                z.len()
            )));
        }

        let mut signals = BTreeMap::<String, AllocatedNum<PrimaryScalar>>::new();
        for signal in &self.program.signals {
            let value = self
                .values
                .get(&signal.name)
                .or(signal.constant.as_ref())
                .ok_or(SynthesisError::AssignmentMissing)?;
            let parsed = parse_scalar(value)?;

            let allocated = if signal.name == self.state_input_signal {
                // Bind h_in signal directly to Nova input state z[0]
                let bound = AllocatedNum::alloc(
                    cs.namespace(|| format!("signal_{}", signal.name)),
                    || Ok(parsed),
                )?;
                cs.enforce(
                    || format!("bind_{}", signal.name),
                    |lc| lc + bound.get_variable() - z[0].get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc,
                );
                bound
            } else {
                AllocatedNum::alloc(cs.namespace(|| format!("signal_{}", signal.name)), || {
                    Ok(parsed)
                })?
            };
            signals.insert(signal.name.clone(), allocated);
        }

        let mut aux_counter = 0usize;
        for (constraint_index, constraint) in self.program.constraints.iter().enumerate() {
            match constraint {
                Constraint::Equal { lhs, rhs, .. } => {
                    let lhs_num = lower_expr(cs, lhs, &signals, &mut aux_counter)?;
                    let rhs_num = lower_expr(cs, rhs, &signals, &mut aux_counter)?;
                    cs.enforce(
                        || format!("constraint_equal_{constraint_index}"),
                        |lc| lc + lhs_num.get_variable() - rhs_num.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc,
                    );
                }
                Constraint::Boolean { signal, .. } => {
                    let value = signals
                        .get(signal)
                        .ok_or(SynthesisError::AssignmentMissing)?
                        .clone();
                    cs.enforce(
                        || format!("constraint_boolean_{constraint_index}"),
                        |lc| lc + value.get_variable(),
                        |lc| lc + CS::one() - value.get_variable(),
                        |lc| lc,
                    );
                }
                Constraint::Range { signal, bits, .. } => {
                    let value = signals
                        .get(signal)
                        .ok_or(SynthesisError::AssignmentMissing)?
                        .clone();
                    let bit_values = value.to_bits_le(
                        cs.namespace(|| format!("constraint_range_bits_{constraint_index}")),
                    )?;
                    let bits_usize = usize::try_from(*bits).map_err(|_| {
                        SynthesisError::Unsatisfiable(format!(
                            "range bit size does not fit platform usize: {bits}"
                        ))
                    })?;
                    if bits_usize > bit_values.len() {
                        return Err(SynthesisError::Unsatisfiable(format!(
                            "range constraint requests {bits} bits, but field representation has only {} bits",
                            bit_values.len()
                        )));
                    }
                    for (bit_index, bit) in bit_values.iter().enumerate().skip(bits_usize) {
                        Boolean::enforce_equal(
                            cs.namespace(|| {
                                format!("constraint_range_zero_{constraint_index}_{bit_index}")
                            }),
                            bit,
                            &Boolean::Constant(false),
                        )?;
                    }
                }
                Constraint::BlackBox { op, .. } => {
                    if *op == zkf_core::BlackBoxOp::RecursiveAggregationMarker {
                        continue;
                    }
                    return Err(SynthesisError::Unsatisfiable(
                        "BlackBox constraint reached Nova synthesis — call lower_blackbox_program() first".into()
                    ));
                }
                Constraint::Lookup { .. } => {
                    return Err(SynthesisError::Unsatisfiable(
                        "Lookup constraint reached Nova synthesis — call lower_lookup_constraints() first".into()
                    ));
                }
            }
        }

        if let Some(expected) = self.expected_state {
            let expected_alloc = AllocatedNum::alloc(
                cs.namespace(|| "nova_state_commitment_expected".to_string()),
                || Ok(expected),
            )?;
            cs.enforce(
                || "nova_state_commitment".to_string(),
                |lc| lc + z[0].get_variable() - expected_alloc.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc,
            );
        }

        let z_out = signals
            .get(&self.state_output_signal)
            .ok_or(SynthesisError::AssignmentMissing)?;
        Ok(vec![z_out.clone()])
    }
}

impl BackendEngine for NovaNativeBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Nova
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Nova,
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
            native_profiles: vec!["classic".to_string(), "hypernova".to_string()],
            notes: "Native Nova backend (nova-snark) with IR-backed step circuit and classic/hypernova profiles. Compatibility delegation is disabled by default and can be enabled only with ZKF_NOVA_ALLOW_COMPAT_DELEGATE=true."
                .to_string(),
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        // Accept BN254 (for compatibility with wrapped circuits) and PastaFq/PastaFp
        // (the native Pallas/Vesta scalar fields used by Nova's R1CS engine).
        // Programs using other fields would produce incorrect witnesses because the
        // witness solver reduces mod the program field while Nova reduces mod PastaFq.
        match program.field {
            FieldId::Bn254 | FieldId::PastaFq | FieldId::PastaFp => {}
            _ => {
                return Err(ZkfError::UnsupportedBackend {
                    backend: self.kind().to_string(),
                    message: format!(
                        "native nova backend requires BN254, pasta-fq, or pasta-fp field; got {}",
                        program.field.as_str()
                    ),
                });
            }
        }
        compile_native_with_profile(program, requested_nova_profile())
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        ensure_compiled_backend(self.kind(), compiled)?;
        let enriched = audited_witness_for_proving(self.kind(), compiled, witness)?;
        let witness = &enriched;

        match prove_native(compiled, witness) {
            Ok(artifact) => Ok(artifact),
            Err(native_err) if allow_compat_delegate() => {
                let compat = CompatNovaBackend;
                let compat_compiled = compat.compile(&compiled.program)?;
                let mut artifact = compat.prove(&compat_compiled, witness)?;
                artifact.backend = BackendKind::Nova;
                artifact
                    .metadata
                    .insert("native_fallback_reason".to_string(), native_err.to_string());
                artifact.metadata.insert(
                    "nova_native_mode".to_string(),
                    "delegate-fallback".to_string(),
                );
                artifact.metadata.insert(
                    "delegated_backend".to_string(),
                    compat_compiled.backend.as_str().to_string(),
                );
                Ok(artifact)
            }
            Err(native_err) => Err(ZkfError::Backend(format!(
                "native nova proving failed: {native_err}; set ZKF_NOVA_ALLOW_COMPAT_DELEGATE=true to allow compatibility fallback"
            ))),
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

        match artifact.metadata.get("nova_native_mode").map(String::as_str) {
            Some(NOVA_NATIVE_MODE) => verify_native(compiled, artifact),
            Some("delegate-fallback") if allow_compat_delegate() => {
                let compat = CompatNovaBackend;
                let compat_compiled = compat.compile(&compiled.program)?;
                let mut delegated = artifact.clone();
                delegated.backend = compat_compiled.backend;
                compat.verify(&compat_compiled, &delegated)
            }
            Some("delegate-fallback") => Err(ZkfError::Backend(
                "artifact was produced via compatibility fallback; set ZKF_NOVA_ALLOW_COMPAT_DELEGATE=true to verify it"
                    .to_string(),
            )),
            _ => Err(ZkfError::InvalidArtifact(
                "unsupported nova_native_mode in proof artifact".to_string(),
            )),
        }
    }
}

fn allow_compat_delegate() -> bool {
    std::env::var("ZKF_NOVA_ALLOW_COMPAT_DELEGATE")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn requested_nova_profile() -> NovaProfile {
    std::env::var("ZKF_NOVA_PROFILE")
        .ok()
        .and_then(|value| NovaProfile::parse(&value))
        .unwrap_or(NovaProfile::Classic)
}

fn trace_nova_compile_enabled() -> bool {
    std::env::var("ZKF_TRACE_NOVA_COMPILE")
        .ok()
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn recommended_nova_setup_thread_cap(
    signal_count: usize,
    constraint_count: usize,
    resources: &SystemResources,
) -> Option<usize> {
    if signal_count < LARGE_NOVA_SETUP_SIGNAL_THRESHOLD
        && constraint_count < LARGE_NOVA_SETUP_CONSTRAINT_THRESHOLD
    {
        return None;
    }

    if !resources.unified_memory {
        return None;
    }

    if matches!(resources.pressure.level, PressureLevel::Normal)
        && resources.total_ram_bytes > SIXTY_FOUR_GIB
    {
        return None;
    }

    Some(match resources.pressure.level {
        PressureLevel::Critical | PressureLevel::High => 1,
        PressureLevel::Elevated => 2,
        PressureLevel::Normal => {
            if resources.total_ram_bytes <= FORTY_EIGHT_GIB {
                4
            } else {
                6
            }
        }
    })
}

fn configure_large_nova_setup_parallelism(program: &Program) {
    if std::env::var_os("RAYON_NUM_THREADS").is_some() {
        return;
    }

    let requested_threads = std::env::var("ZKF_NOVA_SETUP_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|threads| threads.max(1))
        .or_else(|| {
            let resources = SystemResources::detect();
            recommended_nova_setup_thread_cap(
                program.signals.len(),
                program.constraints.len(),
                &resources,
            )
        });

    let Some(threads) = requested_threads else {
        return;
    };

    if trace_nova_compile_enabled() {
        eprintln!("[nova-native-compile] setting RAYON_NUM_THREADS={threads} for large setup");
    }

    // Rayon reads this before first pool initialization. Respect an explicit
    // `RAYON_NUM_THREADS` override, but provide a bounded default for large
    // unified-memory Nova setup on Apple Silicon hosts.
    unsafe {
        std::env::set_var("RAYON_NUM_THREADS", threads.to_string());
    }
}

pub(crate) fn compile_native_with_profile(
    program: &Program,
    profile: NovaProfile,
) -> ZkfResult<CompiledProgram> {
    let trace_compile = trace_nova_compile_enabled();
    if trace_compile {
        eprintln!(
            "[nova-native-compile] lowering program '{}' with profile {}",
            program.name,
            profile.as_str()
        );
    }
    let lowered = lower_program_for_backend(program, BackendKind::Nova)?;
    let lowered_program = lowered.program.clone();

    if trace_compile {
        eprintln!(
            "[nova-native-compile] lowered program has {} signals and {} constraints",
            lowered_program.signals.len(),
            lowered_program.constraints.len()
        );
    }
    let mut compiled =
        build_audited_compiled_program(BackendKind::Nova, program, lowered_program.clone())?;
    if trace_compile {
        eprintln!("[nova-native-compile] built audited compiled artifact");
    }
    configure_large_nova_setup_parallelism(&lowered_program);
    let shape_circuit = IrStepCircuit::shape(lowered_program)?;
    if trace_compile {
        eprintln!("[nova-native-compile] materialized shape circuit");
    }
    compiled.compiled_data = Some(encode_public_params(profile, &shape_circuit)?);
    if trace_compile {
        eprintln!("[nova-native-compile] encoded public parameters");
    }
    compiled
        .metadata
        .insert("nova_native_mode".to_string(), NOVA_NATIVE_MODE.to_string());
    compiled
        .metadata
        .insert("nova_profile".to_string(), profile.as_str().to_string());
    compiled
        .metadata
        .insert("nova_curve_cycle".to_string(), "pallas-vesta".to_string());
    compiled
        .metadata
        .insert("nova_step_arity".to_string(), "1".to_string());
    compiled
        .metadata
        .insert("scheme".to_string(), "nova-ivc".to_string());
    compiled
        .metadata
        .insert("mode".to_string(), "native".to_string());
    attach_r1cs_lowering_metadata(&mut compiled, &lowered);
    crate::metal_runtime::append_trust_metadata(
        &mut compiled.metadata,
        "native",
        "cryptographic",
        1,
    );
    remember_unchecked_compile_gate_bypass(BackendKind::Nova, program, &compiled.program);
    Ok(compiled)
}

/// Internal-style helper for heavyweight showcase/example paths that need a valid
/// Nova compiled artifact without paying the full audited compile duplication cost.
///
/// This still performs backend lowering, retains the original program when the
/// lowered digest differs, and emits the same public-parameter surface as the
/// production backend. It deliberately skips the audited compile gate to keep
/// peak memory bounded for very large lowered programs.
#[doc(hidden)]
pub fn compile_nova_unchecked(program: &Program) -> ZkfResult<CompiledProgram> {
    let profile = requested_nova_profile();

    match program.field {
        FieldId::Bn254 | FieldId::PastaFq | FieldId::PastaFp => {}
        _ => {
            return Err(ZkfError::UnsupportedBackend {
                backend: BackendKind::Nova.to_string(),
                message: format!(
                    "native nova backend requires BN254, pasta-fq, or pasta-fp field; got {}",
                    program.field.as_str()
                ),
            });
        }
    }

    let lowered = lower_program_for_backend(program, BackendKind::Nova)?;
    let lowered_program = lowered.program.clone();
    configure_large_nova_setup_parallelism(&lowered_program);
    let shape_circuit = IrStepCircuit::shape(lowered_program.clone())?;
    let mut compiled = CompiledProgram::new(BackendKind::Nova, lowered_program);
    if program
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, Constraint::BlackBox { .. }))
    {
        compiled.original_program = Some(program.clone());
    }
    compiled.compiled_data = Some(encode_public_params(profile, &shape_circuit)?);
    compiled
        .metadata
        .insert("nova_native_mode".to_string(), NOVA_NATIVE_MODE.to_string());
    compiled
        .metadata
        .insert("nova_profile".to_string(), profile.as_str().to_string());
    compiled
        .metadata
        .insert("nova_curve_cycle".to_string(), "pallas-vesta".to_string());
    compiled
        .metadata
        .insert("nova_step_arity".to_string(), "1".to_string());
    compiled
        .metadata
        .insert("scheme".to_string(), "nova-ivc".to_string());
    compiled
        .metadata
        .insert("mode".to_string(), "native".to_string());
    attach_r1cs_lowering_metadata(&mut compiled, &lowered);
    crate::metal_runtime::append_trust_metadata(
        &mut compiled.metadata,
        "native",
        "cryptographic",
        1,
    );
    Ok(compiled)
}

fn compiled_profile(compiled: &CompiledProgram) -> ZkfResult<NovaProfile> {
    let Some(value) = compiled.metadata.get("nova_profile") else {
        return Ok(NovaProfile::Classic);
    };
    NovaProfile::parse(value).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "unsupported nova_profile in compiled metadata: {value}"
        ))
    })
}

fn artifact_profile(artifact: &ProofArtifact) -> ZkfResult<NovaProfile> {
    let Some(value) = artifact.metadata.get("nova_profile") else {
        return Ok(NovaProfile::Classic);
    };
    NovaProfile::parse(value).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "unsupported nova_profile in proof metadata: {value}"
        ))
    })
}

fn prove_native(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
    let profile = compiled_profile(compiled)?;
    let public_inputs = collect_public_inputs(&compiled.program, witness)?;
    let z0 = proof_initial_state(compiled, witness, &public_inputs)?;
    let circuit = IrStepCircuit::from_witness(compiled.program.clone(), witness, z0)?;
    reset_pasta_metal_msm_telemetry();

    let (proof, final_state) = match profile {
        NovaProfile::Classic => {
            let params = decode_classic_params(compiled)?;
            let mut recursive = ClassicRecursive::new(&params, &circuit, &[z0])
                .map_err(|err| ZkfError::Backend(format!("nova recursive setup failed: {err}")))?;
            recursive
                .prove_step(&params, &circuit)
                .map_err(|err| ZkfError::Backend(format!("nova prove_step failed: {err}")))?;
            let outputs = recursive
                .verify(&params, 1, &[z0])
                .map_err(|err| ZkfError::Backend(format!("nova self-check failed: {err}")))?;
            let final_state = outputs.first().cloned().ok_or_else(|| {
                ZkfError::Backend("nova self-check returned no state".to_string())
            })?;
            let proof = postcard::to_allocvec(&recursive)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            (proof, final_state)
        }
        NovaProfile::HyperNova => {
            let params = decode_hyper_params(compiled)?;
            let mut recursive = HyperRecursive::new(&params, &circuit, &[z0]).map_err(|err| {
                ZkfError::Backend(format!("hypernova recursive setup failed: {err}"))
            })?;
            recursive
                .prove_step(&params, &circuit)
                .map_err(|err| ZkfError::Backend(format!("hypernova prove_step failed: {err}")))?;
            let outputs = recursive
                .verify(&params, 1, &[z0])
                .map_err(|err| ZkfError::Backend(format!("hypernova self-check failed: {err}")))?;
            let final_state = outputs.first().cloned().ok_or_else(|| {
                ZkfError::Backend("hypernova self-check returned no state".to_string())
            })?;
            let proof = postcard::to_allocvec(&recursive)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            (proof, final_state)
        }
    };

    let nova_metal_msm = take_pasta_metal_msm_telemetry();
    let verification_key = verification_key_fingerprint(compiled, profile);

    let mut metadata = BTreeMap::new();
    metadata.insert("nova_native_mode".to_string(), NOVA_NATIVE_MODE.to_string());
    metadata.insert("nova_steps".to_string(), "1".to_string());
    metadata.insert("nova_curve_cycle".to_string(), "pallas-vesta".to_string());
    metadata.insert("nova_profile".to_string(), profile.as_str().to_string());
    append_ivc_state_metadata(&mut metadata, compiled, z0, final_state);
    append_nova_metal_msm_metadata(&mut metadata, &nova_metal_msm);
    append_backend_runtime_metadata(&mut metadata, BackendKind::Nova);

    Ok(ProofArtifact {
        backend: BackendKind::Nova,
        program_digest: compiled.program_digest.clone(),
        proof,
        verification_key,
        public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    })
}

fn verify_native(compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
    let compiled_profile = compiled_profile(compiled)?;
    let artifact_profile = artifact_profile(artifact)?;
    if compiled_profile != artifact_profile {
        return Err(ZkfError::InvalidArtifact(format!(
            "nova profile mismatch: compiled={}, artifact={}",
            compiled_profile.as_str(),
            artifact_profile.as_str()
        )));
    }

    let expected_vk = verification_key_fingerprint(compiled, compiled_profile);
    if artifact.verification_key != expected_vk {
        return Err(ZkfError::InvalidArtifact(
            "nova native verification key fingerprint mismatch".to_string(),
        ));
    }

    let z0 = artifact_initial_state(compiled, artifact)?;
    match compiled_profile {
        NovaProfile::Classic => {
            let params = decode_classic_params(compiled)?;
            let recursive: ClassicRecursive = postcard::from_bytes(&artifact.proof)
                .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
            let outputs = recursive
                .verify(&params, 1, &[z0])
                .map_err(|err| ZkfError::Backend(format!("nova verify failed: {err}")))?;
            verify_expected_final_state(artifact, &outputs)?;
            Ok(true)
        }
        NovaProfile::HyperNova => {
            let params = decode_hyper_params(compiled)?;
            let recursive: HyperRecursive = postcard::from_bytes(&artifact.proof)
                .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
            let outputs = recursive
                .verify(&params, 1, &[z0])
                .map_err(|err| ZkfError::Backend(format!("hypernova verify failed: {err}")))?;
            verify_expected_final_state(artifact, &outputs)?;
            Ok(true)
        }
    }
}

fn encode_public_params(profile: NovaProfile, circuit: &IrStepCircuit) -> ZkfResult<Vec<u8>> {
    match profile {
        NovaProfile::Classic => {
            let params = ClassicPublicParams::setup(
                circuit,
                &*default_ck_hint::<PrimaryEngine>(),
                &*default_ck_hint::<SecondaryEngine>(),
            )
            .map_err(|err| ZkfError::Backend(format!("nova setup failed: {err}")))?;
            postcard::to_allocvec(&params).map_err(|err| ZkfError::Serialization(err.to_string()))
        }
        NovaProfile::HyperNova => {
            let params = HyperPublicParams::setup(
                circuit,
                &*default_ck_hint::<PrimaryEngine>(),
                &*default_ck_hint::<SecondaryEngine>(),
            )
            .map_err(|err| ZkfError::Backend(format!("hypernova setup failed: {err}")))?;
            postcard::to_allocvec(&params).map_err(|err| ZkfError::Serialization(err.to_string()))
        }
    }
}

fn decode_classic_params(compiled: &CompiledProgram) -> ZkfResult<ClassicParams> {
    let bytes = compiled
        .compiled_data
        .as_deref()
        .ok_or(ZkfError::MissingCompiledData)?;
    postcard::from_bytes(bytes).map_err(|err| ZkfError::InvalidArtifact(err.to_string()))
}

fn decode_hyper_params(compiled: &CompiledProgram) -> ZkfResult<HyperParams> {
    let bytes = compiled
        .compiled_data
        .as_deref()
        .ok_or(ZkfError::MissingCompiledData)?;
    postcard::from_bytes(bytes).map_err(|err| ZkfError::InvalidArtifact(err.to_string()))
}

fn verification_key_fingerprint(compiled: &CompiledProgram, profile: NovaProfile) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-nova-native-v2");
    hasher.update(profile.as_str().as_bytes());
    hasher.update(compiled.program_digest.as_bytes());
    if let Some(data) = compiled.compiled_data.as_ref() {
        hasher.update(data);
    }
    hasher.finalize().to_vec()
}

fn initial_state(_compiled: &CompiledProgram, public_inputs: &[FieldElement]) -> PrimaryScalar {
    if let Some(first) = public_inputs.first()
        && let Ok(scalar) = parse_scalar(first)
    {
        return scalar;
    }

    // Fallback to zero if no public inputs
    PrimaryScalar::from(0u64)
}

#[derive(Clone, Debug)]
struct IvcStateBindings {
    input_signal: String,
    output_signal: String,
}

fn resolve_ivc_state_bindings(
    program: &Program,
    require_explicit: bool,
) -> ZkfResult<IvcStateBindings> {
    let input = program.metadata.get("nova_ivc_in").cloned();
    let output = program.metadata.get("nova_ivc_out").cloned();
    match (input, output) {
        (Some(input_signal), Some(output_signal)) => {
            if !program.has_signal(&input_signal) {
                return Err(ZkfError::InvalidArtifact(format!(
                    "nova_ivc_in references unknown signal '{input_signal}'"
                )));
            }
            if !program.has_signal(&output_signal) {
                return Err(ZkfError::InvalidArtifact(format!(
                    "nova_ivc_out references unknown signal '{output_signal}'"
                )));
            }
            Ok(IvcStateBindings {
                input_signal,
                output_signal,
            })
        }
        (None, None) if !require_explicit => {
            let public_signals = program.public_signal_names();
            let Some(input_signal) = public_signals.first() else {
                return Err(ZkfError::InvalidArtifact(
                    "Nova step circuit requires at least one public signal or explicit nova_ivc_in/nova_ivc_out metadata".to_string(),
                ));
            };
            let Some(output_signal) = public_signals.last() else {
                return Err(ZkfError::InvalidArtifact(
                    "Nova step circuit requires at least one public signal or explicit nova_ivc_in/nova_ivc_out metadata".to_string(),
                ));
            };
            Ok(IvcStateBindings {
                input_signal: (*input_signal).to_string(),
                output_signal: (*output_signal).to_string(),
            })
        }
        (None, None) => Err(ZkfError::InvalidArtifact(
            "nova fold requires explicit program metadata keys 'nova_ivc_in' and 'nova_ivc_out'"
                .to_string(),
        )),
        _ => Err(ZkfError::InvalidArtifact(
            "nova_ivc_in and nova_ivc_out must either both be present or both be absent"
                .to_string(),
        )),
    }
}

fn witness_state_scalar(witness: &Witness, signal: &str) -> ZkfResult<PrimaryScalar> {
    let value = witness
        .values
        .get(signal)
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: signal.to_string(),
        })?;
    parse_scalar(value).map_err(|err| ZkfError::Backend(err.to_string()))
}

fn proof_initial_state(
    compiled: &CompiledProgram,
    witness: &Witness,
    public_inputs: &[FieldElement],
) -> ZkfResult<PrimaryScalar> {
    let has_explicit_bindings = compiled.program.metadata.contains_key("nova_ivc_in")
        || compiled.program.metadata.contains_key("nova_ivc_out");
    if has_explicit_bindings {
        let bindings = resolve_ivc_state_bindings(&compiled.program, true)?;
        witness_state_scalar(witness, &bindings.input_signal)
    } else {
        Ok(initial_state(compiled, public_inputs))
    }
}

fn artifact_initial_state(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> ZkfResult<PrimaryScalar> {
    if let Some(raw) = artifact.metadata.get("nova_ivc_initial_state") {
        return parse_scalar_decimal(raw).map_err(|err| ZkfError::InvalidArtifact(err.to_string()));
    }
    Ok(initial_state(compiled, &artifact.public_inputs))
}

fn scalar_to_field_element(value: PrimaryScalar) -> FieldElement {
    FieldElement::from_le_bytes(value.to_repr().as_ref())
}

fn append_ivc_state_metadata(
    metadata: &mut BTreeMap<String, String>,
    compiled: &CompiledProgram,
    initial_state: PrimaryScalar,
    final_state: PrimaryScalar,
) {
    if compiled.program.metadata.contains_key("nova_ivc_in")
        || compiled.program.metadata.contains_key("nova_ivc_out")
    {
        let bindings = resolve_ivc_state_bindings(&compiled.program, true)
            .expect("compiled Nova IVC bindings should be valid");
        metadata.insert("nova_ivc_in".to_string(), bindings.input_signal);
        metadata.insert("nova_ivc_out".to_string(), bindings.output_signal);
        metadata.insert(
            "nova_ivc_initial_state".to_string(),
            scalar_to_field_element(initial_state).to_string(),
        );
        metadata.insert(
            "nova_ivc_final_state".to_string(),
            scalar_to_field_element(final_state).to_string(),
        );
    }
}

fn verify_expected_final_state(
    artifact: &ProofArtifact,
    outputs: &[PrimaryScalar],
) -> ZkfResult<()> {
    let Some(expected) = artifact.metadata.get("nova_ivc_final_state") else {
        return Ok(());
    };
    let Some(actual) = outputs.first().cloned() else {
        return Err(ZkfError::InvalidArtifact(
            "nova verification returned no output state".to_string(),
        ));
    };
    if scalar_to_field_element(actual).to_string() != *expected {
        return Err(ZkfError::InvalidArtifact(
            "nova final state mismatch".to_string(),
        ));
    }
    Ok(())
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

fn lower_expr<CS: ConstraintSystem<PrimaryScalar>>(
    cs: &mut CS,
    expr: &Expr,
    signals: &BTreeMap<String, AllocatedNum<PrimaryScalar>>,
    aux_counter: &mut usize,
) -> Result<AllocatedNum<PrimaryScalar>, SynthesisError> {
    match expr {
        Expr::Const(value) => {
            let scalar = parse_scalar(value)?;
            let id = next_aux(aux_counter);
            let allocated =
                AllocatedNum::alloc(cs.namespace(|| format!("expr_const_{id}")), || Ok(scalar))?;
            cs.enforce(
                || format!("expr_const_enforce_{id}"),
                |lc| lc + allocated.get_variable() - (scalar, CS::one()),
                |lc| lc + CS::one(),
                |lc| lc,
            );
            Ok(allocated)
        }
        Expr::Signal(name) => signals
            .get(name)
            .cloned()
            .ok_or(SynthesisError::AssignmentMissing),
        Expr::Add(items) => {
            if items.is_empty() {
                return lower_expr(
                    cs,
                    &Expr::Const(FieldElement::from_i64(0)),
                    signals,
                    aux_counter,
                );
            }
            let mut iter = items.iter();
            let first = iter
                .next()
                .ok_or_else(|| SynthesisError::Unsatisfiable("empty add expression".to_string()))?;
            let mut acc = lower_expr(cs, first, signals, aux_counter)?;
            for item in iter {
                let rhs = lower_expr(cs, item, signals, aux_counter)?;
                let id = next_aux(aux_counter);
                acc = acc.add(cs.namespace(|| format!("expr_add_{id}")), &rhs)?;
            }
            Ok(acc)
        }
        Expr::Sub(left, right) => {
            let left_num = lower_expr(cs, left, signals, aux_counter)?;
            let right_num = lower_expr(cs, right, signals, aux_counter)?;
            let id = next_aux(aux_counter);
            let output =
                AllocatedNum::alloc(cs.namespace(|| format!("expr_sub_out_{id}")), || {
                    let mut value = left_num
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    value -= right_num
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    Ok(value)
                })?;
            cs.enforce(
                || format!("expr_sub_enforce_{id}"),
                |lc| lc + left_num.get_variable() - right_num.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + output.get_variable(),
            );
            Ok(output)
        }
        Expr::Mul(left, right) => {
            let left_num = lower_expr(cs, left, signals, aux_counter)?;
            let right_num = lower_expr(cs, right, signals, aux_counter)?;
            let id = next_aux(aux_counter);
            left_num.mul(cs.namespace(|| format!("expr_mul_{id}")), &right_num)
        }
        Expr::Div(numerator, denominator) => {
            let numerator_num = lower_expr(cs, numerator, signals, aux_counter)?;
            let denominator_num = lower_expr(cs, denominator, signals, aux_counter)?;
            let id = next_aux(aux_counter);
            let output =
                AllocatedNum::alloc(cs.namespace(|| format!("expr_div_out_{id}")), || {
                    let mut value = numerator_num
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let denominator_value = denominator_num
                        .get_value()
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    let inverse = Option::<PrimaryScalar>::from(denominator_value.invert())
                        .ok_or(SynthesisError::DivisionByZero)?;
                    value *= inverse;
                    Ok(value)
                })?;
            cs.enforce(
                || format!("expr_div_enforce_{id}"),
                |lc| lc + denominator_num.get_variable(),
                |lc| lc + output.get_variable(),
                |lc| lc + numerator_num.get_variable(),
            );
            Ok(output)
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-step IVC folding
// ---------------------------------------------------------------------------

/// Result of a multi-step Nova IVC fold.
#[derive(Debug)]
pub struct FoldResult {
    pub steps: usize,
    pub compressed: bool,
    pub artifact: ProofArtifact,
}

/// Fold multiple witnesses through the same circuit using Nova IVC.
///
/// Each witness in `step_witnesses` is used for one `prove_step` call.
/// The resulting `RecursiveSNARK` commits to N steps of the same circuit.
/// If `compress` is true, the final proof is compressed via Spartan.
pub fn fold_native(
    compiled: &CompiledProgram,
    step_witnesses: &[Witness],
    compress: bool,
) -> ZkfResult<FoldResult> {
    if step_witnesses.is_empty() {
        return Err(ZkfError::Backend(
            "fold requires at least one step witness".to_string(),
        ));
    }
    ensure_compiled_backend(BackendKind::Nova, compiled)?;
    let profile = compiled_profile(compiled)?;
    if profile != NovaProfile::Classic {
        return Err(ZkfError::Backend(
            "multi-step fold currently supports classic Nova profile only".to_string(),
        ));
    }
    let bindings = resolve_ivc_state_bindings(&compiled.program, true)?;

    let first_witness = &step_witnesses[0];
    let public_inputs = collect_public_inputs(&compiled.program, first_witness)?;
    let z0 = witness_state_scalar(first_witness, &bindings.input_signal)?;

    let params = decode_classic_params(compiled)?;
    // Use `for_fold` (no expected_state constraint) for all IVC steps.
    // The per-step `z[0] == z0` equality added by `from_witness` is correct for
    // single-step proving but makes the relaxed R1CS unsatisfiable when folding
    // N > 1 steps — Nova's IVC already commits to z0/z_N internally.
    let first_circuit = IrStepCircuit::for_fold(compiled.program.clone(), first_witness)?;
    reset_pasta_metal_msm_telemetry();

    let mut recursive = ClassicRecursive::new(&params, &first_circuit, &[z0])
        .map_err(|err| ZkfError::Backend(format!("nova fold setup failed: {err}")))?;

    // First step
    recursive
        .prove_step(&params, &first_circuit)
        .map_err(|err| ZkfError::Backend(format!("nova fold step 0 failed: {err}")))?;

    // Subsequent steps
    for (i, witness) in step_witnesses.iter().enumerate().skip(1) {
        let circuit = IrStepCircuit::for_fold(compiled.program.clone(), witness)?;
        recursive
            .prove_step(&params, &circuit)
            .map_err(|err| ZkfError::Backend(format!("nova fold step {i} failed: {err}")))?;
    }

    let num_steps = step_witnesses.len();

    // Self-check
    let outputs = recursive
        .verify(&params, num_steps, &[z0])
        .map_err(|err| ZkfError::Backend(format!("nova fold self-check failed: {err}")))?;
    let final_state = outputs
        .first()
        .cloned()
        .ok_or_else(|| ZkfError::Backend("nova fold self-check returned no state".to_string()))?;

    let (proof_bytes, is_compressed) = if compress {
        let (pk, _vk) = ClassicCompressed::setup(&params)
            .map_err(|err| ZkfError::Backend(format!("nova compress setup failed: {err}")))?;
        let compressed = ClassicCompressed::prove(&params, &pk, &recursive)
            .map_err(|err| ZkfError::Backend(format!("nova compress prove failed: {err}")))?;
        let bytes = postcard::to_allocvec(&compressed)
            .map_err(|err| ZkfError::Serialization(err.to_string()))?;
        (bytes, true)
    } else {
        let bytes = postcard::to_allocvec(&recursive)
            .map_err(|err| ZkfError::Serialization(err.to_string()))?;
        (bytes, false)
    };

    let nova_metal_msm = take_pasta_metal_msm_telemetry();
    let verification_key = verification_key_fingerprint(compiled, profile);

    let mut metadata = BTreeMap::new();
    metadata.insert("nova_native_mode".to_string(), NOVA_NATIVE_MODE.to_string());
    metadata.insert("nova_steps".to_string(), num_steps.to_string());
    metadata.insert("nova_curve_cycle".to_string(), "pallas-vesta".to_string());
    metadata.insert("nova_profile".to_string(), profile.as_str().to_string());
    metadata.insert("nova_compressed".to_string(), is_compressed.to_string());
    metadata.insert("scheme".to_string(), "nova-ivc-fold".to_string());
    metadata.insert("nova_ivc_in".to_string(), bindings.input_signal);
    metadata.insert("nova_ivc_out".to_string(), bindings.output_signal);
    metadata.insert(
        "nova_ivc_initial_state".to_string(),
        scalar_to_field_element(z0).to_string(),
    );
    metadata.insert(
        "nova_ivc_final_state".to_string(),
        scalar_to_field_element(final_state).to_string(),
    );
    append_nova_metal_msm_metadata(&mut metadata, &nova_metal_msm);
    append_backend_runtime_metadata(&mut metadata, BackendKind::Nova);

    let artifact = ProofArtifact {
        backend: BackendKind::Nova,
        program_digest: compiled.program_digest.clone(),
        proof: proof_bytes,
        verification_key,
        public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };

    Ok(FoldResult {
        steps: num_steps,
        compressed: is_compressed,
        artifact,
    })
}

/// Verify a folded Nova proof (compressed or uncompressed).
pub fn verify_fold_native(compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
    ensure_compiled_backend(BackendKind::Nova, compiled)?;
    let profile = compiled_profile(compiled)?;
    if profile != NovaProfile::Classic {
        return Err(ZkfError::Backend(
            "multi-step fold verify currently supports classic Nova profile only".to_string(),
        ));
    }

    let expected_vk = verification_key_fingerprint(compiled, profile);
    if artifact.verification_key != expected_vk {
        return Err(ZkfError::InvalidArtifact(
            "nova fold verification key fingerprint mismatch".to_string(),
        ));
    }

    resolve_ivc_state_bindings(&compiled.program, true)?;
    let z0 = artifact_initial_state(compiled, artifact)?;
    let num_steps: usize = artifact
        .metadata
        .get("nova_steps")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let is_compressed = artifact
        .metadata
        .get("nova_compressed")
        .map(|s| s == "true")
        .unwrap_or(false);

    let params = decode_classic_params(compiled)?;

    if is_compressed {
        let compressed: ClassicCompressed = postcard::from_bytes(&artifact.proof)
            .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
        let (_pk, vk) = ClassicCompressed::setup(&params)
            .map_err(|err| ZkfError::Backend(format!("nova compress setup failed: {err}")))?;
        let outputs = compressed
            .verify(&vk, num_steps, &[z0])
            .map_err(|err| ZkfError::Backend(format!("nova compressed verify failed: {err}")))?;
        verify_expected_final_state(artifact, &outputs)?;
        Ok(true)
    } else {
        let recursive: ClassicRecursive = postcard::from_bytes(&artifact.proof)
            .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
        let outputs = recursive
            .verify(&params, num_steps, &[z0])
            .map_err(|err| ZkfError::Backend(format!("nova fold verify failed: {err}")))?;
        verify_expected_final_state(artifact, &outputs)?;
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn next_aux(counter: &mut usize) -> usize {
    let current = *counter;
    *counter += 1;
    current
}

fn parse_scalar(value: &FieldElement) -> Result<PrimaryScalar, SynthesisError> {
    let s = value.to_decimal_string();
    parse_scalar_decimal(s.trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{Signal, Visibility};

    fn simple_add_program() -> Program {
        let mut program = Program {
            name: "fold_test_add".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("out".to_string()),
                rhs: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Signal("y".to_string()),
                ]),
                label: Some("out_eq_sum".to_string()),
            }],
            ..Default::default()
        };
        program
            .metadata
            .insert("nova_ivc_in".to_string(), "x".to_string());
        program
            .metadata
            .insert("nova_ivc_out".to_string(), "out".to_string());
        program
    }

    fn make_witness(x: i64, y: i64) -> Witness {
        let mut values = BTreeMap::new();
        values.insert("x".to_string(), FieldElement::from_i64(x));
        values.insert("y".to_string(), FieldElement::from_i64(y));
        values.insert("out".to_string(), FieldElement::from_i64(x + y));
        Witness { values }
    }

    #[test]
    fn single_step_fold_matches_prove() {
        let backend = NovaNativeBackend;
        let program = simple_add_program();
        let compiled = backend.compile(&program).expect("compile");
        let witness = make_witness(3, 5);

        let result = fold_native(&compiled, &[witness], false).expect("fold");
        assert_eq!(result.steps, 1);
        assert!(!result.compressed);
        assert!(verify_fold_native(&compiled, &result.artifact).expect("verify fold"));
    }

    #[test]
    fn multi_step_fold_uncompressed() {
        let backend = NovaNativeBackend;
        let program = simple_add_program();
        let compiled = backend.compile(&program).expect("compile");
        let witnesses = vec![make_witness(1, 2), make_witness(3, 4), make_witness(7, 6)];

        let result = fold_native(&compiled, &witnesses, false).expect("fold 3 steps");
        assert_eq!(result.steps, 3);
        assert!(!result.compressed);
        assert_eq!(
            result
                .artifact
                .metadata
                .get("nova_steps")
                .map(String::as_str),
            Some("3")
        );
        assert!(verify_fold_native(&compiled, &result.artifact).expect("verify fold"));
    }

    #[test]
    fn multi_step_fold_compressed() {
        let backend = NovaNativeBackend;
        let program = simple_add_program();
        let compiled = backend.compile(&program).expect("compile");
        let witnesses = vec![make_witness(10, 20), make_witness(30, 40)];

        let result = fold_native(&compiled, &witnesses, true).expect("fold compressed");
        assert_eq!(result.steps, 2);
        assert!(result.compressed);
        assert_eq!(
            result
                .artifact
                .metadata
                .get("nova_compressed")
                .map(String::as_str),
            Some("true")
        );
        assert!(verify_fold_native(&compiled, &result.artifact).expect("verify compressed fold"));
    }

    #[test]
    fn fold_rejects_empty_witnesses() {
        let backend = NovaNativeBackend;
        let program = simple_add_program();
        let compiled = backend.compile(&program).expect("compile");

        assert!(fold_native(&compiled, &[], false).is_err());
    }

    #[test]
    fn recommended_nova_setup_thread_cap_skips_small_circuits() {
        let resources = SystemResources {
            total_ram_bytes: FORTY_EIGHT_GIB,
            available_ram_bytes: 40 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(FORTY_EIGHT_GIB),
            pressure: zkf_core::MemoryPressure::default(),
        };

        assert_eq!(
            recommended_nova_setup_thread_cap(1_024, 2_048, &resources),
            None
        );
    }

    #[test]
    fn recommended_nova_setup_thread_cap_throttles_large_48g_unified_hosts() {
        let resources = SystemResources {
            total_ram_bytes: FORTY_EIGHT_GIB,
            available_ram_bytes: 40 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(FORTY_EIGHT_GIB),
            pressure: zkf_core::MemoryPressure::default(),
        };

        assert_eq!(
            recommended_nova_setup_thread_cap(555_715, 620_750, &resources),
            Some(4)
        );
    }

    #[test]
    fn recommended_nova_setup_thread_cap_drops_to_single_thread_under_high_pressure() {
        let resources = SystemResources {
            total_ram_bytes: FORTY_EIGHT_GIB,
            available_ram_bytes: 4 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(FORTY_EIGHT_GIB),
            pressure: zkf_core::MemoryPressure {
                level: PressureLevel::High,
                utilization_pct: 88.0,
                ..zkf_core::MemoryPressure::default()
            },
        };

        assert_eq!(
            recommended_nova_setup_thread_cap(555_715, 620_750, &resources),
            Some(1)
        );
    }
}

fn parse_scalar_decimal(raw: &str) -> Result<PrimaryScalar, SynthesisError> {
    if raw.is_empty() {
        return Err(SynthesisError::Unsatisfiable(
            "empty scalar string".to_string(),
        ));
    }

    let (negative, digits) = if let Some(rest) = raw.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = raw.strip_prefix('+') {
        (false, rest)
    } else {
        (false, raw)
    };

    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(SynthesisError::Unsatisfiable(format!(
            "invalid scalar literal: '{raw}'"
        )));
    }

    let ten = PrimaryScalar::from(10u64);
    let mut value = PrimaryScalar::from(0u64);
    for digit in digits.bytes() {
        value *= ten;
        value += PrimaryScalar::from(u64::from(digit - b'0'));
    }

    if negative {
        let mut zero = PrimaryScalar::from(0u64);
        zero -= value;
        value = zero;
    }

    Ok(value)
}
