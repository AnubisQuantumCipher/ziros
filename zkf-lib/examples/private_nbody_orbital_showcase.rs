use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::with_setup_seed_override;
use zkf_backends::{
    BackendRoute, compile_arkworks_unchecked, prepare_witness_for_proving,
    requested_groth16_setup_blob_path,
};
use zkf_backends::{with_allow_dev_deterministic_groth16_override, with_proof_seed_override};
use zkf_core::ccs::CcsProgram;
use zkf_core::{
    BackendKind, Program, Witness, WitnessInputs, check_constraints, json_from_slice,
    json_to_vec_pretty, optimize_program,
};
use zkf_lib::evidence::{
    collect_formal_evidence_for_generated_app, generated_app_closure_bundle_summary,
    persist_artifacts_to_cloudfs,
};
use zkf_lib::orbital::{
    PRIVATE_NBODY_BODY_COUNT, PRIVATE_NBODY_DEFAULT_STEPS, PRIVATE_NBODY_PRIVATE_INPUTS,
    PRIVATE_NBODY_PUBLIC_OUTPUTS, effective_gpu_attribution_summary,
    private_nbody_orbital_showcase_with_steps, private_nbody_orbital_witness_with_steps,
};
use zkf_lib::{
    ZkfError, ZkfResult, audit_program_with_live_capabilities, export_groth16_solidity_verifier,
    verify,
};
use zkf_runtime::{
    BackendProofExecutionResult, ExecutionMode, OptimizationObjective, RequiredTrustLane,
    RuntimeExecutor, SwarmConfig,
};

const SETUP_SEED: [u8; 32] = [0x31; 32];
const PROOF_SEED: [u8; 32] = [0x47; 32];

fn with_showcase_groth16_mode<T, F: FnOnce() -> ZkfResult<T>>(
    trusted_setup_used: bool,
    f: F,
) -> ZkfResult<T> {
    if trusted_setup_used {
        f()
    } else {
        with_allow_dev_deterministic_groth16_override(Some(true), f)
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Serialize)]
struct ProgramStats {
    signals: usize,
    constraints: usize,
    public_outputs: usize,
    blackbox_constraints: usize,
}

fn stats(program: &Program) -> ProgramStats {
    ProgramStats {
        signals: program.signals.len(),
        constraints: program.constraints.len(),
        public_outputs: program
            .signals
            .iter()
            .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
            .count(),
        blackbox_constraints: program
            .constraints
            .iter()
            .filter(|constraint| matches!(constraint, zkf_core::Constraint::BlackBox { .. }))
            .count(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    let bytes = json_to_vec_pretty(value).map_err(|error| {
        ZkfError::Serialization(format!("serialize {}: {error}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn write_text(path: &Path, value: &str) -> ZkfResult<()> {
    fs::write(path, value)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let bytes = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    json_from_slice(&bytes)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

fn read_text(path: &Path) -> ZkfResult<String> {
    fs::read_to_string(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))
}

fn ensure_file_exists(path: &Path) -> ZkfResult<()> {
    let metadata = fs::metadata(path)
        .map_err(|error| ZkfError::Io(format!("stat {}: {error}", path.display())))?;
    if !metadata.is_file() {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected {} to be a file",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_dir_exists(path: &Path) -> ZkfResult<()> {
    let metadata = fs::metadata(path)
        .map_err(|error| ZkfError::Io(format!("stat {}: {error}", path.display())))?;
    if !metadata.is_dir() {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected {} to be a directory",
            path.display()
        )));
    }
    Ok(())
}

fn output_dir() -> PathBuf {
    env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string()))
            .join("Desktop/ZirOS_Private_NBody_5Body_1000Step")
    })
}

fn foundry_project_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("foundry")
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn integration_steps() -> ZkfResult<usize> {
    match env::var("ZKF_PRIVATE_NBODY_STEPS_OVERRIDE") {
        Ok(raw) => {
            let steps = raw.parse::<usize>().map_err(|error| {
                ZkfError::Backend(format!(
                    "parse ZKF_PRIVATE_NBODY_STEPS_OVERRIDE={raw:?}: {error}"
                ))
            })?;
            if steps == 0 {
                return Err(ZkfError::Backend(
                    "ZKF_PRIVATE_NBODY_STEPS_OVERRIDE must be greater than zero".to_string(),
                ));
            }
            Ok(steps)
        }
        Err(env::VarError::NotPresent) => Ok(PRIVATE_NBODY_DEFAULT_STEPS),
        Err(error) => Err(ZkfError::Backend(format!(
            "read ZKF_PRIVATE_NBODY_STEPS_OVERRIDE: {error}"
        ))),
    }
}

fn full_audit_requested() -> bool {
    env_flag("ZKF_PRIVATE_NBODY_FULL_AUDIT")
}

fn ensure_foundry_layout(project_dir: &Path) -> ZkfResult<()> {
    fs::create_dir_all(project_dir.join("src"))
        .map_err(|error| ZkfError::Io(format!("create foundry src: {error}")))?;
    fs::create_dir_all(project_dir.join("test"))
        .map_err(|error| ZkfError::Io(format!("create foundry test: {error}")))?;
    write_text(
        &project_dir.join("foundry.toml"),
        "[profile.default]\nsrc = \"src\"\ntest = \"test\"\nout = \"out\"\nlibs = []\n",
    )?;
    Ok(())
}

fn public_outputs(program: &Program, witness: &Witness) -> BTreeMap<String, String> {
    program
        .signals
        .iter()
        .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
        .filter_map(|signal| {
            witness
                .values
                .get(&signal.name)
                .map(|value| (signal.name.clone(), value.to_decimal_string()))
        })
        .collect()
}

fn stage_summary(
    report: &zkf_runtime::GraphExecutionReport,
    artifact_metadata: &BTreeMap<String, String>,
) -> serde_json::Value {
    let gpu_attribution = effective_gpu_attribution_summary(
        report.gpu_nodes,
        report.gpu_stage_busy_ratio(),
        artifact_metadata,
    );
    json!({
        "total_wall_time_ms": report.total_wall_time.as_secs_f64() * 1_000.0,
        "peak_memory_bytes": report.peak_memory_bytes,
        "gpu_nodes": report.gpu_nodes,
        "cpu_nodes": report.cpu_nodes,
        "delegated_nodes": report.delegated_nodes,
        "fallback_nodes": report.fallback_nodes,
        "gpu_busy_ratio": report.gpu_stage_busy_ratio(),
        "effective_gpu_attribution": gpu_attribution,
        "stage_breakdown": report.stage_breakdown(),
        "watchdog_alerts": report.watchdog_alerts,
    })
}

fn telemetry_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".zkf/telemetry")
}

fn telemetry_snapshot() -> BTreeSet<String> {
    let mut snapshot = BTreeSet::new();
    let dir = telemetry_dir();
    if let Ok(read_dir) = fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            snapshot.insert(entry.path().display().to_string());
        }
    }
    snapshot
}

fn new_telemetry_paths(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    after.difference(before).cloned().collect()
}

fn ccs_summary(compiled: &zkf_core::CompiledProgram) -> ZkfResult<serde_json::Value> {
    let ccs = CcsProgram::try_from_program(&compiled.program)?;
    Ok(json!({
        "program_name": ccs.name,
        "field": ccs.field.as_str(),
        "num_constraints": ccs.num_constraints,
        "num_variables": ccs.num_variables,
        "num_public": ccs.num_public,
        "num_matrices": ccs.num_matrices(),
        "num_terms": ccs.num_terms(),
        "degree": ccs.degree(),
        "matrix_nnz": ccs.matrices.iter().enumerate().map(|(index, matrix)| {
            json!({
                "index": index,
                "rows": matrix.rows,
                "cols": matrix.cols,
                "nnz": matrix.nnz(),
            })
        }).collect::<Vec<_>>(),
        "compiled_metadata": compiled.metadata,
    }))
}

fn json_pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn report_markdown(
    _original: &Program,
    _optimized: &Program,
    compiled: &zkf_core::CompiledProgram,
    runtime_artifact: &zkf_core::ProofArtifact,
    prepared: &Witness,
    runtime_result: &zkf_runtime::PlanExecutionResult,
    integration_steps: usize,
    setup_provenance: &str,
    security_boundary: &str,
    determinism: serde_json::Value,
    telemetry_paths: &[String],
    gpu_attribution: &serde_json::Value,
    formal_evidence: &serde_json::Value,
    audit_summary: &serde_json::Value,
    generated_closure: &serde_json::Value,
) -> String {
    let stage_breakdown = runtime_result.report.stage_breakdown();
    let public_map = public_outputs(&compiled.program, prepared);
    let proof_size = runtime_artifact.proof.len();
    let vk_size = runtime_artifact.verification_key.len();
    let formal_status = formal_evidence
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let formal_sentence = if formal_status == "included" {
        "This export bundles the formal proof logs and exercised-surface map under `formal/`."
    } else {
        "This export attempted to bundle the formal proof logs under `formal/`, and the status block below records any failures explicitly."
    };
    let telemetry_lines = if telemetry_paths.is_empty() {
        "- No new telemetry file paths were detected while generating this bundle.\n".to_string()
    } else {
        telemetry_paths
            .iter()
            .map(|path| format!("- `{path}`\n"))
            .collect::<String>()
    };

    format!(
        r#"# ZirOS Private 5-Body Orbital Showcase

## Executive Summary

This bundle contains a private five-body orbital dynamics showcase built on ZirOS and emitted through the system’s strict cryptographic Groth16 runtime/export stack. The application surface is a `ProgramBuilder` circuit over BN254 with exactly {body_count} private bodies, exactly {steps} hard-coded Velocity-Verlet steps, and exactly {public_outputs} public Poseidon commitments, one for each final 3D position. The proving lane for the circuit is the system’s strict cryptographic runtime surface, not an ad hoc backend shortcut, and the bundle captures the compile, witness, proof, verifier export, calldata generation, runtime telemetry, matrix summaries, audit coverage, and formal evidence produced along the way.

This run used Groth16 setup provenance `{setup_provenance}` with security boundary `{security_boundary}`. When the provenance is `deterministic-dev`, the exported bundle is intentionally labeled development-only.

The implementation keeps all masses, positions, and velocities private at input time. Inside the circuit, the orbital trace is encoded with deterministic fixed-point arithmetic at scale `10^18`, using Newtonian gravity with `G = 6.67430e-11` represented as the integer-scaled constant `66743000`. Rather than attempting an IEEE-754 emulation inside the field, the circuit uses a bounded residual model. Pairwise deltas, distance squares, inverse-distance approximations, inverse-distance-cubed terms, pair factors, acceleration contributions, and integration-update remainders are all surfaced explicitly as witness columns. The constraints then certify that each witness value is consistent with the fixed-point Newtonian update and that each rounding residual remains within the configured envelope.

This matters because the system is not just checking a final hash. It is checking the full discrete physics trace. Every step links the current state, pairwise geometry, per-body accelerations, next positions, next accelerations, and next velocities. The public surface is intentionally minimal, but the circuit relation is not. The proof therefore certifies the hidden trajectory, and the bundle keeps enough artifact detail for a developer to inspect how the system got there.

## What Was Built

The core circuit lives in the new orbital module and constructs a fixed five-body application, not a variable-arity gadget. That decision is deliberate. The showcase target is a specific benchmark surface that the system should be able to compile, audit, prove, and export repeatably. Because the body count and step count are fixed, the circuit can hard-code all signal names and all pair enumerations. That makes the trace deterministic, reviewable, and suitable for formal side proofs about exact body count, exact step count, and exact pair scheduling.

The application has {private_inputs} private input scalars:

- 5 masses
- 15 initial position coordinates
- 15 initial velocity coordinates

It has {public_outputs} public outputs:

- `commit_body_0`
- `commit_body_1`
- `commit_body_2`
- `commit_body_3`
- `commit_body_4`

Each commitment is a BN254 Poseidon permutation over `(x_final, y_final, z_final, body_tag)`, so each body’s final position is domain separated. The circuit keeps the internal Poseidon state private and exposes only the first lane as the public commitment value. The prepared witness then includes the final commitments, while the backend witness-enrichment path materializes the auxiliary hash state required by the lowered arithmetic circuit.

The numerical model uses Velocity-Verlet with `dt = 1.0`:

- `x_(t+1) = x_t + v_t + 0.5 * a_t`
- `a_t = Σ_j≠i G * m_j * (r_j - r_i) / |r_j - r_i|^3`
- `v_(t+1) = v_t + 0.5 * (a_t + a_(t+1))`

Inside the field, those updates are encoded using rounded integer quotients and explicit residual witnesses. The system never hides the approximation. If a residual exceeds the bound, the witness is invalid. If a pairwise distance floor is violated, the witness builder fails closed before proving.

## How The Circuit Is Structured

The builder surface starts by declaring the exact private input surface, the public outputs, and metadata describing the integrator, scale, gravity constant, and domain bounds. The current normalized bounds are:

- `|position| <= 10^3`
- `|velocity| <= 10^2`
- `0 < mass <= 10^12`
- `|acceleration| <= 10^6`
- `|r| >= 10^-3`

Each bound is translated into an in-circuit condition. For signed coordinates and accelerations, the circuit uses a square-plus-slack relation so the bound is expressed without assuming signed integers are directly native to the field. For positive masses, the circuit uses an exact upper-bound slack plus a field inverse relation to prove nonzero-ness. Pairwise minimum distance is enforced through a positive slack over the distance-square floor.

Acceleration synthesis is organized per state, not loosely per step. The circuit first computes the initial acceleration state from the initial positions. Then each iteration does three things:

1. Constrain next positions from current positions, current velocities, current accelerations, and a bounded half-step residual.
2. Constrain next accelerations from the newly constrained next positions.
3. Constrain next velocities from current velocities, current accelerations, next accelerations, and a bounded half-step residual.

Pairwise force materialization is explicit. For every unordered pair of bodies and for every acceleration state, the circuit introduces:

- three delta coordinates
- one squared-distance signal
- one minimum-distance slack
- one inverse-distance approximation
- one inverse-distance-square signal
- positive/negative residual lanes for the inverse-distance-square relation
- one inverse-distance-cubed quotient and residual
- one pair-factor quotient and residual
- per-axis temporary weighted deltas
- per-axis acceleration contributions and their division residuals

That is intentionally verbose. The goal of this showcase is not the minimum gate count at any cost; the goal is to show that ZirOS can build a privacy-preserving numerical application where the heavy computation still remains inspectable and auditable at the circuit level.

## Why Fixed-Point Instead Of Floating-Point

The request asked for correctness within double-precision floating-point bounds, but the proving substrate is a prime field and the builder IR is algebraic. Native IEEE-754 emulation would be dramatically more expensive and would not improve the underlying trust story unless every exceptional path, rounding mode, NaN rule, and denormal edge were also modeled. That is the wrong tradeoff for this system.

The fixed-point kernel is therefore a better fit. With scale `10^18`, the lattice spacing is already much smaller than the absolute precision implied by double precision over the normalized domain of this application. The circuit then makes the approximation boundary explicit by carrying residual witnesses. Those residuals are not a fallback. They are the proof surface. The witness builder chooses deterministic rounded values; the circuit checks the corresponding reconstruction equations and the residual bounds. In other words, the physics is not “approximately right because the host said so.” It is approximately right because the host provided a discrete trace and the circuit verified the allowable error of each discrete step.

This is also the part of the build that turns the system into something more general than a hash-and-proof toy. Once the runtime and builder can handle a structured numerical trace with residual certification, the same pattern can be reused for other scientific or simulation-style private applications.

## Runtime And System Path

The proving path for the bundle goes through the strict runtime lane and then exports the same Groth16 proof surface directly for downstream verifier assets. The runtime result includes:

- cryptographic trust lane selection
- deterministic execution mode
- control-plane summaries
- execution-stage telemetry
- swarm telemetry, when available
- Metal runtime reporting

The current stage breakdown snapshot from the successful runtime execution is:

`{stage_breakdown:?}`

That output is important for two reasons. First, it verifies that the system can move a nontrivial application through the same proving runtime used elsewhere in ZirOS. Second, it gives the developer a line of sight into how the runtime scheduled and executed the job instead of reducing the run to a single “proof succeeded” bit.

The bundle also records telemetry file paths emitted during the proving session:

{telemetry_lines}

The bundle-local GPU attribution summary was:

`{gpu_attribution}`

This keeps delegated Arkworks or Metal evidence visible even when the runtime node-placement counters remain CPU or delegated at the graph level.

## Artifacts And Export Surface

The bundle exports the standard Groth16 downstream surfaces:

- compiled artifact JSON
- proof artifact JSON
- Solidity verifier source
- calldata JSON
- Foundry project with an auto-generated verifier test

That means the application does not stop at “a proof exists.” It reaches the full downstream surface expected by teams shipping proofs into contracts, test harnesses, or deployment pipelines.

The resulting proof size for this run was `{proof_size}` bytes and the verification key size was `{vk_size}` bytes. The current public output map was:

`{public_map:?}`

## Matrix, Lowering, And Audit View

The matrix summary in the bundle is generated from the compiled program surface, which already reflects the backend-lowered arithmetic circuit. The important quantities to inspect there are:

- original vs compiled constraint counts
- number of public outputs
- CCS matrix count
- nonzero counts
- maximum degree
- underconstraint analysis over the lowered surface

Those reports matter because they let a developer look at the circuit as a structure, not only as a proving black box. When someone says “study all the matrix everything,” this is the practical answer: emit the circuit census, the lowering report, the CCS matrix shapes, the nonzero densities, and the underconstraint analysis for the exact program that was proved.

## Determinism

The deterministic proof summary captured in this bundle was:

`{determinism}`

This matters because deterministic seeds are not cosmetic here. They are part of making the showcase reproducible and debuggable. A system that claims it can build numerical privacy applications should also be able to give a developer repeatable artifacts when asked to do so.

## Bundle Evidence

{formal_sentence}

The current formal evidence record was:

`{formal_evidence}`

The structured audit coverage record was:

`{audit_summary}`

The generated implementation-closure extract used for this export was:

`{generated_closure}`

The exact claimed or exercised proof surfaces are listed in `formal/exercised_surfaces.json`, and that file is a generated repo closure extract rather than a hand-curated proof inventory.

## Formal Proof Surface

The right scope for the mechanized proofs around this showcase is not “prove all of Newtonian mechanics inside one theorem file.” The right scope is:

- exact body count invariants
- exact step count invariants
- deterministic pair enumeration
- symmetry of pairwise deltas
- algebraic reconstruction relations used by the fixed-point kernel
- binding from final state coordinates to final Poseidon commitments

That is the most useful formal layer for this application because it mirrors the actual implementation choices made in the circuit rather than pretending the code is something more abstract than it is.

## Developer Experience Improvements

Building this showcase exposed several concrete DX improvements that would make ZirOS better for developers:

First, the builder needs a first-class notion of labelled constraints. I had to reason about failing constraint indices by reconstructing builder ordering. That is workable, but it is not good enough for a system meant to support simulation-style applications. Named constraints should flow from `ProgramBuilder` into audit output and runtime failures.

Second, the witness-preparation surface would benefit from a documented pattern for “externally computed deterministic witnesses with backend-side blackbox enrichment.” The current system can do it, but the path is implicit. This showcase uses that path directly because the generic witness solver is not meant to synthesize reciprocal-distance approximations on its own.

Third, range and audit ergonomics should better distinguish “linearly bounded helper slack” from “truly underconstrained signal.” I solved that here by adding explicit nonlinear anchors, which is valid, but the pattern should be supported deliberately because it comes up whenever a circuit uses exact-cap slack variables.

Fourth, the lowering and CCS summary path should be exposed as a stable public helper instead of requiring downstream code to reconstruct it from the compiled artifact. A showcase like this needs to emit a matrix report as a first-class deliverable.

Fifth, the runtime telemetry surface is valuable, but bundle-oriented examples should have a standard helper that captures the before/after telemetry file diff, stage breakdown, Metal summary, and swarm digest together. Right now each example has to assemble that on its own.

Sixth, simulation-style applications would benefit from a library-side “deterministic numeric kernel” module pattern. The orbital showcase now demonstrates one, but the framework should make this a supported style instead of leaving each app author to rediscover it.

## Assessment

From an engineering perspective, this project is unusually compelling because it pushes ZirOS away from the narrow category of “proves small cryptographic gadgets” and toward “builds private applications whose internal computation is rich, structured, and inspectable.” That is where the system becomes more than a proving wrapper.

The most interesting part is not the gravity equations by themselves. It is that the system can carry a stateful numerical process, keep the state private, certify a disciplined approximation model, and still export the normal downstream proof artifacts that developers expect. If ZirOS can do that reliably, it can support a much broader class of applications than people usually assume a proving framework can handle.

The system is not effortless yet. The amount of explicit witness structure required here shows that simulation-style circuits still need better ergonomics, better debugging labels, and better public tooling around lowering and audits. But that is exactly why this showcase is worth building. It reveals the next layer of product work the framework needs.

## Closing

The practical takeaway is straightforward: ZirOS can and should be able to build applications like this. The right way to make that true is not to hide the hard parts or hand-wave around them. The right way is to encode the numerical kernel explicitly, route it through the native runtime path, preserve the audit and matrix view, and export the same verifier surfaces the rest of the system already knows how to produce. That is what this showcase is designed to demonstrate.
"#,
        body_count = PRIVATE_NBODY_BODY_COUNT,
        steps = integration_steps,
        public_outputs = PRIVATE_NBODY_PUBLIC_OUTPUTS,
        private_inputs = PRIVATE_NBODY_PRIVATE_INPUTS,
        setup_provenance = setup_provenance,
        security_boundary = security_boundary,
        gpu_attribution = json_pretty(gpu_attribution),
        formal_evidence = json_pretty(formal_evidence),
        audit_summary = json_pretty(audit_summary),
        generated_closure = json_pretty(generated_closure),
        formal_sentence = formal_sentence,
    )
}

fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ZkfResult<T> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(128 * 1024 * 1024)
        .spawn(f)
        .map_err(|error| ZkfError::Backend(format!("spawn {name} worker: {error}")))?;
    handle.join().map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else if let Some(message) = panic.downcast_ref::<String>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else {
            ZkfError::Backend(format!("{name} worker panicked"))
        }
    })?
}

struct ShowcaseExportInputs {
    out_dir: PathBuf,
    integration_steps: usize,
    original_program: Program,
    optimized_program: Program,
    optimizer_report: zkf_core::OptimizeReport,
    valid_inputs: WitnessInputs,
    base_witness: Witness,
    prepared_witness: Witness,
    source_execution: BackendProofExecutionResult,
    compile_ms: f64,
    witness_ms: f64,
    source_runtime_ms: f64,
    wrap_ms: f64,
    trusted_setup_requested: bool,
    trusted_setup_used: bool,
    setup_provenance: String,
    security_boundary: String,
    telemetry_before: BTreeSet<String>,
    telemetry_after: BTreeSet<String>,
}

fn export_showcase_bundle(inputs: ShowcaseExportInputs) -> ZkfResult<()> {
    let ShowcaseExportInputs {
        out_dir,
        integration_steps,
        original_program,
        optimized_program,
        optimizer_report,
        valid_inputs,
        base_witness,
        prepared_witness,
        source_execution,
        compile_ms,
        witness_ms,
        source_runtime_ms,
        wrap_ms,
        trusted_setup_requested,
        trusted_setup_used,
        setup_provenance,
        security_boundary,
        telemetry_before,
        telemetry_after,
    } = inputs;

    eprintln!("private_nbody_orbital_showcase: export checkpoint: structural summaries");
    let runtime_artifact = source_execution.artifact.clone();
    let wrapped_compiled = source_execution.compiled.clone();
    let verifier_source =
        export_groth16_solidity_verifier(&runtime_artifact, Some("PrivateNBodyVerifier"))?;
    let calldata = proof_to_calldata_json(&runtime_artifact.proof, &runtime_artifact.public_inputs)
        .map_err(ZkfError::Backend)?;
    let foundry_test = generate_foundry_test_from_artifact(
        &runtime_artifact.proof,
        &runtime_artifact.public_inputs,
        "../src/PrivateNBodyVerifier.sol",
        "PrivateNBodyVerifier",
    )
    .map_err(ZkfError::Backend)?;

    let project_dir = foundry_project_dir(&out_dir);
    ensure_foundry_layout(&project_dir)?;

    let matrix_summary = ccs_summary(&source_execution.compiled)?;
    let telemetry_paths = new_telemetry_paths(&telemetry_before, &telemetry_after);
    let gpu_attribution = effective_gpu_attribution_summary(
        source_execution.result.report.gpu_nodes,
        source_execution.result.report.gpu_stage_busy_ratio(),
        &runtime_artifact.metadata,
    );

    let determinism = json!({
        "source_compiled_digest": source_execution.compiled.program_digest,
        "wrapped_compiled_digest": wrapped_compiled.program_digest,
        "runtime_public_input_count": runtime_artifact.public_inputs.len(),
        "proof_seed_hex": hex_string(&PROOF_SEED),
        "setup_seed_hex": hex_string(&SETUP_SEED),
        "export_mode": "direct-groth16",
    });

    let program_original_path = out_dir.join("private_nbody.original.program.json");
    let program_optimized_path = out_dir.join("private_nbody.optimized.program.json");
    let compiled_path = out_dir.join("private_nbody.compiled.json");
    let inputs_path = out_dir.join("private_nbody.inputs.json");
    let witness_base_path = out_dir.join("private_nbody.witness.base.json");
    let witness_path = out_dir.join("private_nbody.witness.prepared.json");
    let proof_path = out_dir.join("private_nbody.runtime.proof.json");
    let verifier_path = out_dir.join("PrivateNBodyVerifier.sol");
    let calldata_path = out_dir.join("private_nbody.calldata.json");
    let summary_path = out_dir.join("private_nbody.summary.json");
    let audit_path = out_dir.join("private_nbody.audit.json");
    let evidence_manifest_path = out_dir.join("private_nbody.evidence_manifest.json");
    let matrix_path = out_dir.join("private_nbody.matrix_ccs_summary.json");
    let runtime_trace_path = out_dir.join("private_nbody.runtime_trace.json");
    let execution_trace_path = out_dir.join("private_nbody.execution_trace.json");
    let report_path = out_dir.join("private_nbody.report.md");
    let foundry_verifier_path = project_dir.join("src/PrivateNBodyVerifier.sol");
    let foundry_test_path = project_dir.join("test/PrivateNBodyVerifier.t.sol");
    let audit_dir = out_dir.join("audit");

    eprintln!("private_nbody_orbital_showcase: export checkpoint: json writes");
    write_json(&program_original_path, &original_program)?;
    write_json(&program_optimized_path, &optimized_program)?;
    write_json(&compiled_path, &wrapped_compiled)?;
    write_json(&inputs_path, &valid_inputs)?;
    write_json(&witness_base_path, &base_witness)?;
    write_json(&witness_path, &prepared_witness)?;
    write_json(&proof_path, &runtime_artifact)?;
    write_text(&verifier_path, &verifier_source)?;
    write_json(&calldata_path, &calldata)?;
    write_json(&matrix_path, &matrix_summary)?;
    write_json(
        &execution_trace_path,
        &json!({
            "source_prove": {
                "outputs": source_execution.result.outputs,
                "control_plane": source_execution.result.control_plane,
                "security": source_execution.result.security,
                "model_integrity": source_execution.result.model_integrity,
                "swarm": source_execution.result.swarm,
            },
            "export": {
                "mode": "direct-groth16",
                "artifact_metadata": runtime_artifact.metadata,
            },
        }),
    )?;

    write_text(&foundry_verifier_path, &verifier_source)?;
    write_text(&foundry_test_path, &foundry_test.source)?;

    ensure_file_exists(&program_original_path)?;
    ensure_file_exists(&program_optimized_path)?;
    ensure_file_exists(&compiled_path)?;
    ensure_file_exists(&inputs_path)?;
    ensure_file_exists(&witness_base_path)?;
    ensure_file_exists(&witness_path)?;
    ensure_file_exists(&proof_path)?;
    ensure_file_exists(&verifier_path)?;
    ensure_file_exists(&calldata_path)?;
    ensure_file_exists(&matrix_path)?;
    ensure_file_exists(&execution_trace_path)?;
    ensure_dir_exists(&project_dir)?;
    ensure_file_exists(&project_dir.join("foundry.toml"))?;
    ensure_file_exists(&foundry_verifier_path)?;
    ensure_file_exists(&foundry_test_path)?;

    eprintln!("private_nbody_orbital_showcase: export checkpoint: disk reload");
    let _: Program = read_json(&program_original_path)?;
    let _: Program = read_json(&program_optimized_path)?;
    let compiled_from_disk: zkf_core::CompiledProgram = read_json(&compiled_path)?;
    let _: WitnessInputs = read_json(&inputs_path)?;
    let _: Witness = read_json(&witness_base_path)?;
    let _: Witness = read_json(&witness_path)?;
    let runtime_artifact_from_disk: zkf_core::ProofArtifact = read_json(&proof_path)?;
    let _: serde_json::Value = read_json(&calldata_path)?;
    let _: serde_json::Value = read_json(&matrix_path)?;
    let _: serde_json::Value = read_json(&execution_trace_path)?;

    eprintln!("private_nbody_orbital_showcase: export checkpoint: disk verify");
    if !verify(&compiled_from_disk, &runtime_artifact_from_disk)? {
        return Err(ZkfError::Backend(
            "disk-loaded runtime proof verification returned false".to_string(),
        ));
    }
    let verifier_source_from_disk = read_text(&verifier_path)?;
    if !verifier_source_from_disk.contains("contract PrivateNBodyVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not contain the expected verifier contract",
            verifier_path.display()
        )));
    }
    let foundry_toml = read_text(&project_dir.join("foundry.toml"))?;
    if !foundry_toml.contains("[profile.default]") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} is not a valid Foundry project manifest",
            project_dir.join("foundry.toml").display()
        )));
    }
    let foundry_test_source = read_text(&foundry_test_path)?;
    if !foundry_test_source.contains("PrivateNBodyVerifier") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not reference the expected verifier contract",
            foundry_test_path.display()
        )));
    }
    eprintln!("private_nbody_orbital_showcase: export checkpoint: formal evidence");
    let (generated_closure, formal_evidence) =
        collect_formal_evidence_for_generated_app(&out_dir, "private_nbody_orbital_showcase")?;
    let generated_closure_summary =
        generated_app_closure_bundle_summary("private_nbody_orbital_showcase")?;
    let formal_dir = out_dir.join("formal");
    ensure_dir_exists(&formal_dir)?;
    ensure_file_exists(&formal_dir.join("STATUS.md"))?;
    ensure_file_exists(&formal_dir.join("rocq.log"))?;
    ensure_file_exists(&formal_dir.join("protocol_lean.log"))?;
    ensure_file_exists(&formal_dir.join("verus_orbital.log"))?;
    ensure_file_exists(&formal_dir.join("exercised_surfaces.json"))?;

    eprintln!("private_nbody_orbital_showcase: export checkpoint: audit coverage");
    let full_audit_enabled = full_audit_requested();
    let structural_summary = json!({
        "status": "included",
        "paths": {
            "matrix_summary": "private_nbody.matrix_ccs_summary.json",
        },
        "original": {
            "program_digest": original_program.digest_hex(),
            "program_stats": stats(&original_program),
        },
        "optimized": {
            "program_digest": optimized_program.digest_hex(),
            "program_stats": stats(&optimized_program),
            "source_program_digest": optimized_program.digest_hex(),
            "compiled_program_digest": source_execution.compiled.program_digest,
        },
        "compiled": {
            "program_digest": wrapped_compiled.program_digest,
            "program_stats": stats(&source_execution.compiled.program),
            "export": "direct-groth16",
        },
    });
    let (full_source_audit, full_compiled_audit) = if full_audit_enabled {
        fs::create_dir_all(&audit_dir)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", audit_dir.display())))?;
        let source_audit_path = audit_dir.join("private_nbody.source_audit.json");
        let compiled_audit_path = audit_dir.join("private_nbody.compiled_audit.json");
        let source_audit = audit_program_with_live_capabilities(
            &original_program,
            Some(BackendKind::ArkworksGroth16),
        );
        let compiled_audit = audit_program_with_live_capabilities(
            &source_execution.compiled.program,
            Some(BackendKind::ArkworksGroth16),
        );
        write_json(&source_audit_path, &source_audit)?;
        write_json(&compiled_audit_path, &compiled_audit)?;
        ensure_file_exists(&source_audit_path)?;
        ensure_file_exists(&compiled_audit_path)?;
        (
            json!({
                "status": "included",
                "reason": "requested via ZKF_PRIVATE_NBODY_FULL_AUDIT=1",
                "path": "audit/private_nbody.source_audit.json",
                "producer": "audit_program_with_live_capabilities(original_program, Some(arkworks-groth16))",
                "summary": source_audit.summary,
            }),
            json!({
                "status": "included",
                "reason": "requested via ZKF_PRIVATE_NBODY_FULL_AUDIT=1",
                "path": "audit/private_nbody.compiled_audit.json",
                "producer": "audit_program_with_live_capabilities(compiled_program, Some(arkworks-groth16))",
                "summary": compiled_audit.summary,
            }),
        )
    } else {
        (
            json!({
                "status": "omitted-by-default",
                "reason": "set ZKF_PRIVATE_NBODY_FULL_AUDIT=1 to include the heavyweight live source audit in the bundle",
                "path": serde_json::Value::Null,
            }),
            json!({
                "status": "omitted-by-default",
                "reason": "set ZKF_PRIVATE_NBODY_FULL_AUDIT=1 to include the heavyweight live compiled audit in the bundle",
                "path": serde_json::Value::Null,
            }),
        )
    };

    let audit_summary = json!({
        "mode": "two-tier-showcase-audit-v1",
        "structural_summary": structural_summary,
        "full_source_audit": full_source_audit,
        "full_compiled_audit": full_compiled_audit,
    });

    let runtime_trace = json!({
        "source_prove": stage_summary(&source_execution.result.report, &runtime_artifact.metadata),
        "effective_gpu_attribution": gpu_attribution,
        "telemetry_paths": telemetry_paths,
        "export": {
            "mode": "direct-groth16",
            "wall_time_ms": wrap_ms,
        }
    });

    let evidence_manifest = json!({
        "bundle_evidence_version": "orbital-showcase-evidence-v1",
        "generated_closure": generated_closure_summary,
        "formal_evidence": formal_evidence,
        "audit_coverage": {
            "mode": "two-tier-showcase-audit-v1",
            "full_audit_requested": full_audit_enabled,
            "structural_summary": audit_summary["structural_summary"],
            "full_source_audit": audit_summary["full_source_audit"],
            "full_compiled_audit": audit_summary["full_compiled_audit"],
        },
        "gpu_attribution": gpu_attribution,
        "trusted_setup": {
            "provenance": setup_provenance,
            "security_boundary": security_boundary,
            "trusted_setup_requested": trusted_setup_requested,
            "trusted_setup_used": trusted_setup_used,
        },
    });

    let summary = json!({
        "circuit_name": original_program.name,
        "field": "bn254",
        "body_count": PRIVATE_NBODY_BODY_COUNT,
        "integration_steps": integration_steps,
        "backend": {
            "source": BackendKind::ArkworksGroth16.as_str(),
            "final": BackendKind::ArkworksGroth16.as_str(),
            "export": "direct-groth16",
        },
        "private_inputs": PRIVATE_NBODY_PRIVATE_INPUTS,
        "public_outputs": PRIVATE_NBODY_PUBLIC_OUTPUTS,
        "original_program": stats(&original_program),
        "optimized_program": stats(&optimized_program),
        "source_compiled_program": stats(&source_execution.compiled.program),
        "optimizer_report": optimizer_report,
        "groth16_setup": {
            "trusted_setup_requested": trusted_setup_requested,
            "trusted_setup_used": trusted_setup_used,
            "provenance": setup_provenance,
            "security_boundary": security_boundary,
        },
        "runtime_witness_mode": "authoritative-base-witness-normalized-by-runtime",
        "timings_ms": {
            "compile": compile_ms,
            "witness_prepare": witness_ms,
            "runtime_strict_lane_source_prove": source_runtime_ms,
            "groth16_export_wrap": wrap_ms,
        },
        "determinism": determinism,
        "public_outputs": public_outputs(&source_execution.compiled.program, &prepared_witness),
        "runtime_public_inputs": runtime_artifact
            .public_inputs
            .iter()
            .map(|value| value.to_decimal_string())
            .collect::<Vec<_>>(),
        "proof_sizes": {
            "runtime_proof_bytes": runtime_artifact.proof.len(),
            "runtime_verification_key_bytes": runtime_artifact.verification_key.len(),
            "source_proof_bytes": source_execution.artifact.proof.len(),
        },
        "runtime": runtime_trace,
        "control_plane": source_execution.result.control_plane,
        "security": source_execution.result.security,
        "model_integrity": source_execution.result.model_integrity,
        "swarm": source_execution.result.swarm,
        "artifact_metadata": runtime_artifact.metadata,
        "effective_gpu_attribution": gpu_attribution,
        "metal_runtime": metal_runtime_report(),
        "telemetry_paths": telemetry_paths,
        "evidence_manifest_path": "private_nbody.evidence_manifest.json",
        "generated_closure": evidence_manifest["generated_closure"],
        "formal_evidence": evidence_manifest["formal_evidence"],
        "audit_coverage": evidence_manifest["audit_coverage"],
    });

    write_json(&summary_path, &summary)?;
    write_json(&audit_path, &audit_summary)?;
    write_json(&runtime_trace_path, &runtime_trace)?;
    write_json(&evidence_manifest_path, &evidence_manifest)?;

    eprintln!("private_nbody_orbital_showcase: export checkpoint: markdown report");
    write_text(
        &report_path,
        &report_markdown(
            &original_program,
            &optimized_program,
            &source_execution.compiled,
            &runtime_artifact,
            &prepared_witness,
            &source_execution.result,
            integration_steps,
            &setup_provenance,
            &security_boundary,
            determinism.clone(),
            &telemetry_paths,
            &gpu_attribution,
            evidence_manifest
                .get("formal_evidence")
                .expect("formal evidence"),
            &audit_summary,
            &generated_closure,
        ),
    )?;

    ensure_file_exists(&summary_path)?;
    ensure_file_exists(&audit_path)?;
    ensure_file_exists(&runtime_trace_path)?;
    ensure_file_exists(&evidence_manifest_path)?;
    ensure_file_exists(&report_path)?;
    let _: serde_json::Value = read_json(&summary_path)?;
    let _: serde_json::Value = read_json(&audit_path)?;
    let _: serde_json::Value = read_json(&runtime_trace_path)?;
    let _: serde_json::Value = read_json(&evidence_manifest_path)?;
    let report_markdown = read_text(&report_path)?;
    if !report_markdown.contains("formal/STATUS.md") {
        return Err(ZkfError::InvalidArtifact(format!(
            "{} does not reference the bundled formal evidence",
            report_path.display()
        )));
    }
    let _cloud_paths = persist_artifacts_to_cloudfs(
        "private_nbody_orbital_showcase",
        &[
            ("proofs".to_string(), proof_path.clone()),
            ("verifiers".to_string(), verifier_path.clone()),
            ("verifiers".to_string(), calldata_path.clone()),
            ("reports".to_string(), summary_path.clone()),
            ("audits".to_string(), audit_path.clone()),
            ("traces".to_string(), runtime_trace_path.clone()),
            ("reports".to_string(), evidence_manifest_path.clone()),
            ("reports".to_string(), report_path.clone()),
        ],
    )?;

    println!("{}", summary_path.display());
    println!("{}", verifier_path.display());
    println!("{}", calldata_path.display());
    println!("{}", evidence_manifest_path.display());
    println!("{}", report_path.display());
    println!("{}", project_dir.display());
    Ok(())
}

fn main() -> ZkfResult<()> {
    if !SwarmConfig::is_enabled() {
        return Err(ZkfError::Backend(
            "swarm monitoring is required for this showcase; set ZKF_SWARM=1".to_string(),
        ));
    }

    let out_dir = output_dir();
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;
    let steps = integration_steps()?;

    eprintln!("private_nbody_orbital_showcase: building template");
    let template = private_nbody_orbital_showcase_with_steps(steps)?;
    let original_program = template.program.clone();
    let valid_inputs: WitnessInputs = template.sample_inputs.clone();
    eprintln!("private_nbody_orbital_showcase: optimizing program");
    let (optimized_program, optimizer_report) = optimize_program(&original_program);

    let trusted_setup_requested = requested_groth16_setup_blob_path(&optimized_program).is_some();
    let trusted_setup_used = trusted_setup_requested;
    let setup_provenance = if trusted_setup_requested {
        "trusted-imported".to_string()
    } else {
        "deterministic-dev".to_string()
    };
    let security_boundary = if trusted_setup_requested {
        "trusted-imported".to_string()
    } else {
        "development-only".to_string()
    };

    eprintln!("private_nbody_orbital_showcase: compiling groth16 artifact");
    let compile_start = Instant::now();
    let source_compiled = with_showcase_groth16_mode(trusted_setup_used, || {
        Ok(with_setup_seed_override(Some(SETUP_SEED), || {
            compile_arkworks_unchecked(&optimized_program)
        })?)
    })?;
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1_000.0;

    eprintln!("private_nbody_orbital_showcase: preparing witness");
    let witness_start = Instant::now();
    let base_witness = private_nbody_orbital_witness_with_steps(&valid_inputs, steps)?;
    let prepared_witness = prepare_witness_for_proving(&source_compiled, &base_witness)?;
    check_constraints(&source_compiled.program, &prepared_witness)?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;

    eprintln!("private_nbody_orbital_showcase: running runtime groth16 prove");
    let telemetry_before = telemetry_snapshot();
    let source_runtime_start = Instant::now();
    let source_execution = with_showcase_groth16_mode(trusted_setup_used, || {
        with_proof_seed_override(Some(PROOF_SEED), || {
            RuntimeExecutor::run_backend_prove_job_with_objective(
                BackendKind::ArkworksGroth16,
                BackendRoute::Auto,
                Arc::new(source_compiled.program.clone()),
                Some(Arc::new(valid_inputs.clone())),
                Some(Arc::new(base_witness.clone())),
                Some(Arc::new(source_compiled.clone())),
                OptimizationObjective::FastestProve,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .map_err(|error| ZkfError::Backend(error.to_string()))
        })
    })?;
    let source_runtime_ms = source_runtime_start.elapsed().as_secs_f64() * 1_000.0;
    if !verify(&source_execution.compiled, &source_execution.artifact)? {
        return Err(ZkfError::Backend(
            "runtime groth16 proof verification returned false".to_string(),
        ));
    }
    let telemetry_after = telemetry_snapshot();
    let wrap_ms = 0.0;

    eprintln!("private_nbody_orbital_showcase: exporting bundle");
    run_with_large_stack_result("private-nbody-export", move || {
        let inputs = ShowcaseExportInputs {
            out_dir,
            integration_steps: steps,
            original_program,
            optimized_program,
            optimizer_report,
            valid_inputs,
            base_witness,
            prepared_witness,
            source_execution,
            compile_ms,
            witness_ms,
            source_runtime_ms,
            wrap_ms,
            trusted_setup_requested,
            trusted_setup_used,
            setup_provenance,
            security_boundary,
            telemetry_before,
            telemetry_after,
        };
        export_showcase_bundle(inputs)
    })
}
