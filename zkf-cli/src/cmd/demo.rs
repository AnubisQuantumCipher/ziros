use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessInputs, wrapping::WrapModeOverride,
};
use zkf_runtime::{ExecutionMode, HardwareProfile, RequiredTrustLane, RuntimeExecutor};

use crate::solidity::render_groth16_solidity_verifier;
use crate::util::{render_zkf_error, with_setup_seed_override, write_json};

#[derive(Debug, Serialize)]
struct DemoReport {
    circuit: CircuitInfo,
    stages: Vec<StageResult>,
    solidity_verifier: SolidityInfo,
    summary: DemoSummary,
}

#[derive(Debug, Serialize)]
struct CircuitInfo {
    name: String,
    description: String,
    signals: usize,
    constraints: usize,
    field: String,
}

#[derive(Debug, Serialize)]
struct StageResult {
    name: String,
    backend: String,
    duration_ms: u128,
    proof_size_bytes: usize,
    public_inputs: usize,
    metadata: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct SolidityInfo {
    contract_name: String,
    source_bytes: usize,
    estimated_deploy_gas: u64,
    estimated_verify_gas: u64,
}

#[derive(Debug, Serialize)]
struct DemoSummary {
    total_duration_ms: u128,
    pipeline: String,
    initial_proof_size: usize,
    wrapped_proof_size: usize,
    compression_ratio: String,
}

pub(crate) fn handle_demo(out: Option<PathBuf>, json: bool) -> Result<(), String> {
    let total_start = Instant::now();
    let mut stages: Vec<StageResult> = Vec::new();

    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║              ZKF Universal Pipeline Demo                    ║");
    eprintln!("║  Circuit → STARK (Plonky3) → Groth16 wrap → Solidity       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    let (program, inputs) = build_demo_circuit();

    let circuit_info = CircuitInfo {
        name: "zkf-demo-fibonacci".to_string(),
        description: "Fibonacci sequence proof: proves knowledge of fib(10) = 89".to_string(),
        signals: program.signals.len(),
        constraints: program.constraints.len(),
        field: format!("{}", program.field),
    };

    eprintln!(
        "  [circuit] {} signals, {} constraints, field={}",
        circuit_info.signals, circuit_info.constraints, circuit_info.field
    );

    // ── Stage 1: Prove with Plonky3 (STARK) ───────────────────────────
    eprintln!("  [1/4] Compiling + proving with Plonky3 (STARK)...");
    let stage1_start = Instant::now();

    let plonky3 = backend_for(BackendKind::Plonky3);
    let execution = with_setup_seed_override(None, || {
        RuntimeExecutor::run_backend_prove_job(
            BackendKind::Plonky3,
            zkf_backends::BackendRoute::Auto,
            Arc::new(program.clone()),
            Some(Arc::new(inputs.clone())),
            None,
            None,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .map_err(|err| err.to_string())
    })?;
    let compiled_plonky3 = execution.compiled;
    let mut stark_proof = execution.artifact;
    crate::util::annotate_artifact_with_runtime_report(&mut stark_proof, &execution.result);

    let stage1_ms = stage1_start.elapsed().as_millis();
    eprintln!(
        "         STARK proof: {} bytes, {} public inputs ({} ms)",
        stark_proof.proof.len(),
        stark_proof.public_inputs.len(),
        stage1_ms
    );

    stages.push(StageResult {
        name: "plonky3-stark-prove".to_string(),
        backend: "plonky3".to_string(),
        duration_ms: stage1_ms,
        proof_size_bytes: stark_proof.proof.len(),
        public_inputs: stark_proof.public_inputs.len(),
        metadata: stark_proof.metadata.clone(),
    });

    // ── Stage 2: Verify the STARK proof ────────────────────────────────
    eprintln!("  [2/4] Verifying STARK proof...");
    let stage2_start = Instant::now();

    let stark_ok = plonky3
        .verify(&compiled_plonky3, &stark_proof)
        .map_err(render_zkf_error)?;
    if !stark_ok {
        return Err("STARK proof verification failed".to_string());
    }

    let stage2_ms = stage2_start.elapsed().as_millis();
    eprintln!("         STARK verified ({} ms)", stage2_ms);

    stages.push(StageResult {
        name: "plonky3-stark-verify".to_string(),
        backend: "plonky3".to_string(),
        duration_ms: stage2_ms,
        proof_size_bytes: 0,
        public_inputs: 0,
        metadata: Default::default(),
    });

    // ── Stage 3: Wrap STARK -> Groth16 ─────────────────────────────────
    eprintln!("  [3/4] Wrapping STARK -> Groth16 (Nova-compressed attestation lane)...");
    let stage3_start = Instant::now();

    let groth16_proof = crate::cmd::runtime::wrap_artifact_via_runtime(
        &stark_proof,
        &compiled_plonky3,
        RequiredTrustLane::AllowAttestation,
        HardwareProfile::detect(),
        Some(WrapModeOverride::Nova),
    )?;

    let stage3_ms = stage3_start.elapsed().as_millis();
    let wrapper_strategy = groth16_proof
        .metadata
        .get("wrapper_strategy")
        .map(String::as_str)
        .unwrap_or("unknown");
    let trust_model = groth16_proof
        .metadata
        .get("trust_model")
        .map(String::as_str)
        .unwrap_or("unknown");
    eprintln!(
        "         {} proof: {} bytes ({} ms)",
        wrapper_strategy,
        groth16_proof.proof.len(),
        stage3_ms
    );
    eprintln!("         trust model: {trust_model}");

    stages.push(StageResult {
        name: "stark-to-groth16-wrap".to_string(),
        backend: "arkworks-groth16".to_string(),
        duration_ms: stage3_ms,
        proof_size_bytes: groth16_proof.proof.len(),
        public_inputs: groth16_proof.public_inputs.len(),
        metadata: groth16_proof.metadata.clone(),
    });

    // ── Stage 4: Generate Solidity verifier ─────────────────────────────
    eprintln!("  [4/4] Generating Solidity verifier contract...");
    let stage4_start = Instant::now();

    let contract_name = "ZkfDemoVerifier";
    let solidity_source = render_groth16_solidity_verifier(&groth16_proof, contract_name);

    let stage4_ms = stage4_start.elapsed().as_millis();
    eprintln!(
        "         {} ({} bytes Solidity) ({} ms)",
        contract_name,
        solidity_source.len(),
        stage4_ms
    );

    stages.push(StageResult {
        name: "solidity-verifier-gen".to_string(),
        backend: "arkworks-groth16".to_string(),
        duration_ms: stage4_ms,
        proof_size_bytes: 0,
        public_inputs: 0,
        metadata: Default::default(),
    });

    // ── Report ──────────────────────────────────────────────────────────
    let total_ms = total_start.elapsed().as_millis();
    let initial_size = stark_proof.proof.len();
    let wrapped_size = groth16_proof.proof.len();
    let ratio = if wrapped_size > 0 {
        format!("{:.1}x", initial_size as f64 / wrapped_size as f64)
    } else {
        "N/A".to_string()
    };

    let solidity_info = SolidityInfo {
        contract_name: contract_name.to_string(),
        source_bytes: solidity_source.len(),
        estimated_deploy_gas: 1_500_000,
        estimated_verify_gas: 280_000,
    };

    let summary = DemoSummary {
        total_duration_ms: total_ms,
        pipeline: "Goldilocks circuit -> Plonky3 STARK -> Groth16 wrap -> Solidity verifier"
            .to_string(),
        initial_proof_size: initial_size,
        wrapped_proof_size: wrapped_size,
        compression_ratio: ratio.clone(),
    };

    let report = DemoReport {
        circuit: circuit_info,
        stages,
        solidity_verifier: solidity_info,
        summary,
    };

    eprintln!();
    eprintln!("══════════════════════════════════════════════════════════════");
    eprintln!("  Pipeline: Goldilocks -> Plonky3 STARK -> Groth16 -> Solidity");
    eprintln!("  STARK proof:   {} bytes", initial_size);
    eprintln!("  Groth16 proof: {} bytes ({})", wrapped_size, ratio);
    eprintln!("  Solidity:      {} bytes", solidity_source.len());
    eprintln!("  Total time:    {} ms", total_ms);
    eprintln!("══════════════════════════════════════════════════════════════");

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    }

    if let Some(out_path) = out {
        write_json(&out_path, &report)?;
        eprintln!("  Report written to {}", out_path.display());

        let sol_path = out_path.with_extension("sol");
        std::fs::write(&sol_path, &solidity_source)
            .map_err(|e| format!("failed to write solidity: {e}"))?;
        eprintln!("  Solidity verifier written to {}", sol_path.display());
    }

    // Store verifier and report to iCloud via CloudFS when available.
    if let Ok(cloudfs) = zkf_cloudfs::CloudFS::new() {
        let app_name = contract_name;

        let report_json = serde_json::to_vec_pretty(&report)
            .map_err(|e| format!("serialize report for icloud: {e}"))?;
        match cloudfs.store_artifact(app_name, "reports", "report.json", &report_json) {
            Ok(path) => eprintln!("  iCloud report:   {}", path.display()),
            Err(err) => eprintln!("  iCloud report failed: {err}"),
        }

        match cloudfs.store_artifact(
            app_name,
            "verifiers",
            &format!("{app_name}.sol"),
            solidity_source.as_bytes(),
        ) {
            Ok(path) => eprintln!("  iCloud verifier: {}", path.display()),
            Err(err) => eprintln!("  iCloud verifier failed: {err}"),
        }
    }

    Ok(())
}

/// Build a Fibonacci circuit in Goldilocks field.
///
/// Proves: "I know the Fibonacci sequence from fib(0)=1, fib(1)=1 to fib(10)=89"
///
/// Signals: fib_0 .. fib_10 (11 signals)
/// Constraints: fib_{i+2} = fib_{i} + fib_{i+1} for i in 0..8 (9 constraints)
/// Public: fib_0, fib_1, fib_10
fn build_demo_circuit() -> (Program, WitnessInputs) {
    const N: usize = 11; // fib_0 through fib_10

    let mut signals: Vec<Signal> = Vec::with_capacity(N);
    for i in 0..N {
        let vis = if i == 0 || i == 1 || i == N - 1 {
            Visibility::Public
        } else {
            Visibility::Private
        };
        signals.push(Signal {
            name: format!("fib_{i}"),
            visibility: vis,
            constant: None,
            ty: None,
        });
    }

    // Constraints: fib_{i+2} = fib_i + fib_{i+1}
    let mut constraints: Vec<Constraint> = Vec::with_capacity(N - 2);
    for i in 0..(N - 2) {
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal(format!("fib_{}", i + 2)),
            rhs: Expr::Add(vec![
                Expr::Signal(format!("fib_{i}")),
                Expr::Signal(format!("fib_{}", i + 1)),
            ]),
            label: Some(format!("fib_{} = fib_{} + fib_{}", i + 2, i, i + 1)),
        });
    }

    let program = Program {
        name: "zkf-demo-fibonacci".to_string(),
        field: FieldId::Goldilocks,
        signals,
        constraints,
        ..Default::default()
    };

    // Compute actual Fibonacci values
    let mut fib_vals: Vec<u64> = vec![1; N];
    fib_vals[0] = 1;
    fib_vals[1] = 1;
    for i in 2..N {
        fib_vals[i] = fib_vals[i - 2] + fib_vals[i - 1];
    }

    let mut inputs = WitnessInputs::new();
    for (i, &val) in fib_vals.iter().enumerate() {
        inputs.insert(format!("fib_{i}"), FieldElement::from_u64(val));
    }

    (program, inputs)
}
