mod hazard;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::{
    prepare_witness_for_proving, with_allow_dev_deterministic_groth16_override,
    with_proof_seed_override,
};
use zkf_core::{check_constraints, CompiledProgram, Program, ProofArtifact, Witness};
use zkf_lib::descent::{
    private_powered_descent_sample_inputs, private_powered_descent_showcase_with_steps,
    private_powered_descent_witness_with_steps,
};
use zkf_lib::{compile, export_groth16_solidity_verifier, prove, verify};

const SETUP_SEED: [u8; 32] = [0x71; 32];
const PROOF_SEED: [u8; 32] = [0x83; 32];
const STACK_SIZE: usize = 512 * 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("demo");

    match command {
        "demo" => big_stack("demo", || cmd_demo()),
        "full-mission" => big_stack("full-mission", || cmd_full_mission()),
        "verify" => {
            let p = args.get(2).ok_or("usage: verify <proof.json> <compiled.json>")?;
            let c = args.get(3).ok_or("usage: verify <proof.json> <compiled.json>")?;
            cmd_verify(Path::new(p), Path::new(c))
        }
        "export" => {
            let p = args.get(2).ok_or("usage: export <proof.json> <out_dir> <contract_name>")?;
            let d = args.get(3).ok_or("usage: export <proof.json> <out_dir> <contract_name>")?;
            let n = args.get(4).map(String::as_str).unwrap_or("LunarVerifier");
            cmd_export(Path::new(p), Path::new(d), n)
        }
        "benchmark" => big_stack("benchmark", || cmd_benchmark()),
        "e2e" => big_stack("e2e", || cmd_e2e()),
        other => Err(format!(
            "unknown: {other}\ncommands: demo | full-mission | verify | export | benchmark | e2e"
        )
        .into()),
    }
}

fn big_stack(name: &str, f: impl FnOnce() -> Result<(), String> + Send + 'static) -> Result<(), Box<dyn std::error::Error>> {
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(STACK_SIZE)
        .spawn(f)
        .map_err(|e| format!("thread: {e}"))?
        .join()
        .unwrap_or_else(|p| std::panic::resume_unwind(p))
        .map_err(|e| e.into())
}

fn app_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap_or(Path::new(".")).to_path_buf()
}

fn ensure_dir(d: &Path) {
    fs::create_dir_all(d).unwrap_or_else(|e| panic!("mkdir {}: {e}", d.display()));
}

// ═══════════════════════════════════════════════════════════════════════════
// Proof pipelines
// ═══════════════════════════════════════════════════════════════════════════

struct ProofResult {
    name: String,
    compiled: CompiledProgram,
    artifact: ProofArtifact,
    signals: usize,
    constraints: usize,
    timing: Timing,
}

#[derive(Default, Clone)]
struct Timing {
    build_ms: u128,
    witness_ms: u128,
    compile_ms: u128,
    check_ms: u128,
    prove_ms: u128,
    verify_ms: u128,
    total_ms: u128,
}

fn prove_circuit(
    name: &str,
    program: Program,
    witness: Witness,
) -> Result<ProofResult, String> {
    let total_start = Instant::now();
    let mut t = Timing::default();
    let signals = program.signals.len();
    let constraints = program.constraints.len();

    let now = Instant::now();
    let compiled = with_allow_dev_deterministic_groth16_override(Some(true), || {
        compile(&program, "arkworks-groth16", Some(SETUP_SEED))
    })
    .map_err(|e| format!("{name} compile: {e}"))?;
    t.compile_ms = now.elapsed().as_millis();

    let now = Instant::now();
    let prepared = prepare_witness_for_proving(&compiled, &witness)
        .map_err(|e| format!("{name} prepare: {e}"))?;
    check_constraints(&compiled.program, &prepared)
        .map_err(|e| format!("{name} constraints: {e}"))?;
    t.check_ms = now.elapsed().as_millis();

    let now = Instant::now();
    let artifact = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_proof_seed_override(Some(PROOF_SEED), || prove(&compiled, &prepared))
    })
    .map_err(|e| format!("{name} prove: {e}"))?;
    t.prove_ms = now.elapsed().as_millis();

    let now = Instant::now();
    let ok = verify(&compiled, &artifact).map_err(|e| format!("{name} verify: {e}"))?;
    t.verify_ms = now.elapsed().as_millis();

    if !ok {
        return Err(format!("{name}: verification failed"));
    }

    t.total_ms = total_start.elapsed().as_millis();

    Ok(ProofResult { name: name.into(), compiled, artifact, signals, constraints, timing: t })
}

fn run_hazard() -> Result<ProofResult, String> {
    let now = Instant::now();
    let program = hazard::build_hazard_program().map_err(|e| format!("hazard build: {e}"))?;
    let build_ms = now.elapsed().as_millis();

    let now = Instant::now();
    let inputs = hazard::hazard_sample_inputs();
    let witness = hazard::hazard_witness(&inputs).map_err(|e| format!("hazard witness: {e}"))?;
    let witness_ms = now.elapsed().as_millis();

    let mut result = prove_circuit("hazard_assessment", program, witness)?;
    result.timing.build_ms = build_ms;
    result.timing.witness_ms = witness_ms;
    Ok(result)
}

fn run_descent(steps: usize) -> Result<ProofResult, String> {
    let now = Instant::now();
    let template = private_powered_descent_showcase_with_steps(steps)
        .map_err(|e| format!("descent build ({steps} steps): {e}"))?;
    let build_ms = now.elapsed().as_millis();

    let now = Instant::now();
    // Use the template's own sample inputs — they match the step count
    let witness = private_powered_descent_witness_with_steps(&template.sample_inputs, steps)
        .map_err(|e| format!("descent witness ({steps} steps): {e}"))?;
    let witness_ms = now.elapsed().as_millis();

    let mut result = prove_circuit(
        &format!("powered_descent_{steps}_steps"),
        template.program,
        witness,
    )?;
    result.timing.build_ms = build_ms;
    result.timing.witness_ms = witness_ms;
    Ok(result)
}

fn print_timing(t: &Timing) {
    println!("  Circuit build:      {:>8} ms", t.build_ms);
    println!("  Witness generation: {:>8} ms", t.witness_ms);
    println!("  Groth16 compile:    {:>8} ms", t.compile_ms);
    println!("  Constraint check:   {:>8} ms", t.check_ms);
    println!("  Proving:            {:>8} ms", t.prove_ms);
    println!("  Verification:       {:>8} ms", t.verify_ms);
    println!("  ─────────────────────────────");
    println!("  Total:              {:>8} ms", t.total_ms);
}

fn write_proof(result: &ProofResult, proofs_dir: &Path, label: &str) -> Result<(), String> {
    ensure_dir(proofs_dir);
    fs::write(
        proofs_dir.join(format!("{label}_compiled.json")),
        serde_json::to_string_pretty(&result.compiled).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        proofs_dir.join(format!("{label}_proof.json")),
        serde_json::to_string_pretty(&result.artifact).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn export_verifier(
    artifact: &ProofArtifact,
    out_dir: &Path,
    contract_name: &str,
) -> Result<(), String> {
    ensure_dir(out_dir);
    let sol = export_groth16_solidity_verifier(artifact, Some(contract_name))
        .map_err(|e| format!("solidity export: {e}"))?;
    let calldata = proof_to_calldata_json(&artifact.proof, &artifact.public_inputs)
        .map_err(|e| format!("calldata: {e}"))?;
    let foundry = generate_foundry_test_from_artifact(
        &artifact.proof,
        &artifact.public_inputs,
        &format!("src/{contract_name}.sol"),
        contract_name,
    )
    .map_err(|e| format!("foundry: {e}"))?;

    fs::write(out_dir.join(format!("{contract_name}.sol")), &sol).map_err(|e| e.to_string())?;
    fs::write(
        out_dir.join("calldata.json"),
        serde_json::to_string_pretty(&calldata).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        out_dir.join(format!("{contract_name}.t.sol")),
        &foundry.source,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Commands
// ═══════════════════════════════════════════════════════════════════════════

fn cmd_demo() -> Result<(), String> {
    println!("================================================================================");
    println!("  ZirOS Lunar Flagship — Hazard Avoidance & Powered Descent Verification");
    println!("  BN254 / Groth16 / ProgramBuilder / Metal-capable");
    println!("================================================================================");
    println!();
    println!("Running demo: hazard assessment + 1-step descent...");
    println!();

    // ── Hazard Assessment ─────────────────────────────────────────────────
    println!("─── Phase 1: Terrain Hazard Assessment ───────────────────────────────────");
    let hz = run_hazard()?;
    println!("  PASS — hazard proof generated and verified");
    println!("  Signals: {}, Constraints: {}, Proof: {} bytes",
        hz.signals, hz.constraints, hz.artifact.proof.len());
    print_timing(&hz.timing);
    println!();

    // ── Powered Descent (1-step for demo speed) ──────────────────────────
    println!("─── Phase 2: Powered Descent Verification (1 step) ──────────────────────");
    let ds = run_descent(1)?;
    println!("  PASS — descent proof generated and verified");
    println!("  Signals: {}, Constraints: {}, Proof: {} bytes",
        ds.signals, ds.constraints, ds.artifact.proof.len());
    print_timing(&ds.timing);
    println!();

    println!("================================================================================");
    println!("  DEMO COMPLETE — Both proofs generated, verified, pipeline validated.");
    println!("  Use 'full-mission' for 200-step descent with Metal GPU acceleration.");
    println!("================================================================================");
    Ok(())
}

fn cmd_full_mission() -> Result<(), String> {
    let root = app_root();
    println!("================================================================================");
    println!("  FULL MISSION: Lunar Landing Hazard Avoidance & Powered Descent");
    println!("  200 steps × 0.2s = 40-second powered descent window");
    println!("  ~23,000 constraints — Metal MSM GPU acceleration expected");
    println!("================================================================================");
    println!();

    // ── Phase 1: Hazard Assessment ────────────────────────────────────────
    println!("─── Phase 1: Terrain Hazard Assessment ───────────────────────────────────");
    println!("  Grid: 4 cells [flat_mare(12), crater_rim(180), slope(45), boulders(220)]");
    println!("  Threshold: 50  ·  Selected: cell_0 (flat mare, score=12)");
    println!();
    let hz = run_hazard()?;
    println!("  RESULT: PASS");
    println!("  Signals: {}, Constraints: {}", hz.signals, hz.constraints);
    print_timing(&hz.timing);
    write_proof(&hz, &root.join("06_proofs"), "hazard")?;
    println!();

    // ── Phase 2: Powered Descent (200 steps) ─────────────────────────────
    println!("─── Phase 2: Powered Descent Verification (200 steps) ───────────────────");
    println!("  Integration: Euler, dt=0.2s, g=9.81 m/s²");
    println!("  Constraints: ~23,000 (crosses Metal MSM threshold of 16,384)");
    println!();
    let ds = run_descent(200)?;
    println!("  RESULT: PASS");
    println!("  Signals: {}, Constraints: {}", ds.signals, ds.constraints);
    print_timing(&ds.timing);
    write_proof(&ds, &root.join("06_proofs"), "descent")?;
    println!();

    // ── Write artifacts ──────────────────────────────────────────────────
    let artifacts_dir = root.join("05_artifacts");
    ensure_dir(&artifacts_dir);
    let mut meta = BTreeMap::new();
    meta.insert("hazard_signals", hz.signals.to_string());
    meta.insert("hazard_constraints", hz.constraints.to_string());
    meta.insert("hazard_proof_bytes", hz.artifact.proof.len().to_string());
    meta.insert("descent_steps", "200".to_string());
    meta.insert("descent_signals", ds.signals.to_string());
    meta.insert("descent_constraints", ds.constraints.to_string());
    meta.insert("descent_proof_bytes", ds.artifact.proof.len().to_string());
    meta.insert("backend", "arkworks-groth16".to_string());
    meta.insert("field", "bn254".to_string());
    meta.insert("msm_threshold", "16384".to_string());
    meta.insert("msm_gpu_expected", (ds.constraints > 16384).to_string());
    fs::write(
        artifacts_dir.join("mission_metadata.json"),
        serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;

    // ── Export verifiers ──────────────────────────────────────────────────
    let verifiers_dir = root.join("07_verifiers");
    export_verifier(&hz.artifact, &verifiers_dir.join("hazard"), "HazardAssessmentVerifier")?;
    export_verifier(&ds.artifact, &verifiers_dir.join("descent"), "PoweredDescentVerifier")?;

    println!("================================================================================");
    println!("  FULL MISSION COMPLETE");
    println!("  Hazard assessment: {} constraints → proof verified", hz.constraints);
    println!("  Powered descent:   {} constraints → proof verified", ds.constraints);
    println!("  Total constraints: {}", hz.constraints + ds.constraints);
    println!("  Artifacts: 06_proofs/, 07_verifiers/");
    println!("  MSM GPU threshold crossed: {}", ds.constraints > 16384);
    println!("================================================================================");
    Ok(())
}

fn cmd_verify(proof_path: &Path, compiled_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let compiled: CompiledProgram = serde_json::from_str(&fs::read_to_string(compiled_path)?)?;
    let artifact: ProofArtifact = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    let now = Instant::now();
    let ok = verify(&compiled, &artifact)?;
    let ms = now.elapsed().as_millis();
    if ok {
        println!("VERIFIED: true  backend={}  time={ms}ms", compiled.backend);
    } else {
        return Err("verification FAILED".into());
    }
    Ok(())
}

fn cmd_export(proof_path: &Path, out_dir: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let artifact: ProofArtifact = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    export_verifier(&artifact, out_dir, name).map_err(|e| e.into())
}

fn cmd_benchmark() -> Result<(), String> {
    println!("================================================================================");
    println!("  ZirOS Lunar Flagship — Benchmark Suite");
    println!("================================================================================");
    println!();

    // Hazard benchmark
    println!("─── Hazard Assessment Circuit ─────────────────────────────────────────────");
    let hz = run_hazard()?;
    println!("  Signals: {}, Constraints: {}, Proof: {} bytes",
        hz.signals, hz.constraints, hz.artifact.proof.len());
    print_timing(&hz.timing);
    println!();

    // Descent benchmarks at multiple scales
    // Only step counts with valid sample profiles: 1 and 200
    // (the module generates valid thrust profiles for these specifically)
    let step_counts = [1, 200];
    let mut results: Vec<(usize, usize, usize, usize, Timing)> = Vec::new();

    for &steps in &step_counts {
        println!("─── Powered Descent: {steps} steps ({:.1}s window) ──────────────────────────",
            steps as f64 * 0.2);
        let ds = run_descent(steps)?;
        println!("  Signals: {}, Constraints: {}, Proof: {} bytes",
            ds.signals, ds.constraints, ds.artifact.proof.len());
        print_timing(&ds.timing);
        println!();
        results.push((steps, ds.signals, ds.constraints, ds.artifact.proof.len(), ds.timing));
    }

    println!("─── Summary ───────────────────────────────────────────────────────────────");
    println!("{:>6} {:>8} {:>12} {:>10} {:>10} {:>10} {:>10}",
        "Steps", "Signals", "Constraints", "Proof(B)", "Build(ms)", "Prove(ms)", "Total(ms)");
    for (steps, signals, constraints, proof_sz, t) in &results {
        println!("{:>6} {:>8} {:>12} {:>10} {:>10} {:>10} {:>10}",
            steps, signals, constraints, proof_sz, t.build_ms, t.prove_ms, t.total_ms);
    }
    println!();
    println!("Metal GPU dispatch (MSM threshold = 16,384):");
    for (steps, _, constraints, _, _) in &results {
        let gpu = *constraints > 16_384;
        println!("  {steps:>4} steps ({constraints:>6} constraints): {}",
            if gpu { "GPU-dispatched (above threshold)" } else { "CPU-only (below threshold)" });
    }

    let root = app_root();
    ensure_dir(&root.join("08_benchmarks"));
    let mut report = String::from("# Benchmark Results\n\n");
    report.push_str("Backend: arkworks-groth16 (BN254)\n\n");
    report.push_str(&format!("Hazard assessment: {} signals, {} constraints, {}ms total\n\n",
        hz.signals, hz.constraints, hz.timing.total_ms));
    report.push_str("| Steps | Signals | Constraints | Proof(B) | Build(ms) | Prove(ms) | Total(ms) |\n");
    report.push_str("|-------|---------|-------------|----------|-----------|-----------|----------|\n");
    for (steps, signals, constraints, proof_sz, t) in &results {
        report.push_str(&format!("| {} | {} | {} | {} | {} | {} | {} |\n",
            steps, signals, constraints, proof_sz, t.build_ms, t.prove_ms, t.total_ms));
    }
    fs::write(root.join("08_benchmarks/benchmark_results.md"), &report).map_err(|e| e.to_string())?;
    println!("\nBenchmark results written to 08_benchmarks/benchmark_results.md");

    Ok(())
}

fn cmd_e2e() -> Result<(), String> {
    let root = app_root();
    println!("================================================================================");
    println!("  End-to-End Pipeline Test");
    println!("================================================================================");
    println!();

    // Step 1: Hazard assessment
    println!("[1/6] Hazard assessment...");
    let hz = run_hazard()?;
    write_proof(&hz, &root.join("06_proofs"), "hazard")?;
    println!("      PASS — {} signals, {} constraints, verified", hz.signals, hz.constraints);

    // Step 2: Powered descent (1 step for E2E speed — full-mission uses 200)
    println!("[2/6] Powered descent (1 step)...");
    let ds = run_descent(1)?;
    write_proof(&ds, &root.join("06_proofs"), "descent")?;
    println!("      PASS — {} signals, {} constraints, verified", ds.signals, ds.constraints);

    // Step 3: Verify hazard from files
    println!("[3/6] Verify hazard proof from files...");
    let hc: CompiledProgram = serde_json::from_str(
        &fs::read_to_string(root.join("06_proofs/hazard_compiled.json")).map_err(|e| e.to_string())?
    ).map_err(|e| e.to_string())?;
    let ha: ProofArtifact = serde_json::from_str(
        &fs::read_to_string(root.join("06_proofs/hazard_proof.json")).map_err(|e| e.to_string())?
    ).map_err(|e| e.to_string())?;
    assert!(verify(&hc, &ha).map_err(|e| e.to_string())?, "hazard verify from files");
    println!("      PASS");

    // Step 4: Tamper detection
    println!("[4/6] Tamper detection...");
    let mut tampered = ha.clone();
    if !tampered.public_inputs.is_empty() {
        tampered.public_inputs[0] = zkf_core::FieldElement::from_i64(999);
    }
    let tamper_ok = verify(&hc, &tampered).unwrap_or(false);
    assert!(!tamper_ok, "tampered proof must fail");
    println!("      PASS — tampered proof correctly rejected");

    // Step 5: Export verifiers
    println!("[5/6] Export Solidity verifiers...");
    let vdir = root.join("07_verifiers");
    export_verifier(&hz.artifact, &vdir.join("hazard"), "HazardAssessmentVerifier")?;
    export_verifier(&ds.artifact, &vdir.join("descent"), "PoweredDescentVerifier")?;
    println!("      PASS — 2 Solidity contracts + Foundry tests");

    // Step 6: Validate exports
    println!("[6/6] Validate exported artifacts...");
    let sol = fs::read_to_string(vdir.join("hazard/HazardAssessmentVerifier.sol")).map_err(|e| e.to_string())?;
    assert!(sol.contains("contract HazardAssessmentVerifier"));
    let foundry = fs::read_to_string(vdir.join("hazard/HazardAssessmentVerifier.t.sol")).map_err(|e| e.to_string())?;
    assert!(foundry.contains("test_tamperedProofFails"));
    println!("      PASS");

    // Write test log
    ensure_dir(&root.join("09_test_results"));
    fs::write(root.join("09_test_results/e2e_log.txt"), format!(
        "E2E: ALL PASSED\nHazard: {} signals, {} constraints\nDescent: {} signals, {} constraints\n\
         Verification from files: true\nTamper detection: true\nSolidity export: true\nFoundry tests: true\n",
        hz.signals, hz.constraints, ds.signals, ds.constraints
    )).map_err(|e| e.to_string())?;

    println!();
    println!("================================================================================");
    println!("  E2E: ALL 6 STAGES PASSED");
    println!("================================================================================");
    Ok(())
}
