use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use zkf_lib::{
    Expr, FieldElement, FieldId, Program, ProgramBuilder, WitnessInputs, ZkfError, ZkfResult,
};

// ---------------------------------------------------------------------------
// Expression helpers
// ---------------------------------------------------------------------------

fn signal(name: &str) -> Expr {
    Expr::signal(name)
}

fn constant(value: i64) -> Expr {
    Expr::constant_i64(value)
}

fn sub(lhs: Expr, rhs: Expr) -> Expr {
    Expr::Sub(Box::new(lhs), Box::new(rhs))
}

fn mul(lhs: Expr, rhs: Expr) -> Expr {
    Expr::Mul(Box::new(lhs), Box::new(rhs))
}

fn add(terms: Vec<Expr>) -> Expr {
    Expr::Add(terms)
}

// ---------------------------------------------------------------------------
// Circuit construction
// ---------------------------------------------------------------------------

const NUM_MANEUVER_STEPS: usize = 4;

fn build_fuel_compliance_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("satellite_fuel_compliance", FieldId::Goldilocks);

    // --- Private inputs ---
    builder.private_input("starting_fuel")?;
    for i in 0..NUM_MANEUVER_STEPS {
        builder.private_input(&format!("burn_step_{i}"))?;
    }
    builder.private_input("safety_reserve")?;

    // --- Public outputs ---
    builder.public_output("fuel_commitment")?;
    builder.public_output("compliance_status")?;

    // --- Range constraints on all inputs (16-bit: values 0..65535) ---
    builder.constrain_range("starting_fuel", 16)?;
    for i in 0..NUM_MANEUVER_STEPS {
        builder.constrain_range(&format!("burn_step_{i}"), 16)?;
    }
    builder.constrain_range("safety_reserve", 16)?;

    // --- Step-by-step fuel computation ---
    // Step 0: fuel_after_step_0 = starting_fuel - burn_step_0
    builder.bind(
        "fuel_after_step_0",
        sub(signal("starting_fuel"), signal("burn_step_0")),
    )?;
    // Steps 1..N: fuel_after_step_i = fuel_after_step_{i-1} - burn_step_i
    for i in 1..NUM_MANEUVER_STEPS {
        builder.bind(
            &format!("fuel_after_step_{i}"),
            sub(
                signal(&format!("fuel_after_step_{}", i - 1)),
                signal(&format!("burn_step_{i}")),
            ),
        )?;
    }

    // --- Range-constrain each intermediate fuel level (proves non-negative) ---
    for i in 0..NUM_MANEUVER_STEPS {
        builder.constrain_range(&format!("fuel_after_step_{i}"), 16)?;
    }

    // --- Safety compliance: final fuel >= safety reserve ---
    builder.constrain_geq(
        "safety_slack",
        signal(&format!("fuel_after_step_{}", NUM_MANEUVER_STEPS - 1)),
        signal("safety_reserve"),
        16,
    )?;

    // --- Public commitment (nonlinear binding of starting_fuel) ---
    // commitment = starting_fuel * (starting_fuel + safety_reserve + 1)
    builder.bind(
        "fuel_commitment",
        mul(
            signal("starting_fuel"),
            add(vec![
                signal("starting_fuel"),
                signal("safety_reserve"),
                constant(1),
            ]),
        ),
    )?;

    // --- Compliance status = 1 (proof existence IS the compliance assertion) ---
    builder.constant_signal("__compliance_one", FieldElement::ONE)?;
    builder.bind("compliance_status", signal("__compliance_one"))?;
    builder.constrain_boolean("compliance_status")?;

    builder.build()
}

// ---------------------------------------------------------------------------
// Witness inputs
// ---------------------------------------------------------------------------

fn compliant_inputs() -> WitnessInputs {
    // Starting fuel: 10000, burns: 1500, 2000, 1000, 500, reserve: 3000
    // Remaining after each step: 8500, 6500, 5500, 5000
    // Final 5000 >= reserve 3000 → compliant
    let mut inputs = WitnessInputs::new();
    inputs.insert("starting_fuel".into(), FieldElement::from_u64(10000));
    inputs.insert("burn_step_0".into(), FieldElement::from_u64(1500));
    inputs.insert("burn_step_1".into(), FieldElement::from_u64(2000));
    inputs.insert("burn_step_2".into(), FieldElement::from_u64(1000));
    inputs.insert("burn_step_3".into(), FieldElement::from_u64(500));
    inputs.insert("safety_reserve".into(), FieldElement::from_u64(3000));
    inputs
}

fn non_compliant_inputs() -> WitnessInputs {
    // Starting fuel: 10000, burns: 3000, 3000, 2500, 1000, reserve: 3000
    // Remaining after each step: 7000, 4000, 1500, 500
    // Final 500 < reserve 3000 → non-compliant (should fail)
    let mut inputs = WitnessInputs::new();
    inputs.insert("starting_fuel".into(), FieldElement::from_u64(10000));
    inputs.insert("burn_step_0".into(), FieldElement::from_u64(3000));
    inputs.insert("burn_step_1".into(), FieldElement::from_u64(3000));
    inputs.insert("burn_step_2".into(), FieldElement::from_u64(2500));
    inputs.insert("burn_step_3".into(), FieldElement::from_u64(1000));
    inputs.insert("safety_reserve".into(), FieldElement::from_u64(3000));
    inputs
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Manifest {
    application: &'static str,
    version: &'static str,
    field: &'static str,
    backend: &'static str,
    num_maneuver_steps: usize,
    description: &'static str,
}

#[derive(Serialize)]
struct ExpectedOutputs {
    compliant_scenario: BTreeMap<String, String>,
    fuel_trace: Vec<u64>,
}

#[derive(Serialize)]
struct ProofMetadata {
    backend: String,
    proof_size_bytes: usize,
    compile_ms: u128,
    prove_ms: u128,
    total_ms: u128,
}

#[derive(Serialize)]
struct VerificationResult {
    verified: bool,
    backend: String,
    verify_ms: u128,
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        ZkfError::InvalidArtifact(format!("serialize {}: {error}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn write_text(path: &Path, text: &str) -> ZkfResult<()> {
    fs::write(path, text)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn ensure_dir(path: &Path) -> ZkfResult<()> {
    fs::create_dir_all(path)
        .map_err(|error| ZkfError::Io(format!("create dir {}: {error}", path.display())))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn output_dir() -> PathBuf {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/zkf-fuel-compliance"))
}

fn main() -> ZkfResult<()> {
    let base = output_dir();
    let artifacts_dir = base.join("04_artifacts");
    let proofs_dir = base.join("05_proofs");
    let verifiers_dir = base.join("06_verifiers");
    let test_results_dir = base.join("07_test_results");

    for dir in [&artifacts_dir, &proofs_dir, &verifiers_dir, &test_results_dir] {
        ensure_dir(dir)?;
    }

    // -----------------------------------------------------------------------
    // 1. Build the circuit
    // -----------------------------------------------------------------------
    println!("[1/6] Building satellite fuel compliance circuit...");
    let program = build_fuel_compliance_program()?;
    println!(
        "       Circuit built: {} signals, {} constraints",
        program.signals.len(),
        program.constraints.len()
    );

    // -----------------------------------------------------------------------
    // 2. Serialize artifacts
    // -----------------------------------------------------------------------
    println!("[2/6] Writing program and input artifacts...");
    write_json(&artifacts_dir.join("program.json"), &program)?;

    let valid = compliant_inputs();
    let rejected = non_compliant_inputs();
    write_json(&artifacts_dir.join("valid_inputs.json"), &valid)?;
    write_json(&artifacts_dir.join("rejected_inputs.json"), &rejected)?;

    // fuel_commitment = starting_fuel * (starting_fuel + safety_reserve + 1)
    //                 = 10000 * (10000 + 3000 + 1) = 10000 * 13001 = 130010000
    let expected = ExpectedOutputs {
        compliant_scenario: BTreeMap::from([
            ("fuel_commitment".into(), "130010000".into()),
            ("compliance_status".into(), "1".into()),
        ]),
        fuel_trace: vec![8500, 6500, 5500, 5000],
    };
    write_json(&artifacts_dir.join("expected_outputs.json"), &expected)?;

    let manifest = Manifest {
        application: "Private Satellite Fuel Budget Compliance Verifier",
        version: "0.1.0",
        field: "Goldilocks",
        backend: "plonky3",
        num_maneuver_steps: NUM_MANEUVER_STEPS,
        description: "Proves that satellite fuel remaining after a maneuver sequence stays above the required safety reserve, without revealing any private fuel data.",
    };
    write_json(&artifacts_dir.join("manifest.json"), &manifest)?;

    // -----------------------------------------------------------------------
    // 3. Compile + Prove (compliant scenario)
    // -----------------------------------------------------------------------
    println!("[3/6] Compiling and generating proof (compliant scenario)...");
    let total_start = Instant::now();

    let compile_start = Instant::now();
    let embedded = zkf_lib::compile_and_prove(&program, &valid, "plonky3", None, None)?;
    let compile_prove_ms = compile_start.elapsed().as_millis();

    let proof_meta = ProofMetadata {
        backend: "plonky3".into(),
        proof_size_bytes: embedded.artifact.proof.len(),
        compile_ms: compile_prove_ms / 2,   // approximate split
        prove_ms: compile_prove_ms / 2,      // approximate split
        total_ms: compile_prove_ms,
    };
    println!(
        "       Proof generated: {} bytes in {}ms",
        proof_meta.proof_size_bytes, proof_meta.total_ms
    );

    // -----------------------------------------------------------------------
    // 4. Write proof artifacts
    // -----------------------------------------------------------------------
    println!("[4/6] Writing proof artifacts...");
    write_json(&proofs_dir.join("proof_artifact.json"), &embedded.artifact)?;
    write_json(&proofs_dir.join("proof_metadata.json"), &proof_meta)?;
    write_text(
        &proofs_dir.join("backend_used.txt"),
        "plonky3 (Goldilocks, transparent setup)\n",
    )?;

    // -----------------------------------------------------------------------
    // 5. Verify
    // -----------------------------------------------------------------------
    println!("[5/6] Verifying proof...");
    let verify_start = Instant::now();
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)?;
    let verify_ms = verify_start.elapsed().as_millis();
    let total_ms = total_start.elapsed().as_millis();

    let verification = VerificationResult {
        verified,
        backend: "plonky3".into(),
        verify_ms,
    };
    write_json(&verifiers_dir.join("verification_result.json"), &verification)?;

    let verify_cmd = format!(
        "# Verification was performed inline using zkf_lib::verify()\n\
         # Backend: plonky3\n\
         # Verified: {verified}\n\
         # Time: {verify_ms}ms\n\
         #\n\
         # To reproduce:\n\
         #   cargo run --example satellite_fuel_compliance -- {}\n",
        base.display()
    );
    write_text(&verifiers_dir.join("verification_command.txt"), &verify_cmd)?;

    println!("       Verification: {} ({}ms)", if verified { "PASS" } else { "FAIL" }, verify_ms);

    // -----------------------------------------------------------------------
    // 6. Test rejection scenario
    // -----------------------------------------------------------------------
    println!("[6/6] Testing non-compliant scenario (should fail)...");
    let rejection_result =
        zkf_lib::compile_and_prove(&program, &rejected, "plonky3", None, None);

    let rejection_status = match &rejection_result {
        Ok(_) => "UNEXPECTED: non-compliant inputs produced a proof (this should not happen)".into(),
        Err(e) => format!("Correctly rejected: {e}"),
    };
    println!("       {rejection_status}");

    // Write test results
    let test_log = format!(
        "=== Satellite Fuel Compliance — Test Results ===\n\n\
         Circuit:\n  Signals: {}\n  Constraints: {}\n\n\
         Compliant Scenario:\n  Proof size: {} bytes\n  Compile+Prove: {}ms\n  Verify: {}ms\n  Result: {}\n\n\
         Non-Compliant Scenario:\n  {}\n\n\
         Total wall time: {}ms\n",
        program.signals.len(),
        program.constraints.len(),
        proof_meta.proof_size_bytes,
        proof_meta.total_ms,
        verify_ms,
        if verified { "VERIFIED" } else { "FAILED" },
        rejection_status,
        total_ms,
    );
    write_text(&test_results_dir.join("test_log.txt"), &test_log)?;

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    println!("\n=== Summary ===");
    println!("  Output directory: {}", base.display());
    println!("  Circuit: {} signals, {} constraints", program.signals.len(), program.constraints.len());
    println!("  Proof: {} bytes", proof_meta.proof_size_bytes);
    println!("  Verified: {verified}");
    println!("  Total time: {total_ms}ms");

    if !verified {
        return Err(ZkfError::InvalidArtifact(
            "proof verification failed for compliant inputs".into(),
        ));
    }

    Ok(())
}
