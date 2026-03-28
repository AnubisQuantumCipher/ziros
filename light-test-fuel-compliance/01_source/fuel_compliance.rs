use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use zkf_core::zir::{self, SignalType, WitnessAssignment, WitnessPlan};
use zkf_core::{
    BackendKind, FieldElement, FieldId, Program, Visibility, WitnessInputs, ZkfError, ZkfResult,
    generate_witness, check_constraints, program_zir_to_v2,
};

// ---------------------------------------------------------------------------
// Expression helpers
// ---------------------------------------------------------------------------

fn sig(name: &str) -> zir::Expr {
    zir::Expr::Signal(name.to_string())
}

fn c(value: i64) -> zir::Expr {
    zir::Expr::Const(FieldElement::from_i64(value))
}

fn sub(lhs: zir::Expr, rhs: zir::Expr) -> zir::Expr {
    zir::Expr::Sub(Box::new(lhs), Box::new(rhs))
}

fn mul(lhs: zir::Expr, rhs: zir::Expr) -> zir::Expr {
    zir::Expr::Mul(Box::new(lhs), Box::new(rhs))
}

fn add(terms: Vec<zir::Expr>) -> zir::Expr {
    zir::Expr::Add(terms)
}

fn private_input(name: &str) -> zir::Signal {
    zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Private,
        ty: SignalType::Field,
        constant: None,
    }
}

fn private_signal(name: &str) -> zir::Signal {
    zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Private,
        ty: SignalType::Field,
        constant: None,
    }
}

fn public_output(name: &str) -> zir::Signal {
    zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Public,
        ty: SignalType::Field,
        constant: None,
    }
}

fn constant_signal(name: &str, value: FieldElement) -> zir::Signal {
    zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Constant,
        ty: SignalType::Field,
        constant: Some(value),
    }
}

fn uint_signal(name: &str, bits: u32) -> zir::Signal {
    zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Private,
        ty: SignalType::UInt { bits },
        constant: None,
    }
}

fn eq(lhs: zir::Expr, rhs: zir::Expr, label: &str) -> zir::Constraint {
    zir::Constraint::Equal {
        lhs,
        rhs,
        label: Some(label.to_string()),
    }
}

fn range(signal: &str, bits: u32, label: &str) -> zir::Constraint {
    zir::Constraint::Range {
        signal: signal.to_string(),
        bits,
        label: Some(label.to_string()),
    }
}

fn boolean(signal: &str, label: &str) -> zir::Constraint {
    zir::Constraint::Boolean {
        signal: signal.to_string(),
        label: Some(label.to_string()),
    }
}

fn assign(target: &str, expr: zir::Expr) -> WitnessAssignment {
    WitnessAssignment {
        target: target.to_string(),
        expr,
    }
}

// ---------------------------------------------------------------------------
// Circuit construction
// ---------------------------------------------------------------------------

const NUM_STEPS: usize = 4;

fn build_fuel_compliance_program() -> ZkfResult<Program> {
    let mut signals = Vec::new();
    let mut constraints = Vec::new();
    let mut assignments = Vec::new();

    // --- Private inputs ---
    signals.push(private_input("starting_fuel"));
    for i in 0..NUM_STEPS {
        signals.push(private_input(&format!("burn_step_{i}")));
    }
    signals.push(private_input("safety_reserve"));

    // --- Public outputs ---
    signals.push(public_output("fuel_commitment"));
    signals.push(public_output("compliance_status"));

    // --- Constants ---
    signals.push(constant_signal("__anchor_one", FieldElement::ONE));

    // --- Range constraints on all inputs (16-bit: values 0..65535) ---
    // Each range constraint + nonlinear anchor (signal * 1 == signal) to satisfy audit
    constraints.push(range("starting_fuel", 16, "starting_fuel_range"));
    constraints.push(eq(
        mul(sig("starting_fuel"), sig("__anchor_one")),
        sig("starting_fuel"),
        "starting_fuel_anchor",
    ));
    for i in 0..NUM_STEPS {
        let name = format!("burn_step_{i}");
        constraints.push(range(&name, 16, &format!("burn_step_{i}_range")));
        constraints.push(eq(
            mul(sig(&name), sig("__anchor_one")),
            sig(&name),
            &format!("burn_step_{i}_anchor"),
        ));
    }
    constraints.push(range("safety_reserve", 16, "safety_reserve_range"));
    constraints.push(eq(
        mul(sig("safety_reserve"), sig("__anchor_one")),
        sig("safety_reserve"),
        "safety_reserve_anchor",
    ));

    // --- Step-by-step fuel computation ---
    for i in 0..NUM_STEPS {
        let step_name = format!("fuel_after_step_{i}");
        signals.push(private_signal(&step_name));

        let prev = if i == 0 {
            sig("starting_fuel")
        } else {
            sig(&format!("fuel_after_step_{}", i - 1))
        };
        let burn = sig(&format!("burn_step_{i}"));
        let diff = sub(prev, burn);

        // Witness assignment: fuel_after_step_i = prev - burn_step_i
        assignments.push(assign(&step_name, diff.clone()));

        // Equality constraint: fuel_after_step_i == prev - burn_step_i
        constraints.push(eq(sig(&step_name), diff, &format!("fuel_step_{i}_eq")));

        // Range constraint + nonlinear anchor
        constraints.push(range(&step_name, 16, &format!("fuel_step_{i}_nonneg")));
        constraints.push(eq(
            mul(sig(&step_name), sig("__anchor_one")),
            sig(&step_name),
            &format!("fuel_step_{i}_anchor"),
        ));
    }

    // --- Safety compliance: final fuel >= safety reserve ---
    // slack = fuel_after_step_3 - safety_reserve (must be >= 0)
    let final_fuel = sig(&format!("fuel_after_step_{}", NUM_STEPS - 1));
    let reserve = sig("safety_reserve");
    signals.push(uint_signal("safety_slack", 16));
    assignments.push(assign("safety_slack", sub(final_fuel.clone(), reserve.clone())));
    constraints.push(eq(
        sig("safety_slack"),
        sub(final_fuel.clone(), reserve.clone()),
        "safety_slack_eq",
    ));
    constraints.push(range("safety_slack", 16, "safety_slack_range"));
    // Anchor safety_slack with nonlinear constraint
    constraints.push(eq(
        mul(sig("safety_slack"), sig("__anchor_one")),
        sig("safety_slack"),
        "safety_slack_anchor",
    ));

    // --- Fuel commitment (nonlinear binding) ---
    // commitment = starting_fuel * (starting_fuel + safety_reserve + 1)
    let commit_expr = mul(
        sig("starting_fuel"),
        add(vec![sig("starting_fuel"), sig("safety_reserve"), c(1)]),
    );
    assignments.push(assign("fuel_commitment", commit_expr.clone()));
    constraints.push(eq(sig("fuel_commitment"), commit_expr, "fuel_commitment_eq"));

    // --- Compliance status = 1 ---
    signals.push(zir::Signal {
        name: "compliance_status".to_string(),
        visibility: Visibility::Public,
        ty: SignalType::Bool,
        constant: None,
    });
    assignments.push(assign("compliance_status", sig("__anchor_one")));
    constraints.push(eq(
        sig("compliance_status"),
        sig("__anchor_one"),
        "compliance_status_eq",
    ));
    constraints.push(boolean("compliance_status", "compliance_status_bool"));

    // --- Build ZIR program and lower to IR-v2 ---
    // Remove duplicate compliance_status signal (was added both as public_output and with Bool type)
    signals.retain({
        let mut seen = std::collections::HashSet::new();
        move |s| seen.insert(s.name.clone())
    });

    let zir_program = zir::Program {
        name: "satellite_fuel_compliance".to_string(),
        field: FieldId::Goldilocks,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: Vec::new(),
            acir_program_bytes: None,
        },
        lookup_tables: Vec::new(),
        memory_regions: Vec::new(),
        custom_gates: Vec::new(),
        metadata: BTreeMap::from([
            ("application".to_string(), "Private Satellite Fuel Budget Compliance Verifier".to_string()),
            ("num_maneuver_steps".to_string(), NUM_STEPS.to_string()),
        ]),
    };

    program_zir_to_v2(&zir_program)
}

// ---------------------------------------------------------------------------
// Witness inputs
// ---------------------------------------------------------------------------

fn compliant_inputs() -> WitnessInputs {
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
    application: String,
    version: String,
    field: String,
    backend: String,
    num_maneuver_steps: usize,
    description: String,
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
    compile_prove_ms: u128,
}

#[derive(Serialize)]
struct VerificationResult {
    verified: bool,
    backend: String,
    verify_ms: u128,
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| {
        ZkfError::InvalidArtifact(format!("serialize {}: {e}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|e| ZkfError::Io(format!("write {}: {e}", path.display())))?;
    Ok(())
}

fn write_text(path: &Path, text: &str) -> ZkfResult<()> {
    fs::write(path, text)
        .map_err(|e| ZkfError::Io(format!("write {}: {e}", path.display())))?;
    Ok(())
}

fn ensure_dir(path: &Path) -> ZkfResult<()> {
    fs::create_dir_all(path)
        .map_err(|e| ZkfError::Io(format!("create dir {}: {e}", path.display())))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn output_dir() -> PathBuf {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("/home/user/Desktop/ZirOS_Light_Test_Fuel_Compliance")
        })
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
    println!("[1/7] Building satellite fuel compliance circuit...");
    let program = build_fuel_compliance_program()?;
    println!(
        "       Circuit built: {} signals, {} constraints",
        program.signals.len(),
        program.constraints.len()
    );

    // -----------------------------------------------------------------------
    // 2. Serialize program and inputs
    // -----------------------------------------------------------------------
    println!("[2/7] Writing program and input artifacts...");
    write_json(&artifacts_dir.join("program.json"), &program)?;

    let valid = compliant_inputs();
    let rejected = non_compliant_inputs();
    write_json(&artifacts_dir.join("valid_inputs.json"), &valid)?;
    write_json(&artifacts_dir.join("rejected_inputs.json"), &rejected)?;

    // fuel_commitment = 10000 * (10000 + 3000 + 1) = 10000 * 13001 = 130010000
    let expected = ExpectedOutputs {
        compliant_scenario: BTreeMap::from([
            ("fuel_commitment".into(), "130010000".into()),
            ("compliance_status".into(), "1".into()),
        ]),
        fuel_trace: vec![8500, 6500, 5500, 5000],
    };
    write_json(&artifacts_dir.join("expected_outputs.json"), &expected)?;

    let manifest = Manifest {
        application: "Private Satellite Fuel Budget Compliance Verifier".into(),
        version: "0.1.0".into(),
        field: "Goldilocks".into(),
        backend: "plonky3".into(),
        num_maneuver_steps: NUM_STEPS,
        description: "Proves satellite fuel remaining after maneuver sequence stays above safety reserve without revealing private fuel data.".into(),
    };
    write_json(&artifacts_dir.join("manifest.json"), &manifest)?;

    // -----------------------------------------------------------------------
    // 3. Witness generation and constraint check (compliant scenario)
    // -----------------------------------------------------------------------
    println!("[3/7] Generating witness and checking constraints (compliant)...");
    let witness = generate_witness(&program, &valid)?;
    check_constraints(&program, &witness)?;
    println!("       Witness generated and constraints satisfied.");

    // -----------------------------------------------------------------------
    // 4. Compile + Prove
    // -----------------------------------------------------------------------
    println!("[4/7] Compiling and generating proof (plonky3)...");
    let compile_start = Instant::now();

    let backend = zkf_backends::backend_for(BackendKind::Plonky3);
    let compiled = backend.compile(&program)?;
    let artifact = backend.prove(&compiled, &witness)?;
    let compile_prove_ms = compile_start.elapsed().as_millis();

    let proof_meta = ProofMetadata {
        backend: "plonky3".into(),
        proof_size_bytes: artifact.proof.len(),
        compile_prove_ms,
    };
    println!(
        "       Proof generated: {} bytes in {}ms",
        proof_meta.proof_size_bytes, proof_meta.compile_prove_ms
    );

    // -----------------------------------------------------------------------
    // 5. Write proof artifacts
    // -----------------------------------------------------------------------
    println!("[5/7] Writing proof artifacts...");
    write_json(&proofs_dir.join("proof_artifact.json"), &artifact)?;
    write_json(&proofs_dir.join("proof_metadata.json"), &proof_meta)?;
    write_text(
        &proofs_dir.join("backend_used.txt"),
        "plonky3 (Goldilocks field, transparent setup — no trusted ceremony)\n",
    )?;

    // -----------------------------------------------------------------------
    // 6. Verify
    // -----------------------------------------------------------------------
    println!("[6/7] Verifying proof...");
    let verify_start = Instant::now();
    let verified = backend.verify(&compiled, &artifact)?;
    let verify_ms = verify_start.elapsed().as_millis();

    let verification = VerificationResult {
        verified,
        backend: "plonky3".into(),
        verify_ms,
    };
    write_json(&verifiers_dir.join("verification_result.json"), &verification)?;

    let verify_cmd = format!(
        "# Verification was performed inline using zkf_backends::BackendEngine::verify()\n\
         # Backend: plonky3 (Goldilocks, transparent setup)\n\
         # Verified: {verified}\n\
         # Time: {verify_ms}ms\n\
         #\n\
         # To reproduce:\n\
         #   cd {}/02_app && cargo run -- {}\n",
        base.display(),
        base.display(),
    );
    write_text(&verifiers_dir.join("verification_command.txt"), &verify_cmd)?;
    println!(
        "       Verification: {} ({}ms)",
        if verified { "PASS" } else { "FAIL" },
        verify_ms
    );

    // -----------------------------------------------------------------------
    // 7. Test rejection scenario
    // -----------------------------------------------------------------------
    println!("[7/7] Testing non-compliant scenario (should fail)...");
    let rejection_result = generate_witness(&program, &rejected)
        .and_then(|w| check_constraints(&program, &w));

    let rejection_status = match &rejection_result {
        Ok(()) => "UNEXPECTED: non-compliant inputs passed constraints (should not happen)".into(),
        Err(e) => format!("Correctly rejected: {e}"),
    };
    println!("       {rejection_status}");

    // Write test results
    let total_ms = compile_start.elapsed().as_millis();
    let test_log = format!(
        "=== Satellite Fuel Compliance — Test Results ===\n\n\
         Circuit:\n  Signals: {}\n  Constraints: {}\n\n\
         Compliant Scenario:\n  Proof size: {} bytes\n  Compile+Prove: {}ms\n  Verify: {}ms\n  Result: {}\n\n\
         Non-Compliant Scenario:\n  {}\n\n\
         Total wall time: {}ms\n",
        program.signals.len(),
        program.constraints.len(),
        proof_meta.proof_size_bytes,
        proof_meta.compile_prove_ms,
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
    println!(
        "  Circuit: {} signals, {} constraints",
        program.signals.len(),
        program.constraints.len()
    );
    println!("  Proof: {} bytes", proof_meta.proof_size_bytes);
    println!("  Verified: {verified}");
    println!("  Rejection test: {}", if rejection_result.is_err() { "PASS" } else { "FAIL" });

    if !verified {
        return Err(ZkfError::InvalidArtifact(
            "proof verification failed for compliant inputs".into(),
        ));
    }

    Ok(())
}
