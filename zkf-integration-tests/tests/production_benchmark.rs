//! Production Benchmark Suite — Phase 2
//!
//! This is the "harsher report" requested after the developer use case suite.
//! It measures what matters for production readiness:
//!
//! 1. **Proof sizes** — byte counts per backend per circuit
//! 2. **Proving times** — release-quality timing (still debug in CI, release for local)
//! 3. **Verification times** — per backend
//! 4. **Witness generation times** — separate from proving
//! 5. **Scaled circuits** — from 64 to 16,384 constraints
//! 6. **Cross-backend comparison** — same circuit, all three backends
//! 7. **GPU dispatch threshold** — where Metal acceleration kicks in
//!
//! Run:
//!   cargo test -p zkf-integration-tests --test production_benchmark --features metal-gpu -- --nocapture --test-threads=1
//!
//! Release profile (real performance numbers):
//!   cargo test -p zkf-integration-tests --test production_benchmark --features metal-gpu --release -- --nocapture --test-threads=1

use std::collections::BTreeMap;
use std::time::Instant;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessInputs, WitnessPlan, generate_witness,
};

// ============================================================================
// Circuit builders — scaled complexity
// ============================================================================

/// Chained multiply-accumulate: z_{i} = z_{i-1}^2 + 1
/// Each step is a real R1CS constraint. This is the purest scaling test.
fn chain_circuit(n: usize, field: FieldId) -> Program {
    let mut signals = vec![Signal {
        name: "z_0".into(),
        visibility: Visibility::Private,
        constant: None,
        ty: None,
    }];
    let mut constraints = Vec::new();
    let mut assignments = Vec::new();

    for i in 1..=n {
        let vis = if i == n {
            Visibility::Public
        } else {
            Visibility::Private
        };
        signals.push(Signal {
            name: format!("z_{i}"),
            visibility: vis,
            constant: None,
            ty: None,
        });

        let sq = Expr::Mul(
            Box::new(Expr::signal(format!("z_{}", i - 1))),
            Box::new(Expr::signal(format!("z_{}", i - 1))),
        );
        let rhs = Expr::Add(vec![sq, Expr::constant_i64(1)]);

        constraints.push(Constraint::Equal {
            lhs: Expr::signal(format!("z_{i}")),
            rhs: rhs.clone(),
            label: Some(format!("step_{i}")),
        });

        assignments.push(WitnessAssignment {
            target: format!("z_{i}"),
            expr: rhs,
        });
    }

    Program {
        name: format!("chain_{n}"),
        field,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Multi-input circuit: simulates realistic workloads with multiple
/// independent constraint groups (like a batch of transfers).
/// n_groups groups of 4 constraints each = 4n total constraints.
fn batch_circuit(n_groups: usize, field: FieldId) -> Program {
    let mut signals = Vec::new();
    let mut constraints = Vec::new();
    let mut assignments = Vec::new();

    for g in 0..n_groups {
        // Each group: balance, amount, diff, nullifier
        signals.push(Signal {
            name: format!("bal_{g}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        signals.push(Signal {
            name: format!("amt_{g}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        signals.push(Signal {
            name: format!("diff_{g}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        signals.push(Signal {
            name: format!("null_{g}"),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        });

        let diff_expr = Expr::Sub(
            Box::new(Expr::signal(format!("bal_{g}"))),
            Box::new(Expr::signal(format!("amt_{g}"))),
        );
        let null_expr = Expr::Mul(
            Box::new(Expr::signal(format!("amt_{g}"))),
            Box::new(Expr::signal(format!("amt_{g}"))),
        );

        // diff = bal - amt
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(format!("diff_{g}")),
            rhs: diff_expr.clone(),
            label: Some(format!("diff_{g}")),
        });
        // null = amt^2
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(format!("null_{g}")),
            rhs: null_expr.clone(),
            label: Some(format!("null_{g}")),
        });

        assignments.push(WitnessAssignment {
            target: format!("diff_{g}"),
            expr: diff_expr,
        });
        assignments.push(WitnessAssignment {
            target: format!("null_{g}"),
            expr: null_expr,
        });
    }

    Program {
        name: format!("batch_{n_groups}"),
        field,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn batch_inputs(n_groups: usize) -> WitnessInputs {
    let mut inputs = BTreeMap::new();
    for g in 0..n_groups {
        inputs.insert(format!("bal_{g}"), FieldElement::from_i64(10000 + g as i64));
        inputs.insert(format!("amt_{g}"), FieldElement::from_i64(100 + g as i64));
    }
    inputs
}

// ============================================================================
// Timing + measurement infrastructure
// ============================================================================

struct Metrics {
    witness_ms: f64,
    compile_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_size_bytes: usize,
    vk_size_bytes: usize,
    public_input_count: usize,
    constraint_count: usize,
    metadata: BTreeMap<String, String>,
}

fn measure_pipeline(
    program: &Program,
    inputs: &WitnessInputs,
    backend_kind: BackendKind,
) -> Metrics {
    let backend = backend_for(backend_kind);

    let witness_start = Instant::now();
    let witness = generate_witness(program, inputs)
        .unwrap_or_else(|e| panic!("[{backend_kind}] witness: {e}"));
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;

    let compile_start = Instant::now();
    let compiled = backend
        .compile(program)
        .unwrap_or_else(|e| panic!("[{backend_kind}] compile: {e}"));
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1_000.0;

    let prove_start = Instant::now();
    let artifact = backend
        .prove(&compiled, &witness)
        .unwrap_or_else(|e| panic!("[{backend_kind}] prove: {e}"));
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;

    let verify_start = Instant::now();
    let valid = backend
        .verify(&compiled, &artifact)
        .unwrap_or_else(|e| panic!("[{backend_kind}] verify: {e}"));
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;

    assert!(valid, "[{backend_kind}] verification failed");

    Metrics {
        witness_ms,
        compile_ms,
        prove_ms,
        verify_ms,
        proof_size_bytes: artifact.proof.len(),
        vk_size_bytes: artifact.verification_key.len(),
        public_input_count: artifact.public_inputs.len(),
        constraint_count: program.constraints.len(),
        metadata: artifact.metadata,
    }
}

fn meta(m: &BTreeMap<String, String>, key: &str) -> String {
    m.get(key).cloned().unwrap_or_else(|| "-".to_string())
}

fn print_metrics(label: &str, m: &Metrics) {
    println!("  {label}:");
    println!("    constraints:   {}", m.constraint_count);
    println!("    witness gen:   {:>10.2} ms", m.witness_ms);
    println!("    compile:       {:>10.2} ms", m.compile_ms);
    println!("    prove:         {:>10.2} ms", m.prove_ms);
    println!("    verify:        {:>10.2} ms", m.verify_ms);
    println!(
        "    total:         {:>10.2} ms",
        m.witness_ms + m.compile_ms + m.prove_ms + m.verify_ms
    );
    println!("    proof size:    {} bytes", m.proof_size_bytes);
    println!("    vk size:       {} bytes", m.vk_size_bytes);
    println!("    public inputs: {}", m.public_input_count);
    println!(
        "    msm_accel:     {}",
        meta(&m.metadata, "msm_accelerator")
    );
    println!(
        "    gpu_ratio:     {}",
        meta(&m.metadata, "metal_gpu_busy_ratio")
    );
}

// ============================================================================
// 1. Cross-backend proof size comparison (same circuit, all backends)
// ============================================================================

#[test]
fn cross_backend_proof_sizes() {
    let sep = "=".repeat(70);
    println!();
    println!("  {sep}");
    println!("  CROSS-BACKEND PROOF SIZE COMPARISON");
    println!("  {sep}");

    let sizes = [64, 256, 1024];

    for &n in &sizes {
        println!();
        println!("  --- {n}-constraint chain circuit ---");

        // Groth16 (BN254)
        let groth16 = {
            let program = chain_circuit(n, FieldId::Bn254);
            let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
            measure_pipeline(&program, &inputs, BackendKind::ArkworksGroth16)
        };
        print_metrics("Groth16 (BN254)", &groth16);

        // Halo2 (PastaFp)
        let halo2 = {
            let program = chain_circuit(n, FieldId::PastaFp);
            let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
            measure_pipeline(&program, &inputs, BackendKind::Halo2)
        };
        print_metrics("Halo2 (PastaFp)", &halo2);

        // Plonky3 (Goldilocks)
        let plonky3 = {
            let program = chain_circuit(n, FieldId::Goldilocks);
            let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
            measure_pipeline(&program, &inputs, BackendKind::Plonky3)
        };
        print_metrics("Plonky3 (Goldilocks)", &plonky3);

        println!();
        println!(
            "  Proof size ratio (vs Groth16): Halo2={:.1}x Plonky3={:.1}x",
            halo2.proof_size_bytes as f64 / groth16.proof_size_bytes.max(1) as f64,
            plonky3.proof_size_bytes as f64 / groth16.proof_size_bytes.max(1) as f64,
        );
    }

    println!();
    println!("  {sep}");
}

// ============================================================================
// 2. Groth16 scaling — where GPU actually matters
// ============================================================================

#[test]
fn groth16_scaling_with_gpu_dispatch() {
    let sep = "=".repeat(70);
    println!();
    println!("  {sep}");
    println!("  GROTH16 SCALING — GPU DISPATCH ANALYSIS");
    let metal_runtime = zkf_backends::metal_runtime_report();
    if metal_runtime.metal_compiled && metal_runtime.metal_available {
        println!("  Metal GPU: ENABLED");
    } else {
        println!("  Metal GPU: DISABLED (CPU baseline)");
    }
    println!("  {sep}");

    // Report Metal runtime
    {
        let report = zkf_backends::metal_runtime_report();
        println!();
        println!(
            "  Runtime: metal_compiled={} available={} device={}",
            report.metal_compiled,
            report.metal_available,
            report.metal_device.as_deref().unwrap_or("none"),
        );
        println!(
            "  Profile: {} | Prewarmed: {} pipelines",
            report.threshold_profile.as_deref().unwrap_or("none"),
            report.prewarmed_pipelines,
        );
    }

    // Warmup
    {
        let program = chain_circuit(32, FieldId::Bn254);
        let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
        let _ = measure_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
    }

    let sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192];
    let mut results = Vec::new();

    for &n in &sizes {
        let program = chain_circuit(n, FieldId::Bn254);
        let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
        let m = measure_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);

        println!();
        print_metrics(&format!("{n} constraints"), &m);
        results.push((n, m));
    }

    // Summary table
    println!();
    println!("  {sep}");
    println!("  SCALING SUMMARY TABLE");
    println!("  {sep}");
    println!(
        "  {:>8} | {:>10} | {:>10} | {:>10} | {:>8} | {:>12}",
        "N", "prove_ms", "verify_ms", "total_ms", "proof_B", "GPU"
    );
    println!("  {}", "-".repeat(68));

    for (n, m) in &results {
        let total = m.witness_ms + m.compile_ms + m.prove_ms + m.verify_ms;
        let gpu = meta(&m.metadata, "msm_accelerator");
        let gpu_short = if gpu.contains("metal") {
            "Metal"
        } else {
            "CPU"
        };
        println!(
            "  {:>8} | {:>10.2} | {:>10.2} | {:>10.2} | {:>8} | {:>12}",
            n, m.prove_ms, m.verify_ms, total, m.proof_size_bytes, gpu_short
        );
    }

    // Compute speedup between sizes
    if results.len() >= 2 {
        println!();
        println!("  Scaling ratios (prove time):");
        for i in 1..results.len() {
            let (n_prev, ref m_prev) = results[i - 1];
            let (n_cur, ref m_cur) = results[i];
            let ratio = m_cur.prove_ms / m_prev.prove_ms.max(0.001);
            println!("    {n_prev} → {n_cur}: {ratio:.2}x prove time");
        }
    }

    println!();
    println!("  {sep}");
}

// ============================================================================
// 3. Batch circuit — realistic multi-input workload
// ============================================================================

#[test]
fn batch_workload_scaling() {
    let sep = "=".repeat(70);
    println!();
    println!("  {sep}");
    println!("  BATCH WORKLOAD SCALING (multi-input circuits)");
    println!("  {sep}");

    // Each group = 2 constraints (diff + nullifier) + 4 signals
    let group_sizes = [32, 64, 128, 256, 512, 1024];

    println!();
    println!(
        "  {:>8} | {:>8} | {:>10} | {:>10} | {:>10} | {:>8}",
        "groups", "constr", "witness_ms", "prove_ms", "verify_ms", "proof_B"
    );
    println!("  {}", "-".repeat(68));

    for &g in &group_sizes {
        let program = batch_circuit(g, FieldId::Bn254);
        let inputs = batch_inputs(g);
        let m = measure_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);

        println!(
            "  {:>8} | {:>8} | {:>10.2} | {:>10.2} | {:>10.2} | {:>8}",
            g, m.constraint_count, m.witness_ms, m.prove_ms, m.verify_ms, m.proof_size_bytes
        );
    }

    println!();
    println!("  {sep}");
}

// ============================================================================
// 4. Plonky3 scaling — STARK proof size growth
// ============================================================================

#[test]
fn plonky3_proof_size_scaling() {
    let sep = "=".repeat(70);
    println!();
    println!("  {sep}");
    println!("  PLONKY3 (STARK) PROOF SIZE SCALING");
    println!("  {sep}");

    let sizes = [64, 128, 256, 512, 1024];

    println!();
    println!(
        "  {:>8} | {:>10} | {:>10} | {:>10} | {:>8}",
        "N", "prove_ms", "verify_ms", "total_ms", "proof_B"
    );
    println!("  {}", "-".repeat(56));

    for &n in &sizes {
        let program = chain_circuit(n, FieldId::Goldilocks);
        let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
        let m = measure_pipeline(&program, &inputs, BackendKind::Plonky3);

        let total = m.witness_ms + m.compile_ms + m.prove_ms + m.verify_ms;
        println!(
            "  {:>8} | {:>10.2} | {:>10.2} | {:>10.2} | {:>8}",
            n, m.prove_ms, m.verify_ms, total, m.proof_size_bytes
        );
    }

    println!();
    println!("  {sep}");
}

// ============================================================================
// 5. Halo2 scaling — SNARK with structured reference string
// ============================================================================

#[test]
fn halo2_proof_scaling() {
    let sep = "=".repeat(70);
    println!();
    println!("  {sep}");
    println!("  HALO2 PROOF SCALING (IPA commitment)");
    println!("  {sep}");

    let sizes = [64, 128, 256, 512];

    println!();
    println!(
        "  {:>8} | {:>10} | {:>10} | {:>10} | {:>8}",
        "N", "prove_ms", "verify_ms", "total_ms", "proof_B"
    );
    println!("  {}", "-".repeat(56));

    for &n in &sizes {
        let program = chain_circuit(n, FieldId::PastaFp);
        let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
        let m = measure_pipeline(&program, &inputs, BackendKind::Halo2);

        let total = m.witness_ms + m.compile_ms + m.prove_ms + m.verify_ms;
        println!(
            "  {:>8} | {:>10.2} | {:>10.2} | {:>10.2} | {:>8}",
            n, m.prove_ms, m.verify_ms, total, m.proof_size_bytes
        );
    }

    println!();
    println!("  {sep}");
}

// ============================================================================
// 6. Backend head-to-head on developer use case circuits
// ============================================================================

fn defi_circuit_for_backend(backend: BackendKind) -> (Program, WitnessInputs) {
    let (field, bits) = match backend {
        BackendKind::ArkworksGroth16 => (FieldId::Bn254, 64),
        BackendKind::Halo2 => (FieldId::PastaFp, 12),
        BackendKind::Plonky3 => (FieldId::Goldilocks, 32),
        _ => (FieldId::Bn254, 64),
    };

    let diff_expr = Expr::Sub(
        Box::new(Expr::signal("balance")),
        Box::new(Expr::signal("threshold")),
    );

    let program = Program {
        name: "defi_bench".into(),
        field,
        signals: vec![
            Signal {
                name: "balance".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "threshold".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "diff".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "sufficient".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("diff"),
                rhs: diff_expr.clone(),
                label: Some("diff_eq".into()),
            },
            Constraint::Range {
                signal: "diff".into(),
                bits,
                label: Some("range".into()),
            },
            Constraint::Boolean {
                signal: "sufficient".into(),
                label: Some("bool".into()),
            },
            Constraint::Equal {
                lhs: Expr::signal("sufficient"),
                rhs: Expr::constant_i64(1),
                label: Some("assert_true".into()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "diff".into(),
                expr: diff_expr,
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    };

    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(1000)),
        ("threshold".into(), FieldElement::from_i64(500)),
        ("sufficient".into(), FieldElement::from_i64(1)),
    ]);

    (program, inputs)
}

#[test]
fn backend_head_to_head_defi() {
    let sep = "=".repeat(70);
    println!();
    println!("  {sep}");
    println!("  BACKEND HEAD-TO-HEAD: DeFi Balance Check");
    println!("  {sep}");

    let backends = [
        BackendKind::ArkworksGroth16,
        BackendKind::Halo2,
        BackendKind::Plonky3,
    ];

    println!();
    println!(
        "  {:>16} | {:>10} | {:>10} | {:>10} | {:>8} | {:>6}",
        "Backend", "prove_ms", "verify_ms", "total_ms", "proof_B", "pubIn"
    );
    println!("  {}", "-".repeat(70));

    for &bk in &backends {
        let (program, inputs) = defi_circuit_for_backend(bk);
        let m = measure_pipeline(&program, &inputs, bk);
        let total = m.witness_ms + m.compile_ms + m.prove_ms + m.verify_ms;

        println!(
            "  {:>16} | {:>10.2} | {:>10.2} | {:>10.2} | {:>8} | {:>6}",
            format!("{bk}"),
            m.prove_ms,
            m.verify_ms,
            total,
            m.proof_size_bytes,
            m.public_input_count
        );
    }

    println!();
    println!("  {sep}");
}

// ============================================================================
// 7. Constant-size proof verification (Groth16 property)
// ============================================================================

#[test]
fn groth16_constant_proof_size() {
    // Groth16's defining property: proof size is constant regardless of circuit size.
    let sizes = [64, 256, 1024, 4096];
    let mut proof_sizes = Vec::new();

    for &n in &sizes {
        let program = chain_circuit(n, FieldId::Bn254);
        let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
        let m = measure_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
        proof_sizes.push((n, m.proof_size_bytes));
    }

    println!();
    println!("  Groth16 proof sizes across circuit sizes:");
    for (n, size) in &proof_sizes {
        println!("    {n:>5} constraints → {size} bytes");
    }

    // All Groth16 proofs should be the same size (192 bytes for BN254)
    let first_size = proof_sizes[0].1;
    for (n, size) in &proof_sizes {
        assert_eq!(
            *size, first_size,
            "Groth16 proof size should be constant, but {n} constraints gave {size} != {first_size}"
        );
    }

    println!("  Verified: ALL sizes produce {first_size}-byte proofs (constant)");
}

// ============================================================================
// Summary
// ============================================================================
//
// Tests: 7
//   cross_backend_proof_sizes         — proof bytes: Groth16 vs Halo2 vs Plonky3
//   groth16_scaling_with_gpu_dispatch — 64→8192 constraints, GPU threshold detection
//   batch_workload_scaling            — multi-input circuits, realistic workloads
//   plonky3_proof_size_scaling        — STARK proof growth vs circuit size
//   halo2_proof_scaling               — IPA proof growth vs circuit size
//   backend_head_to_head_defi         — same DeFi circuit, all backends compared
//   groth16_constant_proof_size       — verify O(1) proof size property
