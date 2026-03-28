//! Metal GPU acceleration benchmark.
//!
//! Builds circuits of increasing size and reports proving timings with
//! Metal GPU telemetry. On M4 Max (AGGRESSIVE threshold: MSM >= 1024 points),
//! circuits above ~512 R1CS constraints produce MSM operations large enough
//! for GPU dispatch.
//!
//! Run WITH GPU feature:
//!   cargo test -p zkf-integration-tests --test metal_gpu_benchmark --features metal-gpu -- --nocapture
//!
//! Run WITHOUT GPU feature (CPU baseline):
//!   cargo test -p zkf-integration-tests --test metal_gpu_benchmark -- --nocapture

use std::collections::BTreeMap;
use std::time::Instant;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessPlan, acceleration::accelerator_registry, generate_witness,
};

/// Build a circuit with `n` chained multiply-accumulate constraints.
/// Each: z_{i} = z_{i-1} * z_{i-1} + 1  (quadratic — each is a real R1CS row)
fn large_mul_circuit(n: usize, field: FieldId) -> Program {
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
            label: Some(format!("mac_{i}")),
        });

        assignments.push(WitnessAssignment {
            target: format!("z_{i}"),
            expr: rhs,
        });
    }

    Program {
        name: format!("gpu_bench_{n}"),
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

struct BenchResult {
    compile_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    metadata: BTreeMap<String, String>,
}

fn run_with_large_stack<T>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> T
where
    T: Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .expect("spawn large-stack benchmark worker")
        .join()
        .expect("large-stack benchmark worker panicked")
}

fn timed_pipeline(n: usize) -> BenchResult {
    let program = large_mul_circuit(n, FieldId::Bn254);
    let backend = backend_for(BackendKind::ArkworksGroth16);

    let compile_start = Instant::now();
    let compiled = backend.compile(&program).expect("compile failed");
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1_000.0;

    let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
    let witness = generate_witness(&program, &inputs).expect("witness gen failed");

    let prove_start = Instant::now();
    let artifact = backend.prove(&compiled, &witness).expect("prove failed");
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;

    let verify_start = Instant::now();
    let ok = backend.verify(&compiled, &artifact).expect("verify failed");
    let verify_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
    assert!(ok, "verification must pass");

    BenchResult {
        compile_ms,
        prove_ms,
        verify_ms,
        metadata: artifact.metadata,
    }
}

fn meta(m: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    m.get(key).cloned().unwrap_or_else(|| default.to_string())
}

fn print_result(label: &str, n: usize, r: &BenchResult) {
    let accelerator = meta(&r.metadata, "msm_accelerator", "unknown");
    let gpu_ratio = meta(&r.metadata, "metal_gpu_busy_ratio", "n/a");
    let inflight = meta(&r.metadata, "metal_inflight_jobs", "0");
    let counter = meta(&r.metadata, "metal_counter_source", "n/a");

    println!();
    println!("  {label} ({n} constraints):");
    println!("    compile:     {:>8.1} ms", r.compile_ms);
    println!("    prove:       {:>8.1} ms", r.prove_ms);
    println!("    verify:      {:>8.1} ms", r.verify_ms);
    println!(
        "    total:       {:>8.1} ms",
        r.compile_ms + r.prove_ms + r.verify_ms
    );
    println!("    msm_accel:   {accelerator}");
    println!("    gpu_ratio:   {gpu_ratio}");
    println!("    inflight:    {inflight}");
    println!("    counter:     {counter}");
}

fn metal_runtime_enabled() -> bool {
    let report = zkf_backends::metal_runtime_report();
    report.metal_compiled && report.metal_available
}

#[test]
fn gpu_benchmark_scaling() {
    run_with_large_stack("metal-gpu-benchmark-scaling", || {
        let sep = "=".repeat(70);
        println!();
        println!("  {sep}");
        println!("  Metal GPU Acceleration Benchmark — Groth16 BN254");
        if metal_runtime_enabled() {
            println!("  Feature: metal-gpu ENABLED");
        } else {
            println!("  Feature: metal-gpu DISABLED (CPU-only)");
        }
        println!("  {sep}");

        // Warmup to trigger Metal accelerator registration
        let _ = timed_pipeline(16);

        // Report Metal runtime status
        {
            let report = zkf_backends::metal_runtime_report();
            println!();
            println!("  Metal runtime:");
            println!("    compiled:    {}", report.metal_compiled);
            println!("    available:   {}", report.metal_available);
            println!(
                "    device:      {}",
                report.metal_device.as_deref().unwrap_or("none")
            );
            println!(
                "    profile:     {}",
                report.threshold_profile.as_deref().unwrap_or("none")
            );
            println!("    prewarmed:   {} pipelines", report.prewarmed_pipelines);
        }

        // Report MSM accelerator
        {
            let reg = accelerator_registry().lock().expect("lock");
            let msm = reg.best_msm();
            println!(
                "    msm_accel:   {} (batch >= {})",
                msm.name(),
                msm.min_batch_size()
            );
        }

        let sizes = [256, 512, 1024, 2048, 4096, 8192];

        for &n in &sizes {
            let r = timed_pipeline(n);
            print_result(&format!("{n}-constraint"), n, &r);
        }

        println!();
        println!("  {sep}");
    });
}

#[test]
fn gpu_dispatch_verification() {
    // Verify that Metal MSM accelerator is registered when feature is enabled
    let _ = backend_for(BackendKind::ArkworksGroth16); // triggers init

    let (msm_name, msm_available, msm_min_batch_size) = {
        let reg = accelerator_registry().lock().expect("lock");
        let msm = reg.best_msm();
        (
            msm.name().to_string(),
            msm.is_available(),
            msm.min_batch_size(),
        )
    };

    if metal_runtime_enabled() {
        assert!(
            msm_name.starts_with("metal-"),
            "With metal-gpu feature, MSM accelerator should be metal-*, got: {}",
            msm_name
        );
        assert!(msm_available);
        assert!(msm_min_batch_size > 0);
    }
}

#[test]
fn proving_produces_valid_proofs_at_all_sizes() {
    run_with_large_stack("metal-gpu-benchmark-proof-sizes", || {
        let sizes = [64, 256, 1024, 4096];
        for &n in &sizes {
            let r = timed_pipeline(n);
            // Prove succeeded and verification passed (asserted inside timed_pipeline)
            assert!(
                r.prove_ms > 0.0,
                "prove should take nonzero time for {n} constraints"
            );
        }
    });
}
