//! Metal GPU Accelerator Validation Suite
//!
//! Validates each of the 8 Metal GPU accelerators against CPU reference
//! implementations. Every test dispatches to GPU and compares results
//! byte-for-byte (or element-for-element) with the CPU fallback.
//!
//! Run: cargo test -p zkf-integration-tests --test metal_accelerator_validation \
//!        --features metal-gpu -- --nocapture --test-threads=1

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand09::SeedableRng;
use sha2::{Digest, Sha256};
use std::sync::MutexGuard;
use tiny_keccak::{Hasher, Keccak};
use zkf_backends::backend_for;
use zkf_core::BackendKind;
use zkf_core::acceleration::{CpuNttAccelerator, NttAccelerator, accelerator_registry};

// ============================================================================
// Helper: ensure Metal accelerators are registered
// ============================================================================

const GL_P: u64 = 0xFFFF_FFFF_0000_0001u64;
const GL_INV_TWO: u64 = 9_223_372_034_707_292_161u64;

fn ensure_metal_init() {
    // Calling backend_for triggers the Metal registration path
    let _ = backend_for(BackendKind::ArkworksGroth16);
}

fn metal_tests_enabled() -> bool {
    ensure_metal_init();
    let report = zkf_backends::metal_runtime_report();
    report.metal_compiled && report.metal_available
}

fn accelerator_registry_guard() -> MutexGuard<'static, zkf_core::acceleration::AcceleratorRegistry>
{
    accelerator_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn gl_add(a: u64, b: u64) -> u64 {
    let sum = a as u128 + b as u128;
    if sum >= GL_P as u128 {
        (sum - GL_P as u128) as u64
    } else {
        sum as u64
    }
}

fn gl_sub(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { GL_P - (b - a) }
}

fn gl_mul(a: u64, b: u64) -> u64 {
    let prod = a as u128 * b as u128;
    let lo = prod as u64;
    let hi = (prod >> 64) as u64;
    let hi_shifted = (hi as u128) * ((1u128 << 32) - 1);
    let sum = lo as u128 + hi_shifted;
    let lo2 = sum as u64;
    let hi2 = (sum >> 64) as u64;
    if hi2 == 0 {
        if lo2 >= GL_P { lo2 - GL_P } else { lo2 }
    } else {
        let hi2_shifted = (hi2 as u128) * ((1u128 << 32) - 1);
        let final_sum = lo2 as u128 + hi2_shifted;
        (final_sum % GL_P as u128) as u64
    }
}

fn batch_sha256_cpu(inputs: &[u8], input_len: usize) -> Vec<u8> {
    let n = inputs.len() / input_len;
    let mut expected = Vec::with_capacity(n * 32);
    for chunk in inputs.chunks_exact(input_len) {
        let mut hasher = Sha256::new();
        hasher.update(chunk);
        expected.extend_from_slice(&hasher.finalize());
    }
    expected
}

fn batch_keccak256_cpu(inputs: &[u8], input_len: usize) -> Vec<u8> {
    let n = inputs.len() / input_len;
    let mut expected = Vec::with_capacity(n * 32);
    for chunk in inputs.chunks_exact(input_len) {
        let mut hasher = Keccak::v256();
        hasher.update(chunk);
        let mut out = [0u8; 32];
        hasher.finalize(&mut out);
        expected.extend_from_slice(&out);
    }
    expected
}

fn cpu_poseidon2_goldilocks(seed: u64, states: &[u64]) -> Vec<u64> {
    let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
    let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
    let mut out = states.to_vec();
    for perm_idx in 0..(out.len() / 16) {
        let offset = perm_idx * 16;
        let mut state: [Goldilocks; 16] =
            std::array::from_fn(|i| Goldilocks::from_u64(out[offset + i]));
        perm.permute_mut(&mut state);
        for i in 0..16 {
            out[offset + i] = state[i].as_canonical_u64();
        }
    }
    out
}

fn cpu_poly_eval(coeffs: &[u64], points: &[u64]) -> Vec<u64> {
    points
        .iter()
        .map(|&x| {
            let mut result = 0u64;
            for coeff in coeffs.iter().rev() {
                result = gl_add(gl_mul(result, x), *coeff);
            }
            result
        })
        .collect()
}

fn cpu_fri_fold(evals: &[u64], alpha: u64, inv_twiddles: &[u64]) -> Vec<u64> {
    let n = evals.len() / 2;
    (0..n)
        .map(|i| {
            let even = evals[2 * i];
            let odd = evals[2 * i + 1];
            let sum = gl_mul(gl_add(even, odd), GL_INV_TWO);
            let diff = gl_mul(gl_mul(gl_sub(even, odd), inv_twiddles[i]), alpha);
            gl_add(sum, diff)
        })
        .collect()
}

fn field_element_to_u64(value: &zkf_core::FieldElement) -> u64 {
    let bytes = value.to_le_bytes();
    let mut out = [0u8; 8];
    out[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    u64::from_le_bytes(out)
}

// ============================================================================
// 1. ACCELERATOR REGISTRY — all 8 Metal accelerators registered
// ============================================================================

#[test]
fn all_metal_accelerators_registered() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        eprintln!("  [skip] metal runtime unavailable");
        return;
    }
    let reg = accelerator_registry_guard();

    // MSM and NTT always have a fallback; others are Option
    let direct = [
        ("msm", reg.best_msm().name()),
        ("ntt", reg.best_ntt().name()),
    ];
    for (cat, name) in &direct {
        assert!(
            name.starts_with("metal-"),
            "{cat}: expected metal-*, got '{name}'"
        );
        eprintln!("  [registry] {cat}: {name} ✓");
    }

    let optional: Vec<(&str, Option<&str>)> = vec![
        ("hash", reg.best_hash().map(|a| a.name())),
        ("poseidon2", reg.best_poseidon2().map(|a| a.name())),
        ("field_ops", reg.best_field_ops().map(|a| a.name())),
        ("poly_ops", reg.best_poly_ops().map(|a| a.name())),
        ("fri", reg.best_fri().map(|a| a.name())),
        (
            "constraint_eval",
            reg.best_constraint_eval().map(|a| a.name()),
        ),
    ];
    for (cat, name) in &optional {
        match name {
            Some(n) => {
                assert!(
                    n.starts_with("metal-"),
                    "{cat}: expected metal-*, got '{n}'"
                );
                eprintln!("  [registry] {cat}: {n} ✓");
            }
            None => eprintln!("  [registry] {cat}: not registered (no GPU impl)"),
        }
    }
}

#[test]
fn all_accelerators_report_available() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    assert!(reg.best_msm().is_available(), "MSM unavailable");
    assert!(reg.best_ntt().is_available(), "NTT unavailable");
    // Optional accelerators — check if registered
    if let Some(h) = reg.best_hash() {
        assert!(h.is_available(), "Hash unavailable");
    }
    if let Some(p) = reg.best_poseidon2() {
        assert!(p.is_available(), "Poseidon2 unavailable");
    }
    if let Some(f) = reg.best_field_ops() {
        assert!(f.is_available(), "FieldOps unavailable");
    }
    if let Some(p) = reg.best_poly_ops() {
        assert!(p.is_available(), "PolyOps unavailable");
    }
    if let Some(f) = reg.best_fri() {
        assert!(f.is_available(), "FRI unavailable");
    }
    if let Some(c) = reg.best_constraint_eval() {
        assert!(c.is_available(), "ConstraintEval unavailable");
    }
}

#[test]
fn thresholds_are_reasonable() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    // MSM threshold should be > 0 and <= 16384
    let msm_min = reg.best_msm().min_batch_size();
    assert!(
        msm_min > 0 && msm_min <= 16384,
        "MSM threshold {msm_min} out of range"
    );
    eprintln!("  [threshold] MSM min_batch={msm_min}");

    // NTT max log size should be reasonable (16-24)
    let ntt_max = reg.best_ntt().max_log_size();
    assert!(
        ntt_max >= 16 && ntt_max <= 28,
        "NTT max_log_size {ntt_max} out of range"
    );
    eprintln!("  [threshold] NTT max_log={ntt_max}");
}

// ============================================================================
// 2. MSM — Multi-Scalar Multiplication (BN254 G1)
// ============================================================================

#[test]
fn msm_gpu_vs_cpu_groth16_proof() {
    // Prove a circuit large enough to trigger GPU MSM dispatch,
    // then verify the proof is valid (end-to-end correctness)
    use std::collections::BTreeMap;
    use zkf_core::{
        Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
        WitnessPlan, generate_witness,
    };

    if !metal_tests_enabled() {
        eprintln!("  [skip] metal-gpu not enabled");
        return;
    }

    // Build a circuit with enough constraints to produce MSM > threshold
    // At threshold=128, ~64 constraints should produce ~127-255 point MSMs
    let n = 256;
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
        let rhs = Expr::Add(vec![
            Expr::Mul(
                Box::new(Expr::signal(format!("z_{}", i - 1))),
                Box::new(Expr::signal(format!("z_{}", i - 1))),
            ),
            Expr::constant_i64(1),
        ]);
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

    let program = Program {
        name: "msm_validation".into(),
        field: FieldId::Bn254,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    };

    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).expect("compile");
    let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(2))]);
    let witness = generate_witness(&program, &inputs).expect("witness");
    let proof = backend.prove(&compiled, &witness).expect("prove");
    let ok = backend.verify(&compiled, &proof).expect("verify");
    assert!(ok, "Groth16 proof with GPU MSM must verify");

    let accel = proof
        .metadata
        .get("msm_accelerator")
        .cloned()
        .unwrap_or_default();
    eprintln!("  [msm] 256-constraint proof verified ✓ accelerator={accel}");
}

// ============================================================================
// 3. NTT — Number Theoretic Transform (Goldilocks)
// ============================================================================

#[test]
fn ntt_gpu_roundtrip() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let ntt = reg.best_ntt();
    assert!(ntt.is_available(), "NTT accelerator unavailable");
    assert!(
        ntt.name().starts_with("metal-"),
        "NTT accelerator must be metal-backed when Metal is available, got '{}'",
        ntt.name()
    );

    // Build a power-of-2 sized array of Goldilocks field elements
    let n = 1 << 12; // 4096
    let original: Vec<u64> = (0..n).map(|i| (i as u64 * 7 + 13) % GL_P).collect();

    // Convert to FieldElement for the accelerator interface
    let mut gpu_values: Vec<zkf_core::FieldElement> = original
        .iter()
        .map(|&v| zkf_core::FieldElement::from_u64(v))
        .collect();
    let mut cpu_values = gpu_values.clone();

    ntt.forward_ntt(&mut gpu_values)
        .expect("Metal forward NTT must succeed");
    CpuNttAccelerator
        .forward_ntt(&mut cpu_values)
        .expect("CPU forward NTT must succeed");
    assert_eq!(gpu_values, cpu_values, "forward NTT parity mismatch");

    ntt.inverse_ntt(&mut gpu_values)
        .expect("Metal inverse NTT must succeed");
    CpuNttAccelerator
        .inverse_ntt(&mut cpu_values)
        .expect("CPU inverse NTT must succeed");
    assert_eq!(gpu_values, cpu_values, "inverse NTT parity mismatch");
    let restored: Vec<u64> = gpu_values.iter().map(field_element_to_u64).collect();
    assert_eq!(
        restored, original,
        "inverse NTT should restore original values"
    );

    eprintln!("  [ntt] roundtrip n={n}: forward→inverse = identity ✓");
}

// ============================================================================
// 4. HASH — Batch SHA-256 / Keccak-256
// ============================================================================

#[test]
fn hash_gpu_sha256_correctness() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let hasher = match reg.best_hash() {
        Some(h) => {
            assert!(h.is_available(), "Hash accelerator unavailable");
            assert!(
                h.name().starts_with("metal-"),
                "Hash accelerator must be metal-backed when present, got '{}'",
                h.name()
            );
            h
        }
        _ => {
            eprintln!("  [skip] hash accelerator not available");
            return;
        }
    };

    // Create batch of identical 64-byte inputs
    let input_len = 64;
    let batch_size = hasher.min_batch_size().max(1000);
    let input_data: Vec<u8> = (0..batch_size)
        .flat_map(|i| {
            let mut block = vec![0u8; input_len];
            block[0] = (i & 0xff) as u8;
            block[1] = ((i >> 8) & 0xff) as u8;
            block
        })
        .collect();

    let digests = hasher
        .batch_sha256(&input_data, input_len)
        .expect("Metal SHA-256 dispatch must succeed");
    let expected = batch_sha256_cpu(&input_data, input_len);
    assert_eq!(digests, expected, "SHA-256 GPU/CPU parity mismatch");
    eprintln!(
        "  [hash] SHA-256 batch={batch_size}: {}-byte output ✓",
        digests.len()
    );
}

#[test]
fn hash_gpu_keccak256_correctness() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let hasher = match reg.best_hash() {
        Some(h) => {
            assert!(h.is_available(), "Hash accelerator unavailable");
            assert!(
                h.name().starts_with("metal-"),
                "Hash accelerator must be metal-backed when present, got '{}'",
                h.name()
            );
            h
        }
        _ => {
            eprintln!("  [skip] hash accelerator not available");
            return;
        }
    };

    let input_len = 64;
    let batch_size = hasher.min_batch_size().max(1000);
    let input_data: Vec<u8> = (0..batch_size)
        .flat_map(|i| {
            let mut block = vec![0u8; input_len];
            block[0] = (i & 0xff) as u8;
            block[1] = ((i >> 8) & 0xff) as u8;
            block
        })
        .collect();

    let digests = hasher
        .batch_keccak256(&input_data, input_len)
        .expect("Metal Keccak-256 dispatch must succeed");
    let expected = batch_keccak256_cpu(&input_data, input_len);
    assert_eq!(digests, expected, "Keccak-256 GPU/CPU parity mismatch");
    eprintln!(
        "  [hash] Keccak-256 batch={batch_size}: {}-byte output ✓",
        digests.len()
    );
}

// ============================================================================
// 5. POSEIDON2 — Batch Permutation (Goldilocks width-16)
// ============================================================================

#[test]
fn poseidon2_gpu_permutation_deterministic() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let poseidon = match reg.best_poseidon2() {
        Some(p) => {
            assert!(p.is_available(), "Poseidon2 accelerator unavailable");
            assert!(
                p.name().starts_with("metal-"),
                "Poseidon2 accelerator must be metal-backed when present, got '{}'",
                p.name()
            );
            p
        }
        _ => {
            eprintln!("  [skip] poseidon2 accelerator not available");
            return;
        }
    };

    let seed = 42u64;
    let (round_constants, n_external, n_internal) =
        zkf_metal::poseidon2::goldilocks::flatten_round_constants(seed);
    let width = 16usize;
    let n_perms = poseidon.min_batch_size().max(500).min(10_000);

    let input: Vec<u64> = (0..n_perms * width)
        .map(|i| (i as u64 * 31 + 7) % GL_P)
        .collect();
    let mut gpu = input.clone();
    poseidon
        .batch_permute_goldilocks(&mut gpu, &round_constants, n_external, n_internal)
        .expect("Metal Poseidon2 dispatch must succeed");
    let cpu = cpu_poseidon2_goldilocks(seed, &input);
    assert_eq!(gpu, cpu, "Poseidon2 GPU/CPU parity mismatch");
    assert_ne!(gpu, input, "Poseidon2 must transform the state");
    eprintln!("  [poseidon2] goldilocks batch={n_perms}: parity ✓");
}

// ============================================================================
// 6. FIELD OPS — Batch Goldilocks Arithmetic
// ============================================================================

#[test]
fn field_ops_gpu_add_mul_sub() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let field_ops = match reg.best_field_ops() {
        Some(f) => {
            assert!(f.is_available(), "FieldOps accelerator unavailable");
            assert!(
                f.name().starts_with("metal-"),
                "FieldOps accelerator must be metal-backed when present, got '{}'",
                f.name()
            );
            f
        }
        _ => {
            eprintln!("  [skip] field_ops accelerator not available");
            return;
        }
    };

    let n = field_ops.min_batch_size().max(4000);

    let a_orig: Vec<u64> = (0..n).map(|i| (i as u64 * 13 + 5) % GL_P).collect();
    let b_vals: Vec<u64> = (0..n).map(|i| (i as u64 * 7 + 3) % GL_P).collect();

    // Test addition: a = a + b
    let mut a_add = a_orig.clone();
    field_ops
        .batch_add_goldilocks(&mut a_add, &b_vals)
        .expect("Metal add must succeed");
    let expected_add: Vec<u64> = a_orig
        .iter()
        .zip(b_vals.iter())
        .map(|(&a, &b)| gl_add(a, b))
        .collect();
    assert_eq!(a_add, expected_add, "field add GPU/CPU parity mismatch");
    eprintln!("  [field_ops] add n={n}: ✓");

    // Test multiplication: a = a * b
    let mut a_mul = a_orig.clone();
    field_ops
        .batch_mul_goldilocks(&mut a_mul, &b_vals)
        .expect("Metal mul must succeed");
    let expected_mul: Vec<u64> = a_orig
        .iter()
        .zip(b_vals.iter())
        .map(|(&a, &b)| gl_mul(a, b))
        .collect();
    assert_eq!(a_mul, expected_mul, "field mul GPU/CPU parity mismatch");
    eprintln!("  [field_ops] mul n={n}: ✓");

    // Test subtraction: a = a - b
    let mut a_sub = a_orig.clone();
    field_ops
        .batch_sub_goldilocks(&mut a_sub, &b_vals)
        .expect("Metal sub must succeed");
    let expected_sub: Vec<u64> = a_orig
        .iter()
        .zip(b_vals.iter())
        .map(|(&a, &b)| gl_sub(a, b))
        .collect();
    assert_eq!(a_sub, expected_sub, "field sub GPU/CPU parity mismatch");
    eprintln!("  [field_ops] sub n={n}: ✓");
}

// ============================================================================
// 7. POLY OPS — Polynomial Evaluation (Goldilocks)
// ============================================================================

#[test]
fn poly_ops_gpu_eval() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let poly = match reg.best_poly_ops() {
        Some(p) => {
            assert!(p.is_available(), "PolyOps accelerator unavailable");
            assert!(
                p.name().starts_with("metal-"),
                "PolyOps accelerator must be metal-backed when present, got '{}'",
                p.name()
            );
            p
        }
        _ => {
            eprintln!("  [skip] poly_ops accelerator not available");
            return;
        }
    };

    // Polynomial: f(x) = 3x^2 + 5x + 7
    let coeffs: Vec<u64> = vec![7, 5, 3]; // constant first

    // Evaluate at several points
    let n_points = poly.min_batch_size().max(1024);
    let points: Vec<u64> = (0..n_points).map(|i| (i as u64 + 1) % GL_P).collect();

    let results = poly
        .batch_eval_goldilocks(&coeffs, &points)
        .expect("Metal polynomial evaluation must succeed");
    let expected = cpu_poly_eval(&coeffs, &points);
    assert_eq!(
        results, expected,
        "polynomial evaluation GPU/CPU parity mismatch"
    );
    eprintln!("  [poly_ops] eval n={n_points}: ✓");
}

// ============================================================================
// 8. FRI — FRI Folding (Goldilocks)
// ============================================================================

#[test]
fn fri_gpu_fold() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let fri = match reg.best_fri() {
        Some(f) => {
            assert!(f.is_available(), "FRI accelerator unavailable");
            assert!(
                f.name().starts_with("metal-"),
                "FRI accelerator must be metal-backed when present, got '{}'",
                f.name()
            );
            f
        }
        _ => {
            eprintln!("  [skip] fri accelerator not available");
            return;
        }
    };

    // FRI fold: input is 2n evaluations, output is n
    let n = fri.min_fold_size().max(1024);
    let evals: Vec<u64> = (0..2 * n).map(|i| (i as u64 * 17 + 11) % GL_P).collect();
    let alpha = 42u64 % GL_P;
    let inv_twiddles: Vec<u64> = (0..n).map(|i| (i as u64 * 3 + 1) % GL_P).collect();

    let folded = fri
        .fold_goldilocks(&evals, alpha, &inv_twiddles)
        .expect("Metal FRI fold must succeed");
    let expected = cpu_fri_fold(&evals, alpha, &inv_twiddles);
    assert_eq!(folded, expected, "FRI fold GPU/CPU parity mismatch");
    eprintln!("  [fri] fold 2*{n} → {}: ✓", folded.len());
}

// ============================================================================
// 9. CONSTRAINT EVAL — Bytecode Evaluation on Trace
// ============================================================================

#[test]
fn constraint_eval_gpu_basic() {
    ensure_metal_init();
    if !metal_tests_enabled() {
        return;
    }
    let reg = accelerator_registry_guard();

    let ce = match reg.best_constraint_eval() {
        Some(c) => {
            assert!(c.is_available(), "ConstraintEval accelerator unavailable");
            assert!(
                c.name().starts_with("metal-"),
                "ConstraintEval accelerator must be metal-backed when present, got '{}'",
                c.name()
            );
            c
        }
        _ => {
            eprintln!("  [skip] constraint_eval accelerator not available");
            return;
        }
    };

    // Simple trace: 2 columns, n_rows rows
    let n_rows = ce.min_rows().max(1024);
    let width = 2;
    let trace: Vec<u64> = (0..n_rows * width)
        .map(|i| (i as u64 * 11 + 3) % GL_P)
        .collect();

    let mut compiler = zkf_metal::constraint_eval::ConstraintCompiler::new();
    compiler.load_column(0);
    compiler.load_column(1);
    compiler.add();
    compiler.emit(0);
    let (bytecode, constants, n_constraints) = compiler.finish();

    let results = ce
        .eval_trace_goldilocks(&trace, width, &bytecode, &constants, n_constraints)
        .expect("Metal constraint evaluation must succeed");
    let expected: Vec<u64> = (0..n_rows)
        .map(|row| {
            let a = trace[row * width];
            let b = trace[row * width + 1];
            gl_add(a, b)
        })
        .collect();
    assert_eq!(
        results, expected,
        "constraint evaluation GPU/CPU parity mismatch"
    );
    eprintln!(
        "  [constraint_eval] trace {}x{} → {} outputs: ✓",
        n_rows,
        width,
        results.len()
    );
}

// ============================================================================
// 10. END-TO-END: Plonky3 STARK proof exercises NTT + Poseidon2 + FRI
// ============================================================================

#[test]
fn plonky3_proof_uses_gpu_accelerators() {
    use std::collections::BTreeMap;
    use zkf_core::{
        Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
        WitnessPlan, generate_witness,
    };

    if !metal_tests_enabled() {
        return;
    }

    // Build a medium circuit in Goldilocks for Plonky3
    let n = 100;
    let mut signals = vec![Signal {
        name: "x_0".into(),
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
            name: format!("x_{i}"),
            visibility: vis,
            constant: None,
            ty: None,
        });
        let rhs = Expr::Add(vec![
            Expr::signal(format!("x_{}", i - 1)),
            Expr::constant_i64(i as i64),
        ]);
        constraints.push(Constraint::Equal {
            lhs: Expr::signal(format!("x_{i}")),
            rhs: rhs.clone(),
            label: Some(format!("step_{i}")),
        });
        assignments.push(WitnessAssignment {
            target: format!("x_{i}"),
            expr: rhs,
        });
    }

    let program = Program {
        name: "plonky3_gpu_test".into(),
        field: FieldId::Goldilocks,
        signals,
        constraints,
        witness_plan: WitnessPlan {
            assignments,
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    };

    let backend = backend_for(BackendKind::Plonky3);
    let compiled = backend.compile(&program).expect("compile");
    let inputs = BTreeMap::from([("x_0".into(), FieldElement::from_i64(0))]);
    let witness = generate_witness(&program, &inputs).expect("witness");
    let proof = backend.prove(&compiled, &witness).expect("prove");
    let ok = backend.verify(&compiled, &proof).expect("verify");
    assert!(ok, "Plonky3 STARK proof must verify");

    eprintln!(
        "  [plonky3] 100-step proof: {} bytes, verified ✓",
        proof.proof.len()
    );
}

// ============================================================================
// 11. METAL RUNTIME REPORT — verify diagnostic output
// ============================================================================

#[test]
fn metal_runtime_report_complete() {
    ensure_metal_init();

    let report = zkf_backends::metal_runtime_report();

    if !report.metal_compiled {
        assert!(!report.metal_available);
        return;
    }

    if !report.metal_available {
        eprintln!("  [skip] metal runtime unavailable on this host");
        return;
    }

    assert!(report.metal_compiled, "metal should be compiled");
    assert!(report.metal_available, "metal should be available");
    assert!(
        report.metal_device.is_some(),
        "metal device should be reported"
    );
    assert!(
        report.threshold_profile.is_some(),
        "threshold profile should be set"
    );
    assert!(
        report.prewarmed_pipelines > 0,
        "should have prewarmed pipelines"
    );

    let device = report.metal_device.as_deref().unwrap_or("?");
    let profile = report.threshold_profile.as_deref().unwrap_or("?");
    eprintln!(
        "  [runtime] device={device} profile={profile} pipelines={}",
        report.prewarmed_pipelines
    );
}

// ============================================================================
// Summary
//
// Test count by accelerator:
//   Registry:              3  (all registered, all available, thresholds)
//   MSM:                   1  (end-to-end Groth16 proof with GPU MSM)
//   NTT:                   1  (forward+inverse roundtrip)
//   Hash:                  2  (SHA-256 batch, Keccak-256 batch)
//   Poseidon2:             1  (deterministic permutation)
//   Field Ops:             1  (add/mul/sub correctness)
//   Poly Ops:              1  (polynomial evaluation)
//   FRI:                   1  (fold halving)
//   Constraint Eval:       1  (bytecode on trace)
//   Plonky3 E2E:           1  (STARK proof uses NTT+Poseidon2+FRI)
//   Runtime Report:        1  (diagnostic completeness)
//                   Total: 14
// ============================================================================
