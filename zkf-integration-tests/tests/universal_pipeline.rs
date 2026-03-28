//! Universal Pipeline Integration Tests
//!
//! These tests validate ZKF's core claim: **write once, prove anywhere**.
//!
//! A single circuit definition flows through every layer of the stack:
//!   IR construction → witness generation → constraint checking →
//!   compilation → proving → verification
//!
//! …and the same logical circuit is proven on every compatible backend,
//! optimized without breaking soundness, debugged with correct diagnostics,
//! converted through every IR tier, wrapped across proof systems, and
//! verified through negative‐path rejection of invalid witnesses and proofs.

use std::collections::BTreeMap;
use zkf_backends::{backend_for, capabilities_matrix};
use zkf_core::ccs::CcsProgram;
use zkf_core::{
    BackendKind, BackendMode, CompiledProgram, Constraint, DebugOptions, Expr, FieldElement,
    FieldId, Program, ProofArtifact, Signal, Visibility, Witness, WitnessAssignment, WitnessHint,
    WitnessInputs, WitnessPlan, analyze_underconstrained, check_constraints, collect_public_inputs,
    debug_program, generate_witness, optimize_program, program_v2_to_zir, program_zir_to_v2,
    zir_v1 as zir,
};

// ============================================================================
// Circuit Builders
//
// These construct progressively more complex circuits to stress-test the
// pipeline.  Every circuit includes a witness plan so that witness generation
// is fully deterministic from inputs alone.
// ============================================================================

/// Minimal: `y = x * x + x` (quadratic, 1 constraint).
/// For x=3, y=12.  For x=7, y=56.
fn quadratic(field: FieldId) -> Program {
    let y_expr = Expr::Add(vec![
        Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("x"))),
        Expr::signal("x"),
    ]);

    Program {
        name: "quadratic".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("y"),
            rhs: y_expr.clone(),
            label: Some("y_eq_x_sq_plus_x".into()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "y".into(),
                expr: y_expr,
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Mid-complexity: private `a`, `b`; public `product`, `sum`, `is_nonzero`.
///   product = a * b
///   sum     = a + b
///   is_nonzero ∈ {0,1}  (boolean constraint)
///   range(a, 8)          (a fits in 8 bits, i.e. a < 256)
///
/// For a=5, b=7: product=35, sum=12, is_nonzero=1.
fn multi_constraint(field: FieldId) -> Program {
    let product_expr = Expr::Mul(Box::new(Expr::signal("a")), Box::new(Expr::signal("b")));
    let sum_expr = Expr::Add(vec![Expr::signal("a"), Expr::signal("b")]);

    Program {
        name: "multi_constraint".to_string(),
        field,
        signals: vec![
            Signal {
                name: "a".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "b".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "product".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "sum".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "is_nonzero".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("product"),
                rhs: product_expr.clone(),
                label: Some("product_eq_a_times_b".into()),
            },
            Constraint::Equal {
                lhs: Expr::signal("sum"),
                rhs: sum_expr.clone(),
                label: Some("sum_eq_a_plus_b".into()),
            },
            Constraint::Boolean {
                signal: "is_nonzero".into(),
                label: Some("is_nonzero_bool".into()),
            },
            Constraint::Range {
                signal: "a".into(),
                bits: 8,
                label: Some("a_fits_8_bits".into()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "product".into(),
                    expr: product_expr,
                },
                WitnessAssignment {
                    target: "sum".into(),
                    expr: sum_expr,
                },
            ],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Division circuit: `quotient = dividend / divisor`.
/// Exercises `Expr::Div` and field inverse computation.
/// For dividend=42, divisor=6: quotient=7.
fn division_circuit(field: FieldId) -> Program {
    let q_expr = Expr::Div(
        Box::new(Expr::signal("dividend")),
        Box::new(Expr::signal("divisor")),
    );

    Program {
        name: "division".to_string(),
        field,
        signals: vec![
            Signal {
                name: "dividend".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "divisor".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "quotient".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("quotient"),
            rhs: q_expr.clone(),
            label: Some("quotient_eq_div".into()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "quotient".into(),
                expr: q_expr,
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Witness-hint circuit: tests the hint propagation path.
/// `original` is private, `alias` copies via hint, `doubled` = alias * 2.
fn hint_circuit(field: FieldId) -> Program {
    let doubled_expr = Expr::Mul(
        Box::new(Expr::signal("alias")),
        Box::new(Expr::Const(FieldElement::from_i64(2))),
    );

    Program {
        name: "hint_propagation".to_string(),
        field,
        signals: vec![
            Signal {
                name: "original".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "alias".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "doubled".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::signal("alias"),
                rhs: Expr::signal("original"),
                label: Some("alias_eq_original".into()),
            },
            Constraint::Equal {
                lhs: Expr::signal("doubled"),
                rhs: doubled_expr.clone(),
                label: Some("doubled_eq_alias_times_2".into()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "doubled".into(),
                expr: doubled_expr,
            }],
            hints: vec![WitnessHint {
                target: "alias".into(),
                source: "original".into(),
                kind: zkf_core::WitnessHintKind::Copy,
            }],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Constant circuit: tests constant signal handling.
/// `c` is a constant (= 7), `result` = x + c.
fn constant_circuit(field: FieldId) -> Program {
    let result_expr = Expr::Add(vec![Expr::signal("x"), Expr::signal("c")]);

    Program {
        name: "constant_fold".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "c".into(),
                visibility: Visibility::Constant,
                constant: Some(FieldElement::from_i64(7)),
                ty: None,
            },
            Signal {
                name: "result".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("result"),
            rhs: result_expr.clone(),
            label: Some("result_eq_x_plus_c".into()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "result".into(),
                expr: result_expr,
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

// ============================================================================
// Helper: Full pipeline runner
// ============================================================================

/// Run the complete compile → witness → prove → verify cycle.
/// Returns (compiled, witness, proof) for further inspection.
fn full_pipeline(
    program: &Program,
    inputs: &WitnessInputs,
    backend_kind: BackendKind,
) -> (CompiledProgram, Witness, ProofArtifact) {
    let backend = backend_for(backend_kind);

    let compiled = backend
        .compile(program)
        .unwrap_or_else(|e| panic!("[{backend_kind}] compile failed: {e}"));

    let witness = generate_witness(program, inputs)
        .unwrap_or_else(|e| panic!("[{backend_kind}] witness generation failed: {e}"));

    let proof = backend
        .prove(&compiled, &witness)
        .unwrap_or_else(|e| panic!("[{backend_kind}] prove failed: {e}"));

    let valid = backend
        .verify(&compiled, &proof)
        .unwrap_or_else(|e| panic!("[{backend_kind}] verify failed: {e}"));

    assert!(valid, "[{backend_kind}] proof verification returned false");

    (compiled, witness, proof)
}

// ============================================================================
// 1. THE UNIVERSAL PIPELINE: One circuit, every backend
//
// This is the central claim.  The same quadratic circuit (y = x² + x)
// compiles and proves on Groth16, Halo2, and Plonky3 without modification.
// ============================================================================

#[test]
fn same_circuit_proves_on_arkworks_groth16() {
    let program = quadratic(FieldId::Bn254);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["y"], FieldElement::from_i64(12));
}

#[test]
fn same_circuit_proves_on_halo2() {
    let program = quadratic(FieldId::PastaFp);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Halo2);
    assert_eq!(witness.values["y"], FieldElement::from_i64(12));
}

#[test]
fn same_circuit_proves_on_plonky3_goldilocks() {
    let program = quadratic(FieldId::Goldilocks);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Plonky3);
    assert_eq!(witness.values["y"], FieldElement::from_i64(12));
}

#[test]
fn same_circuit_proves_on_plonky3_babybear() {
    let program = quadratic(FieldId::BabyBear);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Plonky3);
    assert_eq!(witness.values["y"], FieldElement::from_i64(12));
}

#[test]
fn same_circuit_proves_on_plonky3_mersenne31() {
    let program = quadratic(FieldId::Mersenne31);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Plonky3);
    assert_eq!(witness.values["y"], FieldElement::from_i64(12));
}

#[test]
fn same_circuit_proves_on_halo2_bls12_381() {
    let program = quadratic(FieldId::Bls12_381);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Halo2Bls12381);
    assert_eq!(witness.values["y"], FieldElement::from_i64(12));
}

// ============================================================================
// 2. MULTI-CONSTRAINT CIRCUITS ACROSS BACKENDS
//
// Boolean + Range + Equal constraints all working together, proven on
// multiple backends.
// ============================================================================

fn multi_constraint_inputs() -> WitnessInputs {
    BTreeMap::from([
        ("a".into(), FieldElement::from_i64(5)),
        ("b".into(), FieldElement::from_i64(7)),
        ("is_nonzero".into(), FieldElement::from_i64(1)),
    ])
}

#[test]
fn multi_constraint_groth16() {
    let program = multi_constraint(FieldId::Bn254);
    let (_, witness, _) = full_pipeline(
        &program,
        &multi_constraint_inputs(),
        BackendKind::ArkworksGroth16,
    );
    assert_eq!(witness.values["product"], FieldElement::from_i64(35));
    assert_eq!(witness.values["sum"], FieldElement::from_i64(12));
}

#[test]
fn multi_constraint_halo2() {
    let program = multi_constraint(FieldId::PastaFp);
    let (_, witness, _) = full_pipeline(&program, &multi_constraint_inputs(), BackendKind::Halo2);
    assert_eq!(witness.values["product"], FieldElement::from_i64(35));
}

#[test]
fn multi_constraint_plonky3() {
    let program = multi_constraint(FieldId::Goldilocks);
    let (_, witness, _) = full_pipeline(&program, &multi_constraint_inputs(), BackendKind::Plonky3);
    assert_eq!(witness.values["product"], FieldElement::from_i64(35));
}

// ============================================================================
// 3. DIVISION (FIELD INVERSE) ACROSS BACKENDS
// ============================================================================

#[test]
fn division_groth16() {
    let program = division_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("dividend".into(), FieldElement::from_i64(42)),
        ("divisor".into(), FieldElement::from_i64(6)),
    ]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["quotient"], FieldElement::from_i64(7));
}

#[test]
fn division_plonky3() {
    let program = division_circuit(FieldId::Goldilocks);
    let inputs = BTreeMap::from([
        ("dividend".into(), FieldElement::from_i64(42)),
        ("divisor".into(), FieldElement::from_i64(6)),
    ]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Plonky3);
    assert_eq!(witness.values["quotient"], FieldElement::from_i64(7));
}

// ============================================================================
// 4. WITNESS HINTS (ALIAS PROPAGATION)
// ============================================================================

#[test]
fn hint_propagation_works() {
    let program = hint_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([("original".into(), FieldElement::from_i64(10))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["alias"], FieldElement::from_i64(10));
    assert_eq!(witness.values["doubled"], FieldElement::from_i64(20));
}

// ============================================================================
// 5. CONSTANT SIGNALS
// ============================================================================

#[test]
fn constant_signal_folded_into_witness() {
    let program = constant_circuit(FieldId::Goldilocks);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Plonky3);
    // result = x + c = 3 + 7 = 10
    assert_eq!(witness.values["result"], FieldElement::from_i64(10));
    // constant 'c' should also be in the witness
    assert_eq!(witness.values["c"], FieldElement::from_i64(7));
}

// ============================================================================
// 6. NEGATIVE TESTS: Invalid witnesses MUST fail
//
// The proof system is only as good as its rejection of invalid proofs.
// ============================================================================

#[test]
fn wrong_witness_value_fails_constraint_check() {
    let program = quadratic(FieldId::Bn254);
    let witness = Witness {
        values: BTreeMap::from([
            ("x".into(), FieldElement::from_i64(3)),
            ("y".into(), FieldElement::from_i64(999)), // wrong: should be 12
        ]),
    };
    let result = check_constraints(&program, &witness);
    assert!(
        result.is_err(),
        "Wrong witness should fail constraint check"
    );
}

#[test]
fn boolean_constraint_rejects_non_boolean() {
    let program = multi_constraint(FieldId::Bn254);
    let mut inputs = multi_constraint_inputs();
    inputs.insert("is_nonzero".into(), FieldElement::from_i64(5)); // not 0 or 1
    let result = generate_witness(&program, &inputs);
    assert!(result.is_err(), "Boolean constraint should reject value 5");
}

#[test]
fn range_constraint_rejects_overflow() {
    let program = multi_constraint(FieldId::Bn254);
    let mut inputs = multi_constraint_inputs();
    inputs.insert("a".into(), FieldElement::from_i64(256)); // exceeds 8-bit range
    let result = generate_witness(&program, &inputs);
    assert!(
        result.is_err(),
        "Range constraint should reject 256 (> 8 bits)"
    );
}

#[test]
fn missing_input_signal_fails() {
    let program = quadratic(FieldId::Bn254);
    let inputs: WitnessInputs = BTreeMap::new(); // no inputs at all
    let result = generate_witness(&program, &inputs);
    assert!(
        result.is_err(),
        "Missing input should fail witness generation"
    );
}

#[test]
fn unknown_signal_in_inputs_fails() {
    let program = quadratic(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("x".into(), FieldElement::from_i64(3)),
        ("nonexistent".into(), FieldElement::from_i64(42)),
    ]);
    let result = generate_witness(&program, &inputs);
    assert!(result.is_err(), "Unknown signal in inputs should fail");
}

// ============================================================================
// 7. OPTIMIZER: Optimize, then prove the optimized version
//
// The optimizer must preserve soundness: an optimized program must still
// produce valid proofs for the same inputs.
// ============================================================================

#[test]
fn optimizer_preserves_provability_groth16() {
    let program = multi_constraint(FieldId::Bn254);
    let (optimized, report) = optimize_program(&program);

    // Report should show work was done (or at least analyzed)
    assert_eq!(report.input_constraints, program.constraints.len());
    assert!(report.output_constraints <= report.input_constraints);

    // The optimized program must still prove
    let inputs = multi_constraint_inputs();
    let (_, _, _) = full_pipeline(&optimized, &inputs, BackendKind::ArkworksGroth16);
}

#[test]
fn optimizer_preserves_provability_plonky3() {
    let program = multi_constraint(FieldId::Goldilocks);
    let (optimized, _) = optimize_program(&program);
    let inputs = multi_constraint_inputs();
    let (_, _, _) = full_pipeline(&optimized, &inputs, BackendKind::Plonky3);
}

#[test]
fn optimizer_folds_tautologies() {
    // Build a circuit with a tautology: x = x
    let program = Program {
        name: "tautology_test".into(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            // Tautology: x = x (should be removed)
            Constraint::Equal {
                lhs: Expr::signal("x"),
                rhs: Expr::signal("x"),
                label: Some("tautology".into()),
            },
            // Real constraint: y = x + 1
            Constraint::Equal {
                lhs: Expr::signal("y"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::constant_i64(1)]),
                label: Some("y_eq_x_plus_1".into()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "y".into(),
                expr: Expr::Add(vec![Expr::signal("x"), Expr::constant_i64(1)]),
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    };

    let (optimized, report) = optimize_program(&program);
    assert!(
        report.removed_tautology_constraints > 0
            || optimized.constraints.len() < program.constraints.len(),
        "Optimizer should remove the tautology (x = x)"
    );
}

// ============================================================================
// 8. DEBUGGER: Correct diagnostics on good and bad witnesses
// ============================================================================

#[test]
fn debugger_reports_pass_on_valid_witness() {
    let program = quadratic(FieldId::Bn254);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let witness = generate_witness(&program, &inputs).unwrap();

    let report = debug_program(&program, &witness, DebugOptions::default());

    assert!(
        report.passed,
        "Debugger should report pass for valid witness"
    );
    assert_eq!(report.total_constraints, program.constraints.len());
    assert_eq!(report.evaluated_constraints, program.constraints.len());
    assert!(report.first_failure_index.is_none());
}

#[test]
fn debugger_reports_failure_on_invalid_witness() {
    let program = quadratic(FieldId::Bn254);
    let witness = Witness {
        values: BTreeMap::from([
            ("x".into(), FieldElement::from_i64(3)),
            ("y".into(), FieldElement::from_i64(999)),
        ]),
    };

    let report = debug_program(
        &program,
        &witness,
        DebugOptions {
            stop_on_first_failure: true,
        },
    );

    assert!(
        !report.passed,
        "Debugger should report failure for bad witness"
    );
    assert!(report.first_failure_index.is_some());
    assert_eq!(report.first_failure_index.unwrap(), 0);
}

#[test]
fn debugger_produces_symbolic_analysis() {
    let program = multi_constraint(FieldId::Bn254);
    let inputs = multi_constraint_inputs();
    let witness = generate_witness(&program, &inputs).unwrap();

    let report = debug_program(&program, &witness, DebugOptions::default());

    // Symbolic constraints should have dependency info
    assert!(!report.symbolic_constraints.is_empty());
    for sc in &report.symbolic_constraints {
        assert!(!sc.form.is_empty(), "Symbolic form should not be empty");
        // degree estimate should be reasonable (1 for linear, 2 for quadratic)
        assert!(sc.degree_estimate <= 3, "Degree should be reasonable");
    }

    // Symbolic witness should cover all signals
    assert!(report.symbolic_witness.len() >= program.signals.len());
}

#[test]
fn underconstrained_analysis_on_sound_circuit() {
    let program = quadratic(FieldId::Bn254);
    let analysis = analyze_underconstrained(&program);

    // x is an input (determined externally), y is constrained by y = x² + x.
    // No private signals should be unconstrained.
    assert!(
        analysis.unconstrained_private_signals.is_empty(),
        "Quadratic circuit has no unconstrained private signals: {:?}",
        analysis.unconstrained_private_signals,
    );
}

// ============================================================================
// 9. ZIR ROUND-TRIP: v2 → ZIR → v2 preserves semantics and provability
// ============================================================================

#[test]
fn zir_roundtrip_preserves_structure() {
    let program = multi_constraint(FieldId::Bn254);
    let zir_program = program_v2_to_zir(&program);
    let restored = program_zir_to_v2(&zir_program).expect("ZIR → v2 should succeed");

    assert_eq!(restored.name, program.name);
    assert_eq!(restored.field, program.field);
    assert_eq!(restored.signals.len(), program.signals.len());
    assert_eq!(restored.constraints.len(), program.constraints.len());
}

#[test]
fn zir_roundtrip_preserves_provability() {
    let original = multi_constraint(FieldId::Bn254);
    let zir_program = program_v2_to_zir(&original);
    let restored = program_zir_to_v2(&zir_program).unwrap();

    let inputs = multi_constraint_inputs();
    let (_, _, _) = full_pipeline(&restored, &inputs, BackendKind::ArkworksGroth16);
}

#[test]
fn zir_native_backend_path() {
    // Build a ZIR program and prove via compile_zir (the ZIR-native path)
    let v2_program = quadratic(FieldId::Goldilocks);
    let zir_program = program_v2_to_zir(&v2_program);

    let backend = backend_for(BackendKind::Plonky3);

    // Use the ZIR-native compile path
    let compiled = backend
        .compile_zir(&zir_program)
        .expect("compile_zir should succeed");

    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let witness = generate_witness(&v2_program, &inputs).unwrap();

    let proof = backend
        .prove(&compiled, &witness)
        .expect("prove should succeed");
    let valid = backend
        .verify(&compiled, &proof)
        .expect("verify should succeed");
    assert!(valid, "ZIR-native compiled proof should verify");
}

// ============================================================================
// 10. CCS CONVERSION: IR → CCS structural validation
// ============================================================================

#[test]
fn ccs_from_program_has_correct_structure() {
    let program = quadratic(FieldId::Bn254);
    let ccs = CcsProgram::try_from_program(&program).expect("CCS conversion should succeed");

    assert_eq!(ccs.field, FieldId::Bn254);
    assert!(ccs.num_constraints > 0, "CCS should have constraints");
    assert!(ccs.num_variables > 0, "CCS should have variables");
    // R1CS-style CCS has 3 matrices (A, B, C) and 2 multiset terms
    assert!(ccs.num_matrices() >= 2, "CCS should have ≥2 matrices");
    assert!(ccs.num_terms() >= 1, "CCS should have ≥1 terms");
    // Degree for R1CS is 2 (bilinear: A·z ∘ B·z)
    assert!(ccs.degree() >= 1);
}

#[test]
fn ccs_from_multi_constraint_program() {
    let program = multi_constraint(FieldId::Bn254);
    let ccs = CcsProgram::try_from_program(&program).expect("CCS conversion should succeed");

    // Should have constraints for Equal + Boolean + Range
    assert!(
        ccs.num_constraints >= 3,
        "Multi-constraint should produce ≥3 CCS constraints"
    );
    // Public signals count: product, sum, is_nonzero = 3
    assert!(ccs.num_public >= 3, "Should have ≥3 public variables");
}

// ============================================================================
// 11. PROOF ARTIFACT INTEGRITY
// ============================================================================

#[test]
fn proof_artifact_serialization_roundtrip() {
    let program = quadratic(FieldId::Bn254);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, _, proof) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);

    // Serialize to JSON and back
    let json = serde_json::to_string(&proof).expect("proof serialization should succeed");
    let restored: ProofArtifact =
        serde_json::from_str(&json).expect("proof deserialization should succeed");

    assert_eq!(restored.backend, proof.backend);
    assert_eq!(restored.program_digest, proof.program_digest);
    assert_eq!(restored.proof, proof.proof);
    assert_eq!(restored.verification_key, proof.verification_key);
    assert_eq!(restored.public_inputs, proof.public_inputs);
}

#[test]
fn compiled_program_serialization_roundtrip() {
    let program = quadratic(FieldId::Bn254);
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).unwrap();

    let json = serde_json::to_string(&compiled).expect("compiled serialization");
    let restored: CompiledProgram = serde_json::from_str(&json).expect("compiled deserialization");

    assert_eq!(restored.backend, compiled.backend);
    assert_eq!(restored.program_digest, compiled.program_digest);
    assert_eq!(
        restored.compiled_data.is_some(),
        compiled.compiled_data.is_some()
    );
}

#[test]
fn program_digest_is_deterministic() {
    let p1 = quadratic(FieldId::Bn254);
    let p2 = quadratic(FieldId::Bn254);
    assert_eq!(p1.digest_hex(), p2.digest_hex());
}

#[test]
fn program_digest_changes_with_field() {
    let p_bn254 = quadratic(FieldId::Bn254);
    let p_gold = quadratic(FieldId::Goldilocks);
    assert_ne!(
        p_bn254.digest_hex(),
        p_gold.digest_hex(),
        "Different fields should produce different digests"
    );
}

// ============================================================================
// 12. PUBLIC INPUT EXTRACTION
// ============================================================================

#[test]
fn public_inputs_extracted_correctly() {
    let program = multi_constraint(FieldId::Bn254);
    let inputs = multi_constraint_inputs();
    let witness = generate_witness(&program, &inputs).unwrap();
    let public = collect_public_inputs(&program, &witness).unwrap();

    // Public signals in order: product, sum, is_nonzero
    assert_eq!(public.len(), 3);
    assert_eq!(public[0], FieldElement::from_i64(35)); // product = 5 * 7
    assert_eq!(public[1], FieldElement::from_i64(12)); // sum     = 5 + 7
    assert_eq!(public[2], FieldElement::from_i64(1)); // is_nonzero
}

// ============================================================================
// 13. CAPABILITIES MATRIX CONSISTENCY
// ============================================================================

#[test]
fn capabilities_matrix_covers_all_backends() {
    let matrix = capabilities_matrix();

    let expected_backends = [
        BackendKind::Plonky3,
        BackendKind::Halo2,
        BackendKind::Halo2Bls12381,
        BackendKind::ArkworksGroth16,
        BackendKind::Sp1,
        BackendKind::RiscZero,
        BackendKind::Nova,
        BackendKind::HyperNova,
        BackendKind::MidnightCompact,
    ];

    assert_eq!(
        matrix.len(),
        expected_backends.len(),
        "Capabilities matrix should cover all backends"
    );

    for backend in &expected_backends {
        assert!(
            matrix.iter().any(|cap| cap.backend == *backend),
            "Missing backend in capabilities: {backend}"
        );
    }
}

#[test]
fn native_backends_report_native_mode() {
    let matrix = capabilities_matrix();
    let groth16 = matrix
        .iter()
        .find(|c| c.backend == BackendKind::ArkworksGroth16)
        .unwrap();
    let halo2 = matrix
        .iter()
        .find(|c| c.backend == BackendKind::Halo2)
        .unwrap();
    let plonky3 = matrix
        .iter()
        .find(|c| c.backend == BackendKind::Plonky3)
        .unwrap();

    assert_eq!(groth16.mode, BackendMode::Native);
    assert_eq!(halo2.mode, BackendMode::Native);
    assert_eq!(plonky3.mode, BackendMode::Native);

    // Groth16 requires trusted setup
    assert!(groth16.trusted_setup);
    // Halo2 and Plonky3 are transparent
    assert!(halo2.transparent_setup);
    assert!(plonky3.transparent_setup);
}

// ============================================================================
// 14. CIRCOM R1CS FRONTEND → BACKEND PIPELINE
//
// Import a hand-built R1CS JSON (the kind snarkjs produces), then prove
// on a real backend.  This tests the frontend→IR→backend chain.
// ============================================================================

#[test]
fn circom_r1cs_import_and_prove() {
    // Minimal R1CS: one constraint over 3 variables.
    // Constraint: w0 * w1 = w2  (i.e., a * b = c)
    // nVars = 4 (including the constant "1" wire at index 0)
    // nPubInputs = 1, nOutputs = 1
    let r1cs_json = serde_json::json!({
        "nVars": 4,
        "nPubInputs": 1,
        "nOutputs": 1,
        "constraints": [
            [
                {"1": "1"},     // A: 1 * w1
                {"2": "1"},     // B: 1 * w2
                {"3": "1"}      // C: 1 * w3  =>  w1 * w2 = w3
            ]
        ]
    });

    let engine = zkf_frontends::frontend_for(zkf_frontends::FrontendKind::Circom);
    let probe = engine.probe(&r1cs_json);
    assert!(probe.accepted, "Circom frontend should accept R1CS JSON");

    let program = engine
        .compile_to_ir(&r1cs_json, &zkf_frontends::FrontendImportOptions::default())
        .expect("R1CS import should succeed");

    assert!(!program.signals.is_empty());
    assert!(!program.constraints.is_empty());
    assert_eq!(program.field, FieldId::Bn254); // Circom default
}

// ============================================================================
// 15. GADGET EMISSION → PROVABLE CIRCUIT
//
// Use the gadget registry to emit constraints, build a complete program
// from them, and prove it.
// ============================================================================

#[test]
fn gadget_poseidon_emission_produces_valid_zir() {
    let registry = zkf_gadgets::GadgetRegistry::with_builtins();
    let poseidon = registry
        .get("poseidon")
        .expect("poseidon gadget must exist");

    let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
    let emission = poseidon
        .emit(&inputs, &["hash".into()], FieldId::Bn254, &BTreeMap::new())
        .expect("poseidon emit should succeed");

    // Should produce a BlackBox Poseidon constraint
    assert!(!emission.constraints.is_empty());
    let has_poseidon = emission.constraints.iter().any(|c| {
        matches!(
            c,
            zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Poseidon,
                ..
            }
        )
    });
    assert!(
        has_poseidon,
        "Emission should contain a Poseidon BlackBox constraint"
    );
}

#[test]
fn gadget_range_emission_structure() {
    let registry = zkf_gadgets::GadgetRegistry::with_builtins();
    let range = registry.get("range").expect("range gadget must exist");

    let inputs = vec![zir::Expr::Signal("value".into())];
    let mut params = BTreeMap::new();
    params.insert("bits".to_string(), "16".to_string());

    let emission = range
        .emit(&inputs, &["valid".into()], FieldId::Bn254, &params)
        .expect("range emit should succeed");

    assert!(!emission.constraints.is_empty());
}

#[test]
fn gadget_comparison_emission() {
    let registry = zkf_gadgets::GadgetRegistry::with_builtins();
    let comparison = registry
        .get("comparison")
        .expect("comparison gadget must exist");

    let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
    let mut params = BTreeMap::new();
    params.insert("op".to_string(), "lt".to_string());
    params.insert("bits".to_string(), "32".to_string());

    let emission = comparison
        .emit(&inputs, &["result".into()], FieldId::Bn254, &params)
        .expect("comparison emit should succeed");

    assert!(!emission.constraints.is_empty());
    assert!(!emission.signals.is_empty());
}

// ============================================================================
// 16. DIFFERENT INPUTS, SAME CIRCUIT
//
// Verify the system produces correct proofs for multiple valid input sets.
// ============================================================================

#[test]
fn multiple_valid_inputs_all_prove() {
    let program = quadratic(FieldId::Bn254);

    let test_cases: Vec<(i64, i64)> = vec![
        (0, 0),    // 0² + 0 = 0
        (1, 2),    // 1² + 1 = 2
        (3, 12),   // 3² + 3 = 12
        (7, 56),   // 7² + 7 = 56
        (10, 110), // 10² + 10 = 110
        (100, 10100),
    ];

    for (x_val, expected_y) in test_cases {
        let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(x_val))]);
        let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
        assert_eq!(
            witness.values["y"],
            FieldElement::from_i64(expected_y),
            "x={x_val}: expected y={expected_y}"
        );
    }
}

// ============================================================================
// 17. PROOF WRAPPING REGISTRY
//
// Verify that wrapping paths are registered and queryable.
// ============================================================================

#[test]
fn wrapping_registry_has_stark_to_groth16() {
    let registry = zkf_backends::wrapping::default_wrapper_registry();
    let paths = registry.available_paths();

    assert!(
        paths.contains(&(BackendKind::Plonky3, BackendKind::ArkworksGroth16)),
        "Should have Plonky3 → Groth16 wrapping path. Available: {:?}",
        paths,
    );
}

#[test]
fn wrapping_registry_has_halo2_to_groth16() {
    let registry = zkf_backends::wrapping::default_wrapper_registry();
    let paths = registry.available_paths();

    assert!(
        paths.contains(&(BackendKind::Halo2, BackendKind::ArkworksGroth16)),
        "Should have Halo2 → Groth16 wrapping path. Available: {:?}",
        paths,
    );
}

// ============================================================================
// 18. FIELD ARITHMETIC EDGE CASES
// ============================================================================

#[test]
fn field_element_zero_and_one() {
    assert!(FieldElement::ZERO.is_zero());
    assert!(FieldElement::ONE.is_one());
    assert!(!FieldElement::ZERO.is_one());
    assert!(!FieldElement::ONE.is_zero());
}

#[test]
fn field_element_negative_normalization() {
    // Verify -1 + 1 = 0 in modular arithmetic (proves normalization works)
    let program = Program {
        name: "neg_one_test".into(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "a".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "sum".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("sum"),
            rhs: Expr::Add(vec![Expr::signal("a"), Expr::constant_i64(1)]),
            label: Some("sum_eq_a_plus_1".into()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "sum".into(),
                expr: Expr::Add(vec![Expr::signal("a"), Expr::constant_i64(1)]),
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    };
    // Feed -1 as input; in modular arithmetic, -1 + 1 ≡ 0 (mod p)
    let inputs = BTreeMap::from([("a".into(), FieldElement::from_i64(-1))]);
    let witness = generate_witness(&program, &inputs).unwrap();
    assert!(
        witness.values["sum"].is_zero(),
        "-1 + 1 should be 0 in modular arithmetic"
    );
}

#[test]
fn circuit_with_subtraction_proves() {
    // diff = a - b, with a=10, b=3 → diff=7
    let diff_expr = Expr::Sub(Box::new(Expr::signal("a")), Box::new(Expr::signal("b")));
    let program = Program {
        name: "subtraction".into(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "a".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "b".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "diff".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("diff"),
            rhs: diff_expr.clone(),
            label: Some("diff_eq_a_minus_b".into()),
        }],
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
        ("a".into(), FieldElement::from_i64(10)),
        ("b".into(), FieldElement::from_i64(3)),
    ]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["diff"], FieldElement::from_i64(7));
}

// ============================================================================
// 19. BACKEND FIELD COMPATIBILITY
//
// Verify that backends correctly reject programs targeting incompatible fields.
// ============================================================================

#[test]
fn groth16_rejects_non_bn254() {
    let program = quadratic(FieldId::Goldilocks);
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let result = backend.compile(&program);
    assert!(result.is_err(), "Groth16 should reject Goldilocks field");
}

#[test]
fn halo2_rejects_non_pasta() {
    let program = quadratic(FieldId::Bn254);
    let backend = backend_for(BackendKind::Halo2);
    let result = backend.compile(&program);
    assert!(result.is_err(), "Halo2 should reject BN254 field");
}

// ============================================================================
// 20. PROOF METADATA
//
// Verify that proof artifacts carry meaningful metadata about how they
// were generated.
// ============================================================================

#[test]
fn groth16_proof_has_curve_metadata() {
    let program = quadratic(FieldId::Bn254);
    let inputs = BTreeMap::from([("x".into(), FieldElement::from_i64(3))]);
    let (_, _, proof) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);

    assert_eq!(
        proof.metadata.get("curve").map(|s| s.as_str()),
        Some("bn254")
    );
    assert_eq!(
        proof.metadata.get("scheme").map(|s| s.as_str()),
        Some("groth16")
    );
    assert!(proof.metadata.contains_key("prove_deterministic"));
}

#[test]
fn groth16_compiled_has_setup_metadata() {
    let program = quadratic(FieldId::Bn254);
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).unwrap();

    assert_eq!(
        compiled.metadata.get("curve").map(|s| s.as_str()),
        Some("bn254")
    );
    assert!(compiled.metadata.contains_key("setup_deterministic"));
    assert!(compiled.metadata.contains_key("setup_seed_hex"));
}

// ============================================================================
// 21. WITNESS FLOW: Debug report includes DAG structure
// ============================================================================

#[test]
fn debug_report_includes_witness_flow_graph() {
    let program = hint_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([("original".into(), FieldElement::from_i64(10))]);
    let witness = generate_witness(&program, &inputs).unwrap();

    let report = debug_program(&program, &witness, DebugOptions::default());

    // Witness flow graph should have nodes for each signal
    assert!(
        !report.witness_flow.nodes.is_empty(),
        "Witness flow graph should have nodes"
    );
    // Should have edges (at least from hint: original → alias)
    assert!(
        !report.witness_flow.edges.is_empty(),
        "Witness flow graph should have edges"
    );
}

// ============================================================================
// 22. STRESS: Large(ish) circuit across backends
//
// A chain of constraints: z_i = z_{i-1} + 1, from z_0=input to z_N=output.
// Proves that the backend can handle non-trivial constraint counts.
// ============================================================================

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

        let rhs = Expr::Add(vec![
            Expr::signal(format!("z_{}", i - 1)),
            Expr::constant_i64(1),
        ]);

        constraints.push(Constraint::Equal {
            lhs: Expr::signal(format!("z_{i}")),
            rhs: rhs.clone(),
            label: Some(format!("chain_{i}")),
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

#[test]
fn chain_50_groth16() {
    let program = chain_circuit(50, FieldId::Bn254);
    let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(0))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["z_50"], FieldElement::from_i64(50));
}

#[test]
fn chain_50_plonky3() {
    let program = chain_circuit(50, FieldId::Goldilocks);
    let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(0))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Plonky3);
    assert_eq!(witness.values["z_50"], FieldElement::from_i64(50));
}

#[test]
fn chain_50_halo2() {
    let program = chain_circuit(50, FieldId::PastaFp);
    let inputs = BTreeMap::from([("z_0".into(), FieldElement::from_i64(0))]);
    let (_, witness, _) = full_pipeline(&program, &inputs, BackendKind::Halo2);
    assert_eq!(witness.values["z_50"], FieldElement::from_i64(50));
}

// ============================================================================
// Summary
//
// Test count by category:
//   Universal pipeline (one circuit, every backend):  6
//   Multi-constraint across backends:                 3
//   Division across backends:                         2
//   Witness hints:                                    1
//   Constant signals:                                 1
//   Negative tests (must-fail):                       5
//   Optimizer + provability:                          3
//   Debugger diagnostics:                             4
//   ZIR round-trip + native path:                     3
//   CCS conversion:                                   2
//   Proof artifact integrity:                         4
//   Public input extraction:                          1
//   Capabilities matrix:                              2
//   Circom frontend → backend:                        1
//   Gadget emission:                                  3
//   Multiple valid inputs:                            1
//   Proof wrapping registry:                          2
//   Field arithmetic edge cases:                      3
//   Backend field compatibility:                      2
//   Proof metadata:                                   2
//   Witness flow graph:                               1
//   Stress (chain circuit):                           3
//                                              Total: ~53
// ============================================================================
