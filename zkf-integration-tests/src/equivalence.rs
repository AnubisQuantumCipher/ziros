//! Semantic equivalence testing across backends.
//!
//! Given the same normalized program and inputs, runs all capable backends
//! and verifies that:
//! 1. Public inputs match across backends (semantic equivalence).
//! 2. Verification passes for valid proofs.
//! 3. Backends honestly report failure for incapable programs.

use zkf_core::{
    BackendKind, FieldElement, FieldId, Program, WitnessInputs,
    generate_witness, collect_public_inputs,
};
use zkf_backends::backend_for;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Result of running a single backend in an equivalence test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendEquivalenceResult {
    pub backend: String,
    pub support_class: String,
    pub compile_success: bool,
    pub prove_success: bool,
    pub verify_success: bool,
    pub public_inputs: Option<Vec<FieldElement>>,
    pub compile_time_ms: Option<u64>,
    pub prove_time_ms: Option<u64>,
    pub verify_time_ms: Option<u64>,
    pub proof_size_bytes: Option<usize>,
    pub error: Option<String>,
}

/// Full equivalence test report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivalenceReport {
    pub program_name: String,
    pub program_digest: String,
    pub field: String,
    pub backends_tested: usize,
    pub backends_succeeded: usize,
    pub public_inputs_match: bool,
    pub results: Vec<BackendEquivalenceResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<String>,
}

/// Run an equivalence test across specified backends.
///
/// Tests that for the same program + inputs:
/// - All capable backends produce matching public inputs
/// - All proofs verify successfully
/// - Incapable backends fail gracefully
pub fn run_equivalence_test(
    program: &Program,
    inputs: &WitnessInputs,
    backends: &[BackendKind],
) -> EquivalenceReport {
    let program_digest = program.digest_hex();
    let mut results = Vec::new();
    let mut mismatches = Vec::new();

    // Generate witness once (shared across backends)
    let witness = match generate_witness(program, inputs) {
        Ok(w) => w,
        Err(e) => {
            return EquivalenceReport {
                program_name: program.name.clone(),
                program_digest,
                field: format!("{:?}", program.field),
                backends_tested: 0,
                backends_succeeded: 0,
                public_inputs_match: false,
                results: vec![],
                mismatches: vec![format!("Witness generation failed: {e}")],
            };
        }
    };

    let expected_public_inputs = match collect_public_inputs(program, &witness) {
        Ok(values) => values,
        Err(e) => {
            return EquivalenceReport {
                program_name: program.name.clone(),
                program_digest,
                field: format!("{:?}", program.field),
                backends_tested: 0,
                backends_succeeded: 0,
                public_inputs_match: false,
                results: vec![],
                mismatches: vec![format!("Public input oracle failed: {e}")],
            };
        }
    };

    for &backend_kind in backends {
        let engine = backend_for(backend_kind);
        let caps = engine.capabilities();
        let support_class = caps.mode.as_str().to_string();

        let mut result = BackendEquivalenceResult {
            backend: backend_kind.as_str().to_string(),
            support_class,
            compile_success: false,
            prove_success: false,
            verify_success: false,
            public_inputs: None,
            compile_time_ms: None,
            prove_time_ms: None,
            verify_time_ms: None,
            proof_size_bytes: None,
            error: None,
        };

        // Compile
        let compile_start = Instant::now();
        let compiled = match engine.compile(program) {
            Ok(c) => {
                result.compile_success = true;
                result.compile_time_ms = Some(compile_start.elapsed().as_millis() as u64);
                c
            }
            Err(e) => {
                result.error = Some(format!("compile: {e}"));
                result.compile_time_ms = Some(compile_start.elapsed().as_millis() as u64);
                results.push(result);
                continue;
            }
        };

        // Prove
        let prove_start = Instant::now();
        let proof = match engine.prove(&compiled, &witness) {
            Ok(p) => {
                result.prove_success = true;
                result.prove_time_ms = Some(prove_start.elapsed().as_millis() as u64);
                result.proof_size_bytes = Some(p.proof.len());
                result.public_inputs = Some(p.public_inputs.clone());
                p
            }
            Err(e) => {
                result.error = Some(format!("prove: {e}"));
                result.prove_time_ms = Some(prove_start.elapsed().as_millis() as u64);
                results.push(result);
                continue;
            }
        };

        // Verify
        let verify_start = Instant::now();
        match engine.verify(&compiled, &proof) {
            Ok(valid) => {
                result.verify_success = valid;
                result.verify_time_ms = Some(verify_start.elapsed().as_millis() as u64);
                if !valid {
                    result.error = Some("verification returned false".into());
                }
            }
            Err(e) => {
                result.error = Some(format!("verify: {e}"));
                result.verify_time_ms = Some(verify_start.elapsed().as_millis() as u64);
            }
        }

        // Check public input equivalence
        if let Some(backend_public) = &result.public_inputs {
            if backend_public != &expected_public_inputs {
                mismatches.push(format!(
                    "{}: public inputs differ from witness-derived oracle (expected {:?}, got {:?})",
                    backend_kind.as_str(),
                    expected_public_inputs,
                    backend_public
                ));
            }
        }

        results.push(result);
    }

    let backends_succeeded = results.iter().filter(|r| r.verify_success).count();
    let public_inputs_match = mismatches.is_empty()
        && results.iter().filter(|r| r.prove_success).count() > 0;

    EquivalenceReport {
        program_name: program.name.clone(),
        program_digest,
        field: format!("{:?}", program.field),
        backends_tested: results.len(),
        backends_succeeded,
        public_inputs_match,
        results,
        mismatches,
    }
}

/// Get all backends capable of handling a given field.
pub fn backends_for_field(field: FieldId) -> Vec<BackendKind> {
    match field {
        FieldId::Bn254 => vec![BackendKind::ArkworksGroth16, BackendKind::Nova, BackendKind::HyperNova],
        FieldId::PastaFp => vec![BackendKind::Halo2],
        FieldId::Bls12_381 => vec![BackendKind::Halo2Bls12381],
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => vec![BackendKind::Plonky3],
        FieldId::PastaFq => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{Constraint, Expr, FieldElement, Signal, Visibility, WitnessPlan};
    use std::collections::BTreeMap;

    fn multiply_program(field: FieldId) -> Program {
        Program {
            name: "multiply".into(),
            field,
            signals: vec![
                Signal { name: "x".into(), visibility: Visibility::Private, constant: None, ty: None },
                Signal { name: "y".into(), visibility: Visibility::Private, constant: None, ty: None },
                Signal { name: "out".into(), visibility: Visibility::Public, constant: None, ty: None },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("y".into())),
                ),
                rhs: Expr::Signal("out".into()),
                label: Some("multiply".into()),
            }],
            witness_plan: WitnessPlan {
                assignments: vec![zkf_core::ir::WitnessAssignment {
                    target: "out".into(),
                    expr: Expr::Mul(
                        Box::new(Expr::Signal("x".into())),
                        Box::new(Expr::Signal("y".into())),
                    ),
                }],
                ..Default::default()
            },
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn backends_for_bn254_includes_groth16() {
        let backends = backends_for_field(FieldId::Bn254);
        assert!(backends.contains(&BackendKind::ArkworksGroth16));
    }

    #[test]
    fn equivalence_report_structure() {
        let program = multiply_program(FieldId::Bn254);
        let mut inputs = BTreeMap::new();
        inputs.insert("x".into(), FieldElement::from_i64(3));
        inputs.insert("y".into(), FieldElement::from_i64(5));

        let report = run_equivalence_test(
            &program,
            &inputs,
            &[BackendKind::ArkworksGroth16],
        );

        assert_eq!(report.program_name, "multiply");
        assert_eq!(report.backends_tested, 1);
        // The test may or may not succeed depending on backend availability,
        // but the structure should be correct
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].backend, "arkworks-groth16");
    }

    #[test]
    fn witness_public_inputs_are_the_equivalence_oracle() {
        let program = multiply_program(FieldId::Bn254);
        let mut inputs = BTreeMap::new();
        inputs.insert("x".into(), FieldElement::from_i64(3));
        inputs.insert("y".into(), FieldElement::from_i64(5));

        let witness = generate_witness(&program, &inputs).expect("witness");
        let expected_public = collect_public_inputs(&program, &witness).expect("public inputs");
        assert_eq!(expected_public, vec![FieldElement::from_i64(15)]);
    }
}
