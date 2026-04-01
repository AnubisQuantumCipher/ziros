// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! ZKF Conformance Test Suite.
//!
//! Provides canonical test programs at increasing complexity and a conformance
//! runner that reports per-backend pass/fail for each test case.

pub mod programs;

use programs::ConformanceProgram;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use zkf_backends::{BackendEngine, BackendRoute, backend_for, backend_for_route};
use zkf_core::{BackendKind, FieldId, collect_public_inputs, generate_witness};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

/// Result of a single conformance test case against a single backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceTestResult {
    pub test_name: String,
    pub backend: String,
    pub compile_ok: bool,
    pub prove_ok: bool,
    pub verify_ok: bool,
    pub total_time_ms: u64,
    pub error: Option<String>,
    /// Error message from the compile step, if it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_error: Option<String>,
    /// Error message from the prove step, if it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prove_error: Option<String>,
    /// Error message from the verify step, if it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_error: Option<String>,
    /// Public output values produced by the proof, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_outputs: Option<Vec<String>>,
}

/// Full conformance report for a single backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub backend: String,
    pub field: String,
    pub tests_run: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub pass_rate: f64,
    pub results: Vec<ConformanceTestResult>,
}

/// Run the full conformance suite against a backend.
pub fn run_conformance(backend_kind: BackendKind) -> ConformanceReport {
    run_conformance_with_route(backend_kind, BackendRoute::Auto)
}

/// Run the full conformance suite against a backend through a specific route.
pub fn run_conformance_with_route(
    backend_kind: BackendKind,
    route: BackendRoute,
) -> ConformanceReport {
    let engine = if route == BackendRoute::Auto {
        backend_for(backend_kind)
    } else {
        backend_for_route(backend_kind, route)
    };
    let field = preferred_field_for_backend(backend_kind);
    let test_programs = programs::all_conformance_programs(field);

    let mut results = Vec::new();

    for cp in &test_programs {
        let start = Instant::now();
        let result = run_single_test(&*engine, cp);
        let elapsed = start.elapsed().as_millis() as u64;

        results.push(ConformanceTestResult {
            test_name: cp.name.clone(),
            backend: backend_kind.as_str().to_string(),
            compile_ok: result.compile_ok,
            prove_ok: result.prove_ok,
            verify_ok: result.verify_ok,
            total_time_ms: elapsed,
            error: result.error,
            compile_error: result.compile_error,
            prove_error: result.prove_error,
            verify_error: result.verify_error,
            public_outputs: result.public_outputs,
        });
    }

    let tests_passed = results.iter().filter(|r| r.verify_ok).count();
    let tests_failed = results.len() - tests_passed;
    let pass_rate = if results.is_empty() {
        0.0
    } else {
        tests_passed as f64 / results.len() as f64
    };

    ConformanceReport {
        backend: backend_kind.as_str().to_string(),
        field: format!("{:?}", field),
        tests_run: results.len(),
        tests_passed,
        tests_failed,
        pass_rate,
        results,
    }
}

struct SingleTestOutcome {
    compile_ok: bool,
    prove_ok: bool,
    verify_ok: bool,
    error: Option<String>,
    compile_error: Option<String>,
    prove_error: Option<String>,
    verify_error: Option<String>,
    public_outputs: Option<Vec<String>>,
}

impl SingleTestOutcome {
    fn witness_fail(e: impl std::fmt::Display) -> Self {
        Self {
            compile_ok: false,
            prove_ok: false,
            verify_ok: false,
            error: Some(format!("witness: {e}")),
            compile_error: None,
            prove_error: None,
            verify_error: None,
            public_outputs: None,
        }
    }

    fn compile_fail(e: impl std::fmt::Display) -> Self {
        let msg = format!("compile: {e}");
        Self {
            compile_ok: false,
            prove_ok: false,
            verify_ok: false,
            error: Some(msg.clone()),
            compile_error: Some(msg),
            prove_error: None,
            verify_error: None,
            public_outputs: None,
        }
    }

    fn prove_fail(e: impl std::fmt::Display) -> Self {
        let msg = format!("prove: {e}");
        Self {
            compile_ok: true,
            prove_ok: false,
            verify_ok: false,
            error: Some(msg.clone()),
            compile_error: None,
            prove_error: Some(msg),
            verify_error: None,
            public_outputs: None,
        }
    }

    fn verify_fail(e: impl std::fmt::Display, public_outputs: Option<Vec<String>>) -> Self {
        let msg = format!("verify: {e}");
        Self {
            compile_ok: true,
            prove_ok: true,
            verify_ok: false,
            error: Some(msg.clone()),
            compile_error: None,
            prove_error: None,
            verify_error: Some(msg),
            public_outputs,
        }
    }

    fn success(public_outputs: Option<Vec<String>>) -> Self {
        Self {
            compile_ok: true,
            prove_ok: true,
            verify_ok: true,
            error: None,
            compile_error: None,
            prove_error: None,
            verify_error: None,
            public_outputs,
        }
    }
}

fn run_single_test(engine: &dyn BackendEngine, cp: &ConformanceProgram) -> SingleTestOutcome {
    // Generate witness
    let witness = match generate_witness(&cp.program, &cp.inputs) {
        Ok(w) => w,
        Err(e) => return SingleTestOutcome::witness_fail(e),
    };

    // Compile
    let compiled = match engine.compile(&cp.program) {
        Ok(c) => c,
        Err(e) => return SingleTestOutcome::compile_fail(e),
    };

    // Prove
    let proof = match RuntimeExecutor::run_backend_prove_job(
        compiled.backend,
        BackendRoute::Auto,
        std::sync::Arc::new(cp.program.clone()),
        None,
        Some(std::sync::Arc::new(witness.clone())),
        Some(std::sync::Arc::new(compiled.clone())),
        RequiredTrustLane::StrictCryptographic,
        ExecutionMode::Deterministic,
    ) {
        Ok(execution) => execution.artifact,
        Err(e) => return SingleTestOutcome::prove_fail(e),
    };

    let expected_public_outputs = cp
        .expected_public_outputs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let witness_public_outputs = match collect_public_inputs(&cp.program, &witness) {
        Ok(values) => values,
        Err(e) => {
            return SingleTestOutcome::verify_fail(format!("public-output oracle: {e}"), None);
        }
    };
    let public_outputs = Some(
        witness_public_outputs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    );
    if public_outputs.as_ref() != Some(&expected_public_outputs) {
        return SingleTestOutcome::verify_fail(
            format!(
                "public outputs did not match expected values (expected {:?}, got {:?})",
                expected_public_outputs, public_outputs
            ),
            public_outputs,
        );
    }
    if !proof.public_inputs.is_empty() && proof.public_inputs != witness_public_outputs {
        return SingleTestOutcome::verify_fail(
            format!(
                "proof artifact public inputs diverged from witness-derived oracle (artifact {:?}, witness {:?})",
                proof.public_inputs, witness_public_outputs
            ),
            public_outputs,
        );
    }

    // Verify
    match engine.verify(&compiled, &proof) {
        Ok(true) => SingleTestOutcome::success(public_outputs),
        Ok(false) => SingleTestOutcome::verify_fail("verification returned false", public_outputs),
        Err(e) => SingleTestOutcome::verify_fail(e, public_outputs),
    }
}

fn preferred_field_for_backend(backend: BackendKind) -> FieldId {
    match backend {
        BackendKind::ArkworksGroth16 | BackendKind::Nova | BackendKind::HyperNova => FieldId::Bn254,
        BackendKind::Halo2 => FieldId::PastaFp,
        BackendKind::Halo2Bls12381 => FieldId::Bls12_381,
        BackendKind::Plonky3 | BackendKind::Sp1 | BackendKind::RiscZero => FieldId::Goldilocks,
        BackendKind::MidnightCompact => FieldId::PastaFp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use programs::ConformanceProgram;
    use std::collections::BTreeMap;
    use zkf_core::{
        Constraint, Expr, FieldElement, Program, Signal, Visibility, WitnessInputs, WitnessPlan,
    };

    #[test]
    fn conformance_programs_exist() {
        let programs = programs::all_conformance_programs(FieldId::Bn254);
        assert!(!programs.is_empty());
        assert!(programs.iter().any(|p| p.name == "identity"));
        assert!(programs.iter().any(|p| p.name == "multiply"));
    }

    #[test]
    fn conformance_fails_when_expected_public_outputs_are_wrong() {
        let cp = ConformanceProgram {
            name: "wrong-expected-output".to_string(),
            description: "public oracle mismatch".to_string(),
            program: Program {
                name: "wrong-expected-output".to_string(),
                field: FieldId::Goldilocks,
                signals: vec![
                    Signal {
                        name: "x".to_string(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "out".to_string(),
                        visibility: Visibility::Public,
                        constant: None,
                        ty: None,
                    },
                ],
                constraints: vec![Constraint::Equal {
                    lhs: Expr::Signal("out".to_string()),
                    rhs: Expr::Signal("x".to_string()),
                    label: Some("copy".to_string()),
                }],
                witness_plan: WitnessPlan {
                    assignments: vec![zkf_core::WitnessAssignment {
                        target: "out".to_string(),
                        expr: Expr::Signal("x".to_string()),
                    }],
                    ..Default::default()
                },
                lookup_tables: vec![],
                metadata: BTreeMap::new(),
            },
            inputs: WitnessInputs::from([("x".to_string(), FieldElement::from_i64(7))]),
            expected_public_outputs: vec![FieldElement::from_i64(8)],
        };

        let outcome = run_single_test(&*backend_for(BackendKind::Plonky3), &cp);
        assert!(outcome.compile_ok);
        assert!(outcome.prove_ok);
        assert!(!outcome.verify_ok);
        assert!(
            outcome
                .verify_error
                .as_deref()
                .unwrap_or_default()
                .contains("public outputs did not match expected values")
        );
    }
}
