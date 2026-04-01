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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use zkf_core::{
    BackendKind, BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, WitnessAssignment,
    WitnessInputs,
};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

use crate::util::{
    attach_groth16_setup_blob_path, backend_for_request, ensure_backend_request_allowed,
    ensure_backend_supports_program_constraints, parse_backend_request, parse_setup_seed,
    prepare_witness_for_request_from_inputs, resolve_input_aliases,
    warn_if_r1cs_lookup_limit_exceeded, with_allow_dev_deterministic_groth16_override,
    with_groth16_setup_blob_path_override, with_proof_seed_override, with_setup_seed_override,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct EquivalenceOptions {
    pub(crate) backends: Vec<String>,
    pub(crate) seed: Option<[u8; 32]>,
    pub(crate) groth16_setup_blob: Option<PathBuf>,
    pub(crate) allow_dev_deterministic_groth16: bool,
    pub(crate) allow_compat: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BackendEquivalenceReport {
    pub(crate) requested_backend: String,
    pub(crate) effective_backend: String,
    pub(crate) requested_field: String,
    pub(crate) effective_field: String,
    pub(crate) field_adapted: bool,
    pub(crate) compatibility_ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) compatibility_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) public_outputs: Vec<String>,
    pub(crate) compile_ok: bool,
    pub(crate) prove_ok: bool,
    pub(crate) verify_ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EquivalenceReport {
    pub(crate) equivalent: bool,
    pub(crate) program_name: String,
    pub(crate) program_digest: String,
    pub(crate) requested_field: String,
    pub(crate) results: Vec<BackendEquivalenceReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mismatches: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_equivalence(
    program: PathBuf,
    inputs: PathBuf,
    backends: Vec<String>,
    seed: Option<String>,
    groth16_setup_blob: Option<PathBuf>,
    allow_dev_deterministic_groth16: bool,
    json: bool,
    allow_compat: bool,
) -> Result<(), String> {
    if backends.is_empty() {
        return Err("at least one backend must be specified via --backends".to_string());
    }

    let program_data = std::fs::read_to_string(&program)
        .map_err(|e| format!("failed to read program: {}: {e}", program.display()))?;
    let ir_program: Program =
        serde_json::from_str(&program_data).map_err(|e| format!("failed to parse program: {e}"))?;

    let inputs_data = std::fs::read_to_string(&inputs)
        .map_err(|e| format!("failed to read inputs: {}: {e}", inputs.display()))?;
    let witness_inputs: WitnessInputs =
        serde_json::from_str(&inputs_data).map_err(|e| format!("failed to parse inputs: {e}"))?;

    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let report = run_equivalence_report(
        &ir_program,
        &witness_inputs,
        EquivalenceOptions {
            backends: backends.clone(),
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            allow_compat,
        },
    )?;

    if json {
        let output = serde_json::json!({
            "equivalent": report.equivalent,
            "program": program.display().to_string(),
            "inputs": inputs.display().to_string(),
            "program_name": report.program_name,
            "program_digest": report.program_digest,
            "requested_field": report.requested_field,
            "results": report.results,
            "mismatches": report.mismatches,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
        );
    } else {
        println!("Equivalence Test");
        println!("================");
        println!("Program:  {}", program.display());
        println!("Inputs:   {}", inputs.display());
        println!("Backends: {}", backends.join(", "));
        println!();

        println!(
            "  {:<24} {:<10} {:<10} {:<10} {:<22} error",
            "backend", "compile", "prove", "verify", "field"
        );
        println!("  {}", "-".repeat(100));
        for result in &report.results {
            let ok_str = |value: bool| if value { "ok" } else { "FAIL" };
            let field_summary = if result.field_adapted {
                format!("{} -> {}", result.requested_field, result.effective_field)
            } else {
                result.effective_field.clone()
            };
            println!(
                "  {:<24} {:<10} {:<10} {:<10} {:<22} {}",
                result.requested_backend,
                ok_str(result.compile_ok),
                ok_str(result.prove_ok),
                ok_str(result.verify_ok),
                field_summary,
                result.error.as_deref().unwrap_or("-"),
            );
            if result.verify_ok {
                println!(
                    "  {:<24} public_outputs={}",
                    "",
                    if result.public_outputs.is_empty() {
                        "[]".to_string()
                    } else {
                        format!("[{}]", result.public_outputs.join(", "))
                    }
                );
            }
        }

        if report.equivalent {
            println!("\nAll requested backends produced matching verified public outputs.");
        } else if !report.mismatches.is_empty() {
            println!("\nMismatches:");
            for mismatch in &report.mismatches {
                println!("  - {mismatch}");
            }
        }
    }

    if report.equivalent {
        Ok(())
    } else {
        Err(
            "equivalence test failed: backends did not produce matching verified outputs"
                .to_string(),
        )
    }
}

pub(crate) fn run_equivalence_report(
    program: &Program,
    inputs: &WitnessInputs,
    options: EquivalenceOptions,
) -> Result<EquivalenceReport, String> {
    if options.backends.is_empty() {
        return Err("at least one backend must be specified via --backends".to_string());
    }

    let mut resolved_inputs = inputs.clone();
    resolve_input_aliases(&mut resolved_inputs, program);

    let mut results = Vec::with_capacity(options.backends.len());
    let mut verified_outputs = Vec::new();

    for backend_name in &options.backends {
        let request = parse_backend_request(backend_name)?;
        ensure_backend_request_allowed(&request, options.allow_compat)?;

        let requested_field = program.field;
        let target_field = crate::compose::backend_default_field(request.backend);
        let compatibility_reasons = field_adaptation_compatibility_reasons(program, target_field);
        let (mut adapted_program, adapted_inputs, field_adapted) =
            if compatibility_reasons.is_empty() {
                adapt_program_and_inputs(program, &resolved_inputs, request.backend)
            } else {
                (program.clone(), resolved_inputs.clone(), false)
            };
        attach_groth16_setup_blob_path(
            &mut adapted_program,
            request.backend,
            options.groth16_setup_blob.as_deref(),
        );

        let mut result = BackendEquivalenceReport {
            requested_backend: request.requested_name.clone(),
            effective_backend: request.backend.as_str().to_string(),
            requested_field: requested_field.as_str().to_string(),
            effective_field: adapted_program.field.as_str().to_string(),
            field_adapted,
            compatibility_ok: compatibility_reasons.is_empty(),
            compatibility_reasons,
            public_outputs: Vec::new(),
            compile_ok: false,
            prove_ok: false,
            verify_ok: false,
            error: None,
        };
        if !result.compatibility_ok {
            result.error = Some("compatibility: field adaptation blocked".to_string());
            results.push(result);
            continue;
        }
        ensure_backend_supports_program_constraints(request.backend, &adapted_program)?;
        warn_if_r1cs_lookup_limit_exceeded(request.backend, &adapted_program, "zkf equivalence");

        let prepared = match prepare_witness_for_request_from_inputs(
            &adapted_program,
            &adapted_inputs,
            None,
            &request,
            options.seed,
            options.groth16_setup_blob.as_deref(),
            options.allow_dev_deterministic_groth16,
            "zkf equivalence",
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                let message = err.to_ascii_lowercase();
                result.error = Some(
                    if message.contains("witness") || message.contains("missing") {
                        format!("witness: {err}")
                    } else {
                        format!("compile: {err}")
                    },
                );
                results.push(result);
                continue;
            }
        };
        let compiled = prepared.compiled;
        result.compile_ok = true;
        result.effective_backend = compiled.backend.as_str().to_string();
        result.effective_field = compiled.program.field.as_str().to_string();

        let engine = backend_for_request(&request);
        let execution = with_equivalence_overrides(&options, || {
            RuntimeExecutor::run_backend_prove_job(
                request.backend,
                request.route,
                Arc::new(adapted_program.clone()),
                None,
                Some(Arc::new(prepared.prepared_witness.clone())),
                Some(Arc::new(compiled.clone())),
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .map_err(|err| err.to_string())
        });
        let execution = match execution {
            Ok(execution) => {
                result.prove_ok = true;
                result.effective_backend = execution.compiled.backend.as_str().to_string();
                result.effective_field = execution.compiled.program.field.as_str().to_string();
                result.public_outputs = execution
                    .artifact
                    .public_inputs
                    .iter()
                    .map(FieldElement::to_decimal_string)
                    .collect();
                execution
            }
            Err(err) => {
                result.error = Some(format!("prove: {err}"));
                results.push(result);
                continue;
            }
        };

        match engine.verify(&execution.compiled, &execution.artifact) {
            Ok(true) => {
                result.verify_ok = true;
                verified_outputs.push((
                    result.requested_backend.clone(),
                    result.public_outputs.clone(),
                ));
            }
            Ok(false) => {
                result.error = Some("verify: verification returned false".to_string());
            }
            Err(err) => {
                result.error = Some(format!("verify: {err}"));
            }
        }

        results.push(result);
    }

    let mismatches = collect_output_mismatches(&verified_outputs);
    let equivalent = !results.is_empty()
        && results.iter().all(|result| result.verify_ok)
        && mismatches.is_empty();

    Ok(EquivalenceReport {
        equivalent,
        program_name: program.name.clone(),
        program_digest: program.digest_hex(),
        requested_field: program.field.as_str().to_string(),
        results,
        mismatches,
    })
}

fn with_equivalence_overrides<T>(
    options: &EquivalenceOptions,
    op: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let groth16_setup_blob_override = options
        .groth16_setup_blob
        .as_ref()
        .map(|path| path_to_override_string(path.as_path()));
    with_allow_dev_deterministic_groth16_override(
        options.allow_dev_deterministic_groth16.then_some(true),
        || {
            with_groth16_setup_blob_path_override(groth16_setup_blob_override, || {
                with_setup_seed_override(options.seed, || {
                    with_proof_seed_override(options.seed, op)
                })
            })
        },
    )
}

fn path_to_override_string(path: &Path) -> String {
    path.display().to_string()
}

fn collect_output_mismatches(verified_outputs: &[(String, Vec<String>)]) -> Vec<String> {
    let Some((_, reference_outputs)) = verified_outputs.first() else {
        return Vec::new();
    };

    verified_outputs
        .iter()
        .filter(|(_, outputs)| outputs != reference_outputs)
        .map(|(backend, outputs)| {
            format!(
                "backend '{}' produced public outputs {:?}, expected {:?}",
                backend, outputs, reference_outputs
            )
        })
        .collect()
}

fn adapt_program_and_inputs(
    program: &Program,
    inputs: &WitnessInputs,
    backend: BackendKind,
) -> (Program, WitnessInputs, bool) {
    let target_field = crate::compose::backend_default_field(backend);
    if program.field == target_field {
        return (program.clone(), inputs.clone(), false);
    }

    let mut adapted_program = program.clone();
    adapted_program.field = target_field;
    for signal in &mut adapted_program.signals {
        if let Some(constant) = signal.constant.as_ref() {
            signal.constant = Some(adapt_field_element(constant, program.field, target_field));
        }
    }
    adapted_program.constraints = adapted_program
        .constraints
        .iter()
        .map(|constraint| adapt_constraint(constraint, program.field, target_field))
        .collect();
    adapted_program.witness_plan.assignments = adapted_program
        .witness_plan
        .assignments
        .iter()
        .map(|assignment| WitnessAssignment {
            target: assignment.target.clone(),
            expr: adapt_expr(&assignment.expr, program.field, target_field),
        })
        .collect();
    for table in &mut adapted_program.lookup_tables {
        for row in &mut table.values {
            for value in row {
                *value = adapt_field_element(value, program.field, target_field);
            }
        }
    }

    let adapted_inputs = inputs
        .iter()
        .map(|(name, value)| {
            (
                name.clone(),
                adapt_field_element(value, program.field, target_field),
            )
        })
        .collect();

    (adapted_program, adapted_inputs, true)
}

fn field_adaptation_compatibility_reasons(program: &Program, target_field: FieldId) -> Vec<String> {
    if program.field == target_field {
        return Vec::new();
    }

    program
        .constraints
        .iter()
        .filter_map(|constraint| {
            let Constraint::BlackBox { op, label, .. } = constraint else {
                return None;
            };
            let op_name = op.as_str();
            let field_specific = matches!(
                op,
                BlackBoxOp::Poseidon | BlackBoxOp::Pedersen | BlackBoxOp::SchnorrVerify
            );
            field_specific.then(|| {
                let label_suffix = label
                    .as_deref()
                    .map(|value| format!(" label='{value}'"))
                    .unwrap_or_default();
                format!(
                    "blackbox '{}'{} is field-specific on {}; refusing to adapt this circuit to {}",
                    op_name, label_suffix, program.field, target_field
                )
            })
        })
        .collect()
}

fn adapt_constraint(
    constraint: &Constraint,
    source_field: FieldId,
    target_field: FieldId,
) -> Constraint {
    match constraint {
        Constraint::Equal { lhs, rhs, label } => Constraint::Equal {
            lhs: adapt_expr(lhs, source_field, target_field),
            rhs: adapt_expr(rhs, source_field, target_field),
            label: label.clone(),
        },
        Constraint::Boolean { signal, label } => Constraint::Boolean {
            signal: signal.clone(),
            label: label.clone(),
        },
        Constraint::Range {
            signal,
            bits,
            label,
        } => Constraint::Range {
            signal: signal.clone(),
            bits: *bits,
            label: label.clone(),
        },
        Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } => Constraint::BlackBox {
            op: *op,
            inputs: inputs
                .iter()
                .map(|expr| adapt_expr(expr, source_field, target_field))
                .collect(),
            outputs: outputs.clone(),
            params: params.clone(),
            label: label.clone(),
        },
        Constraint::Lookup {
            inputs,
            table,
            outputs,
            label,
        } => Constraint::Lookup {
            inputs: inputs
                .iter()
                .map(|expr| adapt_expr(expr, source_field, target_field))
                .collect(),
            table: table.clone(),
            outputs: outputs.clone(),
            label: label.clone(),
        },
    }
}

fn adapt_expr(expr: &Expr, source_field: FieldId, target_field: FieldId) -> Expr {
    match expr {
        Expr::Const(value) => Expr::Const(adapt_field_element(value, source_field, target_field)),
        Expr::Signal(name) => Expr::Signal(name.clone()),
        Expr::Add(terms) => Expr::Add(
            terms
                .iter()
                .map(|term| adapt_expr(term, source_field, target_field))
                .collect(),
        ),
        Expr::Sub(lhs, rhs) => Expr::Sub(
            Box::new(adapt_expr(lhs, source_field, target_field)),
            Box::new(adapt_expr(rhs, source_field, target_field)),
        ),
        Expr::Mul(lhs, rhs) => Expr::Mul(
            Box::new(adapt_expr(lhs, source_field, target_field)),
            Box::new(adapt_expr(rhs, source_field, target_field)),
        ),
        Expr::Div(lhs, rhs) => Expr::Div(
            Box::new(adapt_expr(lhs, source_field, target_field)),
            Box::new(adapt_expr(rhs, source_field, target_field)),
        ),
    }
}

fn adapt_field_element(
    value: &FieldElement,
    source_field: FieldId,
    target_field: FieldId,
) -> FieldElement {
    if source_field == target_field {
        return value.clone();
    }

    let normalized = value
        .normalized_bigint(source_field)
        .expect("field element normalization should not fail");
    FieldElement::from_bigint_with_field(normalized, target_field)
}
