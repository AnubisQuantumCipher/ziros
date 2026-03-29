use std::path::PathBuf;
use std::sync::Arc;

use crate::util::{load_program_v2, resolve_input_aliases};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

pub(crate) fn handle_test_vectors(
    program: PathBuf,
    vectors: PathBuf,
    backends: Option<Vec<String>>,
    json: bool,
) -> Result<(), String> {
    let ir_program = load_program_v2(&program)?;

    let vectors_data = std::fs::read_to_string(&vectors)
        .map_err(|e| format!("failed to read vectors: {}: {}", vectors.display(), e))?;

    // Support both plain array and {"vectors": [...]} wrapper
    let test_vectors: Vec<serde_json::Value> = {
        let raw: serde_json::Value = serde_json::from_str(&vectors_data)
            .map_err(|e| format!("failed to parse test vectors: {}", e))?;
        match raw {
            serde_json::Value::Array(arr) => arr,
            serde_json::Value::Object(ref map) if map.contains_key("vectors") => {
                serde_json::from_value(map["vectors"].clone())
                    .map_err(|e| format!("failed to parse vectors array: {}", e))?
            }
            _ => {
                return Err("test vectors must be a JSON array or {\"vectors\": [...]}".to_string());
            }
        }
    };

    let backend_names = backends.unwrap_or_else(|| vec!["plonky3".to_string()]);
    let mut results = Vec::new();

    // Auto-detect solver from program metadata
    let solver_name = ir_program.metadata.get("solver").map(String::as_str);

    for (idx, vector) in test_vectors.iter().enumerate() {
        let vector_name = vector
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");

        let mut inputs: zkf_core::WitnessInputs = serde_json::from_value(
            vector
                .get("inputs")
                .cloned()
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
        )
        .map_err(|e| format!("test vector {}: invalid inputs: {}", idx, e))?;

        resolve_input_aliases(&mut inputs, &ir_program);

        let expected_pass = vector
            .get("expect_pass")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Generate witness using solver if available, otherwise built-in
        let witness_result = if let Some(solver_name) = solver_name {
            zkf_core::solver_by_name(solver_name)
                .and_then(|solver| zkf_core::solve_witness(&ir_program, &inputs, solver.as_ref()))
        } else {
            zkf_core::generate_witness_unchecked(&ir_program, &inputs)
        };

        for backend_name in &backend_names {
            let backend_kind = crate::util::parse_backend(backend_name)?;
            let backend = zkf_backends::backend_for(backend_kind);

            // Adapt program field to match the backend's native field
            let target_field = crate::compose::backend_default_field(backend_kind);
            let adapted_program = if ir_program.field != target_field {
                let mut p = ir_program.clone();
                p.field = target_field;
                // Re-encode field constants for the target field
                for signal in &mut p.signals {
                    if let Some(ref c) = signal.constant {
                        signal.constant = Some(zkf_core::FieldElement::from_bigint_with_field(
                            c.normalized_bigint(ir_program.field).unwrap_or_default(),
                            target_field,
                        ));
                    }
                }
                p
            } else {
                ir_program.clone()
            };

            // Re-generate witness for this field if needed
            let backend_witness = if ir_program.field != target_field {
                zkf_core::generate_witness_unchecked(&adapted_program, &inputs).ok()
            } else {
                witness_result.as_ref().ok().cloned()
            };

            let test_result = if let Some(ref witness) = backend_witness {
                match RuntimeExecutor::run_backend_prove_job(
                    backend_kind,
                    zkf_backends::BackendRoute::Auto,
                    Arc::new(adapted_program.clone()),
                    None,
                    Some(Arc::new(witness.clone())),
                    None,
                    RequiredTrustLane::StrictCryptographic,
                    ExecutionMode::Deterministic,
                ) {
                    Ok(execution) => {
                        let verified = backend.verify(&execution.compiled, &execution.artifact);
                        match verified {
                            Ok(true) => "pass",
                            Ok(false) => "verify_failed",
                            Err(_) => "verify_error",
                        }
                    }
                    Err(_) => "prove_error",
                }
            } else {
                "witness_error"
            };

            let passed = (test_result == "pass") == expected_pass;

            results.push(serde_json::json!({
                "vector_index": idx,
                "vector_name": vector_name,
                "backend": backend_name,
                "result": test_result,
                "expected_pass": expected_pass,
                "passed": passed,
            }));
        }
    }

    let all_passed = results
        .iter()
        .all(|r| r["passed"].as_bool().unwrap_or(false));

    if json {
        let report = serde_json::json!({
            "all_passed": all_passed,
            "total_vectors": test_vectors.len(),
            "total_tests": results.len(),
            "results": results,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "Test vectors: {} vectors x {} backends = {} tests",
            test_vectors.len(),
            backend_names.len(),
            results.len()
        );
        // Print table header
        println!(
            "  {:<12} {:<20} {:<16} status",
            "vector", "backend", "result"
        );
        println!("  {}", "-".repeat(60));
        for result in &results {
            let status = if result["passed"].as_bool().unwrap_or(false) {
                "OK"
            } else {
                "FAIL"
            };
            println!(
                "  {:<12} {:<20} {:<16} {}",
                result["vector_name"].as_str().unwrap_or("?"),
                result["backend"].as_str().unwrap_or("?"),
                result["result"].as_str().unwrap_or("?"),
                status
            );
        }
        if all_passed {
            println!("\nAll tests passed.");
        } else {
            return Err("some test vectors failed".to_string());
        }
    }

    Ok(())
}
