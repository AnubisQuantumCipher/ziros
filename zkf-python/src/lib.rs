//! Python bindings for ZirOS (formerly ZKF).
//!
//! Exposes core ZirOS / ZKF functionality to Python via PyO3: loading programs,
//! normalization, type checking, compilation, proving, verification, and auditing.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::BTreeMap;
use std::str::FromStr;

use zkf_backends::{
    BackendSelection, backend_capability_matrix, backend_for_selection,
    ensure_backend_selection_production_ready, parse_backend_selection,
    preferred_backend_for_field, validate_backend_selection_identity,
};
use zkf_core::{CompiledProgram, Program, ProofArtifact, WitnessInputs, generate_witness};
use zkf_frontends::{
    FrontendImportOptions, FrontendInspection, FrontendKind, default_frontend_translator,
    frontend_for,
};
use zkf_ir_spec::{IR_SPEC_MAJOR, IR_SPEC_MINOR};

fn parse_public_backend_selection_py(backend: &str) -> PyResult<BackendSelection> {
    let selection = parse_backend_selection(backend).map_err(PyErr::new::<PyValueError, _>)?;
    validate_backend_selection_identity(&selection).map_err(PyErr::new::<PyValueError, _>)?;
    Ok(selection)
}

fn parse_execution_backend_selection_py(backend: &str) -> PyResult<BackendSelection> {
    let selection = parse_public_backend_selection_py(backend)?;
    ensure_backend_selection_production_ready(&selection).map_err(PyErr::new::<PyValueError, _>)?;
    Ok(selection)
}

/// Return the ZirOS framework version string.
#[pyfunction]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Return the IR specification version as a dict with "major" and "minor" keys.
#[pyfunction]
fn ir_version(py: Python<'_>) -> PyResult<PyObject> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("major", IR_SPEC_MAJOR)?;
    dict.set_item("minor", IR_SPEC_MINOR)?;
    Ok(dict.into())
}

/// Return the backend capability matrix as a JSON string.
#[pyfunction]
fn capability_matrix() -> PyResult<String> {
    let matrix = backend_capability_matrix();
    serde_json::to_string(&matrix)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Build a ZirOS program from an AppSpecV1 JSON payload.
#[pyfunction]
fn build_app_spec(spec_json: &str) -> PyResult<String> {
    let spec: zkf_lib::AppSpecV1 = serde_json::from_str(spec_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid app spec JSON: {e}")))?;
    let program = zkf_lib::build_app_spec(&spec)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("app spec build error: {e}")))?;
    serde_json::to_string(&program)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Return the shared declarative app-template registry as JSON.
#[pyfunction]
fn template_registry() -> PyResult<String> {
    serde_json::to_string(&zkf_lib::template_registry())
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Instantiate a shared template into AppSpecV1 JSON.
#[pyfunction(signature = (template_id, template_args_json=None))]
fn instantiate_template(template_id: &str, template_args_json: Option<&str>) -> PyResult<String> {
    let template_args = match template_args_json {
        Some(json) => serde_json::from_str::<BTreeMap<String, String>>(json).map_err(|e| {
            PyErr::new::<PyValueError, _>(format!("invalid template args JSON: {e}"))
        })?,
        None => BTreeMap::new(),
    };
    let spec = zkf_lib::instantiate_template(template_id, &template_args)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("template instantiation error: {e}")))?;
    serde_json::to_string(&spec)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Load a ZirOS / ZKF program from a JSON file at the given path.
///
/// Returns the program as a JSON string.
#[pyfunction]
fn load_program(path: &str) -> PyResult<String> {
    let program = zkf_lib::load_program(path)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("failed to load program: {e}")))?;
    serde_json::to_string(&program)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Normalize a ZIR program.
///
/// Takes a program as a JSON string (IR v2 format), converts to ZIR,
/// normalizes it, and returns JSON with the normalized program and report.
#[pyfunction]
fn normalize(program_json: &str) -> PyResult<String> {
    let v2_program: Program = serde_json::from_str(program_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid program JSON: {e}")))?;

    let zir_program = zkf_core::lowering::program_v2_to_zir(&v2_program);
    let (normalized, report) = zkf_core::normalize::normalize(&zir_program);

    let result = serde_json::json!({
        "program": normalized,
        "report": report,
    });

    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Type-check a ZIR program.
///
/// Takes a program as a JSON string (IR v2 format), converts to ZIR,
/// and type-checks it. Returns a list of error strings (empty means OK).
#[pyfunction]
fn type_check(program_json: &str) -> PyResult<Vec<String>> {
    let v2_program: Program = serde_json::from_str(program_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid program JSON: {e}")))?;

    let zir_program = zkf_core::lowering::program_v2_to_zir(&v2_program);

    match zkf_core::type_check::type_check(&zir_program) {
        Ok(()) => Ok(Vec::new()),
        Err(errors) => Ok(errors.iter().map(|e| e.to_string()).collect()),
    }
}

/// Compile a program for a specific backend.
///
/// Takes a program JSON string and a backend name (e.g. "plonky3", "halo2",
/// "arkworks-groth16"). Returns the compiled program as a JSON string.
#[pyfunction]
fn compile(program_json: &str, backend: &str) -> PyResult<String> {
    let program: Program = serde_json::from_str(program_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid program JSON: {e}")))?;

    let selection = parse_execution_backend_selection_py(backend)?;
    let engine = backend_for_selection(&selection).map_err(PyErr::new::<PyValueError, _>)?;
    let compiled = engine
        .compile(&program)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("compilation error: {e}")))?;

    serde_json::to_string(&compiled)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Generate a proof for a program.
///
/// Takes the program JSON, compiled program JSON, witness inputs JSON (a map
/// of signal name to field element value), and a backend name. Returns the
/// proof artifact as a JSON string.
#[pyfunction(signature = (program_json, compiled_json, inputs_json, backend = "", hybrid = false))]
fn prove(
    program_json: &str,
    compiled_json: &str,
    inputs_json: &str,
    backend: &str,
    hybrid: bool,
) -> PyResult<String> {
    if hybrid && !backend.is_empty() && backend != "plonky3" {
        return Err(PyErr::new::<PyValueError, _>(
            "hybrid proving currently requires backend='plonky3' or an empty backend",
        ));
    }
    let program: Program = serde_json::from_str(program_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid program JSON: {e}")))?;

    let compiled: CompiledProgram = serde_json::from_str(compiled_json).map_err(|e| {
        PyErr::new::<PyValueError, _>(format!("invalid compiled program JSON: {e}"))
    })?;

    let inputs: WitnessInputs = serde_json::from_str(inputs_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid inputs JSON: {e}")))?;

    let witness = generate_witness(&program, &inputs)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("witness generation error: {e}")))?;

    let selection = if hybrid {
        BackendSelection::native(zkf_core::BackendKind::Plonky3)
    } else if backend.is_empty() {
        BackendSelection::native(preferred_backend_for_field(program.field))
    } else {
        parse_execution_backend_selection_py(backend)?
    };
    let artifact = if hybrid {
        zkf_runtime::run_hybrid_prove_job_with_objective(
            std::sync::Arc::new(program.clone()),
            None,
            Some(std::sync::Arc::new(witness)),
            zkf_runtime::OptimizationObjective::FastestProve,
            zkf_runtime::RequiredTrustLane::StrictCryptographic,
            zkf_runtime::ExecutionMode::Deterministic,
        )
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("hybrid proving error: {e}")))?
        .artifact
    } else {
        zkf_runtime::RuntimeExecutor::run_backend_prove_job(
            selection.backend,
            selection.route,
            std::sync::Arc::new(program.clone()),
            None,
            Some(std::sync::Arc::new(witness)),
            Some(std::sync::Arc::new(compiled)),
            zkf_runtime::RequiredTrustLane::StrictCryptographic,
            zkf_runtime::ExecutionMode::Deterministic,
        )
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("proving error: {e}")))?
        .artifact
    };

    serde_json::to_string(&artifact)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Verify a proof.
///
/// Takes the compiled program JSON, proof artifact JSON, and a backend name.
/// Returns True if the proof is valid, False otherwise.
#[pyfunction(signature = (compiled_json, proof_json, backend = "", hybrid = false))]
fn verify(compiled_json: &str, proof_json: &str, backend: &str, hybrid: bool) -> PyResult<bool> {
    let compiled: CompiledProgram = serde_json::from_str(compiled_json).map_err(|e| {
        PyErr::new::<PyValueError, _>(format!("invalid compiled program JSON: {e}"))
    })?;

    let artifact: ProofArtifact = serde_json::from_str(proof_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid proof JSON: {e}")))?;

    if hybrid || artifact.hybrid_bundle.is_some() {
        return zkf_runtime::verify_hybrid_artifact(&compiled.program, &artifact)
            .map_err(|e| PyErr::new::<PyValueError, _>(format!("hybrid verification error: {e}")));
    }

    let selection = parse_public_backend_selection_py(backend)?;
    let engine = backend_for_selection(&selection).map_err(PyErr::new::<PyValueError, _>)?;
    engine
        .verify(&compiled, &artifact)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("verification error: {e}")))
}

/// Audit a program.
///
/// Takes a program JSON string and an optional backend name. Returns the
/// audit report as a JSON string.
#[pyfunction]
fn audit(program_json: &str, backend: &str) -> PyResult<String> {
    let v2_program: Program = serde_json::from_str(program_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid program JSON: {e}")))?;

    let zir_program = zkf_core::lowering::program_v2_to_zir(&v2_program);

    let backend_kind = if backend.is_empty() {
        None
    } else {
        Some(parse_public_backend_selection_py(backend)?.backend)
    };

    let matrix = backend_capability_matrix();
    let report =
        zkf_core::audit::audit_program_with_capability_matrix(&zir_program, backend_kind, &matrix);

    serde_json::to_string(&report)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

fn parse_frontend_kind_py(frontend: &str) -> PyResult<FrontendKind> {
    FrontendKind::from_str(frontend)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid frontend: {e}")))
}

/// Import a frontend circuit artifact into canonical ZirOS / ZKF IR JSON.
#[pyfunction(signature = (frontend, artifact_json, name=None, allow_unsupported_version=false))]
fn import_circuit(
    frontend: &str,
    artifact_json: &str,
    name: Option<String>,
    allow_unsupported_version: bool,
) -> PyResult<String> {
    let frontend_kind = parse_frontend_kind_py(frontend)?;
    let artifact: serde_json::Value = serde_json::from_str(artifact_json).map_err(|e| {
        PyErr::new::<PyValueError, _>(format!("invalid frontend artifact JSON: {e}"))
    })?;
    let program = frontend_for(frontend_kind)
        .compile_to_ir(
            &artifact,
            &FrontendImportOptions {
                program_name: name,
                allow_unsupported_versions: allow_unsupported_version,
                translator: Some(default_frontend_translator()),
                ..Default::default()
            },
        )
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("frontend import error: {e}")))?;
    serde_json::to_string(&program)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// Inspect a frontend artifact or canonical IR program and return a JSON summary.
#[pyfunction(signature = (payload_json, frontend=None, backend=None))]
fn inspect(payload_json: &str, frontend: Option<&str>, backend: Option<&str>) -> PyResult<String> {
    if let Some(frontend_name) = frontend {
        let frontend_kind = parse_frontend_kind_py(frontend_name)?;
        let artifact: serde_json::Value = serde_json::from_str(payload_json).map_err(|e| {
            PyErr::new::<PyValueError, _>(format!("invalid frontend artifact JSON: {e}"))
        })?;
        let inspection: FrontendInspection = frontend_for(frontend_kind)
            .inspect(&artifact)
            .map_err(|e| {
                PyErr::new::<PyValueError, _>(format!("frontend inspection error: {e}"))
            })?;
        return serde_json::to_string(&inspection)
            .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")));
    }

    let program: Program = serde_json::from_str(payload_json)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("invalid program JSON: {e}")))?;
    let preferred_backend = preferred_backend_for_field(program.field);
    let backend_kind = if let Some(backend_name) = backend {
        Some(parse_public_backend_selection_py(backend_name)?.backend)
    } else {
        None
    };
    let matrix = backend_capability_matrix();
    let zir_program = zkf_core::lowering::program_v2_to_zir(&program);
    let audit =
        zkf_core::audit::audit_program_with_capability_matrix(&zir_program, backend_kind, &matrix);
    let summary = serde_json::json!({
        "program": {
            "name": program.name,
            "field": program.field,
            "signals": program.signals.len(),
            "public_signals": program.signals.iter().filter(|signal| signal.visibility == zkf_core::Visibility::Public).count(),
            "private_signals": program.signals.iter().filter(|signal| signal.visibility == zkf_core::Visibility::Private).count(),
            "constraints": program.constraints.len(),
        },
        "preferred_backend": preferred_backend.as_str(),
        "audit": audit,
    });
    serde_json::to_string(&summary)
        .map_err(|e| PyErr::new::<PyValueError, _>(format!("serialization error: {e}")))
}

/// ZirOS Python module — Python bindings for ZirOS (formerly ZKF).
#[pymodule(name = "zkf")]
fn zkf_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(ir_version, m)?)?;
    m.add_function(wrap_pyfunction!(capability_matrix, m)?)?;
    m.add_function(wrap_pyfunction!(build_app_spec, m)?)?;
    m.add_function(wrap_pyfunction!(template_registry, m)?)?;
    m.add_function(wrap_pyfunction!(instantiate_template, m)?)?;
    m.add_function(wrap_pyfunction!(load_program, m)?)?;
    m.add_function(wrap_pyfunction!(normalize, m)?)?;
    m.add_function(wrap_pyfunction!(type_check, m)?)?;
    m.add_function(wrap_pyfunction!(compile, m)?)?;
    m.add_function(wrap_pyfunction!(prove, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(audit, m)?)?;
    m.add_function(wrap_pyfunction!(import_circuit, m)?)?;
    m.add_function(wrap_pyfunction!(inspect, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zkf_core::{
        Constraint, Expr, FieldId, Program, Signal, Visibility, WitnessAssignment, WitnessPlan,
    };

    fn init_python() {
        pyo3::prepare_freethreaded_python();
    }

    fn addition_program(field: FieldId, name: &str) -> Program {
        Program {
            name: name.to_string(),
            field,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "sum".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("sum"),
                rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                label: Some("sum".to_string()),
            }],
            witness_plan: WitnessPlan {
                assignments: vec![WitnessAssignment {
                    target: "sum".to_string(),
                    expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
                }],
                hints: Vec::new(),
                ..Default::default()
            },
            ..Program::default()
        }
    }

    #[test]
    fn capability_matrix_labels_implementation_type_and_compat_aliases() {
        init_python();
        let matrix: serde_json::Value =
            serde_json::from_str(&capability_matrix().expect("capability matrix"))
                .expect("matrix json");
        let entries = matrix["entries"].as_array().expect("entries array");
        let sp1 = entries
            .iter()
            .find(|entry| entry["backend"] == "sp1")
            .expect("sp1 entry");
        let notes = sp1["notes"].as_str().expect("notes string");
        assert!(notes.contains("implementation_type="));
        assert!(notes.contains("explicit_compat_alias=sp1-compat"));
    }

    #[test]
    fn compile_prove_verify_and_program_inspect_roundtrip() {
        init_python();
        let program =
            serde_json::to_string(&addition_program(FieldId::Goldilocks, "python-plonky3"))
                .expect("program json");
        let compiled = compile(&program, "plonky3").expect("compile should succeed");
        let proof = prove(
            &program,
            &compiled,
            &json!({"x": "2", "y": "5"}).to_string(),
            "plonky3",
            false,
        )
        .expect("prove should succeed");
        assert!(verify(&compiled, &proof, "plonky3", false).expect("verify should succeed"));

        let inspection: serde_json::Value =
            serde_json::from_str(&inspect(&program, None, Some("plonky3")).expect("inspect"))
                .expect("inspect json");
        assert_eq!(inspection["program"]["constraints"], 1);
        assert_eq!(inspection["program"]["signals"], 3);
        assert_eq!(inspection["preferred_backend"], "plonky3");
    }

    #[test]
    fn import_circuit_and_frontend_inspect_work_on_descriptor_passthrough() {
        init_python();
        let program = addition_program(FieldId::Bn254, "python-circom-import");
        let descriptor = json!({ "program": program });
        let descriptor_json = descriptor.to_string();

        let imported = import_circuit(
            "circom",
            &descriptor_json,
            Some("renamed".to_string()),
            false,
        )
        .expect("import should succeed");
        let imported_program: Program =
            serde_json::from_str(&imported).expect("imported program json");
        assert_eq!(imported_program.name, "renamed");
        assert_eq!(imported_program.field, FieldId::Bn254);

        let inspection: serde_json::Value = serde_json::from_str(
            &inspect(&descriptor_json, Some("circom"), None).expect("inspect"),
        )
        .expect("frontend inspection json");
        assert_eq!(inspection["frontend"], "circom");
    }

    #[test]
    fn app_spec_and_template_registry_surface_work() {
        init_python();
        let registry: serde_json::Value =
            serde_json::from_str(&template_registry().expect("template registry"))
                .expect("registry json");
        assert!(registry.as_array().is_some());
        assert!(
            registry
                .as_array()
                .expect("registry array")
                .iter()
                .any(|entry| entry["id"] == "private-vote")
        );

        let spec = instantiate_template(
            "merkle-membership",
            Some(&json!({"depth": "1"}).to_string()),
        )
        .expect("instantiate template");
        let program = build_app_spec(&spec).expect("build program from spec");
        let inspection: serde_json::Value = serde_json::from_str(
            &inspect(&program, None, Some("arkworks-groth16")).expect("inspect"),
        )
        .expect("inspection json");
        assert_eq!(inspection["program"]["name"], "merkle_membership_depth_1");
    }

    #[test]
    fn compile_prove_verify_from_app_spec_json() {
        init_python();
        let spec = json!({
            "program": { "name": "python-app-spec", "field": "goldilocks" },
            "signals": [
                { "name": "x", "visibility": "private" },
                { "name": "limit", "visibility": "public" },
                { "name": "gap", "visibility": "private" },
                { "name": "ok", "visibility": "public" }
            ],
            "ops": [
                { "kind": "leq", "slack": "gap", "lhs": { "op": "signal", "args": "x" }, "rhs": { "op": "signal", "args": "limit" }, "bits": 8, "label": "x_within_limit" },
                { "kind": "equal", "lhs": { "op": "signal", "args": "ok" }, "rhs": { "op": "const", "args": "1" }, "label": "ok_asserted" }
            ]
        })
        .to_string();

        let program = build_app_spec(&spec).expect("build app spec");
        let compiled = compile(&program, "plonky3").expect("compile");
        let proof = prove(
            &program,
            &compiled,
            &json!({"x": "5", "limit": "9", "ok": "1"}).to_string(),
            "plonky3",
            false,
        )
        .expect("prove");
        assert!(verify(&compiled, &proof, "plonky3", false).expect("verify"));
    }
}
