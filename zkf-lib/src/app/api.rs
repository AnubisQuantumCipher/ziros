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

use super::progress::{ProofEvent, ProofStage};
use super::spec::{AppSpecV1, build_app_spec};
use crate::proof_embedded_app_spec::{
    canonical_input_key_string, default_backend_for_field_spec, program_digest_guard_accepts,
    program_mismatch_fields,
};
use std::time::Instant;
use zkf_backends::{
    BackendRoute, BackendSelection, backend_for_route, ensure_security_covered_groth16_setup,
    parse_backend_selection, validate_backend_selection_identity,
};
#[cfg(feature = "full")]
use zkf_core::{
    AuditReport, DiagnosticsReport, analyze_program, audit_program, program_v2_to_zir,
    solve_and_validate_witness, solver_by_name,
};
use zkf_core::{
    BackendCapabilityMatrix, BackendKind, CompiledProgram, FieldElement, FieldId, Program,
    ProofArtifact, Witness, WitnessInputs, ZkfError, ZkfResult, collect_public_inputs,
    ensure_witness_completeness, generate_witness, program_zir_to_v2,
};

/// Result of an embedded compile+prove flow.
#[derive(Debug, Clone)]
pub struct EmbeddedProof {
    pub compiled: CompiledProgram,
    pub artifact: ProofArtifact,
}

/// Result of an embedded compile+check flow that validates witness generation
/// without invoking the prover.
#[derive(Debug, Clone)]
pub struct EmbeddedCheck {
    pub compiled: CompiledProgram,
    pub witness: Witness,
    pub public_inputs: Vec<FieldElement>,
    #[cfg(feature = "full")]
    pub audit: AuditReport,
    #[cfg(feature = "full")]
    pub diagnostics: DiagnosticsReport,
}

/// Load a ZirOS program from a JSON file.
///
/// Accepts:
/// - `ir-v2` lowered programs
/// - `zir-v1` interchange programs
/// - `zirapp.json` declarative `AppSpecV1` specifications
pub fn load_program(path: &str) -> ZkfResult<Program> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ZkfError::Io(format!("failed to read {path}: {e}")))?;
    if let Ok(spec) = serde_json::from_str::<AppSpecV1>(&content) {
        return build_app_spec(&spec);
    }
    if let Ok(program) = serde_json::from_str::<zkf_core::zir_v1::Program>(&content) {
        return program_zir_to_v2(&program);
    }
    if let Ok(program) = serde_json::from_str::<Program>(&content) {
        return Ok(program);
    }
    Err(ZkfError::Serialization(
        "failed to parse program: expected 'ir-v2', 'zir-v1', or 'zirapp' JSON".to_string(),
    ))
}

/// Load witness inputs from a JSON file.
pub fn load_inputs(path: &str) -> ZkfResult<WitnessInputs> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ZkfError::Io(format!("failed to read {path}: {e}")))?;
    serde_json::from_str(&content)
        .map_err(|e| ZkfError::Serialization(format!("failed to parse inputs: {e}")))
}

/// Get the backend capability matrix (single source of truth).
#[cfg(feature = "full")]
pub fn capability_matrix() -> BackendCapabilityMatrix {
    zkf_backends::backend_capability_matrix()
}

/// Get the ZKF library version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get the IR specification version.
pub fn ir_version() -> zkf_ir_spec::version::IrVersion {
    zkf_ir_spec::version::IrVersion {
        major: zkf_ir_spec::IR_SPEC_MAJOR,
        minor: zkf_ir_spec::IR_SPEC_MINOR,
    }
}

fn route_label(route: BackendRoute) -> &'static str {
    match route {
        BackendRoute::Auto => "native-auto",
        BackendRoute::ExplicitCompat => "explicit-compat",
    }
}

#[allow(dead_code)]
pub(crate) fn canonical_input_key<T: Clone>(requested: T, alias_target: Option<T>) -> T {
    alias_target.unwrap_or(requested)
}

pub(crate) fn ensure_matching_program_digest(expected: &str, found: &str) -> ZkfResult<()> {
    if program_digest_guard_accepts(expected.to_string(), found.to_string()) {
        Ok(())
    } else {
        let mismatch = program_mismatch_fields(expected.to_string(), found.to_string());
        Err(ZkfError::ProgramMismatch {
            expected: mismatch.expected,
            found: mismatch.found,
        })
    }
}

pub(crate) fn default_backend_for_field(field: FieldId) -> BackendKind {
    default_backend_for_field_spec(field)
}

pub(crate) fn default_backend_name_for_field(field: FieldId) -> &'static str {
    default_backend_for_field(field).as_str()
}

fn backend_selection_from_name(backend: &str) -> ZkfResult<BackendSelection> {
    let selection =
        parse_backend_selection(backend).map_err(|message| ZkfError::UnsupportedBackend {
            backend: backend.to_string(),
            message,
        })?;
    validate_backend_selection_identity(&selection).map_err(|message| {
        ZkfError::UnsupportedBackend {
            backend: backend.to_string(),
            message,
        }
    })?;
    Ok(selection)
}

fn annotate_compiled_with_selection(compiled: &mut CompiledProgram, selection: &BackendSelection) {
    compiled.metadata.insert(
        "backend_route".to_string(),
        route_label(selection.route).to_string(),
    );
    compiled.metadata.insert(
        "requested_backend_name".to_string(),
        selection.requested_name.clone(),
    );
}

fn backend_route_for_compiled(compiled: &CompiledProgram) -> BackendRoute {
    match compiled.metadata.get("backend_route").map(String::as_str) {
        Some("explicit-compat") => BackendRoute::ExplicitCompat,
        _ => BackendRoute::Auto,
    }
}

/// Resolve input aliases from a program witness plan into canonical signal names.
pub fn resolve_input_aliases(inputs: &mut WitnessInputs, program: &Program) {
    let aliases = &program.witness_plan.input_aliases;
    if aliases.is_empty() {
        return;
    }
    let keys_to_resolve: Vec<(String, String)> = inputs
        .keys()
        .filter_map(|key| {
            let target = canonical_input_key_string(key.clone(), aliases.get(key).cloned());
            (target != *key).then(|| (key.clone(), target))
        })
        .collect();
    for (alias, target) in keys_to_resolve {
        if let Some(value) = inputs.remove(&alias) {
            inputs.insert(target, value);
        }
    }
}

/// Convert a JSON object of witness inputs into typed `WitnessInputs`.
///
/// Accepts decimal strings, JSON numbers, and booleans (`true` => 1, `false` => 0).
pub fn witness_inputs_from_json_map(
    inputs: &serde_json::Map<String, serde_json::Value>,
) -> ZkfResult<WitnessInputs> {
    let mut typed = WitnessInputs::new();
    for (name, value) in inputs {
        let field_element = match value {
            serde_json::Value::String(raw) => FieldElement::new(raw.clone()),
            serde_json::Value::Number(raw) => FieldElement::new(raw.to_string()),
            serde_json::Value::Bool(raw) => FieldElement::from_i64(if *raw { 1 } else { 0 }),
            other => {
                return Err(ZkfError::Serialization(format!(
                    "input '{name}' must be a decimal string, JSON number, or boolean, found {other}"
                )));
            }
        };
        typed.insert(name.clone(), field_element);
    }
    Ok(typed)
}

/// Compile a program for the requested backend without shelling out to `zkf-cli`.
pub fn compile(
    program: &Program,
    backend: &str,
    seed: Option<[u8; 32]>,
) -> ZkfResult<CompiledProgram> {
    let selection = backend_selection_from_name(backend)?;
    let engine = backend_for_route(selection.backend, selection.route);
    let mut compiled = zkf_backends::with_setup_seed_override(seed, || engine.compile(program))?;
    annotate_compiled_with_selection(&mut compiled, &selection);
    Ok(compiled)
}

/// Resolve the framework's default backend for a program.
pub fn default_backend(program: &Program) -> BackendKind {
    default_backend_for_field(program.field)
}

/// Resolve the framework's default backend name for a program.
pub fn default_backend_name(program: &Program) -> &'static str {
    default_backend_name_for_field(program.field)
}

/// Compile a program with the framework default backend for its field.
pub fn compile_default(program: &Program, seed: Option<[u8; 32]>) -> ZkfResult<CompiledProgram> {
    compile(program, default_backend_name(program), seed)
}

/// Generate a witness for a program from concrete inputs, optionally using a named solver.
pub fn witness_from_inputs(
    program: &Program,
    inputs: &WitnessInputs,
    solver: Option<&str>,
) -> ZkfResult<Witness> {
    let mut resolved = inputs.clone();
    resolve_input_aliases(&mut resolved, program);

    match solver {
        Some(name) => {
            #[cfg(feature = "full")]
            {
                let solver = solver_by_name(name)?;
                solve_and_validate_witness(program, &resolved, solver.as_ref())
            }
            #[cfg(not(feature = "full"))]
            {
                let _ = name;
                Err(ZkfError::FeatureDisabled {
                    backend: "solver".to_string(),
                })
            }
        }
        None => generate_witness(program, &resolved),
    }
}

fn witness_from_compiled_inputs(
    source_program: &Program,
    compiled: &CompiledProgram,
    inputs: &WitnessInputs,
    solver: Option<&str>,
) -> ZkfResult<Witness> {
    let mut resolved = inputs.clone();
    resolve_input_aliases(&mut resolved, source_program);

    match solver {
        Some(name) => {
            #[cfg(feature = "full")]
            {
                let solver = solver_by_name(name)?;
                solve_and_validate_witness(source_program, &resolved, solver.as_ref())
            }
            #[cfg(not(feature = "full"))]
            {
                let _ = name;
                Err(ZkfError::FeatureDisabled {
                    backend: "solver".to_string(),
                })
            }
        }
        None => generate_witness(&compiled.program, &resolved).or_else(|_| {
            let base_witness = generate_witness(source_program, &resolved)?;
            zkf_backends::blackbox_gadgets::enrich_witness_for_proving(compiled, &base_witness)
        }),
    }
}

/// Prove a compiled program with a concrete witness.
pub fn prove(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
    ensure_security_covered_groth16_setup(compiled)?;
    let engine = backend_for_route(compiled.backend, backend_route_for_compiled(compiled));
    engine.prove(compiled, witness)
}

/// Generate a witness from concrete inputs and produce a proof with an already compiled program.
pub fn prove_with_inputs(
    program: &Program,
    compiled: &CompiledProgram,
    inputs: &WitnessInputs,
    solver: Option<&str>,
) -> ZkfResult<ProofArtifact> {
    let expected = compiled
        .original_program
        .as_ref()
        .unwrap_or(&compiled.program)
        .digest_hex();
    let found = program.digest_hex();
    ensure_matching_program_digest(&expected, &found)?;
    let witness = witness_from_compiled_inputs(program, compiled, inputs, solver)?;
    prove(compiled, &witness)
}

/// Compile a program and produce a proof from concrete inputs in one call.
pub fn compile_and_prove(
    program: &Program,
    inputs: &WitnessInputs,
    backend: &str,
    solver: Option<&str>,
    seed: Option<[u8; 32]>,
) -> ZkfResult<EmbeddedProof> {
    let compiled = compile(program, backend, seed)?;
    let artifact = zkf_backends::with_proof_seed_override(seed, || {
        prove_with_inputs(program, &compiled, inputs, solver)
    })?;
    Ok(EmbeddedProof { compiled, artifact })
}

/// Compile a program with the framework default backend and prove it from concrete inputs.
pub fn compile_and_prove_default(
    program: &Program,
    inputs: &WitnessInputs,
    solver: Option<&str>,
    seed: Option<[u8; 32]>,
) -> ZkfResult<EmbeddedProof> {
    compile_and_prove(program, inputs, default_backend_name(program), solver, seed)
}

fn emit_progress_event(observer: &mut Option<&mut dyn FnMut(ProofEvent)>, event: ProofEvent) {
    if let Some(observer) = observer.as_mut() {
        (*observer)(event);
    }
}

/// Compile a program with the framework default backend and prove it while
/// emitting high-level stage events for application UIs.
///
/// This keeps proof semantics aligned with the existing backend implementations:
/// the audited witness preparation stage is surfaced to observers ahead of time,
/// but the final `prove()` call still receives the original witness so
/// backend-specific deterministic proof seeds remain unchanged.
pub fn compile_and_prove_with_progress_backend<F>(
    program: &Program,
    inputs: &WitnessInputs,
    backend: &str,
    solver: Option<&str>,
    seed: Option<[u8; 32]>,
    mut on_event: F,
) -> ZkfResult<EmbeddedProof>
where
    F: FnMut(ProofEvent),
{
    let mut observer: Option<&mut dyn FnMut(ProofEvent)> = Some(&mut on_event);

    emit_progress_event(
        &mut observer,
        ProofEvent::StageStarted {
            stage: ProofStage::Compile,
        },
    );
    let compile_started = Instant::now();
    let compiled = compile(program, backend, seed)?;
    emit_progress_event(
        &mut observer,
        ProofEvent::CompileCompleted {
            backend: compiled.backend,
            signal_count: compiled.program.signals.len(),
            constraint_count: compiled.program.constraints.len(),
            duration_ms: compile_started.elapsed().as_millis(),
        },
    );

    emit_progress_event(
        &mut observer,
        ProofEvent::StageStarted {
            stage: ProofStage::Witness,
        },
    );
    let witness_started = Instant::now();
    let witness = witness_from_compiled_inputs(program, &compiled, inputs, solver)?;
    emit_progress_event(
        &mut observer,
        ProofEvent::WitnessCompleted {
            witness_values: witness.values.len(),
            duration_ms: witness_started.elapsed().as_millis(),
        },
    );

    emit_progress_event(
        &mut observer,
        ProofEvent::StageStarted {
            stage: ProofStage::PrepareWitness,
        },
    );
    let prepare_started = Instant::now();
    let prepared = zkf_backends::prepare_witness_for_proving(&compiled, &witness)?;
    let public_inputs = collect_public_inputs(&compiled.program, &prepared)?;
    emit_progress_event(
        &mut observer,
        ProofEvent::PrepareWitnessCompleted {
            witness_values: prepared.values.len(),
            public_inputs: public_inputs.len(),
            duration_ms: prepare_started.elapsed().as_millis(),
        },
    );

    emit_progress_event(
        &mut observer,
        ProofEvent::StageStarted {
            stage: ProofStage::Prove,
        },
    );
    let prove_started = Instant::now();
    let artifact = zkf_backends::with_proof_seed_override(seed, || prove(&compiled, &witness))?;
    emit_progress_event(
        &mut observer,
        ProofEvent::ProveCompleted {
            backend: compiled.backend,
            proof_size_bytes: artifact.proof.len(),
            duration_ms: prove_started.elapsed().as_millis(),
        },
    );

    Ok(EmbeddedProof { compiled, artifact })
}

/// Compile a program with the framework default backend and prove it while
/// emitting high-level stage events for application UIs.
///
/// This keeps proof semantics aligned with the existing backend implementations:
/// the audited witness preparation stage is surfaced to observers ahead of time,
/// but the final `prove()` call still receives the original witness so
/// backend-specific deterministic proof seeds remain unchanged.
pub fn compile_and_prove_with_progress<F>(
    program: &Program,
    inputs: &WitnessInputs,
    solver: Option<&str>,
    seed: Option<[u8; 32]>,
    on_event: F,
) -> ZkfResult<EmbeddedProof>
where
    F: FnMut(ProofEvent),
{
    compile_and_prove_with_progress_backend(
        program,
        inputs,
        default_backend_name(program),
        solver,
        seed,
        on_event,
    )
}

/// Compile a program with the framework default backend and validate witness
/// generation plus constraints without producing a proof.
pub fn check(
    program: &Program,
    inputs: &WitnessInputs,
    solver: Option<&str>,
    seed: Option<[u8; 32]>,
) -> ZkfResult<EmbeddedCheck> {
    check_with_backend(program, inputs, default_backend_name(program), solver, seed)
}

/// Compile a program with an explicit backend and validate witness generation
/// plus constraints without producing a proof artifact.
pub fn check_with_backend(
    program: &Program,
    inputs: &WitnessInputs,
    backend: &str,
    solver: Option<&str>,
    seed: Option<[u8; 32]>,
) -> ZkfResult<EmbeddedCheck> {
    let compiled = compile(program, backend, seed)?;
    let witness = witness_from_compiled_inputs(program, &compiled, inputs, solver)?;
    let witness = zkf_backends::prepare_witness_for_proving(&compiled, &witness)?;
    ensure_witness_completeness(&compiled.program, &witness)?;
    let public_inputs = collect_public_inputs(&compiled.program, &witness)?;

    #[cfg(feature = "full")]
    let audit = audit_program(&program_v2_to_zir(program), Some(compiled.backend));
    #[cfg(feature = "full")]
    let diagnostics = analyze_program(program);

    Ok(EmbeddedCheck {
        compiled,
        witness,
        public_inputs,
        #[cfg(feature = "full")]
        audit,
        #[cfg(feature = "full")]
        diagnostics,
    })
}

/// Verify a proof against an already compiled program.
pub fn verify(compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
    let engine = backend_for_route(compiled.backend, backend_route_for_compiled(compiled));
    engine.verify(compiled, artifact)
}

/// Compile a program and verify a proof artifact directly.
pub fn verify_program(
    program: &Program,
    artifact: &ProofArtifact,
    backend: &str,
    seed: Option<[u8; 32]>,
) -> ZkfResult<bool> {
    let compiled = compile(program, backend, seed)?;
    verify(&compiled, artifact)
}

/// Compile a program with the framework default backend and verify an artifact directly.
pub fn verify_program_default(
    program: &Program,
    artifact: &ProofArtifact,
    seed: Option<[u8; 32]>,
) -> ZkfResult<bool> {
    verify_program(program, artifact, default_backend_name(program), seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::templates::poseidon_commitment;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn version_is_non_empty() {
        let v = version();
        assert!(!v.is_empty(), "version() must return a non-empty string");
    }

    #[test]
    fn ir_version_is_valid() {
        let v = ir_version();
        assert!(v.major >= 1, "IR major version should be at least 1");
    }

    #[cfg(feature = "full")]
    #[test]
    fn capability_matrix_has_entries() {
        let matrix = capability_matrix();
        assert!(
            !matrix.entries.is_empty(),
            "capability matrix should contain at least one entry"
        );
    }

    #[test]
    fn load_program_invalid_path_returns_error() {
        let result = load_program("/nonexistent/path/to/circuit.ir.json");
        assert!(result.is_err(), "loading from a nonexistent path must fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ZkfError::Io(_)),
            "error should be ZkfError::Io, got: {err}"
        );
    }

    #[test]
    fn load_program_accepts_app_spec_and_lowers_it() {
        let spec = crate::app::spec::instantiate_template("range-proof", &BTreeMap::new())
            .expect("template spec");
        let root =
            std::env::temp_dir().join(format!("zkf-lib-load-program-spec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp dir");
        let path = root.join("zirapp.json");
        let json = serde_json::to_vec_pretty(&spec).expect("serialize spec");
        std::fs::write(&path, json).expect("write spec");

        let program = load_program(path.to_str().expect("utf8 path")).expect("load spec");

        assert_eq!(program.name, spec.program.name);
        assert!(
            !program.constraints.is_empty(),
            "lowered program must be non-empty"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn load_inputs_invalid_path_returns_error() {
        let result = load_inputs("/nonexistent/path/to/inputs.json");
        assert!(result.is_err(), "loading from a nonexistent path must fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ZkfError::Io(_)),
            "error should be ZkfError::Io, got: {err}"
        );
    }

    #[test]
    fn witness_inputs_from_json_map_accepts_strings_numbers_and_bools() {
        let inputs = witness_inputs_from_json_map(&serde_json::Map::from_iter([
            ("as_string".to_string(), json!("42")),
            ("as_number".to_string(), json!(7)),
            ("as_bool".to_string(), json!(true)),
        ]))
        .expect("inputs should parse");

        assert_eq!(
            inputs.get("as_string").map(FieldElement::to_string),
            Some("42".to_string())
        );
        assert_eq!(
            inputs.get("as_number").map(FieldElement::to_string),
            Some("7".to_string())
        );
        assert_eq!(
            inputs.get("as_bool").map(FieldElement::to_string),
            Some("1".to_string())
        );
    }

    #[test]
    fn resolve_input_aliases_rewrites_alias_keys() {
        let program = Program {
            name: "alias-test".to_string(),
            witness_plan: zkf_core::WitnessPlan {
                input_aliases: BTreeMap::from([("external".to_string(), "internal".to_string())]),
                ..zkf_core::WitnessPlan::default()
            },
            ..Program::default()
        };
        let mut inputs = WitnessInputs::from([("external".to_string(), FieldElement::from_i64(9))]);

        resolve_input_aliases(&mut inputs, &program);

        assert!(!inputs.contains_key("external"));
        assert_eq!(
            inputs.get("internal").map(FieldElement::to_string),
            Some("9".to_string())
        );
    }

    #[test]
    fn default_backend_for_bn254_program_is_arkworks() {
        let program = Program {
            field: zkf_core::FieldId::Bn254,
            ..Program::default()
        };

        assert_eq!(default_backend(&program), BackendKind::ArkworksGroth16);
        assert_eq!(default_backend_name(&program), "arkworks-groth16");
    }

    #[test]
    fn prove_with_inputs_uses_lowered_compiled_program_for_blackbox_free_witnesses() {
        let program = Program {
            name: "mul_add".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zkf_core::Signal {
                    name: "x".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "y".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "sum".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "product".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                zkf_core::Constraint::Equal {
                    lhs: zkf_core::Expr::signal("sum"),
                    rhs: zkf_core::Expr::Add(vec![
                        zkf_core::Expr::signal("x"),
                        zkf_core::Expr::signal("y"),
                    ]),
                    label: None,
                },
                zkf_core::Constraint::Equal {
                    lhs: zkf_core::Expr::signal("product"),
                    rhs: zkf_core::Expr::Mul(
                        Box::new(zkf_core::Expr::signal("sum")),
                        Box::new(zkf_core::Expr::signal("x")),
                    ),
                    label: None,
                },
            ],
            witness_plan: zkf_core::WitnessPlan {
                assignments: vec![
                    zkf_core::WitnessAssignment {
                        target: "sum".to_string(),
                        expr: zkf_core::Expr::Add(vec![
                            zkf_core::Expr::signal("x"),
                            zkf_core::Expr::signal("y"),
                        ]),
                    },
                    zkf_core::WitnessAssignment {
                        target: "product".to_string(),
                        expr: zkf_core::Expr::Mul(
                            Box::new(zkf_core::Expr::signal("sum")),
                            Box::new(zkf_core::Expr::signal("x")),
                        ),
                    },
                ],
                ..zkf_core::WitnessPlan::default()
            },
            ..Program::default()
        };
        let inputs = WitnessInputs::from([
            ("x".to_string(), FieldElement::from_i64(3)),
            ("y".to_string(), FieldElement::from_i64(7)),
        ]);
        let compiled = compile_default(&program, None).expect("compile");
        let artifact =
            zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                prove_with_inputs(&program, &compiled, &inputs, None)
            })
            .expect("prove");
        assert!(verify(&compiled, &artifact).expect("verify"));
    }

    #[test]
    fn check_returns_compiled_program_witness_and_public_inputs() {
        let program = Program {
            name: "check_mul_add".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zkf_core::Signal {
                    name: "x".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "y".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "sum".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "product".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                zkf_core::Constraint::Equal {
                    lhs: zkf_core::Expr::signal("sum"),
                    rhs: zkf_core::Expr::Add(vec![
                        zkf_core::Expr::signal("x"),
                        zkf_core::Expr::signal("y"),
                    ]),
                    label: None,
                },
                zkf_core::Constraint::Equal {
                    lhs: zkf_core::Expr::signal("product"),
                    rhs: zkf_core::Expr::Mul(
                        Box::new(zkf_core::Expr::signal("sum")),
                        Box::new(zkf_core::Expr::signal("x")),
                    ),
                    label: None,
                },
            ],
            witness_plan: zkf_core::WitnessPlan {
                assignments: vec![
                    zkf_core::WitnessAssignment {
                        target: "sum".to_string(),
                        expr: zkf_core::Expr::Add(vec![
                            zkf_core::Expr::signal("x"),
                            zkf_core::Expr::signal("y"),
                        ]),
                    },
                    zkf_core::WitnessAssignment {
                        target: "product".to_string(),
                        expr: zkf_core::Expr::Mul(
                            Box::new(zkf_core::Expr::signal("sum")),
                            Box::new(zkf_core::Expr::signal("x")),
                        ),
                    },
                ],
                ..zkf_core::WitnessPlan::default()
            },
            ..Program::default()
        };
        let inputs = WitnessInputs::from([
            ("x".to_string(), FieldElement::from_i64(3)),
            ("y".to_string(), FieldElement::from_i64(7)),
        ]);

        let checked = check(&program, &inputs, None, None).expect("check");

        assert_eq!(checked.compiled.backend, BackendKind::ArkworksGroth16);
        assert_eq!(
            checked.witness.values.get("product"),
            Some(&FieldElement::from_i64(30))
        );
        assert_eq!(
            checked.public_inputs,
            vec![FieldElement::from_i64(7), FieldElement::from_i64(30)]
        );
        #[cfg(feature = "full")]
        {
            assert_eq!(checked.audit.summary.failed, 0);
            assert_eq!(checked.diagnostics.constraint_count, 2);
        }
    }

    #[test]
    fn check_rejects_underconstrained_programs() {
        let program = Program {
            name: "underconstrained".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zkf_core::Signal {
                    name: "x".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "y".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "out".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![zkf_core::Constraint::Equal {
                lhs: zkf_core::Expr::signal("out"),
                rhs: zkf_core::Expr::Add(vec![
                    zkf_core::Expr::signal("x"),
                    zkf_core::Expr::signal("y"),
                ]),
                label: None,
            }],
            ..Program::default()
        };
        let inputs = WitnessInputs::from([
            ("x".to_string(), FieldElement::from_i64(2)),
            ("y".to_string(), FieldElement::from_i64(5)),
        ]);

        let err = check(&program, &inputs, None, None).expect_err("check should fail");
        let message = err.to_string();
        assert!(message.contains("underconstrained"));
        assert!(message.contains("Suggestion:"));
    }

    #[test]
    fn compile_and_prove_with_progress_emits_stage_order_and_matches_default() {
        let handle = std::thread::Builder::new()
            .name("proof-progress".to_string())
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let seed = Some([7u8; 32]);
                let template = poseidon_commitment().expect("poseidon template");
                let baseline =
                    zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                        compile_and_prove_default(
                            &template.program,
                            &template.sample_inputs,
                            None,
                            seed,
                        )
                    })
                    .expect("baseline proof");
                let mut events = Vec::new();
                let with_progress =
                    zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                        compile_and_prove_with_progress(
                            &template.program,
                            &template.sample_inputs,
                            None,
                            seed,
                            |event| events.push(event),
                        )
                    })
                    .expect("progress proof");

                (template, baseline, with_progress, events)
            })
            .expect("spawn progress test thread");
        let (template, baseline, with_progress, events) =
            handle.join().expect("progress test should succeed");

        assert_eq!(baseline.compiled, with_progress.compiled);
        assert_eq!(baseline.artifact.backend, with_progress.artifact.backend);
        assert_eq!(
            baseline.artifact.program_digest,
            with_progress.artifact.program_digest
        );
        assert_eq!(
            baseline.artifact.verification_key,
            with_progress.artifact.verification_key
        );
        assert_eq!(
            baseline.artifact.public_inputs,
            with_progress.artifact.public_inputs
        );
        assert_eq!(baseline.artifact.proof, with_progress.artifact.proof);
        let mut baseline_metadata = baseline.artifact.metadata.clone();
        let mut progress_metadata = with_progress.artifact.metadata.clone();
        baseline_metadata.remove("metal_stage_breakdown");
        progress_metadata.remove("metal_stage_breakdown");
        assert_eq!(baseline_metadata, progress_metadata);
        assert_eq!(
            baseline
                .artifact
                .metadata
                .get("prove_deterministic")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            baseline
                .artifact
                .metadata
                .get("prove_seed_source")
                .map(String::as_str),
            Some("explicit-seed")
        );
        assert!(baseline.artifact.metadata.contains_key("prove_seed_hex"));
        assert!(verify(&baseline.compiled, &baseline.artifact).expect("baseline proof verifies"));
        assert!(
            verify(&with_progress.compiled, &with_progress.artifact)
                .expect("progress proof verifies")
        );
        assert_eq!(
            events.iter().map(ProofEvent::stage).collect::<Vec<_>>(),
            vec![
                ProofStage::Compile,
                ProofStage::Compile,
                ProofStage::Witness,
                ProofStage::Witness,
                ProofStage::PrepareWitness,
                ProofStage::PrepareWitness,
                ProofStage::Prove,
                ProofStage::Prove,
            ]
        );

        match &events[1] {
            ProofEvent::CompileCompleted {
                backend,
                signal_count,
                constraint_count,
                ..
            } => {
                assert_eq!(*backend, baseline.compiled.backend);
                assert_eq!(*signal_count, baseline.compiled.program.signals.len());
                assert_eq!(
                    *constraint_count,
                    baseline.compiled.program.constraints.len()
                );
            }
            other => panic!("unexpected compile event: {other:?}"),
        }

        match &events[3] {
            ProofEvent::WitnessCompleted { witness_values, .. } => {
                assert!(*witness_values >= template.expected_inputs.len());
            }
            other => panic!("unexpected witness event: {other:?}"),
        }

        match &events[5] {
            ProofEvent::PrepareWitnessCompleted {
                witness_values,
                public_inputs,
                ..
            } => {
                assert!(*witness_values >= template.expected_inputs.len());
                assert_eq!(*public_inputs, template.public_outputs.len());
            }
            other => panic!("unexpected prepare event: {other:?}"),
        }

        match &events[7] {
            ProofEvent::ProveCompleted {
                backend,
                proof_size_bytes,
                ..
            } => {
                assert_eq!(*backend, baseline.artifact.backend);
                assert_eq!(*proof_size_bytes, baseline.artifact.proof.len());
            }
            other => panic!("unexpected prove event: {other:?}"),
        }

        assert_eq!(events.iter().filter_map(ProofEvent::duration_ms).count(), 4);
    }

    #[test]
    fn prove_accepts_auto_ceremony_groth16_on_security_covered_surface() {
        let program = Program {
            name: "strict-groth16-boundary".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zkf_core::Signal {
                    name: "x".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "y".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
                zkf_core::Signal {
                    name: "sum".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![zkf_core::Constraint::Equal {
                lhs: zkf_core::Expr::signal("sum"),
                rhs: zkf_core::Expr::Add(vec![
                    zkf_core::Expr::signal("x"),
                    zkf_core::Expr::signal("y"),
                ]),
                label: None,
            }],
            witness_plan: zkf_core::WitnessPlan {
                assignments: vec![zkf_core::WitnessAssignment {
                    target: "sum".to_string(),
                    expr: zkf_core::Expr::Add(vec![
                        zkf_core::Expr::signal("x"),
                        zkf_core::Expr::signal("y"),
                    ]),
                }],
                ..zkf_core::WitnessPlan::default()
            },
            ..Program::default()
        };
        let inputs = WitnessInputs::from([
            ("x".to_string(), FieldElement::from_i64(2)),
            ("y".to_string(), FieldElement::from_i64(5)),
        ]);
        let compiled = compile_default(&program, None).expect("compile");
        ensure_security_covered_groth16_setup(&compiled)
            .expect("auto ceremony should satisfy security-covered Groth16 setup");
        assert_eq!(
            compiled
                .metadata
                .get("setup_seed_source")
                .map(String::as_str),
            Some("auto-ceremony")
        );
        assert_eq!(
            compiled
                .metadata
                .get("groth16_ceremony_subsystem")
                .map(String::as_str),
            Some("strict-groth16-boundary")
        );
        let witness = witness_from_inputs(&program, &inputs, None).expect("witness");
        let proof = prove(&compiled, &witness).expect("strict prove should accept auto ceremony");
        assert_eq!(
            proof
                .metadata
                .get("groth16_ceremony_id")
                .map(String::as_str),
            compiled
                .metadata
                .get("groth16_ceremony_id")
                .map(String::as_str)
        );
    }
}
