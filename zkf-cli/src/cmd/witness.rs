use std::path::{Path, PathBuf};

use serde_json::Value;
use zkf_core::{
    PackageFileRef, PackageManifest, PackageRunFiles, Program, Witness, analyze_program,
    check_constraints, collect_public_inputs, ensure_witness_completeness, generate_witness,
    solve_and_validate_witness, solver_by_name,
};
use zkf_frontends::frontend_for;

use crate::package_io::normalize_run_id;
use crate::util::{
    BackendRequest, WitnessRequirement, ensure_manifest_v2_metadata_for_command, load_program_v2,
    load_program_v2_from_manifest, parse_frontend, parse_witness_requirement,
    prepare_existing_source_witness, prepare_witness_for_request_from_inputs, read_inputs,
    read_json, render_zkf_error, resolve_compiled_artifact_for_request, resolve_input_aliases,
    write_json, write_json_and_hash,
};

pub(crate) fn handle_witness(
    program: PathBuf,
    inputs: PathBuf,
    out: PathBuf,
) -> Result<(), String> {
    let program: Program = load_program_v2(&program)?;
    let diagnostics = analyze_program(&program);
    if !diagnostics.unconstrained_private_signals.is_empty() {
        eprintln!(
            "warning: unconstrained private signals: {}",
            diagnostics.unconstrained_private_signals.join(", ")
        );
    }

    let mut inputs = read_inputs(&inputs)?;
    resolve_input_aliases(&mut inputs, &program);

    let solver_name = program.metadata.get("solver").map(String::as_str);
    let artifacts = prepare_witness_for_request_from_inputs(
        &program,
        &inputs,
        solver_name,
        &BackendRequest::native(zkf_backends::preferred_backend_for_program(&program)),
        None,
        None,
        false,
        "zkf witness",
    )?;
    write_json(&out, &artifacts.source_witness)?;
    println!("wrote witness: {}", out.display());
    Ok(())
}

pub(crate) fn run_package(
    manifest_path: &Path,
    inputs_path: &Path,
    run_id: &str,
    solver: Option<&str>,
) -> Result<crate::RunResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf run")?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let program = load_program_v2_from_manifest(root, &manifest)?;
    let inputs = read_inputs(inputs_path)?;
    let requires_hints = manifest
        .metadata
        .get("requires_hints")
        .is_some_and(|value| value == "true");
    let witness_requirement_legacy = manifest
        .metadata
        .get("witness_requirement")
        .and_then(|value| parse_witness_requirement(value));
    let requires_execution = manifest
        .metadata
        .get("requires_execution")
        .is_some_and(|value| value == "true")
        || witness_requirement_legacy == Some(WitnessRequirement::Execution)
        || requires_hints;
    let requires_solver = manifest
        .metadata
        .get("requires_solver")
        .is_some_and(|value| value == "true")
        || witness_requirement_legacy == Some(WitnessRequirement::Solver);
    let allow_builtin_fallback = manifest.schema_version < 2
        || manifest
            .metadata
            .get("allow_builtin_fallback")
            .is_some_and(|value| value == "true");

    let mut execution_path = String::new();
    let mut attempted_solver_paths = Vec::<String>::new();
    let mut solver_attempt_errors = Vec::<String>::new();
    let mut frontend_execution_error = None::<String>;
    let mut fallback_reason = None::<String>;
    let mut prepared_witness_backends = Vec::<String>::new();

    let (witness, solver_name) = if let Some(solver_name) = solver {
        attempted_solver_paths.push(solver_name.to_string());
        execution_path = "explicit-solver".to_string();
        let solver_impl = solver_by_name(solver_name).map_err(render_zkf_error)?;
        (
            solve_and_validate_witness(&program, &inputs, solver_impl.as_ref())
                .map_err(render_zkf_error)?,
            solver_name.to_string(),
        )
    } else {
        let frontend_solver = if let Ok(frontend_kind) = parse_frontend(&manifest.frontend.kind) {
            let original_path = root.join(&manifest.files.original_artifact.path);
            if original_path.exists() {
                let original_value: Value = read_json(&original_path)?;
                let engine = frontend_for(frontend_kind);
                match engine.execute(&original_value, &inputs) {
                    Ok(witness) => {
                        execution_path = "frontend-execute".to_string();
                        ensure_witness_completeness(&program, &witness)
                            .map_err(render_zkf_error)?;
                        check_constraints(&program, &witness).map_err(render_zkf_error)?;
                        Some((witness, format!("frontend/{}", frontend_kind.as_str())))
                    }
                    Err(err) => {
                        frontend_execution_error = Some(render_zkf_error(err));
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some(result) = frontend_solver {
            result
        } else {
            let mut try_solver = |name: &str| -> Option<(Witness, String)> {
                attempted_solver_paths.push(name.to_string());
                match solver_by_name(name) {
                    Ok(solver_impl) => {
                        match solve_and_validate_witness(&program, &inputs, solver_impl.as_ref()) {
                            Ok(witness) => Some((witness, name.to_string())),
                            Err(err) => {
                                solver_attempt_errors
                                    .push(format!("{name}: {}", render_zkf_error(err)));
                                None
                            }
                        }
                    }
                    Err(zkf_core::ZkfError::FeatureDisabled { .. }) => None,
                    Err(err) => {
                        solver_attempt_errors.push(format!("{name}: {}", render_zkf_error(err)));
                        None
                    }
                }
            };

            let solver_fallback = try_solver("acvm-beta9").or_else(|| try_solver("acvm"));

            if let Some(result) = solver_fallback {
                execution_path = "solver-fallback".to_string();
                result
            } else if requires_execution {
                let frontend_reason = frontend_execution_error
                    .unwrap_or_else(|| "no compatible frontend executor available".to_string());
                let solver_reason = if solver_attempt_errors.is_empty() {
                    "no configured ACVM solver path is available for this build".to_string()
                } else {
                    solver_attempt_errors.join("; ")
                };
                return Err(format!(
                    "package requires execution-mode witness generation; frontend execution failed ({frontend_reason}) and solver fallback failed ({solver_reason})"
                ));
            } else if requires_solver && !allow_builtin_fallback {
                let solver_reason = if solver_attempt_errors.is_empty() {
                    "no configured ACVM solver path is available for this build".to_string()
                } else {
                    solver_attempt_errors.join("; ")
                };
                return Err(format!(
                    "package requires solver-mode witness generation; solver fallback failed ({solver_reason}) and builtin fallback is disabled"
                ));
            } else {
                execution_path = "builtin-fallback".to_string();
                fallback_reason = Some(if solver_attempt_errors.is_empty() {
                    "acvm-solver-unavailable".to_string()
                } else {
                    "acvm-solver-failed".to_string()
                });
                let builtin = match generate_witness(&program, &inputs) {
                    Ok(witness) => witness,
                    Err(_) => {
                        execution_path = "compiled-builtin-fallback".to_string();
                        fallback_reason = Some("compiled-witness-fallback".to_string());
                        let fallback_backend = manifest
                            .backend_targets
                            .first()
                            .copied()
                            .unwrap_or_else(|| {
                                zkf_backends::preferred_backend_for_program(&program)
                            });
                        prepare_witness_for_request_from_inputs(
                            &program,
                            &inputs,
                            None,
                            &BackendRequest::native(fallback_backend),
                            None,
                            None,
                            false,
                            "zkf run",
                        )?
                        .source_witness
                    }
                };
                if !solver_attempt_errors.is_empty() {
                    eprintln!(
                        "warning: ACVM solver fallback failed ({}); using builtin witness generation",
                        solver_attempt_errors.join("; ")
                    );
                }
                if requires_solver {
                    eprintln!(
                        "warning: package is marked solver-mode; builtin witness generation was used as a final fallback"
                    );
                }
                (builtin, "builtin".to_string())
            }
        }
    };

    let public_inputs = collect_public_inputs(&program, &witness).map_err(render_zkf_error)?;

    let prepared_requests = if manifest.backend_targets.is_empty() {
        vec![BackendRequest::native(
            zkf_backends::preferred_backend_for_program(&program),
        )]
    } else {
        manifest
            .backend_targets
            .iter()
            .copied()
            .map(BackendRequest::native)
            .collect()
    };
    for request in &prepared_requests {
        let (compiled, _) = resolve_compiled_artifact_for_request(
            &program, request, None, false, None, None, false, "zkf run",
        )?;
        prepare_existing_source_witness(&compiled, &witness).map_err(|err| {
            format!(
                "prepared witness validation failed for backend '{}': {err}",
                request.requested_name
            )
        })?;
        prepared_witness_backends.push(request.requested_name.clone());
    }

    let witness_rel = PathBuf::from(format!("runs/{run_id}/witness.json"));
    let witness_path = root.join(&witness_rel);
    let witness_sha = write_json_and_hash(&witness_path, &witness)?;
    let witness_ref = PackageFileRef {
        path: witness_rel.display().to_string(),
        sha256: witness_sha,
    };

    let public_inputs_rel = PathBuf::from(format!("runs/{run_id}/public_inputs.json"));
    let public_inputs_path = root.join(&public_inputs_rel);
    let public_inputs_sha = write_json_and_hash(&public_inputs_path, &public_inputs)?;
    let public_inputs_ref = PackageFileRef {
        path: public_inputs_rel.display().to_string(),
        sha256: public_inputs_sha,
    };

    let run_report = crate::RunArtifactReport {
        run_id: run_id.clone(),
        solver: solver_name.clone(),
        solver_path: solver_name.clone(),
        execution_path,
        attempted_solver_paths,
        solver_attempt_errors,
        frontend_execution_error,
        fallback_reason,
        requires_execution,
        requires_solver,
        witness_values: witness.values.len(),
        public_inputs: public_inputs.len(),
        constraints: program.constraints.len(),
        signals: program.signals.len(),
        requires_hints,
        prepared_witness_validated: true,
        prepared_witness_backends,
    };
    let run_report_rel = PathBuf::from(format!("runs/{run_id}/run_report.json"));
    let run_report_path = root.join(&run_report_rel);
    let run_report_sha = write_json_and_hash(&run_report_path, &run_report)?;
    let run_report_ref = PackageFileRef {
        path: run_report_rel.display().to_string(),
        sha256: run_report_sha,
    };

    manifest.runs.insert(
        run_id.clone(),
        PackageRunFiles {
            witness: witness_ref.clone(),
            public_inputs: public_inputs_ref.clone(),
            run_report: run_report_ref.clone(),
        },
    );
    if run_id == "main" {
        manifest.files.witness = Some(witness_ref);
        manifest.files.public_inputs = Some(public_inputs_ref);
        manifest.files.run_report = Some(run_report_ref);
    }

    manifest
        .metadata
        .insert("last_run_solver".to_string(), solver_name.clone());
    manifest
        .metadata
        .insert("last_run_id".to_string(), run_id.clone());
    write_json(manifest_path, &manifest)?;

    Ok(crate::RunResult {
        manifest: manifest_path.display().to_string(),
        run_id,
        witness_path: witness_path.display().to_string(),
        public_inputs_path: public_inputs_path.display().to_string(),
        run_report_path: run_report_path.display().to_string(),
        witness_values: witness.values.len(),
        public_inputs: public_inputs.len(),
        solver: solver_name,
    })
}

pub(crate) fn handle_run(
    manifest: PathBuf,
    inputs: PathBuf,
    run_id: String,
    solver: Option<String>,
    json: bool,
) -> Result<(), String> {
    let report = run_package(&manifest, &inputs, &run_id, solver.as_deref())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "run: run_id={} witness={} public_inputs={} solver={} manifest={}",
            report.run_id,
            report.witness_values,
            report.public_inputs,
            report.solver,
            report.manifest
        );
    }
    Ok(())
}
