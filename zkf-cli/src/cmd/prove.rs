use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use zkf_core::{
    AuditCategory, AuditStatus, CompiledProgram, Program, ProofArtifact, UnderconstrainedAnalysis,
    program_v2_to_zir, solve_and_validate_witness, solver_by_name,
};
use zkf_distributed::{ClusterConfig, DistributedCoordinator};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

use crate::util::{
    attach_groth16_setup_blob_path, backend_for_request, ensure_backend_request_allowed,
    ensure_backend_supports_program_constraints, load_program_v2, parse_backend_request,
    parse_optimization_objective, parse_setup_seed, raw_cli_error, read_inputs, read_json,
    render_zkf_error, resolve_compiled_artifact_for_request, resolve_input_aliases,
    validate_compiled_artifact_for_request, warn_if_r1cs_lookup_limit_exceeded,
    with_allow_dev_deterministic_groth16_override, with_groth16_setup_blob_path_override,
    with_proof_seed_override, with_setup_seed_override, write_json,
};

pub(crate) struct ProveArgs {
    pub(crate) program: PathBuf,
    pub(crate) inputs: PathBuf,
    pub(crate) json: bool,
    pub(crate) backend: Option<String>,
    pub(crate) objective: String,
    pub(crate) mode: Option<String>,
    pub(crate) export: Option<String>,
    pub(crate) allow_attestation: bool,
    pub(crate) out: PathBuf,
    pub(crate) compiled_out: Option<PathBuf>,
    pub(crate) solver: Option<String>,
    pub(crate) seed: Option<String>,
    pub(crate) groth16_setup_blob: Option<PathBuf>,
    pub(crate) allow_dev_deterministic_groth16: bool,
    pub(crate) hybrid: bool,
}

#[derive(Debug, Serialize)]
struct ProveAuditFailurePayload {
    status: &'static str,
    error_kind: &'static str,
    message: String,
    failed_checks: usize,
    failed_categories: Vec<String>,
    audit_report: zkf_core::AuditReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    underconstraint_analysis: Option<UnderconstrainedAnalysis>,
}

pub(crate) fn handle_prove(args: ProveArgs, allow_compat: bool) -> Result<(), String> {
    let mut program: Program = load_program_v2(&args.program)?;
    let objective = parse_optimization_objective(Some(&args.objective))?;
    if args.hybrid
        && let Some(requested) = args.backend.as_deref()
        && requested != "plonky3"
    {
        return Err(
            "--hybrid currently requires backend=plonky3 or no explicit backend".to_string(),
        );
    }
    let backend = if args.hybrid {
        parse_backend_request("plonky3")?
    } else {
        crate::util::resolve_backend_or_mode(
            args.backend.as_deref(),
            args.mode.as_deref(),
            &program,
            objective,
        )?
    };
    let export = crate::util::parse_export_scheme(args.export.as_deref())?;
    ensure_backend_request_allowed(&backend, allow_compat)?;
    ensure_program_passes_fail_closed_audit(&program, backend.backend, args.json)?;
    attach_groth16_setup_blob_path(
        &mut program,
        backend.backend,
        args.groth16_setup_blob.as_deref(),
    );
    ensure_backend_supports_program_constraints(backend.backend, &program)?;
    warn_if_r1cs_lookup_limit_exceeded(backend.backend, &program, "zkf prove");
    let mut inputs = read_inputs(&args.inputs)?;
    resolve_input_aliases(&mut inputs, &program);

    // Determine solver: explicit flag > program metadata > default (none)
    let solver_name = args
        .solver
        .as_deref()
        .or_else(|| program.metadata.get("solver").map(String::as_str));

    let witness = if let Some(solver_name) = solver_name {
        let solver = solver_by_name(solver_name).map_err(render_zkf_error)?;
        Some(
            solve_and_validate_witness(&program, &inputs, solver.as_ref())
                .map_err(render_zkf_error)?,
        )
    } else {
        None
    };
    if args.hybrid && export.is_some() {
        return Err(
            "--hybrid already emits a Groth16 primary leg; --export is not supported".to_string(),
        );
    }
    let seed = args.seed.as_deref().map(parse_setup_seed).transpose()?;
    let groth16_setup_blob_override = args
        .groth16_setup_blob
        .as_ref()
        .map(|path| path.display().to_string());
    if args.hybrid {
        let execution = with_allow_dev_deterministic_groth16_override(
            args.allow_dev_deterministic_groth16.then_some(true),
            || {
                with_groth16_setup_blob_path_override(groth16_setup_blob_override.clone(), || {
                    with_setup_seed_override(seed, || {
                        with_proof_seed_override(seed, || {
                            zkf_runtime::run_hybrid_prove_job_with_objective(
                                Arc::new(program.clone()),
                                if witness.is_none() {
                                    Some(Arc::new(inputs.clone()))
                                } else {
                                    None
                                },
                                witness.map(Arc::new),
                                objective,
                                RequiredTrustLane::StrictCryptographic,
                                ExecutionMode::Deterministic,
                            )
                            .map_err(|e| e.to_string())
                        })
                    })
                })
            },
        )?;
        let compiled = execution.source.compiled;
        let mut artifact = execution.artifact;
        crate::util::annotate_artifact_with_runtime_report(
            &mut artifact,
            &execution.wrapped.result,
        );
        artifact.metadata.insert(
            "hybrid_source_runtime".to_string(),
            serde_json::to_string(&execution.source.result.outputs)
                .map_err(|err| err.to_string())?,
        );
        artifact.metadata.insert(
            "hybrid_wrapped_runtime".to_string(),
            serde_json::to_string(&execution.wrapped.result.outputs)
                .map_err(|err| err.to_string())?,
        );
        write_json(&args.out, &artifact)?;
        if let Some(path) = args.compiled_out {
            write_json(&path, &compiled)?;
            println!("wrote compiled program: {}", path.display());
        }
        println!(
            "hybrid proof generated with plonky3 companion + groth16 primary (public_inputs={}) -> {}",
            artifact.public_inputs.len(),
            args.out.display()
        );
        return Ok(());
    }

    let execution = with_allow_dev_deterministic_groth16_override(
        args.allow_dev_deterministic_groth16.then_some(true),
        || {
            with_groth16_setup_blob_path_override(groth16_setup_blob_override.clone(), || {
                with_setup_seed_override(seed, || {
                    with_proof_seed_override(seed, || {
                        RuntimeExecutor::run_backend_prove_job_with_objective(
                            backend.backend,
                            backend.route,
                            Arc::new(program.clone()),
                            if witness.is_none() {
                                Some(Arc::new(inputs.clone()))
                            } else {
                                None
                            },
                            witness.map(Arc::new),
                            None,
                            objective,
                            RequiredTrustLane::StrictCryptographic,
                            ExecutionMode::Deterministic,
                        )
                        .map_err(|e| e.to_string())
                    })
                })
            })
        },
    )?;
    let compiled = execution.compiled;
    let mut artifact = execution.artifact;
    crate::util::annotate_artifact_with_runtime_report(&mut artifact, &execution.result);
    let artifact = maybe_export_artifact(
        export,
        backend.backend,
        artifact,
        &compiled,
        args.allow_attestation,
    )?;

    write_json(&args.out, &artifact)?;
    if let Some(path) = args.compiled_out {
        write_json(&path, &compiled)?;
        println!("wrote compiled program: {}", path.display());
    }

    println!(
        "proof generated with {} (public_inputs={}) -> {}",
        backend.requested_name,
        artifact.public_inputs.len(),
        args.out.display()
    );
    Ok(())
}

pub(crate) fn handle_distributed_prove(args: ProveArgs, allow_compat: bool) -> Result<(), String> {
    if args.hybrid {
        return Err(
            "distributed hybrid proving is not available yet; rerun without --distributed"
                .to_string(),
        );
    }
    let mut program: Program = load_program_v2(&args.program)?;
    let objective = parse_optimization_objective(Some(&args.objective))?;
    let backend = crate::util::resolve_backend_or_mode(
        args.backend.as_deref(),
        args.mode.as_deref(),
        &program,
        objective,
    )?;
    let export = crate::util::parse_export_scheme(args.export.as_deref())?;
    ensure_backend_request_allowed(&backend, allow_compat)?;
    ensure_program_passes_fail_closed_audit(&program, backend.backend, args.json)?;
    attach_groth16_setup_blob_path(
        &mut program,
        backend.backend,
        args.groth16_setup_blob.as_deref(),
    );
    ensure_backend_supports_program_constraints(backend.backend, &program)?;
    warn_if_r1cs_lookup_limit_exceeded(backend.backend, &program, "zkf prove --distributed");
    let mut inputs = read_inputs(&args.inputs)?;
    resolve_input_aliases(&mut inputs, &program);

    let solver_name = args
        .solver
        .as_deref()
        .or_else(|| program.metadata.get("solver").map(String::as_str));
    let witness = if let Some(solver_name) = solver_name {
        let solver = solver_by_name(solver_name).map_err(render_zkf_error)?;
        Some(
            solve_and_validate_witness(&program, &inputs, solver.as_ref())
                .map_err(render_zkf_error)?,
        )
    } else {
        None
    };

    let config = ClusterConfig::from_env().map_err(|err| err.to_string())?;
    let seed = args.seed.as_deref().map(parse_setup_seed).transpose()?;
    let groth16_setup_blob_override = args
        .groth16_setup_blob
        .as_ref()
        .map(|path| path.display().to_string());
    let mut coordinator = DistributedCoordinator::new(config).map_err(|err| err.to_string())?;
    let execution = with_allow_dev_deterministic_groth16_override(
        args.allow_dev_deterministic_groth16.then_some(true),
        || {
            with_groth16_setup_blob_path_override(groth16_setup_blob_override.clone(), || {
                with_setup_seed_override(seed, || {
                    with_proof_seed_override(seed, || {
                        coordinator
                            .prove_backend_job_distributed(
                                backend.backend,
                                backend.route,
                                Arc::new(program.clone()),
                                if witness.is_none() {
                                    Some(Arc::new(inputs.clone()))
                                } else {
                                    None
                                },
                                witness.clone().map(Arc::new),
                                None,
                                objective,
                                RequiredTrustLane::StrictCryptographic,
                                ExecutionMode::Deterministic,
                            )
                            .map_err(|err| err.to_string())
                    })
                })
            })
        },
    )?;
    let compiled = execution.compiled;
    let mut artifact = execution.artifact;
    if let Some(runtime_result) = execution.runtime_result.as_ref() {
        crate::util::annotate_artifact_with_runtime_report(&mut artifact, runtime_result);
    }
    annotate_artifact_with_distributed_report(&mut artifact, &execution.report)?;
    let artifact = maybe_export_artifact(
        export,
        backend.backend,
        artifact,
        &compiled,
        args.allow_attestation,
    )?;

    write_json(&args.out, &artifact)?;
    if let Some(path) = args.compiled_out {
        write_json(&path, &compiled)?;
        println!("wrote compiled program: {}", path.display());
    }

    println!(
        "distributed proof generated with {} (remote_partitions={}, peers={}) -> {}",
        backend.requested_name,
        execution.report.remote_partition_count,
        execution.report.peer_count,
        args.out.display()
    );
    Ok(())
}

fn ensure_program_passes_fail_closed_audit(
    program: &Program,
    backend: zkf_core::BackendKind,
    json: bool,
) -> Result<(), String> {
    let zir = program_v2_to_zir(program);
    let report = zkf_core::audit_program_with_capability_matrix(
        &zir,
        Some(backend),
        &zkf_backends::backend_capability_matrix(),
    );
    if report.summary.failed == 0 {
        return Ok(());
    }

    let failed_categories = report
        .checks
        .iter()
        .filter(|check| check.status == AuditStatus::Fail)
        .map(|check| audit_category_name(check.category))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let analysis = failed_categories
        .iter()
        .any(|category| category == "underconstrained_signals")
        .then(|| zkf_core::analyze_underconstrained(program));
    let message = format!("audit failed: {} check(s) failed", report.summary.failed);

    if json {
        let payload = ProveAuditFailurePayload {
            status: "error",
            error_kind: "audit_failure",
            message,
            failed_checks: report.summary.failed,
            failed_categories,
            audit_report: report,
            underconstraint_analysis: analysis,
        };
        let json = serde_json::to_string_pretty(&payload).map_err(|err| err.to_string())?;
        return Err(raw_cli_error(json));
    }

    Err(render_zkf_error(zkf_core::ZkfError::AuditFailure {
        message,
        failed_checks: report.summary.failed,
        report: Box::new(report),
        analysis: analysis.map(Box::new),
    }))
}

fn audit_category_name(category: AuditCategory) -> String {
    match category {
        AuditCategory::ConstraintSoundness => "constraint_soundness",
        AuditCategory::UnderconstrainedSignals => "underconstrained_signals",
        AuditCategory::TypeSafety => "type_safety",
        AuditCategory::BackendHonesty => "backend_honesty",
        AuditCategory::GpuAccuracy => "gpu_accuracy",
        AuditCategory::Reproducibility => "reproducibility",
        AuditCategory::SetupIntegrity => "setup_integrity",
        AuditCategory::Normalization => "normalization",
    }
    .to_string()
}

fn maybe_export_artifact(
    export: Option<&str>,
    _source_backend: zkf_core::BackendKind,
    artifact: ProofArtifact,
    compiled: &CompiledProgram,
    allow_attestation: bool,
) -> Result<ProofArtifact, String> {
    let Some("groth16") = export else {
        return Ok(artifact);
    };

    if artifact.backend == zkf_core::BackendKind::ArkworksGroth16 {
        return Ok(artifact);
    }

    let trust_lane = if allow_attestation {
        zkf_runtime::RequiredTrustLane::AllowAttestation
    } else {
        zkf_runtime::RequiredTrustLane::StrictCryptographic
    };
    crate::cmd::runtime::wrap_artifact_via_runtime(
        &artifact,
        compiled,
        trust_lane,
        zkf_runtime::HardwareProfile::detect(),
        None,
    )
}

fn annotate_artifact_with_distributed_report(
    artifact: &mut ProofArtifact,
    report: &zkf_distributed::DistributedExecutionReport,
) -> Result<(), String> {
    artifact
        .metadata
        .insert("distributed_execution".into(), "true".into());
    artifact.metadata.insert(
        "distributed_report".into(),
        serde_json::to_string(report).map_err(|err| err.to_string())?,
    );
    artifact.metadata.insert(
        "distributed_remote_partitions".into(),
        report.remote_partition_count.to_string(),
    );
    artifact.metadata.insert(
        "distributed_peer_count".into(),
        report.peer_count.to_string(),
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_verify(
    program: PathBuf,
    artifact: PathBuf,
    backend: String,
    compiled: Option<PathBuf>,
    seed: Option<String>,
    groth16_setup_blob: Option<PathBuf>,
    allow_dev_deterministic_groth16: bool,
    hybrid: bool,
    allow_compat: bool,
) -> Result<(), String> {
    let program: Program = load_program_v2(&program)?;
    let artifact: ProofArtifact = read_json(&artifact)?;
    if hybrid || artifact.hybrid_bundle.is_some() {
        let ok = zkf_runtime::verify_hybrid_artifact(&program, &artifact)
            .map_err(|err| err.to_string())?;
        if ok {
            println!("verification: OK");
            return Ok(());
        }
        return Err("verification: FAILED".to_string());
    }

    let request = parse_backend_request(&backend)?;
    ensure_backend_request_allowed(&request, allow_compat)?;
    let used_explicit_compiled = compiled.is_some();
    let explicit_compiled = if let Some(path) = compiled.as_ref() {
        let compiled: CompiledProgram = read_json(path)?;
        validate_compiled_artifact_for_request(
            &compiled,
            &request,
            &program.digest_hex(),
            &format!("compiled artifact {}", path.display()),
        )?;
        Some(compiled)
    } else {
        None
    };
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let (compiled, _) = resolve_compiled_artifact_for_request(
        &program,
        &request,
        explicit_compiled,
        used_explicit_compiled,
        seed,
        groth16_setup_blob.as_deref(),
        allow_dev_deterministic_groth16,
        "zkf verify",
    )?;
    let engine = backend_for_request(&request);
    let ok = match engine.verify(&compiled, &artifact) {
        Ok(ok) => ok,
        Err(err) => {
            return Err(render_verify_context_error(
                &request,
                used_explicit_compiled,
                seed.is_some(),
                groth16_setup_blob.is_some(),
                render_zkf_error(err),
            ));
        }
    };

    if ok {
        println!("verification: OK");
        Ok(())
    } else {
        Err(render_verify_context_error(
            &request,
            used_explicit_compiled,
            seed.is_some(),
            groth16_setup_blob.is_some(),
            "verification returned false".to_string(),
        ))
    }
}

fn render_verify_context_error(
    request: &crate::util::BackendRequest,
    used_explicit_compiled: bool,
    provided_seed: bool,
    provided_setup_blob: bool,
    detail: String,
) -> String {
    if used_explicit_compiled {
        return format!("verification failed with the supplied compiled artifact: {detail}");
    }

    if request.backend == zkf_core::BackendKind::ArkworksGroth16
        && (detail.contains("verification key mismatch")
            || detail.contains("verification returned false"))
    {
        let mut missing = Vec::new();
        if !provided_seed {
            missing.push("--seed");
        }
        if !provided_setup_blob {
            missing.push("--groth16-setup-blob");
        }
        let hint = if missing.is_empty() {
            "If this proof was created from a different Groth16 compiled context, verify with the exact compiled artifact via --compiled.".to_string()
        } else {
            format!(
                "If this proof was created from a different Groth16 compiled context, rerun with the matching {} or pass the exact compiled artifact via --compiled.",
                missing.join(" / ")
            )
        };
        return format!(
            "verification failed: the supplied program did not reproduce the proof's Groth16 verification context ({detail}). {hint}"
        );
    }

    format!("verification failed: {detail}")
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_wrap(
    proof_path: PathBuf,
    compiled_path: PathBuf,
    hardware_profile: Option<String>,
    allow_attestation: bool,
    compress: bool,
    dry_run: bool,
    out: PathBuf,
    trace_out: Option<PathBuf>,
) -> Result<(), String> {
    crate::cmd::runtime::handle_wrap_via_runtime(
        proof_path,
        compiled_path,
        hardware_profile,
        allow_attestation,
        compress,
        dry_run,
        out,
        trace_out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::BackendKind;

    #[test]
    fn export_passthrough_keeps_native_groth16() {
        let artifact = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata: Default::default(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };
        let compiled = CompiledProgram::new(
            BackendKind::ArkworksGroth16,
            zkf_examples::mul_add_program(),
        );

        let exported = maybe_export_artifact(
            Some("groth16"),
            BackendKind::ArkworksGroth16,
            artifact.clone(),
            &compiled,
            false,
        )
        .unwrap();

        assert_eq!(exported.backend, artifact.backend);
        assert_eq!(exported.program_digest, artifact.program_digest);
    }
}
