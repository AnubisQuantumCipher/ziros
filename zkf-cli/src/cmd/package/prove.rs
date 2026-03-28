use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::thread;

use zkf_backends::{CapabilityReport, GpuStageCoverage, recommend_gpu_jobs};
use zkf_core::{CompiledProgram, PackageManifest, Program, ProofArtifact, Witness};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

use crate::package_io::{
    load_compiled_artifact, run_witness_ref, write_compiled_artifact, write_proof_artifacts,
};
use crate::util::{
    BackendRequest, annotate_compiled_for_request, capability_report_for_backend,
    ensure_backend_request_allowed, ensure_backend_supports_program_constraints,
    ensure_backend_supports_zir_constraints, ensure_manifest_v2_metadata_for_command,
    load_program_v2_for_backend, load_program_v2_from_manifest, manifest_ir_family,
    parse_backend_request, parse_optimization_objective, parse_prove_mode, parse_setup_seed,
    prepare_existing_source_witness, read_json, resolve_backend_targets_or_mode,
    resolve_compiled_artifact_for_request, with_proof_seed_override, with_setup_seed_override,
    write_json,
};

pub(crate) fn prove_package(
    manifest_path: &Path,
    request: &BackendRequest,
    objective: zkf_runtime::OptimizationObjective,
    run_id: &str,
    seed: Option<[u8; 32]>,
    hybrid: bool,
) -> Result<crate::ProveResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package prove")?;
    let run_id = crate::package_io::normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let backend = request.backend;
    let program = load_program_v2_for_backend(root, &manifest, backend)?;
    let witness_ref = run_witness_ref(&manifest, &run_id).ok_or_else(|| {
        format!(
            "package is missing witness artifact for run_id '{}'; run `zkf run --run-id {}` first",
            run_id, run_id
        )
    })?;
    let witness_path = root.join(&witness_ref.path);
    let witness: Witness = read_json(&witness_path)?;

    let cached_compiled = load_compiled_artifact(root, &manifest, backend, &program.digest_hex())?;
    let (compiled, recovered_compiled) = resolve_compiled_artifact_for_request(
        &program,
        request,
        cached_compiled,
        false,
        seed,
        None,
        false,
        "zkf package prove",
    )?;
    if recovered_compiled {
        write_compiled_artifact(root, &mut manifest, backend, &compiled)?;
    }
    let prepared_witness = prepare_existing_source_witness(&compiled, &witness)?;
    let artifact = if hybrid {
        let execution = with_setup_seed_override(seed, || {
            with_proof_seed_override(seed, || {
                zkf_runtime::run_hybrid_prove_job_with_objective(
                    Arc::new(program.clone()),
                    None,
                    Some(Arc::new(prepared_witness.clone())),
                    objective,
                    RequiredTrustLane::StrictCryptographic,
                    ExecutionMode::Deterministic,
                )
                .map_err(|e| e.to_string())
            })
        })?;
        let mut artifact = execution.artifact;
        crate::util::annotate_artifact_with_runtime_report(
            &mut artifact,
            &execution.wrapped.result,
        );
        artifact
    } else {
        let execution = with_setup_seed_override(seed, || {
            with_proof_seed_override(seed, || {
                RuntimeExecutor::run_backend_prove_job_with_objective(
                    backend,
                    request.route,
                    Arc::new(program.clone()),
                    None,
                    Some(Arc::new(prepared_witness.clone())),
                    Some(Arc::new(compiled.clone())),
                    objective,
                    RequiredTrustLane::StrictCryptographic,
                    ExecutionMode::Deterministic,
                )
                .map_err(|e| e.to_string())
            })
        })?;
        let mut artifact = execution.artifact;
        crate::util::annotate_artifact_with_runtime_report(&mut artifact, &execution.result);
        artifact
    };
    let (proof_path, report_path) = write_proof_artifacts(
        root,
        &mut manifest,
        backend,
        &run_id,
        &program,
        &witness,
        &artifact,
    )?;

    manifest.metadata.insert(
        "last_prove_backend".to_string(),
        backend.as_str().to_string(),
    );
    manifest
        .metadata
        .insert("last_prove_run_id".to_string(), run_id.clone());
    write_json(manifest_path, &manifest)?;
    let runtime_realization = crate::util::runtime_execution_realization(&artifact.metadata);

    Ok(crate::ProveResult {
        manifest: manifest_path.display().to_string(),
        backend: backend.as_str().to_string(),
        run_id,
        proof_path: proof_path.display().to_string(),
        report_path: report_path.display().to_string(),
        proof_size_bytes: artifact.proof.len(),
        public_inputs: artifact.public_inputs.len(),
        proof_semantics: artifact.metadata.get("proof_semantics").cloned(),
        prover_acceleration_scope: artifact.metadata.get("prover_acceleration_scope").cloned(),
        proof_engine: artifact.metadata.get("proof_engine").cloned(),
        gpu_stage_coverage: metadata_stage_coverage(&artifact.metadata),
        metal_complete: metadata_bool(&artifact.metadata, "metal_complete"),
        runtime_execution_regime: runtime_realization.execution_regime,
        runtime_gpu_stage_busy_ratio: runtime_realization.gpu_stage_busy_ratio,
        runtime_prover_acceleration_realized: runtime_realization.prover_acceleration_realized,
        prover_acceleration_realization: runtime_realization.acceleration_label,
        cpu_math_fallback_reason: artifact.metadata.get("cpu_math_fallback_reason").cloned(),
        export_scheme: artifact.metadata.get("export_scheme").cloned(),
        metal_gpu_busy_ratio: metadata_f64(&artifact.metadata, "metal_gpu_busy_ratio"),
        metal_stage_breakdown: artifact.metadata.get("metal_stage_breakdown").cloned(),
        metal_inflight_jobs: metadata_usize(&artifact.metadata, "metal_inflight_jobs"),
        metal_no_cpu_fallback: metadata_bool(&artifact.metadata, "metal_no_cpu_fallback"),
        metal_counter_source: artifact.metadata.get("metal_counter_source").cloned(),
        hybrid,
        security_profile: Some(artifact.effective_security_profile().as_str().to_string()),
        replay_manifest_path: artifact
            .metadata
            .get("hybrid_replay_manifest_path")
            .cloned(),
        companion_backend: artifact
            .hybrid_bundle
            .as_ref()
            .map(|bundle| bundle.companion_leg.backend.as_str().to_string()),
    })
}

pub(crate) fn prove_all_package(
    manifest_path: &Path,
    selected_backends: &[BackendRequest],
    run_id: &str,
    parallel: bool,
    jobs: Option<usize>,
    seed: Option<[u8; 32]>,
) -> Result<crate::ProveAllResult, String> {
    let run_id = crate::package_io::normalize_run_id(run_id)?;

    if !parallel {
        let mut entries = Vec::new();
        let manifest: PackageManifest = read_json(manifest_path)?;
        ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package prove-all")?;
        for request in selected_backends {
            match prove_package(
                manifest_path,
                request,
                zkf_runtime::OptimizationObjective::FastestProve,
                &run_id,
                seed,
                false,
            ) {
                Ok(report) => entries.push(success_entry(report)),
                Err(err) => entries.push(failed_entry(request.backend, err)),
            }
        }
        let (succeeded, failed, skipped) = prove_all_counts(&entries);
        return Ok(crate::ProveAllResult {
            manifest: manifest_path.display().to_string(),
            run_id,
            requested: entries.len(),
            succeeded,
            failed,
            skipped,
            parallel: false,
            jobs_used: 1,
            scheduler: None,
            results: entries,
        });
    }

    if seed.is_some() {
        return Err(
            "package prove-all --parallel does not support --seed because setup seed override is process-global"
                .to_string(),
        );
    }

    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package prove-all")?;
    if selected_backends.is_empty() {
        return Err("package prove-all resolved no backend targets".to_string());
    }

    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let program: Program = load_program_v2_from_manifest(root, &manifest)?;
    let zir_program = if manifest_ir_family(&manifest) == "zir-v1" {
        let program_path = root.join(&manifest.files.program.path);
        Some(read_json::<zkf_core::zir_v1::Program>(&program_path)?)
    } else {
        None
    };
    for request in selected_backends.iter() {
        let backend = request.backend;
        if let Some(zir) = &zir_program {
            ensure_backend_supports_zir_constraints(backend, zir)?;
        }
        ensure_backend_supports_program_constraints(backend, &program)?;
    }
    let witness_ref = run_witness_ref(&manifest, &run_id).ok_or_else(|| {
        format!(
            "package is missing witness artifact for run_id '{}'; run `zkf run --run-id {}` first",
            run_id, run_id
        )
    })?;
    let witness_path = root.join(&witness_ref.path);
    let witness: Witness = read_json(&witness_path)?;

    #[derive(Debug)]
    struct ParallelProveItem {
        index: usize,
        request: BackendRequest,
        compiled: CompiledProgram,
        artifact: ProofArtifact,
    }

    let backend_targets = selected_backends
        .iter()
        .map(|request| request.backend)
        .collect::<Vec<_>>();
    let scheduler = recommend_gpu_jobs(
        &backend_targets,
        program.constraints.len(),
        program.signals.len(),
        jobs,
        backend_targets.len(),
    );
    let worker_count = scheduler.recommended_jobs.max(1);

    let requests = Arc::new(selected_backends.to_vec());
    let next_index = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel();
    for _ in 0..worker_count {
        let sender = sender.clone();
        let requests = Arc::clone(&requests);
        let next_index = Arc::clone(&next_index);
        let program = program.clone();
        let witness = witness.clone();
        thread::spawn(move || {
            loop {
                let index = next_index.fetch_add(1, Ordering::SeqCst);
                if index >= requests.len() {
                    break;
                }
                let request = requests[index].clone();
                let request_for_result = request.clone();
                let backend = request.backend;
                let result = crate::util::compile_program_for_request_with_overrides(
                    &program,
                    &request,
                    None,
                    None,
                    false,
                    "zkf package prove-all --parallel",
                )
                .and_then(|mut compiled| {
                    annotate_compiled_for_request(&mut compiled, &request);
                    let prepared_witness = prepare_existing_source_witness(&compiled, &witness)?;
                    RuntimeExecutor::run_backend_prove_job_with_objective(
                        backend,
                        request.route,
                        Arc::new(program.clone()),
                        None,
                        Some(Arc::new(prepared_witness)),
                        Some(Arc::new(compiled.clone())),
                        zkf_runtime::OptimizationObjective::FastestProve,
                        RequiredTrustLane::StrictCryptographic,
                        ExecutionMode::Deterministic,
                    )
                    .map(|execution| ParallelProveItem {
                        index,
                        request: request_for_result,
                        compiled: execution.compiled,
                        artifact: {
                            let mut artifact = execution.artifact;
                            crate::util::annotate_artifact_with_runtime_report(
                                &mut artifact,
                                &execution.result,
                            );
                            artifact
                        },
                    })
                    .map_err(|e| e.to_string())
                });
                let _ = sender.send((request, result));
            }
        });
    }
    drop(sender);

    let mut results = Vec::new();
    let mut successes = Vec::new();
    for _ in 0..requests.len() {
        match receiver.recv() {
            Ok((_, Ok(item))) => successes.push(item),
            Ok((request, Err(err))) => results.push(failed_entry(request.backend, err)),
            Err(err) => {
                return Err(format!(
                    "package prove-all parallel worker channel failed: {err}"
                ));
            }
        }
    }

    successes.sort_by_key(|item| item.index);
    for item in successes {
        let mut compiled = item.compiled.clone();
        annotate_compiled_for_request(&mut compiled, &item.request);
        write_compiled_artifact(root, &mut manifest, item.request.backend, &compiled)?;
        let (proof_path, _) = write_proof_artifacts(
            root,
            &mut manifest,
            item.request.backend,
            &run_id,
            &program,
            &witness,
            &item.artifact,
        )?;
        let runtime_realization =
            crate::util::runtime_execution_realization(&item.artifact.metadata);
        results.push(success_entry(crate::ProveResult {
            manifest: manifest_path.display().to_string(),
            backend: item.request.backend.as_str().to_string(),
            run_id: run_id.clone(),
            proof_path: proof_path.display().to_string(),
            report_path: String::new(),
            proof_size_bytes: item.artifact.proof.len(),
            public_inputs: item.artifact.public_inputs.len(),
            proof_semantics: item.artifact.metadata.get("proof_semantics").cloned(),
            prover_acceleration_scope: item
                .artifact
                .metadata
                .get("prover_acceleration_scope")
                .cloned(),
            proof_engine: item.artifact.metadata.get("proof_engine").cloned(),
            gpu_stage_coverage: metadata_stage_coverage(&item.artifact.metadata),
            metal_complete: metadata_bool(&item.artifact.metadata, "metal_complete"),
            runtime_execution_regime: runtime_realization.execution_regime,
            runtime_gpu_stage_busy_ratio: runtime_realization.gpu_stage_busy_ratio,
            runtime_prover_acceleration_realized: runtime_realization.prover_acceleration_realized,
            prover_acceleration_realization: runtime_realization.acceleration_label,
            cpu_math_fallback_reason: item
                .artifact
                .metadata
                .get("cpu_math_fallback_reason")
                .cloned(),
            export_scheme: item.artifact.metadata.get("export_scheme").cloned(),
            metal_gpu_busy_ratio: metadata_f64(&item.artifact.metadata, "metal_gpu_busy_ratio"),
            metal_stage_breakdown: item.artifact.metadata.get("metal_stage_breakdown").cloned(),
            metal_inflight_jobs: metadata_usize(&item.artifact.metadata, "metal_inflight_jobs"),
            metal_no_cpu_fallback: metadata_bool(&item.artifact.metadata, "metal_no_cpu_fallback"),
            metal_counter_source: item.artifact.metadata.get("metal_counter_source").cloned(),
            hybrid: false,
            security_profile: item
                .artifact
                .metadata
                .get("proof_security_profile")
                .cloned(),
            replay_manifest_path: None,
            companion_backend: None,
        }));
    }
    results.sort_by(|a, b| a.backend.cmp(&b.backend));

    manifest
        .metadata
        .insert("last_prove_run_id".to_string(), run_id.clone());
    manifest
        .metadata
        .insert("last_prove_parallel".to_string(), "true".to_string());
    manifest
        .metadata
        .insert("last_prove_jobs".to_string(), worker_count.to_string());
    manifest.metadata.insert(
        "last_prove_jobs_requested".to_string(),
        scheduler.requested_jobs.to_string(),
    );
    manifest.metadata.insert(
        "last_prove_jobs_recommended".to_string(),
        scheduler.recommended_jobs.to_string(),
    );
    manifest.metadata.insert(
        "last_prove_scheduler_reason".to_string(),
        scheduler.reason.clone(),
    );
    write_json(manifest_path, &manifest)?;

    let (succeeded, failed, skipped) = prove_all_counts(&results);
    Ok(crate::ProveAllResult {
        manifest: manifest_path.display().to_string(),
        run_id,
        requested: results.len(),
        succeeded,
        failed,
        skipped,
        parallel: true,
        jobs_used: worker_count,
        scheduler: Some(scheduler),
        results,
    })
}

fn metadata_f64(metadata: &std::collections::BTreeMap<String, String>, key: &str) -> Option<f64> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
}

fn metadata_usize(
    metadata: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Option<usize> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
}

fn metadata_bool(metadata: &std::collections::BTreeMap<String, String>, key: &str) -> Option<bool> {
    metadata
        .get(key)
        .and_then(|value| value.parse::<bool>().ok())
}

fn metadata_stage_coverage(
    metadata: &std::collections::BTreeMap<String, String>,
) -> Option<GpuStageCoverage> {
    metadata
        .get("gpu_stage_coverage")
        .and_then(|value| serde_json::from_str::<GpuStageCoverage>(value).ok())
}

pub(crate) struct ProveOptions {
    pub manifest: PathBuf,
    pub backend: Option<String>,
    pub objective: String,
    pub mode: Option<String>,
    pub run_id: String,
    pub json: bool,
    pub seed: Option<String>,
    pub hybrid: bool,
    pub allow_compat: bool,
}

pub(crate) fn handle_prove(opts: ProveOptions) -> Result<(), String> {
    let ProveOptions {
        manifest,
        backend,
        objective,
        mode,
        run_id,
        json,
        seed,
        hybrid,
        allow_compat,
    } = opts;
    let objective = parse_optimization_objective(Some(&objective))?;
    let manifest_preview: PackageManifest = read_json(&manifest)?;
    let program = {
        let root = manifest
            .parent()
            .ok_or_else(|| format!("manifest has no parent directory: {}", manifest.display()))?;
        load_program_v2_from_manifest(root, &manifest_preview)?
    };
    if hybrid
        && let Some(requested) = backend.as_deref()
        && requested != "plonky3"
    {
        return Err(
            "--hybrid currently requires backend=plonky3 or no explicit backend".to_string(),
        );
    }
    let backend = if hybrid {
        parse_backend_request("plonky3")?
    } else {
        crate::util::resolve_backend_or_mode(
            backend.as_deref(),
            mode.as_deref(),
            &program,
            objective,
        )?
    };
    ensure_backend_request_allowed(&backend, allow_compat)?;
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let report = prove_package(&manifest, &backend, objective, &run_id, seed, hybrid)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package prove: backend={} run_id={} proof_size={} public_inputs={} hybrid={}",
            report.backend,
            report.run_id,
            report.proof_size_bytes,
            report.public_inputs,
            report.hybrid
        );
    }
    Ok(())
}

pub(crate) struct ProveAllOptions {
    pub manifest: PathBuf,
    pub backends: Option<Vec<String>>,
    pub mode: Option<String>,
    pub run_id: String,
    pub parallel: bool,
    pub jobs: Option<usize>,
    pub json: bool,
    pub seed: Option<String>,
    pub allow_compat: bool,
}

pub(crate) fn handle_prove_all(opts: ProveAllOptions) -> Result<(), String> {
    let ProveAllOptions {
        manifest,
        backends,
        mode,
        run_id,
        parallel,
        jobs,
        json,
        seed,
        allow_compat,
    } = opts;
    let selected_backends = backends
        .unwrap_or_default()
        .into_iter()
        .map(|name| parse_backend_request(&name))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest_preview: PackageManifest = read_json(&manifest)?;
    let root = manifest
        .parent()
        .ok_or_else(|| format!("manifest has no parent directory: {}", manifest.display()))?;
    let program = load_program_v2_from_manifest(root, &manifest_preview)?;
    let explicit_mode = parse_prove_mode(mode.as_deref())?;
    let mut resolved_backends = resolve_backend_targets_or_mode(
        &selected_backends,
        mode.as_deref(),
        &program,
        &manifest_preview.backend_targets,
    )?;
    let default_native_mode = selected_backends.is_empty() && explicit_mode.is_none();
    let mut skipped = Vec::new();
    let mut runnable = Vec::new();
    for request in resolved_backends.drain(..) {
        let zir_support = if manifest_ir_family(&manifest_preview) == "zir-v1" {
            let program_path = root.join(&manifest_preview.files.program.path);
            let zir_program = read_json::<zkf_core::zir_v1::Program>(&program_path)?;
            ensure_backend_supports_zir_constraints(request.backend, &zir_program)
        } else {
            Ok(())
        };
        let constraint_support =
            ensure_backend_supports_program_constraints(request.backend, &program);
        let readiness = ensure_backend_request_allowed(&request, allow_compat);
        if default_native_mode {
            match (readiness, zir_support, constraint_support) {
                (Ok(()), Ok(()), Ok(())) => runnable.push(request),
                (readiness_result, zir_result, constraint_result) => {
                    let report = capability_report_for_backend(request.backend)?;
                    let error = readiness_result
                        .err()
                        .or_else(|| zir_result.err())
                        .or_else(|| constraint_result.err());
                    skipped.push(skipped_entry(&report, error));
                }
            }
        } else {
            readiness?;
            zir_support?;
            constraint_support?;
            runnable.push(request);
        }
    }
    if default_native_mode {
        for report in zkf_backends::capabilities_report() {
            if report.implementation_type == zkf_core::SupportClass::Delegated
                || report.production_ready
            {
                continue;
            }
            if skipped
                .iter()
                .any(|entry| entry.backend == report.capabilities.backend.as_str())
            {
                continue;
            }
            skipped.push(skipped_entry(&report, None));
        }
    }
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let mut report = if runnable.is_empty() && !skipped.is_empty() {
        crate::ProveAllResult {
            manifest: manifest.display().to_string(),
            run_id: crate::package_io::normalize_run_id(&run_id)?,
            requested: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            parallel,
            jobs_used: if parallel {
                jobs.unwrap_or(1).max(1)
            } else {
                1
            },
            scheduler: None,
            results: Vec::new(),
        }
    } else {
        prove_all_package(&manifest, &runnable, &run_id, parallel, jobs, seed)?
    };
    report.results.extend(skipped);
    report.results.sort_by(|a, b| a.backend.cmp(&b.backend));
    let (succeeded, failed, skipped) = prove_all_counts(&report.results);
    report.requested = report.results.len();
    report.succeeded = succeeded;
    report.failed = failed;
    report.skipped = skipped;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package prove-all: run_id={} requested={} succeeded={} failed={} skipped={} parallel={} jobs_used={}",
            report.run_id,
            report.requested,
            report.succeeded,
            report.failed,
            report.skipped,
            report.parallel,
            report.jobs_used
        );
    }
    Ok(())
}

fn success_entry(report: crate::ProveResult) -> crate::ProveAllEntry {
    crate::ProveAllEntry {
        backend: report.backend,
        status: "succeeded".to_string(),
        ok: true,
        proof_path: Some(report.proof_path),
        proof_size_bytes: Some(report.proof_size_bytes),
        public_inputs: Some(report.public_inputs),
        proof_semantics: report.proof_semantics,
        prover_acceleration_scope: report.prover_acceleration_scope,
        proof_engine: report.proof_engine,
        gpu_stage_coverage: report.gpu_stage_coverage,
        metal_complete: report.metal_complete,
        runtime_execution_regime: report.runtime_execution_regime,
        runtime_gpu_stage_busy_ratio: report.runtime_gpu_stage_busy_ratio,
        runtime_prover_acceleration_realized: report.runtime_prover_acceleration_realized,
        prover_acceleration_realization: report.prover_acceleration_realization,
        cpu_math_fallback_reason: report.cpu_math_fallback_reason,
        export_scheme: report.export_scheme,
        metal_gpu_busy_ratio: report.metal_gpu_busy_ratio,
        metal_stage_breakdown: report.metal_stage_breakdown,
        metal_inflight_jobs: report.metal_inflight_jobs,
        metal_no_cpu_fallback: report.metal_no_cpu_fallback,
        metal_counter_source: report.metal_counter_source,
        implementation_type: None,
        readiness: Some("ready".to_string()),
        readiness_reason: None,
        operator_action: None,
        explicit_compat_alias: None,
        error: None,
    }
}

fn failed_entry(backend: zkf_core::BackendKind, err: String) -> crate::ProveAllEntry {
    crate::ProveAllEntry {
        backend: backend.as_str().to_string(),
        status: "failed".to_string(),
        ok: false,
        proof_path: None,
        proof_size_bytes: None,
        public_inputs: None,
        proof_semantics: None,
        prover_acceleration_scope: None,
        proof_engine: None,
        gpu_stage_coverage: None,
        metal_complete: None,
        runtime_execution_regime: None,
        runtime_gpu_stage_busy_ratio: None,
        runtime_prover_acceleration_realized: None,
        prover_acceleration_realization: None,
        cpu_math_fallback_reason: None,
        export_scheme: None,
        metal_gpu_busy_ratio: None,
        metal_stage_breakdown: None,
        metal_inflight_jobs: None,
        metal_no_cpu_fallback: None,
        metal_counter_source: None,
        implementation_type: None,
        readiness: None,
        readiness_reason: None,
        operator_action: None,
        explicit_compat_alias: None,
        error: Some(err),
    }
}

fn skipped_entry(report: &CapabilityReport, error: Option<String>) -> crate::ProveAllEntry {
    let program_blocked = error.is_some() && report.readiness == "ready";
    crate::ProveAllEntry {
        backend: report.capabilities.backend.as_str().to_string(),
        status: "skipped".to_string(),
        ok: false,
        proof_path: None,
        proof_size_bytes: None,
        public_inputs: None,
        proof_semantics: None,
        prover_acceleration_scope: None,
        proof_engine: Some(report.proof_engine.clone()),
        gpu_stage_coverage: Some(report.gpu_stage_coverage.clone()),
        metal_complete: Some(report.metal_complete),
        runtime_execution_regime: None,
        runtime_gpu_stage_busy_ratio: None,
        runtime_prover_acceleration_realized: None,
        prover_acceleration_realization: None,
        cpu_math_fallback_reason: report.cpu_math_fallback_reason.clone(),
        export_scheme: report.export_scheme.clone(),
        metal_gpu_busy_ratio: None,
        metal_stage_breakdown: None,
        metal_inflight_jobs: None,
        metal_no_cpu_fallback: None,
        metal_counter_source: None,
        implementation_type: Some(report.implementation_type),
        readiness: Some(if program_blocked {
            "blocked".to_string()
        } else {
            report.readiness.clone()
        }),
        readiness_reason: if program_blocked {
            Some("program-unsupported".to_string())
        } else {
            report.readiness_reason.clone()
        },
        operator_action: if program_blocked {
            Some(
                "choose a backend that supports the program constraints or lower the circuit differently"
                    .to_string(),
            )
        } else {
            report.operator_action.clone()
        },
        explicit_compat_alias: report.explicit_compat_alias.clone(),
        error,
    }
}

fn prove_all_counts(entries: &[crate::ProveAllEntry]) -> (usize, usize, usize) {
    let succeeded = entries
        .iter()
        .filter(|entry| entry.status == "succeeded")
        .count();
    let skipped = entries
        .iter()
        .filter(|entry| entry.status == "skipped")
        .count();
    let failed = entries.len().saturating_sub(succeeded + skipped);
    (succeeded, failed, skipped)
}
