use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zkf_backends::backend_for;
use zkf_core::{
    CompiledProgram, PackageFileRef, PackageManifest, Program, ProofArtifact, generate_witness,
};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

use crate::compose::{
    compose_blackbox_semantics, compose_expected_public_inputs, compose_proof_metadata_matches,
    compose_proof_semantics, compose_prover_acceleration_scope, compose_report_matches_aggregate,
    composition_program_for_digest, compute_compose_binding_digest, compute_composition_digest,
    public_input_commitment_for_artifact, statement_digest_for_artifact,
    verification_key_digest_for_artifact,
};
use crate::package_io::{
    bundle_artifact_ref, compose_program_key, compose_proof_key, compose_report_key,
    compose_verify_key, load_compiled_artifact, normalize_run_id,
};
use crate::util::{
    BackendRequest, backend_for_request, ensure_backend_request_allowed,
    ensure_backend_supports_program_constraints, ensure_backend_supports_zir_constraints,
    ensure_manifest_v2_metadata_for_command, load_program_v2_from_manifest, manifest_ir_family,
    parse_backend, parse_backend_request, parse_setup_seed, read_json, render_zkf_error,
    sha256_hex, with_proof_seed_override, with_setup_seed_override, write_json,
    write_json_and_hash,
};

pub(crate) fn compose_package_proofs(
    manifest_path: &Path,
    run_id: &str,
    request: &BackendRequest,
    seed: Option<[u8; 32]>,
) -> Result<crate::ComposeResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package compose")?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    if bundle_artifact_ref(&manifest, &run_id).is_none() {
        super::bundle::bundle_package_proofs(manifest_path, &run_id, &[])?;
        manifest = read_json(manifest_path)?;
    }

    let aggregate_ref = bundle_artifact_ref(&manifest, &run_id).ok_or_else(|| {
        format!(
            "missing bundle artifact for run_id '{}'; run `zkf package bundle --run-id {}` first",
            run_id, run_id
        )
    })?;
    let aggregate_path = root.join(&aggregate_ref.path);
    let aggregate: crate::AggregateArtifact = read_json(&aggregate_path)?;
    if aggregate.scheme != "statement-hash-chain-v3" {
        return Err(format!(
            "compose requires bundle scheme 'statement-hash-chain-v3', found '{}' (re-run `zkf package bundle --run-id {}`)",
            aggregate.scheme, run_id
        ));
    }
    let carried_valid = verify_carried_entries(root, &manifest, &aggregate, seed)?;
    if !carried_valid {
        return Err("compose aborted: one or more carried proofs failed verification".to_string());
    }

    let backend = request.backend;
    let composition_digest = compute_composition_digest(backend, &run_id, &aggregate);
    let compose_program =
        composition_program_for_digest(backend, &run_id, &composition_digest, &aggregate)?;
    let witness = generate_witness(&compose_program, &BTreeMap::new()).map_err(render_zkf_error)?;

    ensure_backend_supports_program_constraints(backend, &compose_program)?;
    let engine = backend_for_request(request);
    let execution = with_setup_seed_override(seed, || {
        with_proof_seed_override(seed, || {
            RuntimeExecutor::run_backend_prove_job(
                backend,
                request.route,
                Arc::new(compose_program.clone()),
                None,
                Some(Arc::new(witness.clone())),
                None,
                RequiredTrustLane::StrictCryptographic,
                ExecutionMode::Deterministic,
            )
            .map_err(|err| err.to_string())
        })
    })?;
    let compiled = execution.compiled;
    let mut artifact = execution.artifact;
    crate::util::annotate_artifact_with_runtime_report(&mut artifact, &execution.result);
    let proof_ok = engine
        .verify(&compiled, &artifact)
        .map_err(render_zkf_error)?;
    if !proof_ok {
        return Err("compose backend proof failed local verification".to_string());
    }

    if let Some(value) = artifact.metadata.get("proof_semantics").cloned() {
        artifact
            .metadata
            .insert("compose_backend_proof_semantics".to_string(), value);
    }
    if let Some(value) = artifact.metadata.get("blackbox_semantics").cloned() {
        artifact
            .metadata
            .insert("compose_backend_blackbox_semantics".to_string(), value);
    }
    if let Some(value) = artifact.metadata.get("prover_acceleration_scope").cloned() {
        artifact.metadata.insert(
            "compose_backend_prover_acceleration_scope".to_string(),
            value,
        );
    }
    artifact.metadata.insert(
        "proof_semantics".to_string(),
        compose_proof_semantics().to_string(),
    );
    artifact.metadata.insert(
        "blackbox_semantics".to_string(),
        compose_blackbox_semantics().to_string(),
    );
    artifact.metadata.insert(
        "prover_acceleration_scope".to_string(),
        compose_prover_acceleration_scope(backend),
    );

    artifact.metadata.insert(
        "compose_scheme".to_string(),
        "attestation-composition-v3".to_string(),
    );
    artifact
        .metadata
        .insert("compose_run_id".to_string(), run_id.clone());
    artifact
        .metadata
        .insert("compose_backend".to_string(), backend.as_str().to_string());
    artifact.metadata.insert(
        "compose_aggregate_digest".to_string(),
        aggregate.aggregate_digest.clone(),
    );
    artifact.metadata.insert(
        "compose_composition_digest".to_string(),
        composition_digest.clone(),
    );
    artifact.metadata.insert(
        "compose_carried_entries".to_string(),
        aggregate.entries.len().to_string(),
    );
    artifact.metadata.insert(
        "compose_binding_digest".to_string(),
        compute_compose_binding_digest(&aggregate),
    );

    let compose_program_rel = PathBuf::from(format!(
        "proofs/compose/{}/{run_id}/program.json",
        backend.as_str()
    ));
    let compose_program_path = root.join(&compose_program_rel);
    let compose_program_sha = write_json_and_hash(&compose_program_path, &compose_program)?;
    let proof_rel = PathBuf::from(format!(
        "proofs/compose/{}/{run_id}/proof.json",
        backend.as_str()
    ));
    let proof_path = root.join(&proof_rel);
    let proof_sha = write_json_and_hash(&proof_path, &artifact)?;

    let compose_report = crate::ComposeReport {
        run_id: run_id.clone(),
        backend: backend.as_str().to_string(),
        carried_entries: aggregate.entries.len(),
        aggregate_digest: aggregate.aggregate_digest.clone(),
        composition_digest: composition_digest.clone(),
        proof_semantics: compose_proof_semantics().to_string(),
        blackbox_semantics: compose_blackbox_semantics().to_string(),
        prover_acceleration_scope: compose_prover_acceleration_scope(backend),
        metal_gpu_busy_ratio: artifact
            .metadata
            .get("metal_gpu_busy_ratio")
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(0.0),
        metal_stage_breakdown: artifact
            .metadata
            .get("metal_stage_breakdown")
            .cloned()
            .unwrap_or_else(|| "{}".to_string()),
        metal_inflight_jobs: artifact
            .metadata
            .get("metal_inflight_jobs")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0),
        metal_no_cpu_fallback: artifact
            .metadata
            .get("metal_no_cpu_fallback")
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(false),
        metal_counter_source: artifact
            .metadata
            .get("metal_counter_source")
            .cloned()
            .unwrap_or_else(|| "not-measured".to_string()),
        carried_backends: aggregate
            .entries
            .iter()
            .map(|e| e.backend.clone())
            .collect(),
        carried_statement_digests: aggregate
            .entries
            .iter()
            .map(|e| e.statement_digest.clone())
            .collect(),
        carried_verification_key_digests: aggregate
            .entries
            .iter()
            .map(|e| e.verification_key_digest.clone())
            .collect(),
        carried_public_input_commitments: aggregate
            .entries
            .iter()
            .map(|e| e.public_input_commitment.clone())
            .collect(),
    };
    let report_rel = PathBuf::from(format!(
        "proofs/compose/{}/{run_id}/report.json",
        backend.as_str()
    ));
    let report_path = root.join(&report_rel);
    let report_sha = write_json_and_hash(&report_path, &compose_report)?;

    manifest.files.proofs.insert(
        compose_program_key(backend, &run_id),
        PackageFileRef {
            path: compose_program_rel.display().to_string(),
            sha256: compose_program_sha,
        },
    );
    manifest.files.proofs.insert(
        compose_proof_key(backend, &run_id),
        PackageFileRef {
            path: proof_rel.display().to_string(),
            sha256: proof_sha,
        },
    );
    manifest.files.proofs.insert(
        compose_report_key(backend, &run_id),
        PackageFileRef {
            path: report_rel.display().to_string(),
            sha256: report_sha,
        },
    );
    write_json(manifest_path, &manifest)?;

    Ok(crate::ComposeResult {
        manifest: manifest_path.display().to_string(),
        run_id,
        backend: backend.as_str().to_string(),
        carried_entries: aggregate.entries.len(),
        composition_digest,
        composition_program_path: compose_program_path.display().to_string(),
        proof_path: proof_path.display().to_string(),
        report_path: report_path.display().to_string(),
        proof_semantics: compose_proof_semantics().to_string(),
        blackbox_semantics: compose_blackbox_semantics().to_string(),
        prover_acceleration_scope: compose_prover_acceleration_scope(backend),
        metal_gpu_busy_ratio: compose_report.metal_gpu_busy_ratio,
        metal_stage_breakdown: compose_report.metal_stage_breakdown.clone(),
        metal_inflight_jobs: compose_report.metal_inflight_jobs,
        metal_no_cpu_fallback: compose_report.metal_no_cpu_fallback,
        metal_counter_source: compose_report.metal_counter_source.clone(),
    })
}

pub(crate) fn verify_composed_package_proof(
    manifest_path: &Path,
    run_id: &str,
    request: &BackendRequest,
    seed: Option<[u8; 32]>,
) -> Result<crate::VerifyComposeResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(
        manifest_path,
        &manifest,
        "zkf package verify-compose",
    )?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    let backend = request.backend;
    let compose_program_ref = manifest
        .files
        .proofs
        .get(&compose_program_key(backend, &run_id))
        .ok_or_else(|| {
            format!(
                "missing composed program artifact for backend '{}' run_id '{}'; run `zkf package compose --backend {} --run-id {}` first",
                backend, run_id, backend, run_id
            )
        })?;
    let compose_proof_ref = manifest
        .files
        .proofs
        .get(&compose_proof_key(backend, &run_id))
        .ok_or_else(|| {
            format!(
                "missing composed proof artifact for backend '{}' run_id '{}'; run `zkf package compose --backend {} --run-id {}` first",
                backend, run_id, backend, run_id
            )
        })?;
    let compose_report_ref = manifest
        .files
        .proofs
        .get(&compose_report_key(backend, &run_id))
        .ok_or_else(|| {
            format!(
                "missing composed report artifact for backend '{}' run_id '{}'; run `zkf package compose --backend {} --run-id {}` first",
                backend, run_id, backend, run_id
            )
        })?;

    if bundle_artifact_ref(&manifest, &run_id).is_none() {
        return Err(format!(
            "missing bundle artifact for run_id '{}'; run `zkf package bundle --run-id {}`",
            run_id, run_id
        ));
    }
    let aggregate_ref = bundle_artifact_ref(&manifest, &run_id).expect("checked above");
    let aggregate_path = root.join(&aggregate_ref.path);
    let aggregate: crate::AggregateArtifact = read_json(&aggregate_path)?;
    if aggregate.scheme != "statement-hash-chain-v3" {
        return Err(format!(
            "verify-compose requires bundle scheme 'statement-hash-chain-v3', found '{}' (re-run `zkf package bundle --run-id {}`)",
            aggregate.scheme, run_id
        ));
    }
    let compose_report_path = root.join(&compose_report_ref.path);
    let compose_report: crate::ComposeReport = read_json(&compose_report_path)?;

    let carried_valid = verify_carried_entries(root, &manifest, &aggregate, seed)?;
    let composition_digest = compute_composition_digest(backend, &run_id, &aggregate);
    let digest_matches =
        compose_report_matches_aggregate(&compose_report, &aggregate, backend, &run_id);

    let compose_program_path = root.join(&compose_program_ref.path);
    let compose_proof_path = root.join(&compose_proof_ref.path);
    let compose_program: Program = read_json(&compose_program_path)?;
    let compose_proof: ProofArtifact = read_json(&compose_proof_path)?;

    ensure_backend_supports_program_constraints(backend, &compose_program)?;
    let engine = backend_for_request(request);
    let compiled = with_setup_seed_override(seed, || {
        engine.compile(&compose_program).map_err(render_zkf_error)
    })?;
    let composition_proof_valid = engine
        .verify(&compiled, &compose_proof)
        .map_err(render_zkf_error)?;
    let proof_binding_valid = compose_proof_metadata_matches(
        &compose_proof,
        &aggregate,
        backend,
        &run_id,
        &composition_digest,
    );
    let expected_public_inputs =
        compose_expected_public_inputs(&compose_program).map_err(render_zkf_error)?;
    let public_input_binding_valid = compose_proof.public_inputs == expected_public_inputs;
    let ok = carried_valid
        && composition_proof_valid
        && digest_matches
        && proof_binding_valid
        && public_input_binding_valid;

    let verify_report = crate::VerifyComposeReport {
        run_id: run_id.clone(),
        backend: backend.as_str().to_string(),
        ok,
        carried_entries: aggregate.entries.len(),
        carried_valid,
        composition_proof_valid,
        proof_binding_valid,
        public_input_binding_valid,
        aggregate_digest: aggregate.aggregate_digest.clone(),
        composition_digest,
        proof_semantics: compose_proof_semantics().to_string(),
        blackbox_semantics: compose_blackbox_semantics().to_string(),
        prover_acceleration_scope: compose_prover_acceleration_scope(backend),
        metal_gpu_busy_ratio: compose_report.metal_gpu_busy_ratio,
        metal_stage_breakdown: compose_report.metal_stage_breakdown.clone(),
        metal_inflight_jobs: compose_report.metal_inflight_jobs,
        metal_no_cpu_fallback: compose_report.metal_no_cpu_fallback,
        metal_counter_source: compose_report.metal_counter_source.clone(),
    };
    let verify_rel = PathBuf::from(format!(
        "proofs/compose/{}/{run_id}/verify_report.json",
        backend.as_str()
    ));
    let verify_path = root.join(&verify_rel);
    let verify_sha = write_json_and_hash(&verify_path, &verify_report)?;
    manifest.files.proofs.insert(
        compose_verify_key(backend, &run_id),
        PackageFileRef {
            path: verify_rel.display().to_string(),
            sha256: verify_sha,
        },
    );
    write_json(manifest_path, &manifest)?;

    Ok(crate::VerifyComposeResult {
        manifest: manifest_path.display().to_string(),
        run_id,
        backend: backend.as_str().to_string(),
        ok,
        carried_entries: aggregate.entries.len(),
        report_path: verify_path.display().to_string(),
    })
}

pub(crate) fn verify_carried_entries(
    root: &Path,
    manifest: &PackageManifest,
    aggregate: &crate::AggregateArtifact,
    seed: Option<[u8; 32]>,
) -> Result<bool, String> {
    let program = load_program_v2_from_manifest(root, manifest)?;
    let zir_program = if manifest_ir_family(manifest) == "zir-v1" {
        let program_path = root.join(&manifest.files.program.path);
        Some(read_json::<zkf_core::zir_v1::Program>(&program_path)?)
    } else {
        None
    };
    let expected_program_digest = program.digest_hex();
    let strict_v3 = aggregate.scheme == "statement-hash-chain-v3";
    let mut compiled_cache = BTreeMap::<String, CompiledProgram>::new();

    for entry in &aggregate.entries {
        let backend = parse_backend(&entry.backend)?;
        let proof_path = root.join(&entry.proof_path);
        let artifact: ProofArtifact = read_json(&proof_path)?;
        let proof_digest = sha256_hex(&artifact.proof);
        if proof_digest != entry.proof_digest {
            return Ok(false);
        }
        if artifact.program_digest != entry.program_digest
            || artifact.program_digest != expected_program_digest
        {
            return Ok(false);
        }
        let statement_digest = statement_digest_for_artifact(backend, &artifact);
        if strict_v3 {
            if entry.statement_digest.is_empty() || entry.statement_digest != statement_digest {
                return Ok(false);
            }
            let vk_digest = verification_key_digest_for_artifact(&artifact);
            if entry.verification_key_digest.is_empty()
                || entry.verification_key_digest != vk_digest
            {
                return Ok(false);
            }
            let public_input_commitment = public_input_commitment_for_artifact(backend, &artifact);
            if entry.public_input_commitment.is_empty()
                || entry.public_input_commitment != public_input_commitment
            {
                return Ok(false);
            }
        } else {
            if !entry.statement_digest.is_empty() && entry.statement_digest != statement_digest {
                return Ok(false);
            }
            if !entry.verification_key_digest.is_empty() {
                let vk_digest = verification_key_digest_for_artifact(&artifact);
                if entry.verification_key_digest != vk_digest {
                    return Ok(false);
                }
            }
            if !entry.public_input_commitment.is_empty() {
                let public_input_commitment =
                    public_input_commitment_for_artifact(backend, &artifact);
                if entry.public_input_commitment != public_input_commitment {
                    return Ok(false);
                }
            }
        }

        let engine = backend_for(backend);
        let cache_key = backend.as_str().to_string();
        let compiled = if let Some(existing) = compiled_cache.get(&cache_key) {
            existing.clone()
        } else if let Some(existing) =
            load_compiled_artifact(root, manifest, backend, &expected_program_digest)?
        {
            compiled_cache.insert(cache_key.clone(), existing.clone());
            existing
        } else {
            if let Some(zir) = &zir_program {
                ensure_backend_supports_zir_constraints(backend, zir)?;
            }
            ensure_backend_supports_program_constraints(backend, &program)?;
            let compiled = with_setup_seed_override(seed, || {
                engine.compile(&program).map_err(render_zkf_error)
            })?;
            compiled_cache.insert(cache_key, compiled.clone());
            compiled
        };

        let ok = engine
            .verify(&compiled, &artifact)
            .map_err(render_zkf_error)?;
        if !ok {
            return Ok(false);
        }
    }

    Ok(true)
}

pub(crate) fn handle_compose(
    manifest: PathBuf,
    run_id: String,
    backend: String,
    json: bool,
    seed: Option<String>,
    allow_compat: bool,
) -> Result<(), String> {
    let request = parse_backend_request(&backend)?;
    ensure_backend_request_allowed(&request, allow_compat)?;
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let report = compose_package_proofs(&manifest, &run_id, &request, seed)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package compose: backend={} run_id={} carried={} digest={}",
            report.backend, report.run_id, report.carried_entries, report.composition_digest
        );
    }
    Ok(())
}

pub(crate) fn handle_verify_compose(
    manifest: PathBuf,
    run_id: String,
    backend: String,
    json: bool,
    seed: Option<String>,
    allow_compat: bool,
) -> Result<(), String> {
    let request = parse_backend_request(&backend)?;
    ensure_backend_request_allowed(&request, allow_compat)?;
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let report = verify_composed_package_proof(&manifest, &run_id, &request, seed)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else if report.ok {
        println!(
            "package verify-compose: backend={} run_id={} status=OK carried={}",
            report.backend, report.run_id, report.carried_entries
        );
    } else {
        return Err(format!(
            "package verify-compose: backend={} run_id={} status=FAILED",
            report.backend, report.run_id
        ));
    }
    Ok(())
}
