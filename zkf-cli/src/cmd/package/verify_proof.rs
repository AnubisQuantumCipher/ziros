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

use zkf_core::{BackendKind, PackageFileRef, PackageManifest, ProofArtifact};

use crate::package_io::{
    legacy_verify_report_key, normalize_run_id, proof_artifact_ref, solidity_verifier_key,
    verify_report_key, write_compiled_artifact,
};
use crate::solidity::{render_groth16_solidity_verifier, render_sp1_solidity_verifier};
use crate::util::{
    backend_for_request, ensure_backend_request_allowed, ensure_manifest_v2_metadata_for_command,
    ensure_release_safe_proof_artifact, load_program_v2_for_backend, parse_backend_request,
    read_json, resolve_compiled_artifact_for_request, sha256_hex, write_json, write_json_and_hash,
    write_text,
};

fn maybe_emit_solidity_verifier(
    root: &Path,
    manifest: &mut PackageManifest,
    backend: BackendKind,
    run_id: &str,
    artifact: &ProofArtifact,
    output_override: Option<&Path>,
) -> Result<Option<String>, String> {
    let should_emit = output_override.is_some()
        || backend == BackendKind::Sp1
        || backend == BackendKind::ArkworksGroth16;
    if !should_emit {
        return Ok(None);
    }

    if backend != BackendKind::Sp1 && backend != BackendKind::ArkworksGroth16 {
        return Err(format!(
            "--solidity-verifier is currently supported only for backends '{}' and '{}' (requested '{}')",
            BackendKind::Sp1,
            BackendKind::ArkworksGroth16,
            backend
        ));
    }

    let rel_path = output_override.unwrap_or_else(|| Path::new(""));
    if rel_path.is_absolute() {
        return Err(format!(
            "solidity verifier path must be package-relative, found absolute path '{}'",
            rel_path.display()
        ));
    }

    let verifier_rel = output_override.map_or_else(
        || PathBuf::from(format!("proofs/{}/{run_id}/verifier.sol", backend.as_str())),
        PathBuf::from,
    );
    let verifier_path = root.join(&verifier_rel);
    let source = match backend {
        BackendKind::ArkworksGroth16 => Ok(render_groth16_solidity_verifier(
            artifact,
            "ZkfGroth16Verifier",
        )),
        _ => render_sp1_solidity_verifier(artifact),
    }?;
    if let Some(parent) = verifier_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    write_text(&verifier_path, &source).map_err(|e| format!("{}: {e}", verifier_path.display()))?;
    let source_sha = sha256_hex(source.as_bytes());
    manifest.files.proofs.insert(
        solidity_verifier_key(backend, run_id),
        PackageFileRef {
            path: verifier_rel.display().to_string(),
            sha256: source_sha,
        },
    );

    Ok(Some(verifier_path.display().to_string()))
}

pub(crate) fn verify_package_proof(
    manifest_path: &Path,
    request: &crate::util::BackendRequest,
    run_id: &str,
    seed: Option<[u8; 32]>,
    solidity_verifier: Option<&Path>,
    hybrid: bool,
) -> Result<crate::VerifyProofResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package verify-proof")?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let backend = request.backend;

    let proof_ref = proof_artifact_ref(&manifest, backend, &run_id).ok_or_else(|| {
        format!(
            "package is missing proof artifact for backend '{}' and run_id '{}'; run `zkf package prove --run-id {}` first",
            backend, run_id, run_id
        )
    })?;
    let proof_path = root.join(&proof_ref.path);
    let artifact: ProofArtifact = read_json(&proof_path)?;
    ensure_release_safe_proof_artifact(&artifact, "zkf package verify-proof")?;

    let program = load_program_v2_for_backend(root, &manifest, backend)?;
    let ok = if hybrid || artifact.hybrid_bundle.is_some() {
        zkf_runtime::verify_hybrid_artifact(&program, &artifact).map_err(|err| err.to_string())?
    } else {
        let engine = backend_for_request(request);
        let cached_compiled = crate::package_io::load_compiled_artifact(
            root,
            &manifest,
            backend,
            &program.digest_hex(),
        )?;
        let (compiled, recovered_compiled) = resolve_compiled_artifact_for_request(
            &program,
            request,
            cached_compiled,
            false,
            seed,
            None,
            false,
            "zkf package verify-proof",
        )?;
        if recovered_compiled {
            write_compiled_artifact(root, &mut manifest, backend, &compiled)?;
        }
        engine
            .verify(&compiled, &artifact)
            .map_err(|err| err.to_string())?
    };

    let proof_digest = sha256_hex(&artifact.proof);
    let verify_report = crate::VerifyProofReport {
        backend: backend.as_str().to_string(),
        run_id: run_id.clone(),
        ok,
        program_digest: program.digest_hex(),
        proof_digest,
        hybrid: artifact.hybrid_bundle.is_some(),
        security_profile: Some(artifact.effective_security_profile().as_str().to_string()),
    };
    let report_rel = PathBuf::from(format!(
        "proofs/{}/{run_id}/verify_report.json",
        backend.as_str()
    ));
    let report_path = root.join(&report_rel);
    let report_sha = write_json_and_hash(&report_path, &verify_report)?;
    manifest.files.proofs.insert(
        verify_report_key(backend, &run_id),
        PackageFileRef {
            path: report_rel.display().to_string(),
            sha256: report_sha.clone(),
        },
    );
    if run_id == "main" {
        manifest.files.proofs.insert(
            legacy_verify_report_key(backend),
            PackageFileRef {
                path: report_rel.display().to_string(),
                sha256: report_sha.clone(),
            },
        );
    }
    manifest.metadata.insert(
        "last_verify_backend".to_string(),
        backend.as_str().to_string(),
    );
    manifest
        .metadata
        .insert("last_verify_run_id".to_string(), run_id.clone());

    let solidity_verifier_path = maybe_emit_solidity_verifier(
        root,
        &mut manifest,
        backend,
        &run_id,
        &artifact,
        solidity_verifier,
    )?;
    write_json(manifest_path, &manifest)?;

    Ok(crate::VerifyProofResult {
        manifest: manifest_path.display().to_string(),
        backend: backend.as_str().to_string(),
        run_id,
        ok,
        proof_path: proof_path.display().to_string(),
        report_path: report_path.display().to_string(),
        hybrid: artifact.hybrid_bundle.is_some(),
        solidity_verifier_path,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_verify_proof(
    manifest: PathBuf,
    backend: String,
    run_id: String,
    solidity_verifier: Option<PathBuf>,
    json: bool,
    seed: Option<String>,
    hybrid: bool,
    allow_compat: bool,
) -> Result<(), String> {
    let request = parse_backend_request(&backend)?;
    ensure_backend_request_allowed(&request, allow_compat)?;
    let seed = seed
        .as_deref()
        .map(crate::util::parse_setup_seed)
        .transpose()?;
    let report = verify_package_proof(
        &manifest,
        &request,
        &run_id,
        seed,
        solidity_verifier.as_deref(),
        hybrid,
    )?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else if report.ok {
        println!(
            "package verify-proof: backend={} run_id={} status=OK",
            report.backend, report.run_id
        );
        if let Some(path) = report.solidity_verifier_path.as_deref() {
            println!("solidity verifier: {path}");
        }
    } else {
        return Err(format!(
            "package verify-proof: backend={} run_id={} status=FAILED",
            report.backend, report.run_id
        ));
    }
    Ok(())
}
