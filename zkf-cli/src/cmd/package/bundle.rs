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

use sha2::{Digest, Sha256};
use zkf_core::{BackendKind, PackageFileRef, PackageManifest, ProofArtifact};

use crate::compose::{
    public_input_commitment_for_artifact, statement_digest_for_artifact,
    verification_key_digest_for_artifact,
};
use crate::package_io::{
    bundle_artifact_ref, bundle_file_key, bundle_verify_file_key, legacy_aggregate_file_key,
    legacy_aggregate_verify_file_key, legacy_bundle_file_key, legacy_bundle_verify_file_key,
    normalize_run_id, proof_artifact_ref,
};
use crate::util::{
    ensure_manifest_v2_metadata_for_command, parse_backend, read_json, sha256_hex, write_json,
    write_json_and_hash,
};

pub(crate) fn bundle_package_proofs(
    manifest_path: &Path,
    run_id: &str,
    selected_backends: &[BackendKind],
) -> Result<crate::BundleResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package bundle")?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    let backends = if selected_backends.is_empty() {
        let mut discovered = Vec::new();
        for key in manifest.files.proofs.keys() {
            if let Some(rest) = key.strip_prefix("proof/") {
                let mut parts = rest.split('/');
                let Some(backend_raw) = parts.next() else {
                    continue;
                };
                let Some(found_run_id) = parts.next() else {
                    continue;
                };
                if found_run_id != run_id {
                    continue;
                }
                if let Ok(backend) = parse_backend(backend_raw)
                    && !discovered.contains(&backend)
                {
                    discovered.push(backend);
                }
            }
        }
        if discovered.is_empty() {
            return Err(format!(
                "no proof artifacts found for run_id '{}'; run `zkf package prove --run-id {}` first",
                run_id, run_id
            ));
        }
        discovered
    } else {
        selected_backends.to_vec()
    };

    let mut entries = Vec::new();
    for backend in backends {
        let proof_ref = proof_artifact_ref(&manifest, backend, &run_id).ok_or_else(|| {
            format!(
                "missing proof for backend '{}' and run_id '{}'; run `zkf package prove --backend {} --run-id {}`",
                backend, run_id, backend, run_id
            )
        })?;
        let proof_path = root.join(&proof_ref.path);
        let artifact: ProofArtifact = read_json(&proof_path)?;
        let statement_digest = statement_digest_for_artifact(backend, &artifact);
        let verification_key_digest = verification_key_digest_for_artifact(&artifact);
        let public_input_commitment = public_input_commitment_for_artifact(backend, &artifact);
        entries.push(crate::BundleEntry {
            backend: backend.as_str().to_string(),
            proof_path: proof_ref.path.clone(),
            proof_digest: sha256_hex(&artifact.proof),
            program_digest: artifact.program_digest,
            statement_digest,
            verification_key_digest,
            public_input_commitment,
        });
    }
    entries.sort_by(|a, b| a.backend.cmp(&b.backend));

    let mut hasher = Sha256::new();
    hasher.update(b"zkf-bundle-v1");
    hasher.update(run_id.as_bytes());
    for entry in &entries {
        hasher.update(entry.backend.as_bytes());
        hasher.update(entry.statement_digest.as_bytes());
        hasher.update(entry.proof_digest.as_bytes());
        hasher.update(entry.program_digest.as_bytes());
        hasher.update(entry.verification_key_digest.as_bytes());
        hasher.update(entry.public_input_commitment.as_bytes());
    }
    let aggregate_digest = format!("{:x}", hasher.finalize());
    let artifact = crate::BundleArtifact {
        run_id: run_id.clone(),
        entries,
        aggregate_digest: aggregate_digest.clone(),
        scheme: "statement-hash-chain-v3".to_string(),
        proof_semantics: "metadata-binding-only".to_string(),
        prover_acceleration_scope: "not-claimed-metadata-only".to_string(),
        metal_gpu_busy_ratio: 0.0,
        metal_stage_breakdown: "{}".to_string(),
        metal_inflight_jobs: 0,
        metal_no_cpu_fallback: false,
        metal_counter_source: "metadata-only".to_string(),
    };

    let artifact_rel = PathBuf::from(format!("proofs/bundle/{run_id}/bundle.json"));
    let artifact_path = root.join(&artifact_rel);
    let artifact_sha = write_json_and_hash(&artifact_path, &artifact)?;
    manifest.files.proofs.insert(
        bundle_file_key(&run_id),
        PackageFileRef {
            path: artifact_rel.display().to_string(),
            sha256: artifact_sha.clone(),
        },
    );
    if run_id == "main" {
        manifest.files.proofs.insert(
            legacy_bundle_file_key().to_string(),
            PackageFileRef {
                path: artifact_rel.display().to_string(),
                sha256: artifact_sha.clone(),
            },
        );
        manifest.files.proofs.insert(
            legacy_aggregate_file_key().to_string(),
            PackageFileRef {
                path: artifact_rel.display().to_string(),
                sha256: artifact_sha,
            },
        );
    }
    manifest
        .metadata
        .insert("last_bundle_run_id".to_string(), run_id.clone());
    write_json(manifest_path, &manifest)?;

    Ok(crate::BundleResult {
        manifest: manifest_path.display().to_string(),
        run_id,
        artifact_path: artifact_path.display().to_string(),
        entries: artifact.entries.len(),
        aggregate_digest,
        proof_semantics: artifact.proof_semantics.clone(),
        prover_acceleration_scope: artifact.prover_acceleration_scope.clone(),
        metal_gpu_busy_ratio: artifact.metal_gpu_busy_ratio,
        metal_stage_breakdown: artifact.metal_stage_breakdown.clone(),
        metal_inflight_jobs: artifact.metal_inflight_jobs,
        metal_no_cpu_fallback: artifact.metal_no_cpu_fallback,
        metal_counter_source: artifact.metal_counter_source.clone(),
    })
}

pub(crate) fn verify_package_bundle(
    manifest_path: &Path,
    run_id: &str,
) -> Result<crate::VerifyBundleResult, String> {
    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package verify-bundle")?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    let bundle_ref = bundle_artifact_ref(&manifest, &run_id).ok_or_else(|| {
        format!(
            "missing bundle artifact for run_id '{}'; run `zkf package bundle --run-id {}` first",
            run_id, run_id
        )
    })?;
    let bundle_path = root.join(&bundle_ref.path);
    let bundle: crate::BundleArtifact = read_json(&bundle_path)?;

    let is_v3 = bundle.scheme == "statement-hash-chain-v3";
    let is_v2 = bundle.scheme == "statement-hash-chain-v2";
    let mut hasher = Sha256::new();
    if is_v3 {
        hasher.update(b"zkf-bundle-v1");
    } else if is_v2 {
        hasher.update(b"zkf-aggregate-v2");
    } else {
        hasher.update(b"zkf-aggregate-v1");
    }
    hasher.update(run_id.as_bytes());

    let mut ok = true;
    for entry in &bundle.entries {
        let proof_path = root.join(&entry.proof_path);
        if !proof_path.exists() {
            ok = false;
            continue;
        }
        let artifact: ProofArtifact = read_json(&proof_path)?;
        let proof_digest = sha256_hex(&artifact.proof);
        if proof_digest != entry.proof_digest || artifact.program_digest != entry.program_digest {
            ok = false;
        }
        let backend = parse_backend(&entry.backend)?;
        let statement_digest = statement_digest_for_artifact(backend, &artifact);
        if (is_v3 || is_v2)
            && (entry.statement_digest.is_empty() || entry.statement_digest != statement_digest)
        {
            ok = false;
        }
        if is_v3 {
            let vk_digest = verification_key_digest_for_artifact(&artifact);
            let public_input_commitment = public_input_commitment_for_artifact(backend, &artifact);
            if entry.verification_key_digest.is_empty()
                || entry.verification_key_digest != vk_digest
            {
                ok = false;
            }
            if entry.public_input_commitment.is_empty()
                || entry.public_input_commitment != public_input_commitment
            {
                ok = false;
            }
        }
        hasher.update(entry.backend.as_bytes());
        if is_v3 || is_v2 {
            hasher.update(statement_digest.as_bytes());
        }
        hasher.update(entry.proof_digest.as_bytes());
        hasher.update(entry.program_digest.as_bytes());
        if is_v3 {
            hasher.update(entry.verification_key_digest.as_bytes());
            hasher.update(entry.public_input_commitment.as_bytes());
        }
    }

    let expected_digest = format!("{:x}", hasher.finalize());
    if expected_digest != bundle.aggregate_digest {
        ok = false;
    }

    let report = crate::VerifyBundleReport {
        run_id: run_id.clone(),
        ok,
        entries: bundle.entries.len(),
        aggregate_digest: bundle.aggregate_digest.clone(),
        proof_semantics: bundle.proof_semantics.clone(),
        prover_acceleration_scope: bundle.prover_acceleration_scope.clone(),
        metal_gpu_busy_ratio: bundle.metal_gpu_busy_ratio,
        metal_stage_breakdown: bundle.metal_stage_breakdown.clone(),
        metal_inflight_jobs: bundle.metal_inflight_jobs,
        metal_no_cpu_fallback: bundle.metal_no_cpu_fallback,
        metal_counter_source: bundle.metal_counter_source.clone(),
    };
    let report_rel = PathBuf::from(format!("proofs/bundle/{run_id}/verify_report.json"));
    let report_path = root.join(&report_rel);
    let report_sha = write_json_and_hash(&report_path, &report)?;
    manifest.files.proofs.insert(
        bundle_verify_file_key(&run_id),
        PackageFileRef {
            path: report_rel.display().to_string(),
            sha256: report_sha.clone(),
        },
    );
    if run_id == "main" {
        manifest.files.proofs.insert(
            legacy_bundle_verify_file_key().to_string(),
            PackageFileRef {
                path: report_rel.display().to_string(),
                sha256: report_sha.clone(),
            },
        );
        manifest.files.proofs.insert(
            legacy_aggregate_verify_file_key().to_string(),
            PackageFileRef {
                path: report_rel.display().to_string(),
                sha256: report_sha,
            },
        );
    }
    manifest
        .metadata
        .insert("last_bundle_verify_run_id".to_string(), run_id.clone());
    write_json(manifest_path, &manifest)?;

    Ok(crate::VerifyBundleResult {
        manifest: manifest_path.display().to_string(),
        run_id,
        ok,
        entries: bundle.entries.len(),
        artifact_path: bundle_path.display().to_string(),
        report_path: report_path.display().to_string(),
    })
}

pub(crate) fn handle_bundle(
    manifest: PathBuf,
    backends: Option<Vec<String>>,
    run_id: String,
    json: bool,
) -> Result<(), String> {
    let selected_backends = backends
        .unwrap_or_default()
        .into_iter()
        .map(|name| parse_backend(&name))
        .collect::<Result<Vec<_>, _>>()?;
    let report = bundle_package_proofs(&manifest, &run_id, &selected_backends)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package bundle: run_id={} entries={} digest={}",
            report.run_id, report.entries, report.aggregate_digest
        );
    }
    Ok(())
}

pub(crate) fn handle_verify_bundle(
    manifest: PathBuf,
    run_id: String,
    json: bool,
) -> Result<(), String> {
    let report = verify_package_bundle(&manifest, &run_id)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else if report.ok {
        println!(
            "package verify-bundle: run_id={} status=OK entries={}",
            report.run_id, report.entries
        );
    } else {
        return Err(format!(
            "package verify-bundle: run_id={} status=FAILED",
            report.run_id
        ));
    }
    Ok(())
}
