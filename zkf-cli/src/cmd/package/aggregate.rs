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

use zkf_backends::{
    aggregation::Plonky3Aggregator,
    wrapping::{
        groth16_recursive_verifier::CryptographicGroth16Aggregator,
        halo2_ipa_accumulator::Halo2IpaAccumulator,
    },
};
use zkf_core::aggregation::{AggregatedProof, ProofAggregator};
use zkf_core::{BackendKind, PackageFileRef, PackageManifest, ProofArtifact};

use crate::package_io::{
    crypto_aggregate_artifact_ref, crypto_aggregate_file_key, crypto_aggregate_verify_file_key,
    load_compiled_artifact, normalize_run_id, proof_artifact_ref,
};
use crate::util::{
    ensure_manifest_v2_metadata_for_command, parse_backend, read_json, write_json,
    write_json_and_hash,
};

fn supported_crypto_aggregation_backend(backend: BackendKind) -> bool {
    matches!(
        backend,
        BackendKind::ArkworksGroth16 | BackendKind::Halo2 | BackendKind::Plonky3
    )
}

fn aggregate_with_backend(
    backend: BackendKind,
    proofs: &[(ProofArtifact, zkf_core::CompiledProgram)],
) -> Result<AggregatedProof, String> {
    match backend {
        BackendKind::ArkworksGroth16 => CryptographicGroth16Aggregator
            .aggregate(proofs)
            .map_err(|err| err.to_string()),
        BackendKind::Halo2 => Halo2IpaAccumulator
            .aggregate(proofs)
            .map_err(|err| err.to_string()),
        BackendKind::Plonky3 => Plonky3Aggregator
            .aggregate(proofs)
            .map_err(|err| err.to_string()),
        other => Err(format!(
            "cryptographic package aggregation is not supported for backend '{}'; use `zkf package bundle` for metadata binding or `zkf package compose` for heterogeneous carried-proof composition",
            other
        )),
    }
}

fn verify_with_backend(backend: BackendKind, aggregated: &AggregatedProof) -> Result<bool, String> {
    match backend {
        BackendKind::ArkworksGroth16 => CryptographicGroth16Aggregator
            .verify_aggregated(aggregated)
            .map_err(|err| err.to_string()),
        BackendKind::Halo2 => Halo2IpaAccumulator
            .verify_aggregated(aggregated)
            .map_err(|err| err.to_string()),
        BackendKind::Plonky3 => Plonky3Aggregator
            .verify_aggregated(aggregated)
            .map_err(|err| err.to_string()),
        other => Err(format!(
            "cryptographic package aggregate verification is not supported for backend '{}'",
            other
        )),
    }
}

fn discovered_backends_for_run(manifest: &PackageManifest, run_id: &str) -> Vec<BackendKind> {
    let mut discovered = Vec::new();
    for key in manifest.files.proofs.keys() {
        let Some(rest) = key.strip_prefix("proof/") else {
            continue;
        };
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
        let Ok(found_backend) = parse_backend(backend_raw) else {
            continue;
        };
        if !discovered.contains(&found_backend) {
            discovered.push(found_backend);
        }
    }
    discovered
}

pub(crate) fn aggregate_package_proofs(
    manifest_path: &Path,
    backend: BackendKind,
    input_run_ids: &[String],
    output_run_id: &str,
) -> Result<crate::AggregateResult, String> {
    if !supported_crypto_aggregation_backend(backend) {
        return Err(format!(
            "cryptographic package aggregation is not supported for backend '{}'; use `zkf package bundle` for metadata binding or `zkf package compose` for heterogeneous carried-proof composition",
            backend
        ));
    }

    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package aggregate")?;
    let output_run_id = normalize_run_id(output_run_id)?;
    let mut normalized_inputs = Vec::new();
    for run_id in input_run_ids {
        let normalized = normalize_run_id(run_id)?;
        if !normalized_inputs.contains(&normalized) {
            normalized_inputs.push(normalized);
        }
    }
    if normalized_inputs.len() < 2 {
        return Err(
            "cryptographic package aggregation requires at least two distinct --input-run-ids"
                .to_string(),
        );
    }

    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    let mut proofs = Vec::with_capacity(normalized_inputs.len());
    for run_id in &normalized_inputs {
        let proof_ref = proof_artifact_ref(&manifest, backend, run_id).ok_or_else(|| {
            let alternatives = discovered_backends_for_run(&manifest, run_id);
            if !alternatives.is_empty() {
                format!(
                    "run_id '{}' does not have a proof for backend '{}'; found proofs for [{}] instead. Cryptographic package aggregation is homogeneous; use `zkf package bundle` for metadata binding or `zkf package compose` for heterogeneous carried-proof composition",
                    run_id,
                    backend,
                    alternatives
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "missing proof for backend '{}' and run_id '{}'; run `zkf package prove --backend {} --run-id {}` first",
                    backend, run_id, backend, run_id
                )
            }
        })?;
        let proof_path = root.join(&proof_ref.path);
        let artifact: ProofArtifact = read_json(&proof_path)?;
        let compiled = load_compiled_artifact(root, &manifest, backend, &artifact.program_digest)?
            .ok_or_else(|| {
                format!(
                    "missing compiled artifact for backend '{}' needed to aggregate run_id '{}'",
                    backend, run_id
                )
            })?;
        proofs.push((artifact, compiled));
    }

    let aggregated = aggregate_with_backend(backend, &proofs)?;
    let artifact_rel = PathBuf::from(format!(
        "proofs/aggregate/{}/{}/aggregate.json",
        backend.as_str(),
        output_run_id
    ));
    let artifact_path = root.join(&artifact_rel);
    let artifact_sha = write_json_and_hash(&artifact_path, &aggregated)?;
    manifest.files.proofs.insert(
        crypto_aggregate_file_key(backend, &output_run_id),
        PackageFileRef {
            path: artifact_rel.display().to_string(),
            sha256: artifact_sha,
        },
    );
    manifest.metadata.insert(
        format!("last_crypto_aggregate_run_id/{}", backend.as_str()),
        output_run_id.clone(),
    );
    write_json(manifest_path, &manifest)?;

    Ok(crate::AggregateResult {
        manifest: manifest_path.display().to_string(),
        backend: backend.as_str().to_string(),
        run_id: output_run_id,
        input_run_ids: normalized_inputs,
        artifact_path: artifact_path.display().to_string(),
        proof_count: aggregated.proof_count,
        scheme: aggregated
            .metadata
            .get("scheme")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        trust_model: aggregated.metadata.get("trust_model").cloned(),
    })
}

pub(crate) fn verify_package_aggregate(
    manifest_path: &Path,
    backend: BackendKind,
    run_id: &str,
) -> Result<crate::VerifyAggregateResult, String> {
    if !supported_crypto_aggregation_backend(backend) {
        return Err(format!(
            "cryptographic package aggregate verification is not supported for backend '{}'",
            backend
        ));
    }

    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(
        manifest_path,
        &manifest,
        "zkf package verify-aggregate",
    )?;
    let run_id = normalize_run_id(run_id)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    let aggregate_ref = crypto_aggregate_artifact_ref(&manifest, backend, &run_id).ok_or_else(
        || {
            format!(
                "missing cryptographic aggregate artifact for backend '{}' run_id '{}'; run `zkf package aggregate --backend {} --input-run-ids ... --run-id {}` first",
                backend, run_id, backend, run_id
            )
        },
    )?;
    let aggregate_path = root.join(&aggregate_ref.path);
    let aggregate: AggregatedProof = read_json(&aggregate_path)?;
    let ok = verify_with_backend(backend, &aggregate)?;

    let report = crate::VerifyAggregateReport {
        backend: backend.as_str().to_string(),
        run_id: run_id.clone(),
        ok,
        proof_count: aggregate.proof_count,
        scheme: aggregate.metadata.get("scheme").cloned(),
        trust_model: aggregate.metadata.get("trust_model").cloned(),
    };
    let report_rel = PathBuf::from(format!(
        "proofs/aggregate/{}/{}/verify_report.json",
        backend.as_str(),
        run_id
    ));
    let report_path = root.join(&report_rel);
    let report_sha = write_json_and_hash(&report_path, &report)?;
    manifest.files.proofs.insert(
        crypto_aggregate_verify_file_key(backend, &run_id),
        PackageFileRef {
            path: report_rel.display().to_string(),
            sha256: report_sha,
        },
    );
    manifest.metadata.insert(
        format!("last_crypto_aggregate_verify_run_id/{}", backend.as_str()),
        run_id.clone(),
    );
    write_json(manifest_path, &manifest)?;

    Ok(crate::VerifyAggregateResult {
        manifest: manifest_path.display().to_string(),
        backend: backend.as_str().to_string(),
        run_id,
        ok,
        proof_count: aggregate.proof_count,
        artifact_path: aggregate_path.display().to_string(),
        report_path: report_path.display().to_string(),
    })
}

pub(crate) fn handle_aggregate(
    manifest: PathBuf,
    backend: String,
    input_run_ids: Vec<String>,
    run_id: String,
    json: bool,
    crypto: bool,
) -> Result<(), String> {
    let backend = parse_backend(&backend)?;
    if crypto && !json {
        eprintln!("warning: `zkf package aggregate --crypto` is deprecated and now a no-op");
    }
    let report = aggregate_package_proofs(&manifest, backend, &input_run_ids, &run_id)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package aggregate: backend={} run_id={} proofs={} scheme={}",
            report.backend, report.run_id, report.proof_count, report.scheme
        );
    }
    Ok(())
}

pub(crate) fn handle_verify_aggregate(
    manifest: PathBuf,
    backend: String,
    run_id: String,
    json: bool,
) -> Result<(), String> {
    let backend = parse_backend(&backend)?;
    let report = verify_package_aggregate(&manifest, backend, &run_id)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else if report.ok {
        println!(
            "package verify-aggregate: backend={} run_id={} status=OK proofs={}",
            report.backend, report.run_id, report.proof_count
        );
    } else {
        return Err(format!(
            "package verify-aggregate: backend={} run_id={} status=FAILED",
            report.backend, report.run_id
        ));
    }
    Ok(())
}
