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
use std::sync::Arc;

use sha2::{Digest, Sha256};
use zkf_core::{
    BackendKind, FieldElement, PackageFileRef, PackageManifest, ProofArtifact, StepMode,
    WitnessInputs,
};
use zkf_runtime::{ExecutionMode, RequiredTrustLane, RuntimeExecutor};

use crate::package_io::{fold_file_key, normalize_run_id};
use crate::util::{
    BackendRequest, ensure_manifest_v2_metadata_for_command, load_program_v2_from_manifest,
    read_inputs, read_json, sha256_hex, write_json, write_json_and_hash,
};

pub(crate) fn chain_step_inputs(
    base_inputs: &WitnessInputs,
    public_signal_names: &[String],
    public_inputs: &[FieldElement],
) -> Result<WitnessInputs, String> {
    if public_signal_names.len() != public_inputs.len() {
        return Err(format!(
            "cannot chain public outputs into next step inputs: program has {} public signals, proof has {} public inputs",
            public_signal_names.len(),
            public_inputs.len()
        ));
    }

    let mut next_inputs = base_inputs.clone();
    for (signal, value) in public_signal_names.iter().zip(public_inputs.iter()) {
        next_inputs.insert(signal.clone(), value.clone());
    }
    Ok(next_inputs)
}

pub(crate) fn chain_nova_ivc_input(
    base_inputs: &WitnessInputs,
    input_signal: &str,
    output_value: &FieldElement,
) -> WitnessInputs {
    let mut next_inputs = base_inputs.clone();
    next_inputs.insert(input_signal.to_string(), output_value.clone());
    next_inputs
}

pub(crate) struct FoldPackageRequest<'a> {
    pub manifest_path: &'a Path,
    pub inputs_path: &'a Path,
    pub steps: usize,
    pub backend: BackendKind,
    pub objective: zkf_runtime::OptimizationObjective,
    pub solver: Option<&'a str>,
    pub step_mode_override: Option<StepMode>,
    pub seed: Option<[u8; 32]>,
}

pub(crate) fn fold_package(request: FoldPackageRequest<'_>) -> Result<crate::FoldResult, String> {
    let FoldPackageRequest {
        manifest_path,
        inputs_path,
        steps,
        backend,
        objective,
        solver,
        step_mode_override,
        seed,
    } = request;
    if steps == 0 {
        return Err("fold requires --steps >= 1".to_string());
    }

    let mut manifest: PackageManifest = read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf fold")?;
    let step_mode = step_mode_override
        .or(manifest.step_mode)
        .unwrap_or(StepMode::ReuseInputs);
    manifest.step_mode = Some(step_mode);
    write_json(manifest_path, &manifest)?;

    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let program = load_program_v2_from_manifest(root, &manifest)?;
    let public_signal_names = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();

    if step_mode == StepMode::ChainPublicOutputs && public_signal_names.is_empty() {
        return Err(
            "fold step_mode=chain-public-outputs requires at least one public signal".to_string(),
        );
    }

    let base_inputs = read_inputs(inputs_path)?;
    let mut current_inputs = base_inputs.clone();

    // Ensure backend setup is cached once before stepping.
    super::compile::compile_package(manifest_path, &BackendRequest::native(backend), seed)?;

    // -----------------------------------------------------------------------
    // Nova IVC path: collect all witnesses, then fold into a single proof
    // when the manifest declares explicit `nova_ivc_in` / `nova_ivc_out`
    // metadata and the selected backend is Nova.
    // -----------------------------------------------------------------------
    let nova_ivc_in = manifest.metadata.get("nova_ivc_in").cloned();
    let nova_ivc_out = manifest.metadata.get("nova_ivc_out").cloned();
    let use_nova_ivc =
        backend == BackendKind::Nova && nova_ivc_in.is_some() && nova_ivc_out.is_some();

    if use_nova_ivc {
        let ivc_in = nova_ivc_in.as_deref().unwrap();
        let ivc_out = nova_ivc_out.as_deref().unwrap();

        let mut all_witnesses: Vec<zkf_core::Witness> = Vec::with_capacity(steps);
        let mut run_ids: Vec<String> = Vec::with_capacity(steps);

        for step in 0..steps {
            let run_id = normalize_run_id(&format!("fold-step-{step}"))?;
            let step_inputs_rel = PathBuf::from(format!("runs/{run_id}/inputs.json"));
            let step_inputs_path = root.join(&step_inputs_rel);
            if let Some(parent) = step_inputs_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            write_json(&step_inputs_path, &current_inputs)?;

            crate::cmd::witness::run_package(manifest_path, &step_inputs_path, &run_id, solver)?;

            let witness_path = root.join(format!("runs/{run_id}/witness.json"));
            let witness: zkf_core::Witness = read_json(&witness_path)?;

            if step + 1 < steps {
                let out_val = witness.values.get(ivc_out).cloned().ok_or_else(|| {
                    format!(
                        "nova IVC chain: output signal '{}' not found in witness for step {}",
                        ivc_out, step
                    )
                })?;
                current_inputs = chain_nova_ivc_input(&base_inputs, ivc_in, &out_val);
            }

            all_witnesses.push(witness);
            run_ids.push(run_id);
        }

        let latest_manifest: PackageManifest = read_json(manifest_path)?;
        let current_program = load_program_v2_from_manifest(root, &latest_manifest)?;
        let expected_digest = current_program.digest_hex();
        let compiled = crate::package_io::load_compiled_artifact(
            root,
            &latest_manifest,
            backend,
            &expected_digest,
        )?
        .ok_or_else(|| {
            "nova IVC fold: compiled artifact not found after compile step".to_string()
        })?;

        eprintln!(
            "nova IVC: folding {} steps with Nova recursive SNARKs...",
            steps
        );
        let execution = RuntimeExecutor::run_backend_fold_job_with_objective(
            Arc::new(compiled.clone()),
            Arc::new(all_witnesses.clone()),
            true,
            objective,
            RequiredTrustLane::StrictCryptographic,
            ExecutionMode::Deterministic,
        )
        .map_err(|e| format!("nova IVC fold failed: {e}"))?;
        let mut artifact = execution.artifact;
        crate::util::annotate_artifact_with_runtime_report(&mut artifact, &execution.result);

        let ok = zkf_backends::try_verify_fold_native(&compiled, &artifact)
            .ok_or_else(|| {
                "nova IVC fold verification unavailable in this build; native Nova folding is not compiled in"
                    .to_string()
            })?
            .map_err(|e| format!("nova IVC fold verification failed: {e}"))?;
        if !ok {
            return Err("nova IVC fold verification returned false".to_string());
        }

        let proof_artifact_rel =
            PathBuf::from(format!("proofs/fold/{}/fold_proof.json", backend.as_str()));
        let proof_artifact_path = root.join(&proof_artifact_rel);
        let proof_sha = write_json_and_hash(&proof_artifact_path, &artifact)?;

        let fold_digest = {
            let mut hasher = Sha256::new();
            hasher.update(b"nova-ivc-fold-v1");
            hasher.update(backend.as_str());
            hasher.update((steps as u64).to_le_bytes());
            hasher.update(&artifact.proof);
            format!("{:x}", hasher.finalize())
        };

        let entries = run_ids
            .iter()
            .enumerate()
            .map(|(step_idx, run_id)| crate::FoldStepEntry {
                step: step_idx,
                run_id: run_id.clone(),
                proof_path: proof_artifact_rel.display().to_string(),
                proof_digest: sha256_hex(&artifact.proof),
                public_inputs: artifact.public_inputs.len(),
            })
            .collect::<Vec<_>>();

        let fold_artifact = crate::FoldArtifact {
            backend: backend.as_str().to_string(),
            steps,
            step_mode: "nova-ivc".to_string(),
            entries,
            fold_digest: fold_digest.clone(),
            scheme: "nova-ivc-fold-v1".to_string(),
        };
        let artifact_rel = PathBuf::from(format!("proofs/fold/{}/fold.json", backend.as_str()));
        let artifact_path = root.join(&artifact_rel);
        let artifact_sha = write_json_and_hash(&artifact_path, &fold_artifact)?;

        let mut final_manifest: PackageManifest = read_json(manifest_path)?;
        final_manifest.files.proofs.insert(
            fold_file_key(backend),
            PackageFileRef {
                path: artifact_rel.display().to_string(),
                sha256: artifact_sha,
            },
        );
        final_manifest.files.proofs.insert(
            format!("fold-proof/{}", backend.as_str()),
            PackageFileRef {
                path: proof_artifact_rel.display().to_string(),
                sha256: proof_sha,
            },
        );
        final_manifest.metadata.insert(
            "last_fold_backend".to_string(),
            backend.as_str().to_string(),
        );
        final_manifest
            .metadata
            .insert("last_fold_steps".to_string(), steps.to_string());
        final_manifest
            .metadata
            .insert("last_fold_step_mode".to_string(), "nova-ivc".to_string());
        final_manifest
            .metadata
            .insert("last_fold_digest".to_string(), fold_digest.clone());
        final_manifest
            .metadata
            .insert("nova_ivc_steps_proven".to_string(), steps.to_string());
        final_manifest
            .metadata
            .insert("nova_ivc_compressed".to_string(), "true".to_string());
        write_json(manifest_path, &final_manifest)?;

        return Ok(crate::FoldResult {
            manifest: manifest_path.display().to_string(),
            backend: backend.as_str().to_string(),
            steps,
            step_mode: "nova-ivc".to_string(),
            run_ids,
            artifact_path: artifact_path.display().to_string(),
            fold_digest,
        });
    }

    // -----------------------------------------------------------------------
    // Standard per-step prove/verify path.
    // -----------------------------------------------------------------------
    let mut entries = Vec::with_capacity(steps);
    let mut run_ids = Vec::with_capacity(steps);
    for step in 0..steps {
        let run_id = normalize_run_id(&format!("fold-step-{step}"))?;
        let step_inputs_rel = PathBuf::from(format!("runs/{run_id}/inputs.json"));
        let step_inputs_path = root.join(&step_inputs_rel);
        if let Some(parent) = step_inputs_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        write_json(&step_inputs_path, &current_inputs)?;

        crate::cmd::witness::run_package(manifest_path, &step_inputs_path, &run_id, solver)?;
        let prove_report = super::prove::prove_package(
            manifest_path,
            &BackendRequest::native(backend),
            objective,
            &run_id,
            seed,
            false,
        )?;
        let verify_report = super::verify_proof::verify_package_proof(
            manifest_path,
            &BackendRequest::native(backend),
            &run_id,
            seed,
            None,
            false,
        )?;
        if !verify_report.ok {
            return Err(format!(
                "fold verification failed at step {} (run_id='{}')",
                step, run_id
            ));
        }

        let proof_path = PathBuf::from(&prove_report.proof_path);
        let artifact: ProofArtifact = read_json(&proof_path)?;
        entries.push(crate::FoldStepEntry {
            step,
            run_id: run_id.clone(),
            proof_path: prove_report.proof_path.clone(),
            proof_digest: sha256_hex(&artifact.proof),
            public_inputs: artifact.public_inputs.len(),
        });
        run_ids.push(run_id);

        if step_mode == StepMode::ChainPublicOutputs && step + 1 < steps {
            current_inputs =
                chain_step_inputs(&base_inputs, &public_signal_names, &artifact.public_inputs)?;
        } else {
            current_inputs = base_inputs.clone();
        }
    }

    let scheme = if backend == BackendKind::Nova {
        "nova-native-fold-v1"
    } else {
        "zkf-fold-v1"
    };

    let mut hasher = Sha256::new();
    hasher.update(scheme.as_bytes());
    hasher.update(backend.as_str());
    hasher.update(step_mode.as_str());
    hasher.update((steps as u64).to_le_bytes());
    for entry in &entries {
        hasher.update(entry.proof_digest.as_bytes());
    }
    let fold_digest = format!("{:x}", hasher.finalize());

    let artifact = crate::FoldArtifact {
        backend: backend.as_str().to_string(),
        steps,
        step_mode: step_mode.as_str().to_string(),
        entries,
        fold_digest: fold_digest.clone(),
        scheme: scheme.to_string(),
    };
    let artifact_rel = PathBuf::from(format!("proofs/fold/{}/fold.json", backend.as_str()));
    let artifact_path = root.join(&artifact_rel);
    let artifact_sha = write_json_and_hash(&artifact_path, &artifact)?;

    let mut latest_manifest: PackageManifest = read_json(manifest_path)?;
    latest_manifest.files.proofs.insert(
        fold_file_key(backend),
        PackageFileRef {
            path: artifact_rel.display().to_string(),
            sha256: artifact_sha,
        },
    );
    latest_manifest.metadata.insert(
        "last_fold_backend".to_string(),
        backend.as_str().to_string(),
    );
    latest_manifest
        .metadata
        .insert("last_fold_steps".to_string(), steps.to_string());
    latest_manifest.metadata.insert(
        "last_fold_step_mode".to_string(),
        step_mode.as_str().to_string(),
    );
    latest_manifest
        .metadata
        .insert("last_fold_digest".to_string(), fold_digest.clone());
    write_json(manifest_path, &latest_manifest)?;

    Ok(crate::FoldResult {
        manifest: manifest_path.display().to_string(),
        backend: backend.as_str().to_string(),
        steps,
        step_mode: step_mode.as_str().to_string(),
        run_ids,
        artifact_path: artifact_path.display().to_string(),
        fold_digest,
    })
}

pub(crate) struct FoldOptions {
    pub manifest: PathBuf,
    pub inputs: PathBuf,
    pub steps: usize,
    pub backend: Option<BackendKind>,
    pub objective: zkf_runtime::OptimizationObjective,
    pub solver: Option<String>,
    pub step_mode: Option<StepMode>,
    pub json: bool,
    pub seed: Option<[u8; 32]>,
}

pub(crate) fn handle_fold(opts: FoldOptions) -> Result<(), String> {
    let backend = match opts.backend {
        Some(backend) => backend,
        None => {
            let manifest: PackageManifest = read_json(&opts.manifest)?;
            let root = opts.manifest.parent().ok_or_else(|| {
                format!(
                    "manifest has no parent directory: {}",
                    opts.manifest.display()
                )
            })?;
            let program = load_program_v2_from_manifest(root, &manifest)?;
            zkf_runtime::recommend_backend_for_program(&program, None, opts.objective).selected
        }
    };
    let report = fold_package(FoldPackageRequest {
        manifest_path: &opts.manifest,
        inputs_path: &opts.inputs,
        steps: opts.steps,
        backend,
        objective: opts.objective,
        solver: opts.solver.as_deref(),
        step_mode_override: opts.step_mode,
        seed: opts.seed,
    })?;

    // Warn if the manifest marks this proof as host-verified attestation (trust_tier=2).
    if let Ok(manifest) = read_json::<PackageManifest>(&opts.manifest)
        && manifest.metadata.get("trust_tier").map(|s| s.as_str()) == Some("2")
    {
        eprintln!(
            "WARNING: This proof uses host-verified ATTESTATION (trust_tier=2).\n\
             For cryptographic recursion: zkf wrap --target groth16-recursive"
        );
    }

    let json = opts.json;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "fold: backend={} steps={} step_mode={} digest={} artifact={}",
            report.backend,
            report.steps,
            report.step_mode,
            report.fold_digest,
            report.artifact_path
        );
    }
    Ok(())
}
