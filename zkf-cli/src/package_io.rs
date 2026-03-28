use serde::Serialize;
use std::path::{Path, PathBuf};
use zkf_core::{
    BackendKind, CompiledProgram, PACKAGE_SCHEMA_VERSION, PackageFileRef, PackageManifest, Program,
    ProofArtifact, Witness,
};

use crate::util::{read_json, write_json_and_hash};

pub(crate) fn normalize_run_id(run_id: &str) -> Result<String, String> {
    let run_id = run_id.trim();
    if run_id.is_empty() {
        return Err("run_id cannot be empty".to_string());
    }
    if run_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Ok(run_id.to_string());
    }
    Err(format!(
        "run_id '{}' contains unsupported characters; allowed: [A-Za-z0-9._-]",
        run_id
    ))
}

pub(crate) fn proof_file_key(backend: BackendKind, run_id: &str) -> String {
    format!("proof/{}/{run_id}", backend.as_str())
}

pub(crate) fn legacy_proof_file_key(backend: BackendKind) -> String {
    format!("proof/{}", backend.as_str())
}

pub(crate) fn proof_report_key(backend: BackendKind, run_id: &str) -> String {
    format!("proof-report/{}/{run_id}", backend.as_str())
}

pub(crate) fn legacy_proof_report_key(backend: BackendKind) -> String {
    format!("proof-report/{}", backend.as_str())
}

pub(crate) fn verify_report_key(backend: BackendKind, run_id: &str) -> String {
    format!("verify-report/{}/{run_id}", backend.as_str())
}

pub(crate) fn legacy_verify_report_key(backend: BackendKind) -> String {
    format!("verify-report/{}", backend.as_str())
}

pub(crate) fn solidity_verifier_key(backend: BackendKind, run_id: &str) -> String {
    format!("solidity-verifier/{}/{run_id}", backend.as_str())
}

pub(crate) fn bundle_file_key(run_id: &str) -> String {
    format!("bundle/{run_id}")
}

pub(crate) fn legacy_bundle_file_key() -> &'static str {
    "bundle"
}

pub(crate) fn legacy_aggregate_file_key() -> &'static str {
    "aggregate"
}

pub(crate) fn bundle_verify_file_key(run_id: &str) -> String {
    format!("bundle-verify/{run_id}")
}

pub(crate) fn legacy_bundle_verify_file_key() -> &'static str {
    "bundle-verify"
}

pub(crate) fn legacy_aggregate_verify_file_key() -> &'static str {
    "aggregate-verify"
}

pub(crate) fn crypto_aggregate_file_key(backend: BackendKind, run_id: &str) -> String {
    format!("aggregate/{}/{run_id}", backend.as_str())
}

pub(crate) fn crypto_aggregate_verify_file_key(backend: BackendKind, run_id: &str) -> String {
    format!("aggregate-verify/{}/{run_id}", backend.as_str())
}

pub(crate) fn fold_file_key(backend: BackendKind) -> String {
    format!("fold/{}", backend.as_str())
}

pub(crate) fn compose_proof_key(backend: BackendKind, run_id: &str) -> String {
    format!("compose-proof/{}/{run_id}", backend.as_str())
}

pub(crate) fn compose_program_key(backend: BackendKind, run_id: &str) -> String {
    format!("compose-program/{}/{run_id}", backend.as_str())
}

pub(crate) fn compose_report_key(backend: BackendKind, run_id: &str) -> String {
    format!("compose-report/{}/{run_id}", backend.as_str())
}

pub(crate) fn compose_verify_key(backend: BackendKind, run_id: &str) -> String {
    format!("compose-verify/{}/{run_id}", backend.as_str())
}

pub(crate) fn run_witness_ref<'a>(
    manifest: &'a PackageManifest,
    run_id: &str,
) -> Option<&'a PackageFileRef> {
    manifest
        .runs
        .get(run_id)
        .map(|run| &run.witness)
        .or_else(|| {
            if run_id == "main" {
                manifest.files.witness.as_ref()
            } else {
                None
            }
        })
}

pub(crate) fn proof_artifact_ref<'a>(
    manifest: &'a PackageManifest,
    backend: BackendKind,
    run_id: &str,
) -> Option<&'a PackageFileRef> {
    manifest
        .files
        .proofs
        .get(&proof_file_key(backend, run_id))
        .or_else(|| {
            if run_id == "main" {
                manifest.files.proofs.get(&legacy_proof_file_key(backend))
            } else {
                None
            }
        })
}

pub(crate) fn bundle_artifact_ref<'a>(
    manifest: &'a PackageManifest,
    run_id: &str,
) -> Option<&'a PackageFileRef> {
    manifest
        .files
        .proofs
        .get(&bundle_file_key(run_id))
        .or_else(|| {
            if run_id == "main" {
                manifest
                    .files
                    .proofs
                    .get(legacy_bundle_file_key())
                    .or_else(|| manifest.files.proofs.get(legacy_aggregate_file_key()))
            } else {
                None
            }
        })
        .or_else(|| {
            manifest
                .files
                .proofs
                .get(&legacy_aggregate_file_key_for_run(run_id))
        })
}

pub(crate) fn crypto_aggregate_artifact_ref<'a>(
    manifest: &'a PackageManifest,
    backend: BackendKind,
    run_id: &str,
) -> Option<&'a PackageFileRef> {
    manifest
        .files
        .proofs
        .get(&crypto_aggregate_file_key(backend, run_id))
}

fn legacy_aggregate_file_key_for_run(run_id: &str) -> String {
    format!("aggregate/{run_id}")
}

pub(crate) fn compiled_file_key(backend: BackendKind) -> String {
    format!("compiled/{}", backend.as_str())
}

pub(crate) fn write_compiled_artifact(
    root: &Path,
    manifest: &mut PackageManifest,
    backend: BackendKind,
    compiled: &CompiledProgram,
) -> Result<PathBuf, String> {
    let compiled_rel = if let Some(cache_dir) = manifest.files.cache_dir.as_deref() {
        PathBuf::from(format!(
            "{}/compiled/{}/compiled.json",
            cache_dir.trim_end_matches('/'),
            backend.as_str()
        ))
    } else {
        PathBuf::from(format!("compiled/{}/compiled.json", backend.as_str()))
    };
    let compiled_path = root.join(&compiled_rel);
    let compiled_sha = write_json_and_hash(&compiled_path, compiled)?;
    manifest.files.compiled.insert(
        compiled_file_key(backend),
        PackageFileRef {
            path: compiled_rel.display().to_string(),
            sha256: compiled_sha,
        },
    );
    Ok(compiled_path)
}

#[derive(Debug, Serialize)]
struct ProveArtifactReport {
    backend: String,
    run_id: String,
    proof_size_bytes: usize,
    public_inputs: usize,
    witness_values: usize,
    program_digest: String,
    hybrid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    companion_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_manifest_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_semantics: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prover_acceleration_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gpu_stage_coverage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metal_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_execution_regime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_gpu_stage_busy_ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_prover_acceleration_realized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prover_acceleration_realization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_math_fallback_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export_scheme: Option<String>,
}

pub(crate) fn write_proof_artifacts(
    root: &Path,
    manifest: &mut PackageManifest,
    backend: BackendKind,
    run_id: &str,
    program: &Program,
    witness: &Witness,
    artifact: &ProofArtifact,
) -> Result<(PathBuf, PathBuf), String> {
    manifest.schema_version = PACKAGE_SCHEMA_VERSION;

    let proof_rel = PathBuf::from(format!("proofs/{}/{run_id}/proof.json", backend.as_str()));
    let proof_path = root.join(&proof_rel);
    let proof_sha = write_json_and_hash(&proof_path, artifact)?;
    manifest.files.proofs.insert(
        proof_file_key(backend, run_id),
        PackageFileRef {
            path: proof_rel.display().to_string(),
            sha256: proof_sha.clone(),
        },
    );
    if run_id == "main" {
        manifest.files.proofs.insert(
            legacy_proof_file_key(backend),
            PackageFileRef {
                path: proof_rel.display().to_string(),
                sha256: proof_sha,
            },
        );
    }

    let replay_manifest_path =
        if let Some(replay_manifest_json) = artifact.metadata.get("hybrid_replay_manifest_json") {
            let replay_rel = PathBuf::from(format!(
                "proofs/{}/{run_id}/replay_manifest.json",
                backend.as_str()
            ));
            let replay_path = root.join(&replay_rel);
            let replay_sha = write_json_and_hash(
                &replay_path,
                &serde_json::from_str::<serde_json::Value>(replay_manifest_json)
                    .map_err(|err| format!("invalid hybrid replay manifest JSON: {err}"))?,
            )?;
            manifest.files.replay_manifests.insert(
                format!("{}:{run_id}", backend.as_str()),
                PackageFileRef {
                    path: replay_rel.display().to_string(),
                    sha256: replay_sha,
                },
            );
            Some(replay_path.display().to_string())
        } else {
            None
        };

    let runtime_realization = crate::util::runtime_execution_realization(&artifact.metadata);
    let prove_report = ProveArtifactReport {
        backend: backend.as_str().to_string(),
        run_id: run_id.to_string(),
        proof_size_bytes: artifact.proof.len(),
        public_inputs: artifact.public_inputs.len(),
        witness_values: witness.values.len(),
        program_digest: program.digest_hex(),
        hybrid: artifact.hybrid_bundle.is_some(),
        security_profile: Some(artifact.effective_security_profile().as_str().to_string()),
        companion_backend: artifact
            .hybrid_bundle
            .as_ref()
            .map(|bundle| bundle.companion_leg.backend.as_str().to_string()),
        replay_manifest_path: replay_manifest_path.clone(),
        proof_engine: artifact.metadata.get("proof_engine").cloned(),
        proof_semantics: artifact.metadata.get("proof_semantics").cloned(),
        prover_acceleration_scope: artifact.metadata.get("prover_acceleration_scope").cloned(),
        gpu_stage_coverage: artifact.metadata.get("gpu_stage_coverage").cloned(),
        metal_complete: artifact
            .metadata
            .get("metal_complete")
            .and_then(|value| value.parse::<bool>().ok()),
        runtime_execution_regime: runtime_realization.execution_regime,
        runtime_gpu_stage_busy_ratio: runtime_realization.gpu_stage_busy_ratio,
        runtime_prover_acceleration_realized: runtime_realization
            .prover_acceleration_realized,
        prover_acceleration_realization: runtime_realization.acceleration_label,
        cpu_math_fallback_reason: artifact.metadata.get("cpu_math_fallback_reason").cloned(),
        export_scheme: artifact.metadata.get("export_scheme").cloned(),
    };
    let report_rel = PathBuf::from(format!("proofs/{}/{run_id}/report.json", backend.as_str()));
    let report_path = root.join(&report_rel);
    let report_sha = write_json_and_hash(&report_path, &prove_report)?;
    manifest.files.proofs.insert(
        proof_report_key(backend, run_id),
        PackageFileRef {
            path: report_rel.display().to_string(),
            sha256: report_sha.clone(),
        },
    );
    if run_id == "main" {
        manifest.files.proofs.insert(
            legacy_proof_report_key(backend),
            PackageFileRef {
                path: report_rel.display().to_string(),
                sha256: report_sha,
            },
        );
    }
    Ok((proof_path, report_path))
}

pub(crate) fn load_compiled_artifact(
    root: &Path,
    manifest: &PackageManifest,
    backend: BackendKind,
    expected_program_digest: &str,
) -> Result<Option<CompiledProgram>, String> {
    let Some(compiled_ref) = manifest.files.compiled.get(&compiled_file_key(backend)) else {
        return Ok(None);
    };

    let compiled_path = root.join(&compiled_ref.path);
    let compiled: CompiledProgram = read_json(&compiled_path)?;
    if compiled.backend != backend {
        return Err(format!(
            "compiled artifact backend mismatch: found {}, expected {} in {}",
            compiled.backend,
            backend,
            compiled_path.display()
        ));
    }
    let compiled_source_digest = compiled
        .original_program
        .as_ref()
        .map(Program::digest_hex)
        .unwrap_or_else(|| compiled.program_digest.clone());
    if compiled_source_digest != expected_program_digest {
        return Err(format!(
            "compiled artifact program digest mismatch for backend {} in {} (expected {}, found {})",
            backend,
            compiled_path.display(),
            expected_program_digest,
            compiled_source_digest
        ));
    }
    Ok(Some(compiled))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zkf_core::{
        Constraint, Expr, FieldElement, FieldId, FrontendProvenance, HybridProofBundle,
        HybridReplayGuard, Program, ProofArchiveMetadata, Signal, Visibility, WitnessPlan,
    };

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zkf-package-io-{label}-{nonce}"));
        fs::create_dir_all(&root).expect("root dir");
        root
    }

    fn demo_program() -> Program {
        Program {
            name: "package_io_demo".to_string(),
            field: FieldId::Goldilocks,
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
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("y"),
                rhs: Expr::signal("x"),
                label: Some("eq".to_string()),
            }],
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        }
    }

    #[test]
    fn write_proof_artifacts_upgrades_manifest_and_records_hybrid_replay_manifest() {
        let root = temp_root("hybrid-manifest");
        let program = demo_program();
        let witness = Witness {
            values: BTreeMap::from([
                ("x".to_string(), FieldElement::from_u64(5)),
                ("y".to_string(), FieldElement::from_u64(5)),
            ]),
        };
        let mut manifest = PackageManifest::from_program(
            &program,
            FrontendProvenance::new("noir"),
            "ir/program.json",
            "frontends/noir/original.json",
        );
        manifest.schema_version = 2;

        let mut primary = ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: program.digest_hex(),
            proof: vec![1, 2, 3],
            verification_key: vec![4, 5, 6],
            public_inputs: vec![FieldElement::from_u64(5)],
            metadata: BTreeMap::from([(
                "hybrid_replay_manifest_json".to_string(),
                serde_json::json!({
                    "replay_id": "hybrid-main",
                    "transcript_hash": "abc123",
                    "stage_manifest_digest": "def456",
                    "proof_manifest_digest": "7890ab"
                })
                .to_string(),
            )]),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };
        let companion = ProofArtifact {
            backend: BackendKind::Plonky3,
            program_digest: program.digest_hex(),
            proof: vec![7, 8, 9],
            verification_key: vec![10, 11, 12],
            public_inputs: vec![FieldElement::from_u64(5)],
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        };
        let primary_leg = primary.as_hybrid_leg();
        let companion_leg = companion.as_hybrid_leg();
        primary = primary.with_hybrid_bundle(
            HybridProofBundle {
                primary_leg,
                companion_leg,
                transcript_hashes: BTreeMap::from([("hybrid".to_string(), "abc123".to_string())]),
                setup_provenance: BTreeMap::from([(
                    "wrapped_backend".to_string(),
                    "arkworks-groth16".to_string(),
                )]),
                tool_digests: BTreeMap::from([("zkf".to_string(), "digest".to_string())]),
                replay_guard: Some(HybridReplayGuard {
                    replay_id: "hybrid-main".to_string(),
                    transcript_hash: "abc123".to_string(),
                    stage_manifest_digest: "def456".to_string(),
                    proof_manifest_digest: "7890ab".to_string(),
                }),
            },
            Some(ProofArchiveMetadata {
                theorem_claim_id: Some("ledger.hybrid.main".to_string()),
                claim_scope: Some("hybrid-package".to_string()),
                archive_path: None,
                metadata: BTreeMap::new(),
            }),
        );

        let (proof_path, report_path) = write_proof_artifacts(
            &root,
            &mut manifest,
            BackendKind::ArkworksGroth16,
            "main",
            &program,
            &witness,
            &primary,
        )
        .expect("write proof artifacts");

        assert_eq!(manifest.schema_version, PACKAGE_SCHEMA_VERSION);
        assert!(proof_path.exists());
        assert!(report_path.exists());
        assert!(
            manifest
                .files
                .replay_manifests
                .contains_key("arkworks-groth16:main")
        );

        let _ = fs::remove_dir_all(&root);
    }
}
