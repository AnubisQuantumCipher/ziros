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

use crate::api::{BackendProofExecutionResult, RuntimeExecutor, WrapperExecutionResult};
use crate::control_plane::{
    ControlPlaneReplayManifest, HardwareProbeSummary, enforce_apple_silicon_production_lane,
    persist_replay_manifest, run_continuous_hardware_probes,
};
use crate::error::RuntimeError;
use crate::hybrid_core;
use crate::trust::HardwareProfile;
use crate::{ExecutionMode, RequiredTrustLane};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_backends::{BackendRoute, backend_for_route, wrapping::default_wrapper_registry};
use zkf_core::wrapping::WrapperExecutionPolicy;
use zkf_core::{
    BackendKind, CompiledProgram, FieldElement, HybridProofBundle, HybridReplayGuard, Program,
    ProofArchiveMetadata, ProofArtifact, ProofSecurityProfile, Witness, WitnessInputs,
};

pub struct HybridBackendProofExecutionResult {
    pub source: BackendProofExecutionResult,
    pub wrapped: WrapperExecutionResult,
    pub artifact: ProofArtifact,
    pub replay_manifest_path: Option<String>,
    pub hardware_probes: HardwareProbeSummary,
}

#[allow(clippy::too_many_arguments)]
pub fn run_hybrid_prove_job_with_objective(
    program: Arc<Program>,
    inputs: Option<Arc<WitnessInputs>>,
    witness: Option<Arc<Witness>>,
    objective: crate::OptimizationObjective,
    trust: RequiredTrustLane,
    mode: ExecutionMode,
) -> Result<HybridBackendProofExecutionResult, RuntimeError> {
    let hardware_profile = HardwareProfile::detect();
    enforce_apple_silicon_production_lane(hardware_profile, true, false)?;
    let hardware_probes = run_continuous_hardware_probes()?;
    if !hardware_probes_clean(&hardware_probes) {
        return Err(RuntimeError::Execution(format!(
            "hardware consistency probes detected {} mismatches; rejecting hybrid proof job",
            hardware_probes.mismatch_count
        )));
    }

    let source = RuntimeExecutor::run_backend_prove_job_with_objective(
        BackendKind::Plonky3,
        BackendRoute::Auto,
        Arc::clone(&program),
        inputs,
        witness,
        None,
        objective,
        trust,
        mode,
    )?;
    verify_companion_leg(&source.compiled, &source.artifact)?;

    let registry = default_wrapper_registry();
    let wrapper = registry
        .find(BackendKind::Plonky3, BackendKind::ArkworksGroth16)
        .ok_or_else(|| RuntimeError::UnsupportedFeature {
            backend: "hybrid".to_string(),
            feature: "plonky3 -> groth16 wrapper is not registered".to_string(),
        })?;
    let policy = WrapperExecutionPolicy::default();
    let preview = wrapper
        .preview_wrap_with_policy(&source.artifact, &source.compiled, policy)
        .map_err(|err| RuntimeError::Execution(format!("hybrid wrapper preview failed: {err}")))?
        .ok_or_else(|| {
            RuntimeError::Execution(
                "hybrid wrapper did not provide an executable runtime preview".to_string(),
            )
        })?;
    let wrapped = RuntimeExecutor::run_wrapper_job_with_sources(
        &preview,
        Arc::new(source.artifact.clone()),
        Arc::new(source.compiled.clone()),
        policy,
        mode,
    )?;
    if !wrapper.verify_wrapped(&wrapped.artifact).map_err(|err| {
        RuntimeError::Execution(format!("hybrid primary leg verify failed: {err}"))
    })? {
        return Err(RuntimeError::Execution(
            "hybrid primary leg did not verify after wrap".to_string(),
        ));
    }

    let mut primary_artifact = wrapped.artifact.clone();
    primary_artifact.security_profile = Some(ProofSecurityProfile::Classical);
    primary_artifact.archive_metadata = wrapped_archive_metadata();

    let mut companion_artifact = source.artifact.clone();
    companion_artifact.security_profile = Some(ProofSecurityProfile::StarkPq);
    companion_artifact.archive_metadata =
        companion_archive_metadata(&source.compiled.program, &source.artifact.metadata);

    let transcript_hashes = hybrid_transcript_hashes(&primary_artifact, &companion_artifact)?;
    let setup_provenance = hybrid_setup_provenance(&primary_artifact, &companion_artifact);
    let tool_digests = hybrid_tool_digests()?;
    let mut manifest = build_replay_manifest(
        hardware_profile,
        &source,
        &wrapped,
        &primary_artifact,
        &companion_artifact,
        &transcript_hashes,
    )?;
    if let Some(control_plane) = source.result.control_plane.as_ref() {
        manifest.model_catalog_fingerprint = Some(model_catalog_fingerprint(control_plane)?);
    }
    manifest.metadata.insert(
        "hardware_probe_mismatch_count".to_string(),
        hardware_probes.mismatch_count.to_string(),
    );
    let (replay_manifest_path, proof_manifest_digest) = persist_replay_manifest(&manifest)?;
    let replay_guard = HybridReplayGuard {
        replay_id: manifest.replay_id.clone(),
        transcript_hash: manifest.transcript_hash.clone(),
        stage_manifest_digest: manifest.stage_manifest_digest.clone(),
        proof_manifest_digest: proof_manifest_digest.clone(),
    };

    let bundle = HybridProofBundle {
        primary_leg: primary_artifact.as_hybrid_leg(),
        companion_leg: companion_artifact.as_hybrid_leg(),
        transcript_hashes: transcript_hashes.clone(),
        setup_provenance: setup_provenance.clone(),
        tool_digests: tool_digests.clone(),
        replay_guard: Some(replay_guard.clone()),
    };

    let primary_archive_metadata = primary_artifact.archive_metadata.clone();
    let mut artifact = primary_artifact.with_hybrid_bundle(bundle, primary_archive_metadata);
    annotate_hybrid_metadata(
        &mut artifact,
        &source.compiled,
        &manifest,
        &replay_guard,
        &tool_digests,
        &hardware_probes,
        &replay_manifest_path,
    )?;
    let replay_manifest_json = serde_json::to_string_pretty(&manifest).map_err(|err| {
        RuntimeError::Execution(format!(
            "failed to serialize replay manifest metadata: {err}"
        ))
    })?;
    artifact.metadata.insert(
        "hybrid_replay_manifest_json".to_string(),
        replay_manifest_json,
    );

    let replay_manifest_path = artifact
        .metadata
        .get("hybrid_replay_manifest_path")
        .cloned();

    Ok(HybridBackendProofExecutionResult {
        source,
        wrapped,
        artifact,
        replay_manifest_path,
        hardware_probes,
    })
}

pub fn verify_hybrid_artifact(
    program: &Program,
    artifact: &ProofArtifact,
) -> Result<bool, RuntimeError> {
    let Some(bundle) = artifact.hybrid_bundle.as_ref() else {
        return Ok(false);
    };

    if !hybrid_primary_leg_matches_outer_artifact(artifact, bundle) {
        return Ok(false);
    }

    let companion_artifact = bundle.companion_leg.to_proof_artifact();
    if !hybrid_bundle_transcript_hashes_match(bundle, artifact, &companion_artifact)? {
        return Ok(false);
    }

    let registry = default_wrapper_registry();
    let wrapper = registry
        .find(bundle.companion_leg.backend, bundle.primary_leg.backend)
        .ok_or_else(|| RuntimeError::UnsupportedFeature {
            backend: "hybrid".to_string(),
            feature: format!(
                "no wrapper registered from '{}' to '{}'",
                bundle.companion_leg.backend, bundle.primary_leg.backend
            ),
        })?;
    let primary_ok = wrapper
        .verify_wrapped(artifact)
        .map_err(|err| RuntimeError::Execution(format!("hybrid primary verify failed: {err}")))?;

    let companion_engine = backend_for_route(bundle.companion_leg.backend, BackendRoute::Auto);
    let companion_compiled = companion_engine.compile(program).map_err(|err| {
        RuntimeError::Execution(format!("hybrid companion compile failed: {err}"))
    })?;
    let companion_ok = companion_engine
        .verify(&companion_compiled, &companion_artifact)
        .map_err(|err| RuntimeError::Execution(format!("hybrid companion verify failed: {err}")))?;
    Ok(hybrid_verify_decision(primary_ok, companion_ok))
}

fn verify_companion_leg(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> Result<(), RuntimeError> {
    let engine = backend_for_route(BackendKind::Plonky3, BackendRoute::Auto);
    let verified = engine.verify(compiled, artifact).map_err(|err| {
        RuntimeError::Execution(format!("hybrid companion leg verify failed: {err}"))
    })?;
    if verified {
        Ok(())
    } else {
        Err(RuntimeError::Execution(
            "hybrid companion leg did not verify".to_string(),
        ))
    }
}

pub(crate) fn hybrid_transcript_hashes(
    primary: &ProofArtifact,
    companion: &ProofArtifact,
) -> Result<BTreeMap<String, String>, RuntimeError> {
    let mut hashes = BTreeMap::new();
    hashes.insert("primary".to_string(), transcript_hash(primary)?);
    hashes.insert("companion".to_string(), transcript_hash(companion)?);
    hashes.insert(
        "public-inputs".to_string(),
        public_inputs_digest(&primary.public_inputs)?,
    );
    Ok(hashes)
}

pub(crate) fn hardware_probes_clean(hardware_probes: &HardwareProbeSummary) -> bool {
    hybrid_core::hardware_probes_clean(hardware_probes)
}

pub(crate) fn hybrid_verify_decision(primary_ok: bool, companion_ok: bool) -> bool {
    hybrid_core::hybrid_verify_decision(primary_ok, companion_ok)
}

pub(crate) fn hybrid_primary_leg_matches_outer_artifact(
    artifact: &ProofArtifact,
    bundle: &HybridProofBundle,
) -> bool {
    hybrid_primary_leg_byte_components_match(
        &artifact.proof,
        &artifact.verification_key,
        &bundle.primary_leg.proof,
        &bundle.primary_leg.verification_key,
    ) && bundle.primary_leg.public_inputs == artifact.public_inputs
}

pub(crate) fn hybrid_primary_leg_byte_components_match(
    artifact_proof: &[u8],
    artifact_verification_key: &[u8],
    primary_leg_proof: &[u8],
    primary_leg_verification_key: &[u8],
) -> bool {
    hybrid_core::hybrid_primary_leg_byte_components_match(
        artifact_proof,
        artifact_verification_key,
        primary_leg_proof,
        primary_leg_verification_key,
    )
}

pub(crate) fn hybrid_bundle_transcript_hashes_match(
    bundle: &HybridProofBundle,
    primary: &ProofArtifact,
    companion: &ProofArtifact,
) -> Result<bool, RuntimeError> {
    let serialized_public_inputs = serde_json::to_vec(&primary.public_inputs)
        .map_err(|err| RuntimeError::Execution(format!("failed to hash public inputs: {err}")))?;
    if !hybrid_public_inputs_hash_matches(&bundle.transcript_hashes, &serialized_public_inputs) {
        return Ok(false);
    }
    Ok(bundle.transcript_hashes == hybrid_transcript_hashes(primary, companion)?)
}

#[allow(dead_code)]
pub(crate) fn replay_manifest_identity_components(
    manifest: &ControlPlaneReplayManifest,
) -> (&str, &str, &str, &str, &str) {
    hybrid_core::replay_manifest_identity_components(manifest)
}

#[allow(dead_code)]
pub(crate) fn replay_manifest_identity_is_deterministic(
    manifest: &ControlPlaneReplayManifest,
) -> bool {
    hybrid_core::replay_manifest_identity_is_deterministic(manifest)
}

pub(crate) fn public_inputs_digest_from_bytes(bytes: &[u8]) -> String {
    hybrid_core::public_inputs_digest_from_bytes(bytes)
}

pub(crate) fn transcript_hash_entry_matches(
    transcript_hashes: &BTreeMap<String, String>,
    label: &str,
    expected_hash: &str,
) -> bool {
    digest_matches_recorded_hash(
        transcript_hashes.get(label).map(String::as_str),
        expected_hash,
    )
}

pub(crate) fn hybrid_public_inputs_hash_matches(
    transcript_hashes: &BTreeMap<String, String>,
    public_inputs_bytes: &[u8],
) -> bool {
    hybrid_public_inputs_digest_entry_matches(
        transcript_hashes,
        &public_inputs_digest_from_bytes(public_inputs_bytes),
    )
}

pub(crate) fn hybrid_public_inputs_digest_entry_matches(
    transcript_hashes: &BTreeMap<String, String>,
    recomputed_public_inputs_hash: &str,
) -> bool {
    transcript_hash_entry_matches(
        transcript_hashes,
        "public-inputs",
        recomputed_public_inputs_hash,
    )
}

fn public_inputs_digest(public_inputs: &[FieldElement]) -> Result<String, RuntimeError> {
    let bytes = serde_json::to_vec(public_inputs)
        .map_err(|err| RuntimeError::Execution(format!("failed to hash public inputs: {err}")))?;
    Ok(public_inputs_digest_from_bytes(&bytes))
}

pub(crate) fn digest_matches_recorded_hash(
    recorded_hash: Option<&str>,
    expected_hash: &str,
) -> bool {
    hybrid_core::digest_matches_recorded_hash(recorded_hash, expected_hash)
}

fn transcript_hash(artifact: &ProofArtifact) -> Result<String, RuntimeError> {
    let bytes = serde_json::to_vec(&(
        artifact.backend,
        &artifact.program_digest,
        &artifact.proof,
        &artifact.verification_key,
        &artifact.public_inputs,
    ))
    .map_err(|err| RuntimeError::Execution(format!("failed to hash proof transcript: {err}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn hybrid_setup_provenance(
    primary: &ProofArtifact,
    companion: &ProofArtifact,
) -> BTreeMap<String, String> {
    let mut provenance = BTreeMap::new();
    for (key, value) in primary
        .metadata
        .iter()
        .chain(companion.metadata.iter())
        .filter(|(key, _)| {
            key.contains("setup")
                || key.contains("srs")
                || key.contains("vk")
                || key.contains("fri")
        })
    {
        provenance
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
    provenance
}

fn hybrid_tool_digests() -> Result<BTreeMap<String, String>, RuntimeError> {
    let mut digests = BTreeMap::new();
    let tool_version = format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    digests.insert(
        "zkf-runtime".to_string(),
        format!("{:x}", Sha256::digest(tool_version.as_bytes())),
    );
    digests.insert(
        "package-schema-v3".to_string(),
        format!("{:x}", Sha256::digest("zkf-package-schema-v3".as_bytes())),
    );
    let cargo_lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../Cargo.lock");
    if cargo_lock.exists() {
        let bytes = fs::read(&cargo_lock).map_err(|err| {
            RuntimeError::Execution(format!("failed to read {}: {err}", cargo_lock.display()))
        })?;
        digests.insert(
            "cargo-lock".to_string(),
            format!("{:x}", Sha256::digest(bytes)),
        );
    }
    Ok(digests)
}

fn build_replay_manifest(
    hardware_profile: HardwareProfile,
    source: &BackendProofExecutionResult,
    wrapped: &WrapperExecutionResult,
    primary: &ProofArtifact,
    companion: &ProofArtifact,
    transcript_hashes: &BTreeMap<String, String>,
) -> Result<ControlPlaneReplayManifest, RuntimeError> {
    let stage_digests = prefixed_stage_digests("companion", &source.result.report)?
        .into_iter()
        .chain(prefixed_stage_digests("primary", &wrapped.result.report)?)
        .collect::<BTreeMap<_, _>>();
    let stage_manifest_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&stage_digests).map_err(|err| {
            RuntimeError::Execution(format!("failed to hash stage manifest: {err}"))
        })?,)
    );
    let transcript_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(transcript_hashes).map_err(|err| {
            RuntimeError::Execution(format!("failed to hash hybrid transcripts: {err}"))
        })?,)
    );
    let mut proof_digests = BTreeMap::new();
    proof_digests.insert(
        "primary".to_string(),
        format!("{:x}", Sha256::digest(&primary.proof)),
    );
    proof_digests.insert(
        "companion".to_string(),
        format!("{:x}", Sha256::digest(&companion.proof)),
    );
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let replay_id = format!("hybrid-{}-{timestamp}", companion.program_digest);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "primary_backend".to_string(),
        primary.backend.as_str().to_string(),
    );
    metadata.insert(
        "companion_backend".to_string(),
        companion.backend.as_str().to_string(),
    );
    metadata.insert("hybrid_verification_mode".to_string(), "and".to_string());

    Ok(ControlPlaneReplayManifest {
        replay_id,
        transcript_hash,
        backend_route: "plonky3:auto -> arkworks-groth16:wrapper".to_string(),
        hardware_profile: hardware_profile.as_str().to_string(),
        stage_manifest_digest,
        stage_digests,
        proof_digests,
        model_catalog_fingerprint: None,
        metadata,
    })
}

fn prefixed_stage_digests(
    prefix: &str,
    report: &crate::telemetry::GraphExecutionReport,
) -> Result<BTreeMap<String, String>, RuntimeError> {
    let mut digests = BTreeMap::new();
    for (stage, telemetry) in report.stage_breakdown() {
        let bytes = serde_json::to_vec(&telemetry).map_err(|err| {
            RuntimeError::Execution(format!("failed to serialize stage telemetry: {err}"))
        })?;
        digests.insert(
            format!("{prefix}:{stage}"),
            format!("{:x}", Sha256::digest(bytes)),
        );
    }
    Ok(digests)
}

fn model_catalog_fingerprint(
    control_plane: &crate::ControlPlaneExecutionSummary,
) -> Result<String, RuntimeError> {
    let bytes = serde_json::to_vec(&control_plane.decision.model_catalog).map_err(|err| {
        RuntimeError::Execution(format!("failed to serialize model catalog: {err}"))
    })?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn annotate_hybrid_metadata(
    artifact: &mut ProofArtifact,
    source_compiled: &CompiledProgram,
    manifest: &ControlPlaneReplayManifest,
    replay_guard: &HybridReplayGuard,
    tool_digests: &BTreeMap<String, String>,
    hardware_probes: &HardwareProbeSummary,
    replay_manifest_path: &Path,
) -> Result<(), RuntimeError> {
    artifact.metadata.insert(
        "hybrid_mode".to_string(),
        "plonky3-stark-plus-groth16-wrap".to_string(),
    );
    artifact.metadata.insert(
        "hybrid_source_backend".to_string(),
        BackendKind::Plonky3.as_str().to_string(),
    );
    artifact.metadata.insert(
        "hybrid_companion_backend".to_string(),
        BackendKind::Plonky3.as_str().to_string(),
    );
    artifact.metadata.insert(
        "hybrid_primary_backend".to_string(),
        artifact.backend.as_str().to_string(),
    );
    artifact
        .metadata
        .insert("hybrid_verification_mode".to_string(), "and".to_string());
    artifact.metadata.insert(
        "proof_security_profile".to_string(),
        ProofSecurityProfile::HybridClassicalStark
            .as_str()
            .to_string(),
    );
    artifact.metadata.insert(
        "hybrid_replay_id".to_string(),
        replay_guard.replay_id.clone(),
    );
    artifact.metadata.insert(
        "hybrid_replay_manifest_path".to_string(),
        replay_manifest_path.display().to_string(),
    );
    artifact.metadata.insert(
        "hybrid_replay_manifest_digest".to_string(),
        replay_guard.proof_manifest_digest.clone(),
    );
    artifact.metadata.insert(
        "hybrid_stage_manifest_digest".to_string(),
        replay_guard.stage_manifest_digest.clone(),
    );
    artifact.metadata.insert(
        "hybrid_transcript_hash".to_string(),
        replay_guard.transcript_hash.clone(),
    );
    artifact.metadata.insert(
        "hybrid_source_program_field".to_string(),
        source_compiled.program.field.as_str().to_string(),
    );
    artifact.metadata.insert(
        "hybrid_hardware_profile".to_string(),
        manifest.hardware_profile.clone(),
    );
    artifact.metadata.insert(
        "hybrid_probe_ok".to_string(),
        hardware_probes.ok.to_string(),
    );
    artifact.metadata.insert(
        "hybrid_probe_mismatch_count".to_string(),
        hardware_probes.mismatch_count.to_string(),
    );
    artifact.metadata.insert(
        "hybrid_probe_summary".to_string(),
        serde_json::to_string(hardware_probes).map_err(|err| {
            RuntimeError::Execution(format!("failed to serialize hardware probes: {err}"))
        })?,
    );
    artifact.metadata.insert(
        "hybrid_tool_digests".to_string(),
        serde_json::to_string(tool_digests).map_err(|err| {
            RuntimeError::Execution(format!("failed to serialize tool digests: {err}"))
        })?,
    );
    Ok(())
}

fn companion_archive_metadata(
    program: &Program,
    metadata: &BTreeMap<String, String>,
) -> Option<ProofArchiveMetadata> {
    let theorem = verification_theorem_for_companion_backend(BackendKind::Plonky3)?;
    let archive_path = metadata
        .get("hybrid_replay_manifest_path")
        .cloned()
        .or_else(|| Some(format!("verification-ledger://{}", theorem.theorem_id)));
    Some(ProofArchiveMetadata {
        theorem_claim_id: Some(theorem.theorem_id),
        claim_scope: Some(theorem.scope),
        archive_path,
        metadata: BTreeMap::from([("program".to_string(), program.name.clone())]),
    })
}

fn wrapped_archive_metadata() -> Option<ProofArchiveMetadata> {
    Some(ProofArchiveMetadata {
        theorem_claim_id: None,
        claim_scope: Some("zkf-backends::wrapping::stark_to_groth16".to_string()),
        archive_path: None,
        metadata: BTreeMap::from([(
            "wrap_relation".to_string(),
            "plonky3-stark->groth16".to_string(),
        )]),
    })
}

#[derive(Debug, Deserialize)]
struct VerificationLedger {
    entries: Vec<VerificationLedgerEntry>,
}

#[derive(Debug, Deserialize)]
struct VerificationLedgerEntry {
    theorem_id: String,
    scope: String,
}

fn verification_theorem_for_companion_backend(
    backend: BackendKind,
) -> Option<VerificationLedgerEntry> {
    let theorem_id = match backend {
        BackendKind::Plonky3 => "backend.plonky3_lowering_soundness",
        _ => return None,
    };
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../zkf-ir-spec/verification-ledger.json");
    let bytes = fs::read(path).ok()?;
    let ledger: VerificationLedger = serde_json::from_slice(&bytes).ok()?;
    ledger
        .entries
        .into_iter()
        .find(|entry| entry.theorem_id == theorem_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::FieldElement;

    fn sample_artifact(
        backend: BackendKind,
        program_digest: &str,
        proof: &[u8],
        verification_key: &[u8],
        public_inputs: Vec<FieldElement>,
    ) -> ProofArtifact {
        ProofArtifact::new(
            backend,
            program_digest,
            proof.to_vec(),
            verification_key.to_vec(),
            public_inputs,
        )
}

    #[test]
    fn verify_decision_is_logical_and() {
        assert!(hybrid_verify_decision(true, true));
        assert!(!hybrid_verify_decision(true, false));
        assert!(!hybrid_verify_decision(false, true));
        assert!(!hybrid_verify_decision(false, false));
    }

    #[test]
    fn transcript_hash_binding_rejects_public_input_tampering() {
        let primary = sample_artifact(
            BackendKind::ArkworksGroth16,
            "digest",
            &[1, 2, 3],
            &[4, 5, 6],
            vec![FieldElement::from_i64(7)],
        );
        let companion = sample_artifact(
            BackendKind::Plonky3,
            "digest",
            &[9, 8, 7],
            &[6, 5, 4],
            vec![FieldElement::from_i64(7)],
        );
        let bundle = HybridProofBundle {
            primary_leg: primary.as_hybrid_leg(),
            companion_leg: companion.as_hybrid_leg(),
            transcript_hashes: hybrid_transcript_hashes(&primary, &companion).expect("hashes"),
            setup_provenance: BTreeMap::new(),
            tool_digests: BTreeMap::new(),
            replay_guard: None,
        };
        let tampered_primary = sample_artifact(
            BackendKind::ArkworksGroth16,
            "digest",
            &[1, 2, 3],
            &[4, 5, 6],
            vec![FieldElement::from_i64(8)],
        );

        assert!(
            !hybrid_bundle_transcript_hashes_match(&bundle, &tampered_primary, &companion)
                .expect("transcript comparison")
        );
    }

    #[test]
    fn hardware_probe_policy_requires_zero_mismatches() {
        assert!(hardware_probes_clean(&HardwareProbeSummary {
            ok: true,
            mismatch_count: 0,
            samples: vec![],
        }));
        assert!(!hardware_probes_clean(&HardwareProbeSummary {
            ok: true,
            mismatch_count: 1,
            samples: vec![],
        }));
        assert!(!hardware_probes_clean(&HardwareProbeSummary {
            ok: false,
            mismatch_count: 0,
            samples: vec![],
        }));
    }

    #[test]
    fn primary_leg_binding_rejects_verification_key_tampering() {
        assert!(hybrid_primary_leg_byte_components_match(
            &[1, 2, 3],
            &[4, 5, 6],
            &[1, 2, 3],
            &[4, 5, 6],
        ));
        assert!(!hybrid_primary_leg_byte_components_match(
            &[1, 2, 3],
            &[4, 5, 6],
            &[1, 2, 3],
            &[9, 9, 9],
        ));
    }

    #[test]
    fn replay_manifest_identity_is_stable_for_clones() {
        let manifest = ControlPlaneReplayManifest {
            replay_id: "replay-1".to_string(),
            transcript_hash: "transcript".to_string(),
            backend_route: "plonky3:auto -> arkworks-groth16:wrapper".to_string(),
            hardware_profile: "apple-silicon".to_string(),
            stage_manifest_digest: "stage-digest".to_string(),
            stage_digests: BTreeMap::new(),
            proof_digests: BTreeMap::new(),
            model_catalog_fingerprint: None,
            metadata: BTreeMap::new(),
        };

        assert_eq!(
            replay_manifest_identity_components(&manifest),
            replay_manifest_identity_components(&manifest.clone())
        );
        assert!(replay_manifest_identity_is_deterministic(&manifest));
    }

    #[test]
    fn verify_hybrid_artifact_rejects_tampered_transcript_bundle() {
        let program = Program::default();
        let primary = sample_artifact(
            BackendKind::ArkworksGroth16,
            &program.digest_hex(),
            &[1, 2, 3],
            &[4, 5, 6],
            vec![FieldElement::from_i64(3)],
        );
        let companion = sample_artifact(
            BackendKind::Plonky3,
            &program.digest_hex(),
            &[7, 8, 9],
            &[1, 2, 3],
            vec![FieldElement::from_i64(3)],
        );
        let mut transcript_hashes = hybrid_transcript_hashes(&primary, &companion).expect("hashes");
        transcript_hashes.insert("public-inputs".to_string(), "tampered".to_string());
        let artifact = primary.clone().with_hybrid_bundle(
            HybridProofBundle {
                primary_leg: primary.as_hybrid_leg(),
                companion_leg: companion.as_hybrid_leg(),
                transcript_hashes,
                setup_provenance: BTreeMap::new(),
                tool_digests: BTreeMap::new(),
                replay_guard: None,
            },
            None,
        );

        assert!(
            !verify_hybrid_artifact(&program, &artifact).expect("hybrid verify should not error")
        );
    }
}
