use crate::blackbox_native::{supported_blackbox_ops, validate_blackbox_constraints};
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::midnight_client::{MidnightClient, ProveRequest, VerifyRequest};
use crate::{BackendEngine, backend_for, midnight};
use base64::Engine;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_core::FieldElement;
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldId, Program,
    ProofArtifact, ToolRequirement, Witness, ZkfError, ZkfResult, check_constraints,
};

pub struct MidnightNativeBackend;

impl BackendEngine for MidnightNativeBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::MidnightCompact
    }

    fn capabilities(&self) -> BackendCapabilities {
        let has_proof_server = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL").is_ok();
        let mode = if has_proof_server {
            BackendMode::Native
        } else if allow_compat_delegate() {
            BackendMode::Compat
        } else {
            BackendMode::Native
        };
        let profile = if has_proof_server {
            "proof-server-v1".to_string()
        } else if allow_compat_delegate() {
            "compat-delegate".to_string()
        } else {
            "proof-server-v1".to_string()
        };
        BackendCapabilities {
            backend: BackendKind::MidnightCompact,
            mode,
            trusted_setup: false,
            recursion_ready: false,
            transparent_setup: true,
            zkvm_mode: false,
            network_target: Some("midnight".to_string()),
            supported_blackbox_ops: supported_blackbox_ops(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec![profile],
            notes: "Midnight runtime: proves via proof server when ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL is set; otherwise delegates to arkworks-groth16 when ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE=true."
                .to_string(),
        }
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "compact".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Compact compiler/runtime CLI for Midnight integration".to_string()),
                required: true,
            },
            ToolRequirement {
                tool: "docker".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Typical local Midnight proof-server runtime".to_string()),
                required: false,
            },
        ]
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        let mut compiled = CompiledProgram::new(self.kind(), program.clone());
        let compact_source = midnight::emit_compact(program);
        compiled
            .metadata
            .insert("compact_source".to_string(), compact_source.clone());
        compiled
            .metadata
            .insert("mode".to_string(), "native".to_string());

        if let Ok(delegate) = midnight_delegate_backend_for_field(program.field) {
            compiled.metadata.insert(
                "delegated_backend_hint".to_string(),
                delegate.as_str().to_string(),
            );
        }

        match try_compact_compile(&program.name, &compact_source) {
            Ok(report) => {
                compiled.metadata.insert(
                    "compact_compile_status".to_string(),
                    if report.success {
                        "ok".to_string()
                    } else {
                        "failed".to_string()
                    },
                );
                compiled.metadata.insert(
                    "compact_compile_artifacts_dir".to_string(),
                    report.artifacts_dir.display().to_string(),
                );
                if !report.stdout.is_empty() {
                    compiled
                        .metadata
                        .insert("compact_compile_stdout".to_string(), report.stdout);
                }
                if !report.stderr.is_empty() {
                    compiled
                        .metadata
                        .insert("compact_compile_stderr".to_string(), report.stderr);
                }
            }
            Err(reason) => {
                compiled
                    .metadata
                    .insert("compact_compile_status".to_string(), "skipped".to_string());
                compiled
                    .metadata
                    .insert("compact_compile_skip_reason".to_string(), reason);
            }
        }

        crate::metal_runtime::append_trust_metadata(
            &mut compiled.metadata,
            "delegated",
            "attestation",
            2,
        );
        Ok(compiled)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        ensure_compiled_backend(self.kind(), compiled)?;
        check_constraints(&compiled.program, witness)?;
        validate_blackbox_constraints(self.kind(), &compiled.program, witness)?;

        let prove_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL").ok();
        let required = proof_server_required();

        match prove_url {
            Some(url) => match prove_with_midnight_proof_server(self.kind(), compiled, witness, &url) {
                Ok(artifact) => Ok(artifact),
                Err(err) if required => Err(err),
                Err(err) if allow_compat_delegate() => {
                    let mut artifact = delegate_prove(self.kind(), compiled, witness)?;
                    artifact.metadata.insert(
                        "proof_server_mode".to_string(),
                        "delegate-fallback".to_string(),
                    );
                    artifact.metadata.insert(
                        "proof_server_fallback_reason".to_string(),
                        err.to_string(),
                    );
                    Ok(artifact)
                }
                Err(err) => Err(err),
            },
            None if required => Err(ZkfError::Backend(
                "midnight native mode requires ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL (set ZKF_MIDNIGHT_PROOF_SERVER_REQUIRED=false and ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE=true to allow delegation)"
                    .to_string(),
            )),
            None if allow_compat_delegate() => {
                let mut artifact = delegate_prove(self.kind(), compiled, witness)?;
                artifact
                    .metadata
                    .insert("proof_server_mode".to_string(), "delegate".to_string());
                Ok(artifact)
            }
            None => Err(ZkfError::Backend(
                "midnight proof server URL is not configured; set ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL or enable compatibility delegate via ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE=true"
                    .to_string(),
            )),
        }
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        ensure_compiled_backend(self.kind(), compiled)?;
        if artifact.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "artifact backend is {}, expected {}",
                artifact.backend,
                self.kind()
            )));
        }

        if artifact.program_digest != compiled.program_digest {
            return Err(ZkfError::ProgramMismatch {
                expected: compiled.program_digest.clone(),
                found: artifact.program_digest.clone(),
            });
        }

        let mode = artifact
            .metadata
            .get("proof_server_mode")
            .map(String::as_str)
            .unwrap_or("unknown");

        if matches!(mode, "delegate" | "delegate-fallback") {
            if allow_compat_delegate() {
                return delegate_verify(self.kind(), compiled, artifact);
            }
            return Err(ZkfError::Backend(
                "artifact was produced via compatibility delegation; set ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE=true to verify delegated artifacts"
                    .to_string(),
            ));
        }

        let verify_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL").ok();
        let required = proof_server_required();
        match verify_url {
            Some(url) => match verify_with_midnight_proof_server(compiled, artifact, &url) {
                Ok(ok) => Ok(ok),
                Err(err) if required => Err(err),
                Err(_) if allow_compat_delegate() => {
                    delegate_verify(self.kind(), compiled, artifact)
                }
                Err(err) => Err(err),
            },
            None if required => Err(ZkfError::Backend(
                "midnight native mode requires ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL".to_string(),
            )),
            None if allow_compat_delegate() => delegate_verify(self.kind(), compiled, artifact),
            None => Err(ZkfError::Backend(
                "midnight verify URL is not configured; set ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL"
                    .to_string(),
            )),
        }
    }

    fn compile_zir(&self, program: &zkf_core::zir_v1::Program) -> ZkfResult<CompiledProgram> {
        use crate::lowering::ZirLowering;
        use crate::lowering::midnight_lowering::MidnightLowering;

        let lowered = MidnightLowering.lower(program)?;
        let v2 = zkf_core::program_zir_to_v2(program)?;
        let mut compiled = self.compile(&v2)?;

        compiled.metadata.insert(
            "compact_source_zir".to_string(),
            lowered.compact_source.clone(),
        );
        compiled.metadata.insert(
            "compact_contract_name".to_string(),
            lowered.contract_name.clone(),
        );
        compiled.metadata.insert(
            "zir_type_map_count".to_string(),
            lowered.type_map.len().to_string(),
        );
        compiled
            .metadata
            .insert("zir_lowered".to_string(), "true".to_string());
        Ok(compiled)
    }
}

fn allow_compat_delegate() -> bool {
    std::env::var("ZKF_MIDNIGHT_ALLOW_COMPAT_DELEGATE")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn proof_server_required() -> bool {
    std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_REQUIRED")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(true)
}

#[derive(Debug)]
struct CompactCompileReport {
    success: bool,
    artifacts_dir: PathBuf,
    stdout: String,
    stderr: String,
}

fn try_compact_compile(
    program_name: &str,
    compact_source: &str,
) -> Result<CompactCompileReport, String> {
    let output = Command::new("compact")
        .arg("--version")
        .output()
        .map_err(|err| format!("compact CLI unavailable: {err}"))?;
    if !output.status.success() {
        return Err("compact CLI returned non-zero exit status for --version".to_string());
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let base = std::env::temp_dir().join("zkf-midnight");
    let workdir = base.join(format!("{program_name}-{nonce}"));
    fs::create_dir_all(&workdir).map_err(|err| format!("{}: {err}", workdir.display()))?;
    let source_path = workdir.join("contract.compact");
    let artifacts_dir = workdir.join("artifacts");
    fs::create_dir_all(&artifacts_dir)
        .map_err(|err| format!("{}: {err}", artifacts_dir.display()))?;
    fs::write(&source_path, compact_source)
        .map_err(|err| format!("{}: {err}", source_path.display()))?;

    let output = Command::new("compact")
        .arg("compile")
        .arg(&source_path)
        .arg(&artifacts_dir)
        .output()
        .map_err(|err| format!("failed to execute `compact compile`: {err}"))?;

    let stdout = truncate_metadata_text(String::from_utf8_lossy(&output.stdout).trim());
    let stderr = truncate_metadata_text(String::from_utf8_lossy(&output.stderr).trim());
    Ok(CompactCompileReport {
        success: output.status.success(),
        artifacts_dir,
        stdout,
        stderr,
    })
}

fn prove_with_midnight_proof_server(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    witness: &Witness,
    prove_url: &str,
) -> ZkfResult<ProofArtifact> {
    let compact_source = compiled
        .metadata
        .get("compact_source")
        .cloned()
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("missing compact_source in compiled metadata".to_string())
        })?;
    let delegated_backend_hint = compiled
        .metadata
        .get("delegated_backend_hint")
        .map(String::as_str);

    // Serialize the witness into the BTreeMap<String, String> format expected by ProveRequest.
    let witness_map: BTreeMap<String, String> = witness
        .values
        .iter()
        .map(|(k, v)| (k.clone(), v.to_decimal_string()))
        .collect();

    // Build a one-shot client (no retries) so that the surrounding
    // BackendEngine::prove() error-handling path stays in control of
    // retry / fallback decisions.  Auth token and timeout come from the
    // environment when set.
    let auth_token = std::env::var("ZKF_MIDNIGHT_AUTH_TOKEN").ok();
    let timeout_ms = std::env::var("ZKF_MIDNIGHT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30_000);
    let verify_url = prove_url.replace("/prove", "/verify");
    let mut client = MidnightClient::new(prove_url.to_string(), verify_url)
        .with_timeout(timeout_ms)
        .with_max_retries(0);
    if let Some(ref token) = auth_token {
        client = client.with_auth(token.clone());
    }

    let request = ProveRequest {
        api_version: crate::midnight_client::MIDNIGHT_API_VERSION.to_string(),
        program_digest: compiled.program_digest.clone(),
        compact_source,
        witness: witness_map,
        network_id: None,
        contract_address: None,
        auth_token,
    };

    let response = client.prove(&request)?;

    if !response.ok {
        return Err(ZkfError::Backend(format!(
            "midnight proof server prove request failed: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        )));
    }

    let proof_b64 = response
        .proof_b64
        .ok_or_else(|| ZkfError::InvalidArtifact("prove response missing proof_b64".to_string()))?;
    let vk_b64 = response
        .vk_b64
        .ok_or_else(|| ZkfError::InvalidArtifact("prove response missing vk_b64".to_string()))?;

    let proof = base64::engine::general_purpose::STANDARD
        .decode(proof_b64.as_bytes())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid prove response proof_b64: {err}"))
        })?;
    let verification_key = base64::engine::general_purpose::STANDARD
        .decode(vk_b64.as_bytes())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid prove response vk_b64: {err}"))
        })?;

    let public_inputs = response
        .public_inputs
        .unwrap_or_default()
        .into_iter()
        .map(FieldElement::new)
        .collect::<Vec<_>>();

    let mut metadata = response.metadata.unwrap_or_default();
    metadata.insert("proof_server_mode".to_string(), "remote".to_string());
    metadata.insert("proof_server_url".to_string(), prove_url.to_string());
    metadata.insert(
        "wrapper_backend".to_string(),
        wrapper_kind.as_str().to_string(),
    );
    if let Some(delegate) = delegated_backend_hint {
        metadata.insert("delegated_backend_hint".to_string(), delegate.to_string());
    }
    append_backend_runtime_metadata(&mut metadata, wrapper_kind);

    Ok(ProofArtifact {
        backend: wrapper_kind,
        program_digest: compiled.program_digest.clone(),
        proof,
        verification_key,
        public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    })
}

fn verify_with_midnight_proof_server(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
    verify_url: &str,
) -> ZkfResult<bool> {
    let public_inputs_map: BTreeMap<String, String> = artifact
        .public_inputs
        .iter()
        .enumerate()
        .map(|(i, v)| (i.to_string(), v.to_decimal_string()))
        .collect();

    // Build a one-shot client (no retries) — same rationale as prove path.
    let auth_token = std::env::var("ZKF_MIDNIGHT_AUTH_TOKEN").ok();
    let timeout_ms = std::env::var("ZKF_MIDNIGHT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30_000);
    let prove_url = verify_url.replace("/verify", "/prove");
    let mut client = MidnightClient::new(prove_url, verify_url.to_string())
        .with_timeout(timeout_ms)
        .with_max_retries(0);
    if let Some(ref token) = auth_token {
        client = client.with_auth(token.clone());
    }

    let request = VerifyRequest {
        api_version: crate::midnight_client::MIDNIGHT_API_VERSION.to_string(),
        program_digest: compiled.program_digest.clone(),
        proof_b64: base64::engine::general_purpose::STANDARD.encode(&artifact.proof),
        vk_b64: base64::engine::general_purpose::STANDARD.encode(&artifact.verification_key),
        public_inputs: public_inputs_map,
        network_id: None,
        auth_token,
    };

    let response = client.verify(&request)?;
    Ok(response.ok)
}

fn truncate_metadata_text(text: impl AsRef<str>) -> String {
    const MAX: usize = 512;
    let trimmed = text.as_ref().trim();
    if trimmed.len() <= MAX {
        trimmed.to_string()
    } else {
        format!("{}...<truncated>", &trimmed[..MAX])
    }
}

fn midnight_delegate_backend_for_field(field: FieldId) -> ZkfResult<BackendKind> {
    match field {
        FieldId::PastaFp => Ok(BackendKind::Halo2),
        FieldId::Bn254 => Ok(BackendKind::ArkworksGroth16),
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => Ok(BackendKind::Plonky3),
        other => Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::MidnightCompact.to_string(),
            message: format!("midnight has no delegate backend for field {other}"),
        }),
    }
}

fn delegate_prove(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    witness: &Witness,
) -> ZkfResult<ProofArtifact> {
    let delegated_kind = midnight_delegate_backend_for_field(compiled.program.field)?;
    let delegated_engine = backend_for(delegated_kind);
    let delegated_compiled = delegated_engine.compile(&compiled.program)?;
    let delegated_artifact = delegated_engine.prove(&delegated_compiled, witness)?;

    let mut metadata = delegated_artifact.metadata.clone();
    metadata.insert(
        "delegated_backend".to_string(),
        delegated_kind.as_str().to_string(),
    );
    metadata.insert(
        "wrapper_backend".to_string(),
        wrapper_kind.as_str().to_string(),
    );
    append_backend_runtime_metadata(&mut metadata, wrapper_kind);

    Ok(ProofArtifact {
        backend: wrapper_kind,
        program_digest: delegated_artifact.program_digest,
        proof: delegated_artifact.proof,
        verification_key: delegated_artifact.verification_key,
        public_inputs: delegated_artifact.public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    })
}

fn delegate_verify(
    _wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> ZkfResult<bool> {
    let delegated_kind = midnight_delegate_backend_for_field(compiled.program.field)?;
    let delegated_engine = backend_for(delegated_kind);
    let delegated_compiled = delegated_engine.compile(&compiled.program)?;

    let delegated_artifact = ProofArtifact {
        backend: delegated_kind,
        program_digest: artifact.program_digest.clone(),
        proof: artifact.proof.clone(),
        verification_key: artifact.verification_key.clone(),
        public_inputs: artifact.public_inputs.clone(),
        metadata: artifact.metadata.clone(),
        security_profile: artifact.security_profile,
        hybrid_bundle: artifact.hybrid_bundle.clone(),
        credential_bundle: artifact.credential_bundle.clone(),
        archive_metadata: artifact.archive_metadata.clone(),
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    delegated_engine.verify(&delegated_compiled, &delegated_artifact)
}

fn ensure_compiled_backend(expected: BackendKind, compiled: &CompiledProgram) -> ZkfResult<()> {
    if compiled.backend != expected {
        return Err(ZkfError::InvalidArtifact(format!(
            "compiled backend is {}, expected {}",
            compiled.backend, expected
        )));
    }
    Ok(())
}
