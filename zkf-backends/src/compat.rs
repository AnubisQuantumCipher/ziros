//! Compatibility-mode backends that delegate proving to native backends.
//!
//! These backends implement `BackendEngine` by delegating compile/prove/verify
//! to a real native backend (e.g., Plonky3, Arkworks Groth16, or Halo2).
//! They are used when native feature flags (e.g., `native-sp1`, `native-nova`)
//! are not enabled, or for backends that don't yet have native implementations.
//!
//! Each compat backend:
//! - Serializes the delegated `CompiledProgram` into `compiled_data`
//! - On prove/verify, deserializes and calls the delegated backend
//! - Tags metadata with `"mode": "compatibility-delegate"` and `"delegated_backend"`

#![allow(dead_code)]

#[cfg(not(target_arch = "wasm32"))]
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::{BackendEngine, backend_for, midnight};
#[cfg(not(target_arch = "wasm32"))]
use base64::Engine;
#[cfg(not(target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::process::Command;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(not(target_arch = "wasm32"))]
use zkf_core::FieldElement;
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldId, Program,
    ProofArtifact, ToolRequirement, Witness, ZkfError, ZkfResult,
};

pub struct Sp1Backend;
pub struct NovaBackend;
pub struct MidnightCompactBackend;
#[cfg(target_arch = "wasm32")]
pub struct WasmUnavailableBackend {
    kind: BackendKind,
}

#[cfg(target_arch = "wasm32")]
impl WasmUnavailableBackend {
    pub fn new(kind: BackendKind) -> Self {
        Self { kind }
    }
}

#[cfg(target_arch = "wasm32")]
impl BackendEngine for WasmUnavailableBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: self.kind,
            mode: BackendMode::Compat,
            trusted_setup: false,
            recursion_ready: false,
            transparent_setup: false,
            zkvm_mode: matches!(self.kind, BackendKind::Sp1),
            network_target: matches!(self.kind, BackendKind::MidnightCompact)
                .then_some("midnight".to_string()),
            supported_blackbox_ops: Vec::new(),
            supported_constraint_kinds: Vec::new(),
            native_profiles: Vec::new(),
            notes: "WASM build: backend proving engines are disabled; use host-native build for compile/prove/verify."
                .to_string(),
        }
    }

    fn compile(&self, _program: &Program) -> ZkfResult<CompiledProgram> {
        Err(ZkfError::UnsupportedBackend {
            backend: self.kind.to_string(),
            message: "backend engines are unavailable on wasm32 build; run zkf in host-native mode"
                .to_string(),
        })
    }

    fn prove(&self, _compiled: &CompiledProgram, _witness: &Witness) -> ZkfResult<ProofArtifact> {
        Err(ZkfError::UnsupportedBackend {
            backend: self.kind.to_string(),
            message: "backend engines are unavailable on wasm32 build; run zkf in host-native mode"
                .to_string(),
        })
    }

    fn verify(&self, _compiled: &CompiledProgram, _artifact: &ProofArtifact) -> ZkfResult<bool> {
        Err(ZkfError::UnsupportedBackend {
            backend: self.kind.to_string(),
            message: "backend engines are unavailable on wasm32 build; run zkf in host-native mode"
                .to_string(),
        })
    }
}

impl BackendEngine for Sp1Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::Sp1
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Sp1,
            mode: BackendMode::Compat,
            trusted_setup: false,
            recursion_ready: true,
            transparent_setup: true,
            zkvm_mode: true,
            network_target: None,
            supported_blackbox_ops: Vec::new(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["compat-delegate-plonky3".to_string()],
            notes: "SP1 compatibility mode: delegates proof generation to plonky3 backend for Goldilocks programs."
                .to_string(),
        }
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "cargo".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Required to build Rust guest binaries".to_string()),
                required: true,
            },
            ToolRequirement {
                tool: "sp1up".to_string(),
                args: vec!["--version".to_string()],
                note: Some("SP1 toolchain manager (optional in compatibility mode)".to_string()),
                required: false,
            },
        ]
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        if program.field != FieldId::Goldilocks {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message:
                    "sp1 compatibility mode currently supports Goldilocks programs only (delegates to plonky3)"
                        .to_string(),
            });
        }
        delegate_compile(self.kind(), program, BackendKind::Plonky3)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        delegate_prove(self.kind(), compiled, witness)
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        delegate_verify(self.kind(), compiled, artifact)
    }
}

impl BackendEngine for NovaBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Nova
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Nova,
            mode: BackendMode::Compat,
            trusted_setup: true,
            recursion_ready: true,
            transparent_setup: false,
            zkvm_mode: false,
            network_target: None,
            supported_blackbox_ops: Vec::new(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["compat-delegate-arkworks".to_string()],
            notes: "Nova compatibility mode: delegates to arkworks-groth16 for BN254 programs."
                .to_string(),
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        if program.field != FieldId::Bn254 {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message:
                    "nova compatibility mode currently supports BN254 programs only (delegates to arkworks-groth16)"
                        .to_string(),
            });
        }
        delegate_compile(self.kind(), program, BackendKind::ArkworksGroth16)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        delegate_prove(self.kind(), compiled, witness)
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        delegate_verify(self.kind(), compiled, artifact)
    }
}

impl BackendEngine for MidnightCompactBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::MidnightCompact
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::MidnightCompact,
            mode: BackendMode::Compat,
            trusted_setup: false,
            recursion_ready: false,
            transparent_setup: true,
            zkvm_mode: false,
            network_target: Some("midnight".to_string()),
            supported_blackbox_ops: Vec::new(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["compat-delegate-field-aware".to_string()],
            notes: "Midnight compatibility mode: emits Compact source and delegates proving to a local backend by field."
                .to_string(),
        }
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "compact".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Compact compiler/runtime CLI for Midnight integration".to_string()),
                required: false,
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
        let delegated = midnight_delegate_backend_for_field(program.field)?;
        let mut compiled = delegate_compile(self.kind(), program, delegated)?;
        let compact_source = midnight::emit_compact(program);
        compiled
            .metadata
            .insert("compact_source".to_string(), compact_source.clone());
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
        Ok(compiled)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let prove_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_PROVE_URL").ok();
            let remote_required = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_REQUIRED")
                .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
                .unwrap_or(false);
            if let Some(url) = prove_url {
                match prove_with_midnight_proof_server(self.kind(), compiled, witness, &url) {
                    Ok(artifact) => return Ok(artifact),
                    Err(err) if remote_required => return Err(err),
                    Err(err) => {
                        let mut artifact = delegate_prove(self.kind(), compiled, witness)?;
                        artifact
                            .metadata
                            .insert("proof_server_fallback_reason".to_string(), err.to_string());
                        artifact.metadata.insert(
                            "proof_server_mode".to_string(),
                            "delegate-fallback".to_string(),
                        );
                        return Ok(artifact);
                    }
                }
            }
        }

        let mut artifact = delegate_prove(self.kind(), compiled, witness)?;
        artifact
            .metadata
            .insert("proof_server_mode".to_string(), "delegate".to_string());
        Ok(artifact)
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let verify_url = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_VERIFY_URL").ok();
            let remote_required = std::env::var("ZKF_MIDNIGHT_PROOF_SERVER_REQUIRED")
                .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
                .unwrap_or(false);

            if let Some(url) = verify_url {
                match verify_with_midnight_proof_server(compiled, artifact, &url) {
                    Ok(ok) => return Ok(ok),
                    Err(err) if remote_required => return Err(err),
                    Err(_) => {}
                }
            }
        }

        delegate_verify(self.kind(), compiled, artifact)
    }
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
    #[cfg(target_arch = "wasm32")]
    {
        let _ = program_name;
        let _ = compact_source;
        return Err("compact compile is unavailable on wasm32 target".to_string());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
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
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Serialize)]
struct MidnightProveRequest<'a> {
    program_digest: &'a str,
    field: &'a str,
    delegated_backend: &'a str,
    compact_source: &'a str,
    witness: &'a Witness,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct MidnightProveResponse {
    proof_base64: String,
    verification_key_base64: String,
    public_inputs: Vec<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[cfg(not(target_arch = "wasm32"))]
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
    let delegated_backend = compiled
        .metadata
        .get("delegated_backend")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let request = MidnightProveRequest {
        program_digest: &compiled.program_digest,
        field: compiled.program.field.as_str(),
        delegated_backend: &delegated_backend,
        compact_source: &compact_source,
        witness,
    };

    let response = ureq::post(prove_url)
        .send_json(
            serde_json::to_value(&request)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?,
        )
        .map_err(|err| {
            ZkfError::Backend(format!("midnight proof server prove request failed: {err}"))
        })?;
    let body: MidnightProveResponse = response.into_json().map_err(|err| {
        ZkfError::InvalidArtifact(format!("invalid midnight prove response JSON: {err}"))
    })?;

    let proof = base64::engine::general_purpose::STANDARD
        .decode(body.proof_base64.as_bytes())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid prove response proof_base64: {err}"))
        })?;
    let verification_key = base64::engine::general_purpose::STANDARD
        .decode(body.verification_key_base64.as_bytes())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "invalid prove response verification_key_base64: {err}"
            ))
        })?;
    let public_inputs = body
        .public_inputs
        .into_iter()
        .map(FieldElement::new)
        .collect::<Vec<_>>();

    let mut metadata = body.metadata;
    metadata.insert("proof_server_mode".to_string(), "remote".to_string());
    metadata.insert("proof_server_url".to_string(), prove_url.to_string());
    metadata.insert(
        "wrapper_backend".to_string(),
        wrapper_kind.as_str().to_string(),
    );
    metadata.insert("delegated_backend".to_string(), delegated_backend);
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
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Serialize)]
struct MidnightVerifyRequest<'a> {
    program_digest: &'a str,
    proof_base64: String,
    verification_key_base64: String,
    public_inputs: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct MidnightVerifyResponse {
    ok: bool,
}

#[cfg(not(target_arch = "wasm32"))]
fn verify_with_midnight_proof_server(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
    verify_url: &str,
) -> ZkfResult<bool> {
    let request = MidnightVerifyRequest {
        program_digest: &compiled.program_digest,
        proof_base64: base64::engine::general_purpose::STANDARD.encode(&artifact.proof),
        verification_key_base64: base64::engine::general_purpose::STANDARD
            .encode(&artifact.verification_key),
        public_inputs: artifact
            .public_inputs
            .iter()
            .map(|value| value.to_decimal_string())
            .collect(),
    };

    let response = ureq::post(verify_url)
        .send_json(
            serde_json::to_value(&request)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?,
        )
        .map_err(|err| {
            ZkfError::Backend(format!(
                "midnight proof server verify request failed: {err}"
            ))
        })?;
    let body: MidnightVerifyResponse = response.into_json().map_err(|err| {
        ZkfError::InvalidArtifact(format!("invalid midnight verify response JSON: {err}"))
    })?;
    Ok(body.ok)
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
        FieldId::Goldilocks => Ok(BackendKind::Plonky3),
        other => Err(ZkfError::UnsupportedBackend {
            backend: BackendKind::MidnightCompact.to_string(),
            message: format!(
                "midnight compatibility mode has no delegate backend for field {other}"
            ),
        }),
    }
}

fn delegate_compile(
    wrapper_kind: BackendKind,
    program: &Program,
    delegated_kind: BackendKind,
) -> ZkfResult<CompiledProgram> {
    let delegated_engine = backend_for(delegated_kind);
    let delegated = delegated_engine.compile(program)?;
    let delegated_bytes =
        serde_json::to_vec(&delegated).map_err(|err| ZkfError::Serialization(err.to_string()))?;

    let mut compiled = CompiledProgram::new(wrapper_kind, program.clone());
    compiled.compiled_data = Some(delegated_bytes);
    compiled.metadata.insert(
        "delegated_backend".to_string(),
        delegated_kind.as_str().to_string(),
    );
    compiled
        .metadata
        .insert("mode".to_string(), "compatibility-delegate".to_string());
    Ok(compiled)
}

fn delegate_prove(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    witness: &Witness,
) -> ZkfResult<ProofArtifact> {
    if compiled.backend != wrapper_kind {
        return Err(ZkfError::InvalidArtifact(format!(
            "compiled backend is {}, expected {}",
            compiled.backend, wrapper_kind
        )));
    }

    let delegated = load_delegated_compiled(compiled)?;
    let delegated_kind = delegated.backend;
    let delegated_engine = backend_for(delegated_kind);
    let delegated_artifact = delegated_engine.prove(&delegated, witness)?;

    let mut metadata = delegated_artifact.metadata.clone();
    metadata.insert(
        "delegated_backend".to_string(),
        delegated_kind.as_str().to_string(),
    );
    metadata.insert(
        "wrapper_backend".to_string(),
        wrapper_kind.as_str().to_string(),
    );
    metadata.insert("mode".to_string(), "compatibility-delegate".to_string());
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
    })
}

fn delegate_verify(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> ZkfResult<bool> {
    if compiled.backend != wrapper_kind {
        return Err(ZkfError::InvalidArtifact(format!(
            "compiled backend is {}, expected {}",
            compiled.backend, wrapper_kind
        )));
    }
    if artifact.backend != wrapper_kind {
        return Err(ZkfError::InvalidArtifact(format!(
            "artifact backend is {}, expected {}",
            artifact.backend, wrapper_kind
        )));
    }

    let delegated = load_delegated_compiled(compiled)?;
    let delegated_kind = delegated.backend;
    let delegated_engine = backend_for(delegated_kind);
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
    };
    delegated_engine.verify(&delegated, &delegated_artifact)
}

fn load_delegated_compiled(compiled: &CompiledProgram) -> ZkfResult<CompiledProgram> {
    let bytes = compiled
        .compiled_data
        .as_deref()
        .ok_or(ZkfError::MissingCompiledData)?;
    serde_json::from_slice(bytes).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to decode delegated compiled artifact: {err}"
        ))
    })
}
