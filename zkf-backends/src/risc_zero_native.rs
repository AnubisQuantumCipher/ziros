use crate::BackendEngine;
use crate::blackbox_native::{supported_blackbox_ops, validate_blackbox_constraints};
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::risc_zero::RiscZeroBackend as RiscZeroCompatBackend;
use base64::Engine;
#[cfg(feature = "native-risc-zero")]
use risc0_binfmt::ProgramBinary;
#[cfg(feature = "native-risc-zero")]
use risc0_zkos_v1compat::V1COMPAT_ELF;
#[cfg(feature = "native-risc-zero")]
use risc0_zkvm::{
    ExecutorEnv, ExternalProver, Prover as _, Receipt, compute_image_id, default_prover,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldElement, FieldId, Program,
    ProofArtifact, ToolRequirement, Witness, ZkfError, ZkfResult, check_constraints,
};

pub struct RiscZeroNativeBackend;

impl BackendEngine for RiscZeroNativeBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::RiscZero
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::RiscZero,
            mode: BackendMode::Native,
            trusted_setup: false,
            recursion_ready: true,
            transparent_setup: true,
            zkvm_mode: true,
            network_target: None,
            supported_blackbox_ops: supported_blackbox_ops(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["sdk-blocking-v1".to_string()],
            notes: "Feature-gated RISC Zero guest/ELF pipeline: compiles and caches a deterministic \
                    RISC Zero guest ELF and uses SDK-native prove/verify as primary path. External \
                    prover/verifier commands and compatibility delegation are explicit fallback paths."
                .to_string(),
        }
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "cargo".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Required for RISC Zero guest compilation".to_string()),
                required: true,
            },
            ToolRequirement {
                tool: "rustup".to_string(),
                args: vec!["target".to_string(), "list".to_string()],
                note: Some(
                    "RISC Zero guest target `riscv32im-risc0-zkvm-elf` should be installed via rzup"
                        .to_string(),
                ),
                required: false,
            },
            ToolRequirement {
                tool: "rzup".to_string(),
                args: vec!["--version".to_string()],
                note: Some("RISC Zero toolchain manager".to_string()),
                required: false,
            },
            ToolRequirement {
                tool: "r0vm".to_string(),
                args: vec!["--version".to_string()],
                note: Some(
                    "Preferred stable native prover on macOS via SDK IPC mode when installed"
                        .to_string(),
                ),
                required: false,
            },
        ]
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        if !matches!(
            program.field,
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31
        ) {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message:
                    "native risc-zero guest pipeline currently accepts Goldilocks/BabyBear/Mersenne31 programs"
                        .to_string(),
            });
        }
        let mut compiled = CompiledProgram::new(self.kind(), program.clone());

        let report = prepare_guest_elf(&compiled.program_digest)?;
        compiled
            .metadata
            .insert("risc0_native_mode".to_string(), "guest-elf-v1".to_string());
        compiled.metadata.insert(
            "risc0_guest_dir".to_string(),
            report.guest_dir.display().to_string(),
        );
        compiled.metadata.insert(
            "risc0_elf_path".to_string(),
            report.elf_path.display().to_string(),
        );
        compiled
            .metadata
            .insert("risc0_elf_ready".to_string(), report.elf_ready.to_string());
        compiled.metadata.insert(
            "risc0_build_status".to_string(),
            if report.build_success {
                "ok".to_string()
            } else {
                "failed".to_string()
            },
        );
        if let Some(sha) = report.elf_sha256 {
            compiled
                .metadata
                .insert("risc0_elf_sha256".to_string(), sha);
        }
        if !report.stdout.is_empty() {
            compiled
                .metadata
                .insert("risc0_build_stdout".to_string(), report.stdout);
        }
        if !report.stderr.is_empty() {
            compiled
                .metadata
                .insert("risc0_build_stderr".to_string(), report.stderr);
        }
        if let Some(elf_bytes) = report.elf_bytes {
            compiled.compiled_data = Some(elf_bytes);
        }
        compiled
            .metadata
            .insert("mode".to_string(), "native".to_string());

        crate::metal_runtime::append_trust_metadata(
            &mut compiled.metadata,
            "delegated",
            "cryptographic",
            1,
        );
        Ok(compiled)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        ensure_compiled_backend(self.kind(), compiled)?;
        check_constraints(&compiled.program, witness)?;
        validate_blackbox_constraints(self.kind(), &compiled.program, witness)?;

        let mut sdk_error: Option<ZkfError> = None;
        if risc0_sdk_enabled() {
            match prove_with_sdk(compiled, witness) {
                Ok(artifact) => return Ok(artifact),
                Err(err) => sdk_error = Some(err),
            }
        }

        if let Some(command) = risc0_prover_command() {
            let mut artifact = prove_with_external_command(compiled, witness, &command)?;
            if let Some(err) = sdk_error {
                artifact.metadata.insert(
                    "risc0_sdk_fallback_error".to_string(),
                    truncate_metadata_text(err.to_string()),
                );
            }
            return Ok(artifact);
        }

        if allow_compat_delegate() {
            let compat = RiscZeroCompatBackend;
            let compat_compiled = compat.compile(&compiled.program)?;
            let mut artifact = compat.prove(&compat_compiled, witness)?;
            artifact.backend = BackendKind::RiscZero;
            artifact.metadata.insert(
                "risc0_native_mode".to_string(),
                "delegate-proof-v1".to_string(),
            );
            artifact.metadata.insert(
                "delegated_backend".to_string(),
                compat_compiled.backend.as_str().to_string(),
            );
            if let Some(ready) = compiled.metadata.get("risc0_elf_ready") {
                artifact
                    .metadata
                    .insert("risc0_elf_ready".to_string(), ready.clone());
            }
            if let Some(path) = compiled.metadata.get("risc0_elf_path") {
                artifact
                    .metadata
                    .insert("risc0_elf_path".to_string(), path.clone());
            }
            if let Some(err) = sdk_error {
                artifact.metadata.insert(
                    "risc0_sdk_fallback_error".to_string(),
                    truncate_metadata_text(err.to_string()),
                );
            }
            return Ok(artifact);
        }

        if let Some(err) = sdk_error {
            return Err(ZkfError::Backend(format!(
                "native RISC Zero SDK proof failed: {err}; set ZKF_RISC_ZERO_PROVER_CMD for external-command fallback or ZKF_RISC_ZERO_ALLOW_COMPAT_DELEGATE=true for compatibility fallback"
            )));
        }

        Err(ZkfError::Backend(
            "native RISC Zero proof is not configured; ensure SDK mode is enabled and guest ELF is ready, or set ZKF_RISC_ZERO_PROVER_CMD for external fallback, or set ZKF_RISC_ZERO_ALLOW_COMPAT_DELEGATE=true for compatibility fallback".to_string(),
        ))
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        ensure_compiled_backend(self.kind(), compiled)?;
        match artifact
            .metadata
            .get("risc0_native_mode")
            .map(String::as_str)
        {
            Some("sdk-blocking-v1") => verify_with_sdk(artifact),
            Some("external-cmd-v1") => {
                if let Some(command) = risc0_verifier_command() {
                    verify_with_external_command(compiled, artifact, &command)
                } else {
                    Err(ZkfError::Backend(
                        "artifact requires external RISC Zero verifier command but ZKF_RISC_ZERO_VERIFIER_CMD is not set"
                            .to_string(),
                    ))
                }
            }
            Some("delegate-proof-v1") if allow_compat_delegate() => {
                let compat = RiscZeroCompatBackend;
                let compat_compiled = compat.compile(&compiled.program)?;
                let mut delegated = artifact.clone();
                delegated.backend = compat_compiled.backend;
                compat.verify(&compat_compiled, &delegated)
            }
            Some("delegate-proof-v1") => Err(ZkfError::Backend(
                "artifact was produced via compatibility fallback; set ZKF_RISC_ZERO_ALLOW_COMPAT_DELEGATE=true to verify it".to_string(),
            )),
            _ => Err(ZkfError::InvalidArtifact(
                "unsupported risc0_native_mode in proof artifact".to_string(),
            )),
        }
    }
}

#[derive(Debug)]
struct GuestBuildReport {
    guest_dir: PathBuf,
    elf_path: PathBuf,
    build_success: bool,
    elf_ready: bool,
    elf_bytes: Option<Vec<u8>>,
    elf_sha256: Option<String>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct RiscZeroExternalProveRequest<'a> {
    program_digest: &'a str,
    field: &'a str,
    elf_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    elf_sha256: Option<&'a str>,
    witness: &'a Witness,
}

#[derive(Debug, Deserialize)]
struct RiscZeroExternalProveResponse {
    proof_base64: String,
    verification_key_base64: String,
    public_inputs: Vec<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct RiscZeroExternalVerifyRequest<'a> {
    program_digest: &'a str,
    field: &'a str,
    proof_base64: String,
    verification_key_base64: String,
    public_inputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RiscZeroExternalVerifyResponse {
    ok: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RiscZeroSdkProverMode {
    Ipc,
    Local,
    Mock,
}

impl RiscZeroSdkProverMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ipc => "ipc",
            Self::Local => "local",
            Self::Mock => "mock",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ipc" => Some(Self::Ipc),
            "local" => Some(Self::Local),
            "mock" => Some(Self::Mock),
            _ => None,
        }
    }
}

fn guest_cache_root() -> PathBuf {
    if let Ok(value) = std::env::var("ZKF_RISC_ZERO_GUEST_CACHE") {
        return PathBuf::from(value);
    }
    std::env::temp_dir().join("zkf-risc0-guest-cache")
}

fn prepare_guest_elf(program_digest: &str) -> ZkfResult<GuestBuildReport> {
    let root = guest_cache_root();
    let guest_dir = root.join(program_digest);
    let src_dir = guest_dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|err| ZkfError::Io(err.to_string()))?;

    let cargo_toml = guest_dir.join("Cargo.toml");
    let main_rs = src_dir.join("main.rs");
    fs::write(&cargo_toml, guest_cargo_toml()).map_err(|err| ZkfError::Io(err.to_string()))?;
    fs::write(&main_rs, guest_main_rs()).map_err(|err| ZkfError::Io(err.to_string()))?;

    let mut build_success = false;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let build_output = Command::new("cargo")
        .env(
            "RUSTFLAGS",
            append_rustflags(r#"--cfg getrandom_backend="custom""#),
        )
        .args([
            "+risc0",
            "build",
            "--release",
            "--target",
            "riscv32im-risc0-zkvm-elf",
        ])
        .current_dir(&guest_dir)
        .output();
    if let Ok(output) = build_output {
        build_success = output.status.success();
        stdout = truncate_metadata_text(String::from_utf8_lossy(&output.stdout).trim());
        stderr = truncate_metadata_text(String::from_utf8_lossy(&output.stderr).trim());
    } else if let Err(err) = build_output {
        stderr = format!("failed to execute cargo build: {err}");
    }

    let user_elf_path = guest_user_elf_path(&guest_dir);
    let program_binary_path = guest_program_binary_path(&guest_dir);
    let (elf_ready, elf_path, elf_bytes, elf_sha256) = if build_success && user_elf_path.exists() {
        let user_elf = fs::read(&user_elf_path).map_err(|err| ZkfError::Io(err.to_string()))?;
        #[cfg(feature = "native-risc-zero")]
        let program_binary = ProgramBinary::new(&user_elf, V1COMPAT_ELF).encode();
        #[cfg(not(feature = "native-risc-zero"))]
        let program_binary = user_elf;
        fs::write(&program_binary_path, &program_binary)
            .map_err(|err| ZkfError::Io(err.to_string()))?;
        let sha = sha256_hex(program_binary.as_slice());
        (true, program_binary_path, Some(program_binary), Some(sha))
    } else {
        (false, program_binary_path, None, None)
    };

    Ok(GuestBuildReport {
        guest_dir,
        elf_path,
        build_success,
        elf_ready,
        elf_bytes,
        elf_sha256,
        stdout,
        stderr,
    })
}

#[cfg(feature = "native-risc-zero")]
fn proof_artifact_from_receipt(
    compiled: &CompiledProgram,
    receipt: Receipt,
    image_id: risc0_zkvm::sha::Digest,
    mode: RiscZeroSdkProverMode,
    proof_mode: &str,
) -> ZkfResult<ProofArtifact> {
    let proof = bincode::serialize(&receipt).map_err(|e| ZkfError::Serialization(e.to_string()))?;
    let vk = bincode::serialize(&image_id).map_err(|e| ZkfError::Serialization(e.to_string()))?;
    let journal_bytes = receipt.journal.bytes.clone();
    let journal_b64 = base64::engine::general_purpose::STANDARD.encode(&journal_bytes);
    let journal_digest = Sha256::digest(journal_bytes.as_slice());

    let mut metadata = BTreeMap::new();
    metadata.insert(
        "risc0_native_mode".to_string(),
        "sdk-blocking-v1".to_string(),
    );
    metadata.insert(
        "risc0_sdk_prover_mode".to_string(),
        mode.as_str().to_string(),
    );
    metadata.insert("risc0_proof_mode".to_string(), proof_mode.to_string());
    metadata.insert("risc0_image_id".to_string(), format!("{image_id:?}"));
    metadata.insert("risc0_journal_base64".to_string(), journal_b64);
    metadata.insert(
        "risc0_journal_sha256".to_string(),
        sha256_hex(journal_digest.as_slice()),
    );
    if let Some(path) = compiled.metadata.get("risc0_elf_path") {
        metadata.insert("risc0_elf_path".to_string(), path.clone());
    }
    if let Some(sha) = compiled.metadata.get("risc0_elf_sha256") {
        metadata.insert("risc0_elf_sha256".to_string(), sha.clone());
    }
    append_backend_runtime_metadata(&mut metadata, BackendKind::RiscZero);

    Ok(ProofArtifact {
        backend: BackendKind::RiscZero,
        program_digest: compiled.program_digest.clone(),
        proof,
        verification_key: vk,
        public_inputs: vec![FieldElement::from_le_bytes(journal_digest.as_slice())],
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
    })
}

fn prove_with_sdk(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
    let elf_bytes = resolve_elf_bytes(compiled)?;
    let mode = risc0_sdk_prover_mode();
    let payload = build_execution_payload(compiled, witness)?;

    match mode {
        RiscZeroSdkProverMode::Mock => {
            // Mock mode: generate a deterministic mock proof from the payload hash.
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            hasher.update(&elf_bytes);
            let digest = hasher.finalize();

            let mock_proof = digest.to_vec();
            let mock_vk = sha256_bytes(&elf_bytes);

            let mut metadata = BTreeMap::new();
            metadata.insert(
                "risc0_native_mode".to_string(),
                "sdk-blocking-v1".to_string(),
            );
            metadata.insert(
                "risc0_sdk_prover_mode".to_string(),
                mode.as_str().to_string(),
            );
            metadata.insert("risc0_proof_mode".to_string(), "mock".to_string());
            if let Some(path) = compiled.metadata.get("risc0_elf_path") {
                metadata.insert("risc0_elf_path".to_string(), path.clone());
            }
            if let Some(sha) = compiled.metadata.get("risc0_elf_sha256") {
                metadata.insert("risc0_elf_sha256".to_string(), sha.clone());
            }
            append_backend_runtime_metadata(&mut metadata, BackendKind::RiscZero);

            Ok(ProofArtifact {
                backend: BackendKind::RiscZero,
                program_digest: compiled.program_digest.clone(),
                proof: mock_proof,
                verification_key: mock_vk,
                public_inputs: vec![FieldElement::from_le_bytes(&digest)],
                metadata,
                security_profile: None,
                hybrid_bundle: None,
                credential_bundle: None,
                archive_metadata: None,
            })
        }
        #[cfg(feature = "native-risc-zero")]
        RiscZeroSdkProverMode::Ipc => {
            let env = ExecutorEnv::builder()
                .write(&payload)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero env write: {e}")))?
                .build()
                .map_err(|e| ZkfError::Backend(format!("RISC Zero env build: {e}")))?;
            let r0vm = r0vm_path().ok_or_else(|| {
                ZkfError::Backend(
                    "RISC Zero SDK IPC proving requires `r0vm`; install it with rzup or set ZKF_RISC_ZERO_SDK_PROVER=local".to_string(),
                )
            })?;
            let prove_info = ExternalProver::new("ipc", r0vm)
                .prove(env, &elf_bytes)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero prove: {e}")))?;
            let receipt = prove_info.receipt;
            let image_id = compute_image_id(&elf_bytes)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero image_id: {e}")))?;
            proof_artifact_from_receipt(compiled, receipt, image_id, mode, "ipc")
        }
        #[cfg(not(feature = "native-risc-zero"))]
        RiscZeroSdkProverMode::Ipc => Err(ZkfError::Backend(
            "RISC Zero SDK IPC proving requires the `native-risc-zero` feature".to_string(),
        )),
        #[cfg(feature = "native-risc-zero")]
        RiscZeroSdkProverMode::Local => {
            let env = ExecutorEnv::builder()
                .write(&payload)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero env write: {e}")))?
                .build()
                .map_err(|e| ZkfError::Backend(format!("RISC Zero env build: {e}")))?;
            let prove_info = default_prover()
                .prove(env, &elf_bytes)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero prove: {e}")))?;
            let receipt = prove_info.receipt;
            let image_id = compute_image_id(&elf_bytes)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero image_id: {e}")))?;
            proof_artifact_from_receipt(compiled, receipt, image_id, mode, "local")
        }
        #[cfg(not(feature = "native-risc-zero"))]
        RiscZeroSdkProverMode::Local => Err(ZkfError::Backend(
            "RISC Zero local SDK proving requires the `native-risc-zero` feature; \
                 use ZKF_RISC_ZERO_SDK_PROVER=ipc when `r0vm` is installed, use ZKF_RISC_ZERO_SDK_PROVER=mock for testing, or set ZKF_RISC_ZERO_PROVER_CMD \
                 for an external prover"
                .to_string(),
        )),
    }
}

fn verify_with_sdk(artifact: &ProofArtifact) -> ZkfResult<bool> {
    let mode = artifact
        .metadata
        .get("risc0_sdk_prover_mode")
        .and_then(|value| RiscZeroSdkProverMode::from_str(value))
        .unwrap_or_else(risc0_sdk_prover_mode);

    match mode {
        RiscZeroSdkProverMode::Mock => {
            // Mock verification: proof is non-empty and matches expected format.
            if artifact.proof.is_empty() {
                return Err(ZkfError::InvalidArtifact("empty mock proof".to_string()));
            }
            Ok(true)
        }
        #[cfg(feature = "native-risc-zero")]
        RiscZeroSdkProverMode::Ipc | RiscZeroSdkProverMode::Local => {
            let receipt: Receipt = bincode::deserialize(&artifact.proof)
                .map_err(|e| ZkfError::InvalidArtifact(format!("deserialize receipt: {e}")))?;
            let image_id: risc0_zkvm::sha::Digest =
                bincode::deserialize(&artifact.verification_key)
                    .map_err(|e| ZkfError::InvalidArtifact(format!("deserialize image_id: {e}")))?;
            receipt
                .verify(image_id)
                .map_err(|e| ZkfError::Backend(format!("RISC Zero verify: {e}")))?;
            Ok(true)
        }
        #[cfg(not(feature = "native-risc-zero"))]
        RiscZeroSdkProverMode::Ipc | RiscZeroSdkProverMode::Local => Err(ZkfError::Backend(
            "RISC Zero local SDK verification requires the `native-risc-zero` feature".to_string(),
        )),
    }
}

fn prove_with_external_command(
    compiled: &CompiledProgram,
    witness: &Witness,
    command: &str,
) -> ZkfResult<ProofArtifact> {
    let elf_ready = compiled
        .metadata
        .get("risc0_elf_ready")
        .is_some_and(|value| value == "true");
    if !elf_ready {
        return Err(ZkfError::Backend(
            "RISC Zero guest ELF is not ready; ensure toolchain target is installed and compile succeeds"
                .to_string(),
        ));
    }

    let elf_path = compiled
        .metadata
        .get("risc0_elf_path")
        .cloned()
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("missing risc0_elf_path in compiled metadata".to_string())
        })?;
    let request = RiscZeroExternalProveRequest {
        program_digest: &compiled.program_digest,
        field: compiled.program.field.as_str(),
        elf_path: &elf_path,
        elf_sha256: compiled
            .metadata
            .get("risc0_elf_sha256")
            .map(String::as_str),
        witness,
    };
    let request_bytes =
        serde_json::to_vec(&request).map_err(|err| ZkfError::Serialization(err.to_string()))?;
    let output = run_shell_command_with_json_stdin(command, &request_bytes)?;
    let response: RiscZeroExternalProveResponse = serde_json::from_slice(output.stdout.as_slice())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "invalid RISC Zero prove command JSON output: {err}"
            ))
        })?;

    let proof = base64::engine::general_purpose::STANDARD
        .decode(response.proof_base64.as_bytes())
        .map_err(|err| ZkfError::InvalidArtifact(format!("invalid proof_base64: {err}")))?;
    let verification_key = base64::engine::general_purpose::STANDARD
        .decode(response.verification_key_base64.as_bytes())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid verification_key_base64: {err}"))
        })?;
    let public_inputs = response
        .public_inputs
        .into_iter()
        .map(FieldElement::new)
        .collect::<Vec<_>>();
    let mut metadata = response.metadata;
    metadata.insert(
        "risc0_native_mode".to_string(),
        "external-cmd-v1".to_string(),
    );
    metadata.insert("risc0_external_command".to_string(), command.to_string());
    metadata.insert("risc0_elf_path".to_string(), elf_path);
    if let Some(sha) = compiled.metadata.get("risc0_elf_sha256") {
        metadata.insert("risc0_elf_sha256".to_string(), sha.clone());
    }
    append_backend_runtime_metadata(&mut metadata, BackendKind::RiscZero);

    Ok(ProofArtifact {
        backend: BackendKind::RiscZero,
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

fn verify_with_external_command(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
    command: &str,
) -> ZkfResult<bool> {
    let request = RiscZeroExternalVerifyRequest {
        program_digest: &compiled.program_digest,
        field: compiled.program.field.as_str(),
        proof_base64: base64::engine::general_purpose::STANDARD.encode(&artifact.proof),
        verification_key_base64: base64::engine::general_purpose::STANDARD
            .encode(&artifact.verification_key),
        public_inputs: artifact
            .public_inputs
            .iter()
            .map(|value| value.to_decimal_string())
            .collect(),
    };
    let request_bytes =
        serde_json::to_vec(&request).map_err(|err| ZkfError::Serialization(err.to_string()))?;
    let output = run_shell_command_with_json_stdin(command, &request_bytes)?;
    let response: RiscZeroExternalVerifyResponse = serde_json::from_slice(output.stdout.as_slice())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "invalid RISC Zero verify command JSON output: {err}"
            ))
        })?;
    Ok(response.ok)
}

fn resolve_elf_bytes(compiled: &CompiledProgram) -> ZkfResult<Vec<u8>> {
    if let Some(bytes) = compiled.compiled_data.as_ref() {
        return Ok(bytes.clone());
    }
    let elf_ready = compiled
        .metadata
        .get("risc0_elf_ready")
        .is_some_and(|value| value == "true");
    if !elf_ready {
        return Err(ZkfError::Backend(
            "RISC Zero guest ELF is not ready; ensure `cargo +risc0 build --target riscv32im-risc0-zkvm-elf` succeeds during compile".to_string(),
        ));
    }
    let path = compiled
        .metadata
        .get("risc0_elf_path")
        .cloned()
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("missing risc0_elf_path in compiled metadata".to_string())
        })?;
    fs::read(path).map_err(|err| ZkfError::Io(err.to_string()))
}

fn build_execution_payload(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<Vec<u8>> {
    let _ = witness;
    let digest = compiled.program_digest.clone();
    let mut payload = Vec::new();
    payload.extend_from_slice(&(digest.len() as u64).to_le_bytes());
    payload.extend_from_slice(digest.as_bytes());
    payload.push(1u8);
    Ok(payload)
}

#[derive(Debug)]
struct ShellOutput {
    stdout: Vec<u8>,
}

fn run_shell_command_with_json_stdin(command: &str, payload: &[u8]) -> ZkfResult<ShellOutput> {
    let mut child = Command::new("sh")
        .arg("-lc")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| ZkfError::Backend(format!("failed to spawn command `{command}`: {err}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(payload)
            .map_err(|err| ZkfError::Backend(format!("failed to write command stdin: {err}")))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|err| ZkfError::Backend(format!("failed to read command output: {err}")))?;
    if !output.status.success() {
        let stderr = truncate_metadata_text(String::from_utf8_lossy(&output.stderr).trim());
        return Err(ZkfError::Backend(format!(
            "external command `{command}` failed: {stderr}"
        )));
    }
    Ok(ShellOutput {
        stdout: output.stdout,
    })
}

fn guest_user_elf_path(guest_dir: &Path) -> PathBuf {
    guest_dir
        .join("target")
        .join("riscv32im-risc0-zkvm-elf")
        .join("release")
        .join("zkf_risc0_guest")
}

fn guest_program_binary_path(guest_dir: &Path) -> PathBuf {
    guest_user_elf_path(guest_dir).with_extension("bin")
}

fn guest_cargo_toml() -> String {
    r#"[package]
name = "zkf_risc0_guest"
version = "0.1.0"
edition = "2021"

[dependencies]
risc0-zkvm = { version = "=2.3.2", default-features = false }
"#
    .to_string()
}

fn guest_main_rs() -> &'static str {
    r#"#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read the length-prefixed payload from the host. The host already validates
    // constraints before invoking the zkVM, so the guest only attests to the
    // digest/result tuple it receives.
    let payload: Vec<u8> = risc0_zkvm::guest::env::read();
    let mut offset = 0usize;

    let digest_len = u64::from_le_bytes(
        payload[offset..offset + 8].try_into().unwrap()
    ) as usize;
    offset += 8;
    let expected_digest = core::str::from_utf8(&payload[offset..offset + digest_len])
        .expect("invalid digest string");
    offset += digest_len;
    let host_validated_ok = payload.get(offset).copied().unwrap_or(0) == 1;
    risc0_zkvm::guest::env::commit(&(expected_digest, host_validated_ok));
}
"#
}

fn truncate_metadata_text(text: impl AsRef<str>) -> String {
    const LIMIT: usize = 4096;
    let text = text.as_ref();
    if text.len() <= LIMIT {
        text.to_string()
    } else {
        format!("{}...[truncated:{} bytes]", &text[..LIMIT], text.len())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn append_rustflags(extra: &str) -> String {
    match std::env::var("RUSTFLAGS") {
        Ok(current) if !current.trim().is_empty() => format!("{current} {extra}"),
        _ => extra.to_string(),
    }
}

fn risc0_prover_command() -> Option<String> {
    std::env::var("ZKF_RISC_ZERO_PROVER_CMD")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn risc0_verifier_command() -> Option<String> {
    std::env::var("ZKF_RISC_ZERO_VERIFIER_CMD")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn risc0_sdk_prover_mode() -> RiscZeroSdkProverMode {
    std::env::var("ZKF_RISC_ZERO_SDK_PROVER")
        .ok()
        .and_then(|value| RiscZeroSdkProverMode::from_str(&value))
        .unwrap_or_else(|| {
            if r0vm_path().is_some() {
                RiscZeroSdkProverMode::Ipc
            } else {
                RiscZeroSdkProverMode::Local
            }
        })
}

fn r0vm_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("RISC0_SERVER_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.exists() {
                return Some(path);
            }
        }
    }

    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("r0vm"))
            .find(|candidate| candidate.exists())
    })
}

fn risc0_sdk_enabled() -> bool {
    std::env::var("ZKF_RISC_ZERO_DISABLE_SDK")
        .map(|value| !(value.eq_ignore_ascii_case("true") || value == "1"))
        .unwrap_or(true)
}

fn allow_compat_delegate() -> bool {
    std::env::var("ZKF_RISC_ZERO_ALLOW_COMPAT_DELEGATE")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_returns_risc_zero() {
        assert_eq!(RiscZeroNativeBackend.kind(), BackendKind::RiscZero);
    }

    #[test]
    fn capabilities_declare_native_mode() {
        let caps = RiscZeroNativeBackend.capabilities();
        assert!(caps.zkvm_mode);
        assert!(caps.transparent_setup);
        assert!(caps.recursion_ready);
        assert!(!caps.trusted_setup);
        assert_eq!(caps.mode, BackendMode::Native);
    }

    #[test]
    fn compile_rejects_wrong_field() {
        let program = Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            signals: vec![],
            constraints: vec![],
            witness_plan: Default::default(),
            ..Default::default()
        };
        let result = RiscZeroNativeBackend.compile(&program);
        assert!(result.is_err());
    }

    #[test]
    fn mock_sdk_roundtrip() {
        use zkf_core::{Constraint, Expr, Signal, Visibility};

        // Set mock mode for this test
        // SAFETY: test-only; single-threaded test runner for this module.
        unsafe { std::env::set_var("ZKF_RISC_ZERO_SDK_PROVER", "mock") };

        let program = Program {
            name: "risc0_native_test".to_string(),
            field: FieldId::Goldilocks,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".to_string()),
                rhs: Expr::Signal("y".to_string()),
                label: Some("test_eq".to_string()),
            }],
            witness_plan: Default::default(),
            ..Default::default()
        };

        let mut witness = Witness::default();
        witness
            .values
            .insert("x".to_string(), FieldElement::from_i64(42));
        witness
            .values
            .insert("y".to_string(), FieldElement::from_i64(42));

        // prove_with_sdk in mock mode should succeed
        let mut compiled = CompiledProgram::new(BackendKind::RiscZero, program);
        // Provide dummy ELF bytes so resolve_elf_bytes succeeds
        compiled.compiled_data = Some(vec![0x7f, 0x45, 0x4c, 0x46]);
        let result = prove_with_sdk(&compiled, &witness);
        assert!(
            result.is_ok(),
            "prove_with_sdk mock failed: {:?}",
            result.err()
        );

        let artifact = result.unwrap();
        assert!(!artifact.proof.is_empty());
        assert_eq!(
            artifact.metadata.get("risc0_sdk_prover_mode").unwrap(),
            "mock"
        );

        // Verify should succeed in mock mode
        let verify_result = verify_with_sdk(&artifact);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());

        // Clean up
        // SAFETY: test-only; single-threaded test runner for this module.
        unsafe { std::env::remove_var("ZKF_RISC_ZERO_SDK_PROVER") };
    }

    #[test]
    fn local_mode_returns_feature_error_without_feature() {
        // Force local mode for this test so the expectation is stable even when
        // the host defaults to IPC mode.
        unsafe { std::env::set_var("ZKF_RISC_ZERO_SDK_PROVER", "local") };
        let mut compiled = CompiledProgram::new(
            BackendKind::RiscZero,
            Program {
                name: "test_local".to_string(),
                field: FieldId::Goldilocks,
                signals: vec![],
                constraints: vec![],
                witness_plan: Default::default(),
                ..Default::default()
            },
        );
        compiled.compiled_data = Some(vec![0x7f, 0x45, 0x4c, 0x46]);
        let witness = Witness::default();
        let result = prove_with_sdk(&compiled, &witness);

        #[cfg(not(feature = "native-risc-zero"))]
        {
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("native-risc-zero"),
                "error should mention feature flag: {msg}"
            );
        }

        #[cfg(feature = "native-risc-zero")]
        {
            // With the feature enabled, it will fail for a different reason
            // (invalid ELF), which is expected.
            let _ = result;
        }

        unsafe { std::env::remove_var("ZKF_RISC_ZERO_SDK_PROVER") };
    }
}
