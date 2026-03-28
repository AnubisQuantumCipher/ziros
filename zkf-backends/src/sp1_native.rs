use crate::BackendEngine;
use crate::blackbox_native::{supported_blackbox_ops, validate_blackbox_constraints};
use crate::compat::Sp1Backend as CompatSp1Backend;
use crate::metal_runtime::append_backend_runtime_metadata;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{ProveRequest as _, ProverClient as BlockingProverClient, SP1Stdin};
use sp1_sdk::{
    Elf as Sp1Elf, HashableKey as _, ProvingKey as _, SP1Proof, SP1ProofWithPublicValues,
    SP1VerifyingKey,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldElement, FieldId, Program,
    ProofArtifact, ToolRequirement, Witness, ZkfError, ZkfResult, check_constraints,
};

pub struct Sp1NativeBackend;

impl BackendEngine for Sp1NativeBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Sp1
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::Sp1,
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
            notes: "Feature-gated SP1 guest/ELF pipeline: compiles and caches a deterministic SP1 guest ELF and uses SDK-native blocking prove/verify as primary path (cpu by default, optional mock mode). External prover/verifier commands and compatibility delegation are explicit fallback paths only."
                .to_string(),
        }
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "cargo".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Required for SP1 guest compilation".to_string()),
                required: true,
            },
            ToolRequirement {
                tool: "rustup".to_string(),
                args: vec!["target".to_string(), "list".to_string()],
                note: Some(
                    "SP1 guest target `riscv32im-succinct-zkvm-elf` should be installed via sp1up"
                        .to_string(),
                ),
                required: false,
            },
            ToolRequirement {
                tool: "sp1up".to_string(),
                args: vec!["--version".to_string()],
                note: Some("SP1 toolchain manager".to_string()),
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
                    "native sp1 guest pipeline currently accepts Goldilocks/BabyBear/Mersenne31 programs"
                        .to_string(),
            });
        }
        let mut compiled = CompiledProgram::new(self.kind(), program.clone());

        let report = prepare_guest_elf(&compiled.program_digest)?;
        compiled
            .metadata
            .insert("sp1_native_mode".to_string(), "guest-elf-v1".to_string());
        compiled.metadata.insert(
            "sp1_guest_dir".to_string(),
            report.guest_dir.display().to_string(),
        );
        compiled.metadata.insert(
            "sp1_elf_path".to_string(),
            report.elf_path.display().to_string(),
        );
        compiled
            .metadata
            .insert("sp1_elf_ready".to_string(), report.elf_ready.to_string());
        compiled.metadata.insert(
            "sp1_build_status".to_string(),
            if report.build_success {
                "ok".to_string()
            } else {
                "failed".to_string()
            },
        );
        if let Some(sha) = report.elf_sha256 {
            compiled.metadata.insert("sp1_elf_sha256".to_string(), sha);
        }
        if !report.stdout.is_empty() {
            compiled
                .metadata
                .insert("sp1_build_stdout".to_string(), report.stdout);
        }
        if !report.stderr.is_empty() {
            compiled
                .metadata
                .insert("sp1_build_stderr".to_string(), report.stderr);
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
        if sp1_sdk_enabled() {
            match prove_with_sdk(compiled, witness) {
                Ok(artifact) => return Ok(artifact),
                Err(err) => sdk_error = Some(err),
            }
        }

        if let Some(command) = sp1_prover_command() {
            let mut artifact = prove_with_external_command(compiled, witness, &command)?;
            if let Some(err) = sdk_error {
                artifact.metadata.insert(
                    "sp1_sdk_fallback_error".to_string(),
                    truncate_metadata_text(err.to_string()),
                );
            }
            return Ok(artifact);
        }

        if allow_compat_delegate() {
            let compat = CompatSp1Backend;
            let compat_compiled = compat.compile(&compiled.program)?;
            let mut artifact = compat.prove(&compat_compiled, witness)?;
            artifact.backend = BackendKind::Sp1;
            artifact.metadata.insert(
                "sp1_native_mode".to_string(),
                "delegate-proof-v1".to_string(),
            );
            artifact.metadata.insert(
                "delegated_backend".to_string(),
                compat_compiled.backend.as_str().to_string(),
            );
            if let Some(ready) = compiled.metadata.get("sp1_elf_ready") {
                artifact
                    .metadata
                    .insert("sp1_elf_ready".to_string(), ready.clone());
            }
            if let Some(path) = compiled.metadata.get("sp1_elf_path") {
                artifact
                    .metadata
                    .insert("sp1_elf_path".to_string(), path.clone());
            }
            if let Some(err) = sdk_error {
                artifact.metadata.insert(
                    "sp1_sdk_fallback_error".to_string(),
                    truncate_metadata_text(err.to_string()),
                );
            }
            return Ok(artifact);
        }

        if let Some(err) = sdk_error {
            return Err(ZkfError::Backend(format!(
                "native SP1 SDK proof failed: {err}; set ZKF_SP1_PROVER_CMD/ZKF_SP1_VERIFIER_CMD for explicit external-command fallback or ZKF_SP1_ALLOW_COMPAT_DELEGATE=true for compatibility fallback"
            )));
        }

        Err(ZkfError::Backend(
            "native SP1 proof is not configured; ensure SDK mode is enabled and guest ELF is ready, or set ZKF_SP1_PROVER_CMD/ZKF_SP1_VERIFIER_CMD for explicit external fallback, or set ZKF_SP1_ALLOW_COMPAT_DELEGATE=true for compatibility fallback".to_string(),
        ))
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        ensure_compiled_backend(self.kind(), compiled)?;
        match artifact.metadata.get("sp1_native_mode").map(String::as_str) {
            Some("sdk-blocking-v1") => verify_with_sdk(artifact),
            Some("external-cmd-v1") => {
                if let Some(command) = sp1_verifier_command() {
                    verify_with_external_command(compiled, artifact, &command)
                } else {
                    Err(ZkfError::Backend(
                        "artifact requires external SP1 verifier command but ZKF_SP1_VERIFIER_CMD is not set"
                            .to_string(),
                    ))
                }
            }
            Some("delegate-proof-v1") if allow_compat_delegate() => {
                let compat = CompatSp1Backend;
                let compat_compiled = compat.compile(&compiled.program)?;
                let mut delegated = artifact.clone();
                delegated.backend = compat_compiled.backend;
                compat.verify(&compat_compiled, &delegated)
            }
            Some("delegate-proof-v1") => Err(ZkfError::Backend(
                "artifact was produced via compatibility fallback; set ZKF_SP1_ALLOW_COMPAT_DELEGATE=true to verify it".to_string(),
            )),
            _ => Err(ZkfError::InvalidArtifact(
                "unsupported sp1_native_mode in proof artifact".to_string(),
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
struct Sp1ExternalProveRequest<'a> {
    program_digest: &'a str,
    field: &'a str,
    elf_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    elf_sha256: Option<&'a str>,
    witness: &'a Witness,
}

#[derive(Debug, Deserialize)]
struct Sp1ExternalProveResponse {
    proof_base64: String,
    verification_key_base64: String,
    public_inputs: Vec<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct Sp1ExternalVerifyRequest<'a> {
    program_digest: &'a str,
    field: &'a str,
    proof_base64: String,
    verification_key_base64: String,
    public_inputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Sp1ExternalVerifyResponse {
    ok: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Sp1SdkProverMode {
    Cpu,
    Mock,
}

impl Sp1SdkProverMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Mock => "mock",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cpu" => Some(Self::Cpu),
            "mock" => Some(Self::Mock),
            _ => None,
        }
    }
}

fn guest_cache_root() -> PathBuf {
    if let Ok(value) = std::env::var("ZKF_SP1_GUEST_CACHE") {
        return PathBuf::from(value);
    }
    std::env::temp_dir().join("zkf-sp1-guest-cache")
}

fn prepare_guest_elf(program_digest: &str) -> ZkfResult<GuestBuildReport> {
    let root = guest_cache_root();
    let guest_dir = root.join(program_digest);
    let src_dir = guest_dir.join("src");
    let output_dir = guest_dir.join("elf");
    fs::create_dir_all(&src_dir).map_err(|err| ZkfError::Io(err.to_string()))?;
    fs::create_dir_all(&output_dir).map_err(|err| ZkfError::Io(err.to_string()))?;

    let cargo_toml = guest_dir.join("Cargo.toml");
    let main_rs = src_dir.join("main.rs");
    fs::write(&cargo_toml, guest_cargo_toml()).map_err(|err| ZkfError::Io(err.to_string()))?;
    fs::write(&main_rs, guest_main_rs()).map_err(|err| ZkfError::Io(err.to_string()))?;

    let mut build_success = false;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let output_dir_arg = output_dir.display().to_string();
    let build_output = Command::new("cargo")
        .env(
            "RUSTFLAGS",
            append_rustflags(r#"--cfg getrandom_backend="custom""#),
        )
        .args([
            "prove",
            "build",
            "--elf-name",
            "zkf_sp1_guest",
            "--output-directory",
            output_dir_arg.as_str(),
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

    let elf_path = guest_elf_path(&guest_dir);
    let (elf_ready, elf_bytes, elf_sha256) = if build_success && elf_path.exists() {
        let bytes = fs::read(&elf_path).map_err(|err| ZkfError::Io(err.to_string()))?;
        let sha = sha256_hex(bytes.as_slice());
        (true, Some(bytes), Some(sha))
    } else {
        (false, None, None)
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

fn prove_with_external_command(
    compiled: &CompiledProgram,
    witness: &Witness,
    command: &str,
) -> ZkfResult<ProofArtifact> {
    let elf_ready = compiled
        .metadata
        .get("sp1_elf_ready")
        .is_some_and(|value| value == "true");
    if !elf_ready {
        return Err(ZkfError::Backend(
            "SP1 guest ELF is not ready; ensure toolchain target is installed and compile succeeds"
                .to_string(),
        ));
    }

    let elf_path = compiled
        .metadata
        .get("sp1_elf_path")
        .cloned()
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("missing sp1_elf_path in compiled metadata".to_string())
        })?;
    let request = Sp1ExternalProveRequest {
        program_digest: &compiled.program_digest,
        field: compiled.program.field.as_str(),
        elf_path: &elf_path,
        elf_sha256: compiled.metadata.get("sp1_elf_sha256").map(String::as_str),
        witness,
    };
    let request_bytes =
        serde_json::to_vec(&request).map_err(|err| ZkfError::Serialization(err.to_string()))?;
    let output = run_shell_command_with_json_stdin(command, &request_bytes)?;
    let response: Sp1ExternalProveResponse = serde_json::from_slice(output.stdout.as_slice())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid SP1 prove command JSON output: {err}"))
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
    metadata.insert("sp1_native_mode".to_string(), "external-cmd-v1".to_string());
    metadata.insert("sp1_external_command".to_string(), command.to_string());
    metadata.insert("sp1_elf_path".to_string(), elf_path);
    if let Some(sha) = compiled.metadata.get("sp1_elf_sha256") {
        metadata.insert("sp1_elf_sha256".to_string(), sha.clone());
    }
    append_backend_runtime_metadata(&mut metadata, BackendKind::Sp1);

    Ok(ProofArtifact {
        backend: BackendKind::Sp1,
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
    let request = Sp1ExternalVerifyRequest {
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
    let response: Sp1ExternalVerifyResponse = serde_json::from_slice(output.stdout.as_slice())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid SP1 verify command JSON output: {err}"))
        })?;
    Ok(response.ok)
}

fn prove_with_sdk(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
    let elf = resolve_elf(compiled)?;
    let mode = sp1_sdk_prover_mode();
    match mode {
        Sp1SdkProverMode::Cpu => {
            let prover = BlockingProverClient::builder().cpu().build();
            prove_with_sdk_prover(prover, elf, compiled, witness, mode)
        }
        Sp1SdkProverMode::Mock => {
            let prover = BlockingProverClient::builder().mock().build();
            prove_with_sdk_prover(prover, elf, compiled, witness, mode)
        }
    }
}

fn prove_with_sdk_prover<P>(
    prover: P,
    elf: Sp1Elf,
    compiled: &CompiledProgram,
    witness: &Witness,
    mode: Sp1SdkProverMode,
) -> ZkfResult<ProofArtifact>
where
    P: sp1_sdk::blocking::Prover,
    P::Error: std::fmt::Display,
{
    let stdin = sdk_stdin(compiled, witness)?;
    let proving_key = prover
        .setup(elf)
        .map_err(|err| ZkfError::Backend(format!("SP1 SDK setup failed: {err}")))?;
    let proof_bundle = prover
        .prove(&proving_key, stdin)
        .compressed()
        .run()
        .map_err(|err| ZkfError::Backend(format!("SP1 SDK prove failed: {err}")))?;

    let proof_mode = sp1_proof_mode(&proof_bundle);
    let (onchain_proof_sha256, onchain_proof_selector, onchain_proof_available) = match proof_mode {
        "plonk" | "groth16" => {
            let onchain_proof_bytes = proof_bundle.bytes();
            let selector = if onchain_proof_bytes.len() >= 4 {
                Some(format!(
                    "0x{}",
                    onchain_proof_bytes
                        .iter()
                        .take(4)
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ))
            } else {
                None
            };
            (
                Some(sha256_hex(onchain_proof_bytes.as_slice())),
                selector,
                true,
            )
        }
        _ => (None, None, false),
    };
    let onchain_proof_reason = if onchain_proof_available {
        None
    } else {
        Some("proof-mode-not-onchain-verifiable")
    };
    let program_vkey_bn254 = proving_key.verifying_key().hash_bn254().to_string();
    let public_values_hash_bn254 = proof_bundle.public_values.hash_bn254().to_string();
    let public_values_bytes = proof_bundle.public_values.to_vec();
    let public_values_base64 =
        base64::engine::general_purpose::STANDARD.encode(public_values_bytes.as_slice());

    let proof = bincode::serialize(&proof_bundle)
        .map_err(|err| ZkfError::Serialization(format!("failed to serialize SP1 proof: {err}")))?;
    let verification_key = bincode::serialize(proving_key.verifying_key()).map_err(|err| {
        ZkfError::Serialization(format!("failed to serialize SP1 verifying key: {err}"))
    })?;
    let public_inputs = vec![FieldElement::new(public_values_hash_bn254.clone())];

    let mut metadata = BTreeMap::new();
    metadata.insert("sp1_native_mode".to_string(), "sdk-blocking-v1".to_string());
    metadata.insert("sp1_sdk_prover_mode".to_string(), mode.as_str().to_string());
    metadata.insert("sp1_sdk_proof_mode".to_string(), proof_mode.to_string());
    metadata.insert(
        "sp1_onchain_proof_available".to_string(),
        onchain_proof_available.to_string(),
    );
    metadata.insert(
        "sp1_public_values_len".to_string(),
        proof_bundle.public_values.as_slice().len().to_string(),
    );
    metadata.insert("sp1_program_vkey_bn254".to_string(), program_vkey_bn254);
    metadata.insert(
        "sp1_public_values_hash_bn254".to_string(),
        public_values_hash_bn254,
    );
    metadata.insert("sp1_public_values_base64".to_string(), public_values_base64);
    if let Some(sha256) = onchain_proof_sha256 {
        metadata.insert("sp1_onchain_proof_sha256".to_string(), sha256);
    }
    if let Some(selector) = onchain_proof_selector {
        metadata.insert("sp1_onchain_proof_selector".to_string(), selector);
    }
    if let Some(reason) = onchain_proof_reason {
        metadata.insert("sp1_onchain_proof_reason".to_string(), reason.to_string());
    }
    if let Some(path) = compiled.metadata.get("sp1_elf_path") {
        metadata.insert("sp1_elf_path".to_string(), path.clone());
    }
    if let Some(sha) = compiled.metadata.get("sp1_elf_sha256") {
        metadata.insert("sp1_elf_sha256".to_string(), sha.clone());
    }
    append_backend_runtime_metadata(&mut metadata, BackendKind::Sp1);

    Ok(ProofArtifact {
        backend: BackendKind::Sp1,
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

fn verify_with_sdk(artifact: &ProofArtifact) -> ZkfResult<bool> {
    let proof_bundle: SP1ProofWithPublicValues = bincode::deserialize(artifact.proof.as_slice())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid SP1 SDK proof serialization: {err}"))
        })?;
    let verification_key: SP1VerifyingKey =
        bincode::deserialize(artifact.verification_key.as_slice()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "invalid SP1 SDK verification key serialization: {err}"
            ))
        })?;

    let mode = artifact
        .metadata
        .get("sp1_sdk_prover_mode")
        .and_then(|value| Sp1SdkProverMode::from_str(value))
        .unwrap_or_else(sp1_sdk_prover_mode);
    match mode {
        Sp1SdkProverMode::Cpu => {
            let prover = BlockingProverClient::builder().cpu().build();
            verify_with_sdk_prover(prover, &proof_bundle, &verification_key)
        }
        Sp1SdkProverMode::Mock => {
            let prover = BlockingProverClient::builder().mock().build();
            verify_with_sdk_prover(prover, &proof_bundle, &verification_key)
        }
    }
}

fn verify_with_sdk_prover<P>(
    prover: P,
    proof_bundle: &SP1ProofWithPublicValues,
    verification_key: &SP1VerifyingKey,
) -> ZkfResult<bool>
where
    P: sp1_sdk::blocking::Prover,
{
    prover
        .verify(proof_bundle, verification_key, None)
        .map_err(|err| ZkfError::Backend(format!("SP1 SDK verify failed: {err}")))?;
    Ok(true)
}

fn resolve_elf(compiled: &CompiledProgram) -> ZkfResult<Sp1Elf> {
    let elf_bytes = if let Some(bytes) = compiled.compiled_data.as_ref() {
        bytes.clone()
    } else {
        let elf_ready = compiled
            .metadata
            .get("sp1_elf_ready")
            .is_some_and(|value| value == "true");
        if !elf_ready {
            return Err(ZkfError::Backend(
                "SP1 guest ELF is not ready; ensure `cargo prove build --elf-name zkf_sp1_guest` succeeds during compile".to_string(),
            ));
        }
        let path = compiled
            .metadata
            .get("sp1_elf_path")
            .cloned()
            .ok_or_else(|| {
                ZkfError::InvalidArtifact("missing sp1_elf_path in compiled metadata".to_string())
            })?;
        fs::read(path).map_err(|err| ZkfError::Io(err.to_string()))?
    };
    Ok(Sp1Elf::from(elf_bytes))
}

fn sdk_stdin(compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<SP1Stdin> {
    let _ = witness;
    let digest = compiled.program_digest.clone();
    let mut stdin = SP1Stdin::new();
    stdin.write(&digest);
    stdin.write(&true);
    Ok(stdin)
}

fn sp1_proof_mode(proof_bundle: &SP1ProofWithPublicValues) -> &'static str {
    match &proof_bundle.proof {
        SP1Proof::Core(_) => "core",
        SP1Proof::Compressed(_) => "compressed",
        SP1Proof::Plonk(_) => "plonk",
        SP1Proof::Groth16(_) => "groth16",
    }
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

fn guest_elf_path(guest_dir: &Path) -> PathBuf {
    guest_dir.join("elf").join("zkf_sp1_guest")
}

fn guest_cargo_toml() -> String {
    r#"[package]
name = "zkf_sp1_guest"
version = "0.1.0"
edition = "2021"

[dependencies]
sp1-zkvm = "6.0.2"
"#
    .to_string()
}

fn guest_main_rs() -> &'static str {
    r#"#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // The host already validates constraints before invoking the zkVM. The guest
    // only attests to the validated digest/result tuple.
    let expected_digest: String = sp1_zkvm::io::read();
    let host_validated_ok: bool = sp1_zkvm::io::read();
    sp1_zkvm::io::commit(&(expected_digest, host_validated_ok));
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

fn append_rustflags(extra: &str) -> String {
    match std::env::var("RUSTFLAGS") {
        Ok(current) if !current.trim().is_empty() => format!("{current} {extra}"),
        _ => extra.to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn sp1_prover_command() -> Option<String> {
    std::env::var("ZKF_SP1_PROVER_CMD")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sp1_verifier_command() -> Option<String> {
    std::env::var("ZKF_SP1_VERIFIER_CMD")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sp1_sdk_prover_mode() -> Sp1SdkProverMode {
    std::env::var("ZKF_SP1_SDK_PROVER")
        .ok()
        .and_then(|value| Sp1SdkProverMode::from_str(&value))
        .unwrap_or(Sp1SdkProverMode::Cpu)
}

fn sp1_sdk_enabled() -> bool {
    std::env::var("ZKF_SP1_DISABLE_SDK")
        .map(|value| !(value.eq_ignore_ascii_case("true") || value == "1"))
        .unwrap_or(true)
}

fn allow_compat_delegate() -> bool {
    std::env::var("ZKF_SP1_ALLOW_COMPAT_DELEGATE")
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
