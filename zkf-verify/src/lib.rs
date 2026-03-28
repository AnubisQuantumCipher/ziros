use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use zkf_metal_public_proof_lib::{
    BUNDLE_EVIDENCE_SCHEMA, BundleEvidence, BundleWitness, EXPECTED_PUBLIC_INPUT_BYTES,
    PUBLIC_GROTH16_PROOF_SCHEMA, PUBLIC_INPUT_SCHEMA, PUBLIC_PROOF_BACKEND, PUBLIC_PROOF_SYSTEM,
    PublicGroth16ProofBundle, expected_public_values, validate_bundle_evidence,
    validate_public_groth16_proving_lane, validate_public_input_bytes,
};

pub const CHECKSUM_PATH: &str = "checksums/sha256.txt";
pub const STATEMENT_SCHEMA: &str = "zkf-metal-public-statement-bundle-v1";
pub const PROOF_MANIFEST_SCHEMA: &str = "zkf-metal-public-proof-manifest-v1";
pub const ATTESTATION_MANIFEST_SCHEMA: &str = "zkf-metal-public-attestation-manifest-v1";
pub const PUBLIC_REFLECTION_DIGEST_SCHEME_V1: &str = "public-v1-no-arg-names";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolchainIdentity {
    pub metal_compiler_version: String,
    pub xcode_version: String,
    pub sdk_version: String,
}

#[derive(Debug, Deserialize)]
struct StatementArtifactBindings {
    program_labels: Vec<String>,
    metallib_digests: Vec<String>,
    reflection_digests: Vec<String>,
    reflection_digest_scheme: String,
    pipeline_descriptor_digests: Vec<String>,
    toolchain_identity_digest: String,
    private_source_commitment_root: String,
    bundle_evidence_digest: String,
}

#[derive(Debug, Deserialize)]
struct PublicStatementBundle {
    schema: String,
    bundle_id: String,
    proof_system: String,
    theorem_ids: Vec<String>,
    artifact_bindings: StatementArtifactBindings,
}

#[derive(Debug, Clone, Deserialize)]
struct PublicArtifactBinding {
    kernel_program_label: String,
    entrypoint_label: String,
    metallib_path: String,
    metallib_digest: String,
    reflection_digest: String,
    pipeline_descriptor_digest: String,
}

#[derive(Debug, Deserialize)]
struct PublicAttestationManifest {
    schema: String,
    bundle_id: String,
    proof_system: String,
    public_input_schema: String,
    theorem_ids: Vec<String>,
    statement_bundle_path: String,
    statement_bundle_digest: String,
    bundle_evidence_path: String,
    bundle_evidence_digest: String,
    private_source_commitment_root: String,
    toolchain_identity: ToolchainIdentity,
    toolchain_identity_digest: String,
    metallib_digest_set_root: String,
    reflection_digest_scheme: String,
    artifacts: Vec<PublicArtifactBinding>,
}

#[derive(Debug, Deserialize)]
struct PublicProofManifest {
    schema: String,
    bundle_id: String,
    proof_system: String,
    public_input_schema: String,
    reflection_digest_scheme: String,
    theorem_ids: Vec<String>,
    attestation_manifest_path: String,
    attestation_manifest_digest: String,
    bundle_evidence_path: String,
    bundle_evidence_digest: String,
    proof_bundle_path: String,
    proof_bundle_digest: String,
    verification_key_path: String,
    verification_key_digest: String,
}

#[derive(Debug, Deserialize)]
struct BundleEvidenceDocument {
    schema: String,
    #[serde(flatten)]
    bundle_evidence: BundleEvidence,
}

#[derive(Debug, Serialize)]
pub struct BundleVerificationReport {
    pub bundle_id: String,
    pub manifest_path: String,
    pub theorem_ids: Vec<String>,
    pub manifest_digest: String,
    pub attestation_manifest_digest: String,
    pub statement_bundle_digest: String,
    pub bundle_evidence_digest: String,
    pub proof_bundle_digest: String,
    pub verification_key_digest: String,
    pub checked_artifacts: usize,
    pub proof_verified: bool,
    pub public_values_match: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifyAllReport {
    pub repo: String,
    pub checksum_file: String,
    pub checksums_verified: usize,
    pub bundles_verified: usize,
    pub bundle_reports: Vec<BundleVerificationReport>,
}

pub fn verify_all(repo: &Path) -> Result<VerifyAllReport, String> {
    if !repo.is_dir() {
        return Err(format!("repo path is not a directory: {}", repo.display()));
    }

    let checksums_verified = verify_checksums(repo)?;
    let manifest_dir = repo.join("proofs").join("manifests");
    if !manifest_dir.is_dir() {
        return Err(format!(
            "public proof manifest directory is missing: {}",
            manifest_dir.display()
        ));
    }

    let mut manifests = fs::read_dir(&manifest_dir)
        .map_err(|err| format!("failed to read {}: {err}", manifest_dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    manifests.sort();
    if manifests.is_empty() {
        return Err(format!(
            "no public proof manifests were found under {}",
            manifest_dir.display()
        ));
    }

    let mut bundle_reports = Vec::with_capacity(manifests.len());
    for manifest_path in manifests {
        bundle_reports.push(verify_bundle(repo, &manifest_path)?);
    }

    Ok(VerifyAllReport {
        repo: repo.display().to_string(),
        checksum_file: repo.join(CHECKSUM_PATH).display().to_string(),
        checksums_verified,
        bundles_verified: bundle_reports.len(),
        bundle_reports,
    })
}

fn verify_checksums(repo: &Path) -> Result<usize, String> {
    let checksum_path = repo.join(CHECKSUM_PATH);
    let raw = fs::read_to_string(&checksum_path)
        .map_err(|err| format!("failed to read {}: {err}", checksum_path.display()))?;
    let mut verified = 0usize;

    for (line_index, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (digest, relative) = trimmed.split_once("  ").ok_or_else(|| {
            format!(
                "invalid checksum line {} in {}: expected `sha256  relative/path`",
                line_index + 1,
                checksum_path.display()
            )
        })?;
        ensure_hex_digest(digest, &format!("checksum line {}", line_index + 1))?;
        let path = repo.join(relative);
        if !path.is_file() {
            return Err(format!(
                "checksummed artifact is missing: {}",
                path.display()
            ));
        }
        let actual = sha256_file(&path)?;
        if actual != digest {
            return Err(format!(
                "checksum mismatch for {}: expected {digest}, got {actual}",
                path.display()
            ));
        }
        verified += 1;
    }

    Ok(verified)
}

fn verify_bundle(repo: &Path, manifest_path: &Path) -> Result<BundleVerificationReport, String> {
    let manifest_bytes = fs::read(manifest_path)
        .map_err(|err| format!("failed to read {}: {err}", manifest_path.display()))?;
    let manifest_digest = sha256_hex(&manifest_bytes);
    let manifest: PublicProofManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|err| format!("invalid JSON in {}: {err}", manifest_path.display()))?;

    if manifest.schema != PROOF_MANIFEST_SCHEMA {
        return Err(format!(
            "{} has unexpected schema: {}",
            manifest_path.display(),
            manifest.schema
        ));
    }
    if manifest.proof_system != PUBLIC_PROOF_SYSTEM {
        return Err(format!(
            "{} declares unsupported proof system: {}",
            manifest_path.display(),
            manifest.proof_system
        ));
    }
    if manifest.public_input_schema != PUBLIC_INPUT_SCHEMA {
        return Err(format!(
            "{} declares unsupported public-input schema: {}",
            manifest_path.display(),
            manifest.public_input_schema
        ));
    }
    if manifest.reflection_digest_scheme != PUBLIC_REFLECTION_DIGEST_SCHEME_V1 {
        return Err(format!(
            "{} declares unsupported reflection digest scheme: {}",
            manifest_path.display(),
            manifest.reflection_digest_scheme
        ));
    }
    ensure_hex_digest(
        &manifest.attestation_manifest_digest,
        &format!("{}.attestation_manifest_digest", manifest_path.display()),
    )?;
    ensure_hex_digest(
        &manifest.bundle_evidence_digest,
        &format!("{}.bundle_evidence_digest", manifest_path.display()),
    )?;
    ensure_hex_digest(
        &manifest.proof_bundle_digest,
        &format!("{}.proof_bundle_digest", manifest_path.display()),
    )?;
    ensure_hex_digest(
        &manifest.verification_key_digest,
        &format!("{}.verification_key_digest", manifest_path.display()),
    )?;

    let attestation_path = repo.join(&manifest.attestation_manifest_path);
    let attestation_bytes = fs::read(&attestation_path)
        .map_err(|err| format!("failed to read {}: {err}", attestation_path.display()))?;
    let attestation_digest = sha256_hex(&attestation_bytes);
    if attestation_digest != manifest.attestation_manifest_digest {
        return Err(format!(
            "attestation manifest digest mismatch for {}: expected {}, got {}",
            attestation_path.display(),
            manifest.attestation_manifest_digest,
            attestation_digest
        ));
    }
    let attestation: PublicAttestationManifest = serde_json::from_slice(&attestation_bytes)
        .map_err(|err| format!("invalid JSON in {}: {err}", attestation_path.display()))?;
    if attestation.schema != ATTESTATION_MANIFEST_SCHEMA {
        return Err(format!(
            "{} has unexpected schema: {}",
            attestation_path.display(),
            attestation.schema
        ));
    }
    if attestation.proof_system != PUBLIC_PROOF_SYSTEM {
        return Err(format!(
            "{} declares unsupported proof system: {}",
            attestation_path.display(),
            attestation.proof_system
        ));
    }
    if attestation.public_input_schema != PUBLIC_INPUT_SCHEMA {
        return Err(format!(
            "{} declares unsupported public-input schema: {}",
            attestation_path.display(),
            attestation.public_input_schema
        ));
    }
    if attestation.bundle_id != manifest.bundle_id {
        return Err(format!(
            "attestation manifest {} does not match manifest bundle {}",
            attestation.bundle_id, manifest.bundle_id
        ));
    }
    if attestation.theorem_ids != manifest.theorem_ids {
        return Err(format!(
            "theorem ids drifted between {} and {}",
            attestation_path.display(),
            manifest_path.display()
        ));
    }
    if attestation.bundle_evidence_path != manifest.bundle_evidence_path {
        return Err(format!(
            "bundle evidence path drifted between {} and {}",
            attestation_path.display(),
            manifest_path.display()
        ));
    }
    if attestation.bundle_evidence_digest != manifest.bundle_evidence_digest {
        return Err(format!(
            "bundle evidence digest drifted between {} and {}",
            attestation_path.display(),
            manifest_path.display()
        ));
    }
    if attestation.reflection_digest_scheme != manifest.reflection_digest_scheme {
        return Err(format!(
            "reflection digest scheme drifted between {} and {}",
            attestation_path.display(),
            manifest_path.display()
        ));
    }
    ensure_hex_digest(
        &attestation.private_source_commitment_root,
        &format!(
            "{}.private_source_commitment_root",
            attestation_path.display()
        ),
    )?;
    ensure_hex_digest(
        &attestation.toolchain_identity_digest,
        &format!("{}.toolchain_identity_digest", attestation_path.display()),
    )?;
    ensure_hex_digest(
        &attestation.metallib_digest_set_root,
        &format!("{}.metallib_digest_set_root", attestation_path.display()),
    )?;
    if attestation.reflection_digest_scheme != PUBLIC_REFLECTION_DIGEST_SCHEME_V1 {
        return Err(format!(
            "{} declares unsupported reflection digest scheme: {}",
            attestation_path.display(),
            attestation.reflection_digest_scheme
        ));
    }

    let statement_path = repo.join(&attestation.statement_bundle_path);
    let statement_bytes = fs::read(&statement_path)
        .map_err(|err| format!("failed to read {}: {err}", statement_path.display()))?;
    let statement_digest = sha256_hex(&statement_bytes);
    if statement_digest != attestation.statement_bundle_digest {
        return Err(format!(
            "statement bundle digest mismatch for {}: expected {}, got {}",
            statement_path.display(),
            attestation.statement_bundle_digest,
            statement_digest
        ));
    }
    let statement_bundle: PublicStatementBundle = serde_json::from_slice(&statement_bytes)
        .map_err(|err| format!("invalid JSON in {}: {err}", statement_path.display()))?;
    if statement_bundle.schema != STATEMENT_SCHEMA {
        return Err(format!(
            "{} has unexpected schema: {}",
            statement_path.display(),
            statement_bundle.schema
        ));
    }
    if statement_bundle.proof_system != PUBLIC_PROOF_SYSTEM {
        return Err(format!(
            "{} declares unsupported proof system: {}",
            statement_path.display(),
            statement_bundle.proof_system
        ));
    }
    if statement_bundle.bundle_id != manifest.bundle_id {
        return Err(format!(
            "statement bundle {} does not match manifest bundle {}",
            statement_bundle.bundle_id, manifest.bundle_id
        ));
    }
    if statement_bundle.theorem_ids != manifest.theorem_ids {
        return Err(format!(
            "theorem ids drifted between {} and {}",
            statement_path.display(),
            manifest_path.display()
        ));
    }
    if statement_bundle.artifact_bindings.reflection_digest_scheme
        != PUBLIC_REFLECTION_DIGEST_SCHEME_V1
    {
        return Err(format!(
            "{} declares unsupported reflection digest scheme: {}",
            statement_path.display(),
            statement_bundle.artifact_bindings.reflection_digest_scheme
        ));
    }

    let bundle_evidence_path = repo.join(&manifest.bundle_evidence_path);
    let bundle_evidence_bytes = fs::read(&bundle_evidence_path)
        .map_err(|err| format!("failed to read {}: {err}", bundle_evidence_path.display()))?;
    let bundle_evidence_doc: BundleEvidenceDocument =
        serde_json::from_slice(&bundle_evidence_bytes)
            .map_err(|err| format!("invalid JSON in {}: {err}", bundle_evidence_path.display()))?;
    if bundle_evidence_doc.schema != BUNDLE_EVIDENCE_SCHEMA {
        return Err(format!(
            "{} has unexpected schema: {}",
            bundle_evidence_path.display(),
            bundle_evidence_doc.schema
        ));
    }

    let actual_toolchain_digest = toolchain_identity_digest(&attestation.toolchain_identity);
    if actual_toolchain_digest != attestation.toolchain_identity_digest {
        return Err(format!(
            "toolchain digest mismatch in {}: expected {}, got {}",
            attestation_path.display(),
            attestation.toolchain_identity_digest,
            actual_toolchain_digest
        ));
    }

    let bundle_witness = BundleWitness {
        bundle_id: manifest.bundle_id.clone(),
        theorem_ids: manifest.theorem_ids.clone(),
        statement_bundle_digest: attestation.statement_bundle_digest.clone(),
        private_source_commitment_root: attestation.private_source_commitment_root.clone(),
        metallib_digest_set_root: attestation.metallib_digest_set_root.clone(),
        attestation_manifest_digest: manifest.attestation_manifest_digest.clone(),
        toolchain_identity_digest: attestation.toolchain_identity_digest.clone(),
        bundle_evidence: bundle_evidence_doc.bundle_evidence.clone(),
    };
    let computed_bundle_evidence_digest =
        validate_bundle_evidence(&bundle_witness).map_err(|err| {
            format!(
                "bundle evidence validation failed for {}: {err}",
                bundle_evidence_path.display()
            )
        })?;
    if computed_bundle_evidence_digest != manifest.bundle_evidence_digest {
        return Err(format!(
            "bundle evidence digest mismatch for {}: expected {}, got {}",
            bundle_evidence_path.display(),
            manifest.bundle_evidence_digest,
            computed_bundle_evidence_digest
        ));
    }
    if statement_bundle.artifact_bindings.bundle_evidence_digest != computed_bundle_evidence_digest
    {
        return Err(format!(
            "statement bundle bundle-evidence digest drifted for {}",
            statement_path.display()
        ));
    }
    if statement_bundle.artifact_bindings.toolchain_identity_digest
        != attestation.toolchain_identity_digest
    {
        return Err(format!(
            "statement bundle toolchain digest drifted for {}",
            statement_path.display()
        ));
    }
    if statement_bundle
        .artifact_bindings
        .private_source_commitment_root
        != attestation.private_source_commitment_root
    {
        return Err(format!(
            "statement bundle private-source commitment drifted for {}",
            statement_path.display()
        ));
    }
    if statement_bundle.artifact_bindings.reflection_digest_scheme
        != attestation.reflection_digest_scheme
    {
        return Err(format!(
            "statement bundle reflection digest scheme drifted for {}",
            statement_path.display()
        ));
    }

    let mut statement_program_labels = statement_bundle
        .artifact_bindings
        .program_labels
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut manifest_program_labels = BTreeSet::new();
    let mut statement_metallib_digests = statement_bundle
        .artifact_bindings
        .metallib_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut statement_reflection_digests = statement_bundle
        .artifact_bindings
        .reflection_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut statement_pipeline_digests = statement_bundle
        .artifact_bindings
        .pipeline_descriptor_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    for artifact in &attestation.artifacts {
        ensure_hex_digest(
            &artifact.metallib_digest,
            &format!(
                "{} artifact metallib digest for {}:{}",
                attestation_path.display(),
                artifact.kernel_program_label,
                artifact.entrypoint_label
            ),
        )?;
        ensure_hex_digest(
            &artifact.reflection_digest,
            &format!(
                "{} artifact reflection digest for {}:{}",
                attestation_path.display(),
                artifact.kernel_program_label,
                artifact.entrypoint_label
            ),
        )?;
        ensure_hex_digest(
            &artifact.pipeline_descriptor_digest,
            &format!(
                "{} artifact pipeline digest for {}:{}",
                attestation_path.display(),
                artifact.kernel_program_label,
                artifact.entrypoint_label
            ),
        )?;
        let metallib_path = repo.join(&artifact.metallib_path);
        let metallib_digest = sha256_file(&metallib_path)?;
        if metallib_digest != artifact.metallib_digest {
            return Err(format!(
                "metallib digest mismatch for {}: expected {}, got {}",
                metallib_path.display(),
                artifact.metallib_digest,
                metallib_digest
            ));
        }
        manifest_program_labels.insert(artifact.kernel_program_label.clone());
        statement_metallib_digests.remove(&artifact.metallib_digest);
        statement_reflection_digests.remove(&artifact.reflection_digest);
        statement_pipeline_digests.remove(&artifact.pipeline_descriptor_digest);
        statement_program_labels.remove(&artifact.kernel_program_label);
    }

    let statement_program_label_set = statement_bundle
        .artifact_bindings
        .program_labels
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if manifest_program_labels != statement_program_label_set {
        return Err(format!(
            "program-label set drifted between {} and {}",
            statement_path.display(),
            attestation_path.display()
        ));
    }
    if !statement_program_labels.is_empty() {
        return Err(format!(
            "statement bundle {} references program labels absent from {}: {}",
            statement_path.display(),
            attestation_path.display(),
            statement_program_labels
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !statement_metallib_digests.is_empty()
        || !statement_reflection_digests.is_empty()
        || !statement_pipeline_digests.is_empty()
    {
        return Err(format!(
            "statement bundle {} drifted from artifact digests in {}",
            statement_path.display(),
            attestation_path.display()
        ));
    }

    let actual_metallib_root = metallib_digest_set_root(&attestation.artifacts);
    if actual_metallib_root != attestation.metallib_digest_set_root {
        return Err(format!(
            "metallib digest-set root mismatch in {}: expected {}, got {}",
            attestation_path.display(),
            attestation.metallib_digest_set_root,
            actual_metallib_root
        ));
    }

    let proof_path = repo.join(&manifest.proof_bundle_path);
    let proof_bytes = fs::read(&proof_path)
        .map_err(|err| format!("failed to read {}: {err}", proof_path.display()))?;
    let proof_digest = sha256_hex(&proof_bytes);
    if proof_digest != manifest.proof_bundle_digest {
        return Err(format!(
            "proof bundle digest mismatch for {}: expected {}, got {}",
            proof_path.display(),
            manifest.proof_bundle_digest,
            proof_digest
        ));
    }

    let verification_key_path = repo.join(&manifest.verification_key_path);
    let verification_key_bytes = fs::read(&verification_key_path).map_err(|err| {
        format!(
            "failed to read verification key {}: {err}",
            verification_key_path.display()
        )
    })?;
    let verification_key_digest = sha256_hex(&verification_key_bytes);
    if verification_key_digest != manifest.verification_key_digest {
        return Err(format!(
            "verification-key digest mismatch for {}: expected {}, got {}",
            verification_key_path.display(),
            manifest.verification_key_digest,
            verification_key_digest
        ));
    }

    let proof_bundle: PublicGroth16ProofBundle =
        bincode::deserialize(&proof_bytes).map_err(|err| {
            format!(
                "invalid public Groth16 proof-bundle serialization in {}: {err}",
                proof_path.display()
            )
        })?;
    if proof_bundle.schema != PUBLIC_GROTH16_PROOF_SCHEMA {
        return Err(format!(
            "{} has unexpected proof-bundle schema: {}",
            proof_path.display(),
            proof_bundle.schema
        ));
    }
    if proof_bundle.proof_system != PUBLIC_PROOF_SYSTEM {
        return Err(format!(
            "{} has unexpected proof system: {}",
            proof_path.display(),
            proof_bundle.proof_system
        ));
    }
    if proof_bundle.backend != PUBLIC_PROOF_BACKEND {
        return Err(format!(
            "{} has unexpected proof backend: {}",
            proof_path.display(),
            proof_bundle.backend
        ));
    }
    validate_public_input_bytes(&proof_bundle.public_input_bytes).map_err(|err| {
        format!(
            "invalid public input bytes in {}: {err}",
            proof_path.display()
        )
    })?;
    validate_public_groth16_proving_lane(&proof_bundle.proving_lane).map_err(|err| {
        format!(
            "invalid public proving lane in {}: {err}",
            proof_path.display()
        )
    })?;

    verify_groth16_bundle(
        &manifest.bundle_id,
        &proof_bundle,
        &verification_key_bytes,
        &verification_key_path,
    )?;

    let expected_public_values = expected_public_values(
        &attestation.statement_bundle_digest,
        &attestation.private_source_commitment_root,
        &attestation.metallib_digest_set_root,
        &manifest.attestation_manifest_digest,
        &attestation.toolchain_identity_digest,
        &computed_bundle_evidence_digest,
    )?;
    if expected_public_values.len() != EXPECTED_PUBLIC_INPUT_BYTES {
        return Err(format!(
            "unexpected public-value payload width for bundle {}: expected {} bytes, got {} bytes",
            manifest.bundle_id,
            EXPECTED_PUBLIC_INPUT_BYTES,
            expected_public_values.len()
        ));
    }
    if proof_bundle.public_input_bytes.as_slice() != expected_public_values.as_slice() {
        return Err(format!(
            "public-value payload mismatch for bundle {}: expected {} bytes, got {} bytes",
            manifest.bundle_id,
            expected_public_values.len(),
            proof_bundle.public_input_bytes.len()
        ));
    }

    Ok(BundleVerificationReport {
        bundle_id: manifest.bundle_id,
        manifest_path: manifest_path.display().to_string(),
        theorem_ids: manifest.theorem_ids,
        manifest_digest,
        attestation_manifest_digest: attestation_digest,
        statement_bundle_digest: statement_digest,
        bundle_evidence_digest: computed_bundle_evidence_digest,
        proof_bundle_digest: proof_digest,
        verification_key_digest,
        checked_artifacts: attestation.artifacts.len(),
        proof_verified: true,
        public_values_match: true,
    })
}

fn verify_groth16_bundle(
    bundle_id: &str,
    proof_bundle: &PublicGroth16ProofBundle,
    verification_key_bytes: &[u8],
    verification_key_path: &Path,
) -> Result<(), String> {
    let vk =
        VerifyingKey::<Bn254>::deserialize_compressed(verification_key_bytes).map_err(|err| {
            format!(
                "deserialize Groth16 verification key {}: {err}",
                verification_key_path.display()
            )
        })?;
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bundle.proof_bytes.as_slice())
        .map_err(|err| {
            format!(
                "deserialize Groth16 proof bundle {} from {}: {err}",
                bundle_id,
                verification_key_path.display()
            )
        })?;
    let public_inputs = proof_bundle
        .public_input_bytes
        .iter()
        .map(|byte| Fr::from(u64::from(*byte)))
        .collect::<Vec<_>>();
    Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .map_err(|err| {
            format!(
                "Groth16 verification failed for bundle {} using {}: {err}",
                bundle_id,
                verification_key_path.display()
            )
        })
        .and_then(|verified| {
            if verified {
                Ok(())
            } else {
                Err(format!(
                    "Groth16 verification returned false for bundle {} using {}",
                    bundle_id,
                    verification_key_path.display()
                ))
            }
        })
}

fn toolchain_identity_digest(identity: &ToolchainIdentity) -> String {
    let payload = format!(
        "metal_compiler_version={}\nxcode_version={}\nsdk_version={}\n",
        identity.metal_compiler_version, identity.xcode_version, identity.sdk_version
    );
    sha256_hex(payload.as_bytes())
}

fn metallib_digest_set_root(artifacts: &[PublicArtifactBinding]) -> String {
    let mut digests = artifacts
        .iter()
        .map(|artifact| artifact.metallib_digest.as_str())
        .collect::<Vec<_>>();
    digests.sort_unstable();
    digests.dedup();
    let joined = digests.join("\n");
    sha256_hex(joined.as_bytes())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn ensure_hex_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a lowercase SHA-256 hex digest"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_hex_digest_accepts_valid_sha256() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ensure_hex_digest(digest, "manifest digest").expect("valid digest");
    }

    #[test]
    fn ensure_hex_digest_rejects_invalid_input() {
        let err = ensure_hex_digest("XYZ", "manifest digest").expect_err("invalid digest");
        assert!(err.contains("manifest digest"));
    }

    #[test]
    fn metallib_digest_set_root_is_order_independent() {
        let a = PublicArtifactBinding {
            kernel_program_label: "prog-a".to_string(),
            entrypoint_label: "kernelA".to_string(),
            metallib_path: "bin/a.metallib".to_string(),
            metallib_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            reflection_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            pipeline_descriptor_digest:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        };
        let b = PublicArtifactBinding {
            kernel_program_label: "prog-b".to_string(),
            entrypoint_label: "kernelB".to_string(),
            metallib_path: "bin/b.metallib".to_string(),
            metallib_digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                .to_string(),
            reflection_digest: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .to_string(),
            pipeline_descriptor_digest:
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        };

        let first = metallib_digest_set_root(&[a.clone(), b.clone()]);
        let second = metallib_digest_set_root(&[b, a]);
        assert_eq!(first, second);
    }
}
