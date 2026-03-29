use crate::cli::CredentialCommands;
use crate::util::{read_json, write_json};
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_87::{
    MLDSA87SigningKey, MLDSA87VerificationKey, generate_key_pair, sign as mldsa_sign,
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zkf_core::{
    CredentialClaimsV1, FieldElement, IssuerSignedCredentialV1, PublicKeyBundle, SignatureBundle,
    SignatureScheme,
};
use zkf_lib::{
    PRIVATE_IDENTITY_ML_DSA_CONTEXT, PrivateIdentityPolicyV1, PrivateIdentityProveRequestV1,
    PrivateIdentityRegistryV1, active_leaf_from_credential_id, credential_id_from_claims,
    prove_private_identity, verify_private_identity_artifact,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialIssuerKeyFileV1 {
    version: u32,
    ed25519_seed: [u8; 32],
    ml_dsa87_signing_key: Vec<u8>,
    ml_dsa87_public_key: Vec<u8>,
}

impl CredentialIssuerKeyFileV1 {
    fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: SigningKey::from_bytes(&self.ed25519_seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            ml_dsa87: self.ml_dsa87_public_key.clone(),
        }
    }

    fn signing_key(&self) -> Result<MLDSA87SigningKey, String> {
        let bytes: [u8; MLDSA87SigningKey::len()] = self
            .ml_dsa87_signing_key
            .clone()
            .try_into()
            .map_err(|_| "issuer ML-DSA signing key file is corrupt".to_string())?;
        Ok(MLDSA87SigningKey::new(bytes))
    }

    fn validate(&self) -> Result<(), String> {
        if self.ml_dsa87_signing_key.len() != MLDSA87SigningKey::len() {
            return Err("issuer ML-DSA signing key file is corrupt".to_string());
        }
        if self.ml_dsa87_public_key.len() != MLDSA87VerificationKey::len() {
            return Err("issuer ML-DSA public key file is corrupt".to_string());
        }
        Ok(())
    }
}

pub(crate) fn handle_credential(command: CredentialCommands) -> Result<(), String> {
    match command {
        CredentialCommands::Issue {
            secret,
            salt,
            age_years,
            status_flags,
            expires_at_epoch_day,
            issuer_registry,
            active_registry,
            issuer_key,
            out,
            slot,
        } => handle_issue(
            &secret,
            &salt,
            age_years,
            status_flags,
            expires_at_epoch_day,
            &issuer_registry,
            &active_registry,
            &issuer_key,
            &out,
            slot,
        ),
        CredentialCommands::Prove {
            credential,
            secret,
            salt,
            issuer_registry,
            active_registry,
            required_age,
            required_status_mask,
            current_epoch_day,
            backend,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            out,
            compiled_out,
        } => handle_prove(
            &credential,
            &secret,
            &salt,
            &issuer_registry,
            &active_registry,
            PrivateIdentityPolicyV1 {
                required_age,
                required_status_mask,
                current_epoch_day,
            },
            backend.as_deref(),
            groth16_setup_blob.as_deref(),
            allow_dev_deterministic_groth16,
            &out,
            compiled_out.as_deref(),
        ),
        CredentialCommands::Verify {
            artifact,
            issuer_root,
            active_root,
            required_age,
            required_status_mask,
            current_epoch_day,
        } => handle_verify(
            &artifact,
            issuer_root.as_deref(),
            active_root.as_deref(),
            required_age,
            required_status_mask,
            current_epoch_day,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_issue(
    secret: &str,
    salt: &str,
    age_years: u8,
    status_flags: u32,
    expires_at_epoch_day: u32,
    issuer_registry_path: &Path,
    active_registry_path: &Path,
    issuer_key_path: &Path,
    out: &Path,
    slot: usize,
) -> Result<(), String> {
    if slot >= zkf_lib::PRIVATE_IDENTITY_TREE_LEAVES {
        return Err(format!(
            "slot {slot} is out of range for {}-entry private identity registries",
            zkf_lib::PRIVATE_IDENTITY_TREE_LEAVES
        ));
    }

    let issuer_keys = load_or_create_issuer_keys(issuer_key_path)?;
    let subject_key_hash = zkf_core::derive_subject_key_hash(secret.as_bytes(), salt.as_bytes())?;
    let base_claims = CredentialClaimsV1 {
        subject_key_hash,
        age_years,
        status_flags,
        expires_at_epoch_day,
        issuer_tree_root: FieldElement::ZERO,
        active_tree_root: FieldElement::ZERO,
        tree_depth: CredentialClaimsV1::FIXED_TREE_DEPTH,
    };
    base_claims.validate()?;

    let credential_id = credential_id_from_claims(&base_claims)?;
    let active_leaf = active_leaf_from_credential_id(&credential_id)?;

    let mut issuer_registry = load_or_zero_registry(issuer_registry_path)?;
    let mut active_registry = load_or_zero_registry(active_registry_path)?;
    ensure_slot_compatible(&issuer_registry, slot, &credential_id, "issuer")?;
    ensure_slot_compatible(&active_registry, slot, &active_leaf, "active")?;
    issuer_registry.set_leaf(slot, credential_id.clone())?;
    active_registry.set_leaf(slot, active_leaf)?;

    let claims = CredentialClaimsV1 {
        issuer_tree_root: issuer_registry.root()?,
        active_tree_root: active_registry.root()?,
        ..base_claims
    };
    let signed_credential = sign_credential_claims(&issuer_keys, claims)?;

    issuer_registry.store(issuer_registry_path)?;
    active_registry.store(active_registry_path)?;
    write_json(out, &signed_credential)?;

    println!(
        "credential issued: slot={} credential_id={} issuer_root={} active_root={}",
        slot,
        credential_id,
        signed_credential.claims.issuer_tree_root,
        signed_credential.claims.active_tree_root
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_prove(
    credential_path: &Path,
    secret: &str,
    salt: &str,
    issuer_registry_path: &Path,
    active_registry_path: &Path,
    policy: PrivateIdentityPolicyV1,
    backend: Option<&str>,
    groth16_setup_blob: Option<&Path>,
    allow_dev_deterministic_groth16: bool,
    out: &Path,
    compiled_out: Option<&Path>,
) -> Result<(), String> {
    let signed_credential: IssuerSignedCredentialV1 = read_json(credential_path)?;
    let issuer_registry = PrivateIdentityRegistryV1::load(issuer_registry_path)?;
    let active_registry = PrivateIdentityRegistryV1::load(active_registry_path)?;
    let proof = prove_private_identity(&PrivateIdentityProveRequestV1 {
        signed_credential,
        subject_secret: secret.as_bytes().to_vec(),
        subject_salt: salt.as_bytes().to_vec(),
        issuer_registry,
        active_registry,
        policy,
        backend: backend.map(str::to_string),
        groth16_setup_blob: groth16_setup_blob.map(|path| path.display().to_string()),
        allow_dev_deterministic_groth16,
    })?;

    write_json(out, &proof.artifact)?;
    if let Some(compiled_out) = compiled_out {
        write_json(compiled_out, &proof.compiled)?;
    }
    println!(
        "credential proof created: backend={} artifact={}",
        proof.artifact.backend,
        out.display()
    );
    Ok(())
}

fn handle_verify(
    artifact_path: &Path,
    issuer_root: Option<&str>,
    active_root: Option<&str>,
    required_age: Option<u8>,
    required_status_mask: Option<u32>,
    current_epoch_day: Option<u32>,
) -> Result<(), String> {
    let artifact = read_json(artifact_path)?;
    let expected = parse_expected_public_inputs(
        issuer_root,
        active_root,
        required_age,
        required_status_mask,
        current_epoch_day,
        &artifact,
    )?;
    let report = verify_private_identity_artifact(&artifact, expected.as_ref())?;
    println!(
        "credential proof verified: backend={} mode={} issuer_root={} active_root={}",
        report.backend,
        report.verification_mode,
        report.public_inputs.issuer_tree_root,
        report.public_inputs.active_tree_root
    );
    Ok(())
}

fn parse_expected_public_inputs(
    issuer_root: Option<&str>,
    active_root: Option<&str>,
    required_age: Option<u8>,
    required_status_mask: Option<u32>,
    current_epoch_day: Option<u32>,
    artifact: &zkf_core::ProofArtifact,
) -> Result<Option<zkf_lib::CredentialPublicInputsV1>, String> {
    let any = issuer_root.is_some()
        || active_root.is_some()
        || required_age.is_some()
        || required_status_mask.is_some()
        || current_epoch_day.is_some();
    if !any {
        return Ok(None);
    }

    let Some(issuer_root) = issuer_root else {
        return Err(
            "issuer_root is required when verifying against an explicit policy".to_string(),
        );
    };
    let Some(active_root) = active_root else {
        return Err(
            "active_root is required when verifying against an explicit policy".to_string(),
        );
    };
    let Some(required_age) = required_age else {
        return Err(
            "required_age is required when verifying against an explicit policy".to_string(),
        );
    };
    let Some(required_status_mask) = required_status_mask else {
        return Err(
            "required_status_mask is required when verifying against an explicit policy"
                .to_string(),
        );
    };
    let Some(current_epoch_day) = current_epoch_day else {
        return Err(
            "current_epoch_day is required when verifying against an explicit policy".to_string(),
        );
    };
    let _actual = zkf_lib::private_identity_public_inputs_from_artifact(artifact)?;
    Ok(Some(zkf_lib::CredentialPublicInputsV1 {
        issuer_tree_root: FieldElement::new(issuer_root.to_string()),
        active_tree_root: FieldElement::new(active_root.to_string()),
        required_age,
        required_status_mask,
        current_epoch_day,
    }))
}

fn load_or_zero_registry(path: &Path) -> Result<PrivateIdentityRegistryV1, String> {
    if path.exists() {
        PrivateIdentityRegistryV1::load(path)
    } else {
        Ok(PrivateIdentityRegistryV1::zeroed())
    }
}

fn ensure_slot_compatible(
    registry: &PrivateIdentityRegistryV1,
    slot: usize,
    expected_leaf: &FieldElement,
    label: &str,
) -> Result<(), String> {
    let current = registry
        .leaves
        .get(slot)
        .ok_or_else(|| format!("{label} registry slot {slot} is out of range"))?;
    if current != &FieldElement::ZERO && current != expected_leaf {
        return Err(format!(
            "{label} registry slot {slot} is already populated with a different leaf"
        ));
    }
    Ok(())
}

fn load_or_create_issuer_keys(path: &Path) -> Result<CredentialIssuerKeyFileV1, String> {
    if path.exists() {
        let key_file: CredentialIssuerKeyFileV1 = read_json(path)?;
        key_file.validate()?;
        return Ok(key_file);
    }

    let mut ed25519_seed = [0u8; 32];
    zkf_core::secure_random::secure_random_bytes(&mut ed25519_seed)
        .map_err(|err| err.to_string())?;
    let randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(randomness);
    let key_file = CredentialIssuerKeyFileV1 {
        version: 1,
        ed25519_seed,
        ml_dsa87_signing_key: keypair.signing_key.as_slice().to_vec(),
        ml_dsa87_public_key: keypair.verification_key.as_slice().to_vec(),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    write_json(path, &key_file)?;
    Ok(key_file)
}

fn sign_credential_claims(
    issuer_keys: &CredentialIssuerKeyFileV1,
    claims: CredentialClaimsV1,
) -> Result<IssuerSignedCredentialV1, String> {
    claims.validate()?;
    let signing_message = claims.canonical_bytes()?;
    let ed25519_signing_key = SigningKey::from_bytes(&issuer_keys.ed25519_seed);
    let ed25519_signature = ed25519_signing_key
        .sign(&signing_message)
        .to_bytes()
        .to_vec();
    let ml_dsa_signing_key = issuer_keys.signing_key()?;
    let randomness = secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?;
    let ml_dsa_signature = mldsa_sign(
        &ml_dsa_signing_key,
        &signing_message,
        PRIVATE_IDENTITY_ML_DSA_CONTEXT,
        randomness,
    )
    .map_err(|err| format!("failed to sign credential with ML-DSA-44: {err:?}"))?;

    Ok(IssuerSignedCredentialV1 {
        claims,
        issuer_public_keys: issuer_keys.public_key_bundle(),
        issuer_signature_bundle: SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signature,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        },
    })
}

fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|err| err.to_string())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn credential_issue_prove_verify_roundtrip() {
        let temp = tempdir().expect("tempdir");
        let issuer_registry = temp.path().join("issuer-registry.json");
        let active_registry = temp.path().join("active-registry.json");
        let issuer_key = temp.path().join("issuer-keys.json");
        let credential = temp.path().join("credential.json");
        let artifact = temp.path().join("artifact.json");

        handle_credential(CredentialCommands::Issue {
            secret: "subject-secret".to_string(),
            salt: "subject-salt".to_string(),
            age_years: 29,
            status_flags: CredentialClaimsV1::STATUS_KYC_PASSED
                | CredentialClaimsV1::STATUS_NOT_SANCTIONED,
            expires_at_epoch_day: 20_123,
            issuer_registry: issuer_registry.clone(),
            active_registry: active_registry.clone(),
            issuer_key,
            out: credential.clone(),
            slot: 4,
        })
        .expect("issue");

        handle_credential(CredentialCommands::Prove {
            credential: credential.clone(),
            secret: "subject-secret".to_string(),
            salt: "subject-salt".to_string(),
            issuer_registry: issuer_registry.clone(),
            active_registry: active_registry.clone(),
            required_age: 21,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
            current_epoch_day: 20_000,
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
            out: artifact.clone(),
            compiled_out: None,
        })
        .expect("prove");

        let issuer_root = PrivateIdentityRegistryV1::load(&issuer_registry)
            .expect("issuer registry")
            .root()
            .expect("issuer root")
            .to_string();
        let active_root = PrivateIdentityRegistryV1::load(&active_registry)
            .expect("active registry")
            .root()
            .expect("active root")
            .to_string();

        handle_credential(CredentialCommands::Verify {
            artifact: artifact.clone(),
            issuer_root: Some(issuer_root.clone()),
            active_root: Some(active_root.clone()),
            required_age: Some(21),
            required_status_mask: Some(CredentialClaimsV1::STATUS_KYC_PASSED),
            current_epoch_day: Some(20_000),
        })
        .expect("verify");

        let age_error = handle_credential(CredentialCommands::Prove {
            credential: credential.clone(),
            secret: "subject-secret".to_string(),
            salt: "subject-salt".to_string(),
            issuer_registry: issuer_registry.clone(),
            active_registry: active_registry.clone(),
            required_age: 40,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
            current_epoch_day: 20_000,
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
            out: artifact.clone(),
            compiled_out: None,
        })
        .expect_err("underage prove request should fail");
        assert!(age_error.contains("required age"));

        let status_error = handle_credential(CredentialCommands::Prove {
            credential: credential.clone(),
            secret: "subject-secret".to_string(),
            salt: "subject-salt".to_string(),
            issuer_registry: issuer_registry.clone(),
            active_registry: active_registry.clone(),
            required_age: 21,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED
                | CredentialClaimsV1::STATUS_ACCREDITED,
            current_epoch_day: 20_000,
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
            out: artifact.clone(),
            compiled_out: None,
        })
        .expect_err("status-mismatched prove request should fail");
        assert!(status_error.contains("required mask"));

        let expiry_error = handle_credential(CredentialCommands::Prove {
            credential: credential.clone(),
            secret: "subject-secret".to_string(),
            salt: "subject-salt".to_string(),
            issuer_registry: issuer_registry.clone(),
            active_registry: active_registry.clone(),
            required_age: 21,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
            current_epoch_day: 20_200,
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
            out: artifact.clone(),
            compiled_out: None,
        })
        .expect_err("expired prove request should fail");
        assert!(expiry_error.contains("expired"));

        let mut revoked_active_registry =
            PrivateIdentityRegistryV1::load(&active_registry).expect("active registry for revoke");
        revoked_active_registry
            .set_leaf(4, FieldElement::ZERO)
            .expect("clear active slot");
        revoked_active_registry
            .store(&active_registry)
            .expect("store revoked active registry");
        let revoked_error = handle_credential(CredentialCommands::Prove {
            credential: credential.clone(),
            secret: "subject-secret".to_string(),
            salt: "subject-salt".to_string(),
            issuer_registry: issuer_registry.clone(),
            active_registry: active_registry.clone(),
            required_age: 21,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
            current_epoch_day: 20_000,
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
            out: artifact.clone(),
            compiled_out: None,
        })
        .expect_err("revoked credential should fail");
        assert!(revoked_error.contains("active registry root does not match signed credential"));

        let proof_artifact: zkf_core::ProofArtifact = read_json(&artifact).expect("artifact json");
        let wrong_root_error = handle_credential(CredentialCommands::Verify {
            artifact: artifact.clone(),
            issuer_root: Some(FieldElement::from_i64(1).to_string()),
            active_root: Some(active_root.clone()),
            required_age: Some(21),
            required_status_mask: Some(CredentialClaimsV1::STATUS_KYC_PASSED),
            current_epoch_day: Some(20_000),
        })
        .expect_err("wrong issuer root should fail");
        assert!(wrong_root_error.contains("expected policy/root surface"));

        let artifact_without_bundle = temp.path().join("artifact-without-bundle.json");
        let mut missing_bundle = proof_artifact.clone();
        missing_bundle.credential_bundle = None;
        write_json(&artifact_without_bundle, &missing_bundle).expect("write tampered artifact");
        let missing_bundle_error = handle_credential(CredentialCommands::Verify {
            artifact: artifact_without_bundle,
            issuer_root: Some(issuer_root.clone()),
            active_root: Some(active_root.clone()),
            required_age: Some(21),
            required_status_mask: Some(CredentialClaimsV1::STATUS_KYC_PASSED),
            current_epoch_day: Some(20_000),
        })
        .expect_err("artifact without credential bundle should fail");
        assert!(missing_bundle_error.contains("credential bundle"));

        let artifact_with_bad_signature = temp.path().join("artifact-bad-signature.json");
        let mut bad_signature = proof_artifact.clone();
        bad_signature
            .credential_bundle
            .as_mut()
            .expect("credential bundle")
            .signed_credential
            .issuer_signature_bundle
            .ed25519[0] ^= 0x01;
        write_json(&artifact_with_bad_signature, &bad_signature)
            .expect("write bad-signature artifact");
        let bad_signature_error = handle_credential(CredentialCommands::Verify {
            artifact: artifact_with_bad_signature,
            issuer_root: Some(issuer_root.clone()),
            active_root: Some(active_root.clone()),
            required_age: Some(21),
            required_status_mask: Some(CredentialClaimsV1::STATUS_KYC_PASSED),
            current_epoch_day: Some(20_000),
        })
        .expect_err("artifact with tampered issuer signature should fail");
        assert!(bad_signature_error.contains("issuer signature bundle failed verification"));

        let artifact_with_bad_mode = temp.path().join("artifact-bad-mode.json");
        let mut bad_mode = proof_artifact;
        bad_mode.metadata.insert(
            "credential_verification_mode".to_string(),
            "tampered-mode".to_string(),
        );
        write_json(&artifact_with_bad_mode, &bad_mode).expect("write bad-mode artifact");
        let bad_mode_error = handle_credential(CredentialCommands::Verify {
            artifact: artifact_with_bad_mode,
            issuer_root: Some(issuer_root),
            active_root: Some(active_root),
            required_age: Some(21),
            required_status_mask: Some(CredentialClaimsV1::STATUS_KYC_PASSED),
            current_epoch_day: Some(20_000),
        })
        .expect_err("artifact with tampered verification mode should fail");
        assert!(bad_mode_error.contains("verification mode mismatch"));
    }
}
