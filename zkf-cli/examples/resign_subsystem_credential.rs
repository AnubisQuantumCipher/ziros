use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_87::{generate_key_pair, sign as mldsa_sign};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use zkf_core::{PublicKeyBundle, SignatureBundle, SignatureScheme};

const SUBSYSTEM_CREDENTIAL_CONTEXT: &[u8] = b"zkf-subsystem-credential-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubsystemCredentialV1 {
    schema: String,
    subsystem_id: String,
    circuit_id: String,
    backend_policy: String,
    backend: String,
    program_digest: String,
    compiled_digest: String,
    proof_digest: String,
    verification_passed: bool,
    audit_failed_checks: usize,
    generated_at: String,
}

fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn sign_payload(bytes: &[u8]) -> Result<(PublicKeyBundle, SignatureBundle), String> {
    let mut ed25519_seed = [0u8; 32];
    zkf_core::secure_random::secure_random_bytes(&mut ed25519_seed)
        .map_err(|error| error.to_string())?;
    let ed25519_signing_key = SigningKey::from_bytes(&ed25519_seed);
    let ed25519_signature = ed25519_signing_key.sign(bytes).to_bytes().to_vec();

    let keypair = generate_key_pair(secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?);
    let ml_dsa_signature = mldsa_sign(
        &keypair.signing_key,
        bytes,
        SUBSYSTEM_CREDENTIAL_CONTEXT,
        secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?,
    )
    .map_err(|error| format!("failed to sign subsystem credential payload with ML-DSA-87: {error:?}"))?;

    Ok((
        PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signing_key.verifying_key().to_bytes().to_vec(),
            ml_dsa87: keypair.verification_key.as_slice().to_vec(),
        },
        SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signature,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        },
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env::args().nth(1).ok_or("usage: resign_subsystem_credential <subsystem_root>")?);
    let credential_path = root.join("11_credentials/subsystem_credential.json");
    let public_keys_path = root.join("12_signatures/subsystem_credential_public_keys.json");
    let signature_path = root.join("12_signatures/subsystem_credential_signature.json");

    let credential: SubsystemCredentialV1 = serde_json::from_slice(&fs::read(&credential_path)?)?;
    let bytes = serde_json::to_vec(&credential)?;
    let (public_keys, signature_bundle) = sign_payload(&bytes).map_err(std::io::Error::other)?;

    fs::create_dir_all(public_keys_path.parent().ok_or("missing signatures parent")?)?;
    fs::write(&public_keys_path, serde_json::to_vec_pretty(&public_keys)?)?;
    fs::write(&signature_path, serde_json::to_vec_pretty(&signature_bundle)?)?;
    println!("{}", root.display());
    Ok(())
}
