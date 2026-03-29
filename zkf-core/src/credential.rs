use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use libcrux_ml_dsa::ml_dsa_44::{MLDSA44Signature, MLDSA44VerificationKey, verify as mldsa_verify};
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{FieldElement, FieldId, normalize_mod};

const CANONICAL_FIELD_BYTES: usize = 32;
const ARGON2_OUTPUT_BYTES: usize = 32;
const ARGON2_MEMORY_KIB: u32 = 4 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_LANES: u32 = 1;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureScheme {
    #[default]
    Ed25519,
    MlDsa44,
    HybridEd25519MlDsa44,
}

impl SignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa44 => "ml-dsa-44",
            Self::HybridEd25519MlDsa44 => "hybrid-ed25519-ml-dsa-44",
        }
    }

    fn canonical_tag(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::MlDsa44 => 2,
            Self::HybridEd25519MlDsa44 => 3,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct PublicKeyBundle {
    pub scheme: SignatureScheme,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ed25519: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ml_dsa44: Vec<u8>,
}

impl PublicKeyBundle {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.ed25519.len() + self.ml_dsa44.len() + 16);
        bytes.push(self.scheme.canonical_tag());
        bytes.extend_from_slice(&(self.ed25519.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ed25519);
        bytes.extend_from_slice(&(self.ml_dsa44.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ml_dsa44);
        bytes
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SignatureBundle {
    pub scheme: SignatureScheme,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ed25519: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ml_dsa44: Vec<u8>,
}

impl SignatureBundle {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.ed25519.len() + self.ml_dsa44.len() + 16);
        bytes.push(self.scheme.canonical_tag());
        bytes.extend_from_slice(&(self.ed25519.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ed25519);
        bytes.extend_from_slice(&(self.ml_dsa44.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ml_dsa44);
        bytes
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialClaimsV1 {
    pub subject_key_hash: FieldElement,
    pub age_years: u8,
    pub status_flags: u32,
    pub expires_at_epoch_day: u32,
    pub issuer_tree_root: FieldElement,
    pub active_tree_root: FieldElement,
    pub tree_depth: u8,
}

impl CredentialClaimsV1 {
    pub const FIXED_TREE_DEPTH: u8 = 5;
    pub const ALLOWED_STATUS_MASK: u32 = 0b111;
    pub const STATUS_KYC_PASSED: u32 = 1 << 0;
    pub const STATUS_NOT_SANCTIONED: u32 = 1 << 1;
    pub const STATUS_ACCREDITED: u32 = 1 << 2;

    pub fn validate(&self) -> Result<(), String> {
        if self.tree_depth != Self::FIXED_TREE_DEPTH {
            return Err(format!(
                "credential tree depth must be {} in v1; found {}",
                Self::FIXED_TREE_DEPTH,
                self.tree_depth
            ));
        }
        if self.status_flags & !Self::ALLOWED_STATUS_MASK != 0 {
            return Err(format!(
                "credential status flags must fit within mask {:#05b}; found {:#034b}",
                Self::ALLOWED_STATUS_MASK,
                self.status_flags
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(64 + (CANONICAL_FIELD_BYTES * 3));
        bytes.extend_from_slice(b"zkf-credential-claims-v1");
        bytes.extend_from_slice(&field_element_to_fixed_be_bytes(&self.subject_key_hash)?);
        bytes.push(self.age_years);
        bytes.extend_from_slice(&self.status_flags.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at_epoch_day.to_le_bytes());
        bytes.extend_from_slice(&field_element_to_fixed_be_bytes(&self.issuer_tree_root)?);
        bytes.extend_from_slice(&field_element_to_fixed_be_bytes(&self.active_tree_root)?);
        bytes.push(self.tree_depth);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerSignedCredentialV1 {
    pub claims: CredentialClaimsV1,
    pub issuer_public_keys: PublicKeyBundle,
    pub issuer_signature_bundle: SignatureBundle,
}

impl IssuerSignedCredentialV1 {
    pub fn signing_message(&self) -> Result<Vec<u8>, String> {
        self.claims.canonical_bytes()
    }

    pub fn verify(&self, ml_dsa_context: &[u8]) -> bool {
        let Ok(bytes) = self.signing_message() else {
            return false;
        };
        verify_bundle(
            &self.issuer_public_keys,
            &bytes,
            &self.issuer_signature_bundle,
            ml_dsa_context,
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialProofBundleV1 {
    pub signed_credential: IssuerSignedCredentialV1,
    pub credential_id: FieldElement,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verification_mode: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl Default for CredentialProofBundleV1 {
    fn default() -> Self {
        Self {
            signed_credential: IssuerSignedCredentialV1 {
                claims: CredentialClaimsV1 {
                    subject_key_hash: FieldElement::ZERO,
                    age_years: 0,
                    status_flags: 0,
                    expires_at_epoch_day: 0,
                    issuer_tree_root: FieldElement::ZERO,
                    active_tree_root: FieldElement::ZERO,
                    tree_depth: CredentialClaimsV1::FIXED_TREE_DEPTH,
                },
                issuer_public_keys: PublicKeyBundle::default(),
                issuer_signature_bundle: SignatureBundle::default(),
            },
            credential_id: FieldElement::ZERO,
            verification_mode: String::new(),
            metadata: BTreeMap::new(),
        }
    }
}

pub fn bundle_has_required_signature_material(
    public_keys: &PublicKeyBundle,
    signatures: &SignatureBundle,
) -> bool {
    if public_keys.scheme != signatures.scheme {
        return false;
    }
    match signatures.scheme {
        SignatureScheme::Ed25519 => {
            !public_keys.ed25519.is_empty() && !signatures.ed25519.is_empty()
        }
        SignatureScheme::MlDsa44 => {
            !public_keys.ml_dsa44.is_empty() && !signatures.ml_dsa44.is_empty()
        }
        SignatureScheme::HybridEd25519MlDsa44 => {
            !public_keys.ed25519.is_empty()
                && !signatures.ed25519.is_empty()
                && !public_keys.ml_dsa44.is_empty()
                && !signatures.ml_dsa44.is_empty()
        }
    }
}

pub fn signed_message_has_complete_bundle_surface(
    public_key_bundle: Option<&PublicKeyBundle>,
    signature_bundle: Option<&SignatureBundle>,
) -> bool {
    match (public_key_bundle, signature_bundle) {
        (None, None) => true,
        (Some(public_keys), Some(signatures)) => {
            bundle_has_required_signature_material(public_keys, signatures)
        }
        _ => false,
    }
}

pub fn verify_ed25519_signature(public_key: &[u8], bytes: &[u8], signature: &[u8]) -> bool {
    let Ok(key_bytes): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature) else {
        return false;
    };
    verifying_key.verify(bytes, &signature).is_ok()
}

pub fn verify_ml_dsa_signature(
    public_key: &[u8],
    bytes: &[u8],
    signature: &[u8],
    context: &[u8],
) -> bool {
    let Ok(public_key): Result<[u8; MLDSA44VerificationKey::len()], _> = public_key.try_into()
    else {
        return false;
    };
    let Ok(signature): Result<[u8; MLDSA44Signature::len()], _> = signature.try_into() else {
        return false;
    };
    let verification_key = MLDSA44VerificationKey::new(public_key);
    let signature = MLDSA44Signature::new(signature);
    mldsa_verify(&verification_key, bytes, context, &signature).is_ok()
}

pub fn verify_bundle(
    public_keys: &PublicKeyBundle,
    bytes: &[u8],
    signatures: &SignatureBundle,
    ml_dsa_context: &[u8],
) -> bool {
    if !bundle_has_required_signature_material(public_keys, signatures) {
        return false;
    }
    match signatures.scheme {
        SignatureScheme::Ed25519 => {
            verify_ed25519_signature(&public_keys.ed25519, bytes, &signatures.ed25519)
        }
        SignatureScheme::MlDsa44 => verify_ml_dsa_signature(
            &public_keys.ml_dsa44,
            bytes,
            &signatures.ml_dsa44,
            ml_dsa_context,
        ),
        SignatureScheme::HybridEd25519MlDsa44 => {
            verify_ed25519_signature(&public_keys.ed25519, bytes, &signatures.ed25519)
                && verify_ml_dsa_signature(
                    &public_keys.ml_dsa44,
                    bytes,
                    &signatures.ml_dsa44,
                    ml_dsa_context,
                )
        }
    }
}

pub fn verify_signed_message(
    legacy_public_key: &[u8],
    public_key_bundle: Option<&PublicKeyBundle>,
    bytes: &[u8],
    legacy_signature: &[u8],
    signature_bundle: Option<&SignatureBundle>,
    ml_dsa_context: &[u8],
) -> bool {
    if !signed_message_has_complete_bundle_surface(public_key_bundle, signature_bundle) {
        return false;
    }
    match (public_key_bundle, signature_bundle) {
        (Some(public_keys), Some(signatures)) => {
            verify_bundle(public_keys, bytes, signatures, ml_dsa_context)
        }
        (None, None) => verify_ed25519_signature(legacy_public_key, bytes, legacy_signature),
        _ => false,
    }
}

pub fn derive_subject_key_hash(secret: &[u8], salt: &[u8]) -> Result<FieldElement, String> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
        Some(ARGON2_OUTPUT_BYTES),
    )
    .map_err(|err| format!("argon2 params: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut stretched = [0u8; ARGON2_OUTPUT_BYTES];
    let normalized_salt;
    let salt = if salt.len() >= 8 {
        salt
    } else {
        normalized_salt = Sha256::digest(salt).to_vec();
        normalized_salt.as_slice()
    };
    argon2
        .hash_password_into(secret, salt, &mut stretched)
        .map_err(|err| format!("argon2 subject key derivation failed: {err}"))?;

    let digest = Sha256::digest(stretched);
    let bigint = BigInt::from_bytes_be(Sign::Plus, digest.as_ref());
    let reduced = normalize_mod(bigint, FieldId::Bn254.modulus());
    Ok(FieldElement::from_bigint_with_field(
        reduced,
        FieldId::Bn254,
    ))
}

fn field_element_to_fixed_be_bytes(
    value: &FieldElement,
) -> Result<[u8; CANONICAL_FIELD_BYTES], String> {
    let bigint = value
        .normalized_bigint(FieldId::Bn254)
        .map_err(|err| err.to_string())?;
    let (_, bytes) = bigint.to_bytes_be();
    if bytes.len() > CANONICAL_FIELD_BYTES {
        return Err(format!(
            "field element exceeds {} canonical bytes",
            CANONICAL_FIELD_BYTES
        ));
    }
    let mut fixed = [0u8; CANONICAL_FIELD_BYTES];
    let start = CANONICAL_FIELD_BYTES - bytes.len();
    fixed[start..].copy_from_slice(&bytes);
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_44::{generate_key_pair, sign as mldsa_sign};
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};

    const TEST_CONTEXT: &[u8] = b"zkf-core-test";

    fn sample_claims() -> CredentialClaimsV1 {
        CredentialClaimsV1 {
            subject_key_hash: FieldElement::from_i64(7),
            age_years: 29,
            status_flags: CredentialClaimsV1::STATUS_KYC_PASSED
                | CredentialClaimsV1::STATUS_NOT_SANCTIONED,
            expires_at_epoch_day: 20_001,
            issuer_tree_root: FieldElement::from_i64(11),
            active_tree_root: FieldElement::from_i64(13),
            tree_depth: CredentialClaimsV1::FIXED_TREE_DEPTH,
        }
    }

    #[test]
    fn public_key_bundle_canonical_bytes_are_stable() {
        let bundle = PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: vec![1, 2, 3],
            ml_dsa44: vec![4, 5],
        };
        assert_eq!(
            bundle.canonical_bytes(),
            vec![3, 3, 0, 0, 0, 1, 2, 3, 2, 0, 0, 0, 4, 5]
        );
    }

    #[test]
    fn hybrid_bundle_completeness_fails_closed() {
        let public_keys = PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: vec![1; 32],
            ml_dsa44: vec![2; 16],
        };
        let missing_ml_dsa = SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa44,
            ed25519: vec![3; 64],
            ml_dsa44: vec![],
        };
        assert!(!bundle_has_required_signature_material(
            &public_keys,
            &missing_ml_dsa
        ));
        assert!(!signed_message_has_complete_bundle_surface(
            Some(&public_keys),
            None,
        ));
    }

    #[test]
    fn argon2_subject_key_derivation_is_stable_and_salt_sensitive() {
        let first = derive_subject_key_hash(b"secret", b"salt-1").expect("first hash");
        let second = derive_subject_key_hash(b"secret", b"salt-1").expect("second hash");
        let third = derive_subject_key_hash(b"secret", b"salt-2").expect("third hash");

        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn issuer_signed_credential_verifies_hybrid_signatures() {
        let claims = sample_claims();
        let message = claims.canonical_bytes().expect("canonical bytes");

        let ed25519_signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let ed25519_signature = ed25519_signing_key.sign(&message).to_bytes().to_vec();

        let keypair = generate_key_pair([5u8; KEY_GENERATION_RANDOMNESS_SIZE]);
        let ml_dsa_signature = mldsa_sign(
            &keypair.signing_key,
            &message,
            TEST_CONTEXT,
            [9u8; SIGNING_RANDOMNESS_SIZE],
        )
        .expect("ml-dsa signature");

        let credential = IssuerSignedCredentialV1 {
            claims,
            issuer_public_keys: PublicKeyBundle {
                scheme: SignatureScheme::HybridEd25519MlDsa44,
                ed25519: ed25519_signing_key.verifying_key().to_bytes().to_vec(),
                ml_dsa44: keypair.verification_key.as_slice().to_vec(),
            },
            issuer_signature_bundle: SignatureBundle {
                scheme: SignatureScheme::HybridEd25519MlDsa44,
                ed25519: ed25519_signature,
                ml_dsa44: ml_dsa_signature.as_slice().to_vec(),
            },
        };

        assert!(credential.verify(TEST_CONTEXT));
    }
}
