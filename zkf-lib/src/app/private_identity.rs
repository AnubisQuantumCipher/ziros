use acir::FieldElement as AcirFieldElement;
use acvm_blackbox_solver::BlackBoxFunctionSolver;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use std::thread;

use zkf_core::{
    BackendKind, CredentialClaimsV1, CredentialProofBundleV1, Expr, FieldElement, FieldId,
    IssuerSignedCredentialV1, Program, ProofArtifact, WitnessInputs,
};

use super::api::{EmbeddedProof, compile, compile_and_prove, verify};
use super::builder::ProgramBuilder;
use super::templates::TemplateProgram;

pub const PRIVATE_IDENTITY_TREE_DEPTH: usize = 5;
pub const PRIVATE_IDENTITY_TREE_LEAVES: usize = 1 << PRIVATE_IDENTITY_TREE_DEPTH;
pub const PRIVATE_IDENTITY_VERIFICATION_MODE: &str = "proof-plus-hybrid-signed-issuer-v1";
pub const PRIVATE_IDENTITY_BINDING_MODE: &str = "claims-bound-program-v1";
pub const PRIVATE_IDENTITY_ML_DSA_CONTEXT: &[u8] = b"zkf-private-identity-v1";
pub const PRIVATE_IDENTITY_PUBLIC_INPUTS_LEN: usize = 5;
const SOURCE_PROGRAM_DIGEST_METADATA_KEY: &str = "source_program_digest";
const COMPILED_PROGRAM_DIGEST_METADATA_KEY: &str = "compiled_program_digest";

thread_local! {
    static PRIVATE_IDENTITY_POSEIDON_SOLVER: OnceCell<Bn254BlackBoxSolver> = const { OnceCell::new() };
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct PrivateIdentityRegistryV1 {
    #[serde(default = "default_registry_version")]
    pub version: u32,
    #[serde(default = "zeroed_registry_leaves")]
    pub leaves: Vec<FieldElement>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerklePathNodeV1 {
    pub sibling: FieldElement,
    pub direction: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateIdentityPolicyV1 {
    pub required_age: u8,
    pub required_status_mask: u32,
    pub current_epoch_day: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialPublicInputsV1 {
    pub issuer_tree_root: FieldElement,
    pub active_tree_root: FieldElement,
    pub required_age: u8,
    pub required_status_mask: u32,
    pub current_epoch_day: u32,
}

#[derive(Debug, Clone)]
pub struct PrivateIdentityProveRequestV1 {
    pub signed_credential: IssuerSignedCredentialV1,
    pub subject_secret: Vec<u8>,
    pub subject_salt: Vec<u8>,
    pub issuer_registry: PrivateIdentityRegistryV1,
    pub active_registry: PrivateIdentityRegistryV1,
    pub policy: PrivateIdentityPolicyV1,
    pub backend: Option<String>,
    pub groth16_setup_blob: Option<String>,
    pub allow_dev_deterministic_groth16: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateIdentityPathProveRequestV1 {
    pub signed_credential: IssuerSignedCredentialV1,
    pub subject_secret: Vec<u8>,
    pub subject_salt: Vec<u8>,
    pub issuer_tree_root: FieldElement,
    pub active_tree_root: FieldElement,
    pub issuer_path: Vec<MerklePathNodeV1>,
    pub active_path: Vec<MerklePathNodeV1>,
    pub policy: PrivateIdentityPolicyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groth16_setup_blob: Option<String>,
    #[serde(default)]
    pub allow_dev_deterministic_groth16: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateIdentityVerificationReportV1 {
    pub backend: String,
    pub verification_mode: String,
    pub public_inputs: CredentialPublicInputsV1,
}

impl Default for PrivateIdentityPolicyV1 {
    fn default() -> Self {
        Self {
            required_age: 18,
            required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
            current_epoch_day: 0,
        }
    }
}

impl PrivateIdentityPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.required_status_mask & !CredentialClaimsV1::ALLOWED_STATUS_MASK != 0 {
            return Err(format!(
                "required status mask must fit within {:#05b}; found {:#034b}",
                CredentialClaimsV1::ALLOWED_STATUS_MASK,
                self.required_status_mask
            ));
        }
        Ok(())
    }
}

fn validate_claims_against_policy(
    claims: &CredentialClaimsV1,
    policy: &PrivateIdentityPolicyV1,
) -> Result<(), String> {
    claims.validate()?;
    policy.validate()?;
    if claims.age_years < policy.required_age {
        return Err(format!(
            "credential age {} does not satisfy required age {}",
            claims.age_years, policy.required_age
        ));
    }
    if claims.status_flags & policy.required_status_mask != policy.required_status_mask {
        return Err(format!(
            "credential status flags {:#05b} do not satisfy required mask {:#05b}",
            claims.status_flags, policy.required_status_mask
        ));
    }
    if claims.expires_at_epoch_day < policy.current_epoch_day {
        return Err(format!(
            "credential expired at epoch day {} before current epoch day {}",
            claims.expires_at_epoch_day, policy.current_epoch_day
        ));
    }
    Ok(())
}

impl PrivateIdentityRegistryV1 {
    pub fn zeroed() -> Self {
        Self {
            version: default_registry_version(),
            leaves: zeroed_registry_leaves(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let registry: Self = serde_json::from_slice(&bytes)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;
        registry.validate()?;
        Ok(registry)
    }

    pub fn store(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|err| format!("failed to serialize registry: {err}"))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        }
        std::fs::write(path, bytes)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.leaves.len() != PRIVATE_IDENTITY_TREE_LEAVES {
            return Err(format!(
                "registry must contain exactly {} leaves; found {}",
                PRIVATE_IDENTITY_TREE_LEAVES,
                self.leaves.len()
            ));
        }
        Ok(())
    }

    pub fn root(&self) -> Result<FieldElement, String> {
        self.validate()?;
        merkle_root_bn254(&self.leaves)
    }

    pub fn set_leaf(&mut self, index: usize, leaf: FieldElement) -> Result<(), String> {
        self.validate()?;
        let Some(slot) = self.leaves.get_mut(index) else {
            return Err(format!("registry index {index} is out of range"));
        };
        *slot = leaf;
        Ok(())
    }

    pub fn find_leaf(&self, leaf: &FieldElement) -> Option<usize> {
        self.leaves.iter().position(|candidate| candidate == leaf)
    }

    pub fn authentication_path(&self, index: usize) -> Result<Vec<MerklePathNodeV1>, String> {
        self.validate()?;
        if index >= self.leaves.len() {
            return Err(format!("registry index {index} is out of range"));
        }

        let mut nodes = self.leaves.clone();
        let mut current_index = index;
        let mut path = Vec::with_capacity(PRIVATE_IDENTITY_TREE_DEPTH);
        for _ in 0..PRIVATE_IDENTITY_TREE_DEPTH {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };
            path.push(MerklePathNodeV1 {
                sibling: nodes[sibling_index].clone(),
                direction: (!current_index.is_multiple_of(2)) as u8,
            });
            nodes = nodes
                .chunks_exact(2)
                .map(|pair| {
                    poseidon_hash4_bn254(&[
                        pair[0].clone(),
                        pair[1].clone(),
                        FieldElement::ZERO,
                        FieldElement::ZERO,
                    ])
                })
                .collect::<Result<Vec<_>, _>>()?;
            current_index /= 2;
        }
        Ok(path)
    }
}

pub fn private_identity_kyc() -> zkf_core::ZkfResult<TemplateProgram> {
    let mut builder = ProgramBuilder::new("private_identity_kyc", FieldId::Bn254);
    builder.private_input("subject_key_hash")?;
    builder.private_input("age_years")?;
    builder.private_input("status_flags")?;
    builder.private_input("expires_at_epoch_day")?;
    builder.private_input("age_surplus")?;
    builder.private_input("expiry_surplus")?;
    builder.private_input("age_surplus_anchor")?;
    builder.private_input("expiry_surplus_anchor")?;
    for bit in 0..3 {
        builder.private_input(format!("status_bit_{bit}"))?;
        builder.private_input(format!("required_status_bit_{bit}"))?;
    }
    builder.public_input("issuer_tree_root")?;
    builder.public_input("active_tree_root")?;
    builder.public_input("required_age")?;
    builder.public_input("required_status_mask")?;
    builder.public_input("current_epoch_day")?;

    builder.constrain_range("age_years", 8)?;
    builder.constrain_range("status_flags", 3)?;
    builder.constrain_range("expires_at_epoch_day", 32)?;
    builder.constrain_range("required_age", 8)?;
    builder.constrain_range("required_status_mask", 3)?;
    builder.constrain_range("current_epoch_day", 32)?;

    builder.constant_signal("__private_identity_zero_0", FieldElement::ZERO)?;
    builder.constant_signal("__private_identity_zero_1", FieldElement::ZERO)?;
    builder.constant_signal("__private_identity_active_flag", FieldElement::ONE)?;

    let credential_id_signal = poseidon_round(
        &mut builder,
        "__private_identity_credential_id",
        &[
            Expr::signal("subject_key_hash"),
            Expr::signal("age_years"),
            Expr::signal("status_flags"),
            Expr::signal("expires_at_epoch_day"),
        ],
    )?;
    let active_leaf_signal = poseidon_round(
        &mut builder,
        "__private_identity_active_leaf",
        &[
            Expr::signal(&credential_id_signal),
            Expr::signal("__private_identity_active_flag"),
            Expr::signal("__private_identity_zero_0"),
            Expr::signal("__private_identity_zero_1"),
        ],
    )?;

    let mut expected_inputs = vec![
        "subject_key_hash".to_string(),
        "age_years".to_string(),
        "status_flags".to_string(),
        "expires_at_epoch_day".to_string(),
        "age_surplus".to_string(),
        "expiry_surplus".to_string(),
        "age_surplus_anchor".to_string(),
        "expiry_surplus_anchor".to_string(),
        "issuer_tree_root".to_string(),
        "active_tree_root".to_string(),
        "required_age".to_string(),
        "required_status_mask".to_string(),
        "current_epoch_day".to_string(),
    ];
    for bit in 0..3 {
        expected_inputs.push(format!("status_bit_{bit}"));
        expected_inputs.push(format!("required_status_bit_{bit}"));
    }

    append_merkle_membership(
        &mut builder,
        "issuer",
        &credential_id_signal,
        "issuer_tree_root",
        Some(&mut expected_inputs),
    )?;
    append_merkle_membership(
        &mut builder,
        "active",
        &active_leaf_signal,
        "active_tree_root",
        Some(&mut expected_inputs),
    )?;

    for bit in 0..3 {
        let status_bit = format!("status_bit_{bit}");
        let required_bit = format!("required_status_bit_{bit}");
        constrain_boolean_explicit(&mut builder, &status_bit)?;
        constrain_boolean_explicit(&mut builder, &required_bit)?;
        builder.constrain_equal(
            Expr::Mul(
                Box::new(Expr::signal(&required_bit)),
                Box::new(Expr::Sub(
                    Box::new(Expr::Const(FieldElement::ONE)),
                    Box::new(Expr::signal(&status_bit)),
                )),
            ),
            Expr::Const(FieldElement::ZERO),
        )?;
    }
    builder.constrain_equal(
        Expr::signal("status_flags"),
        bit_recombination_expr("status_bit_", 3),
    )?;
    builder.constrain_equal(
        Expr::signal("required_status_mask"),
        bit_recombination_expr("required_status_bit_", 3),
    )?;
    builder.constrain_equal(
        Expr::signal("age_surplus"),
        Expr::Sub(
            Box::new(Expr::signal("age_years")),
            Box::new(Expr::signal("required_age")),
        ),
    )?;
    builder.constrain_equal(
        Expr::Mul(
            Box::new(Expr::signal("age_surplus")),
            Box::new(Expr::signal("age_surplus_anchor")),
        ),
        Expr::signal("age_surplus"),
    )?;
    builder.constrain_range("age_surplus", 8)?;
    builder.constrain_equal(
        Expr::signal("expiry_surplus"),
        Expr::Sub(
            Box::new(Expr::signal("expires_at_epoch_day")),
            Box::new(Expr::signal("current_epoch_day")),
        ),
    )?;
    builder.constrain_equal(
        Expr::Mul(
            Box::new(Expr::signal("expiry_surplus")),
            Box::new(Expr::signal("expiry_surplus_anchor")),
        ),
        Expr::signal("expiry_surplus"),
    )?;
    builder.constrain_range("expiry_surplus", 32)?;

    let sample_subject_key_hash = FieldElement::from_i64(1234);
    let sample_age = 29u8;
    let sample_status =
        CredentialClaimsV1::STATUS_KYC_PASSED | CredentialClaimsV1::STATUS_NOT_SANCTIONED;
    let sample_expiry = 20_050u32;
    let sample_credential_id = poseidon_hash4_bn254(&[
        sample_subject_key_hash.clone(),
        FieldElement::from_u64(sample_age.into()),
        FieldElement::from_u64(sample_status.into()),
        FieldElement::from_u64(sample_expiry.into()),
    ])
    .map_err(zkf_core::ZkfError::InvalidArtifact)?;
    let sample_active_leaf = active_leaf_from_credential_id(&sample_credential_id)
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;

    let mut issuer_registry = PrivateIdentityRegistryV1::zeroed();
    let mut active_registry = PrivateIdentityRegistryV1::zeroed();
    issuer_registry
        .set_leaf(7, sample_credential_id.clone())
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;
    active_registry
        .set_leaf(7, sample_active_leaf)
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;

    let issuer_root = issuer_registry
        .root()
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;
    let active_root = active_registry
        .root()
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;
    let issuer_path = issuer_registry
        .authentication_path(7)
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;
    let active_path = active_registry
        .authentication_path(7)
        .map_err(zkf_core::ZkfError::InvalidArtifact)?;

    let mut sample_inputs = WitnessInputs::new();
    sample_inputs.insert("subject_key_hash".to_string(), sample_subject_key_hash);
    sample_inputs.insert(
        "age_years".to_string(),
        FieldElement::from_u64(sample_age.into()),
    );
    sample_inputs.insert(
        "status_flags".to_string(),
        FieldElement::from_u64(sample_status.into()),
    );
    sample_inputs.insert(
        "expires_at_epoch_day".to_string(),
        FieldElement::from_u64(sample_expiry.into()),
    );
    sample_inputs.insert(
        "age_surplus".to_string(),
        FieldElement::from_u64(u64::from(sample_age.saturating_sub(21))),
    );
    sample_inputs.insert("age_surplus_anchor".to_string(), FieldElement::ONE);
    sample_inputs.insert(
        "expiry_surplus".to_string(),
        FieldElement::from_u64(u64::from(sample_expiry - 20_000)),
    );
    sample_inputs.insert("expiry_surplus_anchor".to_string(), FieldElement::ONE);
    sample_inputs.insert("issuer_tree_root".to_string(), issuer_root.clone());
    sample_inputs.insert("active_tree_root".to_string(), active_root.clone());
    sample_inputs.insert("required_age".to_string(), FieldElement::from_u64(21));
    sample_inputs.insert(
        "required_status_mask".to_string(),
        FieldElement::from_u64(CredentialClaimsV1::STATUS_KYC_PASSED.into()),
    );
    sample_inputs.insert(
        "current_epoch_day".to_string(),
        FieldElement::from_u64(20_000),
    );
    insert_status_bits(&mut sample_inputs, "status_bit_", sample_status);
    insert_status_bits(
        &mut sample_inputs,
        "required_status_bit_",
        CredentialClaimsV1::STATUS_KYC_PASSED,
    );
    insert_path_inputs(&mut sample_inputs, "issuer", &issuer_path);
    insert_path_inputs(&mut sample_inputs, "active", &active_path);

    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(
        "required_status_bit_0".to_string(),
        FieldElement::from_u64(2),
    );

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs: vec![
            "issuer_tree_root".to_string(),
            "active_tree_root".to_string(),
            "required_age".to_string(),
            "required_status_mask".to_string(),
            "current_epoch_day".to_string(),
        ],
        sample_inputs,
        violation_inputs,
        description: "Prove policy-compliant possession of an issuer-signed private identity credential against fixed depth-5 Poseidon Merkle registries.",
    })
}

fn build_bound_private_identity_program(
    claims: &CredentialClaimsV1,
) -> zkf_core::ZkfResult<zkf_core::Program> {
    let mut builder = ProgramBuilder::new("private_identity_kyc_bound", FieldId::Bn254);
    builder.private_input("age_surplus")?;
    builder.private_input("expiry_surplus")?;
    builder.private_input("age_surplus_anchor")?;
    builder.private_input("expiry_surplus_anchor")?;
    for bit in 0..3 {
        builder.private_input(format!("required_status_bit_{bit}"))?;
    }
    builder.public_input("issuer_tree_root")?;
    builder.public_input("active_tree_root")?;
    builder.public_input("required_age")?;
    builder.public_input("required_status_mask")?;
    builder.public_input("current_epoch_day")?;

    builder.constrain_range("required_age", 8)?;
    builder.constrain_range("required_status_mask", 3)?;
    builder.constrain_range("current_epoch_day", 32)?;
    builder.constrain_range("age_surplus", 8)?;
    builder.constrain_range("expiry_surplus", 32)?;

    builder.constant_signal("__private_identity_zero_0", FieldElement::ZERO)?;
    builder.constant_signal("__private_identity_zero_1", FieldElement::ZERO)?;
    builder.constant_signal("__private_identity_active_flag", FieldElement::ONE)?;
    builder.constant_signal(
        "__private_identity_claim_subject_key_hash",
        claims.subject_key_hash.clone(),
    )?;
    builder.constant_signal(
        "__private_identity_claim_age_years",
        FieldElement::from_u64(claims.age_years.into()),
    )?;
    builder.constant_signal(
        "__private_identity_claim_status_flags",
        FieldElement::from_u64(claims.status_flags.into()),
    )?;
    builder.constant_signal(
        "__private_identity_claim_expires_at_epoch_day",
        FieldElement::from_u64(claims.expires_at_epoch_day.into()),
    )?;
    for bit in 0..3 {
        builder.constant_signal(
            format!("__private_identity_status_bit_{bit}"),
            FieldElement::from_u64(u64::from((claims.status_flags >> bit) & 1)),
        )?;
    }

    let credential_id_signal = poseidon_round(
        &mut builder,
        "__private_identity_credential_id",
        &[
            Expr::signal("__private_identity_claim_subject_key_hash"),
            Expr::signal("__private_identity_claim_age_years"),
            Expr::signal("__private_identity_claim_status_flags"),
            Expr::signal("__private_identity_claim_expires_at_epoch_day"),
        ],
    )?;
    let active_leaf_signal = poseidon_round(
        &mut builder,
        "__private_identity_active_leaf",
        &[
            Expr::signal(&credential_id_signal),
            Expr::signal("__private_identity_active_flag"),
            Expr::signal("__private_identity_zero_0"),
            Expr::signal("__private_identity_zero_1"),
        ],
    )?;

    append_merkle_membership(
        &mut builder,
        "issuer",
        &credential_id_signal,
        "issuer_tree_root",
        None,
    )?;
    append_merkle_membership(
        &mut builder,
        "active",
        &active_leaf_signal,
        "active_tree_root",
        None,
    )?;

    for bit in 0..3 {
        let status_bit = format!("__private_identity_status_bit_{bit}");
        let required_bit = format!("required_status_bit_{bit}");
        constrain_boolean_explicit(&mut builder, &required_bit)?;
        builder.constrain_equal(
            Expr::Mul(
                Box::new(Expr::signal(&required_bit)),
                Box::new(Expr::Sub(
                    Box::new(Expr::Const(FieldElement::ONE)),
                    Box::new(Expr::signal(&status_bit)),
                )),
            ),
            Expr::Const(FieldElement::ZERO),
        )?;
    }
    builder.constrain_equal(
        Expr::signal("required_status_mask"),
        bit_recombination_expr("required_status_bit_", 3),
    )?;
    builder.constrain_equal(
        Expr::signal("age_surplus"),
        Expr::Sub(
            Box::new(Expr::signal("__private_identity_claim_age_years")),
            Box::new(Expr::signal("required_age")),
        ),
    )?;
    builder.constrain_equal(
        Expr::Mul(
            Box::new(Expr::signal("age_surplus")),
            Box::new(Expr::signal("age_surplus_anchor")),
        ),
        Expr::signal("age_surplus"),
    )?;
    builder.constrain_equal(
        Expr::signal("expiry_surplus"),
        Expr::Sub(
            Box::new(Expr::signal(
                "__private_identity_claim_expires_at_epoch_day",
            )),
            Box::new(Expr::signal("current_epoch_day")),
        ),
    )?;
    builder.constrain_equal(
        Expr::Mul(
            Box::new(Expr::signal("expiry_surplus")),
            Box::new(Expr::signal("expiry_surplus_anchor")),
        ),
        Expr::signal("expiry_surplus"),
    )?;

    builder.build()
}

fn build_bound_private_identity_program_with_source_digest(
    claims: &CredentialClaimsV1,
) -> Result<(Program, String), String> {
    let program = build_bound_private_identity_program(claims).map_err(|err| err.to_string())?;
    let source_program_digest = program.digest_hex();
    Ok((program, source_program_digest))
}

pub fn credential_id_from_claims(claims: &CredentialClaimsV1) -> Result<FieldElement, String> {
    claims.validate()?;
    poseidon_hash4_bn254(&[
        claims.subject_key_hash.clone(),
        FieldElement::from_u64(claims.age_years.into()),
        FieldElement::from_u64(claims.status_flags.into()),
        FieldElement::from_u64(claims.expires_at_epoch_day.into()),
    ])
}

pub fn active_leaf_from_credential_id(
    credential_id: &FieldElement,
) -> Result<FieldElement, String> {
    poseidon_hash4_bn254(&[
        credential_id.clone(),
        FieldElement::ONE,
        FieldElement::ZERO,
        FieldElement::ZERO,
    ])
}

pub fn poseidon_permutation4_bn254(
    inputs: &[FieldElement; 4],
) -> Result<[FieldElement; 4], String> {
    PRIVATE_IDENTITY_POSEIDON_SOLVER.with(|cell| {
        let solver = cell.get_or_init(Bn254BlackBoxSolver::default);
        let acir_inputs = inputs
            .iter()
            .map(field_element_to_acir)
            .collect::<Result<Vec<_>, _>>()?;
        let outputs = solver
            .poseidon2_permutation(&acir_inputs, 4)
            .map_err(|err| format!("poseidon2 permutation failed: {err}"))?;
        if outputs.len() != 4 {
            return Err(format!(
                "poseidon2 permutation produced {} outputs instead of 4",
                outputs.len()
            ));
        }
        let mut lanes = Vec::with_capacity(4);
        for output in &outputs {
            lanes.push(acir_to_field_element(output)?);
        }
        lanes
            .try_into()
            .map_err(|_| "poseidon2 permutation output arity mismatch".to_string())
    })
}

pub fn poseidon_hash4_bn254(inputs: &[FieldElement; 4]) -> Result<FieldElement, String> {
    poseidon_permutation4_bn254(inputs).map(|lanes| lanes[0].clone())
}

pub fn merkle_root_bn254(leaves: &[FieldElement]) -> Result<FieldElement, String> {
    if leaves.len() != PRIVATE_IDENTITY_TREE_LEAVES {
        return Err(format!(
            "expected {} leaves for private identity registry; found {}",
            PRIVATE_IDENTITY_TREE_LEAVES,
            leaves.len()
        ));
    }
    let mut nodes = leaves.to_vec();
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| {
                poseidon_hash4_bn254(&[
                    pair[0].clone(),
                    pair[1].clone(),
                    FieldElement::ZERO,
                    FieldElement::ZERO,
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    nodes
        .into_iter()
        .next()
        .ok_or_else(|| "merkle tree root computation failed".to_string())
}

pub fn merkle_root_from_path_bn254(
    leaf: &FieldElement,
    path: &[MerklePathNodeV1],
) -> Result<FieldElement, String> {
    if path.len() != PRIVATE_IDENTITY_TREE_DEPTH {
        return Err(format!(
            "private identity merkle paths must contain exactly {} nodes; found {}",
            PRIVATE_IDENTITY_TREE_DEPTH,
            path.len()
        ));
    }

    let mut current = leaf.clone();
    for node in path {
        if node.direction > 1 {
            return Err(format!(
                "private identity path direction must be 0 or 1; found {}",
                node.direction
            ));
        }
        let (left, right) = if node.direction == 0 {
            (current, node.sibling.clone())
        } else {
            (node.sibling.clone(), current)
        };
        current = poseidon_hash4_bn254(&[left, right, FieldElement::ZERO, FieldElement::ZERO])?;
    }
    Ok(current)
}

pub fn prove_private_identity(
    request: &PrivateIdentityProveRequestV1,
) -> Result<EmbeddedProof, String> {
    request.issuer_registry.validate()?;
    request.active_registry.validate()?;

    let credential_id = credential_id_from_claims(&request.signed_credential.claims)?;
    let active_leaf = active_leaf_from_credential_id(&credential_id)?;

    let issuer_root = request.issuer_registry.root()?;
    let active_root = request.active_registry.root()?;
    if issuer_root != request.signed_credential.claims.issuer_tree_root {
        return Err("issuer registry root does not match signed credential".to_string());
    }
    if active_root != request.signed_credential.claims.active_tree_root {
        return Err("active registry root does not match signed credential".to_string());
    }

    let issuer_index = request
        .issuer_registry
        .find_leaf(&credential_id)
        .ok_or_else(|| "credential leaf was not found in issuer registry".to_string())?;
    let active_index = request
        .active_registry
        .find_leaf(&active_leaf)
        .ok_or_else(|| "active credential leaf was not found in active registry".to_string())?;
    let issuer_path = request.issuer_registry.authentication_path(issuer_index)?;
    let active_path = request.active_registry.authentication_path(active_index)?;

    prove_private_identity_with_paths(&PrivateIdentityPathProveRequestV1 {
        signed_credential: request.signed_credential.clone(),
        subject_secret: request.subject_secret.clone(),
        subject_salt: request.subject_salt.clone(),
        issuer_tree_root: issuer_root,
        active_tree_root: active_root,
        issuer_path,
        active_path,
        policy: request.policy.clone(),
        backend: request.backend.clone(),
        groth16_setup_blob: request.groth16_setup_blob.clone(),
        allow_dev_deterministic_groth16: request.allow_dev_deterministic_groth16,
    })
}

pub fn prove_private_identity_with_paths(
    request: &PrivateIdentityPathProveRequestV1,
) -> Result<EmbeddedProof, String> {
    prove_private_identity_with_paths_inner(request)
}

pub fn verify_private_identity_artifact(
    artifact: &ProofArtifact,
    expected: Option<&CredentialPublicInputsV1>,
) -> Result<PrivateIdentityVerificationReportV1, String> {
    let bundle = artifact
        .credential_bundle
        .as_ref()
        .ok_or_else(|| "proof artifact does not include a credential bundle".to_string())?;
    bundle.signed_credential.claims.validate()?;
    if bundle.verification_mode != PRIVATE_IDENTITY_VERIFICATION_MODE {
        return Err(format!(
            "credential bundle verification mode mismatch: expected {}, found {}",
            PRIVATE_IDENTITY_VERIFICATION_MODE, bundle.verification_mode
        ));
    }
    if bundle
        .metadata
        .get("credential_binding_mode")
        .map(String::as_str)
        != Some(PRIVATE_IDENTITY_BINDING_MODE)
    {
        return Err("credential bundle binding mode mismatch".to_string());
    }
    if artifact
        .metadata
        .get("credential_verification_mode")
        .map(String::as_str)
        != Some(PRIVATE_IDENTITY_VERIFICATION_MODE)
    {
        return Err("artifact credential verification mode mismatch".to_string());
    }
    if artifact
        .metadata
        .get("credential_binding_mode")
        .map(String::as_str)
        != Some(PRIVATE_IDENTITY_BINDING_MODE)
    {
        return Err("artifact credential binding mode mismatch".to_string());
    }

    let public_inputs = private_identity_public_inputs_from_artifact(artifact)?;
    if let Some(expected) = expected
        && expected != &public_inputs
    {
        return Err(
            "artifact public inputs do not match the expected policy/root surface".to_string(),
        );
    }

    let credential_id = credential_id_from_claims(&bundle.signed_credential.claims)?;
    if credential_id != bundle.credential_id {
        return Err("credential bundle credential_id does not match signed claims".to_string());
    }
    if public_inputs.issuer_tree_root != bundle.signed_credential.claims.issuer_tree_root {
        return Err("public issuer root does not match the signed credential".to_string());
    }
    if public_inputs.active_tree_root != bundle.signed_credential.claims.active_tree_root {
        return Err("public active root does not match the signed credential".to_string());
    }
    validate_claims_against_policy(
        &bundle.signed_credential.claims,
        &PrivateIdentityPolicyV1 {
            required_age: public_inputs.required_age,
            required_status_mask: public_inputs.required_status_mask,
            current_epoch_day: public_inputs.current_epoch_day,
        },
    )?;
    if !bundle
        .signed_credential
        .verify(PRIVATE_IDENTITY_ML_DSA_CONTEXT)
    {
        return Err("issuer signature bundle failed verification".to_string());
    }

    let (program, source_program_digest) =
        build_bound_private_identity_program_with_source_digest(&bundle.signed_credential.claims)?;
    verify_private_identity_digest_policy(artifact, &source_program_digest)?;
    let artifact_for_verify = artifact.clone();
    let program_for_verify = program.clone();
    let verified = run_with_large_stack_result("private-identity-verify", move || {
        if artifact_for_verify.backend == BackendKind::ArkworksGroth16 {
            verify_arkworks_private_identity_artifact_raw(&artifact_for_verify)
        } else {
            let backend_name = artifact_for_verify.backend.as_str().to_string();
            let compiled = compile(&program_for_verify, backend_name.as_str(), None)
                .map_err(|err| err.to_string())?;
            verify(&compiled, &artifact_for_verify).map_err(|err| err.to_string())
        }
    })?;
    if !verified {
        return Err("private identity proof failed cryptographic verification".to_string());
    }

    Ok(PrivateIdentityVerificationReportV1 {
        backend: artifact.backend.as_str().to_string(),
        verification_mode: PRIVATE_IDENTITY_VERIFICATION_MODE.to_string(),
        public_inputs,
    })
}

pub fn private_identity_public_inputs_from_artifact(
    artifact: &ProofArtifact,
) -> Result<CredentialPublicInputsV1, String> {
    if artifact.public_inputs.len() != PRIVATE_IDENTITY_PUBLIC_INPUTS_LEN {
        return Err(format!(
            "private identity proofs must expose {} public inputs; found {}",
            PRIVATE_IDENTITY_PUBLIC_INPUTS_LEN,
            artifact.public_inputs.len()
        ));
    }

    Ok(CredentialPublicInputsV1 {
        issuer_tree_root: artifact.public_inputs[0].clone(),
        active_tree_root: artifact.public_inputs[1].clone(),
        required_age: field_element_to_u8(&artifact.public_inputs[2])?,
        required_status_mask: field_element_to_u32(&artifact.public_inputs[3])?,
        current_epoch_day: field_element_to_u32(&artifact.public_inputs[4])?,
    })
}

fn poseidon_round(
    builder: &mut ProgramBuilder,
    prefix: &str,
    inputs: &[Expr],
) -> zkf_core::ZkfResult<String> {
    let output_names = [
        format!("{prefix}_state_0"),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ];
    for output in &output_names {
        builder.private_signal(output)?;
    }
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    builder.constrain_blackbox(
        zkf_core::BlackBoxOp::Poseidon,
        inputs,
        &[
            output_names[0].as_str(),
            output_names[1].as_str(),
            output_names[2].as_str(),
            output_names[3].as_str(),
        ],
        &params,
    )?;
    Ok(output_names[0].clone())
}

fn append_merkle_membership(
    builder: &mut ProgramBuilder,
    prefix: &str,
    leaf_signal: &str,
    root_signal: &str,
    mut expected_inputs: Option<&mut Vec<String>>,
) -> zkf_core::ZkfResult<()> {
    let mut current = Expr::signal(leaf_signal);
    for level in 0..PRIVATE_IDENTITY_TREE_DEPTH {
        let sibling = format!("{prefix}_sibling_{level}");
        let direction = format!("{prefix}_direction_{level}");
        let left = format!("{prefix}_left_{level}");
        let right = format!("{prefix}_right_{level}");
        builder.private_input(&sibling)?;
        builder.private_input(&direction)?;
        builder.private_signal(&left)?;
        builder.private_signal(&right)?;
        constrain_boolean_explicit(builder, &direction)?;
        builder.constrain_equal(
            Expr::signal(&left),
            Expr::Add(vec![
                current.clone(),
                Expr::Mul(
                    Box::new(Expr::signal(&direction)),
                    Box::new(Expr::Sub(
                        Box::new(Expr::signal(&sibling)),
                        Box::new(current.clone()),
                    )),
                ),
            ]),
        )?;
        builder.constrain_equal(
            Expr::signal(&right),
            Expr::Add(vec![
                Expr::signal(&sibling),
                Expr::Mul(
                    Box::new(Expr::signal(&direction)),
                    Box::new(Expr::Sub(
                        Box::new(current.clone()),
                        Box::new(Expr::signal(&sibling)),
                    )),
                ),
            ]),
        )?;
        current = Expr::signal(poseidon_round(
            builder,
            &format!("__private_identity_{prefix}_merkle_{level}"),
            &[
                Expr::signal(&left),
                Expr::signal(&right),
                Expr::signal("__private_identity_zero_0"),
                Expr::signal("__private_identity_zero_1"),
            ],
        )?);
        if let Some(expected_inputs) = expected_inputs.as_deref_mut() {
            expected_inputs.push(sibling);
            expected_inputs.push(direction);
        }
    }
    builder.constrain_equal(Expr::signal(root_signal), current)?;
    Ok(())
}

fn constrain_boolean_explicit(
    builder: &mut ProgramBuilder,
    signal: impl Into<String>,
) -> zkf_core::ZkfResult<()> {
    let signal = signal.into();
    builder.constrain_boolean(&signal)?;
    builder.constrain_equal(
        Expr::Mul(
            Box::new(Expr::signal(&signal)),
            Box::new(Expr::Sub(
                Box::new(Expr::Const(FieldElement::ONE)),
                Box::new(Expr::signal(&signal)),
            )),
        ),
        Expr::Const(FieldElement::ZERO),
    )?;
    Ok(())
}

fn build_bound_private_identity_inputs(
    claims: &CredentialClaimsV1,
    policy: &PrivateIdentityPolicyV1,
    issuer_path: &[MerklePathNodeV1],
    active_path: &[MerklePathNodeV1],
) -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    inputs.insert(
        "age_surplus".to_string(),
        FieldElement::from_u64(u64::from(
            claims.age_years.saturating_sub(policy.required_age),
        )),
    );
    inputs.insert("age_surplus_anchor".to_string(), FieldElement::ONE);
    inputs.insert(
        "expiry_surplus".to_string(),
        FieldElement::from_u64(u64::from(
            claims
                .expires_at_epoch_day
                .saturating_sub(policy.current_epoch_day),
        )),
    );
    inputs.insert("expiry_surplus_anchor".to_string(), FieldElement::ONE);
    inputs.insert(
        "issuer_tree_root".to_string(),
        claims.issuer_tree_root.clone(),
    );
    inputs.insert(
        "active_tree_root".to_string(),
        claims.active_tree_root.clone(),
    );
    inputs.insert(
        "required_age".to_string(),
        FieldElement::from_u64(policy.required_age.into()),
    );
    inputs.insert(
        "required_status_mask".to_string(),
        FieldElement::from_u64(policy.required_status_mask.into()),
    );
    inputs.insert(
        "current_epoch_day".to_string(),
        FieldElement::from_u64(policy.current_epoch_day.into()),
    );
    insert_status_bits(
        &mut inputs,
        "required_status_bit_",
        policy.required_status_mask,
    );
    insert_path_inputs(&mut inputs, "issuer", issuer_path);
    insert_path_inputs(&mut inputs, "active", active_path);
    inputs
}

fn prove_private_identity_with_paths_inner(
    request: &PrivateIdentityPathProveRequestV1,
) -> Result<EmbeddedProof, String> {
    request.policy.validate()?;
    request.signed_credential.claims.validate()?;
    validate_claims_against_policy(&request.signed_credential.claims, &request.policy)?;
    if !request
        .signed_credential
        .verify(PRIVATE_IDENTITY_ML_DSA_CONTEXT)
    {
        return Err("issuer signature bundle failed verification".to_string());
    }

    let subject_key_hash =
        zkf_core::derive_subject_key_hash(&request.subject_secret, &request.subject_salt)?;
    if subject_key_hash != request.signed_credential.claims.subject_key_hash {
        return Err("derived subject key hash does not match signed credential".to_string());
    }

    let credential_id = credential_id_from_claims(&request.signed_credential.claims)?;
    let active_leaf = active_leaf_from_credential_id(&credential_id)?;
    let derived_issuer_root = merkle_root_from_path_bn254(&credential_id, &request.issuer_path)?;
    let derived_active_root = merkle_root_from_path_bn254(&active_leaf, &request.active_path)?;

    if derived_issuer_root != request.issuer_tree_root {
        return Err("issuer merkle path does not match the supplied issuer root".to_string());
    }
    if derived_active_root != request.active_tree_root {
        return Err("active merkle path does not match the supplied active root".to_string());
    }
    if request.issuer_tree_root != request.signed_credential.claims.issuer_tree_root {
        return Err("supplied issuer root does not match signed credential".to_string());
    }
    if request.active_tree_root != request.signed_credential.claims.active_tree_root {
        return Err("supplied active root does not match signed credential".to_string());
    }

    let inputs = build_bound_private_identity_inputs(
        &request.signed_credential.claims,
        &request.policy,
        &request.issuer_path,
        &request.active_path,
    );

    let (program, source_program_digest) =
        build_bound_private_identity_program_with_source_digest(&request.signed_credential.claims)?;
    let backend_name = request.backend.as_deref().unwrap_or("arkworks-groth16");
    let inputs_for_thread = inputs.clone();
    let backend_name = backend_name.to_string();
    let allow_dev_deterministic_groth16 = request.allow_dev_deterministic_groth16;
    let groth16_setup_blob = request.groth16_setup_blob.clone();
    let mut proof = run_with_large_stack_result("private-identity-prove", move || {
        zkf_backends::with_allow_dev_deterministic_groth16_override(
            allow_dev_deterministic_groth16.then_some(true),
            || {
                zkf_backends::with_groth16_setup_blob_path_override(
                    groth16_setup_blob.clone(),
                    || {
                        compile_and_prove(
                            &program,
                            &inputs_for_thread,
                            backend_name.as_str(),
                            None,
                            None,
                        )
                    },
                )
            },
        )
        .map_err(|err| err.to_string())
    })?;
    proof.artifact.metadata.insert(
        "credential_verification_mode".to_string(),
        PRIVATE_IDENTITY_VERIFICATION_MODE.to_string(),
    );
    proof.artifact.metadata.insert(
        "credential_binding_mode".to_string(),
        PRIVATE_IDENTITY_BINDING_MODE.to_string(),
    );
    proof.artifact.metadata.insert(
        SOURCE_PROGRAM_DIGEST_METADATA_KEY.to_string(),
        source_program_digest,
    );
    proof.artifact.metadata.insert(
        COMPILED_PROGRAM_DIGEST_METADATA_KEY.to_string(),
        proof.artifact.program_digest.clone(),
    );
    proof.artifact = proof
        .artifact
        .clone()
        .with_credential_bundle(CredentialProofBundleV1 {
            signed_credential: request.signed_credential.clone(),
            credential_id,
            verification_mode: PRIVATE_IDENTITY_VERIFICATION_MODE.to_string(),
            metadata: BTreeMap::from([(
                "credential_binding_mode".to_string(),
                PRIVATE_IDENTITY_BINDING_MODE.to_string(),
            )]),
        });
    Ok(proof)
}

fn insert_path_inputs(inputs: &mut WitnessInputs, prefix: &str, path: &[MerklePathNodeV1]) {
    for (level, node) in path.iter().enumerate() {
        inputs.insert(format!("{prefix}_sibling_{level}"), node.sibling.clone());
        inputs.insert(
            format!("{prefix}_direction_{level}"),
            FieldElement::from_u64(node.direction.into()),
        );
    }
}

fn run_with_large_stack_result<T, F>(name: &'static str, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let handle = thread::Builder::new()
        .name(name.to_string())
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .map_err(|err| format!("failed to spawn {name} worker: {err}"))?;
    handle.join().map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            format!("{name} worker panicked: {message}")
        } else if let Some(message) = panic.downcast_ref::<String>() {
            format!("{name} worker panicked: {message}")
        } else {
            format!("{name} worker panicked")
        }
    })?
}

fn insert_status_bits(inputs: &mut WitnessInputs, prefix: &str, value: u32) {
    insert_decomposed_bits(inputs, prefix, u64::from(value), 3);
}

fn insert_decomposed_bits(inputs: &mut WitnessInputs, prefix: &str, value: u64, bits: usize) {
    for bit in 0..bits {
        inputs.insert(
            format!("{prefix}{bit}"),
            FieldElement::from_u64((value >> bit) & 1),
        );
    }
}

fn bit_recombination_expr(prefix: &str, bits: usize) -> Expr {
    Expr::Add(
        (0..bits)
            .map(|bit| {
                Expr::Mul(
                    Box::new(Expr::Const(FieldElement::from_u64(1u64 << bit))),
                    Box::new(Expr::signal(format!("{prefix}{bit}"))),
                )
            })
            .collect(),
    )
}

fn verify_private_identity_digest_policy(
    artifact: &ProofArtifact,
    expected_source_digest: &str,
) -> Result<(), String> {
    let source_program_digest = artifact
        .metadata
        .get(SOURCE_PROGRAM_DIGEST_METADATA_KEY)
        .map(String::as_str);
    let compiled_program_digest = artifact
        .metadata
        .get(COMPILED_PROGRAM_DIGEST_METADATA_KEY)
        .map(String::as_str);

    if source_program_digest.is_none() && compiled_program_digest.is_none() {
        if artifact.program_digest != expected_source_digest {
            return Err(format!(
                "legacy program digest mismatch: expected {}, found {}",
                expected_source_digest, artifact.program_digest
            ));
        }
        return Ok(());
    }

    if let Some(found) = source_program_digest
        && found != expected_source_digest
    {
        return Err(format!(
            "source program digest mismatch: expected {}, found {}",
            expected_source_digest, found
        ));
    }

    if let Some(found) = compiled_program_digest
        && found != artifact.program_digest
    {
        return Err(format!(
            "compiled program digest metadata mismatch: expected {}, found {}",
            artifact.program_digest, found
        ));
    }

    Ok(())
}

fn verify_arkworks_private_identity_artifact_raw(artifact: &ProofArtifact) -> Result<bool, String> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(artifact.verification_key.as_slice())
        .map_err(|err| format!("failed to deserialize Groth16 verification key: {err}"))?;
    let proof = Proof::<Bn254>::deserialize_compressed(artifact.proof.as_slice())
        .map_err(|err| format!("failed to deserialize Groth16 proof: {err}"))?;
    let public_inputs = artifact
        .public_inputs
        .iter()
        .map(parse_bn254_fr)
        .collect::<Result<Vec<_>, _>>()?;

    Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .map_err(|err| format!("backend failure: {err}"))
}

fn parse_bn254_fr(value: &FieldElement) -> Result<Fr, String> {
    let decimal = value.to_decimal_string();
    if let Some(unsigned) = decimal.strip_prefix('-') {
        let parsed =
            Fr::from_str(unsigned).map_err(|_| format!("cannot parse field element {decimal}"))?;
        Ok(-parsed)
    } else {
        Fr::from_str(&decimal).map_err(|_| format!("cannot parse field element {decimal}"))
    }
}

fn field_element_to_acir(value: &FieldElement) -> Result<AcirFieldElement, String> {
    let bigint = value
        .normalized_bigint(FieldId::Bn254)
        .map_err(|err| err.to_string())?;
    AcirFieldElement::try_from_str(&bigint.to_str_radix(10))
        .ok_or_else(|| format!("cannot represent value {} as ACIR field element", bigint))
}

fn acir_to_field_element(value: &AcirFieldElement) -> Result<FieldElement, String> {
    let bigint = BigInt::from_bytes_be(Sign::Plus, &value.to_be_bytes());
    Ok(FieldElement::from_bigint_with_field(bigint, FieldId::Bn254))
}

fn field_element_to_u32(value: &FieldElement) -> Result<u32, String> {
    let bigint = value
        .normalized_bigint(FieldId::Bn254)
        .map_err(|err| err.to_string())?;
    if bigint.sign() == Sign::Minus {
        return Err("expected non-negative public input".to_string());
    }
    bigint
        .to_str_radix(10)
        .parse::<u32>()
        .map_err(|_| format!("public input {} does not fit within u32", value))
}

fn field_element_to_u8(value: &FieldElement) -> Result<u8, String> {
    let bigint = value
        .normalized_bigint(FieldId::Bn254)
        .map_err(|err| err.to_string())?;
    if bigint.sign() == Sign::Minus {
        return Err("expected non-negative public input".to_string());
    }
    bigint
        .to_str_radix(10)
        .parse::<u8>()
        .map_err(|_| format!("public input {} does not fit within u8", value))
}

fn default_registry_version() -> u32 {
    1
}

fn zeroed_registry_leaves() -> Vec<FieldElement> {
    vec![FieldElement::ZERO; PRIVATE_IDENTITY_TREE_LEAVES]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use libcrux_ml_dsa::ml_dsa_44::{generate_key_pair, sign as mldsa_sign};
    use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
    use std::sync::OnceLock;

    #[derive(Clone)]
    struct PrivateIdentityProofFixture {
        artifact: ProofArtifact,
        issuer_registry: PrivateIdentityRegistryV1,
        active_registry: PrivateIdentityRegistryV1,
    }

    fn sign_claims_for_tests(claims: CredentialClaimsV1) -> IssuerSignedCredentialV1 {
        let message = claims.canonical_bytes().expect("canonical bytes");
        let ed25519_signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let keypair = generate_key_pair([5u8; KEY_GENERATION_RANDOMNESS_SIZE]);
        let ml_dsa_signature = mldsa_sign(
            &keypair.signing_key,
            &message,
            PRIVATE_IDENTITY_ML_DSA_CONTEXT,
            [9u8; SIGNING_RANDOMNESS_SIZE],
        )
        .expect("ml-dsa sign");

        IssuerSignedCredentialV1 {
            claims,
            issuer_public_keys: zkf_core::PublicKeyBundle {
                scheme: zkf_core::SignatureScheme::HybridEd25519MlDsa44,
                ed25519: ed25519_signing_key.verifying_key().to_bytes().to_vec(),
                ml_dsa44: keypair.verification_key.as_slice().to_vec(),
            },
            issuer_signature_bundle: zkf_core::SignatureBundle {
                scheme: zkf_core::SignatureScheme::HybridEd25519MlDsa44,
                ed25519: ed25519_signing_key.sign(&message).to_bytes().to_vec(),
                ml_dsa44: ml_dsa_signature.as_slice().to_vec(),
            },
        }
    }

    fn signed_credential_fixture(
        subject_secret: &[u8],
        subject_salt: &[u8],
        age_years: u8,
        status_flags: u32,
        expires_at_epoch_day: u32,
        slot: usize,
    ) -> (
        IssuerSignedCredentialV1,
        PrivateIdentityRegistryV1,
        PrivateIdentityRegistryV1,
    ) {
        let subject_key_hash =
            zkf_core::derive_subject_key_hash(subject_secret, subject_salt).expect("subject hash");
        let mut claims = CredentialClaimsV1 {
            subject_key_hash,
            age_years,
            status_flags,
            expires_at_epoch_day,
            issuer_tree_root: FieldElement::ZERO,
            active_tree_root: FieldElement::ZERO,
            tree_depth: CredentialClaimsV1::FIXED_TREE_DEPTH,
        };
        let credential_id = credential_id_from_claims(&claims).expect("credential id");
        let active_leaf = active_leaf_from_credential_id(&credential_id).expect("active leaf");
        let mut issuer_registry = PrivateIdentityRegistryV1::zeroed();
        let mut active_registry = PrivateIdentityRegistryV1::zeroed();
        issuer_registry
            .set_leaf(slot, credential_id)
            .expect("issuer leaf");
        active_registry
            .set_leaf(slot, active_leaf)
            .expect("active leaf");
        claims.issuer_tree_root = issuer_registry.root().expect("issuer root");
        claims.active_tree_root = active_registry.root().expect("active root");
        (
            sign_claims_for_tests(claims),
            issuer_registry,
            active_registry,
        )
    }

    fn private_identity_proof_fixture() -> PrivateIdentityProofFixture {
        static FIXTURE: OnceLock<PrivateIdentityProofFixture> = OnceLock::new();
        FIXTURE
            .get_or_init(|| {
                let subject_secret = b"subject-secret".to_vec();
                let subject_salt = b"subject-salt".to_vec();
                let (signed_credential, issuer_registry, active_registry) =
                    signed_credential_fixture(
                        &subject_secret,
                        &subject_salt,
                        30,
                        CredentialClaimsV1::STATUS_KYC_PASSED
                            | CredentialClaimsV1::STATUS_NOT_SANCTIONED,
                        20_111,
                        2,
                    );
                let policy = PrivateIdentityPolicyV1 {
                    required_age: 21,
                    required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
                    current_epoch_day: 20_000,
                };
                let credential_id =
                    credential_id_from_claims(&signed_credential.claims).expect("credential id");
                let active_leaf =
                    active_leaf_from_credential_id(&credential_id).expect("active leaf");
                let issuer_index = issuer_registry
                    .find_leaf(&credential_id)
                    .expect("issuer index");
                let active_index = active_registry
                    .find_leaf(&active_leaf)
                    .expect("active index");
                let issuer_path = issuer_registry
                    .authentication_path(issuer_index)
                    .expect("issuer path");
                let active_path = active_registry
                    .authentication_path(active_index)
                    .expect("active path");
                let inputs = build_bound_private_identity_inputs(
                    &signed_credential.claims,
                    &policy,
                    &issuer_path,
                    &active_path,
                );
                let (program, source_program_digest) =
                    build_bound_private_identity_program_with_source_digest(
                        &signed_credential.claims,
                    )
                    .expect("bound private identity program");
                let inputs_for_thread = inputs.clone();
                let program_for_thread = program.clone();
                let mut artifact =
                    run_with_large_stack_result("private-identity-test-fixture-prove", move || {
                        let (_compiled, artifact) =
                            zkf_backends::compile_and_prove_arkworks_unchecked_for_test_fixture(
                                &program_for_thread,
                                &inputs_for_thread,
                            )
                            .map_err(|err| err.to_string())?;
                        Ok(artifact)
                    })
                    .expect("unchecked arkworks private identity proof");
                artifact.metadata.insert(
                    "credential_verification_mode".to_string(),
                    PRIVATE_IDENTITY_VERIFICATION_MODE.to_string(),
                );
                artifact.metadata.insert(
                    "credential_binding_mode".to_string(),
                    PRIVATE_IDENTITY_BINDING_MODE.to_string(),
                );
                artifact.metadata.insert(
                    SOURCE_PROGRAM_DIGEST_METADATA_KEY.to_string(),
                    source_program_digest,
                );
                artifact.metadata.insert(
                    COMPILED_PROGRAM_DIGEST_METADATA_KEY.to_string(),
                    artifact.program_digest.clone(),
                );
                let artifact = artifact.with_credential_bundle(CredentialProofBundleV1 {
                    signed_credential,
                    credential_id,
                    verification_mode: PRIVATE_IDENTITY_VERIFICATION_MODE.to_string(),
                    metadata: BTreeMap::from([(
                        "credential_binding_mode".to_string(),
                        PRIVATE_IDENTITY_BINDING_MODE.to_string(),
                    )]),
                });

                PrivateIdentityProofFixture {
                    artifact,
                    issuer_registry,
                    active_registry,
                }
            })
            .clone()
    }

    #[test]
    fn private_identity_template_passes_source_audit() {
        let template = private_identity_kyc().expect("template");
        let report = zkf_core::audit_program(
            &zkf_core::program_v2_to_zir(&template.program),
            Some(zkf_core::BackendKind::ArkworksGroth16),
        );
        let underconstrained = report
            .checks
            .iter()
            .find(|check| check.name == "underconstrained_signals")
            .expect("underconstrained check");

        assert_ne!(
            underconstrained.status,
            zkf_core::AuditStatus::Fail,
            "private identity template should not fail the audited compile gate: {report:#?}"
        );
    }

    #[test]
    fn registry_root_and_path_roundtrip() {
        let mut registry = PrivateIdentityRegistryV1::zeroed();
        registry
            .set_leaf(5, FieldElement::from_i64(42))
            .expect("set leaf");
        let path = registry.authentication_path(5).expect("path");
        assert_eq!(path.len(), PRIVATE_IDENTITY_TREE_DEPTH);
        assert_eq!(registry.find_leaf(&FieldElement::from_i64(42)), Some(5));
        let root = registry.root().expect("root");
        assert_ne!(root, FieldElement::ZERO);
        assert_eq!(
            merkle_root_from_path_bn254(&FieldElement::from_i64(42), &path).expect("path root"),
            root
        );
    }

    #[test]
    fn private_identity_artifact_verification_checks_bundle_binding() {
        let fixture = private_identity_proof_fixture();
        let artifact = fixture.artifact;
        let issuer_registry = fixture.issuer_registry;
        let active_registry = fixture.active_registry;

        let report = verify_private_identity_artifact(&artifact, None).expect("verify credential");
        assert_eq!(
            report.public_inputs.issuer_tree_root,
            issuer_registry.root().expect("issuer root")
        );
        assert_eq!(
            report.public_inputs.active_tree_root,
            active_registry.root().expect("active root")
        );
        let expected_source_program_digest = build_bound_private_identity_program(
            &artifact
                .credential_bundle
                .as_ref()
                .expect("credential bundle")
                .signed_credential
                .claims,
        )
        .expect("bound source program")
        .digest_hex();
        assert_eq!(
            artifact
                .metadata
                .get(SOURCE_PROGRAM_DIGEST_METADATA_KEY)
                .map(String::as_str),
            Some(expected_source_program_digest.as_str())
        );
        assert_eq!(
            artifact
                .metadata
                .get(COMPILED_PROGRAM_DIGEST_METADATA_KEY)
                .map(String::as_str),
            Some(artifact.program_digest.as_str())
        );

        let mut tampered_signature = artifact.clone();
        tampered_signature
            .credential_bundle
            .as_mut()
            .expect("credential bundle")
            .signed_credential
            .issuer_signature_bundle
            .ed25519[0] ^= 0x01;
        let signature_error = verify_private_identity_artifact(&tampered_signature, None)
            .expect_err("tampered issuer signature must fail");
        assert!(signature_error.contains("issuer signature bundle failed verification"));

        let mut tampered_metadata = artifact.clone();
        tampered_metadata.metadata.insert(
            "credential_verification_mode".to_string(),
            "tampered-mode".to_string(),
        );
        let metadata_error = verify_private_identity_artifact(&tampered_metadata, None)
            .expect_err("tampered verification mode must fail");
        assert!(metadata_error.contains("verification mode mismatch"));

        let mut tampered_binding = artifact.clone();
        tampered_binding
            .credential_bundle
            .as_mut()
            .expect("credential bundle")
            .metadata
            .insert(
                "credential_binding_mode".to_string(),
                "tampered-binding".to_string(),
            );
        let binding_error = verify_private_identity_artifact(&tampered_binding, None)
            .expect_err("tampered binding mode must fail");
        assert!(binding_error.contains("binding mode mismatch"));
    }

    #[test]
    fn private_identity_artifact_verification_rejects_tampered_source_digest_metadata() {
        let fixture = private_identity_proof_fixture();
        let mut artifact = fixture.artifact;
        artifact.metadata.insert(
            SOURCE_PROGRAM_DIGEST_METADATA_KEY.to_string(),
            "tampered-source-digest".to_string(),
        );

        let error = verify_private_identity_artifact(&artifact, None)
            .expect_err("tampered source digest metadata must fail");
        assert!(error.contains("source program digest mismatch"));
    }

    #[test]
    fn private_identity_artifact_verification_rejects_tampered_compiled_digest_metadata() {
        let fixture = private_identity_proof_fixture();
        let mut artifact = fixture.artifact;
        artifact.metadata.insert(
            COMPILED_PROGRAM_DIGEST_METADATA_KEY.to_string(),
            "tampered-compiled-digest".to_string(),
        );

        let error = verify_private_identity_artifact(&artifact, None)
            .expect_err("tampered compiled digest metadata must fail");
        assert!(error.contains("compiled program digest metadata mismatch"));
    }

    #[test]
    fn private_identity_artifact_verification_rejects_tampered_artifact_program_digest() {
        let fixture = private_identity_proof_fixture();
        let mut artifact = fixture.artifact;
        artifact.program_digest = "tampered-artifact-digest".to_string();

        let error = verify_private_identity_artifact(&artifact, None)
            .expect_err("tampered artifact digest must fail");
        assert!(error.contains("compiled program digest metadata mismatch"));
    }

    #[test]
    fn private_identity_artifact_verification_accepts_legacy_no_metadata_compatibility_path() {
        let fixture = private_identity_proof_fixture();
        let mut artifact = fixture.artifact;
        let source_program_digest = build_bound_private_identity_program(
            &artifact
                .credential_bundle
                .as_ref()
                .expect("credential bundle")
                .signed_credential
                .claims,
        )
        .expect("bound source program")
        .digest_hex();
        artifact.metadata.remove(SOURCE_PROGRAM_DIGEST_METADATA_KEY);
        artifact
            .metadata
            .remove(COMPILED_PROGRAM_DIGEST_METADATA_KEY);
        artifact.program_digest = source_program_digest;

        verify_private_identity_artifact(&artifact, None)
            .expect("legacy no-metadata compatibility path should verify");
    }

    #[test]
    fn private_identity_prove_rejects_policy_mismatches_before_proving() {
        let subject_secret = b"subject-secret".to_vec();
        let subject_salt = b"subject-salt".to_vec();
        let (signed_credential, issuer_registry, active_registry) = signed_credential_fixture(
            &subject_secret,
            &subject_salt,
            30,
            CredentialClaimsV1::STATUS_KYC_PASSED | CredentialClaimsV1::STATUS_NOT_SANCTIONED,
            20_111,
            2,
        );
        let base = PrivateIdentityProveRequestV1 {
            signed_credential,
            subject_secret,
            subject_salt,
            issuer_registry,
            active_registry,
            policy: PrivateIdentityPolicyV1 {
                required_age: 21,
                required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
                current_epoch_day: 20_000,
            },
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
        };

        let age_error = prove_private_identity(&PrivateIdentityProveRequestV1 {
            policy: PrivateIdentityPolicyV1 {
                required_age: 40,
                ..base.policy.clone()
            },
            ..base.clone()
        })
        .expect_err("underage proof request must fail");
        assert!(age_error.contains("required age"));

        let status_error = prove_private_identity(&PrivateIdentityProveRequestV1 {
            policy: PrivateIdentityPolicyV1 {
                required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED
                    | CredentialClaimsV1::STATUS_ACCREDITED,
                ..base.policy.clone()
            },
            ..base.clone()
        })
        .expect_err("status-mismatched proof request must fail");
        assert!(status_error.contains("required mask"));

        let expiry_error = prove_private_identity(&PrivateIdentityProveRequestV1 {
            policy: PrivateIdentityPolicyV1 {
                current_epoch_day: 20_200,
                ..base.policy.clone()
            },
            ..base
        })
        .expect_err("expired proof request must fail");
        assert!(expiry_error.contains("expired"));
    }

    #[test]
    fn private_identity_prove_rejects_revoked_active_registry() {
        let subject_secret = b"subject-secret".to_vec();
        let subject_salt = b"subject-salt".to_vec();
        let (signed_credential, issuer_registry, mut active_registry) = signed_credential_fixture(
            &subject_secret,
            &subject_salt,
            30,
            CredentialClaimsV1::STATUS_KYC_PASSED | CredentialClaimsV1::STATUS_NOT_SANCTIONED,
            20_111,
            2,
        );
        active_registry
            .set_leaf(2, FieldElement::ZERO)
            .expect("clear active leaf");

        let err = prove_private_identity(&PrivateIdentityProveRequestV1 {
            signed_credential,
            subject_secret,
            subject_salt,
            issuer_registry,
            active_registry,
            policy: PrivateIdentityPolicyV1 {
                required_age: 21,
                required_status_mask: CredentialClaimsV1::STATUS_KYC_PASSED,
                current_epoch_day: 20_000,
            },
            backend: Some("arkworks-groth16".to_string()),
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: true,
        })
        .expect_err("revoked credential must fail proving");
        assert!(err.contains("active registry root does not match signed credential"));
    }
}
