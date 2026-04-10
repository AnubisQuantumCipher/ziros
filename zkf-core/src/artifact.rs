use crate::{
    CredentialProofBundleV1, FieldElement, FieldId, Program, PublicKeyBundle, SignatureBundle,
    verify_bundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Plonky3,
    Halo2,
    Halo2Bls12381,
    ArkworksGroth16,
    Sp1,
    RiscZero,
    Nova,
    HyperNova,
    MidnightCompact,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Plonky3 => "plonky3",
            BackendKind::Halo2 => "halo2",
            BackendKind::Halo2Bls12381 => "halo2-bls12-381",
            BackendKind::ArkworksGroth16 => "arkworks-groth16",
            BackendKind::Sp1 => "sp1",
            BackendKind::RiscZero => "risc-zero",
            BackendKind::Nova => "nova",
            BackendKind::HyperNova => "hypernova",
            BackendKind::MidnightCompact => "midnight-compact",
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BackendKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plonky3" => Ok(Self::Plonky3),
            "halo2" => Ok(Self::Halo2),
            "halo2-bls12-381" | "halo2-bls12381" | "halo2_bls12_381" => Ok(Self::Halo2Bls12381),
            "arkworks-groth16" | "arkworks" | "groth16" => Ok(Self::ArkworksGroth16),
            "sp1" => Ok(Self::Sp1),
            "risc-zero" | "risc0" | "risc_zero" => Ok(Self::RiscZero),
            "nova" => Ok(Self::Nova),
            "hypernova" | "hyper-nova" => Ok(Self::HyperNova),
            "midnight-compact" | "midnight" | "compact" => Ok(Self::MidnightCompact),
            other => Err(format!("unknown backend '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    pub artifact_digest: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_digests: Vec<String>,
    pub operation: String,
    pub timestamp_unix: u64,
    pub tool_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<FieldId>,
}

impl ArtifactProvenance {
    pub fn new(
        artifact_digest: String,
        parent_digests: Vec<String>,
        operation: impl Into<String>,
        backend: Option<BackendKind>,
        field: Option<FieldId>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            artifact_digest,
            parent_digests,
            operation: operation.into(),
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            backend,
            field,
        }
    }
}

fn artifact_digest<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_vec(value).unwrap_or_default();
    format!("{:x}", Sha256::digest(json))
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub backend: BackendKind,
    pub mode: BackendMode,
    pub trusted_setup: bool,
    pub recursion_ready: bool,
    pub transparent_setup: bool,
    pub zkvm_mode: bool,
    pub network_target: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_blackbox_ops: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_constraint_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_profiles: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendMode {
    Native,
    Compat,
}

impl BackendMode {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendMode::Native => "native",
            BackendMode::Compat => "compat",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompiledProgram {
    pub backend: BackendKind,
    pub program: Program,
    pub program_digest: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "base64_opt_bytes"
    )]
    pub compiled_data: Option<Vec<u8>>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// The original program before BlackBox constraint lowering.
    /// Used by `prove()` to compute auxiliary witness values for
    /// signals introduced during lowering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_program: Option<Program>,
    /// Report describing how the program was lowered/adapted for this backend.
    #[cfg(feature = "full")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lowering_report: Option<crate::lowering::LoweringReport>,
}

impl CompiledProgram {
    pub fn new(backend: BackendKind, program: Program) -> Self {
        let program_digest = program.digest_hex();
        Self {
            backend,
            program,
            program_digest,
            compiled_data: None,
            metadata: BTreeMap::new(),
            original_program: None,
            #[cfg(feature = "full")]
            lowering_report: None,
        }
    }

    pub fn provenance(&self) -> ArtifactProvenance {
        ArtifactProvenance::new(
            artifact_digest(self),
            vec![self.program_digest.clone()],
            "compile",
            Some(self.backend),
            Some(self.program.field),
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofArtifact {
    pub backend: BackendKind,
    pub program_digest: String,
    #[serde(with = "base64_bytes")]
    pub proof: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub verification_key: Vec<u8>,
    pub public_inputs: Vec<FieldElement>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_profile: Option<ProofSecurityProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid_bundle: Option<Box<HybridProofBundle>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_bundle: Option<Box<CredentialProofBundleV1>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_metadata: Option<ProofArchiveMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_origin_signature: Option<SignatureBundle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_origin_public_keys: Option<PublicKeyBundle>,
}

impl ProofArtifact {
    pub fn new(
        backend: BackendKind,
        program_digest: impl Into<String>,
        proof: Vec<u8>,
        verification_key: Vec<u8>,
        public_inputs: Vec<FieldElement>,
    ) -> Self {
        Self {
            backend,
            program_digest: program_digest.into(),
            proof,
            verification_key,
            public_inputs,
            metadata: BTreeMap::new(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        }
    }

    pub fn with_metadata(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_credential_bundle(mut self, bundle: CredentialProofBundleV1) -> Self {
        self.credential_bundle = Some(Box::new(bundle));
        self
    }

    pub fn provenance(&self, parent_digests: Vec<String>) -> ArtifactProvenance {
        ArtifactProvenance::new(
            artifact_digest(self),
            parent_digests,
            "prove",
            Some(self.backend),
            None,
        )
    }

    pub fn effective_security_profile(&self) -> ProofSecurityProfile {
        self.security_profile.unwrap_or(match self.backend {
            BackendKind::Plonky3 => ProofSecurityProfile::StarkPq,
            _ => ProofSecurityProfile::Classical,
        })
    }

    pub fn verify_proof_origin(&self) -> Result<bool, String> {
        let Some(signature_bundle) = self.proof_origin_signature.as_ref() else {
            return Ok(false);
        };
        let Some(public_key_bundle) = self.proof_origin_public_keys.as_ref() else {
            return Err("proof origin signature present without public keys".to_string());
        };
        let proof_digest = Sha384::digest(&self.proof);
        if verify_bundle(
            public_key_bundle,
            proof_digest.as_ref(),
            signature_bundle,
            b"zkf-swarm",
        ) {
            Ok(true)
        } else {
            Err("proof origin signature verification failed".to_string())
        }
    }

    pub fn as_hybrid_leg(&self) -> HybridProofLeg {
        let mut metadata = self.metadata.clone();
        metadata
            .entry("program_digest".to_string())
            .or_insert_with(|| self.program_digest.clone());
        HybridProofLeg {
            backend: self.backend,
            proof: self.proof.clone(),
            verification_key: self.verification_key.clone(),
            public_inputs: self.public_inputs.clone(),
            metadata,
            verifier: Some(HybridProofVerifierMetadata::from_artifact(self)),
            archive_metadata: self.archive_metadata.clone(),
        }
    }

    pub fn with_hybrid_bundle(
        mut self,
        bundle: HybridProofBundle,
        archive_metadata: Option<ProofArchiveMetadata>,
    ) -> Self {
        self.security_profile = Some(ProofSecurityProfile::HybridClassicalStark);
        self.hybrid_bundle = Some(Box::new(bundle));
        if archive_metadata.is_some() {
            self.archive_metadata = archive_metadata;
        }
        self
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofSecurityProfile {
    Classical,
    StarkPq,
    HybridClassicalStark,
}

impl ProofSecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classical => "classical",
            Self::StarkPq => "stark-pq",
            Self::HybridClassicalStark => "hybrid-classical-stark",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ProofArchiveMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem_claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HybridProofVerifierMetadata {
    pub backend: BackendKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl HybridProofVerifierMetadata {
    pub fn from_artifact(artifact: &ProofArtifact) -> Self {
        Self {
            backend: artifact.backend,
            proof_engine: artifact.metadata.get("proof_engine").cloned(),
            proof_semantics: artifact.metadata.get("proof_semantics").cloned(),
            export_scheme: artifact.metadata.get("export_scheme").cloned(),
            metadata: artifact.metadata.clone(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HybridReplayGuard {
    pub replay_id: String,
    pub transcript_hash: String,
    pub stage_manifest_digest: String,
    pub proof_manifest_digest: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HybridProofLeg {
    pub backend: BackendKind,
    #[serde(with = "base64_bytes")]
    pub proof: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub verification_key: Vec<u8>,
    pub public_inputs: Vec<FieldElement>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<HybridProofVerifierMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_metadata: Option<ProofArchiveMetadata>,
}

impl HybridProofLeg {
    pub fn to_proof_artifact(&self) -> ProofArtifact {
        ProofArtifact {
            backend: self.backend,
            program_digest: self
                .metadata
                .get("program_digest")
                .cloned()
                .unwrap_or_default(),
            proof: self.proof.clone(),
            verification_key: self.verification_key.clone(),
            public_inputs: self.public_inputs.clone(),
            metadata: self.metadata.clone(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: self.archive_metadata.clone(),
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HybridProofBundle {
    pub primary_leg: HybridProofLeg,
    pub companion_leg: HybridProofLeg,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub transcript_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub setup_provenance: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tool_digests: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_guard: Option<HybridReplayGuard>,
}

pub const PACKAGE_SCHEMA_VERSION: u32 = 5;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrontendProvenance {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl FrontendProvenance {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            version: None,
            format: None,
            translator: None,
            source: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageFileRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageFiles {
    pub program: PackageFileRef,
    pub original_artifact: PackageFileRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_map: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_report: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligations: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translation_report: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_inputs: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_report: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub compiled: BTreeMap<String, PackageFileRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub proofs: BTreeMap<String, PackageFileRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub replay_manifests: BTreeMap<String, PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<PackageFileRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageRunFiles {
    pub witness: PackageFileRef,
    pub public_inputs: PackageFileRef,
    pub run_report: PackageFileRef,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepMode {
    ReuseInputs,
    ChainPublicOutputs,
}

impl StepMode {
    pub fn as_str(self) -> &'static str {
        match self {
            StepMode::ReuseInputs => "reuse-inputs",
            StepMode::ChainPublicOutputs => "chain-public-outputs",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackageManifest {
    pub schema_version: u32,
    pub package_name: String,
    pub program_digest: String,
    pub field: FieldId,
    pub frontend: FrontendProvenance,
    #[serde(default)]
    pub backend_targets: Vec<BackendKind>,
    pub files: PackageFiles,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub runs: BTreeMap<String, PackageRunFiles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_mode: Option<StepMode>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl PackageManifest {
    pub fn from_program(
        program: &Program,
        frontend: FrontendProvenance,
        program_path: impl Into<String>,
        original_artifact_path: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: PACKAGE_SCHEMA_VERSION,
            package_name: program.name.clone(),
            program_digest: program.digest_hex(),
            field: program.field,
            frontend,
            backend_targets: Vec::new(),
            files: PackageFiles {
                program: PackageFileRef {
                    path: program_path.into(),
                    sha256: String::new(),
                },
                original_artifact: PackageFileRef {
                    path: original_artifact_path.into(),
                    sha256: String::new(),
                },
                source: None,
                source_map: None,
                check_report: None,
                obligations: None,
                translation_report: None,
                witness: None,
                public_inputs: None,
                run_report: None,
                compiled: BTreeMap::new(),
                proofs: BTreeMap::new(),
                replay_manifests: BTreeMap::new(),
                abi: None,
                debug: None,
                cache_dir: None,
            },
            runs: BTreeMap::new(),
            step_mode: None,
            metadata: BTreeMap::from([
                ("ir_family".to_string(), "ir-v2".to_string()),
                ("ir_version".to_string(), "2".to_string()),
                ("strict_mode".to_string(), "true".to_string()),
                ("requires_execution".to_string(), "false".to_string()),
                ("requires_solver".to_string(), "false".to_string()),
                ("allow_builtin_fallback".to_string(), "false".to_string()),
            ]),
        }
    }
}

mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded)
            .map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}

mod base64_opt_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(value) => serializer.serialize_some(&STANDARD.encode(value)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Option::<String>::deserialize(deserializer)?;
        match encoded {
            Some(value) => STANDARD
                .decode(value)
                .map(Some)
                .map_err(|err| serde::de::Error::custom(err.to_string())),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FieldId;

    fn sample_program() -> Program {
        Program {
            name: "hybrid-artifact".to_string(),
            field: FieldId::Goldilocks,
            signals: vec![],
            constraints: vec![],
            witness_plan: Default::default(),
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        }
    }

    fn sample_artifact(backend: BackendKind) -> ProofArtifact {
        let mut metadata = BTreeMap::new();
        metadata.insert("program_digest".to_string(), "digest".to_string());
        metadata.insert("proof_engine".to_string(), backend.as_str().to_string());
        ProofArtifact::new(backend, "digest", vec![1, 2, 3], vec![4, 5, 6], vec![])
            .with_metadata(metadata)
    }

    #[test]
    fn manifest_defaults_to_current_schema() {
        let manifest = PackageManifest::from_program(
            &sample_program(),
            FrontendProvenance::new("unit"),
            "program.json",
            "source.json",
        );
        assert_eq!(manifest.schema_version, PACKAGE_SCHEMA_VERSION);
        assert!(manifest.files.replay_manifests.is_empty());
    }

    #[test]
    fn hybrid_bundle_roundtrip_sets_security_profile() {
        let primary = sample_artifact(BackendKind::ArkworksGroth16);
        let companion = sample_artifact(BackendKind::Plonky3);
        let artifact = primary.clone().with_hybrid_bundle(
            HybridProofBundle {
                primary_leg: primary.as_hybrid_leg(),
                companion_leg: companion.as_hybrid_leg(),
                transcript_hashes: BTreeMap::from([
                    ("primary".to_string(), "aa".to_string()),
                    ("companion".to_string(), "bb".to_string()),
                ]),
                setup_provenance: BTreeMap::new(),
                tool_digests: BTreeMap::new(),
                replay_guard: Some(HybridReplayGuard {
                    replay_id: "replay".to_string(),
                    transcript_hash: "transcript".to_string(),
                    stage_manifest_digest: "stage".to_string(),
                    proof_manifest_digest: "proof".to_string(),
                }),
            },
            Some(ProofArchiveMetadata {
                theorem_claim_id: Some("backend.plonky3_lowering_soundness".to_string()),
                claim_scope: Some("zkf-backends::proof_plonky3_surface".to_string()),
                archive_path: None,
                metadata: BTreeMap::new(),
            }),
        );
        let json = serde_json::to_vec(&artifact).expect("serialize");
        let decoded: ProofArtifact = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(
            decoded.effective_security_profile(),
            ProofSecurityProfile::HybridClassicalStark
        );
        let bundle = decoded.hybrid_bundle.expect("hybrid bundle");
        assert_eq!(bundle.primary_leg.backend, BackendKind::ArkworksGroth16);
        assert_eq!(bundle.companion_leg.backend, BackendKind::Plonky3);
        assert_eq!(
            decoded
                .archive_metadata
                .expect("archive metadata")
                .theorem_claim_id
                .as_deref(),
            Some("backend.plonky3_lowering_soundness")
        );
    }

    #[test]
    fn proof_artifact_roundtrip_preserves_credential_bundle() {
        let claims = crate::CredentialClaimsV1 {
            subject_key_hash: FieldElement::from_i64(7),
            age_years: 21,
            status_flags: crate::CredentialClaimsV1::STATUS_KYC_PASSED,
            expires_at_epoch_day: 20_100,
            issuer_tree_root: FieldElement::from_i64(11),
            active_tree_root: FieldElement::from_i64(13),
            tree_depth: crate::CredentialClaimsV1::FIXED_TREE_DEPTH,
        };
        let artifact = sample_artifact(BackendKind::ArkworksGroth16).with_credential_bundle(
            CredentialProofBundleV1 {
                signed_credential: crate::IssuerSignedCredentialV1 {
                    claims,
                    issuer_public_keys: crate::PublicKeyBundle {
                        scheme: crate::SignatureScheme::Ed25519,
                        ed25519: vec![1; 32],
                        ml_dsa87: Vec::new(),
                    },
                    issuer_signature_bundle: crate::SignatureBundle {
                        scheme: crate::SignatureScheme::Ed25519,
                        ed25519: vec![2; 64],
                        ml_dsa87: Vec::new(),
                    },
                },
                credential_id: FieldElement::from_i64(19),
                verification_mode: "proof-plus-hybrid-signed-issuer-v1".to_string(),
                metadata: BTreeMap::new(),
            },
        );

        let encoded = serde_json::to_vec(&artifact).expect("serialize");
        let decoded: ProofArtifact = serde_json::from_slice(&encoded).expect("deserialize");
        assert!(decoded.credential_bundle.is_some());
        assert!(decoded.hybrid_bundle.is_none());
    }
}
