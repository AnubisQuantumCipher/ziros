use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SUBSYSTEM_MANIFEST_SCHEMA_V1: &str = "zkf-subsystem-manifest-v1";
pub const SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED: &str = "author_fixed";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionClassificationV1 {
    PrimaryStrict,
    CompatibilityOnlySmoke,
    CompatibilityOnly,
    ExternalDelegate,
    PlanningOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum MidnightContractClassV1 {
    TokenTransfer,
    CooperativeTreasury,
    PrivateVoting,
    CredentialVerification,
    PrivateAuction,
    SupplyChainProvenance,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EvmCompatibilityContractClassV1 {
    VerifierExport,
    RegistryAdapter,
    CompatibilityBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicyV1 {
    pub policy_id: String,
    pub summary: String,
    pub witness_local_only: bool,
    pub public_inputs_documented: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentProfileV1 {
    pub primary_chain: String,
    pub primary_network: String,
    pub supports_live_deploy: bool,
    pub explorer_expected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary_targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemCircuitManifestV1 {
    pub backend: String,
    pub program_path: String,
    pub compiled_path: String,
    pub inputs_path: String,
    pub proof_path: String,
    pub verification_path: String,
    pub audit_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane_classification: Option<ProductionClassificationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemCircuitModuleV1 {
    pub module_id: String,
    pub backend: String,
    pub program_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guaranteed_primitives: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemContractSpecV1 {
    pub contract_id: String,
    pub primary_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_circuit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solidity_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_contract_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midnight_class: Option<MidnightContractClassV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_class: Option<EvmCompatibilityContractClassV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemReleaseContractV1 {
    pub public_bundle_dir: String,
    pub evidence_bundle_path: String,
    pub release_pin_path: String,
    pub disclosure_policy_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemEvidenceRefsV1 {
    pub report_path: String,
    pub summary_path: String,
    pub telemetry_report_path: String,
    pub translation_report_path: String,
    pub witness_summary_path: String,
    pub public_inputs_path: String,
    pub public_outputs_path: String,
    pub evidence_summary_path: String,
    pub deterministic_manifest_path: String,
    pub closure_artifacts_path: String,
    pub midnight_package_manifest_path: String,
    pub midnight_flow_manifest_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midnight_validation_summary_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubsystemManifestEnvelopeV1 {
    pub schema: String,
    pub subsystem_id: String,
    pub version: String,
    pub created_at: String,
    pub backend_policy: String,
    pub publication_target: String,
    pub circuits: BTreeMap<String, SubsystemCircuitManifestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production_classification: Option<ProductionClassificationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_report_word_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub circuit_modules: Vec<SubsystemCircuitModuleV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<SubsystemContractSpecV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_policy: Option<DisclosurePolicyV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_profile: Option<DeploymentProfileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_contract: Option<SubsystemReleaseContractV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<SubsystemEvidenceRefsV1>,
}

impl SubsystemManifestEnvelopeV1 {
    pub fn author_fixed(
        subsystem_id: impl Into<String>,
        version: impl Into<String>,
        created_at: impl Into<String>,
        publication_target: impl Into<String>,
        circuits: BTreeMap<String, SubsystemCircuitManifestV1>,
    ) -> Self {
        Self {
            schema: SUBSYSTEM_MANIFEST_SCHEMA_V1.to_string(),
            subsystem_id: subsystem_id.into(),
            version: version.into(),
            created_at: created_at.into(),
            backend_policy: SUBSYSTEM_BACKEND_POLICY_AUTHOR_FIXED.to_string(),
            publication_target: publication_target.into(),
            circuits,
            runtime_profile: None,
            production_classification: None,
            minimum_report_word_count: None,
            circuit_modules: Vec::new(),
            contracts: Vec::new(),
            disclosure_policy: None,
            deployment_profile: None,
            release_contract: None,
            evidence_refs: None,
        }
    }
}
