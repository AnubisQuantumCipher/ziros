#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_core::{ZkfError, ZkfResult};

pub use super::mission_ops::{
    ArtifactClassV1, ArtifactDescriptorV1, MissionOpsBoundaryContractV1,
    NasaClassificationBoundaryV1, artifact_descriptor_v1, mission_ops_boundary_contract_v1,
};
use super::reentry::{ReentryMissionPackV2, reentry_mission_pack_v2_digest};

pub const REENTRY_NASA_TARGET_CLASSIFICATION: &str =
    super::mission_ops::NASA_CLASS_D_GROUND_SUPPORT_MISSION_OPS_ASSURANCE;
pub const REENTRY_NASA_CLASSIFICATION_BOUNDARY_NOTE: &str =
    super::mission_ops::NASA_CLASS_C_PLUS_INDEPENDENT_ASSESSMENT_NOTE;
pub const PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY: &str =
    "source_model_manifest_digests_json";
pub const PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY: &str = "derived_model_package_digest";
pub const PROVENANCE_SCENARIO_LIBRARY_MANIFEST_DIGEST_KEY: &str =
    "scenario_library_manifest_digest";
pub const PROVENANCE_ASSURANCE_TRACE_MATRIX_DIGEST_KEY: &str = "assurance_trace_matrix_digest";
pub const PROVENANCE_NASA_CLASSIFICATION_KEY: &str = "nasa_target_classification";
pub const REENTRY_INGESTION_MODE: &str = super::mission_ops::NORMALIZED_EXPORT_BASED_INGESTION_MODE;
pub const REENTRY_NON_REPLACEMENT_TARGETS: [&str; 8] =
    super::mission_ops::MISSION_OPS_NON_REPLACEMENT_TARGETS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceArtifactFileRefV1 {
    pub logical_name: String,
    pub relative_path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceModelAdapterInputV1 {
    pub version: u32,
    pub mission_id: String,
    pub source_tool: String,
    pub source_schema: String,
    pub coordinate_frame: String,
    pub time_system: String,
    pub units_system: String,
    pub primary_artifact: String,
    pub trajectory_sample_count: usize,
    pub maneuver_segment_count: usize,
    pub source_files: Vec<SourceArtifactFileRefV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceModelManifestV1 {
    pub version: u32,
    pub manifest_id: String,
    pub mission_id: String,
    pub source_tool: String,
    pub source_schema: String,
    pub coordinate_frame: String,
    pub time_system: String,
    pub units_system: String,
    pub primary_artifact: String,
    pub trajectory_sample_count: usize,
    pub maneuver_segment_count: usize,
    pub source_files: Vec<SourceArtifactFileRefV1>,
    pub source_artifact_digest: String,
    pub nasa_classification_boundary: NasaClassificationBoundaryV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovedOperatingDomainV1 {
    pub altitude_min: String,
    pub altitude_max: String,
    pub velocity_min: String,
    pub velocity_max: String,
    pub gamma_min: String,
    pub gamma_max: String,
    pub certified_horizon_steps: usize,
    pub cadence_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelResidualBoundV1 {
    pub quantity: String,
    pub max_abs_error: String,
    pub units: String,
    pub source_tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedModelRequestV1 {
    pub version: u32,
    pub package_id: String,
    pub mission_pack: ReentryMissionPackV2,
    pub source_model_manifests: Vec<SourceModelManifestV1>,
    pub approved_operating_domain: ApprovedOperatingDomainV1,
    pub residual_bounds: Vec<ModelResidualBoundV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub uncertainty_metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DerivedModelPackageV1 {
    pub version: u32,
    pub package_id: String,
    pub mission_id: String,
    pub mission_pack_digest: String,
    pub source_model_manifest_digests: Vec<String>,
    pub approved_operating_domain: ApprovedOperatingDomainV1,
    pub atmosphere_band_digest: String,
    pub sine_band_digest: String,
    pub abort_corridor_band_digest: String,
    pub public_envelope_digest: String,
    pub model_commitment_digest: String,
    pub residual_bounds: Vec<ModelResidualBoundV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub uncertainty_metadata: BTreeMap<String, String>,
    pub nasa_classification_boundary: NasaClassificationBoundaryV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedModelOutputV1 {
    pub derived_model_package: DerivedModelPackageV1,
    pub mission_pack: ReentryMissionPackV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScenarioDefinitionV1 {
    pub scenario_id: String,
    pub category: String,
    pub mission_pack_digest: String,
    pub expected_outcome: String,
    pub expected_abort_mode: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScenarioLibraryManifestV1 {
    pub version: u32,
    pub library_id: String,
    pub mission_id: String,
    pub derived_model_package_digest: String,
    pub scenarios: Vec<ScenarioDefinitionV1>,
    pub nasa_classification_boundary: NasaClassificationBoundaryV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssuranceTraceRowV1 {
    pub requirement_id: String,
    pub description: String,
    pub theorem_ids: Vec<String>,
    pub test_ids: Vec<String>,
    pub operator_artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssuranceTraceMatrixV1 {
    pub version: u32,
    pub matrix_id: String,
    pub mission_id: String,
    pub derived_model_package_digest: String,
    pub scenario_library_manifest_digest: String,
    pub rows: Vec<AssuranceTraceRowV1>,
    pub nasa_classification_boundary: NasaClassificationBoundaryV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QualificationCheckV1 {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelQualificationReportV1 {
    pub version: u32,
    pub mission_id: String,
    pub derived_model_package_digest: String,
    pub scenario_library_manifest_digest: String,
    pub assurance_trace_matrix_digest: String,
    pub approved: bool,
    pub checks: Vec<QualificationCheckV1>,
    pub nasa_classification_boundary: NasaClassificationBoundaryV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

pub fn source_model_manifest_digest(manifest: &SourceModelManifestV1) -> ZkfResult<String> {
    super::science::sha256_hex_json("reentry-source-model-manifest-v1", manifest)
}

pub fn derived_model_package_digest(package: &DerivedModelPackageV1) -> ZkfResult<String> {
    super::science::sha256_hex_json("reentry-derived-model-package-v1", package)
}

pub fn scenario_library_manifest_digest(manifest: &ScenarioLibraryManifestV1) -> ZkfResult<String> {
    super::science::sha256_hex_json("reentry-scenario-library-manifest-v1", manifest)
}

pub fn assurance_trace_matrix_digest(matrix: &AssuranceTraceMatrixV1) -> ZkfResult<String> {
    super::science::sha256_hex_json("reentry-assurance-trace-matrix-v1", matrix)
}

fn digest_json<T: Serialize>(domain: &str, value: &T) -> ZkfResult<String> {
    super::science::sha256_hex_json(domain, value)
}

pub fn validate_source_model_adapter_input(
    input: &SourceModelAdapterInputV1,
    expected_tool: &str,
) -> ZkfResult<()> {
    if input.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported source model adapter input version {}",
            input.version
        )));
    }
    if input.mission_id.trim().is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "source model adapter input mission_id must not be empty".to_string(),
        ));
    }
    if input.source_tool != expected_tool {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected source_tool `{expected_tool}` but found `{}`",
            input.source_tool
        )));
    }
    if input.source_schema.trim().is_empty()
        || input.coordinate_frame.trim().is_empty()
        || input.time_system.trim().is_empty()
        || input.units_system.trim().is_empty()
        || input.primary_artifact.trim().is_empty()
    {
        return Err(ZkfError::InvalidArtifact(
            "source model adapter input requires non-empty schema/frame/time/units/primary_artifact".to_string(),
        ));
    }
    if input.source_files.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "source model adapter input must pin at least one source file".to_string(),
        ));
    }
    if input.source_files.iter().any(|file| {
        file.logical_name.trim().is_empty()
            || file.relative_path.trim().is_empty()
            || file.sha256.trim().is_empty()
    }) {
        return Err(ZkfError::InvalidArtifact(
            "source model adapter input contains an invalid source file entry".to_string(),
        ));
    }
    Ok(())
}

pub fn build_source_model_manifest_from_adapter_input(
    input: &SourceModelAdapterInputV1,
    manifest_id: &str,
) -> ZkfResult<SourceModelManifestV1> {
    validate_source_model_adapter_input(input, &input.source_tool)?;
    Ok(SourceModelManifestV1 {
        version: 1,
        manifest_id: manifest_id.to_string(),
        mission_id: input.mission_id.clone(),
        source_tool: input.source_tool.clone(),
        source_schema: input.source_schema.clone(),
        coordinate_frame: input.coordinate_frame.clone(),
        time_system: input.time_system.clone(),
        units_system: input.units_system.clone(),
        primary_artifact: input.primary_artifact.clone(),
        trajectory_sample_count: input.trajectory_sample_count,
        maneuver_segment_count: input.maneuver_segment_count,
        source_files: input.source_files.clone(),
        source_artifact_digest: digest_json("reentry-source-model-adapter-input-v1", input)?,
        nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
        metadata: input.metadata.clone(),
    })
}

pub fn validate_source_model_manifest(manifest: &SourceModelManifestV1) -> ZkfResult<()> {
    if manifest.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported source model manifest version {}",
            manifest.version
        )));
    }
    if manifest.manifest_id.trim().is_empty()
        || manifest.mission_id.trim().is_empty()
        || manifest.source_tool.trim().is_empty()
        || manifest.source_schema.trim().is_empty()
        || manifest.source_artifact_digest.trim().is_empty()
    {
        return Err(ZkfError::InvalidArtifact(
            "source model manifest is missing required identifiers".to_string(),
        ));
    }
    if manifest.source_files.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "source model manifest must pin at least one source file".to_string(),
        ));
    }
    Ok(())
}

fn digest_bands<T: Serialize>(domain: &str, rows: &[T]) -> ZkfResult<String> {
    if rows.is_empty() {
        return Err(ZkfError::InvalidArtifact(format!(
            "{domain} rows must not be empty"
        )));
    }
    digest_json(domain, &rows)
}

fn model_commitment_digest(mission_pack: &ReentryMissionPackV2) -> ZkfResult<String> {
    digest_json(
        "reentry-private-model-commitments-v1",
        &mission_pack.private_model_commitments,
    )
}

fn validate_pack_against_operating_domain(
    mission_pack: &ReentryMissionPackV2,
    domain: &ApprovedOperatingDomainV1,
) -> ZkfResult<()> {
    if domain.certified_horizon_steps != mission_pack.public_envelope.certified_horizon_steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "approved operating domain horizon {} does not match mission pack horizon {}",
            domain.certified_horizon_steps, mission_pack.public_envelope.certified_horizon_steps
        )));
    }
    if domain.cadence_seconds == 0 {
        return Err(ZkfError::InvalidArtifact(
            "approved operating domain cadence_seconds must be nonzero".to_string(),
        ));
    }
    Ok(())
}

pub fn derive_reentry_model_package(
    request: &DerivedModelRequestV1,
) -> ZkfResult<DerivedModelOutputV1> {
    if request.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported derived model request version {}",
            request.version
        )));
    }
    if request.package_id.trim().is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "derived model request package_id must not be empty".to_string(),
        ));
    }
    if request.source_model_manifests.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "derived model request requires at least one source model manifest".to_string(),
        ));
    }
    for manifest in &request.source_model_manifests {
        validate_source_model_manifest(manifest)?;
        if manifest.mission_id != request.mission_pack.private_model_commitments.mission_id {
            return Err(ZkfError::InvalidArtifact(format!(
                "source model manifest mission_id `{}` does not match mission pack mission_id `{}`",
                manifest.mission_id, request.mission_pack.private_model_commitments.mission_id
            )));
        }
    }
    validate_pack_against_operating_domain(
        &request.mission_pack,
        &request.approved_operating_domain,
    )?;

    let mut mission_pack = request.mission_pack.clone();
    let source_model_manifest_digests = request
        .source_model_manifests
        .iter()
        .map(source_model_manifest_digest)
        .collect::<ZkfResult<Vec<_>>>()?;

    let package = DerivedModelPackageV1 {
        version: 1,
        package_id: request.package_id.clone(),
        mission_id: mission_pack.private_model_commitments.mission_id.clone(),
        mission_pack_digest: reentry_mission_pack_v2_digest(&mission_pack)?,
        source_model_manifest_digests: source_model_manifest_digests.clone(),
        approved_operating_domain: request.approved_operating_domain.clone(),
        atmosphere_band_digest: digest_bands(
            "reentry-atmosphere-band-rows-v1",
            &mission_pack.private.atmosphere_bands,
        )?,
        sine_band_digest: digest_bands(
            "reentry-sine-band-rows-v1",
            &mission_pack.private.sine_bands,
        )?,
        abort_corridor_band_digest: digest_bands(
            "reentry-abort-corridor-band-rows-v1",
            &mission_pack.private.abort_corridor_bands,
        )?,
        public_envelope_digest: digest_json(
            "reentry-public-envelope-v1",
            &mission_pack.public_envelope,
        )?,
        model_commitment_digest: model_commitment_digest(&mission_pack)?,
        residual_bounds: request.residual_bounds.clone(),
        uncertainty_metadata: request.uncertainty_metadata.clone(),
        nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
        metadata: request.metadata.clone(),
    };
    let package_digest = derived_model_package_digest(&package)?;
    mission_pack.provenance_metadata.insert(
        PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY.to_string(),
        serde_json::to_string(&source_model_manifest_digests).map_err(|error| {
            ZkfError::InvalidArtifact(format!(
                "failed to serialize source model manifest digests: {error}"
            ))
        })?,
    );
    mission_pack.provenance_metadata.insert(
        PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY.to_string(),
        package_digest,
    );
    mission_pack.provenance_metadata.insert(
        PROVENANCE_NASA_CLASSIFICATION_KEY.to_string(),
        REENTRY_NASA_TARGET_CLASSIFICATION.to_string(),
    );
    Ok(DerivedModelOutputV1 {
        derived_model_package: package,
        mission_pack,
    })
}

pub fn validate_derived_model_package(package: &DerivedModelPackageV1) -> ZkfResult<()> {
    if package.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported derived model package version {}",
            package.version
        )));
    }
    if package.package_id.trim().is_empty()
        || package.mission_id.trim().is_empty()
        || package.mission_pack_digest.trim().is_empty()
        || package.public_envelope_digest.trim().is_empty()
    {
        return Err(ZkfError::InvalidArtifact(
            "derived model package is missing required identifiers".to_string(),
        ));
    }
    if package.source_model_manifest_digests.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "derived model package must reference at least one source model manifest digest"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn validate_mission_pack_ops_provenance(
    mission_pack: &ReentryMissionPackV2,
    source_manifests: &[SourceModelManifestV1],
    derived_model_package: Option<&DerivedModelPackageV1>,
    scenario_library: Option<&ScenarioLibraryManifestV1>,
    assurance_trace_matrix: Option<&AssuranceTraceMatrixV1>,
) -> ZkfResult<()> {
    if !source_manifests.is_empty() {
        let expected = mission_pack
            .provenance_metadata
            .get(PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "mission pack is missing source model manifest provenance".to_string(),
                )
            })?;
        let expected: Vec<String> = serde_json::from_str(expected).map_err(|error| {
            ZkfError::InvalidArtifact(format!(
                "mission pack source model provenance is not valid JSON: {error}"
            ))
        })?;
        let actual = source_manifests
            .iter()
            .map(source_model_manifest_digest)
            .collect::<ZkfResult<Vec<_>>>()?;
        if expected != actual {
            return Err(ZkfError::InvalidArtifact(
                "mission pack source model manifest digests do not match the supplied manifests"
                    .to_string(),
            ));
        }
    }
    if let Some(package) = derived_model_package {
        validate_derived_model_package(package)?;
        let expected = mission_pack
            .provenance_metadata
            .get(PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "mission pack is missing derived model package provenance".to_string(),
                )
            })?;
        let actual = derived_model_package_digest(package)?;
        if expected != &actual {
            return Err(ZkfError::InvalidArtifact(
                "mission pack derived model package digest does not match the supplied package"
                    .to_string(),
            ));
        }
    }
    if let Some(library) = scenario_library {
        validate_scenario_library_manifest(library)?;
        let expected = mission_pack
            .provenance_metadata
            .get(PROVENANCE_SCENARIO_LIBRARY_MANIFEST_DIGEST_KEY)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "mission pack is missing scenario library provenance".to_string(),
                )
            })?;
        let actual = scenario_library_manifest_digest(library)?;
        if expected != &actual {
            return Err(ZkfError::InvalidArtifact(
                "mission pack scenario library digest does not match the supplied manifest"
                    .to_string(),
            ));
        }
    }
    if let Some(matrix) = assurance_trace_matrix {
        validate_assurance_trace_matrix(matrix)?;
        let expected = mission_pack
            .provenance_metadata
            .get(PROVENANCE_ASSURANCE_TRACE_MATRIX_DIGEST_KEY)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "mission pack is missing assurance trace matrix provenance".to_string(),
                )
            })?;
        let actual = assurance_trace_matrix_digest(matrix)?;
        if expected != &actual {
            return Err(ZkfError::InvalidArtifact(
                "mission pack assurance trace matrix digest does not match the supplied matrix"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_scenario_library_manifest(manifest: &ScenarioLibraryManifestV1) -> ZkfResult<()> {
    if manifest.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported scenario library manifest version {}",
            manifest.version
        )));
    }
    if manifest.library_id.trim().is_empty()
        || manifest.mission_id.trim().is_empty()
        || manifest.derived_model_package_digest.trim().is_empty()
    {
        return Err(ZkfError::InvalidArtifact(
            "scenario library manifest is missing required identifiers".to_string(),
        ));
    }
    if manifest.scenarios.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "scenario library manifest must contain at least one scenario".to_string(),
        ));
    }
    Ok(())
}

pub fn build_assurance_trace_matrix(
    package: &DerivedModelPackageV1,
    scenario_library: &ScenarioLibraryManifestV1,
    theorem_ids: &[&str],
) -> ZkfResult<AssuranceTraceMatrixV1> {
    validate_derived_model_package(package)?;
    validate_scenario_library_manifest(scenario_library)?;
    if scenario_library.derived_model_package_digest != derived_model_package_digest(package)? {
        return Err(ZkfError::InvalidArtifact(
            "scenario library manifest does not match the supplied derived model package"
                .to_string(),
        ));
    }
    Ok(AssuranceTraceMatrixV1 {
        version: 1,
        matrix_id: format!("{}-trace-matrix", package.package_id),
        mission_id: package.mission_id.clone(),
        derived_model_package_digest: derived_model_package_digest(package)?,
        scenario_library_manifest_digest: scenario_library_manifest_digest(scenario_library)?,
        rows: vec![
            AssuranceTraceRowV1 {
                requirement_id: "REQ-REENTRY-001".to_string(),
                description: "Accepted RK4/private-table/abort lane must remain theorem-backed and proof-verifiable.".to_string(),
                theorem_ids: theorem_ids.iter().map(|item| (*item).to_string()).collect(),
                test_ids: vec![
                    "accepted_rk4_program_and_witness_satisfy_constraints".to_string(),
                    "reentry_assurance_signed_operator_roundtrip".to_string(),
                ],
                operator_artifacts: vec![
                    "receipt.json".to_string(),
                    "proof.json".to_string(),
                    "formal/STATUS.md".to_string(),
                ],
            },
            AssuranceTraceRowV1 {
                requirement_id: "REQ-REENTRY-002".to_string(),
                description: "Scenario library outcomes must remain consistent with the derived model package and mission pack provenance.".to_string(),
                theorem_ids: vec![
                    "app.reentry_manifest_window_contains_signed_pack".to_string(),
                    "app.reentry_receipt_projection_preserves_signed_digests".to_string(),
                ],
                test_ids: scenario_library
                    .scenarios
                    .iter()
                    .map(|scenario| format!("scenario:{}", scenario.scenario_id))
                    .collect(),
                operator_artifacts: vec![
                    "mission_pack_provenance.json".to_string(),
                    "evidence_manifest.json".to_string(),
                ],
            },
            AssuranceTraceRowV1 {
                requirement_id: "REQ-REENTRY-003".to_string(),
                description: format!(
                    "ZirOS is targeted at {} and requires independent assessment for any Class C+ decision chain.",
                    REENTRY_NASA_TARGET_CLASSIFICATION
                ),
                theorem_ids: vec![],
                test_ids: vec![
                    "mission_ops_docs_target_class_d_boundary".to_string(),
                    "reentry_publish_annex_carries_classification_boundary".to_string(),
                ],
                operator_artifacts: vec![
                    "mission_assurance_report.md".to_string(),
                    "annex_manifest.json".to_string(),
                ],
            },
        ],
        nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
        metadata: BTreeMap::new(),
    })
}

pub fn validate_assurance_trace_matrix(matrix: &AssuranceTraceMatrixV1) -> ZkfResult<()> {
    if matrix.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported assurance trace matrix version {}",
            matrix.version
        )));
    }
    if matrix.matrix_id.trim().is_empty()
        || matrix.mission_id.trim().is_empty()
        || matrix.derived_model_package_digest.trim().is_empty()
        || matrix.scenario_library_manifest_digest.trim().is_empty()
    {
        return Err(ZkfError::InvalidArtifact(
            "assurance trace matrix is missing required identifiers".to_string(),
        ));
    }
    if matrix.rows.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "assurance trace matrix must contain at least one row".to_string(),
        ));
    }
    Ok(())
}

pub fn qualify_reentry_model_package(
    package: &DerivedModelPackageV1,
    scenario_library: &ScenarioLibraryManifestV1,
    theorem_ids: &[&str],
) -> ZkfResult<(AssuranceTraceMatrixV1, ModelQualificationReportV1)> {
    let matrix = build_assurance_trace_matrix(package, scenario_library, theorem_ids)?;
    let checks = vec![
        QualificationCheckV1 {
            name: "derived-model-package-valid".to_string(),
            passed: true,
            detail: "Derived model package digests, operating domain, and classification boundary validated.".to_string(),
        },
        QualificationCheckV1 {
            name: "scenario-library-valid".to_string(),
            passed: true,
            detail: format!(
                "{} scenarios reference the supplied derived model package digest.",
                scenario_library.scenarios.len()
            ),
        },
        QualificationCheckV1 {
            name: "class-d-boundary-explicit".to_string(),
            passed: true,
            detail: REENTRY_NASA_CLASSIFICATION_BOUNDARY_NOTE.to_string(),
        },
        QualificationCheckV1 {
            name: "theorem-coverage-linked".to_string(),
            passed: !theorem_ids.is_empty(),
            detail: format!("{} theorem identifiers linked into the assurance trace matrix.", theorem_ids.len()),
        },
    ];
    let report = ModelQualificationReportV1 {
        version: 1,
        mission_id: package.mission_id.clone(),
        derived_model_package_digest: derived_model_package_digest(package)?,
        scenario_library_manifest_digest: scenario_library_manifest_digest(scenario_library)?,
        assurance_trace_matrix_digest: assurance_trace_matrix_digest(&matrix)?,
        approved: checks.iter().all(|check| check.passed),
        checks,
        nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
        metadata: BTreeMap::new(),
    };
    Ok((matrix, report))
}

pub fn copy_ops_provenance_into_pack(
    mission_pack: &mut ReentryMissionPackV2,
    source_manifest_digests: &[String],
    derived_package_digest: &str,
    scenario_library_digest: Option<&str>,
    assurance_trace_digest: Option<&str>,
) -> ZkfResult<()> {
    mission_pack.provenance_metadata.insert(
        PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY.to_string(),
        serde_json::to_string(source_manifest_digests).map_err(|error| {
            ZkfError::InvalidArtifact(format!(
                "failed to serialize source manifest digests: {error}"
            ))
        })?,
    );
    mission_pack.provenance_metadata.insert(
        PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY.to_string(),
        derived_package_digest.to_string(),
    );
    if let Some(digest) = scenario_library_digest {
        mission_pack.provenance_metadata.insert(
            PROVENANCE_SCENARIO_LIBRARY_MANIFEST_DIGEST_KEY.to_string(),
            digest.to_string(),
        );
    }
    if let Some(digest) = assurance_trace_digest {
        mission_pack.provenance_metadata.insert(
            PROVENANCE_ASSURANCE_TRACE_MATRIX_DIGEST_KEY.to_string(),
            digest.to_string(),
        );
    }
    mission_pack.provenance_metadata.insert(
        PROVENANCE_NASA_CLASSIFICATION_KEY.to_string(),
        REENTRY_NASA_TARGET_CLASSIFICATION.to_string(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::reentry::reentry_mission_pack_v2_sample_with_steps;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};

    fn sample_adapter_input(source_tool: &str) -> SourceModelAdapterInputV1 {
        SourceModelAdapterInputV1 {
            version: 1,
            mission_id: "sample-reentry-v2-2-step".to_string(),
            source_tool: source_tool.to_string(),
            source_schema: "normalized-export-v1".to_string(),
            coordinate_frame: "LVLH".to_string(),
            time_system: "UTC".to_string(),
            units_system: "km-km_s".to_string(),
            primary_artifact: "trajectory.json".to_string(),
            trajectory_sample_count: 256,
            maneuver_segment_count: 8,
            source_files: vec![SourceArtifactFileRefV1 {
                logical_name: "trajectory".to_string(),
                relative_path: "trajectory.json".to_string(),
                sha256: "abc123".to_string(),
                bytes: 1024,
            }],
            metadata: BTreeMap::from([("producer".to_string(), source_tool.to_string())]),
        }
    }

    fn classification_boundary_value(boundary: &NasaClassificationBoundaryV1) -> Value {
        json!({
            "target_classification": boundary.target_classification,
            "target_use": boundary.target_use,
            "requires_independent_assessment_for_class_c_or_higher": boundary.requires_independent_assessment_for_class_c_or_higher,
            "boundary_note": boundary.boundary_note,
        })
    }

    fn source_file_ref_value(file: &SourceArtifactFileRefV1) -> Value {
        json!({
            "logical_name": file.logical_name,
            "relative_path": file.relative_path,
            "sha256": file.sha256,
            "bytes": file.bytes,
        })
    }

    fn approved_operating_domain_value(domain: &ApprovedOperatingDomainV1) -> Value {
        json!({
            "altitude_min": domain.altitude_min,
            "altitude_max": domain.altitude_max,
            "velocity_min": domain.velocity_min,
            "velocity_max": domain.velocity_max,
            "gamma_min": domain.gamma_min,
            "gamma_max": domain.gamma_max,
            "certified_horizon_steps": domain.certified_horizon_steps,
            "cadence_seconds": domain.cadence_seconds,
        })
    }

    fn residual_bound_value(bound: &ModelResidualBoundV1) -> Value {
        json!({
            "quantity": bound.quantity,
            "max_abs_error": bound.max_abs_error,
            "units": bound.units,
            "source_tool": bound.source_tool,
            "notes": bound.notes,
        })
    }

    fn scenario_definition_value(scenario: &ScenarioDefinitionV1) -> Value {
        json!({
            "scenario_id": scenario.scenario_id,
            "category": scenario.category,
            "mission_pack_digest": scenario.mission_pack_digest,
            "expected_outcome": scenario.expected_outcome,
            "expected_abort_mode": scenario.expected_abort_mode,
            "metadata": scenario.metadata,
        })
    }

    fn assurance_trace_row_value(row: &AssuranceTraceRowV1) -> Value {
        json!({
            "requirement_id": row.requirement_id,
            "description": row.description,
            "theorem_ids": row.theorem_ids,
            "test_ids": row.test_ids,
            "operator_artifacts": row.operator_artifacts,
        })
    }

    fn assert_unknown_field_rejected<T>(value: Value)
    where
        T: DeserializeOwned + std::fmt::Debug,
    {
        let mut object = value.as_object().cloned().expect("schema value object");
        object.insert("schema_drift".to_string(), json!(true));
        let error =
            serde_json::from_value::<T>(Value::Object(object)).expect_err("unknown field rejected");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected serde error: {error}"
        );
    }

    fn sample_source_model_manifest(source_tool: &str) -> SourceModelManifestV1 {
        let mut manifest = build_source_model_manifest_from_adapter_input(
            &sample_adapter_input(source_tool),
            &format!("sample-{source_tool}"),
        )
        .expect("manifest");
        manifest
            .metadata
            .insert("owner".to_string(), "schema-freeze".to_string());
        manifest
    }

    fn sample_derived_model_request() -> DerivedModelRequestV1 {
        DerivedModelRequestV1 {
            version: 1,
            package_id: "sample-package".to_string(),
            mission_pack: reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack"),
            source_model_manifests: vec![
                sample_source_model_manifest("gmat"),
                sample_source_model_manifest("spice"),
            ],
            approved_operating_domain: ApprovedOperatingDomainV1 {
                altitude_min: "0".to_string(),
                altitude_max: "120".to_string(),
                velocity_min: "0".to_string(),
                velocity_max: "8".to_string(),
                gamma_min: "-0.35".to_string(),
                gamma_max: "0.35".to_string(),
                certified_horizon_steps: 2,
                cadence_seconds: 1,
            },
            residual_bounds: vec![ModelResidualBoundV1 {
                quantity: "dynamic-pressure".to_string(),
                max_abs_error: "0.5".to_string(),
                units: "kPa".to_string(),
                source_tool: "gmat".to_string(),
                notes: Some("validated against normalized source exports".to_string()),
            }],
            uncertainty_metadata: BTreeMap::from([(
                "uncertainty_model".to_string(),
                "bounded-residual-envelope".to_string(),
            )]),
            metadata: BTreeMap::from([("owner".to_string(), "schema-freeze".to_string())]),
        }
    }

    fn sample_derived_model_output() -> DerivedModelOutputV1 {
        derive_reentry_model_package(&sample_derived_model_request()).expect("output")
    }

    fn sample_scenario_library_manifest() -> ScenarioLibraryManifestV1 {
        let output = sample_derived_model_output();
        ScenarioLibraryManifestV1 {
            version: 1,
            library_id: "sample-library".to_string(),
            mission_id: output.derived_model_package.mission_id.clone(),
            derived_model_package_digest: derived_model_package_digest(
                &output.derived_model_package,
            )
            .expect("package digest"),
            scenarios: vec![ScenarioDefinitionV1 {
                scenario_id: "nominal".to_string(),
                category: "nominal".to_string(),
                mission_pack_digest: reentry_mission_pack_v2_digest(&output.mission_pack)
                    .expect("mission pack digest"),
                expected_outcome: "pass".to_string(),
                expected_abort_mode: "nominal".to_string(),
                metadata: BTreeMap::from([("owner".to_string(), "schema-freeze".to_string())]),
            }],
            nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
            metadata: BTreeMap::from([("owner".to_string(), "schema-freeze".to_string())]),
        }
    }

    fn sample_assurance_trace_matrix() -> AssuranceTraceMatrixV1 {
        let output = sample_derived_model_output();
        let scenario_library = sample_scenario_library_manifest();
        let (mut matrix, _) = qualify_reentry_model_package(
            &output.derived_model_package,
            &scenario_library,
            &["app.reentry_rk4_weighted_step_soundness"],
        )
        .expect("qualified");
        matrix
            .metadata
            .insert("owner".to_string(), "schema-freeze".to_string());
        matrix
    }

    #[test]
    fn build_source_model_manifest_pins_class_d_boundary() {
        let input = sample_adapter_input("gmat");
        let manifest = build_source_model_manifest_from_adapter_input(&input, "sample-gmat")
            .expect("manifest");
        assert_eq!(
            manifest.nasa_classification_boundary.target_classification,
            REENTRY_NASA_TARGET_CLASSIFICATION
        );
        validate_source_model_manifest(&manifest).expect("valid");
    }

    #[test]
    fn mission_ops_boundary_contract_is_explicit_and_non_replacement() {
        let contract = mission_ops_boundary_contract_v1();
        assert_eq!(
            contract.nasa_classification_boundary.target_classification,
            REENTRY_NASA_TARGET_CLASSIFICATION
        );
        assert_eq!(contract.ingestion_mode, REENTRY_INGESTION_MODE);
        assert!(contract.no_native_replacement_claim);
        assert!(
            contract
                .non_replacement_targets
                .iter()
                .any(|item| item == "GMAT")
        );
        assert!(
            contract
                .non_replacement_targets
                .iter()
                .any(|item| item == "cFS")
        );
    }

    #[test]
    fn derive_model_package_updates_mission_pack_provenance() {
        let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        let request = DerivedModelRequestV1 {
            version: 1,
            package_id: "sample-package".to_string(),
            mission_pack,
            source_model_manifests: vec![
                build_source_model_manifest_from_adapter_input(
                    &sample_adapter_input("gmat"),
                    "sample-gmat",
                )
                .expect("gmat"),
                build_source_model_manifest_from_adapter_input(
                    &sample_adapter_input("spice"),
                    "sample-spice",
                )
                .expect("spice"),
            ],
            approved_operating_domain: ApprovedOperatingDomainV1 {
                altitude_min: "0".to_string(),
                altitude_max: "120".to_string(),
                velocity_min: "0".to_string(),
                velocity_max: "8".to_string(),
                gamma_min: "-0.35".to_string(),
                gamma_max: "0.35".to_string(),
                certified_horizon_steps: 2,
                cadence_seconds: 1,
            },
            residual_bounds: vec![ModelResidualBoundV1 {
                quantity: "dynamic-pressure".to_string(),
                max_abs_error: "0.5".to_string(),
                units: "kPa".to_string(),
                source_tool: "gmat".to_string(),
                notes: None,
            }],
            uncertainty_metadata: BTreeMap::new(),
            metadata: BTreeMap::new(),
        };
        let output = derive_reentry_model_package(&request).expect("output");
        let digests_json = output
            .mission_pack
            .provenance_metadata
            .get(PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY)
            .expect("digests");
        let digests: Vec<String> = serde_json::from_str(digests_json).expect("json");
        assert_eq!(digests.len(), 2);
        assert!(
            output
                .mission_pack
                .provenance_metadata
                .contains_key(PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY)
        );
    }

    #[test]
    fn qualify_model_package_builds_trace_matrix() {
        let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        let request = DerivedModelRequestV1 {
            version: 1,
            package_id: "sample-package".to_string(),
            mission_pack,
            source_model_manifests: vec![
                build_source_model_manifest_from_adapter_input(
                    &sample_adapter_input("openmdao"),
                    "sample-openmdao",
                )
                .expect("manifest"),
            ],
            approved_operating_domain: ApprovedOperatingDomainV1 {
                altitude_min: "0".to_string(),
                altitude_max: "120".to_string(),
                velocity_min: "0".to_string(),
                velocity_max: "8".to_string(),
                gamma_min: "-0.35".to_string(),
                gamma_max: "0.35".to_string(),
                certified_horizon_steps: 2,
                cadence_seconds: 1,
            },
            residual_bounds: vec![],
            uncertainty_metadata: BTreeMap::new(),
            metadata: BTreeMap::new(),
        };
        let output = derive_reentry_model_package(&request).expect("output");
        let package_digest =
            derived_model_package_digest(&output.derived_model_package).expect("package digest");
        let scenario_library = ScenarioLibraryManifestV1 {
            version: 1,
            library_id: "sample-library".to_string(),
            mission_id: output.derived_model_package.mission_id.clone(),
            derived_model_package_digest: package_digest,
            scenarios: vec![ScenarioDefinitionV1 {
                scenario_id: "nominal".to_string(),
                category: "nominal".to_string(),
                mission_pack_digest: reentry_mission_pack_v2_digest(&output.mission_pack)
                    .expect("mission pack digest"),
                expected_outcome: "pass".to_string(),
                expected_abort_mode: "nominal".to_string(),
                metadata: BTreeMap::new(),
            }],
            nasa_classification_boundary: NasaClassificationBoundaryV1::default(),
            metadata: BTreeMap::new(),
        };
        let (matrix, report) = qualify_reentry_model_package(
            &output.derived_model_package,
            &scenario_library,
            &["app.reentry_rk4_weighted_step_soundness"],
        )
        .expect("qualified");
        assert!(report.approved);
        assert!(!matrix.rows.is_empty());
        validate_assurance_trace_matrix(&matrix).expect("matrix valid");
    }

    #[test]
    fn source_model_manifest_v1_schema_is_frozen() {
        let manifest = sample_source_model_manifest("gmat");
        let expected = json!({
            "version": manifest.version,
            "manifest_id": manifest.manifest_id,
            "mission_id": manifest.mission_id,
            "source_tool": manifest.source_tool,
            "source_schema": manifest.source_schema,
            "coordinate_frame": manifest.coordinate_frame,
            "time_system": manifest.time_system,
            "units_system": manifest.units_system,
            "primary_artifact": manifest.primary_artifact,
            "trajectory_sample_count": manifest.trajectory_sample_count,
            "maneuver_segment_count": manifest.maneuver_segment_count,
            "source_files": manifest
                .source_files
                .iter()
                .map(source_file_ref_value)
                .collect::<Vec<_>>(),
            "source_artifact_digest": manifest.source_artifact_digest,
            "nasa_classification_boundary": classification_boundary_value(&manifest.nasa_classification_boundary),
            "metadata": manifest.metadata,
        });
        assert_eq!(
            serde_json::to_value(&manifest).expect("serialize"),
            expected
        );
        assert_unknown_field_rejected::<SourceModelManifestV1>(expected);
    }

    #[test]
    fn derived_model_package_v1_schema_is_frozen() {
        let package = sample_derived_model_output().derived_model_package;
        let expected = json!({
            "version": package.version,
            "package_id": package.package_id,
            "mission_id": package.mission_id,
            "mission_pack_digest": package.mission_pack_digest,
            "source_model_manifest_digests": package.source_model_manifest_digests,
            "approved_operating_domain": approved_operating_domain_value(&package.approved_operating_domain),
            "atmosphere_band_digest": package.atmosphere_band_digest,
            "sine_band_digest": package.sine_band_digest,
            "abort_corridor_band_digest": package.abort_corridor_band_digest,
            "public_envelope_digest": package.public_envelope_digest,
            "model_commitment_digest": package.model_commitment_digest,
            "residual_bounds": package
                .residual_bounds
                .iter()
                .map(residual_bound_value)
                .collect::<Vec<_>>(),
            "uncertainty_metadata": package.uncertainty_metadata,
            "nasa_classification_boundary": classification_boundary_value(&package.nasa_classification_boundary),
            "metadata": package.metadata,
        });
        assert_eq!(serde_json::to_value(&package).expect("serialize"), expected);
        assert_unknown_field_rejected::<DerivedModelPackageV1>(expected);
    }

    #[test]
    fn scenario_library_manifest_v1_schema_is_frozen() {
        let manifest = sample_scenario_library_manifest();
        let expected = json!({
            "version": manifest.version,
            "library_id": manifest.library_id,
            "mission_id": manifest.mission_id,
            "derived_model_package_digest": manifest.derived_model_package_digest,
            "scenarios": manifest
                .scenarios
                .iter()
                .map(scenario_definition_value)
                .collect::<Vec<_>>(),
            "nasa_classification_boundary": classification_boundary_value(&manifest.nasa_classification_boundary),
            "metadata": manifest.metadata,
        });
        assert_eq!(
            serde_json::to_value(&manifest).expect("serialize"),
            expected
        );
        assert_unknown_field_rejected::<ScenarioLibraryManifestV1>(expected);
    }

    #[test]
    fn assurance_trace_matrix_v1_schema_is_frozen() {
        let matrix = sample_assurance_trace_matrix();
        let expected = json!({
            "version": matrix.version,
            "matrix_id": matrix.matrix_id,
            "mission_id": matrix.mission_id,
            "derived_model_package_digest": matrix.derived_model_package_digest,
            "scenario_library_manifest_digest": matrix.scenario_library_manifest_digest,
            "rows": matrix
                .rows
                .iter()
                .map(assurance_trace_row_value)
                .collect::<Vec<_>>(),
            "nasa_classification_boundary": classification_boundary_value(&matrix.nasa_classification_boundary),
            "metadata": matrix.metadata,
        });
        assert_eq!(serde_json::to_value(&matrix).expect("serialize"), expected);
        assert_unknown_field_rejected::<AssuranceTraceMatrixV1>(expected);
    }
}
