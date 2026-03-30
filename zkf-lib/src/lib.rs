#![allow(unexpected_cfgs)]

//! ZKF Library — embeddable ZK framework for compiling, proving, and verifying circuits.
//!
//! This crate is the standalone application surface for ZirOS-built apps.
//! Shipped applications should link this crate directly instead of shelling out
//! to `zkf-cli` at runtime.

#[cfg(not(hax))]
pub mod app;
pub(crate) mod proof_embedded_app_spec;
#[cfg(kani)]
mod verification_kani;

// ---------------------------------------------------------------------------
// Core re-exports — always available
// ---------------------------------------------------------------------------

pub use zkf_core::{
    BackendKind, CompiledProgram, Constraint, CredentialClaimsV1, CredentialProofBundleV1, Expr,
    FieldElement, FieldId, IssuerSignedCredentialV1, Program, ProofArtifact, PublicKeyBundle,
    Signal, SignatureBundle, SignatureScheme, Visibility, Witness, WitnessAssignment, WitnessHint,
    WitnessInputs, WitnessPlan, ZkfError, ZkfResult, bundle_has_required_signature_material,
    derive_subject_key_hash, generate_witness, signed_message_has_complete_bundle_surface,
    verify_bundle, verify_ed25519_signature, verify_ml_dsa_signature, verify_signed_message,
};

// ---------------------------------------------------------------------------
// Phase 0-2 re-exports — gated behind the "full" feature
// ---------------------------------------------------------------------------

#[cfg(all(feature = "full", not(hax)))]
pub use zkf_core::{
    AUDIT_REPORT_VERSION, ArtifactKind, AuditCategory, AuditCheck, AuditFinding, AuditReport,
    AuditSeverity, AuditStatus, AuditSummary, BackendCapabilityEntry, BackendCapabilityMatrix,
    BenchmarkMetrics, BenchmarkReport, DiagnosticsReport, ExportMode, FieldAdapter,
    GpuAcceleration, NormalizationReport, RecursionPlan, SecurityModel, SetupKind, SetupProvenance,
    StatsAggregate, SupportClass, TypeError, ZkfArtifactBundle, audit_program,
    available_recursion_paths, normalize, sanitize_artifact, solve_and_validate_witness,
    solver_by_name, type_check,
};

// ---------------------------------------------------------------------------
// Backend re-exports
// ---------------------------------------------------------------------------

#[cfg(all(not(target_arch = "wasm32"), not(hax)))]
pub use zkf_backends::verifier_export::{
    VerifierExportResult, VerifierLanguage, verifier_exporter_for,
};
#[cfg(not(hax))]
pub use zkf_backends::{BackendEngine, backend_for, preferred_backend_for_program};
#[cfg(not(hax))]
pub use zkf_backends::{
    BackendRoute, BackendSelection, backend_for_route, parse_backend_selection,
    validate_backend_selection_identity,
};

// ---------------------------------------------------------------------------
// Frontend re-exports — opt-in for applications that import external circuit
// formats at runtime.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "frontends", not(hax)))]
pub use zkf_frontends::{FrontendEngine, FrontendKind, frontend_for};

// ---------------------------------------------------------------------------
// IR spec re-exports
// ---------------------------------------------------------------------------

pub use zkf_ir_spec::{IR_SPEC_MAJOR, IR_SPEC_MINOR, version::IrVersion};

// ---------------------------------------------------------------------------
// Stable app surface re-exports
// ---------------------------------------------------------------------------

#[cfg(not(hax))]
pub use app::aerospace::{
    AEROSPACE_ROTATIONAL_AXES, AEROSPACE_TRANSLATIONAL_AXES, BargeTerminalProfileV1,
    CertificationInvariantSetV1, CertificationObservedMetricsV1, DistributedProofConfigV1,
    ImportedCrsManifestRefV1, LandingInterfaceProfileV1, MonteCarloBatchConfigV1,
    PlanetaryTerminalProfileV1, PrivateStarshipFlipCatchRequestV1, RigidBodyStateV1,
    STARSHIP_DEFAULT_GNC_STEPS, STARSHIP_DEFAULT_MONTE_CARLO_SAMPLES,
    STARSHIP_MONTE_CARLO_PRODUCTION_TARGET_SAMPLES, STARSHIP_TEAM_SUBGRAPH_COUNT,
    SurrogateBandRowV1, TeamSubgraphDescriptorV1, TeamSubgraphKindV1, TowerCatchGeometryV1,
    VehicleEnvelopeV1, add_surrogate_band_lookup, barge_terminal_profile_showcase,
    build_gnc_6dof_core_program_with_steps, build_gust_robustness_batch_program_with_samples,
    build_private_starship_flip_catch_program_with_profile, constrain_surrogate_band_lookup,
    gnc_6dof_core_showcase, gnc_6dof_core_showcase_with_steps, gust_robustness_batch_showcase,
    gust_robustness_batch_showcase_with_samples, planetary_terminal_profile_showcase,
    private_starship_flip_catch_inputs_from_request, private_starship_flip_catch_sample_request,
    private_starship_flip_catch_showcase, private_starship_flip_catch_showcase_with_profile,
    tower_catch_geometry_showcase,
};
#[cfg(all(feature = "full", not(hax)))]
pub use app::api::capability_matrix;
#[cfg(not(hax))]
pub use app::api::{
    EmbeddedCheck, EmbeddedProof, check, check_with_backend, compile, compile_and_prove,
    compile_and_prove_default, compile_and_prove_with_progress,
    compile_and_prove_with_progress_backend, compile_default, default_backend,
    default_backend_name, load_inputs, load_program, prove, prove_with_inputs,
    resolve_input_aliases, verify, verify_program, verify_program_default, version,
    witness_from_inputs, witness_inputs_from_json_map,
};
#[cfg(all(feature = "full", not(hax)))]
pub use app::audit::{audit_program_default, audit_program_with_live_capabilities};
#[cfg(not(hax))]
pub use app::builder::{BooleanOp, ProgramBuilder};
#[cfg(not(hax))]
pub use app::combustion::{
    COMBUSTION_DEFAULT_SAMPLES, COMBUSTION_PUBLIC_OUTPUTS, CombustionInstabilityRequestV1,
    build_combustion_instability_program_with_samples, combustion_instability_inputs_from_request,
    combustion_instability_rayleigh_showcase,
    combustion_instability_rayleigh_showcase_with_samples,
};
#[cfg(not(hax))]
pub use app::descent::{
    PRIVATE_POWERED_DESCENT_DEFAULT_STEPS, PRIVATE_POWERED_DESCENT_DIMENSIONS,
    PRIVATE_POWERED_DESCENT_PRIVATE_INPUTS, PRIVATE_POWERED_DESCENT_PUBLIC_INPUTS,
    PRIVATE_POWERED_DESCENT_PUBLIC_OUTPUTS, PrivatePoweredDescentPrivateInputsV1,
    PrivatePoweredDescentPublicInputsV1, PrivatePoweredDescentRequestV1,
    build_private_powered_descent_program, private_powered_descent_sample_inputs,
    private_powered_descent_showcase, private_powered_descent_showcase_with_steps,
    private_powered_descent_witness, private_powered_descent_witness_with_steps,
};
#[cfg(all(not(target_arch = "wasm32"), not(hax)))]
pub use app::evidence::{
    DEFAULT_FORMAL_SCRIPT_SPECS, FormalScriptSpec, GENERATED_APP_CLOSURE_DIR_RELATIVE_PATH,
    GENERATED_APP_CLOSURE_SCHEMA, GENERATED_IMPLEMENTATION_CLOSURE_SCHEMA,
    IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY, IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH,
    audit_entry_included, audit_entry_omitted_by_default, canonicalize_for_determinism_hash,
    collect_default_formal_evidence, collect_formal_evidence,
    collect_formal_evidence_for_generated_app, effective_gpu_attribution_summary,
    ensure_dir_exists, ensure_file_exists, ensure_foundry_layout, foundry_project_dir,
    generated_app_closure_bundle_summary, generated_app_closure_relative_path,
    generated_app_formal_script_specs, hash_json_value, json_pretty, load_generated_app_closure,
    load_generated_implementation_closure_summary, read_json as read_bundle_json,
    read_text as read_bundle_text, repo_root as bundle_repo_root, sha256_hex,
    two_tier_audit_record, write_json as write_bundle_json, write_text as write_bundle_text,
};
#[cfg(not(hax))]
pub use app::inputs::{
    bools_to_field_elements, bytes_to_field_elements, merkle_path_witness_inputs,
    string_to_field_elements, u64s_to_field_elements,
};
#[cfg(not(hax))]
pub use app::mission_ops::{
    ArtifactClassV1, ArtifactDescriptorV1, MISSION_OPS_NON_REPLACEMENT_TARGETS,
    MissionOpsBoundaryContractV1, NASA_CLASS_C_PLUS_INDEPENDENT_ASSESSMENT_NOTE,
    NASA_CLASS_D_GROUND_SUPPORT_MISSION_OPS_ASSURANCE, NORMALIZED_EXPORT_BASED_INGESTION_MODE,
    NasaClassificationBoundaryV1, artifact_descriptor_v1, exportable_artifacts,
    mission_ops_boundary_contract_v1, mission_ops_boundary_lines, mission_ops_boundary_markdown,
    release_block_on_oracle_mismatch, scrub_public_export_text, scrub_public_export_text_tree,
};
#[cfg(not(hax))]
pub use app::multi_satellite::{
    PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT, PRIVATE_MULTI_SATELLITE_BASE_PUBLIC_OUTPUTS,
    PRIVATE_MULTI_SATELLITE_BASE_SATELLITE_COUNT, PRIVATE_MULTI_SATELLITE_BASE_STEPS,
    PRIVATE_MULTI_SATELLITE_DIMENSIONS, PRIVATE_MULTI_SATELLITE_PRIVATE_INPUTS_PER_SATELLITE,
    PRIVATE_MULTI_SATELLITE_PUBLIC_INPUTS, PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT,
    PRIVATE_MULTI_SATELLITE_STRESS_PUBLIC_OUTPUTS, PRIVATE_MULTI_SATELLITE_STRESS_SATELLITE_COUNT,
    PRIVATE_MULTI_SATELLITE_STRESS_STEPS, PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS, PairCheck,
    PrivateMultiSatelliteScenario, PrivateMultiSatelliteScenarioSpec,
    private_multi_satellite_conjunction_sample_inputs,
    private_multi_satellite_conjunction_showcase_base32,
    private_multi_satellite_conjunction_showcase_for_scenario,
    private_multi_satellite_conjunction_showcase_stress64,
    private_multi_satellite_conjunction_witness, private_multi_satellite_pair_schedule,
    private_multi_satellite_scenario_spec,
};
#[cfg(not(hax))]
pub use app::navier_stokes::{
    NAVIER_STOKES_DEFAULT_CELLS, NAVIER_STOKES_PUBLIC_OUTPUTS, NavierStokesCellStateV1,
    NavierStokesInterfaceCertificateV1, NavierStokesStructuredStepRequestV1,
    build_navier_stokes_structured_step_program, navier_stokes_structured_step_inputs_from_request,
    navier_stokes_structured_step_showcase, navier_stokes_structured_step_showcase_with_cells,
};
#[cfg(not(hax))]
pub use app::orbital::{
    PRIVATE_NBODY_BODY_COUNT, PRIVATE_NBODY_DEFAULT_STEPS, PRIVATE_NBODY_DIMENSIONS,
    PRIVATE_NBODY_PRIVATE_INPUTS, PRIVATE_NBODY_PUBLIC_OUTPUTS,
    private_nbody_orbital_sample_inputs, private_nbody_orbital_showcase,
    private_nbody_orbital_showcase_with_steps, private_nbody_orbital_witness,
    private_nbody_orbital_witness_with_steps,
};
#[cfg(not(hax))]
pub use app::private_identity::{
    CredentialPublicInputsV1, MerklePathNodeV1, PRIVATE_IDENTITY_ML_DSA_CONTEXT,
    PRIVATE_IDENTITY_PUBLIC_INPUTS_LEN, PRIVATE_IDENTITY_TREE_DEPTH, PRIVATE_IDENTITY_TREE_LEAVES,
    PRIVATE_IDENTITY_VERIFICATION_MODE, PrivateIdentityPathProveRequestV1, PrivateIdentityPolicyV1,
    PrivateIdentityProveRequestV1, PrivateIdentityRegistryV1, PrivateIdentityVerificationReportV1,
    active_leaf_from_credential_id, credential_id_from_claims, merkle_root_bn254,
    merkle_root_from_path_bn254, poseidon_hash4_bn254, private_identity_kyc,
    private_identity_public_inputs_from_artifact, prove_private_identity,
    prove_private_identity_with_paths, verify_private_identity_artifact,
};
#[cfg(not(hax))]
pub use app::progress::{ProofEvent, ProofStage};
#[cfg(not(hax))]
pub use app::real_gas::{
    REAL_GAS_COMPONENTS, REAL_GAS_PUBLIC_OUTPUTS, RealGasModelFamilyV1, RealGasStateRequestV1,
    build_real_gas_state_program, real_gas_state_inputs_from_request, real_gas_state_showcase,
    real_gas_state_showcase_for_model,
};
#[cfg(not(hax))]
pub use app::reentry::{
    PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS, PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS,
    PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS, PrivateReentryThermalRequestV1,
    REENTRY_ASSURANCE_ML_DSA_CONTEXT, ReentryAbortCorridorBandRowV1, ReentryAbortThresholdsV1,
    ReentryAssuranceReceiptV1, ReentryAssuranceReceiptV2, ReentryAtmosphereBandRowV1,
    ReentryAuthorizedSignerV1, ReentryMissionPackV1, ReentryMissionPackV2,
    ReentryOracleComparisonV1, ReentryOracleSummaryV1, ReentryPrivateInputsV1,
    ReentryPrivateInputsV2, ReentryPrivateModelCommitmentsV1, ReentryPublicEnvelopeV1,
    ReentryPublicInputsV1, ReentrySignerManifestV1, ReentrySineBandRowV1,
    SignedReentryMissionPackV1, build_private_reentry_thermal_accepted_program_for_mission_pack,
    build_private_reentry_thermal_program, build_reentry_assurance_receipt_v2,
    build_reentry_oracle_summary_v1, compare_reentry_receipt_to_oracle_v1,
    materialize_private_reentry_request_v1_from_v2,
    private_reentry_thermal_accepted_witness_from_mission_pack,
    private_reentry_thermal_sample_inputs, private_reentry_thermal_sample_request_with_steps,
    private_reentry_thermal_showcase, private_reentry_thermal_showcase_with_steps,
    private_reentry_thermal_witness, private_reentry_thermal_witness_with_steps,
    reentry_mission_pack_v2_digest, reentry_mission_pack_v2_sample_with_steps,
    reentry_signer_manifest_digest, validate_signed_reentry_mission_pack,
};
#[cfg(not(hax))]
pub use app::satellite::{
    PRIVATE_SATELLITE_DEFAULT_STEPS, PRIVATE_SATELLITE_DIMENSIONS,
    PRIVATE_SATELLITE_PRIVATE_INPUTS, PRIVATE_SATELLITE_PUBLIC_INPUTS,
    PRIVATE_SATELLITE_PUBLIC_OUTPUTS, PRIVATE_SATELLITE_SPACECRAFT_COUNT,
    private_satellite_conjunction_sample_inputs, private_satellite_conjunction_showcase,
    private_satellite_conjunction_witness,
};
#[cfg(not(hax))]
pub use app::spec::{
    AppSpecCustomGateV1, AppSpecLookupTableV1, AppSpecMemoryRegionV1, AppSpecProgramV1,
    AppSpecSignalV1, AppSpecV1, BuilderOpV1, TemplateArgSpecV1, TemplateRegistryEntryV1,
    build_app_spec, instantiate_template, template_registry,
};
#[cfg(not(hax))]
pub use app::sovereign_economic_defense::{
    AntiExtractionShieldRequestV1, CommunityLandTrustGovernanceRequestV1,
    CooperativeTreasuryAssuranceRequestV1, RecirculationSovereigntyScoreRequestV1,
    SOVEREIGN_ECONOMIC_DEFENSE_BN254_SCALE_DECIMALS,
    SOVEREIGN_ECONOMIC_DEFENSE_GOLDILOCKS_SCALE_DECIMALS,
    SOVEREIGN_ECONOMIC_DEFENSE_INTEGRATION_STEPS, SovereignEconomicDefenseRunManifestV1,
    WealthTrajectoryAssuranceRequestV1, anti_extraction_shield_witness_from_request,
    build_anti_extraction_shield_program, build_community_land_trust_governance_program,
    build_cooperative_treasury_assurance_program,
    build_recirculation_sovereignty_score_program,
    build_wealth_trajectory_assurance_program,
    community_land_trust_governance_witness_from_request,
    cooperative_treasury_assurance_witness_from_request,
    recirculation_sovereignty_score_witness_from_request,
    wealth_trajectory_assurance_witness_from_request,
};
#[cfg(not(hax))]
pub use app::aerospace_qualification::{
    AEROSPACE_QUALIFICATION_BN254_SCALE_DECIMALS, AEROSPACE_QUALIFICATION_GOLDILOCKS_SCALE_DECIMALS,
    AEROSPACE_QUALIFICATION_MAX_COMPONENTS, AEROSPACE_QUALIFICATION_MAX_HANDLERS,
    AEROSPACE_QUALIFICATION_MAX_READINGS, AEROSPACE_QUALIFICATION_MAX_TESTS,
    AEROSPACE_QUALIFICATION_SPECTRAL_BANDS, AerospaceQualificationRunManifestV1,
    ComponentThermalQualificationRequestV1, FlightReadinessAssemblyRequestV1,
    FirmwareProvenanceRequestV1, LotGenealogyRequestV1, TestCampaignComplianceRequestV1,
    VibrationShockQualificationRequestV1, build_component_thermal_qualification_program,
    build_firmware_provenance_program, build_flight_readiness_assembly_program,
    build_lot_genealogy_program, build_test_campaign_compliance_program,
    build_vibration_shock_qualification_program,
    component_thermal_qualification_witness_from_request,
    firmware_provenance_witness_from_request, flight_readiness_assembly_witness_from_request,
    lot_genealogy_witness_from_request, test_campaign_compliance_witness_from_request,
    vibration_shock_qualification_witness_from_request,
};
#[cfg(not(hax))]
pub use app::falcon_heavy_certification::{
    AscentTrajectoryRequestV1, BoosterRecoveryCertificationRequestV1, CoreRecoveryDataV1,
    EngineHealthCertificationRequestV1, EngineOutMissionRequestV1, EngineShutdownEventV1,
    FALCON_HEAVY_ASCENT_STEPS, FALCON_HEAVY_BN254_SCALE_DECIMALS, FALCON_HEAVY_CORE_COUNT,
    FALCON_HEAVY_ENGINE_COUNT, FALCON_HEAVY_ENGINES_PER_CORE,
    FALCON_HEAVY_ENVIRONMENT_STEPS, FALCON_HEAVY_GOLDILOCKS_SCALE_DECIMALS,
    FALCON_HEAVY_MAX_BURNS, FALCON_HEAVY_PARAMS_PER_ENGINE,
    FALCON_HEAVY_RECOVERY_STEPS_PER_CORE, FalconHeavyMissionManifestV1,
    FullMissionIntegrationRequestV1, OrbitalBurnV1, PayloadFairingEnvironmentRequestV1,
    UpperStageMultiBurnRequestV1, ascent_trajectory_witness_from_request,
    booster_recovery_witness_from_request, build_ascent_trajectory_program,
    build_booster_recovery_program, build_engine_health_certification_program,
    build_engine_out_mission_program, build_full_mission_integration_program,
    build_payload_fairing_environment_program, build_upper_stage_multi_burn_program,
    engine_health_certification_witness_from_request,
    engine_out_mission_witness_from_request,
    full_mission_integration_witness_from_request,
    payload_fairing_environment_witness_from_request,
    upper_stage_multi_burn_witness_from_request,
};
#[cfg(not(hax))]
pub use app::templates::TemplateProgram;
#[cfg(not(hax))]
pub use app::thermochemical::{
    THERMOCHEMICAL_ELEMENTS, THERMOCHEMICAL_PUBLIC_OUTPUTS, THERMOCHEMICAL_SPECIES,
    ThermochemicalEquilibriumRequestV1, build_thermochemical_equilibrium_program,
    thermochemical_equilibrium_inputs_from_request, thermochemical_equilibrium_showcase,
};
#[cfg(all(not(target_arch = "wasm32"), not(hax)))]
pub use app::verifier::{export_groth16_solidity_verifier, export_verifier};
#[cfg(not(hax))]
pub use zkf_gadgets::{Gadget, GadgetRegistry, GadgetSpec};

#[cfg(not(hax))]
pub mod combustion {
    pub use crate::app::combustion::*;
}

#[cfg(not(hax))]
pub mod aerospace {
    pub use crate::app::aerospace::*;
}

#[cfg(not(hax))]
pub mod descent {
    pub use crate::app::descent::*;
}

#[cfg(not(hax))]
pub mod inputs {
    pub use crate::app::inputs::*;
}

#[cfg(all(not(target_arch = "wasm32"), not(hax)))]
pub mod evidence {
    pub use crate::app::evidence::*;
}

#[cfg(not(hax))]
pub mod navier_stokes {
    pub use crate::app::navier_stokes::*;
}

#[cfg(not(hax))]
pub mod multi_satellite {
    pub use crate::app::multi_satellite::{
        PRIVATE_MULTI_SATELLITE_BASE_PAIR_COUNT, PRIVATE_MULTI_SATELLITE_BASE_PUBLIC_OUTPUTS,
        PRIVATE_MULTI_SATELLITE_BASE_SATELLITE_COUNT, PRIVATE_MULTI_SATELLITE_BASE_STEPS,
        PRIVATE_MULTI_SATELLITE_DIMENSIONS, PRIVATE_MULTI_SATELLITE_PRIVATE_INPUTS_PER_SATELLITE,
        PRIVATE_MULTI_SATELLITE_PUBLIC_INPUTS, PRIVATE_MULTI_SATELLITE_STRESS_PAIR_COUNT,
        PRIVATE_MULTI_SATELLITE_STRESS_PUBLIC_OUTPUTS,
        PRIVATE_MULTI_SATELLITE_STRESS_SATELLITE_COUNT, PRIVATE_MULTI_SATELLITE_STRESS_STEPS,
        PRIVATE_MULTI_SATELLITE_TIMESTEP_SECONDS, PairCheck, PrivateMultiSatelliteScenario,
        PrivateMultiSatelliteScenarioSpec, private_multi_satellite_conjunction_sample_inputs,
        private_multi_satellite_conjunction_showcase_base32,
        private_multi_satellite_conjunction_showcase_for_scenario,
        private_multi_satellite_conjunction_showcase_stress64,
        private_multi_satellite_conjunction_witness, private_multi_satellite_pair_schedule,
        private_multi_satellite_scenario_spec,
    };
}

#[cfg(not(hax))]
pub mod orbital {
    pub use crate::app::orbital::*;
}

#[cfg(not(hax))]
pub mod real_gas {
    pub use crate::app::real_gas::*;
}

#[cfg(not(hax))]
pub mod reentry {
    pub use crate::app::reentry::*;
}

#[cfg(not(hax))]
pub mod thermochemical {
    pub use crate::app::thermochemical::*;
}

#[cfg(not(hax))]
pub mod satellite {
    pub use crate::app::satellite::{
        PRIVATE_SATELLITE_DEFAULT_STEPS, PRIVATE_SATELLITE_DIMENSIONS,
        PRIVATE_SATELLITE_PRIVATE_INPUTS, PRIVATE_SATELLITE_PUBLIC_INPUTS,
        PRIVATE_SATELLITE_PUBLIC_OUTPUTS, PRIVATE_SATELLITE_SPACECRAFT_COUNT,
        private_satellite_conjunction_sample_inputs,
        private_satellite_conjunction_sample_inputs_for_steps,
        private_satellite_conjunction_showcase, private_satellite_conjunction_showcase_with_steps,
        private_satellite_conjunction_witness, private_satellite_conjunction_witness_with_steps,
    };
}

#[cfg(not(hax))]
pub mod templates {
    pub use crate::app::templates::*;
}

#[cfg(all(test, not(hax)))]
mod tests {
    use super::*;

    #[test]
    fn raw_ir_construction_works_via_reexported_witness_types() {
        let program = Program {
            name: "raw-ir".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::signal("x"),
                label: None,
            }],
            witness_plan: WitnessPlan {
                assignments: vec![WitnessAssignment {
                    target: "out".to_string(),
                    expr: Expr::signal("x"),
                }],
                hints: vec![WitnessHint {
                    target: "out".to_string(),
                    source: "identity".to_string(),
                    kind: zkf_core::WitnessHintKind::Copy,
                }],
                ..WitnessPlan::default()
            },
            ..Program::default()
        };

        let compiled = compile_default(&program, None).expect("compile raw IR program");
        assert_eq!(compiled.program.name, "raw-ir");
    }
}
