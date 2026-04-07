pub use zkf_core::BlackBoxOp;
pub use zkf_core::zir::SignalType;
pub use zkf_lib::{
    AntiExtractionShieldRequestV1, BackendKind, CommunityLandTrustGovernanceRequestV1,
    CompiledProgram, Constraint, CooperativeTreasuryAssuranceRequestV1, Expr, FieldElement,
    FieldId, Program, ProgramBuilder, ProofArtifact, RecirculationSovereigntyScoreRequestV1,
    Signal, SovereignEconomicDefenseRunManifestV1, WealthTrajectoryAssuranceRequestV1, Witness,
    WitnessInputs, ZkfError, ZkfResult, anti_extraction_shield_witness_from_request, compile,
    compile_default, cooperative_treasury_assurance_witness_from_request, prove, verify,
    wealth_trajectory_assurance_witness_from_request, witness_from_inputs,
};
pub use zkf_lib::{
    build_anti_extraction_shield_program, build_community_land_trust_governance_program,
    build_cooperative_treasury_assurance_program, build_recirculation_sovereignty_score_program,
    build_wealth_trajectory_assurance_program,
    community_land_trust_governance_witness_from_request,
    recirculation_sovereignty_score_witness_from_request,
};

pub type SignalVisibility = zkf_core::Visibility;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConstraintKind {
    Equal,
    Boolean,
    Range,
    BlackBox,
    Lookup,
}
