pub mod builder;
pub mod config;
pub mod entrypoint;
pub mod queen;
pub mod sentinel;
pub mod warrior;

pub use builder::{
    AttackGenome, AttackGenomeProvenance, AttackPattern, AttackTaxonomy, BuilderRuleRecord,
    DetectionCondition, DetectionRule, GenomeState, RetrainRequest, RollbackMarker, RuleState,
};
pub use config::{SwarmConfig, SwarmKeyBackend};
pub use entrypoint::{EntrypointGuard, EntrypointObservation, EntrypointSurface};
#[cfg(kani)]
pub(crate) use queen::controller_artifact_path;
#[cfg(kani)]
pub(crate) use queen::preserve_successful_artifact;
pub use queen::{
    ActivationLevel, QueenConfig, QueenState, SwarmController, SwarmTelemetryDigest, SwarmVerdict,
    current_activation_level, current_bias, median_activation_level,
};
pub use sentinel::{
    JitterState, SentinelConfig, SentinelState, ThreatDigest, default_stage_keys,
    runtime_stage_seed_state,
};
pub use warrior::{
    BackendQuorumResult, HoneypotVerdict, QuorumConfig, QuorumOutcome, ThreatAdaptiveQuorumPolicy,
    WarriorDecision,
};
