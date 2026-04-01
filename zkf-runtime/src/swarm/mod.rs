// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

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
