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

use crate::{BackendKind, CompiledProgram, ProofArtifact, ZkfResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapperPreview {
    pub wrapper: String,
    pub source_backend: BackendKind,
    pub target_backend: BackendKind,
    pub planned_status: String,
    pub strategy: String,
    pub trust_model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_model_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_constraints: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_budget_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_memory_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepare_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_cache_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapperCachePrepareReport {
    pub wrapper: String,
    pub source_backend: BackendKind,
    pub target_backend: BackendKind,
    pub strategy: String,
    pub trust_model: String,
    pub setup_cache_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape_cache_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_cache_pk_format: Option<String>,
    #[serde(default)]
    pub setup_cache_pk_migrated: bool,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_cache_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapperExecutionPolicy {
    pub honor_env_overrides: bool,
    #[serde(default)]
    pub allow_large_direct_materialization: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_mode: Option<WrapModeOverride>,
}

impl Default for WrapperExecutionPolicy {
    fn default() -> Self {
        Self {
            honor_env_overrides: true,
            allow_large_direct_materialization: false,
            force_mode: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WrapModeOverride {
    Auto,
    Direct,
    Nova,
}

impl WrapModeOverride {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Direct => "direct",
            Self::Nova => "nova",
        }
    }
}

/// A proof wrapper transforms a proof from one backend into a proof in another.
///
/// The canonical use case is STARK-to-SNARK wrapping: a fast STARK proof
/// (e.g., Plonky3) is verified inside a SNARK circuit (e.g., Groth16),
/// producing a compact proof suitable for cheap on-chain verification (~200k gas).
pub trait ProofWrapper: Send + Sync {
    /// The backend that produced the original (source) proof.
    fn source_backend(&self) -> BackendKind;

    /// The backend that will produce the wrapped (target) proof.
    fn target_backend(&self) -> BackendKind;

    /// Wrap a source proof: verify the source proof inside the target proof system
    /// and produce a new proof of the verification.
    ///
    /// `source_proof` is the proof to wrap (e.g., a STARK proof).
    /// `source_compiled` is the compiled program that produced the source proof.
    ///
    /// Returns a new `ProofArtifact` in the target backend's format.
    fn wrap(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
    ) -> ZkfResult<ProofArtifact>;

    /// Wrap a source proof under an explicit execution policy.
    ///
    /// The default implementation preserves legacy behavior and delegates to
    /// `wrap`, which means wrapper-specific overrides remain enabled.
    fn wrap_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        _policy: WrapperExecutionPolicy,
    ) -> ZkfResult<ProofArtifact> {
        self.wrap(source_proof, source_compiled)
    }

    /// Preview the strategy and trust model this wrapper expects to use.
    ///
    /// Wrappers that can determine this cheaply should implement it so callers can
    /// apply policy before expensive proving work starts.
    fn preview_wrap(
        &self,
        _source_proof: &ProofArtifact,
        _source_compiled: &CompiledProgram,
    ) -> ZkfResult<Option<WrapperPreview>> {
        Ok(None)
    }

    /// Preview a wrap under an explicit execution policy.
    ///
    /// The default implementation preserves legacy behavior and delegates to
    /// `preview_wrap`.
    fn preview_wrap_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        _policy: WrapperExecutionPolicy,
    ) -> ZkfResult<Option<WrapperPreview>> {
        self.preview_wrap(source_proof, source_compiled)
    }

    /// Prepare wrapper-local caches without generating a wrapped proof.
    ///
    /// Wrappers can use this to migrate setup caches, materialize proving shapes,
    /// or prewarm device-local assets before the first production wrap.
    fn prepare_wrap_cache(
        &self,
        _source_proof: &ProofArtifact,
        _source_compiled: &CompiledProgram,
    ) -> ZkfResult<Option<WrapperCachePrepareReport>> {
        Ok(None)
    }

    /// Prepare wrapper-local caches under an explicit execution policy.
    fn prepare_wrap_cache_with_policy(
        &self,
        source_proof: &ProofArtifact,
        source_compiled: &CompiledProgram,
        _policy: WrapperExecutionPolicy,
    ) -> ZkfResult<Option<WrapperCachePrepareReport>> {
        self.prepare_wrap_cache(source_proof, source_compiled)
    }

    /// Verify a wrapped proof using the target backend's verification.
    fn verify_wrapped(&self, wrapped_proof: &ProofArtifact) -> ZkfResult<bool>;
}

/// Registry for available proof wrappers.
pub struct WrapperRegistry {
    wrappers: Vec<Box<dyn ProofWrapper>>,
}

impl WrapperRegistry {
    pub fn new() -> Self {
        Self {
            wrappers: Vec::new(),
        }
    }

    /// Register a new proof wrapper.
    pub fn register(&mut self, wrapper: Box<dyn ProofWrapper>) {
        self.wrappers.push(wrapper);
    }

    /// Find a wrapper that can transform from `source` to `target`.
    pub fn find(&self, source: BackendKind, target: BackendKind) -> Option<&dyn ProofWrapper> {
        self.wrappers
            .iter()
            .find(|w| w.source_backend() == source && w.target_backend() == target)
            .map(|w| w.as_ref())
    }

    /// List all available wrapping paths as (source, target) pairs.
    pub fn available_paths(&self) -> Vec<(BackendKind, BackendKind)> {
        self.wrappers
            .iter()
            .map(|w| (w.source_backend(), w.target_backend()))
            .collect()
    }
}

/// Core's `default()` is intentionally empty — it contains no wrappers.
/// Consumers should call `zkf_backends::wrapping::default_wrapper_registry()`
/// which pre-populates with all available wrapping paths (e.g., STARK→Groth16,
/// Halo2→Groth16).
impl Default for WrapperRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_finds_nothing() {
        let reg = WrapperRegistry::new();
        assert!(
            reg.find(BackendKind::Plonky3, BackendKind::ArkworksGroth16)
                .is_none()
        );
        assert!(reg.available_paths().is_empty());
    }
}
