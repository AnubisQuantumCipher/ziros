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

use crate::{BackendEngine, backend_for};
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldId, Program,
    ProofArtifact, ToolRequirement, Witness, ZkfError, ZkfResult,
};

/// RISC Zero zkVM backend.
///
/// In compatibility mode, delegates proof generation to the Plonky3 backend
/// for Goldilocks-field programs. When the `native-risc-zero` feature is
/// enabled, a native backend using the `risc0-zkvm` crate can replace this.
pub struct RiscZeroBackend;

impl BackendEngine for RiscZeroBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::RiscZero
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::RiscZero,
            mode: BackendMode::Compat,
            trusted_setup: false,
            recursion_ready: true,
            transparent_setup: true,
            zkvm_mode: true,
            network_target: None,
            supported_blackbox_ops: Vec::new(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["compat-delegate-plonky3".to_string()],
            notes: "RISC Zero compatibility mode: delegates proof generation to plonky3 backend \
                    for Goldilocks programs. Native RISC Zero integration requires the \
                    `native-risc-zero` feature flag."
                .to_string(),
        }
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "cargo".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Required to build Rust guest binaries".to_string()),
                required: true,
            },
            ToolRequirement {
                tool: "rzup".to_string(),
                args: vec!["--version".to_string()],
                note: Some(
                    "RISC Zero toolchain manager (optional in compatibility mode)".to_string(),
                ),
                required: false,
            },
        ]
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        if program.field != FieldId::Goldilocks {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message:
                    "risc-zero compatibility mode currently supports Goldilocks programs only \
                     (delegates to plonky3)"
                        .to_string(),
            });
        }
        delegate_compile(self.kind(), program, BackendKind::Plonky3)
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        delegate_prove(self.kind(), compiled, witness)
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        delegate_verify(self.kind(), compiled, artifact)
    }
}

fn delegate_compile(
    wrapper_kind: BackendKind,
    program: &Program,
    delegated_kind: BackendKind,
) -> ZkfResult<CompiledProgram> {
    let delegated_engine = backend_for(delegated_kind);
    let delegated = delegated_engine.compile(program)?;
    let delegated_bytes =
        serde_json::to_vec(&delegated).map_err(|err| ZkfError::Serialization(err.to_string()))?;

    let mut compiled = CompiledProgram::new(wrapper_kind, program.clone());
    compiled.compiled_data = Some(delegated_bytes);
    compiled.metadata.insert(
        "delegated_backend".to_string(),
        delegated_kind.as_str().to_string(),
    );
    compiled
        .metadata
        .insert("mode".to_string(), "compatibility-delegate".to_string());
    Ok(compiled)
}

fn delegate_prove(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    witness: &Witness,
) -> ZkfResult<ProofArtifact> {
    if compiled.backend != wrapper_kind {
        return Err(ZkfError::InvalidArtifact(format!(
            "compiled backend is {}, expected {}",
            compiled.backend, wrapper_kind
        )));
    }

    let delegated = load_delegated_compiled(compiled)?;
    let delegated_kind = delegated.backend;
    let delegated_engine = backend_for(delegated_kind);
    let delegated_artifact = delegated_engine.prove(&delegated, witness)?;

    let mut metadata = delegated_artifact.metadata.clone();
    metadata.insert(
        "delegated_backend".to_string(),
        delegated_kind.as_str().to_string(),
    );
    metadata.insert(
        "wrapper_backend".to_string(),
        wrapper_kind.as_str().to_string(),
    );
    metadata.insert("mode".to_string(), "compatibility-delegate".to_string());

    Ok(ProofArtifact {
        backend: wrapper_kind,
        program_digest: delegated_artifact.program_digest,
        proof: delegated_artifact.proof,
        verification_key: delegated_artifact.verification_key,
        public_inputs: delegated_artifact.public_inputs,
        metadata,
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    })
}

fn delegate_verify(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> ZkfResult<bool> {
    if compiled.backend != wrapper_kind {
        return Err(ZkfError::InvalidArtifact(format!(
            "compiled backend is {}, expected {}",
            compiled.backend, wrapper_kind
        )));
    }
    if artifact.backend != wrapper_kind {
        return Err(ZkfError::InvalidArtifact(format!(
            "artifact backend is {}, expected {}",
            artifact.backend, wrapper_kind
        )));
    }

    let delegated = load_delegated_compiled(compiled)?;
    let delegated_kind = delegated.backend;
    let delegated_engine = backend_for(delegated_kind);
    let delegated_artifact = ProofArtifact {
        backend: delegated_kind,
        program_digest: artifact.program_digest.clone(),
        proof: artifact.proof.clone(),
        verification_key: artifact.verification_key.clone(),
        public_inputs: artifact.public_inputs.clone(),
        metadata: artifact.metadata.clone(),
        security_profile: artifact.security_profile,
        hybrid_bundle: artifact.hybrid_bundle.clone(),
        credential_bundle: artifact.credential_bundle.clone(),
        archive_metadata: artifact.archive_metadata.clone(),
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    };
    delegated_engine.verify(&delegated, &delegated_artifact)
}

fn load_delegated_compiled(compiled: &CompiledProgram) -> ZkfResult<CompiledProgram> {
    let bytes = compiled
        .compiled_data
        .as_deref()
        .ok_or(ZkfError::MissingCompiledData)?;
    serde_json::from_slice(bytes).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to decode delegated compiled artifact: {err}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_returns_risc_zero() {
        assert_eq!(RiscZeroBackend.kind(), BackendKind::RiscZero);
    }

    #[test]
    fn capabilities_declare_zkvm_mode() {
        let caps = RiscZeroBackend.capabilities();
        assert!(caps.zkvm_mode);
        assert!(caps.transparent_setup);
        assert!(caps.recursion_ready);
        assert!(!caps.trusted_setup);
        assert_eq!(caps.mode, BackendMode::Compat);
    }

    #[test]
    fn compile_rejects_wrong_field() {
        let program = Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            signals: vec![],
            constraints: vec![],
            witness_plan: Default::default(),
            ..Default::default()
        };
        let result = RiscZeroBackend.compile(&program);
        assert!(result.is_err());
    }

    #[test]
    fn compile_delegates_to_plonky3_for_goldilocks() {
        use zkf_core::{Constraint, Expr, Signal, Visibility};

        let program = Program {
            name: "risc_zero_test".to_string(),
            field: FieldId::Goldilocks,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".to_string()),
                rhs: Expr::Signal("y".to_string()),
                label: Some("test_eq".to_string()),
            }],
            witness_plan: Default::default(),
            ..Default::default()
        };
        let compiled = RiscZeroBackend.compile(&program).unwrap();
        assert_eq!(compiled.backend, BackendKind::RiscZero);
        assert_eq!(
            compiled.metadata.get("delegated_backend").unwrap(),
            "plonky3"
        );
        assert_eq!(
            compiled.metadata.get("mode").unwrap(),
            "compatibility-delegate"
        );
    }
}
