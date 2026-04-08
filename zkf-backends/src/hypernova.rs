use crate::metal_runtime::append_backend_runtime_metadata;
#[cfg(feature = "native-nova")]
use crate::nova_native::{NovaProfile, compile_native_with_profile};
use crate::r1cs_lowering::lower_program_for_backend;
use crate::{BackendEngine, backend_for};
use zkf_core::ccs::CcsProgram;
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, FieldId, Program,
    ProofArtifact, Witness, ZkfError, ZkfResult,
};

/// HyperNova multifolding backend.
///
/// HyperNova generalizes Nova's folding scheme to work with Customizable
/// Constraint Systems (CCS), which unify R1CS, PLONKish, and AIR. This
/// enables efficient IVC (Incremental Verifiable Computation) over richer
/// constraint types than Nova's R1CS-only model.
///
/// When the `native-nova` feature is enabled, delegates to the Nova native
/// backend with the HyperNova profile, providing real CCS multifolding over
/// the Pallas/Vesta curve cycle. Without the feature, falls back to
/// Arkworks Groth16 for BN254 programs in compatibility mode.
pub struct HyperNovaBackend;

impl BackendEngine for HyperNovaBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::HyperNova
    }

    fn capabilities(&self) -> BackendCapabilities {
        let (mode, recursion_ready, profiles, notes) = if nova_native_available() {
            (
                BackendMode::Native,
                true,
                vec!["hypernova-ccs".to_string(), "pallas-vesta".to_string()],
                "HyperNova native mode: delegates to Nova native backend with HyperNova \
                 CCS profile for real multifolding over Pallas/Vesta curve cycle. \
                 Supports BN254, PastaFp, and PastaFq IR programs."
                    .to_string(),
            )
        } else {
            (
                BackendMode::Compat,
                false,
                vec!["compat-delegate-arkworks".to_string()],
                "HyperNova compatibility mode: delegates to arkworks-groth16 for BN254 \
                 programs. Enable `native-nova` feature for real CCS multifolding."
                    .to_string(),
            )
        };

        BackendCapabilities {
            backend: BackendKind::HyperNova,
            mode,
            trusted_setup: !nova_native_available(),
            recursion_ready,
            transparent_setup: nova_native_available(),
            zkvm_mode: false,
            network_target: None,
            supported_blackbox_ops: Vec::new(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: profiles,
            notes,
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        crate::with_serialized_heavy_backend_test(|| {
            if nova_native_available() {
                match program.field {
                    FieldId::Bn254 | FieldId::PastaFq | FieldId::PastaFp => {}
                    _ => {
                        return Err(ZkfError::UnsupportedBackend {
                            backend: self.kind().to_string(),
                            message: format!(
                                "hypernova native mode requires bn254, pasta-fq, or pasta-fp programs; got {}",
                                program.field.as_str()
                            ),
                        });
                    }
                }
            } else if program.field != FieldId::Bn254 {
                return Err(ZkfError::UnsupportedBackend {
                    backend: self.kind().to_string(),
                    message: "hypernova compatibility mode currently supports BN254 programs only"
                        .to_string(),
                });
            }

            let lowered = lower_program_for_backend(program, self.kind())?;
            let ccs = CcsProgram::try_from_program(&lowered.program)?;

            let mut compiled = if nova_native_available() {
                compile_via_nova_native(self.kind(), program)?
            } else {
                delegate_compile(self.kind(), program, BackendKind::ArkworksGroth16)?
            };

            compiled.metadata.insert(
                "ccs_num_matrices".to_string(),
                ccs.num_matrices().to_string(),
            );
            compiled
                .metadata
                .insert("ccs_degree".to_string(), ccs.degree().to_string());
            compiled
                .metadata
                .insert("ccs_num_terms".to_string(), ccs.num_terms().to_string());
            compiled.metadata.insert(
                "ccs_num_constraints".to_string(),
                ccs.num_constraints.to_string(),
            );
            compiled.metadata.insert(
                "ccs_num_variables".to_string(),
                ccs.num_variables.to_string(),
            );
            compiled
                .metadata
                .insert("ccs_num_public".to_string(), ccs.num_public.to_string());

            crate::metal_runtime::append_trust_metadata(
                &mut compiled.metadata,
                "native",
                "cryptographic",
                1,
            );
            Ok(compiled)
        })
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        crate::with_serialized_heavy_backend_test(|| {
            if compiled.backend != self.kind() {
                return Err(ZkfError::InvalidArtifact(format!(
                    "compiled backend is {}, expected {}",
                    compiled.backend,
                    self.kind()
                )));
            }

            match compiled.metadata.get("mode").map(String::as_str) {
                Some("native" | "native-delegate") => {
                    prove_via_nova_native(self.kind(), compiled, witness)
                }
                _ => delegate_prove(self.kind(), compiled, witness),
            }
        })
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        if compiled.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "compiled backend is {}, expected {}",
                compiled.backend,
                self.kind()
            )));
        }
        if artifact.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "artifact backend is {}, expected {}",
                artifact.backend,
                self.kind()
            )));
        }

        match compiled.metadata.get("mode").map(String::as_str) {
            Some("native" | "native-delegate") => {
                verify_via_nova_native(self.kind(), compiled, artifact)
            }
            _ => delegate_verify(self.kind(), compiled, artifact),
        }
    }
}

fn nova_native_available() -> bool {
    cfg!(feature = "native-nova")
        && std::env::var("ZKF_HYPERNOVA_FORCE_COMPAT")
            .map(|v| !(v.eq_ignore_ascii_case("true") || v == "1"))
            .unwrap_or(true)
}

#[cfg(feature = "native-nova")]
fn compile_via_nova_native(
    wrapper_kind: BackendKind,
    program: &Program,
) -> ZkfResult<CompiledProgram> {
    let mut compiled = compile_native_with_profile(program, NovaProfile::HyperNova)?;
    // Re-tag as HyperNova
    compiled.backend = wrapper_kind;
    compiled
        .metadata
        .insert("mode".to_string(), "native".to_string());
    compiled.metadata.insert(
        "delegated_backend".to_string(),
        BackendKind::Nova.as_str().to_string(),
    );
    compiled
        .metadata
        .insert("nova_profile".to_string(), "hypernova".to_string());
    compiled
        .metadata
        .insert("scheme".to_string(), "hypernova-ccs-ivc".to_string());
    Ok(compiled)
}

#[cfg(not(feature = "native-nova"))]
fn compile_via_nova_native(
    _wrapper_kind: BackendKind,
    _program: &Program,
) -> ZkfResult<CompiledProgram> {
    unreachable!("compile_via_nova_native is only called when native-nova is enabled")
}

fn prove_via_nova_native(
    wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    witness: &Witness,
) -> ZkfResult<ProofArtifact> {
    // Reconstruct a Nova-tagged compiled for the native backend
    let mut nova_compiled = compiled.clone();
    nova_compiled.backend = BackendKind::Nova;

    let nova_engine = backend_for(BackendKind::Nova);
    let mut artifact = nova_engine.prove(&nova_compiled, witness)?;

    artifact.backend = wrapper_kind;
    artifact.metadata.insert(
        "wrapper_backend".to_string(),
        wrapper_kind.as_str().to_string(),
    );
    artifact.metadata.insert(
        "delegated_backend".to_string(),
        BackendKind::Nova.as_str().to_string(),
    );
    append_backend_runtime_metadata(&mut artifact.metadata, wrapper_kind);
    Ok(artifact)
}

fn verify_via_nova_native(
    _wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> ZkfResult<bool> {
    let mut nova_compiled = compiled.clone();
    nova_compiled.backend = BackendKind::Nova;

    let mut nova_artifact = artifact.clone();
    nova_artifact.backend = BackendKind::Nova;

    let nova_engine = backend_for(BackendKind::Nova);
    nova_engine.verify(&nova_compiled, &nova_artifact)
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
    append_backend_runtime_metadata(&mut metadata, wrapper_kind);

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
    _wrapper_kind: BackendKind,
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> ZkfResult<bool> {
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
    fn kind_returns_hypernova() {
        assert_eq!(HyperNovaBackend.kind(), BackendKind::HyperNova);
    }

    #[test]
    fn capabilities_declare_ccs_support() {
        let caps = HyperNovaBackend.capabilities();
        assert!(!caps.zkvm_mode);
        assert!(
            caps.supported_constraint_kinds
                .contains(&"blackbox".to_string())
        );
        assert!(
            caps.supported_constraint_kinds
                .contains(&"range".to_string())
        );
    }

    #[test]
    fn compile_rejects_wrong_field() {
        crate::with_serialized_heavy_backend_test(|| {
            let program = Program {
                name: "test".to_string(),
                field: FieldId::Goldilocks,
                signals: vec![],
                constraints: vec![],
                witness_plan: Default::default(),
                ..Default::default()
            };
            let result = HyperNovaBackend.compile(&program);
            assert!(result.is_err());
        });
    }

    #[test]
    fn compile_includes_ccs_metadata() {
        crate::with_serialized_heavy_backend_test(|| {
            use zkf_core::{Constraint, Expr, Signal, Visibility};

            let program = Program {
                name: "ccs_test".to_string(),
                field: FieldId::Bn254,
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
            let compiled = HyperNovaBackend.compile(&program).unwrap();
            assert!(compiled.metadata.contains_key("ccs_num_matrices"));
            assert!(compiled.metadata.contains_key("ccs_degree"));
            assert!(compiled.metadata.contains_key("ccs_num_terms"));
            assert!(compiled.metadata.contains_key("ccs_num_constraints"));
            assert!(compiled.metadata.contains_key("ccs_num_variables"));
            assert!(compiled.metadata.contains_key("ccs_num_public"));

            // Should have 3 matrices (R1CS → CCS), degree 2, 2 terms
            assert_eq!(compiled.metadata.get("ccs_num_matrices").unwrap(), "3");
            assert_eq!(compiled.metadata.get("ccs_degree").unwrap(), "2");
            assert_eq!(compiled.metadata.get("ccs_num_terms").unwrap(), "2");
        });
    }

    #[test]
    fn compile_delegates_for_bn254() {
        crate::with_serialized_heavy_backend_test(|| {
            use zkf_core::{Constraint, Expr, Signal, Visibility};

            let program = Program {
                name: "hypernova_test".to_string(),
                field: FieldId::Bn254,
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
            let compiled = HyperNovaBackend.compile(&program).unwrap();
            assert_eq!(compiled.backend, BackendKind::HyperNova);
            assert!(compiled.metadata.contains_key("delegated_backend"));
        });
    }

    #[cfg(feature = "native-nova")]
    #[test]
    fn native_mode_roundtrips_without_delegated_compiled_blob() {
        use std::collections::BTreeMap;
        use zkf_core::{Constraint, Expr, Signal, Visibility};

        let program = Program {
            name: "hypernova_native_roundtrip".to_string(),
            field: FieldId::Bn254,
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
                label: Some("native_eq".to_string()),
            }],
            witness_plan: Default::default(),
            ..Default::default()
        };
        let compiled = HyperNovaBackend.compile(&program).unwrap();
        assert_eq!(
            compiled.metadata.get("mode").map(String::as_str),
            Some("native")
        );
        assert_eq!(
            compiled
                .metadata
                .get("delegated_backend")
                .map(String::as_str),
            Some(BackendKind::Nova.as_str())
        );

        let mut witness_values = BTreeMap::new();
        witness_values.insert("x".to_string(), zkf_core::FieldElement::from_i64(7));
        witness_values.insert("y".to_string(), zkf_core::FieldElement::from_i64(7));
        let witness = Witness {
            values: witness_values,
        };

        let artifact = HyperNovaBackend.prove(&compiled, &witness).unwrap();
        assert_eq!(artifact.backend, BackendKind::HyperNova);
        assert!(
            HyperNovaBackend.verify(&compiled, &artifact).unwrap(),
            "native HyperNova artifact should verify"
        );
    }
}
