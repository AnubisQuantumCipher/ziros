use crate::blackbox_gadgets;
use crate::blackbox_native::validate_blackbox_constraints;
use crate::r1cs_lowering::LoweredR1csProgram;
use crate::range_decomposition;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use zkf_core::{
    AuditCategory, AuditStatus, BackendKind, CompiledProgram, Program, Witness, ZkfError,
    ZkfResult, analyze_underconstrained, check_constraints,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompileGateDecision {
    Audited,
    ExplicitUncheckedBypass,
}

type CompileGateCacheKey = (String, String, String);
type CompileGateCache = Mutex<BTreeMap<CompileGateCacheKey, CompileGateDecision>>;

fn compile_gate_cache() -> &'static CompileGateCache {
    static CACHE: OnceLock<CompileGateCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn compile_gate_cache_key(
    backend: BackendKind,
    source_program: &Program,
    compiled_program: &Program,
) -> CompileGateCacheKey {
    (
        backend.as_str().to_string(),
        source_program.digest_hex(),
        compiled_program.digest_hex(),
    )
}

fn remember_compile_gate_decision(
    backend: BackendKind,
    source_program: &Program,
    compiled_program: &Program,
    decision: CompileGateDecision,
) {
    let key = compile_gate_cache_key(backend, source_program, compiled_program);
    match compile_gate_cache().lock() {
        Ok(mut cache) => {
            cache.insert(key, decision);
        }
        Err(poisoned) => {
            poisoned.into_inner().insert(key, decision);
        }
    }
}

fn remember_audited_compile(
    backend: BackendKind,
    source_program: &Program,
    compiled_program: &Program,
) {
    remember_compile_gate_decision(
        backend,
        source_program,
        compiled_program,
        CompileGateDecision::Audited,
    );
}

pub(crate) fn remember_unchecked_compile_gate_bypass(
    backend: BackendKind,
    source_program: &Program,
    compiled_program: &Program,
) {
    remember_compile_gate_decision(
        backend,
        source_program,
        compiled_program,
        CompileGateDecision::ExplicitUncheckedBypass,
    );
}

fn has_compile_gate_clearance(
    backend: BackendKind,
    source_program: &Program,
    compiled_program: &Program,
) -> bool {
    let key = compile_gate_cache_key(backend, source_program, compiled_program);
    match compile_gate_cache().lock() {
        Ok(cache) => cache.contains_key(&key),
        Err(poisoned) => poisoned.into_inner().contains_key(&key),
    }
}

fn audited_compile_categories() -> [AuditCategory; 4] {
    [
        AuditCategory::TypeSafety,
        AuditCategory::Normalization,
        AuditCategory::UnderconstrainedSignals,
        AuditCategory::ConstraintSoundness,
    ]
}

fn audited_compiled_surface_categories() -> [AuditCategory; 3] {
    [
        AuditCategory::TypeSafety,
        AuditCategory::Normalization,
        AuditCategory::ConstraintSoundness,
    ]
}

fn format_blocking_finding(finding: &zkf_core::AuditFinding) -> String {
    match finding.suggestion.as_deref() {
        Some(suggestion) => format!("{} Suggestion: {}", finding.message, suggestion),
        None => finding.message.clone(),
    }
}

#[inline]
fn should_retain_original_program(source_program: &Program, compiled_program: &Program) -> bool {
    source_program.digest_hex() != compiled_program.digest_hex()
}

fn ensure_program_passes_audited_compile(
    backend: BackendKind,
    program: &Program,
    categories: &[AuditCategory],
    surface: &str,
) -> ZkfResult<()> {
    let zir = zkf_core::program_v2_to_zir(program);
    let report = zkf_core::audit_program(&zir, Some(backend));
    let blocking_checks = report
        .checks
        .iter()
        .filter(|check| check.status == AuditStatus::Fail && categories.contains(&check.category))
        .map(|check| {
            let evidence = check.evidence.as_deref().unwrap_or("no evidence");
            format!("{} ({:?}): {}", check.name, check.category, evidence)
        })
        .collect::<Vec<_>>();

    if blocking_checks.is_empty() {
        return Ok(());
    }

    let blocking_findings = report
        .findings
        .iter()
        .filter(|finding| categories.contains(&finding.category))
        .map(format_blocking_finding)
        .take(3)
        .collect::<Vec<_>>();

    let mut message = format!(
        "{surface} program audit failed before compile: {}",
        blocking_checks.join("; ")
    );
    if !blocking_findings.is_empty() {
        message.push_str(" | findings: ");
        message.push_str(&blocking_findings.join(" | "));
    }

    let analysis = categories
        .contains(&AuditCategory::UnderconstrainedSignals)
        .then(|| {
            report
                .checks
                .iter()
                .any(|check| {
                    check.category == AuditCategory::UnderconstrainedSignals
                        && check.status == AuditStatus::Fail
                })
                .then(|| analyze_underconstrained(program))
        })
        .flatten()
        .map(Box::new);

    Err(ZkfError::AuditFailure {
        message,
        failed_checks: blocking_checks.len(),
        report: Box::new(report),
        analysis,
    })
}

pub(crate) fn build_audited_compiled_program(
    backend: BackendKind,
    source_program: &Program,
    compiled_program: Program,
) -> ZkfResult<CompiledProgram> {
    ensure_program_passes_audited_compile(
        backend,
        source_program,
        &audited_compile_categories(),
        "source",
    )?;
    ensure_program_passes_audited_compile(
        backend,
        &compiled_program,
        &audited_compiled_surface_categories(),
        "compiled",
    )?;
    let mut compiled = CompiledProgram::new(backend, compiled_program);
    if should_retain_original_program(source_program, &compiled.program) {
        compiled.original_program = Some(source_program.clone());
    }
    remember_audited_compile(backend, source_program, &compiled.program);
    Ok(compiled)
}

pub(crate) fn attach_r1cs_lowering_metadata(
    compiled: &mut CompiledProgram,
    lowered: &LoweredR1csProgram,
) {
    compiled.metadata.insert(
        "r1cs_constraints_total".to_string(),
        lowered.summary.constraints_total.to_string(),
    );
    compiled.metadata.insert(
        "r1cs_recursive_markers".to_string(),
        lowered.summary.recursive_marker_constraints.to_string(),
    );
    compiled.metadata.insert(
        "lowering_adapted_count".to_string(),
        lowered.summary.blackbox_constraints_lowered.to_string(),
    );
    compiled
        .metadata
        .insert("lowering_dropped_count".to_string(), "0".to_string());
    compiled.lowering_report = Some(lowered.lowering_report.clone());
}

pub(crate) fn audited_witness_for_proving(
    backend: BackendKind,
    compiled: &CompiledProgram,
    witness: &Witness,
) -> ZkfResult<Witness> {
    let source_program = compiled
        .original_program
        .as_ref()
        .unwrap_or(&compiled.program);
    if !has_compile_gate_clearance(backend, source_program, &compiled.program) {
        ensure_program_passes_audited_compile(
            backend,
            source_program,
            &audited_compile_categories(),
            "source",
        )?;
        ensure_program_passes_audited_compile(
            backend,
            &compiled.program,
            &audited_compiled_surface_categories(),
            "compiled",
        )?;
    }
    let enriched = blackbox_gadgets::enrich_witness_for_proving(compiled, witness)?;
    let enriched = range_decomposition::enrich_range_witness(
        &compiled.program,
        &compiled.metadata,
        &enriched,
    )?;
    // When the compiled artifact preserved a pre-lowering source program, run
    // native BlackBox validation against that original surface too. Otherwise,
    // post-lowering validation only sees the arithmetic expansion and silently
    // skips the critical op-specific checks.
    if let Some(original_program) = &compiled.original_program {
        validate_blackbox_constraints(backend, original_program, &enriched)?;
    }
    check_constraints(&compiled.program, &enriched)?;
    validate_blackbox_constraints(backend, &compiled.program, &enriched)?;
    Ok(enriched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range_decomposition;
    use acir::FieldElement as AcirFieldElement;
    use bn254_blackbox_solver::poseidon2_permutation;
    use num_bigint::{BigInt, Sign};
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use zkf_core::{
        BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Signal, Visibility, Witness,
        WitnessPlan,
    };

    fn digest_fixture(name: String) -> Program {
        Program {
            name,
            field: FieldId::Bn254,
            ..Program::default()
        }
    }

    fn poseidon_source_program() -> Program {
        let mut signals = (0..4)
            .map(|index| Signal {
                name: format!("in{index}"),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            })
            .collect::<Vec<_>>();
        signals.extend((0..4).map(|index| Signal {
            name: format!("out{index}"),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        }));

        Program {
            name: "audited-poseidon".to_string(),
            field: FieldId::Bn254,
            signals,
            constraints: vec![Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                inputs: (0..4)
                    .map(|index| Expr::Signal(format!("in{index}")))
                    .collect(),
                outputs: (0..4).map(|index| format!("out{index}")).collect(),
                params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
                label: Some("poseidon".to_string()),
            }],
            witness_plan: WitnessPlan::default(),
            ..Program::default()
        }
    }

    fn poseidon_witness(valid: bool) -> Witness {
        let expected =
            poseidon2_permutation(&vec![AcirFieldElement::zero(); 4], 4).expect("solver works");
        let mut values = BTreeMap::new();
        for index in 0..4 {
            values.insert(format!("in{index}"), FieldElement::from_i64(0));
            let output = if !valid && index == 0 {
                FieldElement::from_i64(1)
            } else {
                let bigint = BigInt::from_bytes_be(Sign::Plus, &expected[index].to_be_bytes());
                FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
            };
            values.insert(format!("out{index}"), output);
        }
        Witness { values }
    }

    proptest! {
        #[test]
        fn audited_compiled_program_retains_original_only_when_digest_changes(
            source_suffix in any::<u8>(),
            compiled_suffix in any::<u8>(),
            same_digest in any::<bool>(),
        ) {
            let source = digest_fixture(format!("source-{source_suffix}"));
            let compiled_program = if same_digest {
                source.clone()
            } else {
                digest_fixture(format!("compiled-{compiled_suffix}"))
            };

            let compiled = build_audited_compiled_program(
                BackendKind::ArkworksGroth16,
                &source,
                compiled_program,
            )
            .expect("audit-safe digest fixture should compile");

            if same_digest {
                prop_assert!(compiled.original_program.is_none());
            } else {
                prop_assert_eq!(compiled.original_program.as_ref(), Some(&source));
            }
            prop_assert!(has_compile_gate_clearance(
                BackendKind::ArkworksGroth16,
                &source,
                &compiled.program,
            ));
        }
    }

    #[test]
    fn audited_witness_uses_original_program_for_blackbox_validation() {
        let source = poseidon_source_program();
        let lowered =
            crate::blackbox_gadgets::lower_blackbox_program(&source).expect("poseidon lowering");
        let mut compiled =
            build_audited_compiled_program(BackendKind::ArkworksGroth16, &source, lowered)
                .expect("poseidon fixture should compile");
        compiled.original_program = Some(source);

        let err = audited_witness_for_proving(
            BackendKind::ArkworksGroth16,
            &compiled,
            &poseidon_witness(false),
        )
        .expect_err("invalid Poseidon output must be rejected against original blackbox");

        assert!(
            err.to_string().contains("poseidon"),
            "error should mention the original blackbox validation path: {err}"
        );
    }

    #[test]
    fn audited_witness_accepts_valid_original_blackbox_witness() {
        let source = poseidon_source_program();
        let lowered =
            crate::blackbox_gadgets::lower_blackbox_program(&source).expect("poseidon lowering");
        let mut compiled =
            build_audited_compiled_program(BackendKind::ArkworksGroth16, &source, lowered)
                .expect("poseidon fixture should compile");
        compiled.original_program = Some(source);

        let enriched = audited_witness_for_proving(
            BackendKind::ArkworksGroth16,
            &compiled,
            &poseidon_witness(true),
        )
        .expect("valid Poseidon output must survive original-program validation");

        assert_eq!(
            enriched.values.get("out0"),
            Some(&poseidon_witness(true).values["out0"]),
        );
    }

    #[test]
    fn audited_compile_rejects_linearly_underdetermined_program() {
        let program = Program {
            name: "underdetermined".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
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
                lhs: Expr::Signal("out".to_string()),
                rhs: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Signal("y".to_string()),
                ]),
                label: Some("sum".to_string()),
            }],
            witness_plan: WitnessPlan::default(),
            ..Program::default()
        };

        let err =
            build_audited_compiled_program(BackendKind::ArkworksGroth16, &program, program.clone())
                .expect_err("linearly underdetermined circuits must fail compile-time audit");

        assert!(
            err.to_string().contains("underconstrained_signals"),
            "compile error should mention the failed audit check: {err}"
        );
    }

    #[test]
    fn audited_compile_rejects_signature_sham_program() {
        let program = Program {
            name: "fake_signature_check".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "issuer_public_key".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "issuer_signature_r".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "issuer_signature_s".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "is_issuer_valid".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("issuer_signature_s".to_string()),
                    rhs: Expr::Mul(
                        Box::new(Expr::Signal("issuer_public_key".to_string())),
                        Box::new(Expr::Signal("issuer_signature_r".to_string())),
                    ),
                    label: Some("issuer_signature_relation".to_string()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("is_issuer_valid".to_string()),
                    rhs: Expr::Const(FieldElement::from_i64(1)),
                    label: Some("issuer_auth_claim".to_string()),
                },
            ],
            witness_plan: WitnessPlan::default(),
            metadata: BTreeMap::from([(
                "issuer_public_key_hint".to_string(),
                "demo-only".to_string(),
            )]),
            ..Program::default()
        };

        let err =
            build_audited_compiled_program(BackendKind::ArkworksGroth16, &program, program.clone())
                .expect_err("signature shams must fail compile-time audit");

        assert!(
            err.to_string().contains("signature_semantics"),
            "compile error should mention the failed signature audit check: {err}"
        );
    }

    #[test]
    fn unchecked_compile_gate_bypass_is_cached_for_runtime_reuse() {
        let source = digest_fixture("unchecked-source".to_string());
        let compiled_program = digest_fixture("unchecked-compiled".to_string());

        remember_unchecked_compile_gate_bypass(
            BackendKind::ArkworksGroth16,
            &source,
            &compiled_program,
        );

        let key = compile_gate_cache_key(BackendKind::ArkworksGroth16, &source, &compiled_program);
        let decision = match compile_gate_cache().lock() {
            Ok(cache) => cache.get(&key).copied(),
            Err(poisoned) => poisoned.into_inner().get(&key).copied(),
        };

        assert_eq!(decision, Some(CompileGateDecision::ExplicitUncheckedBypass));
        assert!(has_compile_gate_clearance(
            BackendKind::ArkworksGroth16,
            &source,
            &compiled_program,
        ));
    }

    #[test]
    fn audited_witness_for_proving_populates_range_chunks_before_constraint_check() {
        let raw_program = Program {
            name: "range_chunk_enrichment".to_string(),
            field: FieldId::Bls12_381,
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
            constraints: vec![
                Constraint::Range {
                    signal: "x".to_string(),
                    bits: 64,
                    label: Some("x_range".to_string()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("out".to_string()),
                    rhs: Expr::Signal("x".to_string()),
                    label: Some("publish_x".to_string()),
                },
            ],
            ..Program::default()
        };

        let (compiled_surface, decompositions) =
            range_decomposition::lower_large_range_constraints(&raw_program, 16, "halo2_bls")
                .expect("range lowering");
        let mut compiled = build_audited_compiled_program(
            BackendKind::Halo2Bls12381,
            &raw_program,
            compiled_surface,
        )
        .expect("audited compiled program");
        range_decomposition::write_range_decomposition_metadata(
            &mut compiled.metadata,
            &decompositions,
        )
        .expect("range decomposition metadata");

        let witness = Witness {
            values: BTreeMap::from([("x".to_string(), FieldElement::from_i64(7))]),
        };
        let enriched = audited_witness_for_proving(BackendKind::Halo2Bls12381, &compiled, &witness)
            .expect("range chunks should be derived before audited constraint checks");

        assert!(
            enriched.values.contains_key("__halo2_bls_range_0_chunk_0"),
            "expected range chunk witness to be populated"
        );
    }
}
