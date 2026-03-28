use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use crate::cmd::equivalence::{EquivalenceOptions, run_equivalence_report};
use zkf_core::{BlackBoxOp, Constraint, Expr, FieldId, Program, Signal, Visibility, WitnessPlan};
use zkf_examples::{mul_add_inputs, mul_add_program};

fn equivalence_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn equivalence_report_tracks_field_adaptation_and_public_outputs() {
    let _guard = equivalence_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let report = run_equivalence_report(
        &mul_add_program(),
        &mul_add_inputs(3, 5),
        EquivalenceOptions {
            backends: vec!["plonky3".to_string(), "halo2".to_string()],
            ..Default::default()
        },
    )
    .expect("equivalence report");

    assert!(
        report.equivalent,
        "expected matching verified outputs: {report:?}"
    );
    assert!(report.mismatches.is_empty());
    assert_eq!(report.results.len(), 2);

    let plonky3 = &report.results[0];
    assert_eq!(plonky3.requested_backend, "plonky3");
    assert_eq!(plonky3.effective_backend, "plonky3");
    assert_eq!(plonky3.requested_field, "bn254");
    assert_eq!(plonky3.effective_field, "goldilocks");
    assert!(plonky3.field_adapted);
    assert!(plonky3.compatibility_ok);
    assert!(plonky3.compile_ok);
    assert!(plonky3.prove_ok);
    assert!(plonky3.verify_ok);
    assert_eq!(
        plonky3.public_outputs,
        vec!["5".to_string(), "24".to_string()]
    );

    let halo2 = &report.results[1];
    assert_eq!(halo2.requested_backend, "halo2");
    assert_eq!(halo2.effective_backend, "halo2");
    assert_eq!(halo2.requested_field, "bn254");
    assert_eq!(halo2.effective_field, "pasta-fp");
    assert!(halo2.field_adapted);
    assert!(halo2.compatibility_ok);
    assert!(halo2.compile_ok);
    assert!(halo2.prove_ok);
    assert!(halo2.verify_ok);
    assert_eq!(
        halo2.public_outputs,
        vec!["5".to_string(), "24".to_string()]
    );
}

#[test]
fn equivalence_report_supports_seeded_groth16_execution() {
    let _guard = equivalence_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let report = run_equivalence_report(
        &mul_add_program(),
        &mul_add_inputs(3, 5),
        EquivalenceOptions {
            backends: vec!["arkworks-groth16".to_string()],
            seed: Some([0x44; 32]),
            allow_dev_deterministic_groth16: true,
            ..Default::default()
        },
    )
    .expect("groth16 equivalence report");

    assert!(
        report.equivalent,
        "expected groth16 leg to succeed: {report:?}"
    );
    assert!(report.mismatches.is_empty());
    assert_eq!(report.results.len(), 1);

    let groth16 = &report.results[0];
    assert_eq!(groth16.requested_backend, "arkworks-groth16");
    assert_eq!(groth16.effective_backend, "arkworks-groth16");
    assert_eq!(groth16.requested_field, "bn254");
    assert_eq!(groth16.effective_field, "bn254");
    assert!(!groth16.field_adapted);
    assert!(groth16.compatibility_ok);
    assert!(groth16.compile_ok);
    assert!(groth16.prove_ok);
    assert!(groth16.verify_ok);
    assert_eq!(
        groth16.public_outputs,
        vec!["5".to_string(), "24".to_string()]
    );
}

#[test]
fn equivalence_report_rejects_field_specific_blackbox_adaptation_preflight() {
    let _guard = equivalence_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let program = Program {
        name: "identity_poseidon_commitment".to_string(),
        field: FieldId::Bn254,
        signals: (0..4)
            .map(|index| Signal {
                name: format!("in_{index}"),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            })
            .chain((0..4).map(|index| Signal {
                name: format!("out_{index}"),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            }))
            .collect(),
        constraints: vec![Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: (0..4)
                .map(|index| Expr::signal(format!("in_{index}")))
                .collect(),
            outputs: (0..4).map(|index| format!("out_{index}")).collect(),
            params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
            label: Some("identity_commitment".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };

    let report = run_equivalence_report(
        &program,
        &BTreeMap::from([
            ("in_0".to_string(), zkf_core::FieldElement::from_i64(1)),
            ("in_1".to_string(), zkf_core::FieldElement::from_i64(2)),
            ("in_2".to_string(), zkf_core::FieldElement::from_i64(3)),
            ("in_3".to_string(), zkf_core::FieldElement::from_i64(4)),
        ]),
        EquivalenceOptions {
            backends: vec!["plonky3".to_string()],
            ..Default::default()
        },
    )
    .expect("equivalence report");

    assert!(!report.equivalent);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0];
    assert!(!result.compatibility_ok);
    assert!(!result.field_adapted);
    assert!(!result.compile_ok);
    assert_eq!(
        result.error.as_deref(),
        Some("compatibility: field adaptation blocked")
    );
    assert!(
        result
            .compatibility_reasons
            .iter()
            .any(|reason| reason.contains("field-specific")),
        "expected explicit field-specific compatibility reason: {:?}",
        result.compatibility_reasons
    );
}
