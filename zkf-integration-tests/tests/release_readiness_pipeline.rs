use std::collections::BTreeMap;

use zkf_backends::backend_for;
use zkf_backends::with_allow_dev_deterministic_groth16_override;
use zkf_backends::wrapping::halo2_to_groth16::Halo2ToGroth16Wrapper;
use zkf_backends::wrapping::stark_to_groth16::StarkToGroth16Wrapper;
use zkf_core::wrapping::{ProofWrapper, WrapModeOverride, WrapperExecutionPolicy};
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessInputs, WitnessPlan, generate_witness,
};
use zkf_lib::{export_groth16_solidity_verifier, verify};

fn anchored_square_program(field: FieldId, name: &str) -> Program {
    let square_expr = Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("x")));
    Program {
        name: name.to_string(),
        field,
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
            rhs: square_expr.clone(),
            label: Some("out_eq_x_squared".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: square_expr,
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn sample_inputs() -> WitnessInputs {
    BTreeMap::from([("x".to_string(), FieldElement::from_i64(3))])
}

#[test]
fn groth16_direct_pipeline_emits_solidity_verifier() {
    let program = anchored_square_program(FieldId::Bn254, "release-groth16-direct");
    let inputs = sample_inputs();

    let embedded = with_allow_dev_deterministic_groth16_override(Some(true), || {
        zkf_lib::compile_and_prove(&program, &inputs, "arkworks-groth16", None, None)
    })
    .expect("compile + prove");

    assert!(verify(&embedded.compiled, &embedded.artifact).expect("verify"));

    let solidity = export_groth16_solidity_verifier(&embedded.artifact, Some("ReleaseVerifier"))
        .expect("solidity export");
    assert!(solidity.contains("contract ReleaseVerifier"));
}

#[test]
fn plonky3_wrapped_pipeline_emits_groth16_verifier() {
    let program = anchored_square_program(FieldId::Goldilocks, "release-plonky3-wrap");
    let inputs = sample_inputs();

    let embedded =
        zkf_lib::compile_and_prove(&program, &inputs, "plonky3", None, None).expect("source prove");
    assert!(verify(&embedded.compiled, &embedded.artifact).expect("source verify"));

    let wrapper = StarkToGroth16Wrapper;
    let policy = WrapperExecutionPolicy {
        force_mode: Some(WrapModeOverride::Nova),
        ..WrapperExecutionPolicy::default()
    };
    let wrapped = wrapper
        .wrap_with_policy(&embedded.artifact, &embedded.compiled, policy)
        .expect("wrap plonky3 proof");
    assert!(wrapper.verify_wrapped(&wrapped).expect("verify wrapped"));
    assert_eq!(
        wrapped.metadata.get("trust_model").map(String::as_str),
        Some("attestation")
    );

    let solidity = export_groth16_solidity_verifier(&wrapped, Some("WrappedStarkVerifier"))
        .expect("solidity export");
    assert!(solidity.contains("contract WrappedStarkVerifier"));
}

#[test]
fn halo2_wrapped_pipeline_emits_groth16_verifier() {
    let program = anchored_square_program(FieldId::PastaFp, "release-halo2-wrap");
    let inputs = sample_inputs();
    let witness = generate_witness(&program, &inputs).expect("witness");
    let backend = backend_for(BackendKind::Halo2);
    let compiled = backend.compile(&program).expect("compile");
    let artifact = backend.prove(&compiled, &witness).expect("prove");
    assert!(backend.verify(&compiled, &artifact).expect("source verify"));

    let wrapper = Halo2ToGroth16Wrapper;
    let wrapped = wrapper
        .wrap(&artifact, &compiled)
        .expect("wrap halo2 proof");
    assert!(wrapper.verify_wrapped(&wrapped).expect("verify wrapped"));
    assert_eq!(
        wrapped.metadata.get("trust_model").map(String::as_str),
        Some("attestation")
    );

    let solidity = export_groth16_solidity_verifier(&wrapped, Some("WrappedHalo2Verifier"))
        .expect("solidity export");
    assert!(solidity.contains("contract WrappedHalo2Verifier"));
}
