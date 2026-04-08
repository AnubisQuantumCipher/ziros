use zkf_lib::{
    build_trade_finance_decision_core_program, private_trade_finance_approve_inputs,
    trade_finance_decision_witness_from_inputs, Visibility,
};

#[test]
fn trade_finance_decision_core_fixture_builds_and_witnesses() {
    let program = build_trade_finance_decision_core_program().expect("program");
    let request = private_trade_finance_approve_inputs();
    let (_witness, computation) =
        trade_finance_decision_witness_from_inputs(&request).expect("witness");

    assert!(
        program
            .signals
            .iter()
            .any(|signal| matches!(signal.visibility, Visibility::Public)),
        "expected public outputs"
    );
    assert!(
        computation.eligible_for_midnight_settlement(),
        "approval fixture should be settlement-eligible"
    );
}
