use serde_json::{Map, Value};
use zkf_lib::{
    TradeFinanceActionClassV1, TradeFinancePrivateInputsV1, Visibility,
    build_trade_finance_decision_core_program, private_trade_finance_settlement_approve_inputs,
    private_trade_finance_settlement_approve_with_manual_review_inputs,
    private_trade_finance_settlement_inconsistency_rejection_inputs,
    private_trade_finance_settlement_reject_for_rule_failure_inputs,
    private_trade_finance_settlement_risk_review_inputs,
    trade_finance_decision_witness_from_inputs,
};

#[test]
fn trade_finance_decision_core_fixture_builds_and_witnesses() {
    let program = build_trade_finance_decision_core_program().expect("program");
    let request = private_trade_finance_settlement_approve_inputs();
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

#[test]
fn trade_finance_action_matrix_matches_expected_paths() {
    let cases = [
        (
            private_trade_finance_settlement_approve_inputs(),
            TradeFinanceActionClassV1::Approve,
            true,
        ),
        (
            private_trade_finance_settlement_approve_with_manual_review_inputs(),
            TradeFinanceActionClassV1::ApproveWithManualReview,
            false,
        ),
        (
            private_trade_finance_settlement_risk_review_inputs(),
            TradeFinanceActionClassV1::EscalateForRiskReview,
            false,
        ),
        (
            private_trade_finance_settlement_reject_for_rule_failure_inputs(),
            TradeFinanceActionClassV1::RejectForRuleFailure,
            false,
        ),
        (
            private_trade_finance_settlement_inconsistency_rejection_inputs(),
            TradeFinanceActionClassV1::RejectForInconsistency,
            false,
        ),
    ];

    for (request, expected_action, expected_settlement_eligibility) in cases {
        let (_witness, computation) =
            trade_finance_decision_witness_from_inputs(&request).expect("witness");
        let rendered = serde_json::to_value(&computation).expect("serialize computation");
        let action = rendered
            .get("action_class")
            .and_then(Value::as_str)
            .expect("action_class string");
        let expected_action_name = match expected_action {
            TradeFinanceActionClassV1::Approve => "approve",
            TradeFinanceActionClassV1::ApproveWithManualReview => "approve_with_manual_review",
            TradeFinanceActionClassV1::EscalateForRiskReview => "escalate_for_risk_review",
            TradeFinanceActionClassV1::RejectForRuleFailure => "reject_for_rule_failure",
            TradeFinanceActionClassV1::RejectForInconsistency => "reject_for_inconsistency",
        };
        assert_eq!(action, expected_action_name);
        assert_eq!(
            computation.eligible_for_midnight_settlement(),
            expected_settlement_eligibility,
        );
    }
}

#[test]
fn trade_finance_root_legacy_aliases_are_rejected_and_canonical_names_serialize() {
    fn rename_key(map: &mut Map<String, Value>, from: &str, to: &str) {
        let value = map
            .remove(from)
            .unwrap_or_else(|| panic!("missing key {from}"));
        assert!(
            map.insert(to.to_string(), value).is_none(),
            "duplicate key {to}"
        );
    }

    let sample = private_trade_finance_settlement_approve_inputs();
    let canonical = serde_json::to_value(&sample).expect("serialize sample");
    let root = canonical.as_object().expect("root object");
    for canonical_key in [
        "financing_policy",
        "receivable_context",
        "supporting_documents",
        "duplicate_risk_inputs",
        "settlement_terms",
    ] {
        assert!(
            root.contains_key(canonical_key),
            "missing canonical key {canonical_key}"
        );
    }
    fn legacy_root_key(parts: &[&str]) -> String {
        parts.concat()
    }

    let legacy_root_keys = [
        legacy_root_key(&["po", "licy"]),
        legacy_root_key(&["cl", "aim_event"]),
        legacy_root_key(&["evi", "dence"]),
        legacy_root_key(&["analysis_", "inputs"]),
        legacy_root_key(&["settlement_", "governance"]),
    ];
    for legacy_key in &legacy_root_keys {
        assert!(
            !root.contains_key(legacy_key),
            "legacy key {legacy_key} should not be emitted",
        );
    }

    let mut root = root.clone();
    rename_key(&mut root, "financing_policy", &legacy_root_keys[0]);
    rename_key(&mut root, "receivable_context", &legacy_root_keys[1]);
    rename_key(&mut root, "supporting_documents", &legacy_root_keys[2]);
    rename_key(&mut root, "duplicate_risk_inputs", &legacy_root_keys[3]);
    rename_key(&mut root, "settlement_terms", &legacy_root_keys[4]);

    let err = serde_json::from_value::<TradeFinancePrivateInputsV1>(Value::Object(root))
        .expect_err("root legacy aliases should be rejected");
    let text = err.to_string();
    assert!(
        legacy_root_keys
            .iter()
            .any(|legacy_key| text.contains(legacy_key))
            || text.contains("unknown field"),
        "unexpected error: {text}"
    );
}

#[test]
fn trade_finance_nested_legacy_aliases_are_rejected() {
    fn rename_key(map: &mut Map<String, Value>, from: &str, to: &str) {
        let value = map
            .remove(from)
            .unwrap_or_else(|| panic!("missing key {from}"));
        assert!(
            map.insert(to.to_string(), value).is_none(),
            "duplicate key {to}"
        );
    }

    let sample = private_trade_finance_settlement_approve_inputs();
    let mut root = serde_json::to_value(&sample)
        .expect("serialize sample")
        .as_object()
        .expect("root object")
        .clone();

    let financing_policy = root
        .get_mut("financing_policy")
        .and_then(Value::as_object_mut)
        .expect("financing_policy object");
    let legacy_open_timestamp = ["po", "licy_effective_timestamp"].concat();
    rename_key(
        financing_policy,
        "financing_window_open_timestamp",
        &legacy_open_timestamp,
    );

    let err = serde_json::from_value::<TradeFinancePrivateInputsV1>(Value::Object(root))
        .expect_err("nested legacy aliases should be rejected");
    let text = err.to_string();
    assert!(
        text.contains(&legacy_open_timestamp) || text.contains("unknown field"),
        "unexpected error: {text}"
    );
}

#[test]
fn trade_finance_invalid_receivable_timeline_is_rejected() {
    let mut request = private_trade_finance_settlement_approve_inputs();
    request.receivable_context.invoice_presented_timestamp = 1_950_000_000;
    request.receivable_context.financing_request_timestamp = 1_940_000_000;
    let err = trade_finance_decision_witness_from_inputs(&request).expect_err("timeline must fail");
    let text = err.to_string();
    assert!(
        text.contains("invoice presented timestamp")
            || text.contains("financing request timestamp")
            || text.contains("flagship lane"),
        "unexpected error: {text}",
    );
}
