use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};
use zkf_core::{BlackBoxOp, Constraint, FieldId, Visibility, WitnessHintKind};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("compact_zkir")
        .join(relative)
}

fn load_fixture_value(relative: &str) -> Value {
    let path = fixture_path(relative);
    serde_json::from_str(&fs::read_to_string(&path).expect("fixture"))
        .expect("fixture json should deserialize")
}

fn import_fixture(relative: &str) -> zkf_core::Program {
    let path = fixture_path(relative);
    let value = load_fixture_value(relative);
    frontend_for(FrontendKind::Compact)
        .compile_to_ir(
            &value,
            &FrontendImportOptions {
                source_path: Some(path),
                ..Default::default()
            },
        )
        .expect("fixture should import")
}

#[test]
fn compact_import_reads_raw_zkir_and_discovers_sidecars() {
    let program = import_fixture("contracts/passing/zkir/set.zkir");

    assert_eq!(program.field, FieldId::Bls12_381);
    assert_eq!(
        program.metadata.get("frontend").map(String::as_str),
        Some("compact")
    );
    assert_eq!(
        program
            .metadata
            .get("preferred_backend")
            .map(String::as_str),
        Some("halo2-bls12-381")
    );
    assert_eq!(
        program
            .metadata
            .get("compact_compiler_version")
            .map(String::as_str),
        Some("0.30.0")
    );
    assert_eq!(
        program
            .metadata
            .get("compact_language_version")
            .map(String::as_str),
        Some("0.21.0")
    );

    let value_signal = program
        .witness_plan
        .input_aliases
        .get("value")
        .expect("contract-info alias should be present");
    let signal = program.signal(value_signal).expect("value signal");
    assert_eq!(signal.visibility, Visibility::Private);
    assert_eq!(signal.ty.as_deref(), Some("Uint<64>"));
    assert!(
        program.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::Range { signal, bits, .. }
                if signal == value_signal && *bits == 64
        )),
        "expected imported Uint<64> argument to carry a range constraint"
    );

    let public_count = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Public)
        .count();
    assert!(
        public_count > 0,
        "disclose transcript should materialize public signals"
    );

    let transcript: Vec<String> = serde_json::from_str(
        program
            .metadata
            .get("compact_public_transcript_json")
            .expect("transcript metadata"),
    )
    .expect("transcript json");
    assert!(
        !transcript.is_empty(),
        "expected disclose/public transcript entries"
    );
}

#[test]
fn compact_import_preserves_underconstrained_linear_contracts_for_audit() {
    let program = import_fixture("contracts/failing/zkir/publish_sum.zkir");
    let analysis = zkf_core::analyze_underconstrained(&program);

    assert_eq!(program.field, FieldId::Bls12_381);
    assert!(
        analysis.linear_nullity > 0,
        "expected positive linear nullity"
    );
    assert!(
        !analysis.linearly_underdetermined_private_signals.is_empty(),
        "expected linearly underdetermined private signals"
    );
}

#[test]
fn compact_import_lowers_test_eq_with_inverse_or_zero_hint() {
    let program = import_fixture("opcodes/test_eq.zkir");

    assert!(
        program
            .witness_plan
            .hints
            .iter()
            .any(|hint| hint.kind == WitnessHintKind::InverseOrZero),
        "test_eq should request an inverse_or_zero witness hint"
    );
    assert!(
        program
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Boolean { label, .. } if label.as_deref().is_some_and(|label| label.contains("compact_test_eq_boolean")))),
        "test_eq should add a boolean constraint for the equality flag"
    );
    assert!(
        program
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Equal { label, .. } if label.as_deref().is_some_and(|label| label.contains("zero_product")))),
        "test_eq should add the zero-product anchor"
    );
}

#[test]
fn compact_import_lowers_cond_select_with_boolean_guard() {
    let program = import_fixture("opcodes/cond_select.zkir");

    assert!(
        program
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Boolean { label, .. } if label.as_deref().is_some_and(|label| label.contains("compact_cond_select_guard")))),
        "cond_select should constrain its selector to be boolean"
    );
    assert!(
        program
            .signals
            .iter()
            .any(|signal| signal.visibility == Visibility::Public),
        "cond_select fixture should expose its selected output publicly"
    );
}

#[test]
fn compact_import_lowers_div_mod_power_of_two_into_range_and_recomposition() {
    let program = import_fixture("opcodes/div_mod_power_of_two.zkir");

    assert!(
        program
            .constraints
            .iter()
            .any(|constraint| matches!(
                constraint,
                Constraint::Range { bits, label, .. }
                    if *bits == 5 && label.as_deref().is_some_and(|label| label.contains("div_mod_pow2_range"))
            )),
        "div_mod_power_of_two should range-check the remainder"
    );
    assert!(
        program
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Equal { label, .. } if label.as_deref().is_some_and(|label| label.contains("div_mod_pow2_recompose")))),
        "div_mod_power_of_two should add a recomposition equality"
    );
}

#[test]
fn compact_import_lowers_persistent_hash_to_poseidon_blackbox() {
    let program = import_fixture("opcodes/persistent_hash.zkir");

    assert!(
        program.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                params,
                ..
            } if params.get("state_len").map(String::as_str) == Some("4")
        )),
        "persistent_hash should import as a Poseidon black-box constraint"
    );
}

#[test]
fn compact_import_rejects_unsupported_schema_unknown_opcode_and_dynamic_pi_skip() {
    let compact = frontend_for(FrontendKind::Compact);

    let schema_err = compact
        .compile_to_ir(
            &json!({
                "version": { "major": 3, "minor": 0 },
                "do_communications_commitment": false,
                "num_inputs": 0,
                "instructions": []
            }),
            &FrontendImportOptions::default(),
        )
        .expect_err("unsupported schema should fail closed");
    assert!(schema_err.to_string().contains("schema version 2.0"));

    let opcode_err = compact
        .compile_to_ir(
            &json!({
                "version": { "major": 2, "minor": 0 },
                "do_communications_commitment": false,
                "num_inputs": 0,
                "instructions": [{ "op": "mystery_opcode" }]
            }),
            &FrontendImportOptions::default(),
        )
        .expect_err("unknown opcode should fail closed");
    assert!(
        opcode_err
            .to_string()
            .contains("unsupported Compact zkir opcode")
    );

    let pi_skip_err = compact
        .compile_to_ir(
            &load_fixture_value("opcodes/dynamic_pi_skip.zkir"),
            &FrontendImportOptions::default(),
        )
        .expect_err("dynamic pi_skip guard should fail closed");
    assert!(pi_skip_err.to_string().contains("compile-time constant"));

    let poseidon_err = compact
        .compile_to_ir(
            &load_fixture_value("opcodes/unsupported_poseidon_width.zkir"),
            &FrontendImportOptions::default(),
        )
        .expect_err("unsupported poseidon width should fail closed");
    assert!(poseidon_err.to_string().contains("width-4"));
}
