// Run directly with:
// cargo test -p zkf-backends --test range_limit_provenance -- --nocapture

use zkf_backends::backend_for;
use zkf_core::{BackendKind, Constraint, FieldId, Program, Signal, Visibility};

#[test]
fn plonky3_compile_names_signal_and_constraint_for_unsupported_range_bits() {
    let program = Program {
        field: FieldId::Goldilocks,
        signals: vec![Signal {
            name: "value".to_string(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Range {
            signal: "value".to_string(),
            bits: 67,
            label: Some("value_range".to_string()),
        }],
        ..Default::default()
    };

    let error = backend_for(BackendKind::Plonky3)
        .compile(&program)
        .expect_err("range should overflow Goldilocks");
    let rendered = error.to_string();
    assert!(rendered.contains("signal value"));
    assert!(rendered.contains("constraint #0"));
    assert!(rendered.contains("value_range"));
}
