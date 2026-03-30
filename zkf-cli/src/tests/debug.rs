use super::*;

#[test]
fn debug_writes_report_for_partial_witness_and_keeps_concrete_failures() {
    let root = tempfile::tempdir().expect("tempdir");
    let program_path = root.path().join("program.json");
    let inputs_path = root.path().join("inputs.json");
    let out_path = root.path().join("debug.json");

    let program = Program {
        name: "partial_debug".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "hidden".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "out".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: zkf_core::Expr::signal("out"),
                rhs: zkf_core::Expr::signal("hidden"),
                label: Some("unresolved_link".to_string()),
            },
            Constraint::Range {
                signal: "x".to_string(),
                bits: 8,
                label: Some("x_range".to_string()),
            },
        ],
        witness_plan: zkf_core::WitnessPlan::default(),
        ..Default::default()
    };

    write_json(&program_path, &program).expect("program");
    write_json(
        &inputs_path,
        &WitnessInputs::from([("x".to_string(), FieldElement::from_i64(300))]),
    )
    .expect("inputs");

    crate::cmd::debug::handle_debug(program_path, inputs_path, out_path.clone(), false, false, None)
        .expect("debug should write a report for partial witnesses");

    let report: zkf_core::DebugReport = read_json(&out_path).expect("debug report");
    assert!(!report.passed);
    assert_eq!(report.evaluated_constraints, 2);
    assert_eq!(report.total_constraints, 2);
    assert_eq!(report.first_failure_index, Some(0));
    assert!(
        report
            .constraints
            .iter()
            .any(|trace| trace.index == 0 && trace.error.is_some()),
        "expected unresolved dependency information in the report"
    );
    assert!(
        report
            .constraints
            .iter()
            .any(|trace| trace.index == 1 && !trace.passed && trace.error.is_none()),
        "expected the later concrete range failure to remain in the report"
    );
}
