use zkf_sdk::{
    Constraint, ConstraintKind, Expr, FieldElement, FieldId, ProgramBuilder, SignalType,
    SignalVisibility, WitnessInputs, compile_default, prove, verify, witness_from_inputs,
};

#[test]
fn sdk_exports_support_a_basic_multiply_flow() {
    let mut builder = ProgramBuilder::new("sdk_multiply", FieldId::Bn254);
    builder.private_input("x").expect("private x");
    builder.private_input("y").expect("private y");
    builder.public_output("product").expect("public output");
    builder
        .add_assignment(
            "product",
            Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
        )
        .expect("assignment");
    builder
        .constrain_equal(
            Expr::signal("product"),
            Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
        )
        .expect("constraint");

    let program = builder.build().expect("program");
    assert!(matches!(program.signals[2].visibility, SignalVisibility::Public));
    assert!(matches!(program.constraints[0], Constraint::Equal { .. }));
    assert_eq!(ConstraintKind::Equal, ConstraintKind::Equal);
    assert!(matches!(SignalType::Field, SignalType::Field));

    let compiled = compile_default(&program, None).expect("compile");
    let inputs = WitnessInputs::from([
        ("x".to_string(), FieldElement::from_i64(4)),
        ("y".to_string(), FieldElement::from_i64(6)),
    ]);
    let witness = witness_from_inputs(&program, &inputs, None).expect("witness");
    let artifact = prove(&compiled, &witness).expect("prove");

    assert!(verify(&compiled, &artifact).expect("verify"));
    assert_eq!(artifact.public_inputs[0].to_decimal_string(), "24");
}
