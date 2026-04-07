use zkf_sdk::{
    Expr, FieldElement, FieldId, ProgramBuilder, WitnessInputs, compile_default, prove, verify,
    witness_from_inputs,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = ProgramBuilder::new("simple_multiply", FieldId::Bn254);
    builder.private_input("x")?;
    builder.private_input("y")?;
    builder.public_output("product")?;
    builder.add_assignment(
        "product",
        Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
    )?;
    builder.constrain_equal(
        Expr::signal("product"),
        Expr::Mul(Box::new(Expr::signal("x")), Box::new(Expr::signal("y"))),
    )?;

    let program = builder.build()?;
    let compiled = compile_default(&program, None)?;
    let inputs = WitnessInputs::from([
        ("x".to_string(), FieldElement::from_i64(3)),
        ("y".to_string(), FieldElement::from_i64(7)),
    ]);
    let witness = witness_from_inputs(&program, &inputs, None)?;
    let artifact = prove(&compiled, &witness)?;

    assert!(verify(&compiled, &artifact)?);
    println!(
        "simple_multiply verified with output {}",
        artifact.public_inputs[0].to_decimal_string()
    );
    Ok(())
}
