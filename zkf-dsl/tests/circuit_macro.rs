#[allow(unused_imports)]
use zkf_core::dsl_types::{Field, Private, Public};
use zkf_dsl as zkf;

#[zkf::circuit(field = "bn254")]
fn multiply(x: Private<Field>, y: Private<Field>) -> Public<Field> {
    x * y
}

#[zkf::circuit(field = "bn254")]
fn add_circuit(x: Private<Field>, y: Private<Field>) -> Public<Field> {
    x + y
}

#[zkf::circuit(field = "bn254")]
fn with_intermediate(x: Private<Field>, y: Private<Field>) -> Public<Field> {
    let sum = x + y;
    let result = sum * x;
    result
}

#[test]
fn multiply_program_compiles_and_has_signals() {
    let program = multiply_program();
    assert_eq!(program.name, "multiply");
    assert!(!program.signals.is_empty());
}

#[test]
fn multiply_inputs_builds_witness() {
    let inputs = multiply_inputs("3", "7");
    assert!(inputs.contains_key("x"));
    assert!(inputs.contains_key("y"));
}

#[test]
fn add_circuit_program_compiles() {
    let program = add_circuit_program();
    assert_eq!(program.name, "add_circuit");
    assert!(!program.signals.is_empty());
}

#[test]
fn add_circuit_inputs_builds_witness() {
    let inputs = add_circuit_inputs("10", "20");
    assert!(inputs.contains_key("x"));
    assert!(inputs.contains_key("y"));
}

#[test]
fn intermediate_signals_have_witness_assignments() {
    let program = with_intermediate_program();
    assert_eq!(program.name, "with_intermediate");
    // The `let sum = ...` and `let result = ...` should produce witness assignments
    assert!(
        !program.witness_plan.assignments.is_empty(),
        "witness plan must have assignments for intermediate signals"
    );
    let targets: Vec<&str> = program
        .witness_plan
        .assignments
        .iter()
        .map(|a| a.target.as_str())
        .collect();
    assert!(
        targets.contains(&"sum"),
        "missing witness assignment for 'sum'"
    );
    assert!(
        targets.contains(&"result"),
        "missing witness assignment for 'result'"
    );
}
