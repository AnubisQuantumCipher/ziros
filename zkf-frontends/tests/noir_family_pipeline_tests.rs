use acir::FieldElement as AcirFieldElement;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{
    Circuit as AcirCircuit, ExpressionWidth, Opcode as AcirOpcode, Program as AcirProgram,
    PublicInputs,
};
use acir::native_types::{Expression as AcirExpression, Witness as AcirWitness};
use acir_beta9::FieldElement as Beta9FieldElement;
use acir_beta9::circuit::opcodes::{
    BlackBoxFuncCall as Beta9BlackBoxFuncCall, FunctionInput as Beta9FunctionInput,
};
use acir_beta9::circuit::{
    Circuit as Beta9Circuit, ExpressionWidth as Beta9ExpressionWidth, Opcode as Beta9Opcode,
    Program as Beta9Program, PublicInputs as Beta9PublicInputs,
};
use acir_beta9::native_types::{Expression as Beta9Expression, Witness as Beta9Witness};
use base64::Engine;
use serde_json::json;
use std::collections::BTreeMap;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, check_constraints, generate_witness,
};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

fn supported_acir_program() -> AcirProgram {
    let assert_zero = AcirOpcode::AssertZero(AcirExpression {
        mul_terms: Vec::new(),
        linear_combinations: vec![(AcirFieldElement::from(1_i128), AcirWitness(3))],
        q_c: AcirFieldElement::zero(),
    });

    let range = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
        input: FunctionInput {
            witness: AcirWitness(1),
            num_bits: 8,
        },
    });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 3,
            opcodes: vec![assert_zero, range],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [AcirWitness(1), AcirWitness(2)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs([AcirWitness(3)].into_iter().collect()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn beta9_supported_program() -> Beta9Program<Beta9FieldElement> {
    let assert_zero = Beta9Opcode::AssertZero(Beta9Expression {
        mul_terms: Vec::new(),
        linear_combinations: vec![(Beta9FieldElement::from(1_i128), Beta9Witness(3))],
        q_c: Beta9FieldElement::from(0_i128),
    });

    let range = Beta9Opcode::BlackBoxFuncCall(Beta9BlackBoxFuncCall::RANGE {
        input: Beta9FunctionInput::witness(Beta9Witness(1), 8),
    });

    Beta9Program {
        functions: vec![Beta9Circuit {
            current_witness_index: 3,
            opcodes: vec![assert_zero, range],
            expression_width: Beta9ExpressionWidth::Unbounded,
            private_parameters: [Beta9Witness(1), Beta9Witness(2)].into_iter().collect(),
            public_parameters: Beta9PublicInputs(Default::default()),
            return_values: Beta9PublicInputs([Beta9Witness(3)].into_iter().collect()),
            assert_messages: Default::default(),
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn anchor_private_signals(mut program: Program) -> Program {
    let private_signals: Vec<String> = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Private)
        .map(|signal| signal.name.clone())
        .collect();
    for signal in private_signals {
        let anchor_name = format!("{signal}_anchor");
        program.signals.push(Signal {
            name: anchor_name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        program.constraints.push(Constraint::Equal {
            lhs: Expr::signal(&anchor_name),
            rhs: Expr::Mul(
                Box::new(Expr::signal(&signal)),
                Box::new(Expr::signal(&signal)),
            ),
            label: Some(format!("{signal}_anchor")),
        });
        program.witness_plan.assignments.push(WitnessAssignment {
            target: anchor_name,
            expr: Expr::Mul(
                Box::new(Expr::signal(&signal)),
                Box::new(Expr::signal(&signal)),
            ),
        });
    }
    program
}

fn run_noir_pipeline(artifact: &serde_json::Value, field: FieldId, backend: BackendKind) {
    let frontend = frontend_for(FrontendKind::Noir);
    let import_options = FrontendImportOptions {
        field: Some(field),
        ..Default::default()
    };
    let program = frontend
        .compile_to_ir(artifact, &import_options)
        .expect("noir import should pass");
    let program = anchor_private_signals(program);

    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(7));
    inputs.insert("w2".to_string(), FieldElement::from_i64(5));
    inputs.insert("w3".to_string(), FieldElement::from_i64(0));

    let executed_witness = frontend
        .execute(artifact, &inputs)
        .expect("noir execute should return a witness");
    assert!(
        executed_witness.values.contains_key("w1") && executed_witness.values.contains_key("w2"),
        "execution witness should contain input assignments"
    );

    let witness = generate_witness(&program, &inputs).expect("generated witness should satisfy");
    check_constraints(&program, &witness).expect("generated witness should satisfy constraints");

    let backend = backend_for(backend);
    let compiled = backend
        .compile(&program)
        .expect("backend compile should pass");
    let proof = backend
        .prove(&compiled, &witness)
        .expect("backend prove should pass");
    assert!(
        backend
            .verify(&compiled, &proof)
            .expect("backend verify should run"),
        "backend verify should return true"
    );
}

#[test]
fn noir_beta9_bytecode_pipeline_runs_on_arkworks_and_halo2() {
    let beta_program = beta9_supported_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = json!({
        "name": "beta9_pipeline_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    run_noir_pipeline(&artifact, FieldId::Bn254, BackendKind::ArkworksGroth16);
    run_noir_pipeline(&artifact, FieldId::PastaFp, BackendKind::Halo2);
}

#[test]
fn noir_beta10_program_json_pipeline_runs_on_arkworks_and_halo2() {
    let artifact = json!({
        "name": "beta10_pipeline_demo",
        "noir_version": "1.0.0-beta.10+demo",
        "program": supported_acir_program()
    });

    run_noir_pipeline(&artifact, FieldId::Bn254, BackendKind::ArkworksGroth16);
    run_noir_pipeline(&artifact, FieldId::PastaFp, BackendKind::Halo2);
}

#[test]
fn noir_stable_program_json_pipeline_runs_on_arkworks_and_plonky3() {
    let artifact = json!({
        "name": "stable_pipeline_demo",
        "noir_version": "1.0.0",
        "program": supported_acir_program()
    });

    run_noir_pipeline(&artifact, FieldId::Bn254, BackendKind::ArkworksGroth16);
    run_noir_pipeline(&artifact, FieldId::Goldilocks, BackendKind::Plonky3);
}
