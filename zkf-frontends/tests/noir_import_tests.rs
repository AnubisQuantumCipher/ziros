use acir::FieldElement as AcirFieldElement;
use acir::circuit::brillig::BrilligOutputs;
use acir::circuit::opcodes::{BlackBoxFuncCall, BlockId, FunctionInput, MemOp};
use acir::circuit::{
    Circuit as AcirCircuit, ExpressionWidth, Opcode as AcirOpcode, Program as AcirProgram,
    PublicInputs,
};
use acir::native_types::{Expression as AcirExpression, Witness};
use acir_beta9::FieldElement as Beta9FieldElement;
use acir_beta9::circuit::brillig::{
    BrilligBytecode as Beta9BrilligBytecode, BrilligFunctionId as Beta9BrilligFunctionId,
};
use acir_beta9::circuit::opcodes::{
    BlackBoxFuncCall as Beta9BlackBoxFuncCall, FunctionInput as Beta9FunctionInput,
};
use acir_beta9::circuit::{
    Circuit as Beta9Circuit, ExpressionWidth as Beta9ExpressionWidth, Opcode as Beta9Opcode,
    Program as Beta9Program, PublicInputs as Beta9PublicInputs,
};
use acir_beta9::native_types::{Expression as Beta9Expression, Witness as Beta9Witness};
use acir_beta19::AcirField as _;
use acir_beta19::FieldElement as Beta19FieldElement;
use acir_beta19::circuit::Program as Beta19Program;
use acir_beta19::circuit::opcodes::{
    BlackBoxFuncCall as Beta19BlackBoxFuncCall, FunctionInput as Beta19FunctionInput,
};
use acir_beta19::circuit::{
    Circuit as Beta19Circuit, Opcode as Beta19Opcode, PublicInputs as Beta19PublicInputs,
};
use acir_beta19::native_types::{Expression as Beta19Expression, Witness as Beta19Witness};
use base64::Engine;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::BTreeMap;
use std::io::Write;
use zkf_core::{BlackBoxOp, Constraint, FieldElement, FieldId, ZkfError, generate_witness};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

#[path = "../../zkf-core/tests/support/private_identity_fixture.rs"]
mod private_identity_fixture;

fn supported_acir_program() -> AcirProgram {
    let assert_zero = AcirOpcode::AssertZero(AcirExpression {
        mul_terms: Vec::new(),
        linear_combinations: vec![
            (AcirFieldElement::from(1_i128), Witness(1)),
            (AcirFieldElement::from(1_i128), Witness(2)),
            (AcirFieldElement::from(-1_i128), Witness(3)),
        ],
        q_c: AcirFieldElement::zero(),
    });

    let range = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
        input: FunctionInput {
            witness: Witness(1),
            num_bits: 8,
        },
    });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 3,
            opcodes: vec![assert_zero, range],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs([Witness(3)].into_iter().collect()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn boolean_and_program() -> AcirProgram {
    let and = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
        lhs: FunctionInput {
            witness: Witness(1),
            num_bits: 1,
        },
        rhs: FunctionInput {
            witness: Witness(2),
            num_bits: 1,
        },
        output: Witness(3),
    });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 3,
            opcodes: vec![and],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2), Witness(3)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs(Default::default()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn multibit_and_program() -> AcirProgram {
    let and = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
        lhs: FunctionInput {
            witness: Witness(1),
            num_bits: 8,
        },
        rhs: FunctionInput {
            witness: Witness(2),
            num_bits: 8,
        },
        output: Witness(3),
    });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 3,
            opcodes: vec![and],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2), Witness(3)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs(Default::default()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn sha256_program() -> AcirProgram {
    let inputs = vec![
        FunctionInput {
            witness: Witness(1),
            num_bits: 8,
        },
        FunctionInput {
            witness: Witness(2),
            num_bits: 8,
        },
    ];
    let outputs: Box<[Witness; 32]> = Box::new(std::array::from_fn(|i| Witness(10 + i as u32)));
    let sha = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::SHA256 { inputs, outputs });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 41,
            opcodes: vec![sha],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs(Default::default()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn keccak_program() -> AcirProgram {
    let inputs = vec![
        FunctionInput {
            witness: Witness(1),
            num_bits: 8,
        },
        FunctionInput {
            witness: Witness(2),
            num_bits: 8,
        },
    ];
    let outputs: Box<[Witness; 32]> = Box::new(std::array::from_fn(|i| Witness(50 + i as u32)));
    let keccak = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::Keccak256 {
        inputs,
        var_message_size: FunctionInput {
            witness: Witness(3),
            num_bits: 32,
        },
        outputs,
    });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 81,
            opcodes: vec![keccak],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2), Witness(3)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs(Default::default()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn unsupported_recursive_aggregation_program() -> AcirProgram {
    let recursive = AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::RecursiveAggregation {
        verification_key: vec![FunctionInput {
            witness: Witness(1),
            num_bits: 8,
        }],
        proof: vec![FunctionInput {
            witness: Witness(2),
            num_bits: 8,
        }],
        public_inputs: vec![FunctionInput {
            witness: Witness(3),
            num_bits: 8,
        }],
        key_hash: FunctionInput {
            witness: Witness(4),
            num_bits: 8,
        },
    });

    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 4,
            opcodes: vec![recursive],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2), Witness(3), Witness(4)]
                .into_iter()
                .collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs(Default::default()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn multi_function_call_program() -> AcirProgram {
    let callee_assert = AcirOpcode::AssertZero(AcirExpression {
        mul_terms: Vec::new(),
        linear_combinations: vec![
            (AcirFieldElement::from(1_i128), Witness(2)),
            (AcirFieldElement::from(-1_i128), Witness(0)),
            (AcirFieldElement::from(-1_i128), Witness(1)),
        ],
        q_c: AcirFieldElement::zero(),
    });

    let main_call = AcirOpcode::Call {
        id: 1,
        inputs: vec![Witness(1), Witness(2)],
        outputs: vec![Witness(3)],
        predicate: None,
    };

    AcirProgram {
        functions: vec![
            AcirCircuit {
                current_witness_index: 3,
                opcodes: vec![main_call],
                expression_width: ExpressionWidth::Unbounded,
                private_parameters: [Witness(1), Witness(2)].into_iter().collect(),
                public_parameters: PublicInputs(Default::default()),
                return_values: PublicInputs([Witness(3)].into_iter().collect()),
                assert_messages: Default::default(),
                recursive: false,
            },
            AcirCircuit {
                current_witness_index: 2,
                opcodes: vec![callee_assert],
                expression_width: ExpressionWidth::Unbounded,
                private_parameters: [Witness(0), Witness(1)].into_iter().collect(),
                public_parameters: PublicInputs(Default::default()),
                return_values: PublicInputs([Witness(2)].into_iter().collect()),
                assert_messages: Default::default(),
                recursive: false,
            },
        ],
        unconstrained_functions: Vec::new(),
    }
}

fn memory_read_program() -> AcirProgram {
    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 3,
            opcodes: vec![
                AcirOpcode::MemoryInit {
                    block_id: BlockId(7),
                    init: vec![Witness(1), Witness(2)],
                },
                AcirOpcode::MemoryOp {
                    block_id: BlockId(7),
                    op: MemOp::read_at_mem_index(AcirExpression::zero(), Witness(3)),
                    predicate: None,
                },
            ],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs([Witness(3)].into_iter().collect()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn brillig_hint_program() -> AcirProgram {
    AcirProgram {
        functions: vec![AcirCircuit {
            current_witness_index: 3,
            opcodes: vec![AcirOpcode::BrilligCall {
                id: 0,
                inputs: Vec::new(),
                outputs: vec![BrilligOutputs::Simple(Witness(3))],
                predicate: None,
            }],
            expression_width: ExpressionWidth::Unbounded,
            private_parameters: [Witness(1), Witness(2), Witness(3)].into_iter().collect(),
            public_parameters: PublicInputs(Default::default()),
            return_values: PublicInputs(Default::default()),
            assert_messages: Default::default(),
            recursive: false,
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn beta9_supported_program() -> Beta9Program<Beta9FieldElement> {
    let assert_zero = Beta9Opcode::AssertZero(Beta9Expression {
        mul_terms: Vec::new(),
        linear_combinations: vec![
            (Beta9FieldElement::from(1_i128), Beta9Witness(1)),
            (Beta9FieldElement::from(1_i128), Beta9Witness(2)),
            (Beta9FieldElement::from(-1_i128), Beta9Witness(3)),
        ],
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

fn beta19_supported_program() -> Beta19Program<Beta19FieldElement> {
    let assert_zero = Beta19Opcode::AssertZero(Beta19Expression {
        mul_terms: Vec::new(),
        linear_combinations: vec![
            (Beta19FieldElement::from(1_i128), Beta19Witness(1)),
            (Beta19FieldElement::from(1_i128), Beta19Witness(2)),
            (Beta19FieldElement::from(-1_i128), Beta19Witness(3)),
        ],
        q_c: Beta19FieldElement::zero(),
    });

    let range = Beta19Opcode::BlackBoxFuncCall(Beta19BlackBoxFuncCall::RANGE {
        input: Beta19FunctionInput::Witness(Beta19Witness(1)),
        num_bits: 8,
    });

    Beta19Program {
        functions: vec![Beta19Circuit {
            function_name: "main".to_string(),
            current_witness_index: 3,
            opcodes: vec![assert_zero, range],
            private_parameters: [Beta19Witness(1), Beta19Witness(2)].into_iter().collect(),
            public_parameters: Beta19PublicInputs(Default::default()),
            return_values: Beta19PublicInputs([Beta19Witness(3)].into_iter().collect()),
            assert_messages: Default::default(),
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn beta9_boolean_and_program() -> Beta9Program<Beta9FieldElement> {
    let and = Beta9Opcode::BlackBoxFuncCall(Beta9BlackBoxFuncCall::AND {
        lhs: Beta9FunctionInput::witness(Beta9Witness(1), 1),
        rhs: Beta9FunctionInput::witness(Beta9Witness(2), 1),
        output: Beta9Witness(3),
    });

    Beta9Program {
        functions: vec![Beta9Circuit {
            current_witness_index: 3,
            opcodes: vec![and],
            expression_width: Beta9ExpressionWidth::Unbounded,
            private_parameters: [Beta9Witness(1), Beta9Witness(2), Beta9Witness(3)]
                .into_iter()
                .collect(),
            public_parameters: Beta9PublicInputs(Default::default()),
            return_values: Beta9PublicInputs(Default::default()),
            assert_messages: Default::default(),
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn beta9_and_with_constant_input_program() -> Beta9Program<Beta9FieldElement> {
    let lhs_const = Beta9FunctionInput::constant(Beta9FieldElement::from(1_i128), 1)
        .expect("constant should fit in one bit");
    let and = Beta9Opcode::BlackBoxFuncCall(Beta9BlackBoxFuncCall::AND {
        lhs: lhs_const,
        rhs: Beta9FunctionInput::witness(Beta9Witness(2), 1),
        output: Beta9Witness(3),
    });

    Beta9Program {
        functions: vec![Beta9Circuit {
            current_witness_index: 3,
            opcodes: vec![and],
            expression_width: Beta9ExpressionWidth::Unbounded,
            private_parameters: [Beta9Witness(2), Beta9Witness(3)].into_iter().collect(),
            public_parameters: Beta9PublicInputs(Default::default()),
            return_values: Beta9PublicInputs(Default::default()),
            assert_messages: Default::default(),
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn beta9_blake2s_program() -> Beta9Program<Beta9FieldElement> {
    let outputs: Box<[Beta9Witness; 32]> =
        Box::new(std::array::from_fn(|i| Beta9Witness(10 + i as u32)));
    let blake2s = Beta9Opcode::BlackBoxFuncCall(Beta9BlackBoxFuncCall::Blake2s {
        inputs: vec![
            Beta9FunctionInput::witness(Beta9Witness(1), 8),
            Beta9FunctionInput::witness(Beta9Witness(2), 8),
        ],
        outputs,
    });

    Beta9Program {
        functions: vec![Beta9Circuit {
            current_witness_index: 41,
            opcodes: vec![blake2s],
            expression_width: Beta9ExpressionWidth::Unbounded,
            private_parameters: [Beta9Witness(1), Beta9Witness(2)].into_iter().collect(),
            public_parameters: Beta9PublicInputs(Default::default()),
            return_values: Beta9PublicInputs(Default::default()),
            assert_messages: Default::default(),
        }],
        unconstrained_functions: Vec::new(),
    }
}

fn beta9_program_with_brillig_hint() -> Beta9Program<Beta9FieldElement> {
    let mut program = beta9_supported_program();
    program.functions[0].opcodes.push(Beta9Opcode::BrilligCall {
        id: Beta9BrilligFunctionId(0),
        inputs: Vec::new(),
        outputs: Vec::new(),
        predicate: None,
    });
    program.unconstrained_functions = vec![Beta9BrilligBytecode::default()];
    program
}

#[test]
fn imports_direct_acir_program_json() {
    let json = serde_json::to_value(supported_acir_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(
            &json,
            &FrontendImportOptions {
                program_name: Some("acir_json_demo".to_string()),
                field: None,
                ..Default::default()
            },
        )
        .expect("import should pass");

    assert_eq!(imported.name, "acir_json_demo");
    assert_eq!(imported.field, FieldId::Bn254);
    assert_eq!(imported.signals.len(), 3);
    assert_eq!(imported.constraints.len(), 2);
    assert!(matches!(
        imported.constraints[1],
        Constraint::Range {
            ref signal,
            bits: 8,
            ..
        } if signal == "w1"
    ));

    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(3));
    inputs.insert("w2".to_string(), FieldElement::from_i64(5));
    inputs.insert("w3".to_string(), FieldElement::from_i64(8));

    let witness = generate_witness(&imported, &inputs).expect("witness should satisfy constraints");
    assert_eq!(witness.values["w3"], FieldElement::new("8"));
}

#[test]
fn inspect_reports_opcode_and_blackbox_counts() {
    let json = serde_json::to_value(supported_acir_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let inspection = frontend.inspect(&json).expect("inspect should pass");

    assert_eq!(inspection.functions, 1);
    assert_eq!(inspection.unconstrained_functions, 0);
    assert_eq!(inspection.opcode_counts.get("assert_zero"), Some(&1usize));
    assert_eq!(
        inspection.opcode_counts.get("black_box_func_call"),
        Some(&1usize)
    );
    assert_eq!(inspection.blackbox_counts.get("range"), Some(&1usize));
    assert!(
        inspection
            .required_capabilities
            .iter()
            .any(|capability| capability == "blackbox:range")
    );
}

#[test]
fn imports_noir_artifact_bytecode() {
    let acir_program = supported_acir_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(AcirProgram::serialize_program(&acir_program));

    let artifact = serde_json::json!({
        "name": "noir_artifact_demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(
            &artifact,
            &FrontendImportOptions {
                field: Some(FieldId::PastaFp),
                ..Default::default()
            },
        )
        .expect("import should pass");

    assert_eq!(imported.name, "noir_artifact_demo");
    assert_eq!(imported.field, FieldId::PastaFp);
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_gzip_encoded_noir_artifact_bytecode() {
    let acir_program = supported_acir_program();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&AcirProgram::serialize_program(&acir_program))
        .expect("gzip writer should accept bytes");
    let compressed = encoder.finish().expect("gzip encoder should finish");
    let bytecode = base64::engine::general_purpose::STANDARD.encode(compressed);

    let artifact = serde_json::json!({
        "name": "noir_artifact_gzip_demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("import should pass");

    assert_eq!(imported.name, "noir_artifact_gzip_demo");
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_boolean_and_blackbox_program() {
    let json = serde_json::to_value(boolean_and_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("boolean AND should import");

    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Boolean { .. }))
    );
    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Equal { .. }))
    );
}

#[test]
fn imports_multibit_and_blackbox_program() {
    let json = serde_json::to_value(multibit_and_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("import should pass");

    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Boolean { .. }))
    );
    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Equal { .. }))
    );
}

#[test]
fn imports_sha256_opcode_as_native_blackbox_constraint() {
    let json = serde_json::to_value(sha256_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("sha256 should import as native blackbox constraint");

    assert!(imported.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::Sha256,
                ..
            }
        )
    }));
    assert!(imported.witness_plan.hints.is_empty());
}

#[test]
fn inspect_marks_native_blackbox_without_hints_requirement() {
    let json = serde_json::to_value(sha256_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let inspection = frontend.inspect(&json).expect("inspect should pass");

    assert!(!inspection.requires_hints);
    assert!(
        !inspection
            .required_capabilities
            .iter()
            .any(|capability| capability == "hints")
    );
    assert!(
        inspection
            .required_capabilities
            .iter()
            .any(|capability| capability == "blackbox:sha256")
    );
}

#[test]
fn imports_keccak_opcode_as_native_blackbox_constraint() {
    let json = serde_json::to_value(keccak_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("keccak should import as native blackbox constraint");

    assert!(imported.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::Keccak256,
                ..
            }
        )
    }));
    assert!(imported.witness_plan.hints.is_empty());
}

#[test]
fn rejects_unsupported_recursive_aggregation_opcode() {
    let json = serde_json::to_value(unsupported_recursive_aggregation_program())
        .expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("recursive aggregation should import as marker constraint");
    assert!(imported.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::RecursiveAggregationMarker,
                ..
            }
        )
    }));
}

#[test]
fn rejects_known_unsupported_noir_version_in_strict_mode() {
    let acir_program = beta9_supported_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&acir_program));
    let artifact = serde_json::json!({
        "name": "unsupported_noir_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let err = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect_err("strict mode should reject version");

    match err {
        ZkfError::UnsupportedBackend { backend, message } => {
            assert!(backend.contains("frontend-translator"));
            assert!(
                message.contains("no translator supports")
                    || message.contains("requires artifact `program` JSON payload")
            );
        }
        ZkfError::InvalidArtifact(message) => {
            assert!(
                message.contains("failed to deserialize Noir beta.19 bytecode")
                    || message.contains("failed to deserialize beta.19 program JSON")
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn imports_non_beta9_v1_artifact_when_program_json_is_present() {
    let artifact = serde_json::json!({
        "name": "beta10_program_json_demo",
        "noir_version": "1.0.0-beta.10+demo",
        "program": supported_acir_program()
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("program-json based v1 artifacts should translate");

    assert_eq!(imported.name, "beta10_program_json_demo");
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_stable_v1_artifact_when_program_json_is_present() {
    let artifact = serde_json::json!({
        "name": "stable_program_json_demo",
        "noir_version": "1.0.0",
        "program": supported_acir_program()
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("program-json based stable v1 artifacts should import");

    assert_eq!(imported.name, "stable_program_json_demo");
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_unsupported_version_when_bytecode_is_directly_parseable() {
    let acir_program = supported_acir_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(AcirProgram::serialize_program(&acir_program));
    let artifact = serde_json::json!({
        "name": "direct_parseable_v1_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("parseable bytecode should import without translator");
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_beta19_bytecode_via_normalized_parse_fallback() {
    let beta19_program = beta19_supported_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta19Program::serialize_program(&beta19_program));
    let artifact = serde_json::json!({
        "name": "beta19_normalized_bytecode_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("beta.19 bytecode should import through normalized parse fallback");

    assert_eq!(imported.name, "beta19_normalized_bytecode_demo");
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_beta19_program_json_via_normalized_parse_fallback() {
    let artifact = serde_json::json!({
        "name": "beta19_program_json_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "program": beta19_supported_program()
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("beta.19 program JSON should import through normalized parse fallback");

    assert_eq!(imported.name, "beta19_program_json_demo");
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_noir_beta9_artifact_via_translator() {
    let beta_program = beta9_supported_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = serde_json::json!({
        "name": "beta9_translator_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("beta9 artifact should import via translator");

    assert_eq!(imported.name, "beta9_translator_demo");
    assert_eq!(imported.field, FieldId::Bn254);
    assert_eq!(imported.signals.len(), 3);
    assert_eq!(imported.constraints.len(), 2);
}

#[test]
fn imports_noir_beta9_boolean_and_via_translator() {
    let beta_program = beta9_boolean_and_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = serde_json::json!({
        "name": "beta9_and_translator_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("beta9 boolean AND should import via translator");

    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Boolean { .. }))
    );
}

#[test]
fn imports_noir_beta9_and_with_constant_input_via_translator() {
    let beta_program = beta9_and_with_constant_input_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = serde_json::json!({
        "name": "beta9_and_constant_translator_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("beta9 AND with constant input should import via translator");

    assert!(imported.signals.iter().any(|signal| signal.name == "w2"));
    assert!(imported.signals.iter().any(|signal| signal.name == "w3"));
    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Boolean { .. }))
    );
}

#[test]
fn imports_noir_beta9_blake2s_via_translator() {
    let beta_program = beta9_blake2s_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = serde_json::json!({
        "name": "beta9_blake2s_translator_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&artifact, &FrontendImportOptions::default())
        .expect("beta9 blake2s should import via translator");

    assert!(imported.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::Blake2s,
                ..
            }
        )
    }));
    assert!(imported.witness_plan.hints.is_empty());
}

#[test]
fn inspect_beta9_translation_flags_hints_and_loss() {
    let beta_program = beta9_program_with_brillig_hint();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = serde_json::json!({
        "name": "beta9_translator_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let inspection = frontend.inspect(&artifact).expect("inspect should pass");

    assert!(inspection.requires_hints);
    assert!(
        inspection
            .dropped_features
            .iter()
            .any(|feature| feature == "BrilligCall")
    );
}

#[test]
fn execute_beta9_artifact_solves_missing_witness() {
    let beta_program = beta9_supported_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta9Program::serialize_program(&beta_program));
    let artifact = serde_json::json!({
        "name": "beta9_execute_demo",
        "noir_version": "1.0.0-beta.9+demo",
        "bytecode": bytecode
    });

    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(3));
    inputs.insert("w2".to_string(), FieldElement::from_i64(5));

    let witness = frontend
        .execute(&artifact, &inputs)
        .expect("beta9 executor should solve missing witness");
    assert_eq!(
        witness
            .values
            .get("w1")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("3")
    );
    assert_eq!(
        witness
            .values
            .get("w2")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("5")
    );
    assert_eq!(
        witness
            .values
            .get("w3")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("8")
    );
}

#[test]
fn execute_parseable_acir_program_without_noir_version() {
    let artifact = serde_json::to_value(supported_acir_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(4));
    inputs.insert("w2".to_string(), FieldElement::from_i64(7));

    let witness = frontend
        .execute(&artifact, &inputs)
        .expect("acir 0.46 executor should solve parseable program");
    assert_eq!(
        witness
            .values
            .get("w1")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("4")
    );
    assert_eq!(
        witness
            .values
            .get("w2")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("7")
    );
    assert_eq!(
        witness
            .values
            .get("w3")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("11")
    );
}

#[test]
fn execute_multi_function_call_program_checks_translated_constraints() {
    let artifact =
        serde_json::to_value(multi_function_call_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(8));
    inputs.insert("w2".to_string(), FieldElement::from_i64(13));

    let witness = frontend
        .execute(&artifact, &inputs)
        .expect("multi-function call execution should satisfy translated constraints");
    assert_eq!(
        witness
            .values
            .get("w3")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("21")
    );
}

#[test]
fn execute_memory_read_program_checks_translated_constraints() {
    let artifact = serde_json::to_value(memory_read_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(34));
    inputs.insert("w2".to_string(), FieldElement::from_i64(55));

    let witness = frontend
        .execute(&artifact, &inputs)
        .expect("memory execution should satisfy translated constraints");
    assert_eq!(
        witness
            .values
            .get("w3")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("34")
    );
}

#[test]
fn execute_fails_closed_when_translation_metadata_is_invalid() {
    let program = serde_json::to_value(supported_acir_program()).expect("program must serialize");
    let artifact = serde_json::json!({
        "name": "execute_fail_closed_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "program": program,
        "witness_hints": "not-a-witness-hint-list"
    });
    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(4));
    inputs.insert("w2".to_string(), FieldElement::from_i64(7));

    let error = frontend
        .execute(&artifact, &inputs)
        .expect_err("invalid translation metadata should fail closed after execution");
    let message = error.to_string();
    assert!(
        message.contains("witness_hints metadata"),
        "unexpected error: {message}"
    );
}

#[test]
fn execute_unknown_noir_version_uses_parseable_acir_fallback() {
    let program = serde_json::to_value(supported_acir_program()).expect("program must serialize");
    let artifact = serde_json::json!({
        "name": "acir_fallback_execute_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "program": program
    });
    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(9));
    inputs.insert("w2".to_string(), FieldElement::from_i64(2));

    let witness = frontend
        .execute(&artifact, &inputs)
        .expect("parseable acir program should execute despite unsupported noir_version");
    assert_eq!(
        witness
            .values
            .get("w3")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("11")
    );
}

#[test]
fn execute_beta19_bytecode_uses_normalized_parse_fallback() {
    let beta19_program = beta19_supported_program();
    let bytecode = base64::engine::general_purpose::STANDARD
        .encode(Beta19Program::serialize_program(&beta19_program));
    let artifact = serde_json::json!({
        "name": "beta19_execute_demo",
        "noir_version": "1.0.0-beta.19+demo",
        "bytecode": bytecode
    });
    let frontend = frontend_for(FrontendKind::Noir);
    let mut inputs = BTreeMap::new();
    inputs.insert("w1".to_string(), FieldElement::from_i64(6));
    inputs.insert("w2".to_string(), FieldElement::from_i64(4));

    let witness = frontend
        .execute(&artifact, &inputs)
        .expect("beta.19 bytecode should execute through normalized parse fallback");
    assert_eq!(
        witness
            .values
            .get("w3")
            .map(|v| v.to_decimal_string())
            .as_deref(),
        Some("10")
    );
}

#[test]
fn imports_beta19_private_identity_pipeline_structure() {
    let Some(artifact_path) =
        private_identity_fixture::ensure_private_identity_artifact(env!("CARGO_MANIFEST_DIR"))
    else {
        return;
    };
    let artifact_json = std::fs::read_to_string(&artifact_path)
        .expect("private_identity beta.19 artifact should exist");
    let artifact: serde_json::Value =
        serde_json::from_str(&artifact_json).expect("private_identity artifact should parse");

    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(
            &artifact,
            &FrontendImportOptions {
                program_name: Some("private_identity".to_string()),
                ..Default::default()
            },
        )
        .expect("private_identity import should pass");

    assert!(
        imported.witness_plan.acir_program_bytes.is_some(),
        "beta.19 import should preserve original artifact bytes for witness presolve"
    );
    assert!(
        imported.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::ScalarMulG1,
                ..
            }
        )),
        "private_identity import should preserve scalar-mul compatibility ops"
    );
    assert!(
        imported
            .witness_plan
            .hints
            .iter()
            .any(|hint| hint.target == "w10" && hint.source == "__brillig_f0_op12_out0"),
        "private_identity import should preserve beta.19 Brillig hint wiring"
    );
}

#[test]
fn imports_multi_function_call_program() {
    let json = serde_json::to_value(multi_function_call_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("multi-function import should pass");

    assert_eq!(imported.constraints.len(), 1);
    assert!(
        imported
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, Constraint::Equal { .. }))
    );
}

#[test]
fn imports_memory_read_program() {
    let json = serde_json::to_value(memory_read_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("memory import should pass");

    assert_eq!(imported.constraints.len(), 1);
}

#[test]
fn imports_brillig_as_witness_hint() {
    let json = serde_json::to_value(brillig_hint_program()).expect("program must serialize");
    let frontend = frontend_for(FrontendKind::Noir);
    let imported = frontend
        .compile_to_ir(&json, &FrontendImportOptions::default())
        .expect("brillig hint import should pass");

    assert!(
        imported
            .witness_plan
            .hints
            .iter()
            .any(|hint| hint.target == "w3")
    );
}
