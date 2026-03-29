use num_bigint::BigInt;
use proptest::prelude::*;
use std::collections::BTreeMap;
use zkf_core::ccs::CcsProgram;
use zkf_core::ir::LookupTable;
use zkf_core::{
    BackendKind, BlackBoxOp, CompiledProgram, Constraint, Expr, FieldElement, FieldId, Program,
    ProofArtifact, Signal, Visibility, WitnessPlan, ZkfError, check_constraints, generate_witness,
    mod_inverse_bigint, normalize_mod, optimize_program, optimize_zir, program_zir_to_v2,
};

fn field_by_index(index: u8) -> FieldId {
    match index % 7 {
        0 => FieldId::Bn254,
        1 => FieldId::Bls12_381,
        2 => FieldId::PastaFp,
        3 => FieldId::PastaFq,
        4 => FieldId::Goldilocks,
        5 => FieldId::BabyBear,
        _ => FieldId::Mersenne31,
    }
}

fn linear_program(field: FieldId) -> Program {
    Program {
        name: "verification-linear".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("out".to_string()),
            rhs: Expr::Add(vec![
                Expr::Signal("x".to_string()),
                Expr::Signal("y".to_string()),
            ]),
            label: Some("out=x+y".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Signal("y".to_string()),
                ]),
            }],
            hints: vec![],
            input_aliases: BTreeMap::new(),
            acir_program_bytes: None,
        },
        ..Default::default()
    }
}

fn small_field_by_index(index: u8) -> FieldId {
    match index % 3 {
        0 => FieldId::Goldilocks,
        1 => FieldId::BabyBear,
        _ => FieldId::Mersenne31,
    }
}

fn lookup_program() -> Program {
    Program {
        name: "verification-lookup".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "selector".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "mapped".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("selector".to_string())],
            table: "table".to_string(),
            outputs: Some(vec!["mapped".to_string()]),
            label: Some("selector_lookup".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        lookup_tables: vec![LookupTable {
            name: "table".to_string(),
            columns: vec!["selector".to_string(), "mapped".to_string()],
            values: vec![
                vec![FieldElement::from_i64(0), FieldElement::from_i64(5)],
                vec![FieldElement::from_i64(1), FieldElement::from_i64(9)],
                vec![FieldElement::from_i64(2), FieldElement::from_i64(17)],
                vec![FieldElement::from_i64(3), FieldElement::from_i64(33)],
            ],
        }],
        ..Default::default()
    }
}

fn assignment_plan_program(field: FieldId) -> Program {
    Program {
        name: "verification-assignment".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("out".to_string()),
            rhs: Expr::Add(vec![
                Expr::Signal("x".to_string()),
                Expr::Const(FieldElement::from_i64(5)),
            ]),
            label: Some("assigned_out".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Const(FieldElement::from_i64(5)),
                ]),
            }],
            ..WitnessPlan::default()
        },
        ..Default::default()
    }
}

fn hint_plan_program(field: FieldId) -> Program {
    Program {
        name: "verification-hint".to_string(),
        field,
        signals: vec![
            Signal {
                name: "source".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "mirror".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("mirror".to_string()),
            rhs: Expr::Signal("source".to_string()),
            label: Some("hint_copy".to_string()),
        }],
        witness_plan: WitnessPlan {
            hints: vec![zkf_core::WitnessHint {
                target: "mirror".to_string(),
                source: "source".to_string(),
                kind: zkf_core::WitnessHintKind::Copy,
            }],
            ..WitnessPlan::default()
        },
        ..Default::default()
    }
}

fn mixed_plan_program(field: FieldId) -> Program {
    Program {
        name: "verification-mixed-plan".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "sum".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "mirror".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::Signal("sum".to_string()),
                rhs: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Const(FieldElement::from_i64(7)),
                ]),
                label: Some("sum_assignment".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::Signal("mirror".to_string()),
                rhs: Expr::Signal("sum".to_string()),
                label: Some("mirror_hint".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "sum".to_string(),
                expr: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Const(FieldElement::from_i64(7)),
                ]),
            }],
            hints: vec![zkf_core::WitnessHint {
                target: "mirror".to_string(),
                source: "sum".to_string(),
                kind: zkf_core::WitnessHintKind::Copy,
            }],
            ..WitnessPlan::default()
        },
        ..Default::default()
    }
}

fn normalization_arithmetic_program(field: FieldId) -> zkf_core::zir::Program {
    zkf_core::zir::Program {
        name: "verification-normalize".to_string(),
        field,
        signals: vec![
            zkf_core::zir::Signal {
                name: "tmp".to_string(),
                visibility: Visibility::Private,
                ty: zkf_core::zir::SignalType::Field,
                constant: None,
            },
            zkf_core::zir::Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                ty: zkf_core::zir::SignalType::Field,
                constant: None,
            },
            zkf_core::zir::Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                ty: zkf_core::zir::SignalType::Field,
                constant: None,
            },
            zkf_core::zir::Signal {
                name: "dead".to_string(),
                visibility: Visibility::Private,
                ty: zkf_core::zir::SignalType::Field,
                constant: Some(FieldElement::from_i64(0)),
            },
        ],
        constraints: vec![
            zkf_core::zir::Constraint::Equal {
                lhs: zkf_core::zir::Expr::Signal("out".to_string()),
                rhs: zkf_core::zir::Expr::Signal("tmp".to_string()),
                label: Some("copy".to_string()),
            },
            zkf_core::zir::Constraint::Equal {
                lhs: zkf_core::zir::Expr::Signal("tmp".to_string()),
                rhs: zkf_core::zir::Expr::Add(vec![
                    zkf_core::zir::Expr::Mul(
                        Box::new(zkf_core::zir::Expr::Const(FieldElement::from_i64(1))),
                        Box::new(zkf_core::zir::Expr::Signal("x".to_string())),
                    ),
                    zkf_core::zir::Expr::Const(FieldElement::from_i64(0)),
                ]),
                label: Some("normalize-me".to_string()),
            },
        ],
        witness_plan: zkf_core::zir::WitnessPlan {
            assignments: vec![zkf_core::zir::WitnessAssignment {
                target: "tmp".to_string(),
                expr: zkf_core::zir::Expr::Add(vec![
                    zkf_core::zir::Expr::Mul(
                        Box::new(zkf_core::zir::Expr::Const(FieldElement::from_i64(1))),
                        Box::new(zkf_core::zir::Expr::Signal("x".to_string())),
                    ),
                    zkf_core::zir::Expr::Const(FieldElement::from_i64(0)),
                ]),
            }],
            hints: vec![zkf_core::zir::WitnessHint {
                target: "out".to_string(),
                source: "tmp".to_string(),
                kind: zkf_core::zir::WitnessHintKind::Copy,
            }],
            acir_program_bytes: None,
        },
        lookup_tables: vec![],
        memory_regions: vec![],
        custom_gates: vec![],
        metadata: BTreeMap::new(),
    }
}

fn normalization_reordered_program(field: FieldId) -> zkf_core::zir::Program {
    let mut program = normalization_arithmetic_program(field);
    program.signals.reverse();
    program.constraints.reverse();
    program
}

fn optimizer_arithmetic_program(field: FieldId) -> Program {
    Program {
        name: "verification-optimize-ir".to_string(),
        field,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "tmp".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "dead".to_string(),
                visibility: Visibility::Private,
                constant: Some(FieldElement::from_i64(0)),
                ty: None,
            },
        ],
        constraints: vec![
            Constraint::Equal {
                lhs: Expr::Signal("dead".to_string()),
                rhs: Expr::Signal("dead".to_string()),
                label: Some("tautology".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::Signal("tmp".to_string()),
                rhs: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Const(FieldElement::from_i64(0)),
                ]),
                label: Some("tmp=x+0".to_string()),
            },
            Constraint::Equal {
                lhs: Expr::Signal("out".to_string()),
                rhs: Expr::Signal("tmp".to_string()),
                label: Some("copy".to_string()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "tmp".to_string(),
                expr: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Const(FieldElement::from_i64(0)),
                ]),
            }],
            hints: vec![zkf_core::WitnessHint {
                target: "out".to_string(),
                source: "tmp".to_string(),
                kind: zkf_core::WitnessHintKind::Copy,
            }],
            ..WitnessPlan::default()
        },
        ..Default::default()
    }
}

fn optimizer_zir_arithmetic_program(field: FieldId) -> zkf_core::zir::Program {
    let mut program = normalization_arithmetic_program(field);
    program.constraints.insert(
        0,
        zkf_core::zir::Constraint::Equal {
            lhs: zkf_core::zir::Expr::Signal("dead".to_string()),
            rhs: zkf_core::zir::Expr::Signal("dead".to_string()),
            label: Some("tautology".to_string()),
        },
    );
    program
}

fn ccs_unsupported_program(use_lookup: bool, include_label: bool) -> Program {
    let label = include_label.then(|| {
        if use_lookup {
            "lookup".to_string()
        } else {
            "blackbox".to_string()
        }
    });

    Program {
        name: "verification-ccs-fail-closed".to_string(),
        field: FieldId::Bn254,
        signals: vec![Signal {
            name: "selector".to_string(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        }],
        constraints: vec![if use_lookup {
            Constraint::Lookup {
                inputs: vec![Expr::Signal("selector".to_string())],
                table: "table".to_string(),
                outputs: None,
                label,
            }
        } else {
            Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                inputs: vec![Expr::Signal("selector".to_string())],
                outputs: vec!["digest".to_string()],
                params: BTreeMap::new(),
                label,
            }
        }],
        witness_plan: WitnessPlan::default(),
        lookup_tables: vec![LookupTable {
            name: "table".to_string(),
            columns: vec!["selector".to_string()],
            values: vec![vec![FieldElement::from_i64(1)]],
        }],
        ..Default::default()
    }
}

fn ccs_range_program() -> Program {
    Program {
        name: "verification-ccs-range".to_string(),
        field: FieldId::Bn254,
        signals: vec![Signal {
            name: "x".to_string(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Range {
            signal: "x".to_string(),
            bits: 3,
            label: Some("range3".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn ccs_public_private_order_program() -> Program {
    Program {
        name: "verification-ccs-order".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "private_a".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "public_out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "private_b".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("public_out".to_string()),
            rhs: Expr::Add(vec![
                Expr::Signal("private_a".to_string()),
                Expr::Signal("private_b".to_string()),
            ]),
            label: Some("public_first".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn ccs_nested_division_program() -> Program {
    Program {
        name: "verification-ccs-division".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "y".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "z".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::Signal("out".to_string()),
            rhs: Expr::Div(
                Box::new(Expr::Mul(
                    Box::new(Expr::Signal("x".to_string())),
                    Box::new(Expr::Signal("y".to_string())),
                )),
                Box::new(Expr::Signal("z".to_string())),
            ),
            label: Some("nested_division".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn compiled_program_fixture(compiled_bytes: [u8; 3], include_original: bool) -> CompiledProgram {
    let program = linear_program(FieldId::BabyBear);
    let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, program.clone());
    compiled.compiled_data = Some(compiled_bytes.to_vec());
    compiled
        .metadata
        .insert("fixture".to_string(), "compiled-roundtrip".to_string());
    if include_original {
        compiled.original_program = Some(lookup_program());
    }
    compiled
}

fn proof_artifact_fixture(proof: [u8; 3], vk: [u8; 4], public_value: i16) -> ProofArtifact {
    ProofArtifact {
        backend: BackendKind::ArkworksGroth16,
        program_digest: linear_program(FieldId::BabyBear).digest_hex(),
        proof: proof.to_vec(),
        verification_key: vk.to_vec(),
        public_inputs: vec![
            FieldElement::from_i64(i64::from(public_value)),
            FieldElement::from_i64(7),
        ],
        metadata: BTreeMap::from([("fixture".to_string(), "proof-roundtrip".to_string())]),
        security_profile: None,
        hybrid_bundle: None,
        credential_bundle: None,
        archive_metadata: None,
        proof_origin_signature: None,
        proof_origin_public_keys: None,
    }
}

proptest! {
    #[test]
    fn field_element_json_roundtrip(field_index in 0u8..7, value in any::<i64>()) {
        let field = field_by_index(field_index);
        let element = FieldElement::from_i64(value);
        let json = serde_json::to_string(&element).expect("serialize field element");
        let parsed: FieldElement = serde_json::from_str(&json).expect("deserialize field element");
        prop_assert_eq!(parsed, element.clone());

        let normalized = element.normalized_bigint(field).expect("normalize field element");
        prop_assert!(normalized >= BigInt::from(0u8));
        prop_assert!(normalized < *field.modulus());
    }

    #[test]
    fn witness_generation_matches_linear_constraint(field_index in 0u8..7, x in any::<u16>(), y in any::<u16>()) {
        let field = field_by_index(field_index);
        let program = linear_program(field);
        let inputs = BTreeMap::from([
            ("x".to_string(), FieldElement::from_u64(u64::from(x))),
            ("y".to_string(), FieldElement::from_u64(u64::from(y))),
        ]);

        let witness = generate_witness(&program, &inputs).expect("witness should generate");
        check_constraints(&program, &witness).expect("witness should satisfy constraints");

        let expected = FieldElement::from_bigint_with_field(
            BigInt::from(u64::from(x)) + BigInt::from(u64::from(y)),
            field,
        );
        prop_assert_eq!(witness.values.get("out"), Some(&expected));
    }

    #[test]
    fn assignment_plan_generation_matches_constraint(field_index in 0u8..7, x in any::<u16>()) {
        let field = field_by_index(field_index);
        let program = assignment_plan_program(field);
        let inputs = BTreeMap::from([(
            "x".to_string(),
            FieldElement::from_u64(u64::from(x)),
        )]);

        let witness = generate_witness(&program, &inputs).expect("assignment witness should generate");
        check_constraints(&program, &witness).expect("assignment witness should satisfy constraints");

        let expected = FieldElement::from_bigint_with_field(BigInt::from(u64::from(x)) + BigInt::from(5u8), field);
        prop_assert_eq!(witness.values.get("out"), Some(&expected));
    }

    #[test]
    fn hint_plan_generation_matches_constraint(field_index in 0u8..7, source in any::<u16>()) {
        let field = field_by_index(field_index);
        let program = hint_plan_program(field);
        let inputs = BTreeMap::from([(
            "source".to_string(),
            FieldElement::from_u64(u64::from(source)),
        )]);

        let witness = generate_witness(&program, &inputs).expect("hint witness should generate");
        check_constraints(&program, &witness).expect("hint witness should satisfy constraints");

        prop_assert_eq!(
            witness.values.get("mirror"),
            Some(&FieldElement::from_u64(u64::from(source)))
        );
    }

    #[test]
    fn mixed_plan_generation_matches_constraint(field_index in 0u8..7, x in any::<u16>()) {
        let field = field_by_index(field_index);
        let program = mixed_plan_program(field);
        let inputs = BTreeMap::from([(
            "x".to_string(),
            FieldElement::from_u64(u64::from(x)),
        )]);

        let witness = generate_witness(&program, &inputs).expect("mixed witness should generate");
        check_constraints(&program, &witness).expect("mixed witness should satisfy constraints");

        let expected = FieldElement::from_bigint_with_field(BigInt::from(u64::from(x)) + BigInt::from(7u8), field);
        prop_assert_eq!(witness.values.get("sum"), Some(&expected));
        prop_assert_eq!(witness.values.get("mirror"), Some(&expected));
    }

    #[test]
    fn normalization_is_idempotent_and_digest_stable(field_index in 0u8..7, reorder in any::<bool>()) {
        let field = field_by_index(field_index);
        let original = if reorder {
            normalization_reordered_program(field)
        } else {
            normalization_arithmetic_program(field)
        };
        let equivalent = if reorder {
            normalization_arithmetic_program(field)
        } else {
            normalization_reordered_program(field)
        };

        let (normalized_once, report_once) = zkf_core::normalize::normalize(&original);
        let (normalized_twice, report_twice) = zkf_core::normalize::normalize(&normalized_once);
        let (normalized_equivalent, _) = zkf_core::normalize::normalize(&equivalent);

        prop_assert_eq!(normalized_once.digest_hex(), normalized_twice.digest_hex());
        prop_assert_eq!(normalized_once.digest_hex(), normalized_equivalent.digest_hex());
        prop_assert_eq!(report_once.output_digest, normalized_once.digest_hex());
        prop_assert_eq!(report_twice.input_digest, normalized_once.digest_hex());
    }

    #[test]
    fn normalization_preserves_supported_witnesses(field_index in 0u8..7, x in any::<u16>()) {
        let field = field_by_index(field_index);
        let original_zir = normalization_reordered_program(field);
        let (normalized_zir, _) = zkf_core::normalize::normalize(&original_zir);
        let original = program_zir_to_v2(&original_zir).expect("original ZIR should lower");
        let normalized = program_zir_to_v2(&normalized_zir).expect("normalized ZIR should lower");

        let x_value = FieldElement::from_bigint_with_field(BigInt::from(u64::from(x)), field);
        let inputs = BTreeMap::from([("x".to_string(), x_value.clone())]);

        let original_witness = generate_witness(&original, &inputs).expect("original witness should generate");
        let normalized_witness = generate_witness(&normalized, &inputs).expect("normalized witness should generate");

        check_constraints(&original, &original_witness).expect("original witness should satisfy constraints");
        check_constraints(&normalized, &normalized_witness).expect("normalized witness should satisfy constraints");

        prop_assert_eq!(original_witness.values.get("out"), Some(&x_value));
        prop_assert_eq!(normalized_witness.values.get("out"), Some(&x_value));
        prop_assert_eq!(normalized_witness.values.get("out"), original_witness.values.get("out"));
    }

    #[test]
    fn optimize_program_preserves_supported_witnesses(field_index in 0u8..7, x in any::<u16>()) {
        let field = field_by_index(field_index);
        let original = optimizer_arithmetic_program(field);
        let (optimized, report) = optimize_program(&original);

        let x_value = FieldElement::from_bigint_with_field(BigInt::from(u64::from(x)), field);
        let inputs = BTreeMap::from([("x".to_string(), x_value.clone())]);

        let original_witness = generate_witness(&original, &inputs).expect("original witness should generate");
        let optimized_witness = generate_witness(&optimized, &inputs).expect("optimized witness should generate");

        check_constraints(&original, &original_witness).expect("original witness should satisfy constraints");
        check_constraints(&optimized, &optimized_witness).expect("optimized witness should satisfy constraints");

        prop_assert!(report.removed_tautology_constraints >= 1);
        prop_assert_eq!(original_witness.values.get("out"), Some(&x_value));
        prop_assert_eq!(optimized_witness.values.get("out"), Some(&x_value));
        prop_assert_eq!(optimized_witness.values.get("out"), original_witness.values.get("out"));
    }

    #[test]
    fn optimize_zir_preserves_supported_witnesses(field_index in 0u8..7, x in any::<u16>()) {
        let field = field_by_index(field_index);
        let original_zir = optimizer_zir_arithmetic_program(field);
        let (optimized_zir, report) = optimize_zir(&original_zir).expect("optimizer should succeed");
        let original = program_zir_to_v2(&original_zir).expect("original ZIR should lower");
        let optimized = program_zir_to_v2(&optimized_zir).expect("optimized ZIR should lower");

        let x_value = FieldElement::from_bigint_with_field(BigInt::from(u64::from(x)), field);
        let inputs = BTreeMap::from([("x".to_string(), x_value.clone())]);

        let original_witness = generate_witness(&original, &inputs).expect("original witness should generate");
        let optimized_witness = generate_witness(&optimized, &inputs).expect("optimized witness should generate");

        check_constraints(&original, &original_witness).expect("original witness should satisfy constraints");
        check_constraints(&optimized, &optimized_witness).expect("optimized witness should satisfy constraints");

        prop_assert!(report.removed_tautology_constraints >= 1);
        prop_assert_eq!(original_witness.values.get("out"), Some(&x_value));
        prop_assert_eq!(optimized_witness.values.get("out"), Some(&x_value));
        prop_assert_eq!(optimized_witness.values.get("out"), original_witness.values.get("out"));
    }

    #[test]
    fn lookup_inference_preserves_lookup_semantics(selector in 0u8..4) {
        let program = lookup_program();
        let witness = generate_witness(
            &program,
            &BTreeMap::from([(
                "selector".to_string(),
                FieldElement::from_u64(u64::from(selector)),
            )]),
        ).expect("lookup witness should generate");

        let expected = match selector {
            0 => 5,
            1 => 9,
            2 => 17,
            _ => 33,
        };

        prop_assert_eq!(
            witness.values.get("mapped"),
            Some(&FieldElement::from_i64(expected))
        );
        check_constraints(&program, &witness).expect("lookup witness should satisfy constraints");
    }

    #[test]
    fn program_fixture_json_roundtrip_uses_small_canonical_shapes(use_lookup in any::<bool>()) {
        let program = if use_lookup {
            lookup_program()
        } else {
            linear_program(FieldId::BabyBear)
        };

        let json = serde_json::to_string(&program).expect("serialize program");
        let parsed: Program = serde_json::from_str(&json).expect("deserialize program");
        prop_assert_eq!(parsed, program);
    }

    #[test]
    fn compiled_program_json_roundtrip_preserves_small_fixture(
        compiled_bytes in prop::array::uniform3(any::<u8>()),
        include_original in any::<bool>(),
    ) {
        let compiled = compiled_program_fixture(compiled_bytes, include_original);
        let json = serde_json::to_string(&compiled).expect("serialize compiled program");
        let parsed: CompiledProgram = serde_json::from_str(&json).expect("deserialize compiled program");
        prop_assert_eq!(parsed, compiled);
    }

    #[test]
    fn proof_artifact_json_roundtrip_preserves_small_fixture(
        proof in prop::array::uniform3(any::<u8>()),
        vk in prop::array::uniform4(any::<u8>()),
        public_value in -32i16..32i16,
    ) {
        let artifact = proof_artifact_fixture(proof, vk, public_value);
        let json = serde_json::to_string(&artifact).expect("serialize proof artifact");
        let parsed: ProofArtifact = serde_json::from_str(&json).expect("deserialize proof artifact");
        prop_assert_eq!(parsed, artifact);
    }

    #[test]
    fn small_field_inverse_roundtrip_preserves_multiplicative_identity(
        field_index in 0u8..3,
        value in 1u16..256u16,
    ) {
        let field = small_field_by_index(field_index);
        let inverse = mod_inverse_bigint(BigInt::from(value), field.modulus())
            .expect("non-zero direct-field inverse");
        let product = normalize_mod(BigInt::from(value) * inverse, field.modulus());
        prop_assert_eq!(product, BigInt::from(1u8));
    }

    #[test]
    fn small_field_adapter_arithmetic_matches_expected_modulus(
        field_index in 0u8..3,
        lhs in any::<u8>(),
        rhs in any::<u8>(),
    ) {
        let field = small_field_by_index(field_index);
        let expected_add = normalize_mod(BigInt::from(lhs) + BigInt::from(rhs), field.modulus());
        let expected_sub = normalize_mod(BigInt::from(lhs) - BigInt::from(rhs), field.modulus());
        let expected_mul = normalize_mod(BigInt::from(lhs) * BigInt::from(rhs), field.modulus());

        let add = FieldElement::from_bigint_with_field(BigInt::from(lhs) + BigInt::from(rhs), field)
            .normalized_bigint(field)
            .expect("adapter add normalization");
        let sub = FieldElement::from_bigint_with_field(BigInt::from(lhs) - BigInt::from(rhs), field)
            .normalized_bigint(field)
            .expect("adapter sub normalization");
        let mul = FieldElement::from_bigint_with_field(BigInt::from(lhs) * BigInt::from(rhs), field)
            .normalized_bigint(field)
            .expect("adapter mul normalization");

        prop_assert_eq!(add, expected_add);
        prop_assert_eq!(sub, expected_sub);
        prop_assert_eq!(mul, expected_mul);
    }

    #[test]
    fn small_field_normalization_matches_expected_modulus(
        field_index in 0u8..3,
        value in any::<i16>(),
    ) {
        let field = small_field_by_index(field_index);
        let expected = normalize_mod(BigInt::from(value), field.modulus());
        let normalized = FieldElement::from_i64(i64::from(value))
            .normalized_bigint(field)
            .expect("direct-field normalization");
        prop_assert_eq!(normalized, expected);
    }

    #[test]
    fn ccs_conversion_fails_closed_for_lookup_and_nonlowered_blackbox(
        use_lookup in any::<bool>(),
        include_label in any::<bool>(),
    ) {
        let program = ccs_unsupported_program(use_lookup, include_label);
        let err = CcsProgram::try_from_program(&program).expect_err("unsupported CCS program must fail closed");
        let expected_label = include_label.then(|| {
            if use_lookup {
                "lookup".to_string()
            } else {
                "blackbox".to_string()
            }
        });

        match err {
            ZkfError::UnsupportedCcsEncoding { label, reason, .. } => {
                prop_assert_eq!(label, expected_label);
                if use_lookup {
                    prop_assert!(reason.contains("lookup constraints must be lowered"));
                } else {
                    prop_assert!(reason.contains("blackbox constraints must be lowered"));
                }
            }
            other => prop_assert!(false, "unexpected error: {other:?}"),
        }
    }
}

#[test]
fn ccs_range_constraint_expands_into_boolean_bits_and_recomposition() {
    let ccs = CcsProgram::try_from_program(&ccs_range_program())
        .expect("range program should synthesize");
    assert_eq!(ccs.num_constraints, 4);
    assert_eq!(ccs.degree(), 2);
}

#[test]
fn ccs_public_inputs_occupy_low_columns() {
    let ccs = CcsProgram::try_from_program(&ccs_public_private_order_program())
        .expect("public/private ordering program should synthesize");

    let public_col = ccs
        .matrices
        .iter()
        .flat_map(|matrix| matrix.entries.iter())
        .filter(|(row, _, _)| *row == 0)
        .filter(|(_, col, _)| *col != 0)
        .map(|(_, col, _)| *col)
        .min()
        .expect("row should reference at least one signal column");

    assert_eq!(ccs.num_public, 1);
    assert_eq!(public_col, 1);
}

#[test]
fn ccs_nested_division_allocates_auxiliary_rows() {
    let ccs = CcsProgram::try_from_program(&ccs_nested_division_program())
        .expect("nested division program should synthesize");

    assert!(ccs.num_constraints >= 3);
    assert!(ccs.num_variables > 5);
}
