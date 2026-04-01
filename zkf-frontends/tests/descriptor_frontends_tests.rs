// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use serde_json::json;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
    WitnessPlan,
};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

fn demo_program() -> Program {
    Program {
        name: "descriptor_demo".to_string(),
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
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("out"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("sum".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "out".to_string(),
                expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn compact_frontend_compiles_embedded_program() {
    let engine = frontend_for(FrontendKind::Compact);
    let value = json!({ "program": demo_program() });
    let program = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect("compact compile should pass");
    assert_eq!(program.name, "descriptor_demo");
    assert_eq!(program.constraints.len(), 1);
}

#[test]
fn compact_frontend_executes_embedded_witness_values() {
    let engine = frontend_for(FrontendKind::Compact);
    let value = json!({
        "witness_values": {
            "x": "3",
            "y": 4,
            "out": "7"
        }
    });
    let witness = engine
        .execute(&value, &Default::default())
        .expect("compact execute should pass");
    assert_eq!(witness.values["out"], FieldElement::new("7"));
}

#[test]
fn zkvm_frontend_compiles_with_name_override() {
    let engine = frontend_for(FrontendKind::Zkvm);
    let value = json!({ "ir_program": demo_program() });
    let program = engine
        .compile_to_ir(
            &value,
            &FrontendImportOptions {
                program_name: Some("zkvm_override".to_string()),
                ..Default::default()
            },
        )
        .expect("zkvm compile should pass");
    assert_eq!(program.name, "zkvm_override");
}

#[test]
fn plonky3_air_frontend_compiles_schema_export() {
    let engine = frontend_for(FrontendKind::Plonky3Air);
    let value = json!({
        "schema": "zkf-plonky3-air-export-v1",
        "program": demo_program(),
        "trace_width": 3,
        "rows": 8
    });
    let program = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect("plonky3-air schema compile should pass");
    assert_eq!(program.field, FieldId::Bn254);
}
