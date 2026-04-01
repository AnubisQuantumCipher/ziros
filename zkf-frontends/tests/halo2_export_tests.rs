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
    Constraint, Expr, FieldId, Program, Signal, Visibility, WitnessAssignment, WitnessPlan,
};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

fn demo_program() -> Program {
    Program {
        name: "halo2_export_demo".to_string(),
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
                name: "sum".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("sum"),
            rhs: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            label: Some("sum".to_string()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "sum".to_string(),
                expr: Expr::Add(vec![Expr::signal("x"), Expr::signal("y")]),
            }],
            hints: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn halo2_export_compiles_to_ir() {
    let engine = frontend_for(FrontendKind::Halo2Rust);
    let value = json!({
        "schema": "zkf-halo2-export-v1",
        "program": demo_program(),
        "columns": [
            {"name": "advice0", "kind": "advice"},
            {"name": "instance0", "kind": "instance"}
        ],
        "gates": [
            {"name": "sum_gate", "selectors": ["q_sum"], "constraints": ["x + y - sum = 0"]}
        ],
        "copy_constraints": [
            {"left": "advice0@0", "right": "instance0@0"}
        ]
    });

    let program = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect("halo2 export compile should pass");
    assert_eq!(program.name, "halo2_export_demo");
    assert_eq!(program.constraints.len(), 1);
}

#[test]
fn halo2_export_rejects_unknown_schema() {
    let engine = frontend_for(FrontendKind::Halo2Rust);
    let value = json!({
        "schema": "unknown",
        "program": demo_program()
    });
    let err = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect_err("unknown schema must fail");
    let rendered = err.to_string();
    assert!(rendered.contains("unsupported halo2 export schema"));
}
