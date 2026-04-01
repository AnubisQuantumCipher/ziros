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

use super::*;
use clap::Parser;

fn circuit_summary_program() -> Program {
    Program {
        name: "circuit_show_demo".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            zkf_core::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                constant: None,
                ty: None,
            },
            zkf_core::Signal {
                name: "digest".to_string(),
                visibility: zkf_core::Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::BlackBox {
            op: zkf_core::BlackBoxOp::Poseidon,
            inputs: vec![zkf_core::Expr::signal("x")],
            outputs: vec!["digest".to_string()],
            params: BTreeMap::new(),
            label: Some("poseidon_hash".to_string()),
        }],
        witness_plan: zkf_core::WitnessPlan {
            assignments: vec![zkf_core::WitnessAssignment {
                target: "digest".to_string(),
                expr: zkf_core::Expr::signal("x"),
            }],
            ..zkf_core::WitnessPlan::default()
        },
        ..Program::default()
    }
}

#[test]
fn cli_parses_circuit_show_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "circuit",
        "show",
        "--program",
        "/tmp/program.json",
        "--json",
        "--show-assignments",
        "--show-flow",
    ]);

    match cli.command {
        crate::cli::Commands::Circuit {
            command:
                crate::cli::CircuitCommands::Show {
                    program,
                    json,
                    show_assignments,
                    show_flow,
                },
        } => {
            assert_eq!(program, PathBuf::from("/tmp/program.json"));
            assert!(json);
            assert!(show_assignments);
            assert!(show_flow);
        }
        other => panic!("expected circuit show command, got {other:?}"),
    }
}

#[test]
fn circuit_render_includes_assignments_blackboxes_and_flow() {
    let summary = zkf_core::summarize_program(
        &circuit_summary_program(),
        zkf_core::CircuitSummaryOptions {
            include_assignments: true,
            include_flow: true,
        },
    );

    let rendered = crate::cmd::circuit::render_circuit_summary(&summary).expect("render");
    assert!(rendered.contains("Circuit Summary"));
    assert!(rendered.contains("Witness assignments: 1"));
    assert!(rendered.contains("Targets: digest"));
    assert!(rendered.contains("BlackBox ops:"));
    assert!(rendered.contains("poseidon"));
    assert!(rendered.contains("Witness flow: nodes="));
    assert!(rendered.contains("digest <- x"));
}

#[test]
fn circuit_show_json_summary_contains_flow_when_requested() {
    let summary = zkf_core::summarize_program(
        &circuit_summary_program(),
        zkf_core::CircuitSummaryOptions {
            include_assignments: true,
            include_flow: true,
        },
    );

    let json = serde_json::to_value(&summary).expect("summary json");
    assert_eq!(json["program_name"], "circuit_show_demo");
    assert_eq!(json["constraint_kinds"]["blackbox"], 1);
    assert_eq!(json["blackbox_ops"]["poseidon"], 1);
    assert_eq!(json["witness_assignment_targets"][0], "digest");
    assert!(json.get("witness_flow").is_some());
}
