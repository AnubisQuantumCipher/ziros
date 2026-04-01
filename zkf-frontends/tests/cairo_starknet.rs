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

//! Integration tests for realistic StarkNet-style Cairo descriptors.
//!
//! The Sierra fixture below intentionally contains stateful StarkNet surfaces
//! like `storage_read` and `storage_write`. Those are no longer allowed to
//! compile directly to IR v2 because the frontend now fails closed instead of
//! pretending those effects were ordinary BlackBox constraints.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use zkf_core::{FieldId, Visibility, zir_v1};
use zkf_frontends::{FrontendImportOptions, FrontendKind, FrontendProgram, frontend_for};

/// Build the Sierra JSON for a realistic StarkNet token-transfer contract.
fn build_starknet_transfer_sierra() -> Value {
    json!({
        "type_declarations": [
            {
                "id": { "id": 0, "debug_name": "felt252" },
                "long_id": { "generic_id": "felt252", "generic_args": [] }
            },
            {
                "id": { "id": 1, "debug_name": "u128" },
                "long_id": { "generic_id": "u128", "generic_args": [] }
            },
            {
                "id": { "id": 2, "debug_name": "RangeCheck" },
                "long_id": { "generic_id": "RangeCheck", "generic_args": [] }
            }
        ],
        "libfunc_declarations": [
            { "id": { "id": 0 }, "long_id": { "generic_id": "storage_read" } },
            { "id": { "id": 1 }, "long_id": { "generic_id": "storage_write" } },
            { "id": { "id": 2 }, "long_id": { "generic_id": "u128_le" } },
            { "id": { "id": 3 }, "long_id": { "generic_id": "poseidon" } },
            { "id": { "id": 4 }, "long_id": { "generic_id": "return" } }
        ],
        "funcs": [
            {
                "id": { "id": 0, "debug_name": "check_transfer" },
                "signature": {
                    "param_types": [
                        { "id": 2, "debug_name": "RangeCheck" },
                        { "id": 0, "debug_name": "felt252" },
                        { "id": 0, "debug_name": "felt252" },
                        { "id": 1, "debug_name": "u128" }
                    ],
                    "ret_types": [
                        { "id": 0, "debug_name": "felt252" }
                    ]
                },
                "params": [
                    { "id": 0 },
                    { "id": 1 },
                    { "id": 2 },
                    { "id": 3 }
                ]
            }
        ],
        "statements": [
            {
                "Invocation": {
                    "libfunc_id": { "id": 0 },
                    "args": [{ "id": 1 }],
                    "branches": [{ "results": [{ "id": 10 }] }]
                }
            },
            {
                "Invocation": {
                    "libfunc_id": { "id": 2 },
                    "args": [{ "id": 3 }, { "id": 10 }],
                    "branches": [{ "results": [{ "id": 11 }] }]
                }
            },
            {
                "Invocation": {
                    "libfunc_id": { "id": 1 },
                    "args": [{ "id": 2 }, { "id": 10 }],
                    "branches": [{ "results": [{ "id": 12 }] }]
                }
            },
            {
                "Invocation": {
                    "libfunc_id": { "id": 3 },
                    "args": [{ "id": 1 }, { "id": 2 }],
                    "branches": [{ "results": [{ "id": 13 }] }]
                }
            },
            {
                "Invocation": {
                    "libfunc_id": { "id": 4 },
                    "args": [{ "id": 13 }],
                    "branches": [{ "results": [] }]
                }
            }
        ]
    })
}

fn options() -> FrontendImportOptions {
    FrontendImportOptions {
        program_name: Some("starknet_transfer".to_string()),
        field: Some(FieldId::Goldilocks),
        allow_unsupported_versions: false,
        translator: None,
        ir_family: Default::default(),
        source_path: None,
    }
}

fn compile_ir_error(value: &Value) -> String {
    let engine = frontend_for(FrontendKind::Cairo);
    engine
        .compile_to_ir(value, &options())
        .expect_err("stateful Sierra should fail closed without explicit ZIR")
        .to_string()
}

fn embedded_stateful_zir() -> zir_v1::Program {
    zir_v1::Program {
        name: "starknet_transfer_stateful".to_string(),
        field: FieldId::Goldilocks,
        signals: vec![
            zir_v1::Signal {
                name: "sender".to_string(),
                visibility: Visibility::Public,
                ty: zir_v1::SignalType::Field,
                constant: None,
            },
            zir_v1::Signal {
                name: "recipient".to_string(),
                visibility: Visibility::Public,
                ty: zir_v1::SignalType::Field,
                constant: None,
            },
            zir_v1::Signal {
                name: "amount".to_string(),
                visibility: Visibility::Public,
                ty: zir_v1::SignalType::UInt { bits: 128 },
                constant: None,
            },
            zir_v1::Signal {
                name: "receipt".to_string(),
                visibility: Visibility::Public,
                ty: zir_v1::SignalType::Field,
                constant: None,
            },
        ],
        constraints: vec![
            zir_v1::Constraint::MemoryRead {
                memory: "storage".to_string(),
                index: zir_v1::Expr::Signal("sender".to_string()),
                value: zir_v1::Expr::Signal("receipt".to_string()),
                label: Some("storage_read_sender".to_string()),
            },
            zir_v1::Constraint::MemoryWrite {
                memory: "storage".to_string(),
                index: zir_v1::Expr::Signal("recipient".to_string()),
                value: zir_v1::Expr::Signal("amount".to_string()),
                label: Some("storage_write_recipient".to_string()),
            },
        ],
        witness_plan: Default::default(),
        lookup_tables: vec![],
        memory_regions: vec![],
        custom_gates: vec![],
        metadata: BTreeMap::new(),
    }
}

#[test]
fn test_probe_accepts_sierra() {
    let sierra = build_starknet_transfer_sierra();
    let engine = frontend_for(FrontendKind::Cairo);
    let probe = engine.probe(&sierra);
    assert!(probe.accepted, "frontend should accept Sierra JSON");
    assert_eq!(probe.format.as_deref(), Some("sierra-json"));
}

#[test]
fn test_compile_to_ir_rejects_stateful_placeholder_surfaces() {
    let error = compile_ir_error(&build_starknet_transfer_sierra());
    assert!(error.contains("storage_read"));
    assert!(error.contains("storage_write"));
    assert!(error.contains("placeholder-only libfunc surface"));
}

#[test]
fn test_descriptor_path_rejects_placeholder_sierra_without_zir() {
    let descriptor = json!({ "sierra_json": build_starknet_transfer_sierra() });
    let error = compile_ir_error(&descriptor);
    assert!(error.contains("zir_program"));
    assert!(error.contains("compiled_zir_path"));
}

#[test]
fn test_compile_to_program_family_accepts_embedded_zir_for_stateful_contract() {
    let descriptor = json!({
        "sierra_json": build_starknet_transfer_sierra(),
        "zir_program": embedded_stateful_zir(),
    });
    let engine = frontend_for(FrontendKind::Cairo);
    let program = engine
        .compile_to_program_family(&descriptor, &options())
        .expect("descriptor should succeed when explicit ZIR is provided");
    match program {
        FrontendProgram::ZirV1(program) => {
            assert_eq!(program.name, "starknet_transfer");
            assert_eq!(program.field, FieldId::Goldilocks);
            assert_eq!(program.constraints.len(), 2);
            assert_eq!(program.signals.len(), 4);
        }
        other => panic!("expected zir-v1 program family, got {}", other.ir_family()),
    }
}

#[test]
fn test_inspect_reports_sierra_metadata() {
    let sierra = build_starknet_transfer_sierra();
    let engine = frontend_for(FrontendKind::Cairo);
    let inspection = engine.inspect(&sierra).expect("inspect should succeed");

    assert_eq!(inspection.frontend, FrontendKind::Cairo);
    assert_eq!(inspection.functions, 1);
    assert!(
        *inspection
            .opcode_counts
            .get("sierra_statements")
            .unwrap_or(&0)
            > 0,
        "should report non-zero statement count"
    );
    assert!(
        *inspection.opcode_counts.get("sierra_types").unwrap_or(&0) > 0,
        "should report non-zero type count"
    );
}
