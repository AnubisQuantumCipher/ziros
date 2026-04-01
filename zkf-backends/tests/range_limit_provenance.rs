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

// Run directly with:
// cargo test -p zkf-backends --test range_limit_provenance -- --nocapture

use zkf_backends::backend_for;
use zkf_core::{BackendKind, Constraint, FieldId, Program, Signal, Visibility};

#[test]
fn plonky3_compile_names_signal_and_constraint_for_unsupported_range_bits() {
    let program = Program {
        field: FieldId::Goldilocks,
        signals: vec![Signal {
            name: "value".to_string(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        }],
        constraints: vec![Constraint::Range {
            signal: "value".to_string(),
            bits: 67,
            label: Some("value_range".to_string()),
        }],
        ..Default::default()
    };

    let error = backend_for(BackendKind::Plonky3)
        .compile(&program)
        .expect_err("range should overflow Goldilocks");
    let rendered = error.to_string();
    assert!(rendered.contains("signal value"));
    assert!(rendered.contains("constraint #0"));
    assert!(rendered.contains("value_range"));
}
