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

use std::collections::BTreeMap;
use zkf_core::ZkfResult;
use zkf_core::zir;

/// Compact type inferred from ZIR signal types.
///
/// Maps the ZIR type system onto Midnight Compact's native type system:
/// - `Field` stays as `Field`
/// - `Bool` becomes `Boolean`
/// - `UInt { bits: 8 }` becomes `Bytes<1>`, `UInt { bits: 32 }` becomes `Bytes<4>`, etc.
/// - `Array { element: Field, len: N }` becomes `Vector<Field, N>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactType {
    Field,
    Boolean,
    Bytes(usize),
    Uint(u32),
    Vector(Box<CompactType>, usize),
}

impl CompactType {
    /// Render this type as a Compact type string.
    pub fn to_compact_string(&self) -> String {
        match self {
            CompactType::Field => "Field".to_string(),
            CompactType::Boolean => "Boolean".to_string(),
            CompactType::Bytes(n) => format!("Bytes<{}>", n),
            CompactType::Uint(bits) => {
                // Map uint bit-widths to Compact Bytes<N> representation.
                let byte_count = (*bits).div_ceil(8) as usize;
                format!("Bytes<{}>", byte_count)
            }
            CompactType::Vector(elem, len) => {
                format!("Vector<{}, {}>", elem.to_compact_string(), len)
            }
        }
    }
}

/// A typed witness declaration for the Compact `witnesses { }` block.
#[derive(Debug, Clone)]
pub struct CompactWitnessDecl {
    pub name: String,
    pub compact_type: CompactType,
}

/// A ledger state declaration for Compact contracts.
#[derive(Debug, Clone)]
pub struct CompactLedgerDecl {
    pub name: String,
    pub compact_type: CompactType,
}

/// A circuit input/output parameter.
#[derive(Debug, Clone)]
pub struct CompactParam {
    pub name: String,
    pub compact_type: CompactType,
}

/// Represents a full Compact program with structured declarations.
///
/// This captures the key structural elements of a Midnight Compact program:
/// - `export circuit` declarations with typed inputs/outputs
/// - `witnesses { }` block declaring private witnesses
/// - `ledger` state declarations for stateful contracts
#[derive(Debug, Clone)]
pub struct CompactCircuit {
    pub name: String,
    pub inputs: Vec<CompactParam>,
    pub outputs: Vec<CompactParam>,
    pub witnesses: Vec<CompactWitnessDecl>,
    pub ledger_decls: Vec<CompactLedgerDecl>,
    pub body_statements: Vec<String>,
}

/// State schema for Compact contracts.
#[derive(Debug, Clone)]
pub struct CompactStateSchema {
    pub fields: Vec<(String, CompactType)>,
}

/// Generated Compact program with metadata.
#[derive(Debug, Clone)]
pub struct CompactProgram {
    pub source: String,
    pub contract_name: String,
    pub state_schema: Option<CompactStateSchema>,
    pub type_map: BTreeMap<String, CompactType>,
    pub circuit: CompactCircuit,
}

/// Generate a type-aware Compact program from a ZIR program.
///
/// Produces authentic Midnight Compact output with:
/// - `export circuit` declarations with typed inputs/outputs
/// - `witnesses { }` block for private signals
/// - `ledger` declarations for stateful contracts
/// - Proper Compact types: `Field`, `Boolean`, `Bytes<N>`, `Vector<Field, N>`
pub fn generate_compact(program: &zir::Program) -> ZkfResult<CompactProgram> {
    let mut type_map = BTreeMap::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut witnesses = Vec::new();
    let mut ledger_decls = Vec::new();

    // Map ZIR signal types to Compact types and classify signals.
    for signal in &program.signals {
        let compact_type = signal_type_to_compact(&signal.ty);
        type_map.insert(signal.name.clone(), compact_type.clone());

        let is_state = signal.name.starts_with("state_");

        if is_state {
            // State signals become ledger declarations.
            ledger_decls.push(CompactLedgerDecl {
                name: signal.name.clone(),
                compact_type: compact_type.clone(),
            });
            // Also an output (readable from the circuit).
            outputs.push(CompactParam {
                name: signal.name.clone(),
                compact_type,
            });
        } else {
            match signal.visibility {
                zkf_core::Visibility::Public => {
                    outputs.push(CompactParam {
                        name: signal.name.clone(),
                        compact_type,
                    });
                }
                zkf_core::Visibility::Private => {
                    witnesses.push(CompactWitnessDecl {
                        name: signal.name.clone(),
                        compact_type: compact_type.clone(),
                    });
                    inputs.push(CompactParam {
                        name: signal.name.clone(),
                        compact_type,
                    });
                }
                zkf_core::Visibility::Constant => {
                    inputs.push(CompactParam {
                        name: signal.name.clone(),
                        compact_type,
                    });
                }
            }
        }
    }

    // Render constraint statements.
    let mut body_statements = Vec::new();
    for (idx, constraint) in program.constraints.iter().enumerate() {
        let stmt = render_compact_constraint(constraint, idx);
        body_statements.push(stmt);
    }

    // Build the structured circuit.
    let circuit = CompactCircuit {
        name: program.name.clone(),
        inputs: inputs.clone(),
        outputs: outputs.clone(),
        witnesses: witnesses.clone(),
        ledger_decls: ledger_decls.clone(),
        body_statements: body_statements.clone(),
    };

    // Generate formatted Compact source.
    let source = render_compact_source(
        &program.name,
        &program.field,
        &inputs,
        &outputs,
        &witnesses,
        &ledger_decls,
        &body_statements,
    );

    // Detect state schema.
    let state_fields: Vec<(String, CompactType)> = program
        .signals
        .iter()
        .filter(|s| s.name.starts_with("state_"))
        .map(|s| {
            (
                s.name.clone(),
                type_map.get(&s.name).cloned().unwrap_or(CompactType::Field),
            )
        })
        .collect();

    let state_schema = if state_fields.is_empty() {
        None
    } else {
        Some(CompactStateSchema {
            fields: state_fields,
        })
    };

    Ok(CompactProgram {
        source,
        contract_name: program.name.clone(),
        state_schema,
        type_map,
        circuit,
    })
}

/// Convert a ZIR signal type to the corresponding Compact type.
fn signal_type_to_compact(ty: &zir::SignalType) -> CompactType {
    match ty {
        zir::SignalType::Field => CompactType::Field,
        zir::SignalType::Bool => CompactType::Boolean,
        zir::SignalType::UInt { bits } => {
            // Map byte-aligned UInt widths to Bytes<N>, keep others as Uint.
            if *bits % 8 == 0 {
                CompactType::Bytes((*bits / 8) as usize)
            } else {
                CompactType::Uint(*bits)
            }
        }
        zir::SignalType::Array { element, len } => {
            CompactType::Vector(Box::new(signal_type_to_compact(element)), *len as usize)
        }
        zir::SignalType::Tuple { .. } => CompactType::Field, // fallback
    }
}

/// Render a single ZIR constraint as a Compact statement string.
fn render_compact_constraint(constraint: &zir::Constraint, idx: usize) -> String {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, label } => {
            let label_comment = label_suffix(label, idx);
            format!(
                "assert {} == {};{}",
                render_compact_expr(lhs),
                render_compact_expr(rhs),
                label_comment
            )
        }
        zir::Constraint::Boolean { signal, label } => {
            let label_comment = label_suffix(label, idx);
            format!(
                "assert {} * (1 - {}) == 0;{}",
                signal, signal, label_comment
            )
        }
        zir::Constraint::Range {
            signal,
            bits,
            label,
        } => {
            let label_comment = label_suffix(label, idx);
            format!("assert_range({}, {});{}", signal, bits, label_comment)
        }
        zir::Constraint::Lookup {
            inputs,
            table,
            label,
        } => {
            let label_comment = label_suffix(label, idx);
            let args: Vec<String> = inputs.iter().map(render_compact_expr).collect();
            format!("lookup({}, [{}]);{}", table, args.join(", "), label_comment)
        }
        zir::Constraint::CustomGate {
            gate,
            inputs,
            outputs,
            label,
            ..
        } => {
            let label_comment = label_suffix(label, idx);
            let args: Vec<String> = inputs.iter().map(render_compact_expr).collect();
            format!(
                "custom_gate({}, [{}], [{}]);{}",
                gate,
                args.join(", "),
                outputs.join(", "),
                label_comment
            )
        }
        zir::Constraint::MemoryRead {
            memory,
            index,
            value,
            label,
        } => {
            let label_comment = label_suffix(label, idx);
            format!(
                "mem_read({}, {}, {});{}",
                memory,
                render_compact_expr(index),
                render_compact_expr(value),
                label_comment
            )
        }
        zir::Constraint::MemoryWrite {
            memory,
            index,
            value,
            label,
        } => {
            let label_comment = label_suffix(label, idx);
            format!(
                "mem_write({}, {}, {});{}",
                memory,
                render_compact_expr(index),
                render_compact_expr(value),
                label_comment
            )
        }
        zir::Constraint::BlackBox {
            op,
            inputs,
            outputs,
            label,
            ..
        } => {
            let label_comment = label_suffix(label, idx);
            let args: Vec<String> = inputs.iter().map(render_compact_expr).collect();
            let compact_fn = blackbox_to_compact_fn(*op);
            format!(
                "{}([{}]) -> [{}];{}",
                compact_fn,
                args.join(", "),
                outputs.join(", "),
                label_comment
            )
        }
        zir::Constraint::Permutation { left, right, label } => {
            let label_comment = label_suffix(label, idx);
            format!("permutation({}, {});{}", left, right, label_comment)
        }
        zir::Constraint::Copy { from, to, label } => {
            let label_comment = label_suffix(label, idx);
            format!("assert {} == {};{}", from, to, label_comment)
        }
    }
}

/// Map a ZIR BlackBoxOp to the corresponding Compact native function name.
fn blackbox_to_compact_fn(op: zir::BlackBoxOp) -> &'static str {
    match op {
        zir::BlackBoxOp::Poseidon => "poseidon_hash",
        zir::BlackBoxOp::Sha256 => "sha256_hash",
        zir::BlackBoxOp::Keccak256 => "keccak256_hash",
        zir::BlackBoxOp::Pedersen => "pedersen_commit",
        zir::BlackBoxOp::EcdsaSecp256k1 => "ecdsa_verify_secp256k1",
        zir::BlackBoxOp::EcdsaSecp256r1 => "ecdsa_verify_secp256r1",
        zir::BlackBoxOp::SchnorrVerify => "schnorr_verify",
        zir::BlackBoxOp::Blake2s => "blake2s_hash",
        zir::BlackBoxOp::RecursiveAggregationMarker => "recursive_aggregation",
        zir::BlackBoxOp::ScalarMulG1 => "scalar_mul_g1",
        zir::BlackBoxOp::PointAddG1 => "point_add_g1",
        zir::BlackBoxOp::PairingCheck => "pairing_check",
    }
}

/// Generate a label suffix comment. Named labels get ` // label`, anonymous
/// constraints get nothing (index is used only as fallback identifier).
fn label_suffix(label: &Option<String>, _idx: usize) -> String {
    match label {
        Some(l) => format!(" // {}", l),
        None => String::new(),
    }
}

/// Render a ZIR expression to Compact expression syntax.
fn render_compact_expr(expr: &zir::Expr) -> String {
    match expr {
        zir::Expr::Const(c) => c.to_decimal_string(),
        zir::Expr::Signal(name) => name.clone(),
        zir::Expr::Add(values) => {
            let parts: Vec<String> = values.iter().map(render_compact_expr).collect();
            format!("({})", parts.join(" + "))
        }
        zir::Expr::Sub(a, b) => {
            format!("({} - {})", render_compact_expr(a), render_compact_expr(b))
        }
        zir::Expr::Mul(a, b) => {
            format!("({} * {})", render_compact_expr(a), render_compact_expr(b))
        }
        zir::Expr::Div(a, b) => {
            format!("({} / {})", render_compact_expr(a), render_compact_expr(b))
        }
    }
}

/// Render the complete Compact source text from structured declarations.
fn render_compact_source(
    name: &str,
    field: &zkf_core::FieldId,
    inputs: &[CompactParam],
    outputs: &[CompactParam],
    witnesses: &[CompactWitnessDecl],
    ledger_decls: &[CompactLedgerDecl],
    body_statements: &[String],
) -> String {
    let mut src = String::new();

    // Header.
    src.push_str(&format!("// Generated Compact program: {}\n", name));
    src.push_str(&format!("// Field: {:?}\n\n", field));

    // Ledger declarations (top-level, before circuit).
    for decl in ledger_decls {
        src.push_str(&format!(
            "ledger {}: {};\n",
            decl.name,
            decl.compact_type.to_compact_string()
        ));
    }
    if !ledger_decls.is_empty() {
        src.push('\n');
    }

    // Witnesses block.
    if !witnesses.is_empty() {
        src.push_str("witnesses {\n");
        for w in witnesses {
            src.push_str(&format!(
                "  {}: {};\n",
                w.name,
                w.compact_type.to_compact_string()
            ));
        }
        src.push_str("}\n\n");
    }

    // Export circuit declaration.
    src.push_str(&format!("export circuit {}(", name));

    // Input parameters.
    let input_params: Vec<String> = inputs
        .iter()
        .map(|p| format!("{}: {}", p.name, p.compact_type.to_compact_string()))
        .collect();
    src.push_str(&input_params.join(", "));
    src.push_str(") -> (");

    // Output parameters (exclude state signals -- they are accessed via ledger).
    let non_state_outputs: Vec<&CompactParam> = outputs
        .iter()
        .filter(|p| !p.name.starts_with("state_"))
        .collect();
    let output_params: Vec<String> = non_state_outputs
        .iter()
        .map(|p| format!("{}: {}", p.name, p.compact_type.to_compact_string()))
        .collect();
    src.push_str(&output_params.join(", "));
    src.push_str(") {\n");

    // Circuit body.
    for stmt in body_statements {
        src.push_str(&format!("  {}\n", stmt));
    }

    src.push_str("}\n");
    src
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_export_circuit_with_typed_params() {
        let program = zir::Program {
            name: "age_check".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zir::Signal {
                    name: "birth_year".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::UInt { bits: 16 },
                    constant: None,
                },
                zir::Signal {
                    name: "is_adult".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Bool,
                    constant: None,
                },
            ],
            constraints: vec![
                zir::Constraint::Range {
                    signal: "birth_year".to_string(),
                    bits: 16,
                    label: Some("year_range".to_string()),
                },
                zir::Constraint::Boolean {
                    signal: "is_adult".to_string(),
                    label: None,
                },
            ],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        assert_eq!(compact.contract_name, "age_check");

        // Should use `export circuit` syntax.
        assert!(compact.source.contains("export circuit age_check("));

        // Witnesses block for private signals.
        assert!(compact.source.contains("witnesses {"));
        assert!(compact.source.contains("birth_year: Bytes<2>"));

        // Output typed parameter.
        assert!(compact.source.contains("is_adult: Boolean"));

        // Compact constraint syntax: boolean constraint.
        assert!(compact.source.contains("is_adult * (1 - is_adult) == 0;"));

        // Compact constraint syntax: range constraint.
        assert!(compact.source.contains("assert_range(birth_year, 16);"));

        // Type map correctness.
        assert_eq!(
            compact.type_map.get("birth_year"),
            Some(&CompactType::Bytes(2))
        );
        assert_eq!(
            compact.type_map.get("is_adult"),
            Some(&CompactType::Boolean)
        );
    }

    #[test]
    fn generates_ledger_for_state_signals() {
        let program = zir::Program {
            name: "stateful".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "state_counter".to_string(),
                visibility: zkf_core::Visibility::Public,
                ty: zir::SignalType::Field,
                constant: None,
            }],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        assert!(compact.state_schema.is_some());

        // Should have ledger declaration.
        assert!(compact.source.contains("ledger state_counter: Field;"));

        // State signals should NOT appear in circuit output params.
        assert!(!compact.source.contains("-> (state_counter"));
    }

    #[test]
    fn maps_uint8_to_bytes1() {
        let program = zir::Program {
            name: "byte_test".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "data".to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::UInt { bits: 8 },
                constant: None,
            }],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        assert_eq!(compact.type_map.get("data"), Some(&CompactType::Bytes(1)));
        assert!(compact.source.contains("data: Bytes<1>"));
    }

    #[test]
    fn maps_uint32_to_bytes4() {
        let program = zir::Program {
            name: "u32_test".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "amount".to_string(),
                visibility: zkf_core::Visibility::Public,
                ty: zir::SignalType::UInt { bits: 32 },
                constant: None,
            }],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        assert_eq!(compact.type_map.get("amount"), Some(&CompactType::Bytes(4)));
        assert!(compact.source.contains("amount: Bytes<4>"));
    }

    #[test]
    fn maps_array_to_vector() {
        let program = zir::Program {
            name: "vec_test".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "vals".to_string(),
                visibility: zkf_core::Visibility::Public,
                ty: zir::SignalType::Array {
                    element: Box::new(zir::SignalType::Field),
                    len: 8,
                },
                constant: None,
            }],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        assert_eq!(
            compact.type_map.get("vals"),
            Some(&CompactType::Vector(Box::new(CompactType::Field), 8))
        );
        assert!(compact.source.contains("vals: Vector<Field, 8>"));
    }

    #[test]
    fn handles_blackbox_constraints() {
        let program = zir::Program {
            name: "hash_circuit".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zir::Signal {
                    name: "preimage".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "digest".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Poseidon,
                inputs: vec![zir::Expr::Signal("preimage".to_string())],
                outputs: vec!["digest".to_string()],
                params: std::collections::BTreeMap::new(),
                label: Some("hash_op".to_string()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        assert!(
            compact
                .source
                .contains("poseidon_hash([preimage]) -> [digest];")
        );
    }

    #[test]
    fn compact_type_string_representations() {
        assert_eq!(CompactType::Field.to_compact_string(), "Field");
        assert_eq!(CompactType::Boolean.to_compact_string(), "Boolean");
        assert_eq!(CompactType::Bytes(32).to_compact_string(), "Bytes<32>");
        assert_eq!(CompactType::Uint(16).to_compact_string(), "Bytes<2>");
        assert_eq!(CompactType::Uint(8).to_compact_string(), "Bytes<1>");
        assert_eq!(CompactType::Uint(32).to_compact_string(), "Bytes<4>");
        assert_eq!(
            CompactType::Vector(Box::new(CompactType::Field), 4).to_compact_string(),
            "Vector<Field, 4>"
        );
        assert_eq!(
            CompactType::Vector(Box::new(CompactType::Bytes(32)), 10).to_compact_string(),
            "Vector<Bytes<32>, 10>"
        );
    }

    #[test]
    fn circuit_struct_is_populated() {
        let program = zir::Program {
            name: "test_circuit".to_string(),
            field: zkf_core::FieldId::Bn254,
            signals: vec![
                zir::Signal {
                    name: "secret_val".to_string(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "public_out".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
                zir::Signal {
                    name: "state_balance".to_string(),
                    visibility: zkf_core::Visibility::Public,
                    ty: zir::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir::Constraint::Equal {
                lhs: zir::Expr::Signal("secret_val".to_string()),
                rhs: zir::Expr::Signal("public_out".to_string()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: std::collections::BTreeMap::new(),
        };

        let compact = generate_compact(&program).unwrap();
        let circuit = &compact.circuit;

        // Inputs: secret_val (private, non-state).
        assert_eq!(circuit.inputs.len(), 1);
        assert_eq!(circuit.inputs[0].name, "secret_val");

        // Outputs: public_out (public, non-state) + state_balance (state).
        assert_eq!(circuit.outputs.len(), 2);

        // Witnesses: secret_val.
        assert_eq!(circuit.witnesses.len(), 1);
        assert_eq!(circuit.witnesses[0].name, "secret_val");

        // Ledger decls: state_balance.
        assert_eq!(circuit.ledger_decls.len(), 1);
        assert_eq!(circuit.ledger_decls[0].name, "state_balance");

        // Body: one constraint.
        assert_eq!(circuit.body_statements.len(), 1);
    }
}
