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

use super::ZirLowering;
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{BackendKind, ZkfResult};

/// Compact type inferred from ZIR signal types.
///
/// Maps the ZIR type system onto Midnight Compact's type system:
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

/// A typed signal in the Compact program.
#[derive(Debug, Clone)]
pub struct CompactSignal {
    pub name: String,
    pub compact_type: CompactType,
    pub is_public: bool,
    pub is_state: bool,
}

/// A witness declaration in a Compact `witnesses { }` block.
#[derive(Debug, Clone)]
pub struct CompactWitnessDecl {
    pub name: String,
    pub compact_type: CompactType,
}

/// Compact circuit block representation using `export circuit` syntax.
#[derive(Debug, Clone)]
pub struct CompactCircuitBlock {
    pub name: String,
    pub inputs: Vec<CompactSignal>,
    pub outputs: Vec<CompactSignal>,
    pub body: Vec<CompactStatement>,
}

/// Statement in a Compact circuit block.
#[derive(Debug, Clone)]
pub enum CompactStatement {
    /// `let name: type = expr;`
    Let {
        name: String,
        ty: CompactType,
        expr: String,
    },
    /// `assert expr;` with an optional label comment.
    Assert { expr: String, label: Option<String> },
    /// Return statement: `return (values);`
    Return { values: Vec<String> },
    /// `export circuit name(inputs) -> (outputs) { body }`
    ExportCircuit {
        name: String,
        inputs: Vec<(String, CompactType)>,
        outputs: Vec<(String, CompactType)>,
    },
    /// `witnesses { declarations }`
    WitnessBlock {
        declarations: Vec<CompactWitnessDecl>,
    },
    /// `ledger name: compact_type;`
    LedgerDecl {
        name: String,
        compact_type: CompactType,
    },
}

/// State schema for Compact contracts.
#[derive(Debug, Clone)]
pub struct CompactStateSchema {
    pub fields: Vec<(String, CompactType)>,
}

/// Lowered Midnight Compact representation.
#[derive(Debug, Clone)]
pub struct MidnightLoweredIr {
    pub contract_name: String,
    pub compact_source: String,
    pub circuit_blocks: Vec<CompactCircuitBlock>,
    pub state_schema: Option<CompactStateSchema>,
    pub type_map: BTreeMap<String, CompactType>,
    pub field: zkf_core::FieldId,
    pub metadata: BTreeMap<String, String>,
}

pub struct MidnightLowering;

impl ZirLowering for MidnightLowering {
    type LoweredIr = MidnightLoweredIr;

    fn backend(&self) -> BackendKind {
        BackendKind::MidnightCompact
    }

    fn lower(&self, program: &zir::Program) -> ZkfResult<MidnightLoweredIr> {
        let mut type_map = BTreeMap::new();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut witnesses = Vec::new();
        let mut ledger_decls = Vec::new();

        // Map signals to Compact types and classify them.
        for signal in &program.signals {
            let compact_type = signal_type_to_compact(&signal.ty);
            type_map.insert(signal.name.clone(), compact_type.clone());

            let is_state = signal.name.starts_with("state_");

            let cs = CompactSignal {
                name: signal.name.clone(),
                compact_type: compact_type.clone(),
                is_public: signal.visibility == zkf_core::Visibility::Public,
                is_state,
            };

            if is_state {
                // State signals become ledger declarations.
                ledger_decls.push(CompactStatement::LedgerDecl {
                    name: signal.name.clone(),
                    compact_type: compact_type.clone(),
                });
                outputs.push(cs);
            } else if signal.visibility == zkf_core::Visibility::Public {
                outputs.push(cs);
            } else if signal.visibility == zkf_core::Visibility::Private {
                // Private signals are witnesses.
                witnesses.push(CompactWitnessDecl {
                    name: signal.name.clone(),
                    compact_type,
                });
                inputs.push(cs);
            } else {
                // Constants become inputs.
                inputs.push(cs);
            }
        }

        // Generate circuit block body from constraints.
        let mut body = Vec::new();
        for constraint in &program.constraints {
            lower_constraint(constraint, &mut body);
        }

        // Build circuit block.
        let circuit_block = CompactCircuitBlock {
            name: program.name.clone(),
            inputs,
            outputs,
            body,
        };

        // Generate Compact source using the new structured format.
        let compact_source = generate_compact_source(
            &program.name,
            &circuit_block,
            &witnesses,
            &ledger_decls,
            &type_map,
        );

        // Detect state schema from signals.
        let state_fields: Vec<(String, CompactType)> = program
            .signals
            .iter()
            .filter(|s| s.name.starts_with("state_"))
            .map(|s| (s.name.clone(), signal_type_to_compact(&s.ty)))
            .collect();

        let state_schema = if state_fields.is_empty() {
            None
        } else {
            Some(CompactStateSchema {
                fields: state_fields,
            })
        };

        Ok(MidnightLoweredIr {
            contract_name: program.name.clone(),
            compact_source,
            circuit_blocks: vec![circuit_block],
            state_schema,
            type_map,
            field: program.field,
            metadata: program.metadata.clone(),
        })
    }
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

/// Lower a single ZIR constraint into one or more `CompactStatement`s.
fn lower_constraint(constraint: &zir::Constraint, body: &mut Vec<CompactStatement>) {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, label } => {
            let lhs_str = expr_to_compact(lhs);
            let rhs_str = expr_to_compact(rhs);
            body.push(CompactStatement::Assert {
                expr: format!("{} == {}", lhs_str, rhs_str),
                label: label.clone(),
            });
        }
        zir::Constraint::Boolean { signal, label } => {
            body.push(CompactStatement::Assert {
                expr: format!("{} * (1 - {}) == 0", signal, signal),
                label: label.clone(),
            });
        }
        zir::Constraint::Range {
            signal,
            bits,
            label,
        } => {
            body.push(CompactStatement::Assert {
                expr: format!("assert_range({}, {})", signal, bits),
                label: label.clone(),
            });
        }
        zir::Constraint::Lookup {
            inputs: lk_inputs,
            table,
            label,
        } => {
            let args: Vec<String> = lk_inputs.iter().map(expr_to_compact).collect();
            body.push(CompactStatement::Assert {
                expr: format!("lookup({}, [{}])", table, args.join(", ")),
                label: label.clone(),
            });
        }
        zir::Constraint::CustomGate {
            gate,
            inputs: gate_inputs,
            outputs: gate_outputs,
            label,
            ..
        } => {
            let args: Vec<String> = gate_inputs.iter().map(expr_to_compact).collect();
            body.push(CompactStatement::Assert {
                expr: format!(
                    "custom_gate({}, [{}], [{}])",
                    gate,
                    args.join(", "),
                    gate_outputs.join(", ")
                ),
                label: label.clone(),
            });
        }
        zir::Constraint::MemoryRead {
            memory,
            index,
            value,
            label,
        } => {
            body.push(CompactStatement::Assert {
                expr: format!(
                    "mem_read({}, {}, {})",
                    memory,
                    expr_to_compact(index),
                    expr_to_compact(value)
                ),
                label: label.clone(),
            });
        }
        zir::Constraint::MemoryWrite {
            memory,
            index,
            value,
            label,
        } => {
            body.push(CompactStatement::Assert {
                expr: format!(
                    "mem_write({}, {}, {})",
                    memory,
                    expr_to_compact(index),
                    expr_to_compact(value)
                ),
                label: label.clone(),
            });
        }
        zir::Constraint::BlackBox {
            op,
            inputs: bb_inputs,
            outputs: bb_outputs,
            label,
            ..
        } => {
            let args: Vec<String> = bb_inputs.iter().map(expr_to_compact).collect();
            let compact_fn = blackbox_to_compact_fn(*op);
            body.push(CompactStatement::Assert {
                expr: format!(
                    "{}([{}]) -> [{}]",
                    compact_fn,
                    args.join(", "),
                    bb_outputs.join(", ")
                ),
                label: label.clone(),
            });
        }
        zir::Constraint::Permutation { left, right, label } => {
            body.push(CompactStatement::Assert {
                expr: format!("permutation({}, {})", left, right),
                label: label.clone(),
            });
        }
        zir::Constraint::Copy { from, to, label } => {
            body.push(CompactStatement::Assert {
                expr: format!("{} == {}", from, to),
                label: label.clone(),
            });
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

/// Convert a ZIR expression to Compact expression syntax.
fn expr_to_compact(expr: &zir::Expr) -> String {
    match expr {
        zir::Expr::Const(c) => c.to_decimal_string(),
        zir::Expr::Signal(name) => name.clone(),
        zir::Expr::Add(values) => {
            let parts: Vec<String> = values.iter().map(expr_to_compact).collect();
            parts.join(" + ")
        }
        zir::Expr::Sub(l, r) => format!("({} - {})", expr_to_compact(l), expr_to_compact(r)),
        zir::Expr::Mul(l, r) => format!("({} * {})", expr_to_compact(l), expr_to_compact(r)),
        zir::Expr::Div(l, r) => format!("({} / {})", expr_to_compact(l), expr_to_compact(r)),
    }
}

/// Generate the full Compact source text from the structured IR.
fn generate_compact_source(
    name: &str,
    block: &CompactCircuitBlock,
    witnesses: &[CompactWitnessDecl],
    ledger_decls: &[CompactStatement],
    _type_map: &BTreeMap<String, CompactType>,
) -> String {
    let mut src = String::new();

    // Header comment.
    src.push_str(&format!("// Generated Compact program: {}\n\n", name));

    // Ledger declarations (top-level, outside circuit).
    if !ledger_decls.is_empty() {
        for decl in ledger_decls {
            if let CompactStatement::LedgerDecl {
                name: decl_name,
                compact_type,
            } = decl
            {
                src.push_str(&format!(
                    "ledger {}: {};\n",
                    decl_name,
                    compact_type.to_compact_string()
                ));
            }
        }
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

    // Input parameters (non-state private signals and constants).
    let non_state_inputs: Vec<&CompactSignal> =
        block.inputs.iter().filter(|s| !s.is_state).collect();
    let input_params: Vec<String> = non_state_inputs
        .iter()
        .map(|s| format!("{}: {}", s.name, s.compact_type.to_compact_string()))
        .collect();
    src.push_str(&input_params.join(", "));
    src.push_str(") -> (");

    // Output parameters (public non-state signals).
    let non_state_outputs: Vec<&CompactSignal> =
        block.outputs.iter().filter(|s| !s.is_state).collect();
    let output_params: Vec<String> = non_state_outputs
        .iter()
        .map(|s| format!("{}: {}", s.name, s.compact_type.to_compact_string()))
        .collect();
    src.push_str(&output_params.join(", "));
    src.push_str(") {\n");

    // Circuit body: constraint statements.
    for stmt in &block.body {
        match stmt {
            CompactStatement::Let {
                name: var_name,
                ty,
                expr,
            } => {
                src.push_str(&format!(
                    "  let {}: {} = {};\n",
                    var_name,
                    ty.to_compact_string(),
                    expr
                ));
            }
            CompactStatement::Assert { expr, label } => {
                if let Some(l) = label {
                    src.push_str(&format!("  assert {}; // {}\n", expr, l));
                } else {
                    src.push_str(&format!("  assert {};\n", expr));
                }
            }
            CompactStatement::Return { values } => {
                src.push_str(&format!("  return ({});\n", values.join(", ")));
            }
            // ExportCircuit, WitnessBlock, LedgerDecl are structural and
            // rendered at top-level, not inside the circuit body.
            CompactStatement::ExportCircuit { .. }
            | CompactStatement::WitnessBlock { .. }
            | CompactStatement::LedgerDecl { .. } => {}
        }
    }

    src.push_str("}\n");
    src
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::FieldId;

    #[test]
    fn generates_export_circuit_syntax() {
        let program = zir::Program {
            name: "age_check".to_string(),
            field: FieldId::Bn254,
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
            metadata: BTreeMap::new(),
        };

        let lowered = MidnightLowering.lower(&program).unwrap();
        assert_eq!(lowered.contract_name, "age_check");

        // Should use `export circuit` instead of bare `circuit`.
        assert!(lowered.compact_source.contains("export circuit age_check("));

        // Witnesses block for private signals.
        assert!(lowered.compact_source.contains("witnesses {"));
        assert!(lowered.compact_source.contains("birth_year: Bytes<2>"));

        // Output parameter in circuit signature.
        assert!(lowered.compact_source.contains("is_adult: Boolean"));

        // Compact constraint syntax: boolean check.
        assert!(
            lowered
                .compact_source
                .contains("is_adult * (1 - is_adult) == 0")
        );

        // Compact constraint syntax: range check.
        assert!(
            lowered
                .compact_source
                .contains("assert_range(birth_year, 16)")
        );

        // Type map should have Bytes<2> for 16-bit uint.
        assert_eq!(
            lowered.type_map.get("birth_year"),
            Some(&CompactType::Bytes(2))
        );
        assert_eq!(
            lowered.type_map.get("is_adult"),
            Some(&CompactType::Boolean)
        );
    }

    #[test]
    fn generates_ledger_declarations() {
        let program = zir::Program {
            name: "stateful".to_string(),
            field: FieldId::Bn254,
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
            metadata: BTreeMap::new(),
        };

        let lowered = MidnightLowering.lower(&program).unwrap();
        assert!(lowered.state_schema.is_some());
        assert_eq!(lowered.state_schema.unwrap().fields.len(), 1);

        // Should have ledger declaration.
        assert!(
            lowered
                .compact_source
                .contains("ledger state_counter: Field;")
        );
    }

    #[test]
    fn maps_array_to_vector_type() {
        let program = zir::Program {
            name: "vector_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "values".to_string(),
                visibility: zkf_core::Visibility::Public,
                ty: zir::SignalType::Array {
                    element: Box::new(zir::SignalType::Field),
                    len: 4,
                },
                constant: None,
            }],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = MidnightLowering.lower(&program).unwrap();
        assert_eq!(
            lowered.type_map.get("values"),
            Some(&CompactType::Vector(Box::new(CompactType::Field), 4))
        );
        assert!(lowered.compact_source.contains("values: Vector<Field, 4>"));
    }

    #[test]
    fn maps_uint8_to_bytes1() {
        let program = zir::Program {
            name: "byte_test".to_string(),
            field: FieldId::Bn254,
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
            metadata: BTreeMap::new(),
        };

        let lowered = MidnightLowering.lower(&program).unwrap();
        assert_eq!(lowered.type_map.get("data"), Some(&CompactType::Bytes(1)));
        assert!(lowered.compact_source.contains("data: Bytes<1>"));
    }

    #[test]
    fn maps_uint32_to_bytes4() {
        let program = zir::Program {
            name: "u32_test".to_string(),
            field: FieldId::Bn254,
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
            metadata: BTreeMap::new(),
        };

        let lowered = MidnightLowering.lower(&program).unwrap();
        assert_eq!(lowered.type_map.get("amount"), Some(&CompactType::Bytes(4)));
        assert!(lowered.compact_source.contains("amount: Bytes<4>"));
    }

    #[test]
    fn handles_blackbox_constraints() {
        let program = zir::Program {
            name: "hash_test".to_string(),
            field: FieldId::Bn254,
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
                params: BTreeMap::new(),
                label: Some("hash_check".to_string()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = MidnightLowering.lower(&program).unwrap();
        assert!(
            lowered
                .compact_source
                .contains("poseidon_hash([preimage]) -> [digest]")
        );
    }

    #[test]
    fn compact_type_string_representations() {
        assert_eq!(CompactType::Field.to_compact_string(), "Field");
        assert_eq!(CompactType::Boolean.to_compact_string(), "Boolean");
        assert_eq!(CompactType::Bytes(32).to_compact_string(), "Bytes<32>");
        assert_eq!(CompactType::Uint(16).to_compact_string(), "Bytes<2>");
        assert_eq!(
            CompactType::Vector(Box::new(CompactType::Field), 8).to_compact_string(),
            "Vector<Field, 8>"
        );
    }
}
