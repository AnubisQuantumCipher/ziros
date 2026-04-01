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

//! Plonky3 AIR export specification generator for the ZKF universal framework.
//!
//! This module produces [`ZkfPlonky3AirExport`] specification structs that
//! describe how a ZKF program maps to a Plonky3 Algebraic Intermediate
//! Representation (AIR) — transition constraints, boundary constraints, and
//! trace layout. These specs can be serialized to JSON and consumed by external
//! Plonky3 tooling or used for AIR introspection.

use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use zkf_core::{Program, ToolRequirement, ZkfError, ZkfResult};

const PLONKY3_AIR_EXPORT_SCHEMA_V1: &str = "zkf-plonky3-air-export-v1";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Plonky3AirConstraintSpec {
    pub name: String,
    #[serde(default)]
    pub expression: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZkfPlonky3AirExport {
    pub schema: String,
    pub program: Program,
    #[serde(default)]
    pub trace_width: Option<u32>,
    #[serde(default)]
    pub rows: Option<u32>,
    #[serde(default)]
    pub transition_constraints: Vec<Plonky3AirConstraintSpec>,
    #[serde(default)]
    pub boundary_constraints: Vec<Plonky3AirConstraintSpec>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

pub struct Plonky3AirFrontend;

impl FrontendEngine for Plonky3AirFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Plonky3Air
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Plonky3Air,
            can_compile_to_ir: true,
            can_execute: false,
            input_formats: vec![
                "zkf-plonky3-air-export-json".to_string(),
                "zkf-plonky3-air-export-descriptor-json".to_string(),
            ],
            notes: "Plonky3 AIR frontend import accepts explicit ZkfPlonky3AirExport schema (`schema=zkf-plonky3-air-export-v1`) via embedded export object or `plonky3_air_export_path`."
                .to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let accepted = value.get("schema").is_some()
            || value.get("plonky3_air_export").is_some()
            || value.get("plonky3_air_export_path").is_some();
        FrontendProbe {
            accepted,
            format: accepted.then_some("zkf-plonky3-air-export-json".to_string()),
            noir_version: None,
            notes: if accepted {
                vec![]
            } else {
                vec![
                    "expected `schema`, `plonky3_air_export`, or `plonky3_air_export_path` for plonky3-air frontend"
                        .to_string(),
                ]
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        let mut export = parse_plonky3_air_export(value)?;
        validate_plonky3_air_export(&export)?;
        if let Some(name) = options.program_name.as_ref() {
            export.program.name = name.clone();
        }
        if let Some(field) = options.field {
            export.program.field = field;
        }
        Ok(export.program)
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let export = parse_plonky3_air_export(value)?;
        validate_plonky3_air_export(&export)?;

        let mut opcode_counts = BTreeMap::new();
        opcode_counts.insert(
            "air_transition_constraint".to_string(),
            export
                .transition_constraints
                .len()
                .max(export.program.constraints.len()),
        );
        opcode_counts.insert(
            "air_boundary_constraint".to_string(),
            export.boundary_constraints.len(),
        );

        Ok(FrontendInspection {
            frontend: FrontendKind::Plonky3Air,
            format: probe.format,
            version: Some(export.schema),
            functions: 1,
            unconstrained_functions: 0,
            opcode_counts,
            blackbox_counts: BTreeMap::new(),
            required_capabilities: vec![
                "air-trace".to_string(),
                "air-transition-constraints".to_string(),
            ],
            dropped_features: Vec::new(),
            requires_hints: !export.program.witness_plan.hints.is_empty(),
        })
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![ToolRequirement {
            tool: "cargo".to_string(),
            args: vec!["--version".to_string()],
            note: Some("Required for plonky3 AIR export generation from Rust crates".to_string()),
            required: true,
        }]
    }
}

fn parse_plonky3_air_export(value: &Value) -> ZkfResult<ZkfPlonky3AirExport> {
    if let Some(path) = value.get("plonky3_air_export_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        let content = fs::read_to_string(&path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading plonky3_air_export_path '{}': {err}",
                path.display()
            ))
        })?;
        return serde_json::from_str::<ZkfPlonky3AirExport>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize plonky3 AIR export from '{}': {err}",
                path.display()
            ))
        });
    }

    if let Some(export_value) = value.get("plonky3_air_export") {
        return serde_json::from_value::<ZkfPlonky3AirExport>(export_value.clone()).map_err(
            |err| {
                ZkfError::InvalidArtifact(format!(
                    "failed to deserialize embedded `plonky3_air_export`: {err}"
                ))
            },
        );
    }

    serde_json::from_value::<ZkfPlonky3AirExport>(value.clone()).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "plonky3-air frontend expects ZkfPlonky3AirExport JSON or descriptor: {err}"
        ))
    })
}

// ---------------------------------------------------------------------------
// AIR constraint generation types and implementation
// ---------------------------------------------------------------------------

/// A set of AIR constraints derived from a ZKF program.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AirConstraintSet {
    pub transition_constraints: Vec<Plonky3AirConstraintSpec>,
    pub boundary_constraints: Vec<Plonky3AirConstraintSpec>,
    pub trace_width: u32,
    pub num_public_inputs: usize,
}

/// A trace specification describing column layout for a Plonky3 AIR.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceSpec {
    pub width: u32,
    pub column_names: Vec<String>,
    pub public_column_indices: Vec<usize>,
}

impl ZkfPlonky3AirExport {
    /// Serialize this export to a `serde_json::Value`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Generate AIR constraint specifications from ZKF constraints.
    pub fn to_air_constraints(&self) -> ZkfResult<AirConstraintSet> {
        if self.program.signals.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot generate AIR constraints: program has no signals".to_string(),
            ));
        }

        let mut transition_constraints = Vec::new();
        let mut boundary_constraints = Vec::new();

        for (idx, constraint) in self.program.constraints.iter().enumerate() {
            match constraint {
                zkf_core::Constraint::Equal { lhs, rhs, label } => {
                    let name = label.clone().unwrap_or_else(|| format!("eq_{idx}"));
                    let expr = format!(
                        "({}) - ({})",
                        air_expr_to_string(lhs),
                        air_expr_to_string(rhs)
                    );
                    transition_constraints.push(Plonky3AirConstraintSpec {
                        name,
                        expression: expr,
                    });
                }
                zkf_core::Constraint::Boolean { signal, label } => {
                    let name = label.clone().unwrap_or_else(|| format!("bool_{idx}"));
                    transition_constraints.push(Plonky3AirConstraintSpec {
                        name,
                        expression: format!("{signal} * (1 - {signal})"),
                    });
                }
                zkf_core::Constraint::Range {
                    signal,
                    bits,
                    label,
                } => {
                    let name = label.clone().unwrap_or_else(|| format!("range_{idx}"));
                    // Emit a bit-decomposition constraint expression.
                    transition_constraints.push(Plonky3AirConstraintSpec {
                        name,
                        expression: format!("bit_decomposition({signal}, {bits})"),
                    });
                }
                zkf_core::Constraint::BlackBox { op, label, .. } => {
                    let name = label
                        .clone()
                        .unwrap_or_else(|| format!("blackbox_{}_{idx}", op.as_str()));
                    transition_constraints.push(Plonky3AirConstraintSpec {
                        name,
                        expression: format!("custom({})", op.as_str()),
                    });
                }
                zkf_core::Constraint::Lookup { .. } => { /* Lookup constraints not exportable; must be lowered first */
                }
            }
        }

        // Public signals become boundary constraints (pinned at row 0).
        for (col_idx, signal) in self.program.signals.iter().enumerate() {
            if signal.visibility == zkf_core::Visibility::Public {
                boundary_constraints.push(Plonky3AirConstraintSpec {
                    name: format!("public_input_{}", signal.name),
                    expression: format!("col[{col_idx}] - public_input({})", signal.name),
                });
            }
        }

        let trace_width = self.program.signals.len() as u32;
        let num_public_inputs = self
            .program
            .signals
            .iter()
            .filter(|s| s.visibility == zkf_core::Visibility::Public)
            .count();

        Ok(AirConstraintSet {
            transition_constraints,
            boundary_constraints,
            trace_width,
            num_public_inputs,
        })
    }

    /// Generate a trace specification from ZKF signals.
    pub fn generate_trace_spec(&self) -> ZkfResult<TraceSpec> {
        if self.program.signals.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot generate trace spec: program has no signals".to_string(),
            ));
        }

        let column_names: Vec<String> = self
            .program
            .signals
            .iter()
            .map(|s| s.name.clone())
            .collect();

        let public_column_indices: Vec<usize> = self
            .program
            .signals
            .iter()
            .enumerate()
            .filter_map(|(i, s)| (s.visibility == zkf_core::Visibility::Public).then_some(i))
            .collect();

        Ok(TraceSpec {
            width: column_names.len() as u32,
            column_names,
            public_column_indices,
        })
    }
}

/// Render a ZKF `Expr` as a string for AIR constraint expressions.
fn air_expr_to_string(expr: &zkf_core::Expr) -> String {
    use zkf_core::Expr;
    match expr {
        Expr::Const(fe) => format!("{fe}"),
        Expr::Signal(name) => name.clone(),
        Expr::Add(terms) => {
            if terms.is_empty() {
                "0".to_string()
            } else {
                let parts: Vec<String> = terms.iter().map(air_expr_to_string).collect();
                parts.join(" + ")
            }
        }
        Expr::Sub(a, b) => format!("({} - {})", air_expr_to_string(a), air_expr_to_string(b)),
        Expr::Mul(a, b) => format!("({} * {})", air_expr_to_string(a), air_expr_to_string(b)),
        Expr::Div(a, b) => format!("({} / {})", air_expr_to_string(a), air_expr_to_string(b)),
    }
}

fn validate_plonky3_air_export(export: &ZkfPlonky3AirExport) -> ZkfResult<()> {
    if export.schema != PLONKY3_AIR_EXPORT_SCHEMA_V1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported plonky3 AIR export schema '{}', expected '{}'",
            export.schema, PLONKY3_AIR_EXPORT_SCHEMA_V1
        )));
    }
    if export.program.signals.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "plonky3 AIR export `program.signals` must not be empty".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{Constraint, Expr, Signal, Visibility, WitnessPlan};

    fn make_test_export() -> ZkfPlonky3AirExport {
        ZkfPlonky3AirExport {
            schema: PLONKY3_AIR_EXPORT_SCHEMA_V1.to_string(),
            program: Program {
                name: "test_air".to_string(),
                field: Default::default(),
                signals: vec![
                    Signal {
                        name: "a".to_string(),
                        visibility: Visibility::Public,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "b".to_string(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "c".to_string(),
                        visibility: Visibility::Public,
                        constant: None,
                        ty: None,
                    },
                ],
                constraints: vec![
                    Constraint::Equal {
                        lhs: Expr::Signal("a".to_string()),
                        rhs: Expr::Signal("b".to_string()),
                        label: Some("eq_ab".to_string()),
                    },
                    Constraint::Boolean {
                        signal: "b".to_string(),
                        label: None,
                    },
                    Constraint::Range {
                        signal: "c".to_string(),
                        bits: 16,
                        label: Some("range_c".to_string()),
                    },
                ],
                witness_plan: WitnessPlan::default(),
                lookup_tables: vec![],
                metadata: BTreeMap::new(),
            },
            trace_width: None,
            rows: None,
            transition_constraints: vec![],
            boundary_constraints: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_to_air_constraints_transition() {
        let export = make_test_export();
        let air = export.to_air_constraints().unwrap();

        assert_eq!(air.trace_width, 3);
        assert_eq!(air.num_public_inputs, 2); // a and c are public

        // 3 program constraints -> 3 transition constraints
        assert_eq!(air.transition_constraints.len(), 3);
        assert_eq!(air.transition_constraints[0].name, "eq_ab");
        assert!(air.transition_constraints[0].expression.contains(" - "));
        assert!(air.transition_constraints[1].expression.contains("* (1 - "));
        assert!(
            air.transition_constraints[2]
                .expression
                .contains("bit_decomposition")
        );
    }

    #[test]
    fn test_to_air_constraints_boundary() {
        let export = make_test_export();
        let air = export.to_air_constraints().unwrap();

        // 2 public signals -> 2 boundary constraints
        assert_eq!(air.boundary_constraints.len(), 2);
        assert_eq!(air.boundary_constraints[0].name, "public_input_a");
        assert!(air.boundary_constraints[0].expression.contains("col[0]"));
        assert_eq!(air.boundary_constraints[1].name, "public_input_c");
        assert!(air.boundary_constraints[1].expression.contains("col[2]"));
    }

    #[test]
    fn test_generate_trace_spec() {
        let export = make_test_export();
        let spec = export.generate_trace_spec().unwrap();

        assert_eq!(spec.width, 3);
        assert_eq!(spec.column_names, vec!["a", "b", "c"]);
        assert_eq!(spec.public_column_indices, vec![0, 2]);
    }

    #[test]
    fn test_to_air_constraints_empty_signals_error() {
        let mut export = make_test_export();
        export.program.signals.clear();
        assert!(export.to_air_constraints().is_err());
    }

    #[test]
    fn test_generate_trace_spec_empty_signals_error() {
        let mut export = make_test_export();
        export.program.signals.clear();
        assert!(export.generate_trace_spec().is_err());
    }

    #[test]
    fn test_air_expr_to_string() {
        let e = Expr::Sub(
            Box::new(Expr::Signal("x".to_string())),
            Box::new(Expr::Signal("y".to_string())),
        );
        assert_eq!(air_expr_to_string(&e), "(x - y)");
    }
}
