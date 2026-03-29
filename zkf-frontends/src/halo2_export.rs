//! Halo2 export specification generator for the ZKF universal framework.
//!
//! This module produces [`ZkfHalo2Export`] specification structs that describe
//! how a ZKF program maps to Halo2's plonkish constraint system (columns,
//! gates, copy constraints). These specs can be serialized to JSON and consumed
//! by external Halo2 tooling or used for circuit introspection.

use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe, FrontendProgram,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use zkf_core::{Program, ToolRequirement, ZkfError, ZkfResult, program_v2_to_zir, zir_v1};

const HALO2_EXPORT_SCHEMA_V1: &str = "zkf-halo2-export-v1";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Halo2ColumnKind {
    Advice,
    Instance,
    Fixed,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Halo2ColumnSpec {
    pub name: String,
    pub kind: Halo2ColumnKind,
    #[serde(default)]
    pub phase: Option<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Halo2GateSpec {
    pub name: String,
    #[serde(default)]
    pub selectors: Vec<String>,
    #[serde(default)]
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Halo2CopyConstraintSpec {
    pub left: String,
    pub right: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZkfHalo2Export {
    pub schema: String,
    pub program: Program,
    #[serde(default)]
    pub columns: Vec<Halo2ColumnSpec>,
    #[serde(default)]
    pub gates: Vec<Halo2GateSpec>,
    #[serde(default)]
    pub copy_constraints: Vec<Halo2CopyConstraintSpec>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

pub struct Halo2RustFrontend;

impl FrontendEngine for Halo2RustFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Halo2Rust
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Halo2Rust,
            can_compile_to_ir: true,
            can_execute: false,
            input_formats: vec![
                "zkf-halo2-export-json".to_string(),
                "zkf-halo2-export-descriptor-json".to_string(),
            ],
            notes: "Halo2 frontend import accepts explicit ZkfHalo2Export schema (`schema=zkf-halo2-export-v1`) via embedded export object or `halo2_export_path`."
                .to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let has_embedded = value.get("schema").is_some()
            || value.get("halo2_export").is_some()
            || value.get("halo2_export_path").is_some();
        FrontendProbe {
            accepted: has_embedded,
            format: has_embedded.then_some("zkf-halo2-export-json".to_string()),
            noir_version: None,
            notes: if has_embedded {
                vec![]
            } else {
                vec![
                    "expected `schema`, `halo2_export`, or `halo2_export_path` for halo2-rust frontend"
                        .to_string(),
                ]
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        let mut export = parse_halo2_export(value)?;
        validate_halo2_export(&export)?;
        if let Some(name) = options.program_name.as_ref() {
            export.program.name = name.clone();
        }
        if let Some(field) = options.field {
            export.program.field = field;
        }
        Ok(export.program)
    }

    fn compile_to_program_family(
        &self,
        value: &Value,
        options: &FrontendImportOptions,
    ) -> ZkfResult<FrontendProgram> {
        let mut export = parse_halo2_export(value)?;
        validate_halo2_export(&export)?;
        if let Some(name) = options.program_name.as_ref() {
            export.program.name = name.clone();
        }
        if let Some(field) = options.field {
            export.program.field = field;
        }

        let mut zir_program = halo2_export_to_zir(&export);
        zir_program.metadata.insert(
            "frontend".to_string(),
            FrontendKind::Halo2Rust.as_str().to_string(),
        );
        zir_program.metadata.insert(
            "source_format".to_string(),
            HALO2_EXPORT_SCHEMA_V1.to_string(),
        );

        Ok(FrontendProgram::ZirV1(zir_program))
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let export = parse_halo2_export(value)?;
        validate_halo2_export(&export)?;

        let mut opcode_counts = BTreeMap::new();
        opcode_counts.insert(
            "halo2_gate_spec".to_string(),
            export.gates.len().max(export.program.constraints.len()),
        );
        opcode_counts.insert(
            "halo2_copy_constraint".to_string(),
            export.copy_constraints.len(),
        );

        Ok(FrontendInspection {
            frontend: FrontendKind::Halo2Rust,
            format: probe.format,
            version: Some(export.schema),
            functions: 1,
            unconstrained_functions: 0,
            opcode_counts,
            blackbox_counts: BTreeMap::new(),
            required_capabilities: vec![
                "plonkish-layout".to_string(),
                "copy-constraints".to_string(),
            ],
            dropped_features: Vec::new(),
            requires_hints: !export.program.witness_plan.hints.is_empty(),
        })
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![ToolRequirement {
            tool: "cargo".to_string(),
            args: vec!["--version".to_string()],
            note: Some("Required for halo2 export generation from Rust circuits".to_string()),
            required: true,
        }]
    }
}

fn parse_halo2_export(value: &Value) -> ZkfResult<ZkfHalo2Export> {
    if let Some(path) = value.get("halo2_export_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        let content = fs::read_to_string(&path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading halo2_export_path '{}': {err}",
                path.display()
            ))
        })?;
        return serde_json::from_str::<ZkfHalo2Export>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize halo2 export from '{}': {err}",
                path.display()
            ))
        });
    }

    if let Some(export_value) = value.get("halo2_export") {
        return serde_json::from_value::<ZkfHalo2Export>(export_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize embedded `halo2_export`: {err}"
            ))
        });
    }

    serde_json::from_value::<ZkfHalo2Export>(value.clone()).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "halo2-rust frontend expects ZkfHalo2Export JSON or descriptor: {err}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Circuit synthesis types and implementation
// ---------------------------------------------------------------------------

/// A fully synthesized Halo2 circuit description produced from a ZKF program.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SynthesizedHalo2Circuit {
    pub columns: Vec<Halo2ColumnSpec>,
    pub gates: Vec<Halo2GateSpec>,
    pub copy_constraints: Vec<Halo2CopyConstraintSpec>,
    /// log2 of the number of rows needed.
    pub k: u32,
    pub num_advice: usize,
    pub num_instance: usize,
    pub num_fixed: usize,
}

impl ZkfHalo2Export {
    /// Serialize this export to a `serde_json::Value`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Synthesize this export into Halo2 column/gate specifications.
    /// Maps ZKF constraints to Halo2 gate specs and column specs.
    pub fn synthesize(&self) -> ZkfResult<SynthesizedHalo2Circuit> {
        if self.program.signals.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "cannot synthesize: program has no signals".to_string(),
            ));
        }

        let columns = self.generate_columns();
        let gates = self.generate_gates();
        let copy_constraints = self.generate_copy_constraints();

        let num_advice = columns
            .iter()
            .filter(|c| c.kind == Halo2ColumnKind::Advice)
            .count();
        let num_instance = columns
            .iter()
            .filter(|c| c.kind == Halo2ColumnKind::Instance)
            .count();
        let num_fixed = columns
            .iter()
            .filter(|c| c.kind == Halo2ColumnKind::Fixed)
            .count();

        // k = ceil(log2(max(signals.len(), constraints.len()))) + 1
        let max_dim = self
            .program
            .signals
            .len()
            .max(self.program.constraints.len())
            .max(1);
        let k = ceil_log2(max_dim) + 1;

        Ok(SynthesizedHalo2Circuit {
            columns,
            gates,
            copy_constraints,
            k,
            num_advice,
            num_instance,
            num_fixed,
        })
    }

    /// Generate column specs from program signals.
    fn generate_columns(&self) -> Vec<Halo2ColumnSpec> {
        use zkf_core::Visibility;
        self.program
            .signals
            .iter()
            .map(|sig| {
                let kind = match sig.visibility {
                    Visibility::Public => Halo2ColumnKind::Instance,
                    Visibility::Private => Halo2ColumnKind::Advice,
                    Visibility::Constant => Halo2ColumnKind::Fixed,
                };
                Halo2ColumnSpec {
                    name: sig.name.clone(),
                    kind,
                    phase: None,
                }
            })
            .collect()
    }

    /// Generate gate specs from program constraints.
    fn generate_gates(&self) -> Vec<Halo2GateSpec> {
        use zkf_core::Constraint;
        self.program
            .constraints
            .iter()
            .enumerate()
            .filter_map(|(idx, constraint)| match constraint {
                Constraint::Equal { lhs, rhs, label } => {
                    let gate_name = label.clone().unwrap_or_else(|| format!("equal_{idx}"));
                    Some(Halo2GateSpec {
                        name: gate_name.clone(),
                        selectors: vec![format!("q_{gate_name}")],
                        constraints: vec![format!(
                            "({}) - ({})",
                            expr_to_string(lhs),
                            expr_to_string(rhs)
                        )],
                    })
                }
                Constraint::Boolean { signal, label } => {
                    let gate_name = label.clone().unwrap_or_else(|| format!("bool_{idx}"));
                    Some(Halo2GateSpec {
                        name: gate_name.clone(),
                        selectors: vec![format!("q_{gate_name}")],
                        constraints: vec![format!("{signal} * (1 - {signal})")],
                    })
                }
                Constraint::Range {
                    signal,
                    bits,
                    label,
                } => {
                    let gate_name = label.clone().unwrap_or_else(|| format!("range_{idx}"));
                    Some(Halo2GateSpec {
                        name: gate_name.clone(),
                        selectors: vec![format!("q_{gate_name}")],
                        constraints: vec![format!("range_check({signal}, {bits})")],
                    })
                }
                Constraint::BlackBox { op, label, .. } => {
                    let gate_name = label
                        .clone()
                        .unwrap_or_else(|| format!("blackbox_{}_{idx}", op.as_str()));
                    Some(Halo2GateSpec {
                        name: gate_name.clone(),
                        selectors: vec![format!("q_{gate_name}")],
                        constraints: vec![format!("custom({})", op.as_str())],
                    })
                }
                Constraint::Lookup { .. } => {
                    /* Lookup constraints not exportable; must be lowered first */
                    None
                }
            })
            .collect()
    }

    /// Generate copy constraint specs from equality constraints between two signals.
    fn generate_copy_constraints(&self) -> Vec<Halo2CopyConstraintSpec> {
        use zkf_core::{Constraint, Expr};
        self.program
            .constraints
            .iter()
            .filter_map(|constraint| {
                if let Constraint::Equal {
                    lhs: Expr::Signal(left),
                    rhs: Expr::Signal(right),
                    ..
                } = constraint
                {
                    Some(Halo2CopyConstraintSpec {
                        left: left.clone(),
                        right: right.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Compute ceil(log2(n)) for n >= 1, returning at least 1.
fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        return 1;
    }
    usize::BITS - (n - 1).leading_zeros()
}

/// Render a ZKF `Expr` as a human-readable string for gate constraint expressions.
fn expr_to_string(expr: &zkf_core::Expr) -> String {
    use zkf_core::Expr;
    match expr {
        Expr::Const(fe) => format!("{fe}"),
        Expr::Signal(name) => name.clone(),
        Expr::Add(terms) => {
            if terms.is_empty() {
                "0".to_string()
            } else {
                let parts: Vec<String> = terms.iter().map(expr_to_string).collect();
                parts.join(" + ")
            }
        }
        Expr::Sub(a, b) => format!("({} - {})", expr_to_string(a), expr_to_string(b)),
        Expr::Mul(a, b) => format!("({} * {})", expr_to_string(a), expr_to_string(b)),
        Expr::Div(a, b) => format!("({} / {})", expr_to_string(a), expr_to_string(b)),
    }
}

fn validate_halo2_export(export: &ZkfHalo2Export) -> ZkfResult<()> {
    if export.schema != HALO2_EXPORT_SCHEMA_V1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported halo2 export schema '{}', expected '{}'",
            export.schema, HALO2_EXPORT_SCHEMA_V1
        )));
    }
    if export.program.signals.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "halo2 export `program.signals` must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn halo2_export_to_zir(export: &ZkfHalo2Export) -> zir_v1::Program {
    let mut program = program_v2_to_zir(&export.program);
    program
        .metadata
        .insert("ir_family".to_string(), "zir-v1".to_string());
    program
        .metadata
        .insert("source_ir".to_string(), HALO2_EXPORT_SCHEMA_V1.to_string());

    for gate in &export.gates {
        program.custom_gates.push(zir_v1::CustomGateDefinition {
            name: gate.name.clone(),
            input_count: 0,
            output_count: 0,
            constraint_expr: (!gate.constraints.is_empty()).then(|| gate.constraints.join(" && ")),
        });
    }

    for (index, copy) in export.copy_constraints.iter().enumerate() {
        program.constraints.push(zir_v1::Constraint::Copy {
            from: copy.left.clone(),
            to: copy.right.clone(),
            label: Some(format!("halo2_copy_{index}")),
        });
    }

    program
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{Constraint, Expr, Signal, Visibility, WitnessPlan};

    fn make_test_export() -> ZkfHalo2Export {
        ZkfHalo2Export {
            schema: HALO2_EXPORT_SCHEMA_V1.to_string(),
            program: Program {
                name: "test".to_string(),
                field: Default::default(),
                signals: vec![
                    Signal {
                        name: "x".to_string(),
                        visibility: Visibility::Public,
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
                        name: "one".to_string(),
                        visibility: Visibility::Constant,
                        constant: None,
                        ty: None,
                    },
                ],
                constraints: vec![
                    Constraint::Equal {
                        lhs: Expr::Signal("x".to_string()),
                        rhs: Expr::Signal("y".to_string()),
                        label: Some("eq_xy".to_string()),
                    },
                    Constraint::Boolean {
                        signal: "x".to_string(),
                        label: None,
                    },
                    Constraint::Range {
                        signal: "y".to_string(),
                        bits: 8,
                        label: Some("range_y".to_string()),
                    },
                ],
                witness_plan: WitnessPlan::default(),
                lookup_tables: vec![],
                metadata: BTreeMap::new(),
            },
            columns: vec![],
            gates: vec![],
            copy_constraints: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_synthesize_columns() {
        let export = make_test_export();
        let synth = export.synthesize().unwrap();

        assert_eq!(synth.num_instance, 1); // x is Public
        assert_eq!(synth.num_advice, 1); // y is Private
        assert_eq!(synth.num_fixed, 1); // one is Constant
        assert_eq!(synth.columns.len(), 3);

        assert_eq!(synth.columns[0].name, "x");
        assert_eq!(synth.columns[0].kind, Halo2ColumnKind::Instance);
        assert_eq!(synth.columns[1].name, "y");
        assert_eq!(synth.columns[1].kind, Halo2ColumnKind::Advice);
        assert_eq!(synth.columns[2].name, "one");
        assert_eq!(synth.columns[2].kind, Halo2ColumnKind::Fixed);
    }

    #[test]
    fn test_synthesize_gates() {
        let export = make_test_export();
        let synth = export.synthesize().unwrap();

        assert_eq!(synth.gates.len(), 3);
        // Equal gate
        assert_eq!(synth.gates[0].name, "eq_xy");
        assert!(synth.gates[0].constraints[0].contains(" - "));
        // Boolean gate
        assert!(synth.gates[1].constraints[0].contains("* (1 - "));
        // Range gate
        assert_eq!(synth.gates[2].name, "range_y");
        assert!(synth.gates[2].constraints[0].contains("range_check"));
    }

    #[test]
    fn test_synthesize_copy_constraints() {
        let export = make_test_export();
        let synth = export.synthesize().unwrap();

        // The Equal constraint between two signals produces a copy constraint
        assert_eq!(synth.copy_constraints.len(), 1);
        assert_eq!(synth.copy_constraints[0].left, "x");
        assert_eq!(synth.copy_constraints[0].right, "y");
    }

    #[test]
    fn test_synthesize_k() {
        let export = make_test_export();
        let synth = export.synthesize().unwrap();

        // max(3 signals, 3 constraints) = 3, ceil_log2(3) = 2, k = 2 + 1 = 3
        assert_eq!(synth.k, 3);
    }

    #[test]
    fn test_synthesize_empty_signals_error() {
        let mut export = make_test_export();
        export.program.signals.clear();
        assert!(export.synthesize().is_err());
    }

    #[test]
    fn test_ceil_log2() {
        assert_eq!(ceil_log2(1), 1);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(8), 3);
        assert_eq!(ceil_log2(9), 4);
    }

    #[test]
    fn test_expr_to_string() {
        let e = Expr::Signal("a".to_string());
        assert_eq!(expr_to_string(&e), "a");

        let e = Expr::Mul(
            Box::new(Expr::Signal("a".to_string())),
            Box::new(Expr::Signal("b".to_string())),
        );
        assert_eq!(expr_to_string(&e), "(a * b)");

        let e = Expr::Add(vec![
            Expr::Signal("a".to_string()),
            Expr::Signal("b".to_string()),
        ]);
        assert_eq!(expr_to_string(&e), "a + b");
    }

    #[test]
    fn compile_to_program_family_preserves_copy_constraints_in_zir() {
        let mut export = make_test_export();
        export.copy_constraints.push(Halo2CopyConstraintSpec {
            left: "x".to_string(),
            right: "y".to_string(),
        });
        let value = serde_json::to_value(export).expect("halo2 export json");
        let compiled = Halo2RustFrontend
            .compile_to_program_family(&value, &FrontendImportOptions::default())
            .expect("frontend program");

        let FrontendProgram::ZirV1(program) = compiled else {
            panic!("halo2 frontend should emit zir-v1 program family");
        };
        assert!(program.constraints.iter().any(|constraint| {
            matches!(
                constraint,
                zir_v1::Constraint::Copy { from, to, .. } if from == "x" && to == "y"
            )
        }));
    }
}
