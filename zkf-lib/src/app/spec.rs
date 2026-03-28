use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zkf_core::zir;
use zkf_core::{
    BlackBoxOp, Expr, FieldElement, FieldId, Program, Visibility, WitnessInputs, ZkfError,
    ZkfResult, program_v2_to_zir,
};

use super::builder::ProgramBuilder;
use super::templates::TemplateProgram;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSpecProgramV1 {
    pub name: String,
    pub field: FieldId,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSpecSignalV1 {
    pub name: String,
    pub visibility: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant: Option<FieldElement>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSpecLookupTableV1 {
    pub name: String,
    pub columns: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<Vec<FieldElement>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSpecMemoryRegionV1 {
    pub name: String,
    pub size: u32,
    pub read_only: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSpecCustomGateV1 {
    pub name: String,
    pub input_count: usize,
    pub output_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_expr: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TemplateArgSpecV1 {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TemplateRegistryEntryV1 {
    pub id: String,
    pub description: String,
    pub release_ready: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub template_args: Vec<TemplateArgSpecV1>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BuilderOpV1 {
    Assign {
        target: String,
        expr: Expr,
    },
    Hint {
        target: String,
        source: String,
    },
    Equal {
        lhs: Expr,
        rhs: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Boolean {
        signal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Range {
        signal: String,
        bits: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Lookup {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        table: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    BlackBox {
        op: BlackBoxOp,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outputs: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        params: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Gadget {
        gadget: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outputs: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        params: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    CustomGate {
        gate: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outputs: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        params: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    MemoryRead {
        memory: String,
        index: Expr,
        value: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    MemoryWrite {
        memory: String,
        index: Expr,
        value: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Copy {
        from: String,
        to: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Permutation {
        left: String,
        right: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Leq {
        slack: String,
        lhs: Expr,
        rhs: Expr,
        bits: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Geq {
        slack: String,
        lhs: Expr,
        rhs: Expr,
        bits: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Nonzero {
        signal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Select {
        target: String,
        selector: String,
        when_true: Expr,
        when_false: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppSpecV1 {
    pub program: AppSpecProgramV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<AppSpecSignalV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ops: Vec<BuilderOpV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookup_tables: Vec<AppSpecLookupTableV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_regions: Vec<AppSpecMemoryRegionV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_gates: Vec<AppSpecCustomGateV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sample_inputs: WitnessInputs,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub violation_inputs: WitnessInputs,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_outputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub template_args: BTreeMap<String, String>,
}

fn string_refs(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

fn from_zir_expr(expr: &zir::Expr) -> Expr {
    match expr {
        zir::Expr::Const(value) => Expr::Const(value.clone()),
        zir::Expr::Signal(name) => Expr::Signal(name.clone()),
        zir::Expr::Add(values) => Expr::Add(values.iter().map(from_zir_expr).collect()),
        zir::Expr::Sub(left, right) => Expr::Sub(
            Box::new(from_zir_expr(left)),
            Box::new(from_zir_expr(right)),
        ),
        zir::Expr::Mul(left, right) => Expr::Mul(
            Box::new(from_zir_expr(left)),
            Box::new(from_zir_expr(right)),
        ),
        zir::Expr::Div(left, right) => Expr::Div(
            Box::new(from_zir_expr(left)),
            Box::new(from_zir_expr(right)),
        ),
    }
}

fn map_zir_blackbox_op(op: zir::BlackBoxOp) -> BlackBoxOp {
    match op {
        zir::BlackBoxOp::Poseidon => BlackBoxOp::Poseidon,
        zir::BlackBoxOp::Sha256 => BlackBoxOp::Sha256,
        zir::BlackBoxOp::Keccak256 => BlackBoxOp::Keccak256,
        zir::BlackBoxOp::Pedersen => BlackBoxOp::Pedersen,
        zir::BlackBoxOp::EcdsaSecp256k1 => BlackBoxOp::EcdsaSecp256k1,
        zir::BlackBoxOp::EcdsaSecp256r1 => BlackBoxOp::EcdsaSecp256r1,
        zir::BlackBoxOp::SchnorrVerify => BlackBoxOp::SchnorrVerify,
        zir::BlackBoxOp::Blake2s => BlackBoxOp::Blake2s,
        zir::BlackBoxOp::RecursiveAggregationMarker => BlackBoxOp::RecursiveAggregationMarker,
        zir::BlackBoxOp::ScalarMulG1 => BlackBoxOp::ScalarMulG1,
        zir::BlackBoxOp::PointAddG1 => BlackBoxOp::PointAddG1,
        zir::BlackBoxOp::PairingCheck => BlackBoxOp::PairingCheck,
    }
}

fn instantiate_from_template(
    id: &str,
    template_args: &BTreeMap<String, String>,
    template: TemplateProgram,
) -> AppSpecV1 {
    let zir_program = program_v2_to_zir(&template.program);
    let signals = zir_program
        .signals
        .iter()
        .map(|signal| AppSpecSignalV1 {
            name: signal.name.clone(),
            visibility: signal.visibility.clone(),
            constant: signal.constant.clone(),
        })
        .collect::<Vec<_>>();
    let mut ops = Vec::new();
    ops.extend(
        zir_program
            .witness_plan
            .assignments
            .iter()
            .map(|assignment| BuilderOpV1::Assign {
                target: assignment.target.clone(),
                expr: from_zir_expr(&assignment.expr),
            }),
    );
    ops.extend(
        zir_program
            .witness_plan
            .hints
            .iter()
            .map(|hint| BuilderOpV1::Hint {
                target: hint.target.clone(),
                source: hint.source.clone(),
            }),
    );
    ops.extend(
        zir_program
            .constraints
            .iter()
            .map(|constraint| match constraint {
                zir::Constraint::Equal { lhs, rhs, label } => BuilderOpV1::Equal {
                    lhs: from_zir_expr(lhs),
                    rhs: from_zir_expr(rhs),
                    label: label.clone(),
                },
                zir::Constraint::Boolean { signal, label } => BuilderOpV1::Boolean {
                    signal: signal.clone(),
                    label: label.clone(),
                },
                zir::Constraint::Range {
                    signal,
                    bits,
                    label,
                } => BuilderOpV1::Range {
                    signal: signal.clone(),
                    bits: *bits,
                    label: label.clone(),
                },
                zir::Constraint::Lookup {
                    inputs,
                    table,
                    label,
                } => BuilderOpV1::Lookup {
                    inputs: inputs.iter().map(from_zir_expr).collect(),
                    table: table.clone(),
                    label: label.clone(),
                },
                zir::Constraint::BlackBox {
                    op,
                    inputs,
                    outputs,
                    params,
                    label,
                } => BuilderOpV1::BlackBox {
                    op: map_zir_blackbox_op(*op),
                    inputs: inputs.iter().map(from_zir_expr).collect(),
                    outputs: outputs.clone(),
                    params: params.clone(),
                    label: label.clone(),
                },
                zir::Constraint::CustomGate {
                    gate,
                    inputs,
                    outputs,
                    params,
                    label,
                } => BuilderOpV1::CustomGate {
                    gate: gate.clone(),
                    inputs: inputs.iter().map(from_zir_expr).collect(),
                    outputs: outputs.clone(),
                    params: params.clone(),
                    label: label.clone(),
                },
                zir::Constraint::MemoryRead {
                    memory,
                    index,
                    value,
                    label,
                } => BuilderOpV1::MemoryRead {
                    memory: memory.clone(),
                    index: from_zir_expr(index),
                    value: from_zir_expr(value),
                    label: label.clone(),
                },
                zir::Constraint::MemoryWrite {
                    memory,
                    index,
                    value,
                    label,
                } => BuilderOpV1::MemoryWrite {
                    memory: memory.clone(),
                    index: from_zir_expr(index),
                    value: from_zir_expr(value),
                    label: label.clone(),
                },
                zir::Constraint::Permutation { left, right, label } => BuilderOpV1::Permutation {
                    left: left.clone(),
                    right: right.clone(),
                    label: label.clone(),
                },
                zir::Constraint::Copy { from, to, label } => BuilderOpV1::Copy {
                    from: from.clone(),
                    to: to.clone(),
                    label: label.clone(),
                },
            }),
    );

    AppSpecV1 {
        program: AppSpecProgramV1 {
            name: template.program.name,
            field: template.program.field,
        },
        signals,
        ops,
        lookup_tables: zir_program
            .lookup_tables
            .iter()
            .map(|table| AppSpecLookupTableV1 {
                name: table.name.clone(),
                columns: table.columns,
                values: table.values.clone(),
            })
            .collect(),
        memory_regions: zir_program
            .memory_regions
            .iter()
            .map(|memory| AppSpecMemoryRegionV1 {
                name: memory.name.clone(),
                size: memory.size,
                read_only: memory.read_only,
            })
            .collect(),
        custom_gates: zir_program
            .custom_gates
            .iter()
            .map(|gate| AppSpecCustomGateV1 {
                name: gate.name.clone(),
                input_count: gate.input_count,
                output_count: gate.output_count,
                constraint_expr: gate.constraint_expr.clone(),
            })
            .collect(),
        metadata: zir_program.metadata.clone(),
        sample_inputs: template.sample_inputs,
        violation_inputs: template.violation_inputs,
        expected_inputs: template.expected_inputs,
        public_outputs: template.public_outputs,
        description: Some(template.description.to_string()),
        template_id: Some(id.to_string()),
        template_args: template_args.clone(),
    }
}

fn parse_usize_arg(args: &BTreeMap<String, String>, key: &str, default: usize) -> ZkfResult<usize> {
    Ok(args
        .get(key)
        .map(|value| {
            value.parse::<usize>().map_err(|error| {
                ZkfError::InvalidArtifact(format!(
                    "template arg '{key}' must be a positive integer: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(default))
}

fn parse_u32_arg(args: &BTreeMap<String, String>, key: &str, default: u32) -> ZkfResult<u32> {
    Ok(args
        .get(key)
        .map(|value| {
            value.parse::<u32>().map_err(|error| {
                ZkfError::InvalidArtifact(format!(
                    "template arg '{key}' must be an unsigned integer: {error}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(default))
}

fn reject_unknown_args(args: &BTreeMap<String, String>, allowed: &[&str]) -> ZkfResult<()> {
    let allowed = allowed
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let unknown = args
        .keys()
        .filter(|key| !allowed.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(ZkfError::InvalidArtifact(format!(
            "unknown template args: {}",
            unknown.join(", ")
        )))
    }
}

pub fn build_app_spec(spec: &AppSpecV1) -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new(&spec.program.name, spec.program.field);
    for signal in &spec.signals {
        match signal.visibility {
            Visibility::Private => {
                if signal.constant.is_some() {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "signal '{}' cannot be private and constant in AppSpecV1",
                        signal.name
                    )));
                }
                builder.private_signal(&signal.name)?;
            }
            Visibility::Public => {
                if signal.constant.is_some() {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "signal '{}' cannot be public and constant in AppSpecV1",
                        signal.name
                    )));
                }
                builder.public_input(&signal.name)?;
            }
            Visibility::Constant => {
                let value = signal.constant.clone().ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "constant signal '{}' is missing its constant value",
                        signal.name
                    ))
                })?;
                builder.constant_signal(&signal.name, value)?;
            }
        }
    }
    for table in &spec.lookup_tables {
        builder.add_lookup_table(&table.name, table.columns, table.values.clone())?;
    }
    for memory in &spec.memory_regions {
        builder.define_memory_region(&memory.name, memory.size, memory.read_only)?;
    }
    for gate in &spec.custom_gates {
        builder.define_custom_gate(
            &gate.name,
            gate.input_count,
            gate.output_count,
            gate.constraint_expr.clone(),
        )?;
    }
    for (key, value) in &spec.metadata {
        builder.metadata_entry(key, value)?;
    }

    for op in &spec.ops {
        match op {
            BuilderOpV1::Assign { target, expr } => {
                builder.add_assignment(target, expr.clone())?;
            }
            BuilderOpV1::Hint { target, source } => {
                builder.add_hint(target, source)?;
            }
            BuilderOpV1::Equal { lhs, rhs, label } => {
                builder.constrain_equal_labeled(lhs.clone(), rhs.clone(), label.clone())?;
            }
            BuilderOpV1::Boolean { signal, label } => {
                builder.constrain_boolean_labeled(signal, label.clone())?;
            }
            BuilderOpV1::Range {
                signal,
                bits,
                label,
            } => {
                builder.constrain_range_labeled(signal, *bits, label.clone())?;
            }
            BuilderOpV1::Lookup {
                inputs,
                table,
                label,
            } => {
                builder.constrain_lookup_labeled(inputs, table, label.clone())?;
            }
            BuilderOpV1::BlackBox {
                op,
                inputs,
                outputs,
                params,
                label,
            } => {
                let outputs = string_refs(outputs);
                builder.constrain_blackbox_labeled(*op, inputs, &outputs, params, label.clone())?;
            }
            BuilderOpV1::Gadget {
                gadget,
                inputs,
                outputs,
                params,
                label,
            } => {
                let outputs = string_refs(outputs);
                builder.emit_gadget_labeled(gadget, inputs, &outputs, params, label.clone())?;
            }
            BuilderOpV1::CustomGate {
                gate,
                inputs,
                outputs,
                params,
                label,
            } => {
                let outputs = string_refs(outputs);
                builder.constrain_custom_gate_labeled(
                    gate,
                    inputs,
                    &outputs,
                    params,
                    label.clone(),
                )?;
            }
            BuilderOpV1::MemoryRead {
                memory,
                index,
                value,
                label,
            } => {
                builder.constrain_memory_read_labeled(
                    memory,
                    index.clone(),
                    value.clone(),
                    label.clone(),
                )?;
            }
            BuilderOpV1::MemoryWrite {
                memory,
                index,
                value,
                label,
            } => {
                builder.constrain_memory_write_labeled(
                    memory,
                    index.clone(),
                    value.clone(),
                    label.clone(),
                )?;
            }
            BuilderOpV1::Copy { from, to, label } => {
                builder.constrain_copy_labeled(from, to, label.clone())?;
            }
            BuilderOpV1::Permutation { left, right, label } => {
                builder.constrain_permutation_labeled(left, right, label.clone())?;
            }
            BuilderOpV1::Leq {
                slack,
                lhs,
                rhs,
                bits,
                label,
            } => {
                builder.constrain_leq_labeled(
                    slack,
                    lhs.clone(),
                    rhs.clone(),
                    *bits,
                    label.clone(),
                )?;
            }
            BuilderOpV1::Geq {
                slack,
                lhs,
                rhs,
                bits,
                label,
            } => {
                builder.constrain_geq_labeled(
                    slack,
                    lhs.clone(),
                    rhs.clone(),
                    *bits,
                    label.clone(),
                )?;
            }
            BuilderOpV1::Nonzero { signal, label } => {
                builder.constrain_nonzero_labeled(signal, label.clone())?;
            }
            BuilderOpV1::Select {
                target,
                selector,
                when_true,
                when_false,
                label,
            } => {
                builder.constrain_select_labeled(
                    target,
                    selector,
                    when_true.clone(),
                    when_false.clone(),
                    label.clone(),
                )?;
            }
        }
    }

    builder.build()
}

pub fn template_registry() -> Vec<TemplateRegistryEntryV1> {
    vec![
        TemplateRegistryEntryV1 {
            id: "poseidon-commitment".to_string(),
            description: "Compute a BN254 Poseidon commitment from secret and blinding inputs."
                .to_string(),
            release_ready: true,
            template_args: Vec::new(),
        },
        TemplateRegistryEntryV1 {
            id: "merkle-membership".to_string(),
            description:
                "Compute a Poseidon-based Merkle root from a private leaf and authentication path."
                    .to_string(),
            release_ready: true,
            template_args: vec![TemplateArgSpecV1 {
                name: "depth".to_string(),
                description: "Binary tree depth to scaffold.".to_string(),
                default_value: Some("2".to_string()),
                required: false,
            }],
        },
        TemplateRegistryEntryV1 {
            id: "range-proof".to_string(),
            description:
                "Commit to a private value and prove that it fits within the configured bit range."
                    .to_string(),
            release_ready: true,
            template_args: vec![TemplateArgSpecV1 {
                name: "bits".to_string(),
                description: "Bit width enforced by the range constraint.".to_string(),
                default_value: Some("32".to_string()),
                required: false,
            }],
        },
        TemplateRegistryEntryV1 {
            id: "private-vote".to_string(),
            description:
                "Commit to a three-candidate private vote while constraining the candidate domain."
                    .to_string(),
            release_ready: true,
            template_args: Vec::new(),
        },
        TemplateRegistryEntryV1 {
            id: "sha256-preimage".to_string(),
            description: "Prove knowledge of a SHA-256 preimage with a configurable byte length."
                .to_string(),
            release_ready: true,
            template_args: vec![TemplateArgSpecV1 {
                name: "byte_len".to_string(),
                description: "Private preimage length in bytes.".to_string(),
                default_value: Some("4".to_string()),
                required: false,
            }],
        },
        TemplateRegistryEntryV1 {
            id: "private-identity".to_string(),
            description: "Prove private-identity KYC policy compliance.".to_string(),
            release_ready: true,
            template_args: Vec::new(),
        },
        TemplateRegistryEntryV1 {
            id: "private-powered-descent".to_string(),
            description:
                "Private powered-descent guidance showcase with strict runtime-compatible outputs."
                    .to_string(),
            release_ready: true,
            template_args: vec![TemplateArgSpecV1 {
                name: "steps".to_string(),
                description: "Number of fixed descent steps.".to_string(),
                default_value: Some("8".to_string()),
                required: false,
            }],
        },
        TemplateRegistryEntryV1 {
            id: "private-satellite-conjunction".to_string(),
            description: "Private two-spacecraft conjunction-avoidance showcase.".to_string(),
            release_ready: true,
            template_args: Vec::new(),
        },
        TemplateRegistryEntryV1 {
            id: "private-multi-satellite-base32".to_string(),
            description: "Private multi-satellite conjunction showcase, base scenario.".to_string(),
            release_ready: true,
            template_args: Vec::new(),
        },
        TemplateRegistryEntryV1 {
            id: "private-multi-satellite-stress64".to_string(),
            description: "Private multi-satellite conjunction showcase, stress scenario."
                .to_string(),
            release_ready: true,
            template_args: Vec::new(),
        },
        TemplateRegistryEntryV1 {
            id: "private-nbody-orbital".to_string(),
            description: "Private orbital dynamics showcase with committed final positions."
                .to_string(),
            release_ready: true,
            template_args: vec![TemplateArgSpecV1 {
                name: "steps".to_string(),
                description: "Number of hard-coded orbital integration steps.".to_string(),
                default_value: Some("8".to_string()),
                required: false,
            }],
        },
    ]
}

pub fn instantiate_template(
    id: &str,
    template_args: &BTreeMap<String, String>,
) -> ZkfResult<AppSpecV1> {
    let template = match id {
        "poseidon-commitment" => {
            reject_unknown_args(template_args, &[])?;
            super::templates::poseidon_commitment()?
        }
        "merkle-membership" => {
            reject_unknown_args(template_args, &["depth"])?;
            super::templates::merkle_membership_with_depth(parse_usize_arg(
                template_args,
                "depth",
                2,
            )?)?
        }
        "range-proof" => {
            reject_unknown_args(template_args, &["bits"])?;
            super::templates::range_proof_with_bits(parse_u32_arg(template_args, "bits", 32)?)?
        }
        "private-vote" => {
            reject_unknown_args(template_args, &[])?;
            super::templates::private_vote_commitment_three_candidate()?
        }
        "sha256-preimage" => {
            reject_unknown_args(template_args, &["byte_len"])?;
            super::templates::sha256_preimage_with_len(parse_usize_arg(
                template_args,
                "byte_len",
                4,
            )?)?
        }
        "private-identity" => {
            reject_unknown_args(template_args, &[])?;
            super::templates::private_identity_kyc()?
        }
        "private-powered-descent" => {
            reject_unknown_args(template_args, &["steps"])?;
            super::templates::private_powered_descent_showcase_with_steps(parse_usize_arg(
                template_args,
                "steps",
                8,
            )?)?
        }
        "private-satellite-conjunction" => {
            reject_unknown_args(template_args, &[])?;
            super::templates::private_satellite_conjunction_showcase()?
        }
        "private-multi-satellite-base32" => {
            reject_unknown_args(template_args, &[])?;
            super::templates::private_multi_satellite_conjunction_showcase_base32()?
        }
        "private-multi-satellite-stress64" => {
            reject_unknown_args(template_args, &[])?;
            super::templates::private_multi_satellite_conjunction_showcase_stress64()?
        }
        "private-nbody-orbital" => {
            reject_unknown_args(template_args, &["steps"])?;
            super::templates::private_nbody_orbital_showcase_with_steps(parse_usize_arg(
                template_args,
                "steps",
                8,
            )?)?
        }
        other => {
            let supported = template_registry()
                .into_iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ZkfError::InvalidArtifact(format!(
                "unknown template '{other}'. Supported templates: {supported}"
            )));
        }
    };

    Ok(instantiate_from_template(id, template_args, template))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn template_registry_contains_release_builder_entries() {
        let registry = template_registry();
        assert!(registry.iter().any(|entry| entry.id == "private-vote"));
        assert!(registry.iter().any(|entry| entry.id == "private-identity"));
        assert!(
            registry
                .iter()
                .any(|entry| entry.id == "private-powered-descent")
        );
        assert!(registry.iter().all(|entry| entry.release_ready));
    }

    #[test]
    fn instantiated_template_roundtrips_back_to_program() {
        let spec = instantiate_template(
            "merkle-membership",
            &BTreeMap::from([("depth".to_string(), "1".to_string())]),
        )
        .expect("template spec");
        let rebuilt = build_app_spec(&spec).expect("rebuilt program");
        let direct = super::super::templates::merkle_membership_with_depth(1)
            .expect("direct template")
            .program;
        let rebuilt_zir = program_v2_to_zir(&rebuilt);
        let direct_zir = program_v2_to_zir(&direct);
        assert_eq!(rebuilt_zir.signals, direct_zir.signals);
        assert_eq!(rebuilt_zir.constraints, direct_zir.constraints);
        assert_eq!(rebuilt_zir.witness_plan, direct_zir.witness_plan);
        assert_eq!(rebuilt_zir.lookup_tables, direct_zir.lookup_tables);
    }

    #[test]
    fn relation_and_select_ops_lower_through_builder() {
        let spec = AppSpecV1 {
            program: AppSpecProgramV1 {
                name: "spec_relation_ops".to_string(),
                field: FieldId::Bn254,
            },
            signals: vec![
                AppSpecSignalV1 {
                    name: "amount".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                },
                AppSpecSignalV1 {
                    name: "limit".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                },
                AppSpecSignalV1 {
                    name: "flag".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                },
                AppSpecSignalV1 {
                    name: "selected".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                },
            ],
            ops: vec![
                BuilderOpV1::Leq {
                    slack: "gap".to_string(),
                    lhs: Expr::signal("amount"),
                    rhs: Expr::signal("limit"),
                    bits: 16,
                    label: Some("amount_within_limit".to_string()),
                },
                BuilderOpV1::Nonzero {
                    signal: "amount".to_string(),
                    label: Some("amount_nonzero".to_string()),
                },
                BuilderOpV1::Select {
                    target: "selected".to_string(),
                    selector: "flag".to_string(),
                    when_true: Expr::signal("amount"),
                    when_false: Expr::signal("limit"),
                    label: Some("selected_value".to_string()),
                },
            ],
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
            sample_inputs: BTreeMap::new(),
            violation_inputs: BTreeMap::new(),
            expected_inputs: Vec::new(),
            public_outputs: vec!["selected".to_string()],
            description: None,
            template_id: None,
            template_args: BTreeMap::new(),
        };

        let program = build_app_spec(&spec).expect("build app spec");
        assert!(
            program
                .constraints
                .iter()
                .any(|constraint| constraint.label().is_some())
        );
        assert!(program.signals.iter().any(|signal| signal.name == "gap"));
        assert!(
            program
                .signals
                .iter()
                .any(|signal| signal.name == "__builder_anchor_one")
        );
    }

    #[test]
    fn epa_fixture_deserializes_as_app_spec_and_builds_constraints() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("docs")
            .join("examples")
            .join("fixtures")
            .join("epa")
            .join("zirapp.json");
        let bytes = fs::read(&path).expect("read EPA fixture");
        let spec: AppSpecV1 =
            serde_json::from_slice(&bytes).expect("EPA fixture should parse as AppSpecV1");
        let program = build_app_spec(&spec).expect("EPA fixture should build");

        assert_eq!(program.name, "epa_water_discharge_compliance");
        assert!(
            !program.constraints.is_empty(),
            "EPA program should have constraints"
        );
    }
}
