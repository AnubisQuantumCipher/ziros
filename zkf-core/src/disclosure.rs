use crate::debugger::{WitnessFlowGraph, build_witness_flow};
use crate::{BlackBoxOp, Constraint, Expr, Program, Visibility, ZkfError, ZkfResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const DISCLOSURE_SCHEMA_VERSION: &str = "zkf-midnight-disclosure-v1";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureClassification {
    DisclosedPublic,
    CommitmentPublicHash,
    PrivateOnly,
    Uncertain,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureSidecarStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_info_path: Option<String>,
    pub contract_info_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_types_path: Option<String>,
    pub contract_types_present: bool,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureSurface {
    pub name: String,
    pub visibility: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ty: Option<String>,
    pub classification: DisclosureClassification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_index: Option<usize>,
    pub tracked_in_transcript: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_signals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constant_dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commitment_ops: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_guards: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_consumers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureFinding {
    pub severity: DisclosureSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    pub message: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureSummary {
    pub total_public_signals: usize,
    pub disclosed_public: usize,
    pub commitment_public_hash: usize,
    pub private_only: usize,
    pub uncertain: usize,
    pub warnings: usize,
    pub errors: usize,
    pub overall_status: DisclosureStatus,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisclosureReport {
    pub schema: &'static str,
    pub program_name: String,
    pub program_digest: String,
    pub frontend: String,
    pub circuit_name: String,
    pub public_transcript_order: Vec<String>,
    pub sidecars: DisclosureSidecarStatus,
    pub summary: DisclosureSummary,
    pub public_signals: Vec<DisclosureSurface>,
    pub private_signals: Vec<DisclosureSurface>,
    pub findings: Vec<DisclosureFinding>,
    pub witness_flow: WitnessFlowGraph,
}

#[derive(Debug, Clone)]
struct BlackBoxBinding {
    op: BlackBoxOp,
    inputs: Vec<Expr>,
}

#[derive(Debug, Clone, Default)]
struct DependencySummary {
    leaves: BTreeSet<String>,
    private_leaves: BTreeSet<String>,
    public_leaves: BTreeSet<String>,
    constant_leaves: BTreeSet<String>,
    commitment_ops: BTreeSet<String>,
    conditional_guards: BTreeSet<String>,
}

impl DependencySummary {
    fn merge(&mut self, other: Self) {
        self.leaves.extend(other.leaves);
        self.private_leaves.extend(other.private_leaves);
        self.public_leaves.extend(other.public_leaves);
        self.constant_leaves.extend(other.constant_leaves);
        self.commitment_ops.extend(other.commitment_ops);
        self.conditional_guards.extend(other.conditional_guards);
    }
}

struct DisclosureContext<'a> {
    program: &'a Program,
    assignments: BTreeMap<String, Expr>,
    hints: BTreeMap<String, String>,
    blackbox_outputs: BTreeMap<String, BlackBoxBinding>,
    cache: BTreeMap<String, DependencySummary>,
}

pub fn analyze_midnight_disclosure(program: &Program) -> ZkfResult<DisclosureReport> {
    let frontend = program
        .metadata
        .get("frontend")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    if frontend != "compact" {
        return Err(ZkfError::InvalidArtifact(format!(
            "midnight disclosure requires a Compact-imported program; frontend metadata is '{}'",
            frontend
        )));
    }

    let public_transcript_order = parse_public_transcript(program)?;
    let transcript_positions = public_transcript_order
        .iter()
        .enumerate()
        .map(|(index, name)| (name.clone(), index))
        .collect::<BTreeMap<_, _>>();

    let mut context = DisclosureContext {
        program,
        assignments: program
            .witness_plan
            .assignments
            .iter()
            .map(|assignment| (assignment.target.clone(), assignment.expr.clone()))
            .collect(),
        hints: program
            .witness_plan
            .hints
            .iter()
            .map(|hint| (hint.target.clone(), hint.source.clone()))
            .collect(),
        blackbox_outputs: collect_blackbox_outputs(program),
        cache: BTreeMap::new(),
    };

    let mut findings = Vec::new();
    let mut public_signals = Vec::new();
    let mut consumers_by_private_signal = BTreeMap::<String, BTreeSet<String>>::new();

    for signal in &program.signals {
        if signal.visibility != Visibility::Public {
            continue;
        }

        let tracked_in_transcript = transcript_positions.contains_key(&signal.name);
        let dependency = analyze_signal_dependencies(&signal.name, &mut context, &mut BTreeSet::new());

        let classification = if !dependency.commitment_ops.is_empty() && !dependency.private_leaves.is_empty() {
            DisclosureClassification::CommitmentPublicHash
        } else if !tracked_in_transcript || !dependency.conditional_guards.is_empty() {
            DisclosureClassification::Uncertain
        } else {
            DisclosureClassification::DisclosedPublic
        };

        if !tracked_in_transcript {
            let (message, remediation) = if dependency.private_leaves.is_empty() {
                (
                    format!(
                        "public signal '{}' is not listed in the Compact public transcript metadata",
                        signal.name
                    ),
                    "Regenerate the Compact import and ensure every intended public output is recorded in `compact_public_transcript_json`.".to_string(),
                )
            } else {
                (
                    format!(
                        "public signal '{}' depends on private inputs but is not listed in the Compact public transcript metadata",
                        signal.name
                    ),
                    "Route the output through an explicit `disclose()` boundary or keep it private; fail closed on untracked public exposure.".to_string(),
                )
            };
            findings.push(DisclosureFinding {
                severity: DisclosureSeverity::Error,
                signal: Some(signal.name.clone()),
                message,
                remediation,
            });
        }

        if !dependency.conditional_guards.is_empty() {
            findings.push(DisclosureFinding {
                severity: DisclosureSeverity::Warning,
                signal: Some(signal.name.clone()),
                message: format!(
                    "public signal '{}' depends on conditional guard(s): {}",
                    signal.name,
                    dependency
                        .conditional_guards
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                remediation: "Review the guard-driven disclosure path and confirm the branch choice is intended to become observable.".to_string(),
            });
        }

        for private_signal in &dependency.private_leaves {
            consumers_by_private_signal
                .entry(private_signal.clone())
                .or_default()
                .insert(signal.name.clone());
        }

        public_signals.push(DisclosureSurface {
            name: signal.name.clone(),
            visibility: signal.visibility.clone(),
            ty: signal.ty.clone(),
            classification,
            transcript_index: transcript_positions.get(&signal.name).copied(),
            tracked_in_transcript,
            source_signals: dependency.leaves.iter().cloned().collect(),
            private_dependencies: dependency.private_leaves.iter().cloned().collect(),
            public_dependencies: dependency.public_leaves.iter().cloned().collect(),
            constant_dependencies: dependency.constant_leaves.iter().cloned().collect(),
            commitment_ops: dependency.commitment_ops.iter().cloned().collect(),
            conditional_guards: dependency.conditional_guards.iter().cloned().collect(),
            public_consumers: Vec::new(),
            note: note_for_public_signal(&signal.name, tracked_in_transcript, &dependency),
        });
    }

    for transcript_signal in &public_transcript_order {
        if !public_signals.iter().any(|signal| &signal.name == transcript_signal) {
            findings.push(DisclosureFinding {
                severity: DisclosureSeverity::Error,
                signal: Some(transcript_signal.clone()),
                message: format!(
                    "Compact transcript metadata references '{}' but no public signal with that name exists in the imported program",
                    transcript_signal
                ),
                remediation: "Re-import the Compact contract and confirm the sidecar metadata matches the generated public signal list.".to_string(),
            });
        }
    }

    let private_signals = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == Visibility::Private)
        .map(|signal| DisclosureSurface {
            name: signal.name.clone(),
            visibility: signal.visibility.clone(),
            ty: signal.ty.clone(),
            classification: DisclosureClassification::PrivateOnly,
            transcript_index: None,
            tracked_in_transcript: false,
            source_signals: Vec::new(),
            private_dependencies: Vec::new(),
            public_dependencies: Vec::new(),
            constant_dependencies: Vec::new(),
            commitment_ops: Vec::new(),
            conditional_guards: Vec::new(),
            public_consumers: consumers_by_private_signal
                .remove(&signal.name)
                .unwrap_or_default()
                .into_iter()
                .collect(),
            note: Some(
                "Private witness signal; review public consumers to understand the disclosure boundary."
                    .to_string(),
            ),
        })
        .collect::<Vec<_>>();

    let warnings = findings
        .iter()
        .filter(|finding| finding.severity == DisclosureSeverity::Warning)
        .count();
    let errors = findings
        .iter()
        .filter(|finding| finding.severity == DisclosureSeverity::Error)
        .count();
    let overall_status = if errors > 0 {
        DisclosureStatus::Fail
    } else if warnings > 0 {
        DisclosureStatus::Warn
    } else {
        DisclosureStatus::Pass
    };
    let summary = DisclosureSummary {
        total_public_signals: public_signals.len(),
        disclosed_public: public_signals
            .iter()
            .filter(|signal| signal.classification == DisclosureClassification::DisclosedPublic)
            .count(),
        commitment_public_hash: public_signals
            .iter()
            .filter(|signal| {
                signal.classification == DisclosureClassification::CommitmentPublicHash
            })
            .count(),
        private_only: private_signals.len(),
        uncertain: public_signals
            .iter()
            .filter(|signal| signal.classification == DisclosureClassification::Uncertain)
            .count(),
        warnings,
        errors,
        overall_status,
    };

    Ok(DisclosureReport {
        schema: DISCLOSURE_SCHEMA_VERSION,
        program_name: program.name.clone(),
        program_digest: program.digest_hex(),
        frontend,
        circuit_name: program
            .metadata
            .get("compact_circuit_name")
            .cloned()
            .unwrap_or_else(|| program.name.clone()),
        public_transcript_order,
        sidecars: DisclosureSidecarStatus {
            contract_info_path: program.metadata.get("compact_contract_info_path").cloned(),
            contract_info_present: program
                .metadata
                .get("compact_contract_info_path")
                .is_some_and(|path| Path::new(path).exists()),
            contract_types_path: program.metadata.get("compact_contract_types_path").cloned(),
            contract_types_present: program
                .metadata
                .get("compact_contract_types_path")
                .is_some_and(|path| Path::new(path).exists()),
        },
        summary,
        public_signals,
        private_signals,
        findings,
        witness_flow: build_witness_flow(program),
    })
}

fn parse_public_transcript(program: &Program) -> ZkfResult<Vec<String>> {
    let raw = program
        .metadata
        .get("compact_public_transcript_json")
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "Compact program metadata is missing `compact_public_transcript_json`".to_string(),
            )
        })?;
    serde_json::from_str(raw).map_err(|error| {
        ZkfError::InvalidArtifact(format!(
            "failed to parse `compact_public_transcript_json`: {error}"
        ))
    })
}

fn collect_blackbox_outputs(program: &Program) -> BTreeMap<String, BlackBoxBinding> {
    let mut outputs = BTreeMap::new();
    for constraint in &program.constraints {
        if let Constraint::BlackBox { op, inputs, outputs: signals, .. } = constraint {
            for signal in signals {
                outputs.insert(
                    signal.clone(),
                    BlackBoxBinding {
                        op: *op,
                        inputs: inputs.clone(),
                    },
                );
            }
        }
    }
    outputs
}

fn analyze_signal_dependencies(
    signal: &str,
    context: &mut DisclosureContext<'_>,
    visiting: &mut BTreeSet<String>,
) -> DependencySummary {
    if let Some(cached) = context.cache.get(signal) {
        return cached.clone();
    }

    if !visiting.insert(signal.to_string()) {
        return leaf_dependency(signal, context.program.signal(signal).map(|entry| &entry.visibility));
    }

    let summary = if let Some(binding) = context.blackbox_outputs.get(signal).cloned() {
        let mut summary = DependencySummary::default();
        if is_commitment_blackbox(binding.op) {
            summary
                .commitment_ops
                .insert(binding.op.as_str().to_string());
        }
        for expr in binding.inputs {
            summary.merge(analyze_expr_dependencies(&expr, context, visiting));
        }
        summary
    } else if let Some(expr) = context.assignments.get(signal).cloned() {
        analyze_expr_dependencies(&expr, context, visiting)
    } else if let Some(source) = context.hints.get(signal).cloned() {
        analyze_signal_dependencies(&source, context, visiting)
    } else {
        leaf_dependency(signal, context.program.signal(signal).map(|entry| &entry.visibility))
    };

    visiting.remove(signal);
    context.cache.insert(signal.to_string(), summary.clone());
    summary
}

fn analyze_expr_dependencies(
    expr: &Expr,
    context: &mut DisclosureContext<'_>,
    visiting: &mut BTreeSet<String>,
) -> DependencySummary {
    let mut summary = DependencySummary::default();
    collect_conditional_guards(expr, &mut summary.conditional_guards);
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => summary.merge(analyze_signal_dependencies(name, context, visiting)),
        Expr::Add(values) => {
            for value in values {
                summary.merge(analyze_expr_dependencies(value, context, visiting));
            }
        }
        Expr::Sub(left, right) | Expr::Mul(left, right) | Expr::Div(left, right) => {
            summary.merge(analyze_expr_dependencies(left, context, visiting));
            summary.merge(analyze_expr_dependencies(right, context, visiting));
        }
    }
    summary
}

fn leaf_dependency(signal: &str, visibility: Option<&Visibility>) -> DependencySummary {
    let mut summary = DependencySummary::default();
    summary.leaves.insert(signal.to_string());
    match visibility.unwrap_or(&Visibility::Private) {
        Visibility::Public => {
            summary.public_leaves.insert(signal.to_string());
        }
        Visibility::Private => {
            summary.private_leaves.insert(signal.to_string());
        }
        Visibility::Constant => {
            summary.constant_leaves.insert(signal.to_string());
        }
    }
    summary
}

fn note_for_public_signal(
    signal: &str,
    tracked_in_transcript: bool,
    dependency: &DependencySummary,
) -> Option<String> {
    if !tracked_in_transcript {
        return Some(format!(
            "Public signal '{}' is not tracked in Compact transcript metadata and should be reviewed as a leak.",
            signal
        ));
    }
    if !dependency.commitment_ops.is_empty() && !dependency.private_leaves.is_empty() {
        return Some(format!(
            "Commitment-backed public output over private dependencies via {}.",
            dependency
                .commitment_ops
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !dependency.conditional_guards.is_empty() {
        return Some(
            "Intentional disclosure path depends on private conditional structure; manual review required."
                .to_string(),
        );
    }
    if dependency.private_leaves.is_empty() {
        return Some(
            "Public output depends only on public or constant values and is fully visible by design."
                .to_string(),
        );
    }
    Some(
        "Intentional Compact disclosure boundary: private data becomes public through the tracked transcript."
            .to_string(),
    )
}

fn is_commitment_blackbox(op: BlackBoxOp) -> bool {
    matches!(
        op,
        BlackBoxOp::Poseidon
            | BlackBoxOp::Pedersen
            | BlackBoxOp::Sha256
            | BlackBoxOp::Keccak256
            | BlackBoxOp::Blake2s
    )
}

fn collect_conditional_guards(expr: &Expr, guards: &mut BTreeSet<String>) {
    if let Some(guard) = conditional_guard(expr) {
        guards.insert(guard);
    }
    match expr {
        Expr::Const(_) | Expr::Signal(_) => {}
        Expr::Add(values) => {
            for value in values {
                collect_conditional_guards(value, guards);
            }
        }
        Expr::Sub(left, right) | Expr::Mul(left, right) | Expr::Div(left, right) => {
            collect_conditional_guards(left, guards);
            collect_conditional_guards(right, guards);
        }
    }
}

fn conditional_guard(expr: &Expr) -> Option<String> {
    let Expr::Add(values) = expr else {
        return None;
    };
    if values.len() != 2 {
        return None;
    }

    let left_guard = guard_term(&values[0]);
    let right_guard = inverse_guard_term(&values[1]);
    if let (Some(left), Some(right)) = (left_guard, right_guard)
        && left == right
    {
        return Some(left.to_string());
    }

    let left_guard = guard_term(&values[1]);
    let right_guard = inverse_guard_term(&values[0]);
    if let (Some(left), Some(right)) = (left_guard, right_guard)
        && left == right
    {
        return Some(left.to_string());
    }

    None
}

fn guard_term(expr: &Expr) -> Option<&str> {
    let Expr::Mul(left, right) = expr else {
        return None;
    };
    match (left.as_ref(), right.as_ref()) {
        (Expr::Signal(guard), _) | (_, Expr::Signal(guard)) => Some(guard.as_str()),
        _ => None,
    }
}

fn inverse_guard_term(expr: &Expr) -> Option<&str> {
    let Expr::Mul(left, right) = expr else {
        return None;
    };
    one_minus_guard(left.as_ref()).or_else(|| one_minus_guard(right.as_ref()))
}

fn one_minus_guard(expr: &Expr) -> Option<&str> {
    let Expr::Sub(left, right) = expr else {
        return None;
    };
    if !matches!(left.as_ref(), Expr::Const(value) if value.is_one()) {
        return None;
    }
    match right.as_ref() {
        Expr::Signal(guard) => Some(guard.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldElement, FieldId, Signal, WitnessAssignment, WitnessPlan};

    fn compact_program(public_transcript: &[&str]) -> Program {
        let mut program = Program {
            name: "compact_fixture".to_string(),
            field: FieldId::Bls12_381,
            ..Default::default()
        };
        program
            .metadata
            .insert("frontend".to_string(), "compact".to_string());
        program.metadata.insert(
            "compact_public_transcript_json".to_string(),
            serde_json::to_string(
                &public_transcript
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        program
            .metadata
            .insert("compact_circuit_name".to_string(), "fixture".to_string());
        program
    }

    #[test]
    fn safe_disclose_contract_passes() {
        let mut program = compact_program(&["disclosed"]);
        program.signals = vec![
            Signal {
                name: "secret".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
            Signal {
                name: "disclosed".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
        ];
        program.witness_plan = WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "disclosed".to_string(),
                expr: Expr::Signal("secret".to_string()),
            }],
            ..Default::default()
        };

        let report = analyze_midnight_disclosure(&program).expect("disclosure report");
        assert_eq!(report.summary.overall_status, DisclosureStatus::Pass);
        assert_eq!(
            report.public_signals[0].classification,
            DisclosureClassification::DisclosedPublic
        );
        assert!(report.findings.is_empty());
    }

    #[test]
    fn direct_public_leak_fails() {
        let mut program = compact_program(&[]);
        program.signals = vec![
            Signal {
                name: "private_balance".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
            Signal {
                name: "leak".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
        ];
        program.witness_plan.assignments.push(WitnessAssignment {
            target: "leak".to_string(),
            expr: Expr::Signal("private_balance".to_string()),
        });

        let report = analyze_midnight_disclosure(&program).expect("disclosure report");
        assert_eq!(report.summary.overall_status, DisclosureStatus::Fail);
        assert_eq!(
            report.public_signals[0].classification,
            DisclosureClassification::Uncertain
        );
        assert_eq!(report.summary.errors, 1);
    }

    #[test]
    fn conditional_mixed_flow_warns() {
        let mut program = compact_program(&["decision"]);
        program.signals = vec![
            Signal {
                name: "flag".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Bool".to_string()),
            },
            Signal {
                name: "left".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
            Signal {
                name: "right".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
            Signal {
                name: "selected".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
            Signal {
                name: "decision".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
        ];
        program.witness_plan.assignments = vec![
            WitnessAssignment {
                target: "selected".to_string(),
                expr: Expr::Add(vec![
                    Expr::Mul(
                        Box::new(Expr::Signal("flag".to_string())),
                        Box::new(Expr::Signal("left".to_string())),
                    ),
                    Expr::Mul(
                        Box::new(Expr::Sub(
                            Box::new(Expr::Const(FieldElement::ONE)),
                            Box::new(Expr::Signal("flag".to_string())),
                        )),
                        Box::new(Expr::Signal("right".to_string())),
                    ),
                ]),
            },
            WitnessAssignment {
                target: "decision".to_string(),
                expr: Expr::Signal("selected".to_string()),
            },
        ];

        let report = analyze_midnight_disclosure(&program).expect("disclosure report");
        assert_eq!(report.summary.overall_status, DisclosureStatus::Warn);
        assert_eq!(report.summary.warnings, 1);
        assert_eq!(
            report.public_signals[0].classification,
            DisclosureClassification::Uncertain
        );
        assert_eq!(
            report.public_signals[0].conditional_guards,
            vec!["flag".to_string()]
        );
    }

    #[test]
    fn commitment_backed_disclosure_passes() {
        let mut program = compact_program(&["commitment"]);
        program.signals = vec![
            Signal {
                name: "secret".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: Some("Uint<64>".to_string()),
            },
            Signal {
                name: "hash_out".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "commitment".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: Some("Bytes<32>".to_string()),
            },
        ];
        program.constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: vec![Expr::Signal("secret".to_string())],
            outputs: vec!["hash_out".to_string()],
            params: BTreeMap::new(),
            label: Some("commitment_hash".to_string()),
        });
        program.witness_plan.assignments.push(WitnessAssignment {
            target: "commitment".to_string(),
            expr: Expr::Signal("hash_out".to_string()),
        });

        let report = analyze_midnight_disclosure(&program).expect("disclosure report");
        assert_eq!(report.summary.overall_status, DisclosureStatus::Pass);
        assert_eq!(
            report.public_signals[0].classification,
            DisclosureClassification::CommitmentPublicHash
        );
        assert_eq!(
            report.public_signals[0].commitment_ops,
            vec!["poseidon".to_string()]
        );
    }
}
