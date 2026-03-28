use std::collections::{BTreeMap, BTreeSet, HashMap};

use zkf_core::ir::{BlackBoxOp, Expr, Program, Visibility};
use zkf_core::zir;
use zkf_core::{FieldElement, FieldId, ZkfError, ZkfResult, program_zir_to_v2};
use zkf_gadgets::{
    Gadget, GadgetRegistry, GadgetSpec, all_gadget_specs, gadget_spec,
    validate_builtin_field_support,
};

fn expr_to_zir(expr: &Expr) -> zir::Expr {
    match expr {
        Expr::Const(value) => zir::Expr::Const(value.clone()),
        Expr::Signal(name) => zir::Expr::Signal(name.clone()),
        Expr::Add(values) => zir::Expr::Add(values.iter().map(expr_to_zir).collect()),
        Expr::Sub(left, right) => {
            zir::Expr::Sub(Box::new(expr_to_zir(left)), Box::new(expr_to_zir(right)))
        }
        Expr::Mul(left, right) => {
            zir::Expr::Mul(Box::new(expr_to_zir(left)), Box::new(expr_to_zir(right)))
        }
        Expr::Div(left, right) => {
            zir::Expr::Div(Box::new(expr_to_zir(left)), Box::new(expr_to_zir(right)))
        }
    }
}

fn field_type() -> zir::SignalType {
    zir::SignalType::Field
}

fn collect_expr_signal_refs(expr: &zir::Expr, refs: &mut Vec<String>) {
    match expr {
        zir::Expr::Const(_) => {}
        zir::Expr::Signal(name) => refs.push(name.clone()),
        zir::Expr::Add(values) => {
            for value in values {
                collect_expr_signal_refs(value, refs);
            }
        }
        zir::Expr::Sub(left, right) | zir::Expr::Mul(left, right) | zir::Expr::Div(left, right) => {
            collect_expr_signal_refs(left, refs);
            collect_expr_signal_refs(right, refs);
        }
    }
}

fn validate_expr_signal_refs(
    expr: &zir::Expr,
    declared_signals: &BTreeSet<String>,
    errors: &mut Vec<String>,
    context: &str,
) {
    let mut refs = Vec::new();
    collect_expr_signal_refs(expr, &mut refs);
    for signal in refs {
        if !declared_signals.contains(&signal) {
            errors.push(format!("{context} references undeclared signal '{signal}'"));
        }
    }
}

fn validate_blackbox_surface(
    field: FieldId,
    op: BlackBoxOp,
    inputs_len: usize,
    outputs_len: usize,
) -> ZkfResult<()> {
    match op {
        BlackBoxOp::Poseidon => {
            if field != FieldId::Bn254 || inputs_len != 4 || outputs_len != 4 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "blackbox '{}' requires field=bn254 with 4 inputs and 4 outputs; got field={}, inputs={}, outputs={}",
                    op.as_str(),
                    field,
                    inputs_len,
                    outputs_len
                )));
            }
        }
        BlackBoxOp::Sha256 => {
            if outputs_len != 32 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "blackbox '{}' requires exactly 32 outputs, got {}",
                    op.as_str(),
                    outputs_len
                )));
            }
        }
        BlackBoxOp::Pedersen
        | BlackBoxOp::EcdsaSecp256k1
        | BlackBoxOp::EcdsaSecp256r1
        | BlackBoxOp::SchnorrVerify => {
            if field != FieldId::Bn254 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "blackbox '{}' only supports field=bn254, got {}",
                    op.as_str(),
                    field
                )));
            }
        }
        _ => {}
    }

    Ok(())
}

fn rewrite_zir_expr(expr: &zir::Expr, signal_names: &BTreeMap<String, String>) -> zir::Expr {
    match expr {
        zir::Expr::Const(value) => zir::Expr::Const(value.clone()),
        zir::Expr::Signal(name) => zir::Expr::Signal(
            signal_names
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone()),
        ),
        zir::Expr::Add(values) => zir::Expr::Add(
            values
                .iter()
                .map(|expr| rewrite_zir_expr(expr, signal_names))
                .collect(),
        ),
        zir::Expr::Sub(left, right) => zir::Expr::Sub(
            Box::new(rewrite_zir_expr(left, signal_names)),
            Box::new(rewrite_zir_expr(right, signal_names)),
        ),
        zir::Expr::Mul(left, right) => zir::Expr::Mul(
            Box::new(rewrite_zir_expr(left, signal_names)),
            Box::new(rewrite_zir_expr(right, signal_names)),
        ),
        zir::Expr::Div(left, right) => zir::Expr::Div(
            Box::new(rewrite_zir_expr(left, signal_names)),
            Box::new(rewrite_zir_expr(right, signal_names)),
        ),
    }
}

fn rewrite_optional_signal_name(name: &str, signal_names: &BTreeMap<String, String>) -> String {
    signal_names
        .get(name)
        .cloned()
        .unwrap_or_else(|| name.to_string())
}

fn rewrite_constraint(
    constraint: &zir::Constraint,
    signal_names: &BTreeMap<String, String>,
    table_names: &BTreeMap<String, String>,
) -> zir::Constraint {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, label } => zir::Constraint::Equal {
            lhs: rewrite_zir_expr(lhs, signal_names),
            rhs: rewrite_zir_expr(rhs, signal_names),
            label: label.clone(),
        },
        zir::Constraint::Boolean { signal, label } => zir::Constraint::Boolean {
            signal: rewrite_optional_signal_name(signal, signal_names),
            label: label.clone(),
        },
        zir::Constraint::Range {
            signal,
            bits,
            label,
        } => zir::Constraint::Range {
            signal: rewrite_optional_signal_name(signal, signal_names),
            bits: *bits,
            label: label.clone(),
        },
        zir::Constraint::Lookup {
            inputs,
            table,
            label,
        } => zir::Constraint::Lookup {
            inputs: inputs
                .iter()
                .map(|expr| rewrite_zir_expr(expr, signal_names))
                .collect(),
            table: table_names
                .get(table)
                .cloned()
                .unwrap_or_else(|| table.clone()),
            label: label.clone(),
        },
        zir::Constraint::CustomGate {
            gate,
            inputs,
            outputs,
            params,
            label,
        } => zir::Constraint::CustomGate {
            gate: gate.clone(),
            inputs: inputs
                .iter()
                .map(|expr| rewrite_zir_expr(expr, signal_names))
                .collect(),
            outputs: outputs
                .iter()
                .map(|output| rewrite_optional_signal_name(output, signal_names))
                .collect(),
            params: params.clone(),
            label: label.clone(),
        },
        zir::Constraint::MemoryRead {
            memory,
            index,
            value,
            label,
        } => zir::Constraint::MemoryRead {
            memory: memory.clone(),
            index: rewrite_zir_expr(index, signal_names),
            value: rewrite_zir_expr(value, signal_names),
            label: label.clone(),
        },
        zir::Constraint::MemoryWrite {
            memory,
            index,
            value,
            label,
        } => zir::Constraint::MemoryWrite {
            memory: memory.clone(),
            index: rewrite_zir_expr(index, signal_names),
            value: rewrite_zir_expr(value, signal_names),
            label: label.clone(),
        },
        zir::Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } => zir::Constraint::BlackBox {
            op: *op,
            inputs: inputs
                .iter()
                .map(|expr| rewrite_zir_expr(expr, signal_names))
                .collect(),
            outputs: outputs
                .iter()
                .map(|output| rewrite_optional_signal_name(output, signal_names))
                .collect(),
            params: params.clone(),
            label: label.clone(),
        },
        zir::Constraint::Permutation { left, right, label } => zir::Constraint::Permutation {
            left: rewrite_optional_signal_name(left, signal_names),
            right: rewrite_optional_signal_name(right, signal_names),
            label: label.clone(),
        },
        zir::Constraint::Copy { from, to, label } => zir::Constraint::Copy {
            from: rewrite_optional_signal_name(from, signal_names),
            to: rewrite_optional_signal_name(to, signal_names),
            label: label.clone(),
        },
    }
}

fn rewrite_lookup_table(
    table: &zir::LookupTable,
    table_names: &BTreeMap<String, String>,
) -> zir::LookupTable {
    zir::LookupTable {
        name: table_names
            .get(&table.name)
            .cloned()
            .unwrap_or_else(|| table.name.clone()),
        columns: table.columns,
        values: table.values.clone(),
    }
}

fn with_constraint_label(
    mut constraint: zir::Constraint,
    label: Option<String>,
) -> zir::Constraint {
    match &mut constraint {
        zir::Constraint::Equal {
            label: target_label,
            ..
        }
        | zir::Constraint::Boolean {
            label: target_label,
            ..
        }
        | zir::Constraint::Range {
            label: target_label,
            ..
        }
        | zir::Constraint::Lookup {
            label: target_label,
            ..
        }
        | zir::Constraint::CustomGate {
            label: target_label,
            ..
        }
        | zir::Constraint::MemoryRead {
            label: target_label,
            ..
        }
        | zir::Constraint::MemoryWrite {
            label: target_label,
            ..
        }
        | zir::Constraint::BlackBox {
            label: target_label,
            ..
        }
        | zir::Constraint::Permutation {
            label: target_label,
            ..
        }
        | zir::Constraint::Copy {
            label: target_label,
            ..
        } => *target_label = label,
    }
    constraint
}

fn scoped_label(label: Option<&str>, suffix: &str) -> Option<String> {
    label.map(|label| {
        if suffix.is_empty() {
            label.to_string()
        } else {
            format!("{label}:{suffix}")
        }
    })
}

fn map_blackbox_op(op: BlackBoxOp) -> zir::BlackBoxOp {
    match op {
        BlackBoxOp::Poseidon => zir::BlackBoxOp::Poseidon,
        BlackBoxOp::Sha256 => zir::BlackBoxOp::Sha256,
        BlackBoxOp::Keccak256 => zir::BlackBoxOp::Keccak256,
        BlackBoxOp::Pedersen => zir::BlackBoxOp::Pedersen,
        BlackBoxOp::EcdsaSecp256k1 => zir::BlackBoxOp::EcdsaSecp256k1,
        BlackBoxOp::EcdsaSecp256r1 => zir::BlackBoxOp::EcdsaSecp256r1,
        BlackBoxOp::SchnorrVerify => zir::BlackBoxOp::SchnorrVerify,
        BlackBoxOp::Blake2s => zir::BlackBoxOp::Blake2s,
        BlackBoxOp::RecursiveAggregationMarker => zir::BlackBoxOp::RecursiveAggregationMarker,
        BlackBoxOp::ScalarMulG1 => zir::BlackBoxOp::ScalarMulG1,
        BlackBoxOp::PointAddG1 => zir::BlackBoxOp::PointAddG1,
        BlackBoxOp::PairingCheck => zir::BlackBoxOp::PairingCheck,
    }
}

fn merge_signal_ty(existing: &mut zir::SignalType, incoming: &zir::SignalType) -> ZkfResult<()> {
    if existing == incoming {
        return Ok(());
    }
    match (&*existing, incoming) {
        (zir::SignalType::Field, other) => {
            *existing = other.clone();
            Ok(())
        }
        (_, zir::SignalType::Field) => Ok(()),
        _ => Err(ZkfError::InvalidArtifact(format!(
            "conflicting signal types: existing={existing:?}, incoming={incoming:?}"
        ))),
    }
}

fn merge_visibility(existing: Visibility, incoming: Visibility) -> ZkfResult<Visibility> {
    if existing == incoming {
        return Ok(existing);
    }
    match (existing, incoming) {
        (Visibility::Private, other) => Ok(other),
        (other, Visibility::Private) => Ok(other),
        (Visibility::Public, Visibility::Public) => Ok(Visibility::Public),
        (Visibility::Constant, Visibility::Constant) => Ok(Visibility::Constant),
        (left, right) => Err(ZkfError::InvalidArtifact(format!(
            "conflicting signal visibility for the same name: {left:?} vs {right:?}"
        ))),
    }
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right_chars.len()).collect::<Vec<_>>();

    for (i, left_char) in left.chars().enumerate() {
        let mut current = vec![i + 1];
        for (j, right_char) in right_chars.iter().enumerate() {
            let substitution_cost = usize::from(left_char != *right_char);
            current.push(
                (previous[j + 1] + 1)
                    .min(current[j] + 1)
                    .min(previous[j] + substitution_cost),
            );
        }
        previous = current;
    }

    previous[right_chars.len()]
}

fn nearby_gadget_names(gadget: &str, specs: &[GadgetSpec]) -> Vec<String> {
    let needle = gadget.to_ascii_lowercase();
    let first_char = needle.chars().next();
    let mut ranked = specs
        .iter()
        .map(|spec| {
            let candidate = spec.name.to_ascii_lowercase();
            let starts_with = usize::from(!candidate.starts_with(&needle));
            let contains =
                usize::from(!(candidate.contains(&needle) || needle.contains(&candidate)));
            let same_initial = usize::from(candidate.chars().next() != first_char);
            (
                starts_with,
                contains,
                same_initial,
                edit_distance(&needle, &candidate),
                spec.name.clone(),
            )
        })
        .collect::<Vec<_>>();
    ranked.sort();
    ranked
        .into_iter()
        .map(|(_, _, _, _, name)| name)
        .take(5)
        .collect()
}

fn format_gadget_contract(spec: &GadgetSpec) -> String {
    let supported_fields = if spec.supported_fields.is_empty() {
        "all".to_string()
    } else {
        spec.supported_fields.join(", ")
    };
    let mut parts = vec![
        format!(
            "expected inputs={}, outputs={}",
            spec.input_count, spec.output_count
        ),
        format!("supported fields=[{}]", supported_fields),
    ];
    if !spec.required_params.is_empty() {
        parts.push(format!(
            "required params=[{}]",
            spec.required_params.join(", ")
        ));
    }
    format!("Contract: {}.", parts.join("; "))
}

fn unknown_gadget_error(gadget: &str) -> ZkfError {
    let specs = all_gadget_specs();
    let similar = nearby_gadget_names(gadget, &specs);
    let available = specs
        .into_iter()
        .map(|spec| spec.name)
        .collect::<Vec<_>>()
        .join(", ");
    let mut message = format!("unknown gadget '{gadget}'");
    if !similar.is_empty() {
        message.push_str(&format!(". Similar gadgets: {}", similar.join(", ")));
    }
    message.push_str(&format!(". Available gadgets: {available}"));
    ZkfError::InvalidArtifact(message)
}

fn invalid_gadget_invocation_error(gadget: &str, spec: &GadgetSpec, error: &ZkfError) -> ZkfError {
    ZkfError::InvalidArtifact(format!(
        "invalid gadget invocation for '{gadget}': {error}. {}",
        format_gadget_contract(spec)
    ))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BooleanOp {
    And,
    Or,
    Xor,
    Not,
}

impl BooleanOp {
    fn as_param_value(self) -> &'static str {
        match self {
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
        }
    }

    fn expected_inputs(self) -> usize {
        match self {
            Self::Not => 1,
            Self::And | Self::Or | Self::Xor => 2,
        }
    }
}

/// Builder for application-authored circuits.
pub struct ProgramBuilder {
    name: String,
    field: FieldId,
    signals: Vec<zir::Signal>,
    signal_indices: HashMap<String, usize>,
    constraints: Vec<zir::Constraint>,
    assignments: Vec<zir::WitnessAssignment>,
    hints: Vec<zir::WitnessHint>,
    lookup_tables: Vec<zir::LookupTable>,
    memory_regions: Vec<zir::MemoryRegion>,
    custom_gates: Vec<zir::CustomGateDefinition>,
    metadata: BTreeMap<String, String>,
    input_aliases: BTreeMap<String, String>,
    registry: GadgetRegistry,
    gadget_invocations: usize,
    helper_invocations: usize,
}

impl ProgramBuilder {
    pub fn new(name: impl Into<String>, field: FieldId) -> Self {
        Self::with_registry(name, field, GadgetRegistry::with_builtins())
    }

    pub fn with_registry(
        name: impl Into<String>,
        field: FieldId,
        registry: GadgetRegistry,
    ) -> Self {
        Self {
            name: name.into(),
            field,
            signals: Vec::new(),
            signal_indices: HashMap::new(),
            constraints: Vec::new(),
            assignments: Vec::new(),
            hints: Vec::new(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
            input_aliases: BTreeMap::new(),
            registry,
            gadget_invocations: 0,
            helper_invocations: 0,
        }
    }

    pub fn available_gadgets(&self) -> Vec<GadgetSpec> {
        all_gadget_specs()
    }

    pub fn gadget_info(&self, name: &str) -> Option<GadgetSpec> {
        gadget_spec(name)
    }

    pub fn register_gadget(&mut self, gadget: Box<dyn Gadget>) -> &mut Self {
        self.registry.register(gadget);
        self
    }

    fn upsert_signal(&mut self, signal: zir::Signal) -> ZkfResult<&mut Self> {
        if let Some(&index) = self.signal_indices.get(&signal.name) {
            let existing = &mut self.signals[index];
            existing.visibility = merge_visibility(existing.visibility.clone(), signal.visibility)?;
            merge_signal_ty(&mut existing.ty, &signal.ty)?;
            match (&existing.constant, signal.constant) {
                (Some(left), Some(right)) if left != &right => {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "signal '{}' already has a different constant value",
                        existing.name
                    )));
                }
                (None, Some(value)) => existing.constant = Some(value),
                _ => {}
            }
            return Ok(self);
        }
        let name = signal.name.clone();
        self.signal_indices.insert(name, self.signals.len());
        self.signals.push(signal);
        Ok(self)
    }

    fn add_signal(
        &mut self,
        name: impl Into<String>,
        visibility: Visibility,
        ty: zir::SignalType,
        constant: Option<FieldElement>,
    ) -> ZkfResult<&mut Self> {
        self.upsert_signal(zir::Signal {
            name: name.into(),
            visibility,
            ty,
            constant,
        })
    }

    fn mark_signal_bool(&mut self, name: &str) -> ZkfResult<()> {
        if let Some(&index) = self.signal_indices.get(name) {
            let signal = &mut self.signals[index];
            merge_signal_ty(&mut signal.ty, &zir::SignalType::Bool)?;
            return Ok(());
        }
        Err(ZkfError::UnknownSignal {
            signal: name.to_string(),
        })
    }

    fn mark_signal_range(&mut self, name: &str, bits: u32) -> ZkfResult<()> {
        if let Some(&index) = self.signal_indices.get(name) {
            let signal = &mut self.signals[index];
            merge_signal_ty(&mut signal.ty, &zir::SignalType::UInt { bits })?;
            return Ok(());
        }
        Err(ZkfError::UnknownSignal {
            signal: name.to_string(),
        })
    }

    fn ensure_signal_known(&self, name: &str) -> ZkfResult<()> {
        if self.signal_indices.contains_key(name) {
            Ok(())
        } else {
            Err(ZkfError::UnknownSignal {
                signal: name.to_string(),
            })
        }
    }

    fn ensure_output_signal(&mut self, name: &str) -> ZkfResult<()> {
        if self.signal_indices.contains_key(name) {
            return Ok(());
        }
        self.private_signal(name)?;
        Ok(())
    }

    fn push_constraint(&mut self, constraint: zir::Constraint) -> ZkfResult<&mut Self> {
        self.constraints.push(constraint);
        Ok(self)
    }

    fn fresh_helper_signal(&mut self, prefix: &str) -> String {
        let name = format!("__builder_{prefix}_{}", self.helper_invocations);
        self.helper_invocations += 1;
        name
    }

    fn ensure_anchor_one(&mut self) -> ZkfResult<String> {
        let name = "__builder_anchor_one";
        self.constant_signal(name, FieldElement::ONE)?;
        Ok(name.to_string())
    }

    fn anchor_signal_labeled(&mut self, signal: &str, label: Option<&str>) -> ZkfResult<&mut Self> {
        self.ensure_signal_known(signal)?;
        let anchor_one = self.ensure_anchor_one()?;
        self.constrain_equal_labeled(
            Expr::Mul(
                Box::new(Expr::signal(signal)),
                Box::new(Expr::signal(anchor_one)),
            ),
            Expr::signal(signal),
            scoped_label(label, "anchor"),
        )
    }

    pub fn private_input(&mut self, name: impl Into<String>) -> ZkfResult<&mut Self> {
        self.add_signal(name, Visibility::Private, field_type(), None)
    }

    pub fn public_input(&mut self, name: impl Into<String>) -> ZkfResult<&mut Self> {
        self.add_signal(name, Visibility::Public, field_type(), None)
    }

    pub fn public_output(&mut self, name: impl Into<String>) -> ZkfResult<&mut Self> {
        self.add_signal(name, Visibility::Public, field_type(), None)
    }

    pub fn private_signal(&mut self, name: impl Into<String>) -> ZkfResult<&mut Self> {
        self.add_signal(name, Visibility::Private, field_type(), None)
    }

    pub fn constant_signal(
        &mut self,
        name: impl Into<String>,
        value: FieldElement,
    ) -> ZkfResult<&mut Self> {
        self.add_signal(name, Visibility::Constant, field_type(), Some(value))
    }

    pub fn input_alias(
        &mut self,
        alias: impl Into<String>,
        target: impl Into<String>,
    ) -> ZkfResult<&mut Self> {
        self.input_aliases.insert(alias.into(), target.into());
        Ok(self)
    }

    pub fn add_assignment(
        &mut self,
        target: impl Into<String>,
        expr: Expr,
    ) -> ZkfResult<&mut Self> {
        self.assignments.push(zir::WitnessAssignment {
            target: target.into(),
            expr: expr_to_zir(&expr),
        });
        Ok(self)
    }

    pub fn add_hint(
        &mut self,
        target: impl Into<String>,
        source: impl Into<String>,
    ) -> ZkfResult<&mut Self> {
        self.hints.push(zir::WitnessHint {
            target: target.into(),
            source: source.into(),
            kind: zir::WitnessHintKind::Copy,
        });
        Ok(self)
    }

    pub fn metadata_entry(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> ZkfResult<&mut Self> {
        self.metadata.insert(key.into(), value.into());
        Ok(self)
    }

    pub fn constrain_equal(&mut self, lhs: Expr, rhs: Expr) -> ZkfResult<&mut Self> {
        self.constrain_equal_labeled(lhs, rhs, None::<String>)
    }

    pub fn constrain_equal_labeled(
        &mut self,
        lhs: Expr,
        rhs: Expr,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        self.push_constraint(zir::Constraint::Equal {
            lhs: expr_to_zir(&lhs),
            rhs: expr_to_zir(&rhs),
            label: label.into(),
        })
    }

    pub fn constrain_boolean(&mut self, signal: impl Into<String>) -> ZkfResult<&mut Self> {
        self.constrain_boolean_labeled(signal, None::<String>)
    }

    pub fn constrain_boolean_labeled(
        &mut self,
        signal: impl Into<String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let signal = signal.into();
        self.mark_signal_bool(&signal)?;
        self.push_constraint(zir::Constraint::Boolean {
            signal,
            label: label.into(),
        })
    }

    pub fn constrain_range(
        &mut self,
        signal: impl Into<String>,
        bits: u32,
    ) -> ZkfResult<&mut Self> {
        self.constrain_range_labeled(signal, bits, None::<String>)
    }

    pub fn constrain_range_labeled(
        &mut self,
        signal: impl Into<String>,
        bits: u32,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let signal = signal.into();
        self.mark_signal_range(&signal, bits)?;
        self.push_constraint(zir::Constraint::Range {
            signal,
            bits,
            label: label.into(),
        })
    }

    pub fn bind(&mut self, target: impl Into<String>, expr: Expr) -> ZkfResult<&mut Self> {
        self.bind_labeled(target, expr, None::<String>)
    }

    pub fn bind_labeled(
        &mut self,
        target: impl Into<String>,
        expr: Expr,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let target = target.into();
        self.ensure_output_signal(&target)?;
        self.add_assignment(target.clone(), expr.clone())?;
        self.constrain_equal_labeled(Expr::signal(target), expr, label)
    }

    pub fn constrain_leq(
        &mut self,
        slack: impl Into<String>,
        lhs: Expr,
        rhs: Expr,
        bits: u32,
    ) -> ZkfResult<&mut Self> {
        self.constrain_leq_labeled(slack, lhs, rhs, bits, None::<String>)
    }

    pub fn constrain_leq_labeled(
        &mut self,
        slack: impl Into<String>,
        lhs: Expr,
        rhs: Expr,
        bits: u32,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let slack = slack.into();
        let label = label.into();
        self.private_signal(&slack)?;
        self.bind_labeled(
            &slack,
            Expr::Sub(Box::new(rhs.clone()), Box::new(lhs.clone())),
            scoped_label(label.as_deref(), "bind"),
        )?;
        self.constrain_range_labeled(&slack, bits, scoped_label(label.as_deref(), "range"))?;
        self.anchor_signal_labeled(&slack, label.as_deref())
    }

    pub fn constrain_geq(
        &mut self,
        slack: impl Into<String>,
        lhs: Expr,
        rhs: Expr,
        bits: u32,
    ) -> ZkfResult<&mut Self> {
        self.constrain_geq_labeled(slack, lhs, rhs, bits, None::<String>)
    }

    pub fn constrain_geq_labeled(
        &mut self,
        slack: impl Into<String>,
        lhs: Expr,
        rhs: Expr,
        bits: u32,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let slack = slack.into();
        let label = label.into();
        self.private_signal(&slack)?;
        self.bind_labeled(
            &slack,
            Expr::Sub(Box::new(lhs.clone()), Box::new(rhs.clone())),
            scoped_label(label.as_deref(), "bind"),
        )?;
        self.constrain_range_labeled(&slack, bits, scoped_label(label.as_deref(), "range"))?;
        self.anchor_signal_labeled(&slack, label.as_deref())
    }

    pub fn constrain_nonzero(&mut self, signal: impl Into<String>) -> ZkfResult<&mut Self> {
        self.constrain_nonzero_labeled(signal, None::<String>)
    }

    pub fn constrain_nonzero_labeled(
        &mut self,
        signal: impl Into<String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let signal = signal.into();
        let label = label.into();
        self.ensure_signal_known(&signal)?;
        let inverse = self.fresh_helper_signal(&format!("{}_nonzero_inv", signal));
        self.private_signal(&inverse)?;
        self.add_assignment(
            &inverse,
            Expr::Div(
                Box::new(Expr::constant_i64(1)),
                Box::new(Expr::signal(&signal)),
            ),
        )?;
        self.constrain_equal_labeled(
            Expr::Mul(
                Box::new(Expr::signal(&signal)),
                Box::new(Expr::signal(&inverse)),
            ),
            Expr::constant_i64(1),
            scoped_label(label.as_deref(), "product"),
        )
    }

    pub fn constrain_select(
        &mut self,
        target: impl Into<String>,
        selector: impl Into<String>,
        when_true: Expr,
        when_false: Expr,
    ) -> ZkfResult<&mut Self> {
        self.constrain_select_labeled(target, selector, when_true, when_false, None::<String>)
    }

    pub fn constrain_select_labeled(
        &mut self,
        target: impl Into<String>,
        selector: impl Into<String>,
        when_true: Expr,
        when_false: Expr,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let target = target.into();
        let selector = selector.into();
        let label = label.into();
        self.ensure_output_signal(&target)?;
        self.constrain_boolean_labeled(&selector, scoped_label(label.as_deref(), "selector"))?;
        self.bind_labeled(
            &target,
            Expr::Add(vec![
                when_false.clone(),
                Expr::Mul(
                    Box::new(Expr::signal(&selector)),
                    Box::new(Expr::Sub(Box::new(when_true), Box::new(when_false))),
                ),
            ]),
            scoped_label(label.as_deref(), "bind"),
        )
    }

    pub fn poseidon_hash(&mut self, inputs: &[Expr], outputs: &[&str]) -> ZkfResult<&mut Self> {
        if inputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "poseidon_hash helper requires at least 1 input".into(),
            ));
        }
        if outputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "poseidon_hash helper requires at least 1 output".into(),
            ));
        }

        let width = match inputs.len().max(outputs.len()) {
            0..=2 => 2,
            3..=4 => 4,
            _ => {
                return Err(ZkfError::InvalidArtifact(
                    "poseidon_hash helper supports up to 4 inputs/outputs; use emit_gadget(\"poseidon\", ...) for wider custom permutations".into(),
                ))
            }
        };

        let params = BTreeMap::from([("width".to_string(), width.to_string())]);
        self.emit_gadget("poseidon", inputs, outputs, &params)
    }

    pub fn sha256_hash(&mut self, inputs: &[Expr], outputs: &[&str]) -> ZkfResult<&mut Self> {
        if inputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "sha256_hash helper requires at least 1 input".into(),
            ));
        }
        if outputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "sha256_hash helper requires at least 1 output".into(),
            ));
        }

        self.emit_gadget("sha256", inputs, outputs, &BTreeMap::new())
    }

    pub fn boolean_op(
        &mut self,
        op: BooleanOp,
        inputs: &[Expr],
        output: &str,
    ) -> ZkfResult<&mut Self> {
        let expected_inputs = op.expected_inputs();
        if inputs.len() != expected_inputs {
            return Err(ZkfError::InvalidArtifact(format!(
                "boolean_op helper requires {} input(s) for '{}' but received {}",
                expected_inputs,
                op.as_param_value(),
                inputs.len()
            )));
        }

        let params = BTreeMap::from([("op".to_string(), op.as_param_value().to_string())]);
        self.emit_gadget("boolean", inputs, &[output], &params)
    }

    pub fn emit_gadget_labeled(
        &mut self,
        gadget: &str,
        inputs: &[Expr],
        outputs: &[&str],
        params: &BTreeMap<String, String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let label = label.into();
        let spec = self
            .gadget_info(gadget)
            .ok_or_else(|| unknown_gadget_error(gadget))?;
        validate_builtin_field_support(gadget, self.field)
            .map_err(|error| invalid_gadget_invocation_error(gadget, &spec, &error))?;
        let input_exprs = inputs.iter().map(expr_to_zir).collect::<Vec<_>>();
        let output_names = outputs
            .iter()
            .map(|output| (*output).to_string())
            .collect::<Vec<_>>();
        let emission = self
            .registry
            .get(gadget)
            .ok_or_else(|| unknown_gadget_error(gadget))?
            .emit(&input_exprs, &output_names, self.field, params)
            .map_err(|error| invalid_gadget_invocation_error(gadget, &spec, &error))?;

        let namespace = format!("__gadget_{gadget}_{}__", self.gadget_invocations);
        self.gadget_invocations += 1;

        let output_names = output_names.into_iter().collect::<BTreeSet<_>>();
        let mut signal_names = BTreeMap::new();
        for signal in &emission.signals {
            if output_names.contains(&signal.name) {
                continue;
            }
            signal_names.insert(signal.name.clone(), format!("{namespace}{}", signal.name));
        }
        let table_names = emission
            .lookup_tables
            .iter()
            .map(|table| {
                (
                    table.name.clone(),
                    format!("{namespace}lookup_{}", table.name),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for signal in emission.signals.into_iter().map(|mut signal| {
            if let Some(name) = signal_names.get(&signal.name) {
                signal.name = name.clone();
            }
            signal
        }) {
            self.upsert_signal(signal)?;
        }
        self.constraints
            .extend(
                emission
                    .constraints
                    .iter()
                    .enumerate()
                    .map(|(index, constraint)| {
                        let rewritten = rewrite_constraint(constraint, &signal_names, &table_names);
                        let emitted_label = match constraint {
                            zir::Constraint::Equal { label, .. }
                            | zir::Constraint::Boolean { label, .. }
                            | zir::Constraint::Range { label, .. }
                            | zir::Constraint::Lookup { label, .. }
                            | zir::Constraint::CustomGate { label, .. }
                            | zir::Constraint::MemoryRead { label, .. }
                            | zir::Constraint::MemoryWrite { label, .. }
                            | zir::Constraint::BlackBox { label, .. }
                            | zir::Constraint::Permutation { label, .. }
                            | zir::Constraint::Copy { label, .. } => label.clone(),
                        };
                        let decorated = label.as_deref().map(|prefix| {
                            emitted_label
                                .clone()
                                .map(|child| format!("{prefix}:{child}"))
                                .unwrap_or_else(|| format!("{prefix}:{index}"))
                        });
                        with_constraint_label(rewritten, decorated.or(emitted_label))
                    }),
            );
        self.assignments
            .extend(
                emission
                    .assignments
                    .iter()
                    .map(|assignment| zir::WitnessAssignment {
                        target: rewrite_optional_signal_name(&assignment.target, &signal_names),
                        expr: rewrite_zir_expr(&assignment.expr, &signal_names),
                    }),
            );
        self.lookup_tables.extend(
            emission
                .lookup_tables
                .iter()
                .map(|table| rewrite_lookup_table(table, &table_names)),
        );
        Ok(self)
    }

    pub fn emit_gadget(
        &mut self,
        gadget: &str,
        inputs: &[Expr],
        outputs: &[&str],
        params: &BTreeMap<String, String>,
    ) -> ZkfResult<&mut Self> {
        self.emit_gadget_labeled(gadget, inputs, outputs, params, None::<String>)
    }

    pub fn constrain_blackbox(
        &mut self,
        op: BlackBoxOp,
        inputs: &[Expr],
        outputs: &[&str],
        params: &BTreeMap<String, String>,
    ) -> ZkfResult<&mut Self> {
        self.constrain_blackbox_labeled(op, inputs, outputs, params, None::<String>)
    }

    pub fn constrain_blackbox_labeled(
        &mut self,
        op: BlackBoxOp,
        inputs: &[Expr],
        outputs: &[&str],
        params: &BTreeMap<String, String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        validate_blackbox_surface(self.field, op, inputs.len(), outputs.len())?;
        for output in outputs {
            self.ensure_output_signal(output)?;
        }
        self.push_constraint(zir::Constraint::BlackBox {
            op: map_blackbox_op(op),
            inputs: inputs.iter().map(expr_to_zir).collect(),
            outputs: outputs.iter().map(|output| (*output).to_string()).collect(),
            params: params.clone(),
            label: label.into(),
        })
    }

    pub fn add_lookup_table(
        &mut self,
        name: impl Into<String>,
        columns: usize,
        values: Vec<Vec<FieldElement>>,
    ) -> ZkfResult<&mut Self> {
        self.lookup_tables.push(zir::LookupTable {
            name: name.into(),
            columns,
            values,
        });
        Ok(self)
    }

    pub fn define_memory_region(
        &mut self,
        name: impl Into<String>,
        size: u32,
        read_only: bool,
    ) -> ZkfResult<&mut Self> {
        self.memory_regions.push(zir::MemoryRegion {
            name: name.into(),
            size,
            read_only,
        });
        Ok(self)
    }

    pub fn define_custom_gate(
        &mut self,
        name: impl Into<String>,
        input_count: usize,
        output_count: usize,
        constraint_expr: Option<String>,
    ) -> ZkfResult<&mut Self> {
        self.custom_gates.push(zir::CustomGateDefinition {
            name: name.into(),
            input_count,
            output_count,
            constraint_expr,
        });
        Ok(self)
    }

    pub fn constrain_lookup(
        &mut self,
        inputs: &[Expr],
        table: impl Into<String>,
    ) -> ZkfResult<&mut Self> {
        self.constrain_lookup_labeled(inputs, table, None::<String>)
    }

    pub fn constrain_lookup_labeled(
        &mut self,
        inputs: &[Expr],
        table: impl Into<String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        self.push_constraint(zir::Constraint::Lookup {
            inputs: inputs.iter().map(expr_to_zir).collect(),
            table: table.into(),
            label: label.into(),
        })
    }

    pub fn constrain_custom_gate(
        &mut self,
        gate: impl Into<String>,
        inputs: &[Expr],
        outputs: &[&str],
        params: &BTreeMap<String, String>,
    ) -> ZkfResult<&mut Self> {
        self.constrain_custom_gate_labeled(gate, inputs, outputs, params, None::<String>)
    }

    pub fn constrain_custom_gate_labeled(
        &mut self,
        gate: impl Into<String>,
        inputs: &[Expr],
        outputs: &[&str],
        params: &BTreeMap<String, String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        for output in outputs {
            self.ensure_output_signal(output)?;
        }
        self.push_constraint(zir::Constraint::CustomGate {
            gate: gate.into(),
            inputs: inputs.iter().map(expr_to_zir).collect(),
            outputs: outputs.iter().map(|output| (*output).to_string()).collect(),
            params: params.clone(),
            label: label.into(),
        })
    }

    pub fn constrain_memory_read(
        &mut self,
        memory: impl Into<String>,
        index: Expr,
        value: Expr,
    ) -> ZkfResult<&mut Self> {
        self.constrain_memory_read_labeled(memory, index, value, None::<String>)
    }

    pub fn constrain_memory_read_labeled(
        &mut self,
        memory: impl Into<String>,
        index: Expr,
        value: Expr,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        self.push_constraint(zir::Constraint::MemoryRead {
            memory: memory.into(),
            index: expr_to_zir(&index),
            value: expr_to_zir(&value),
            label: label.into(),
        })
    }

    pub fn constrain_memory_write(
        &mut self,
        memory: impl Into<String>,
        index: Expr,
        value: Expr,
    ) -> ZkfResult<&mut Self> {
        self.constrain_memory_write_labeled(memory, index, value, None::<String>)
    }

    pub fn constrain_memory_write_labeled(
        &mut self,
        memory: impl Into<String>,
        index: Expr,
        value: Expr,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        self.push_constraint(zir::Constraint::MemoryWrite {
            memory: memory.into(),
            index: expr_to_zir(&index),
            value: expr_to_zir(&value),
            label: label.into(),
        })
    }

    pub fn constrain_copy(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> ZkfResult<&mut Self> {
        self.constrain_copy_labeled(from, to, None::<String>)
    }

    pub fn constrain_copy_labeled(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let from = from.into();
        let to = to.into();
        self.ensure_signal_known(&from)?;
        self.ensure_signal_known(&to)?;
        self.push_constraint(zir::Constraint::Copy {
            from,
            to,
            label: label.into(),
        })
    }

    pub fn constrain_permutation(
        &mut self,
        left: impl Into<String>,
        right: impl Into<String>,
    ) -> ZkfResult<&mut Self> {
        self.constrain_permutation_labeled(left, right, None::<String>)
    }

    pub fn constrain_permutation_labeled(
        &mut self,
        left: impl Into<String>,
        right: impl Into<String>,
        label: impl Into<Option<String>>,
    ) -> ZkfResult<&mut Self> {
        let left = left.into();
        let right = right.into();
        self.ensure_signal_known(&left)?;
        self.ensure_signal_known(&right)?;
        self.push_constraint(zir::Constraint::Permutation {
            left,
            right,
            label: label.into(),
        })
    }

    pub fn build(&self) -> ZkfResult<Program> {
        let zir_program = zir::Program {
            name: self.name.clone(),
            field: self.field,
            signals: self.signals.clone(),
            constraints: self.constraints.clone(),
            witness_plan: zir::WitnessPlan {
                assignments: self.assignments.clone(),
                hints: self.hints.clone(),
                acir_program_bytes: None,
            },
            lookup_tables: self.lookup_tables.clone(),
            memory_regions: self.memory_regions.clone(),
            custom_gates: self.custom_gates.clone(),
            metadata: self.metadata.clone(),
        };

        let declared_signals = zir_program
            .signals
            .iter()
            .map(|signal| signal.name.clone())
            .collect::<BTreeSet<_>>();
        let mut validation_errors = Vec::new();

        for (alias, target) in &self.input_aliases {
            if !declared_signals.contains(target) {
                validation_errors.push(format!(
                    "input alias '{alias}' references undeclared signal '{target}'"
                ));
            }
        }

        for (index, assignment) in zir_program.witness_plan.assignments.iter().enumerate() {
            if !declared_signals.contains(&assignment.target) {
                validation_errors.push(format!(
                    "witness assignment {index} targets undeclared signal '{}'",
                    assignment.target
                ));
            }
            validate_expr_signal_refs(
                &assignment.expr,
                &declared_signals,
                &mut validation_errors,
                &format!("witness assignment {index}"),
            );
        }

        for (index, hint) in zir_program.witness_plan.hints.iter().enumerate() {
            if !declared_signals.contains(&hint.target) {
                validation_errors.push(format!(
                    "witness hint {index} targets undeclared signal '{}'",
                    hint.target
                ));
            }
            if !declared_signals.contains(&hint.source) {
                validation_errors.push(format!(
                    "witness hint {index} sources undeclared signal '{}'",
                    hint.source
                ));
            }
        }

        if let Err(type_errors) = zkf_core::type_check::type_check(&zir_program) {
            validation_errors.extend(type_errors.into_iter().map(|error| error.to_string()));
        }
        if !validation_errors.is_empty() {
            return Err(ZkfError::InvalidArtifact(format!(
                "program builder validation failed: {}",
                validation_errors.join("; ")
            )));
        }

        let mut lowered = program_zir_to_v2(&zir_program)?;
        lowered.witness_plan.input_aliases = self.input_aliases.clone();
        Ok(lowered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::Constraint;

    #[test]
    fn builder_restores_aliases_after_lowering() {
        let mut builder = ProgramBuilder::new("alias_builder", FieldId::Bn254);
        builder.private_input("x").unwrap();
        builder.public_output("y").unwrap();
        builder
            .add_assignment(
                "y",
                Expr::Add(vec![Expr::signal("x"), Expr::constant_i64(1)]),
            )
            .unwrap();
        builder
            .input_alias("external_x", "x")
            .expect("alias registration");

        let program = builder.build().expect("build");
        assert_eq!(
            program.witness_plan.input_aliases.get("external_x"),
            Some(&"x".to_string())
        );
    }

    #[test]
    fn builder_marks_boolean_and_range_types() {
        let mut builder = ProgramBuilder::new("typed", FieldId::Bn254);
        builder.private_input("flag").unwrap();
        builder.private_input("value").unwrap();
        builder.constrain_boolean("flag").unwrap();
        builder.constrain_range("value", 16).unwrap();

        let program = builder.build().expect("build");
        assert!(matches!(program.constraints[0], Constraint::Boolean { .. }));
        assert!(matches!(
            program.constraints[1],
            Constraint::Range { bits: 16, .. }
        ));
        assert_eq!(
            program
                .signals
                .iter()
                .find(|signal| signal.name == "flag")
                .and_then(|signal| signal.ty.as_deref()),
            Some("bool")
        );
        assert_eq!(
            program
                .signals
                .iter()
                .find(|signal| signal.name == "value")
                .and_then(|signal| signal.ty.as_deref()),
            Some("uint(16)")
        );
    }

    #[test]
    fn builder_emits_builtin_gadgets_and_lowers_to_ir_v2() {
        let mut builder = ProgramBuilder::new("builder_boolean", FieldId::Bn254);
        builder.private_input("a").unwrap();
        builder.public_output("out").unwrap();
        builder.constrain_boolean("a").unwrap();
        let mut params = BTreeMap::new();
        params.insert("op".to_string(), "not".to_string());
        builder
            .emit_gadget("boolean", &[Expr::signal("a")], &["out"], &params)
            .unwrap();

        let program = builder.build().expect("build");
        assert!(program.constraints.len() >= 2);
    }

    #[test]
    fn builder_exposes_registry_backed_gadget_metadata() {
        let builder = ProgramBuilder::new("metadata", FieldId::Bn254);

        let specs = builder.available_gadgets();
        let poseidon = builder.gadget_info("poseidon").expect("poseidon spec");

        assert_eq!(
            specs
                .iter()
                .map(|spec| spec.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "blake3",
                "boolean",
                "comparison",
                "ecdsa",
                "kzg",
                "merkle",
                "plonk_gate",
                "poseidon",
                "range",
                "schnorr",
                "sha256",
            ]
        );
        assert_eq!(poseidon.name, "poseidon");
        assert!(poseidon.supported_fields.contains(&"bn254".to_string()));
    }

    #[test]
    fn builder_rejects_undeclared_signal_references_at_build() {
        let mut builder = ProgramBuilder::new("undeclared", FieldId::Bn254);
        builder.private_input("x").unwrap();
        builder.private_signal("y").unwrap();
        builder
            .constrain_equal(Expr::signal("x"), Expr::signal("missing_constraint"))
            .unwrap();
        builder
            .add_assignment(
                "y",
                Expr::Add(vec![Expr::signal("x"), Expr::signal("missing_assignment")]),
            )
            .unwrap();

        let err = builder.build().expect_err("undeclared signal should fail");
        let message = err.to_string();
        assert!(message.contains("missing_constraint"));
        assert!(message.contains("missing_assignment"));
    }

    #[test]
    fn builder_rejects_unsupported_gadget_field_immediately() {
        let mut builder = ProgramBuilder::new("unsupported_poseidon", FieldId::PastaFq);

        let err = builder
            .emit_gadget(
                "poseidon",
                &[Expr::constant_i64(1)],
                &["out"],
                &BTreeMap::new(),
            )
            .err()
            .expect("unsupported field should fail");
        let message = err.to_string();
        assert!(message.contains("does not support field 'pasta-fq'"));
        assert!(message.contains("supported fields="));
    }

    #[test]
    fn builder_hints_and_metadata_round_trip() {
        let mut builder = ProgramBuilder::new("metadata_roundtrip", FieldId::Bn254);
        builder.private_input("source").unwrap();
        builder.private_signal("target").unwrap();
        builder
            .add_hint("target", "source")
            .expect("hint registration");
        builder
            .metadata_entry("owner", "builder")
            .expect("metadata entry");

        let program = builder.build().expect("build");
        assert_eq!(
            program.witness_plan.hints,
            vec![zkf_core::WitnessHint {
                target: "target".to_string(),
                source: "source".to_string(),
                kind: zkf_core::WitnessHintKind::Copy,
            }]
        );
        assert_eq!(program.metadata.get("owner"), Some(&"builder".to_string()));
    }

    #[test]
    fn typed_helpers_emit_common_gadgets() {
        let mut builder = ProgramBuilder::new("typed_helpers", FieldId::Bn254);
        builder.private_input("a").unwrap();
        builder.private_input("b").unwrap();
        builder.public_output("hash").unwrap();
        builder.public_output("sha").unwrap();
        builder.public_output("flag").unwrap();

        builder
            .poseidon_hash(&[Expr::signal("a"), Expr::signal("b")], &["hash"])
            .expect("poseidon helper");
        builder
            .sha256_hash(&[Expr::signal("a")], &["sha"])
            .expect("sha256 helper");
        builder
            .boolean_op(
                BooleanOp::Xor,
                &[Expr::signal("a"), Expr::signal("b")],
                "flag",
            )
            .expect("boolean helper");

        let program = builder.build().expect("build");
        assert!(program.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                ..
            }
        )));
        assert!(program.constraints.iter().any(|constraint| matches!(
            constraint,
            Constraint::BlackBox {
                op: BlackBoxOp::Sha256,
                ..
            }
        )));
        assert!(
            program
                .constraints
                .iter()
                .any(|constraint| matches!(constraint, Constraint::Equal { .. }))
        );
    }

    #[test]
    fn emit_gadget_errors_include_contract_details() {
        let mut builder = ProgramBuilder::new("errors", FieldId::Bn254);
        builder.private_input("a").unwrap();

        let missing_param = builder
            .emit_gadget("boolean", &[Expr::signal("a")], &["out"], &BTreeMap::new())
            .err()
            .expect("missing op param should fail");
        let missing_param_message = missing_param.to_string();
        assert!(missing_param_message.contains("required params=[op]"));
        assert!(missing_param_message.contains("expected inputs=2, outputs=1"));

        let unknown = builder
            .emit_gadget("booleann", &[Expr::signal("a")], &["out"], &BTreeMap::new())
            .err()
            .expect("unknown gadget should fail");
        let unknown_message = unknown.to_string();
        assert!(unknown_message.contains("Similar gadgets"));
        assert!(unknown_message.contains("boolean"));
    }

    #[test]
    fn builder_namespaces_internal_gadget_signals_per_invocation() {
        let mut builder = ProgramBuilder::new("builder_merkle", FieldId::Bn254);
        builder.private_input("leaf").unwrap();
        builder.private_input("sib_a").unwrap();
        builder.private_input("dir_a").unwrap();
        builder.private_input("sib_b").unwrap();
        builder.private_input("dir_b").unwrap();

        let params = BTreeMap::from([("depth".to_string(), "1".to_string())]);
        builder
            .emit_gadget(
                "merkle",
                &[
                    Expr::signal("leaf"),
                    Expr::signal("sib_a"),
                    Expr::signal("dir_a"),
                ],
                &["root_a"],
                &params,
            )
            .unwrap();
        builder
            .emit_gadget(
                "merkle",
                &[
                    Expr::signal("leaf"),
                    Expr::signal("sib_b"),
                    Expr::signal("dir_b"),
                ],
                &["root_b"],
                &params,
            )
            .unwrap();

        let program = builder.build().expect("build");
        let names = program
            .signals
            .iter()
            .map(|signal| signal.name.clone())
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(program.signals.len(), names.len());
        assert_eq!(program.signals.len(), 17);
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("__gadget_merkle_0__"))
        );
        assert!(
            names
                .iter()
                .any(|name| name.starts_with("__gadget_merkle_1__"))
        );
    }

    #[test]
    fn relation_helpers_emit_anchor_labels_and_select_outputs() {
        let mut builder = ProgramBuilder::new("builder_relations", FieldId::Bn254);
        builder.private_input("amount").unwrap();
        builder.public_input("limit").unwrap();
        builder.private_input("flag").unwrap();
        builder.public_output("selected").unwrap();

        builder
            .constrain_leq_labeled(
                "gap",
                Expr::signal("amount"),
                Expr::signal("limit"),
                16,
                Some("amount_within_limit".to_string()),
            )
            .unwrap();
        builder
            .constrain_nonzero_labeled("amount", Some("amount_nonzero".to_string()))
            .unwrap();
        builder
            .constrain_select_labeled(
                "selected",
                "flag",
                Expr::signal("amount"),
                Expr::signal("limit"),
                Some("selected_value".to_string()),
            )
            .unwrap();

        let program = builder.build().expect("build");
        let labels = program
            .constraints
            .iter()
            .filter_map(|constraint| constraint.label().cloned())
            .collect::<Vec<_>>();

        assert!(program.signals.iter().any(|signal| signal.name == "gap"));
        assert!(
            program
                .signals
                .iter()
                .any(|signal| signal.name == "__builder_anchor_one")
        );
        assert!(
            labels
                .iter()
                .any(|label| label == "amount_within_limit:anchor")
        );
        assert!(labels.iter().any(|label| label == "selected_value:bind"));
        assert!(labels.iter().any(|label| label == "amount_nonzero:product"));
    }

    #[test]
    fn unsupported_memory_and_custom_gate_surfaces_fail_honestly_at_build() {
        let mut memory_builder = ProgramBuilder::new("memory_surface", FieldId::Bn254);
        memory_builder.private_input("idx").unwrap();
        memory_builder.private_signal("value").unwrap();
        memory_builder
            .define_memory_region("mem", 8, false)
            .expect("memory region");
        memory_builder
            .constrain_memory_read("mem", Expr::signal("idx"), Expr::signal("value"))
            .expect("memory read");
        let memory_error = memory_builder
            .build()
            .expect_err("memory read should stay unsupported");
        assert!(memory_error.to_string().contains("memory"));

        let mut custom_gate_builder = ProgramBuilder::new("custom_gate_surface", FieldId::Bn254);
        custom_gate_builder.private_input("in").unwrap();
        custom_gate_builder.public_output("out").unwrap();
        custom_gate_builder
            .define_custom_gate("demo_gate", 1, 1, Some("out = in".to_string()))
            .expect("custom gate definition");
        custom_gate_builder
            .constrain_custom_gate(
                "demo_gate",
                &[Expr::signal("in")],
                &["out"],
                &BTreeMap::new(),
            )
            .expect("custom gate invocation");
        let custom_gate_error = custom_gate_builder
            .build()
            .expect_err("custom gate should stay unsupported");
        assert!(custom_gate_error.to_string().contains("custom gate"));
    }
}
