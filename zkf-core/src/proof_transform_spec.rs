#![allow(dead_code)]

use crate::field::FieldElement;
use crate::proof_kernel_spec::{
    self, SpecFieldValue, SpecKernelCheckError, SpecKernelConstraint, SpecKernelExpr,
    SpecKernelProgram, SpecKernelWitness, spec_field_value_zero,
};
use crate::{FieldId, ZkfError, ZkfResult};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SpecTransformVisibility {
    Public,
    Constant,
    Private,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecTransformSignal {
    pub(crate) signal_index: usize,
    pub(crate) sort_key: usize,
    pub(crate) visibility: SpecTransformVisibility,
    pub(crate) constant_value: Option<SpecFieldValue>,
    pub(crate) required: bool,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecTransformExpr {
    Const {
        value: SpecFieldValue,
        sort_key: usize,
    },
    Signal {
        signal_index: usize,
        sort_key: usize,
    },
    Add(Vec<SpecTransformExpr>),
    Sub(Box<SpecTransformExpr>, Box<SpecTransformExpr>),
    Mul(Box<SpecTransformExpr>, Box<SpecTransformExpr>),
    Div(Box<SpecTransformExpr>, Box<SpecTransformExpr>),
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum SpecTransformConstraint {
    Equal {
        lhs: SpecTransformExpr,
        rhs: SpecTransformExpr,
        label_key: usize,
    },
    Boolean {
        signal_index: usize,
        signal_sort_key: usize,
        label_key: usize,
    },
    Range {
        signal_index: usize,
        signal_sort_key: usize,
        bits: u32,
        label_key: usize,
    },
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecTransformAssignment {
    pub(crate) target_signal_index: usize,
    pub(crate) expr: SpecTransformExpr,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecTransformHint {
    pub(crate) target_signal_index: usize,
    pub(crate) source_signal_index: usize,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecTransformProgram {
    pub(crate) field: FieldId,
    pub(crate) signals: Vec<SpecTransformSignal>,
    pub(crate) constraints: Vec<SpecTransformConstraint>,
    pub(crate) assignments: Vec<SpecTransformAssignment>,
    pub(crate) hints: Vec<SpecTransformHint>,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub(crate) struct SpecNormalizationReport {
    pub(crate) algebraic_rewrites: u32,
    pub(crate) constant_folds: u32,
    pub(crate) dead_signals_removed: u32,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecNormalizationResult {
    pub(crate) program: SpecTransformProgram,
    pub(crate) report: SpecNormalizationReport,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub(crate) struct SpecOptimizeReport {
    pub(crate) folded_expr_nodes: usize,
    pub(crate) deduplicated_constraints: usize,
    pub(crate) removed_tautology_constraints: usize,
    pub(crate) removed_private_signals: usize,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SpecOptimizeResult {
    pub(crate) program: SpecTransformProgram,
    pub(crate) report: SpecOptimizeReport,
}

#[cfg_attr(hax, hax_lib::include)]
fn zero_spec_value() -> SpecFieldValue {
    spec_field_value_zero()
}

#[cfg_attr(hax, hax_lib::include)]
fn zero_spec_expr() -> SpecTransformExpr {
    SpecTransformExpr::Const {
        value: zero_spec_value(),
        sort_key: 0,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn normalize_spec_value(value: &SpecFieldValue, field: FieldId) -> SpecFieldValue {
    proof_kernel_spec::spec_field_ops::normalize(value, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn add_spec_values(lhs: &SpecFieldValue, rhs: &SpecFieldValue, field: FieldId) -> SpecFieldValue {
    proof_kernel_spec::spec_field_ops::add(lhs, rhs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn sub_spec_values(lhs: &SpecFieldValue, rhs: &SpecFieldValue, field: FieldId) -> SpecFieldValue {
    proof_kernel_spec::spec_field_ops::sub(lhs, rhs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn mul_spec_values(lhs: &SpecFieldValue, rhs: &SpecFieldValue, field: FieldId) -> SpecFieldValue {
    proof_kernel_spec::spec_field_ops::mul(lhs, rhs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn div_spec_values(
    lhs: &SpecFieldValue,
    rhs: &SpecFieldValue,
    field: FieldId,
) -> Option<SpecFieldValue> {
    proof_kernel_spec::spec_field_ops::div(lhs, rhs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn spec_values_equal(lhs: &SpecFieldValue, rhs: &SpecFieldValue, field: FieldId) -> bool {
    proof_kernel_spec::spec_field_ops::eq(lhs, rhs, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn spec_value_is_boolean(value: &SpecFieldValue, field: FieldId) -> bool {
    proof_kernel_spec::spec_field_ops::is_boolean(value, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn spec_value_fits_bits(value: &SpecFieldValue, bits: u32, field: FieldId) -> bool {
    proof_kernel_spec::spec_field_ops::fits_bits(value, bits, field)
}

#[cfg_attr(hax, hax_lib::include)]
fn spec_value_is_zero_raw(value: &SpecFieldValue) -> bool {
    proof_kernel_spec::spec_field_value_is_zero_raw(value)
}

#[cfg_attr(hax, hax_lib::include)]
fn spec_value_is_one_raw(value: &SpecFieldValue) -> bool {
    proof_kernel_spec::spec_field_value_is_one_raw(value)
}

#[cfg_attr(hax, hax_lib::include)]
fn expr_order_rank(expr: &SpecTransformExpr) -> usize {
    match expr {
        SpecTransformExpr::Add(_) => 0,
        SpecTransformExpr::Const { .. } => 1,
        SpecTransformExpr::Div(_, _) => 2,
        SpecTransformExpr::Mul(_, _) => 3,
        SpecTransformExpr::Signal { .. } => 4,
        SpecTransformExpr::Sub(_, _) => 5,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn expr_sort_key(expr: &SpecTransformExpr) -> usize {
    match expr {
        SpecTransformExpr::Const { sort_key, .. } | SpecTransformExpr::Signal { sort_key, .. } => {
            *sort_key
        }
        _ => 0,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn expr_order_lt(lhs: &SpecTransformExpr, rhs: &SpecTransformExpr) -> bool {
    let lhs_rank = expr_order_rank(lhs);
    let rhs_rank = expr_order_rank(rhs);
    if lhs_rank != rhs_rank {
        return lhs_rank < rhs_rank;
    }
    expr_sort_key(lhs) < expr_sort_key(rhs)
}

#[cfg_attr(hax, hax_lib::include)]
fn expr_order_cmp(lhs: &SpecTransformExpr, rhs: &SpecTransformExpr) -> Ordering {
    let lhs_rank = expr_order_rank(lhs);
    let rhs_rank = expr_order_rank(rhs);
    lhs_rank
        .cmp(&rhs_rank)
        .then_with(|| expr_sort_key(lhs).cmp(&expr_sort_key(rhs)))
}

#[cfg_attr(hax, hax_lib::include)]
fn constraint_order_variant(constraint: &SpecTransformConstraint) -> usize {
    match constraint {
        SpecTransformConstraint::Equal { .. } => 0,
        SpecTransformConstraint::Boolean { .. } => 1,
        SpecTransformConstraint::Range { .. } => 2,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn constraint_order_lt(lhs: &SpecTransformConstraint, rhs: &SpecTransformConstraint) -> bool {
    let lhs_variant = constraint_order_variant(lhs);
    let rhs_variant = constraint_order_variant(rhs);
    if lhs_variant != rhs_variant {
        return lhs_variant < rhs_variant;
    }

    match (lhs, rhs) {
        (
            SpecTransformConstraint::Equal {
                lhs: lhs_expr,
                rhs: lhs_rhs,
                label_key: lhs_label,
            },
            SpecTransformConstraint::Equal {
                lhs: rhs_expr,
                rhs: rhs_rhs,
                label_key: rhs_label,
            },
        ) => {
            if expr_order_lt(lhs_expr, rhs_expr) {
                return true;
            }
            if expr_order_lt(rhs_expr, lhs_expr) {
                return false;
            }
            if expr_order_lt(lhs_rhs, rhs_rhs) {
                return true;
            }
            if expr_order_lt(rhs_rhs, lhs_rhs) {
                return false;
            }
            lhs_label < rhs_label
        }
        (
            SpecTransformConstraint::Boolean {
                signal_sort_key: lhs_signal_sort_key,
                signal_index: lhs_signal_index,
                label_key: lhs_label,
            },
            SpecTransformConstraint::Boolean {
                signal_sort_key: rhs_signal_sort_key,
                signal_index: rhs_signal_index,
                label_key: rhs_label,
            },
        ) => {
            if lhs_signal_sort_key != rhs_signal_sort_key {
                return lhs_signal_sort_key < rhs_signal_sort_key;
            }
            if lhs_signal_index != rhs_signal_index {
                return lhs_signal_index < rhs_signal_index;
            }
            lhs_label < rhs_label
        }
        (
            SpecTransformConstraint::Range {
                signal_sort_key: lhs_signal_sort_key,
                signal_index: lhs_signal_index,
                bits: lhs_bits,
                label_key: lhs_label,
            },
            SpecTransformConstraint::Range {
                signal_sort_key: rhs_signal_sort_key,
                signal_index: rhs_signal_index,
                bits: rhs_bits,
                label_key: rhs_label,
            },
        ) => {
            if lhs_signal_sort_key != rhs_signal_sort_key {
                return lhs_signal_sort_key < rhs_signal_sort_key;
            }
            if lhs_signal_index != rhs_signal_index {
                return lhs_signal_index < rhs_signal_index;
            }
            if lhs_bits != rhs_bits {
                return lhs_bits < rhs_bits;
            }
            lhs_label < rhs_label
        }
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn constraint_order_cmp(lhs: &SpecTransformConstraint, rhs: &SpecTransformConstraint) -> Ordering {
    let lhs_variant = constraint_order_variant(lhs);
    let rhs_variant = constraint_order_variant(rhs);
    lhs_variant
        .cmp(&rhs_variant)
        .then_with(|| match (lhs, rhs) {
            (
                SpecTransformConstraint::Equal {
                    lhs: lhs_expr,
                    rhs: lhs_rhs,
                    label_key: lhs_label,
                },
                SpecTransformConstraint::Equal {
                    lhs: rhs_expr,
                    rhs: rhs_rhs,
                    label_key: rhs_label,
                },
            ) => expr_order_cmp(lhs_expr, rhs_expr)
                .then_with(|| expr_order_cmp(lhs_rhs, rhs_rhs))
                .then_with(|| lhs_label.cmp(rhs_label)),
            (
                SpecTransformConstraint::Boolean {
                    signal_sort_key: lhs_signal_sort_key,
                    signal_index: lhs_signal_index,
                    label_key: lhs_label,
                },
                SpecTransformConstraint::Boolean {
                    signal_sort_key: rhs_signal_sort_key,
                    signal_index: rhs_signal_index,
                    label_key: rhs_label,
                },
            ) => lhs_signal_sort_key
                .cmp(rhs_signal_sort_key)
                .then_with(|| lhs_signal_index.cmp(rhs_signal_index))
                .then_with(|| lhs_label.cmp(rhs_label)),
            (
                SpecTransformConstraint::Range {
                    signal_sort_key: lhs_signal_sort_key,
                    signal_index: lhs_signal_index,
                    bits: lhs_bits,
                    label_key: lhs_label,
                },
                SpecTransformConstraint::Range {
                    signal_sort_key: rhs_signal_sort_key,
                    signal_index: rhs_signal_index,
                    bits: rhs_bits,
                    label_key: rhs_label,
                },
            ) => lhs_signal_sort_key
                .cmp(rhs_signal_sort_key)
                .then_with(|| lhs_signal_index.cmp(rhs_signal_index))
                .then_with(|| lhs_bits.cmp(rhs_bits))
                .then_with(|| lhs_label.cmp(rhs_label)),
            _ => Ordering::Equal,
        })
}

#[cfg_attr(hax, hax_lib::include)]
fn insert_signal_sorted_from(
    signal: SpecTransformSignal,
    sorted: &[SpecTransformSignal],
    inserted: bool,
    mut result: Vec<SpecTransformSignal>,
) -> Vec<SpecTransformSignal> {
    match sorted.split_first() {
        Some((item, remaining)) => {
            let inserted = if !inserted && signal.sort_key < item.sort_key {
                result.push(signal.clone());
                true
            } else {
                inserted
            };
            result.push(item.clone());
            insert_signal_sorted_from(signal, remaining, inserted, result)
        }
        None => {
            if !inserted {
                result.push(signal);
            }
            result
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn insert_signal_sorted(
    signal: SpecTransformSignal,
    sorted: &[SpecTransformSignal],
) -> Vec<SpecTransformSignal> {
    insert_signal_sorted_from(signal, sorted, false, Vec::with_capacity(sorted.len() + 1))
}

#[cfg_attr(hax, hax_lib::include)]
fn sort_signals_by_key(signals: &[SpecTransformSignal]) -> Vec<SpecTransformSignal> {
    let mut sorted = signals.to_vec();
    sorted.sort_by(|lhs, rhs| lhs.sort_key.cmp(&rhs.sort_key));
    sorted
}

#[cfg_attr(hax, hax_lib::include)]
fn insert_constraint_sorted_from(
    constraint: SpecTransformConstraint,
    sorted: &[SpecTransformConstraint],
    inserted: bool,
    mut result: Vec<SpecTransformConstraint>,
) -> Vec<SpecTransformConstraint> {
    match sorted.split_first() {
        Some((item, remaining)) => {
            let inserted = if !inserted && constraint_order_lt(&constraint, item) {
                result.push(constraint.clone());
                true
            } else {
                inserted
            };
            result.push(item.clone());
            insert_constraint_sorted_from(constraint, remaining, inserted, result)
        }
        None => {
            if !inserted {
                result.push(constraint);
            }
            result
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn insert_constraint_sorted(
    constraint: SpecTransformConstraint,
    sorted: &[SpecTransformConstraint],
) -> Vec<SpecTransformConstraint> {
    insert_constraint_sorted_from(
        constraint,
        sorted,
        false,
        Vec::with_capacity(sorted.len() + 1),
    )
}

#[cfg_attr(hax, hax_lib::include)]
fn sort_constraints_by_key(
    constraints: &[SpecTransformConstraint],
) -> Vec<SpecTransformConstraint> {
    let mut sorted = constraints.to_vec();
    sorted.sort_by(constraint_order_cmp);
    sorted
}

#[cfg_attr(hax, hax_lib::include)]
fn signal_index_is_marked(signal_marks: &[u8], signal_index: usize) -> bool {
    signal_marks.get(signal_index).copied().unwrap_or(0) != 0
}

#[cfg_attr(hax, hax_lib::include)]
fn mark_signal_index(signal_marks: &mut [u8], signal_index: usize) {
    if signal_index < signal_marks.len() {
        signal_marks[signal_index] = 1;
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_constraint_signal_marks(
    constraints: &[SpecTransformConstraint],
    signal_marks: &mut [u8],
) {
    for constraint in constraints {
        collect_constraint_signals(constraint, signal_marks);
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_assignment_signal_marks(
    assignments: &[SpecTransformAssignment],
    signal_marks: &mut [u8],
) {
    for assignment in assignments {
        mark_signal_index(signal_marks, assignment.target_signal_index);
        collect_expr_signals(&assignment.expr, signal_marks);
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_hint_signal_marks(hints: &[SpecTransformHint], signal_marks: &mut [u8]) {
    for hint in hints {
        mark_signal_index(signal_marks, hint.target_signal_index);
        mark_signal_index(signal_marks, hint.source_signal_index);
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn referenced_signal_marks(
    program: &SpecTransformProgram,
    constraints: &[SpecTransformConstraint],
) -> Vec<u8> {
    let mut signal_marks = vec![0; program.signals.len()];
    collect_constraint_signal_marks(constraints, &mut signal_marks);
    collect_assignment_signal_marks(&program.assignments, &mut signal_marks);
    collect_hint_signal_marks(&program.hints, &mut signal_marks);
    signal_marks
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_expr_signal_slice(values: &[SpecTransformExpr], signal_marks: &mut [u8]) {
    if let Some((value, remaining)) = values.split_first() {
        collect_expr_signals(value, signal_marks);
        collect_expr_signal_slice(remaining, signal_marks);
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_expr_signals(expr: &SpecTransformExpr, signal_marks: &mut [u8]) {
    match expr {
        SpecTransformExpr::Const { .. } => {}
        SpecTransformExpr::Signal { signal_index, .. } => {
            mark_signal_index(signal_marks, *signal_index)
        }
        SpecTransformExpr::Add(values) => collect_expr_signal_slice(values, signal_marks),
        SpecTransformExpr::Sub(lhs, rhs)
        | SpecTransformExpr::Mul(lhs, rhs)
        | SpecTransformExpr::Div(lhs, rhs) => {
            collect_expr_signals(lhs, signal_marks);
            collect_expr_signals(rhs, signal_marks);
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_constraint_signals(constraint: &SpecTransformConstraint, signal_marks: &mut [u8]) {
    match constraint {
        SpecTransformConstraint::Equal { lhs, rhs, .. } => {
            collect_expr_signals(lhs, signal_marks);
            collect_expr_signals(rhs, signal_marks);
        }
        SpecTransformConstraint::Boolean { signal_index, .. }
        | SpecTransformConstraint::Range { signal_index, .. } => {
            mark_signal_index(signal_marks, *signal_index);
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn normalize_non_zero_values_from(
    values: &[SpecTransformExpr],
    report: &mut SpecNormalizationReport,
    mut non_zero: Vec<SpecTransformExpr>,
) -> Vec<SpecTransformExpr> {
    match values.split_first() {
        Some((value, remaining_values)) => {
            let normalized = normalize_transform_expr(value, report);
            match &normalized {
                SpecTransformExpr::Const { value, .. } if spec_value_is_zero_raw(value) => {
                    report.algebraic_rewrites += 1;
                }
                _ => non_zero.push(normalized),
            }
            normalize_non_zero_values_from(remaining_values, report, non_zero)
        }
        None => non_zero,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn all_const_exprs(values: &[SpecTransformExpr]) -> bool {
    match values.split_first() {
        Some((value, remaining_values)) => {
            matches!(value, SpecTransformExpr::Const { .. }) && all_const_exprs(remaining_values)
        }
        None => true,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn normalize_transform_expr(
    expr: &SpecTransformExpr,
    report: &mut SpecNormalizationReport,
) -> SpecTransformExpr {
    match expr {
        SpecTransformExpr::Const { .. } | SpecTransformExpr::Signal { .. } => expr.clone(),
        SpecTransformExpr::Add(values) => {
            let mut non_zero = normalize_non_zero_values_from(values, report, Vec::new());

            match non_zero.len() {
                0 => {
                    report.constant_folds += 1;
                    zero_spec_expr()
                }
                1 => non_zero.remove(0),
                _ => {
                    if all_const_exprs(&non_zero) {
                        report.constant_folds += 1;
                    }
                    SpecTransformExpr::Add(non_zero)
                }
            }
        }
        SpecTransformExpr::Mul(lhs, rhs) => {
            let lhs = normalize_transform_expr(lhs, report);
            let rhs = normalize_transform_expr(rhs, report);

            if matches!(
                &lhs,
                SpecTransformExpr::Const { value, .. } if spec_value_is_one_raw(value)
            ) {
                report.algebraic_rewrites += 1;
                return rhs;
            }
            if matches!(
                &rhs,
                SpecTransformExpr::Const { value, .. } if spec_value_is_one_raw(value)
            ) {
                report.algebraic_rewrites += 1;
                return lhs;
            }
            if matches!(
                &lhs,
                SpecTransformExpr::Const { value, .. } if spec_value_is_zero_raw(value)
            ) {
                report.algebraic_rewrites += 1;
                return zero_spec_expr();
            }
            if matches!(
                &rhs,
                SpecTransformExpr::Const { value, .. } if spec_value_is_zero_raw(value)
            ) {
                report.algebraic_rewrites += 1;
                return zero_spec_expr();
            }
            SpecTransformExpr::Mul(Box::new(lhs), Box::new(rhs))
        }
        SpecTransformExpr::Sub(lhs, rhs) => {
            let lhs = normalize_transform_expr(lhs, report);
            let rhs = normalize_transform_expr(rhs, report);

            if matches!(
                &rhs,
                SpecTransformExpr::Const { value, .. } if spec_value_is_zero_raw(value)
            ) {
                report.algebraic_rewrites += 1;
                return lhs;
            }
            SpecTransformExpr::Sub(Box::new(lhs), Box::new(rhs))
        }
        SpecTransformExpr::Div(lhs, rhs) => {
            let lhs = normalize_transform_expr(lhs, report);
            let rhs = normalize_transform_expr(rhs, report);

            if matches!(
                &rhs,
                SpecTransformExpr::Const { value, .. } if spec_value_is_one_raw(value)
            ) {
                report.algebraic_rewrites += 1;
                return lhs;
            }
            SpecTransformExpr::Div(Box::new(lhs), Box::new(rhs))
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn normalize_transform_constraint(
    constraint: &SpecTransformConstraint,
    report: &mut SpecNormalizationReport,
) -> SpecTransformConstraint {
    match constraint {
        SpecTransformConstraint::Equal {
            lhs,
            rhs,
            label_key,
        } => SpecTransformConstraint::Equal {
            lhs: normalize_transform_expr(lhs, report),
            rhs: normalize_transform_expr(rhs, report),
            label_key: *label_key,
        },
        _ => constraint.clone(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn normalize_constraints_from(
    constraints: &[SpecTransformConstraint],
    report: &mut SpecNormalizationReport,
    mut normalized_constraints: Vec<SpecTransformConstraint>,
) -> Vec<SpecTransformConstraint> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            normalized_constraints.push(normalize_transform_constraint(constraint, report));
            normalize_constraints_from(remaining_constraints, report, normalized_constraints)
        }
        None => normalized_constraints,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn filter_live_signals_for_normalization_from(
    signals: &[SpecTransformSignal],
    referenced_marks: &[u8],
    report: &mut SpecNormalizationReport,
    mut live_signals: Vec<SpecTransformSignal>,
) -> Vec<SpecTransformSignal> {
    match signals.split_first() {
        Some((signal, remaining_signals)) => {
            let keep = matches!(signal.visibility, SpecTransformVisibility::Public)
                || matches!(signal.visibility, SpecTransformVisibility::Constant)
                || signal_index_is_marked(referenced_marks, signal.signal_index);
            if keep {
                live_signals.push(signal.clone());
            } else {
                report.dead_signals_removed += 1;
            }
            filter_live_signals_for_normalization_from(
                remaining_signals,
                referenced_marks,
                report,
                live_signals,
            )
        }
        None => live_signals,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn normalize_supported_program(
    program: &SpecTransformProgram,
) -> SpecNormalizationResult {
    let mut report = SpecNormalizationReport::default();
    let constraints = normalize_constraints_from(
        &program.constraints,
        &mut report,
        Vec::with_capacity(program.constraints.len()),
    );
    let referenced_marks = referenced_signal_marks(program, &constraints);
    let live_signals = filter_live_signals_for_normalization_from(
        &program.signals,
        &referenced_marks,
        &mut report,
        Vec::new(),
    );

    SpecNormalizationResult {
        program: SpecTransformProgram {
            field: program.field,
            signals: sort_signals_by_key(&live_signals),
            constraints: sort_constraints_by_key(&constraints),
            assignments: program.assignments.clone(),
            hints: program.hints.clone(),
        },
        report,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn normalize_expr_output(expr: &SpecTransformExpr) -> SpecTransformExpr {
    let mut report = SpecNormalizationReport::default();
    normalize_transform_expr(expr, &mut report)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn normalize_constraint_output(
    constraint: &SpecTransformConstraint,
) -> SpecTransformConstraint {
    let mut report = SpecNormalizationReport::default();
    normalize_transform_constraint(constraint, &mut report)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn normalize_program_output(program: &SpecTransformProgram) -> SpecTransformProgram {
    normalize_supported_program(program).program
}

#[cfg_attr(hax, hax_lib::include)]
fn fold_transform_expr(
    expr: &SpecTransformExpr,
    field: FieldId,
    folded_nodes: &mut usize,
) -> SpecTransformExpr {
    match expr {
        SpecTransformExpr::Const { .. } | SpecTransformExpr::Signal { .. } => expr.clone(),
        SpecTransformExpr::Add(values) => {
            let (const_acc, saw_const, mut terms) = fold_add_terms_from(
                values,
                field,
                folded_nodes,
                zero_spec_value(),
                false,
                Vec::new(),
            );

            if saw_const && !spec_value_is_zero_raw(&const_acc) {
                terms.push(SpecTransformExpr::Const {
                    value: const_acc,
                    sort_key: 0,
                });
            }

            match terms.len() {
                0 => zero_spec_expr(),
                1 => terms.remove(0),
                _ => SpecTransformExpr::Add(terms),
            }
        }
        SpecTransformExpr::Sub(lhs, rhs) => {
            let lhs = fold_transform_expr(lhs, field, folded_nodes);
            let rhs = fold_transform_expr(rhs, field, folded_nodes);
            if let (
                SpecTransformExpr::Const {
                    value: lhs_value, ..
                },
                SpecTransformExpr::Const {
                    value: rhs_value, ..
                },
            ) = (&lhs, &rhs)
            {
                *folded_nodes += 1;
                SpecTransformExpr::Const {
                    value: sub_spec_values(lhs_value, rhs_value, field),
                    sort_key: 0,
                }
            } else if matches!(
                rhs,
                SpecTransformExpr::Const { ref value, .. } if spec_value_is_zero_raw(value)
            ) {
                *folded_nodes += 1;
                lhs
            } else {
                SpecTransformExpr::Sub(Box::new(lhs), Box::new(rhs))
            }
        }
        SpecTransformExpr::Mul(lhs, rhs) => {
            let lhs = fold_transform_expr(lhs, field, folded_nodes);
            let rhs = fold_transform_expr(rhs, field, folded_nodes);
            match (&lhs, &rhs) {
                (
                    SpecTransformExpr::Const {
                        value: lhs_value, ..
                    },
                    SpecTransformExpr::Const {
                        value: rhs_value, ..
                    },
                ) => {
                    *folded_nodes += 1;
                    SpecTransformExpr::Const {
                        value: mul_spec_values(lhs_value, rhs_value, field),
                        sort_key: 0,
                    }
                }
                (SpecTransformExpr::Const { value, .. }, _) if spec_value_is_zero_raw(value) => {
                    *folded_nodes += 1;
                    zero_spec_expr()
                }
                (_, SpecTransformExpr::Const { value, .. }) if spec_value_is_zero_raw(value) => {
                    *folded_nodes += 1;
                    zero_spec_expr()
                }
                (SpecTransformExpr::Const { value, .. }, _) if spec_value_is_one_raw(value) => {
                    *folded_nodes += 1;
                    rhs
                }
                (_, SpecTransformExpr::Const { value, .. }) if spec_value_is_one_raw(value) => {
                    *folded_nodes += 1;
                    lhs
                }
                _ => SpecTransformExpr::Mul(Box::new(lhs), Box::new(rhs)),
            }
        }
        SpecTransformExpr::Div(lhs, rhs) => {
            let lhs = fold_transform_expr(lhs, field, folded_nodes);
            let rhs = fold_transform_expr(rhs, field, folded_nodes);
            if let (
                SpecTransformExpr::Const {
                    value: lhs_value, ..
                },
                SpecTransformExpr::Const {
                    value: rhs_value, ..
                },
            ) = (&lhs, &rhs)
            {
                if let Some(value) = div_spec_values(lhs_value, rhs_value, field) {
                    *folded_nodes += 1;
                    return SpecTransformExpr::Const { value, sort_key: 0 };
                }
                return SpecTransformExpr::Div(Box::new(lhs), Box::new(rhs));
            }
            if matches!(
                rhs,
                SpecTransformExpr::Const { ref value, .. } if spec_value_is_one_raw(value)
            ) {
                *folded_nodes += 1;
                lhs
            } else {
                SpecTransformExpr::Div(Box::new(lhs), Box::new(rhs))
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn fold_add_terms_from(
    values: &[SpecTransformExpr],
    field: FieldId,
    folded_nodes: &mut usize,
    const_acc: SpecFieldValue,
    saw_const: bool,
    mut terms: Vec<SpecTransformExpr>,
) -> (SpecFieldValue, bool, Vec<SpecTransformExpr>) {
    match values.split_first() {
        Some((value, remaining_values)) => {
            let folded = fold_transform_expr(value, field, folded_nodes);
            let (const_acc, saw_const, terms) = match folded {
                SpecTransformExpr::Const { value, .. } => {
                    *folded_nodes += 1;
                    (add_spec_values(&const_acc, &value, field), true, terms)
                }
                SpecTransformExpr::Add(nested) => {
                    *folded_nodes += 1;
                    append_transform_exprs(&mut terms, &nested);
                    (const_acc, saw_const, terms)
                }
                other => {
                    terms.push(other);
                    (const_acc, saw_const, terms)
                }
            };
            fold_add_terms_from(
                remaining_values,
                field,
                folded_nodes,
                const_acc,
                saw_const,
                terms,
            )
        }
        None => (const_acc, saw_const, terms),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn append_transform_exprs(target: &mut Vec<SpecTransformExpr>, values: &[SpecTransformExpr]) {
    if let Some((value, remaining_values)) = values.split_first() {
        target.push(value.clone());
        append_transform_exprs(target, remaining_values);
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn fold_transform_constraint(
    constraint: &SpecTransformConstraint,
    field: FieldId,
    folded_nodes: &mut usize,
) -> SpecTransformConstraint {
    match constraint {
        SpecTransformConstraint::Equal {
            lhs,
            rhs,
            label_key,
        } => SpecTransformConstraint::Equal {
            lhs: fold_transform_expr(lhs, field, folded_nodes),
            rhs: fold_transform_expr(rhs, field, folded_nodes),
            label_key: *label_key,
        },
        _ => constraint.clone(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn fold_expr_output(expr: &SpecTransformExpr, field: FieldId) -> SpecTransformExpr {
    let mut folded_nodes = 0usize;
    fold_transform_expr(expr, field, &mut folded_nodes)
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn fold_constraint_output(
    constraint: &SpecTransformConstraint,
    field: FieldId,
) -> SpecTransformConstraint {
    let mut folded_nodes = 0usize;
    fold_transform_constraint(constraint, field, &mut folded_nodes)
}

#[cfg_attr(hax, hax_lib::include)]
fn constraint_is_tautology(constraint: &SpecTransformConstraint) -> bool {
    match constraint {
        SpecTransformConstraint::Equal { lhs, rhs, .. } => transform_expr_eq(lhs, rhs),
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_expr_list_eq(lhs: &[SpecTransformExpr], rhs: &[SpecTransformExpr]) -> bool {
    match (lhs.split_first(), rhs.split_first()) {
        (Some((lhs_value, lhs_remaining)), Some((rhs_value, rhs_remaining))) => {
            transform_expr_eq(lhs_value, rhs_value)
                && transform_expr_list_eq(lhs_remaining, rhs_remaining)
        }
        (None, None) => true,
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_expr_eq(lhs: &SpecTransformExpr, rhs: &SpecTransformExpr) -> bool {
    match (lhs, rhs) {
        (
            SpecTransformExpr::Const {
                value: lhs_value,
                sort_key: lhs_sort_key,
            },
            SpecTransformExpr::Const {
                value: rhs_value,
                sort_key: rhs_sort_key,
            },
        ) => lhs_sort_key == rhs_sort_key && lhs_value == rhs_value,
        (
            SpecTransformExpr::Signal {
                signal_index: lhs_signal_index,
                sort_key: lhs_sort_key,
            },
            SpecTransformExpr::Signal {
                signal_index: rhs_signal_index,
                sort_key: rhs_sort_key,
            },
        ) => lhs_signal_index == rhs_signal_index && lhs_sort_key == rhs_sort_key,
        (SpecTransformExpr::Add(lhs_values), SpecTransformExpr::Add(rhs_values)) => {
            transform_expr_list_eq(lhs_values, rhs_values)
        }
        (SpecTransformExpr::Sub(lhs_lhs, lhs_rhs), SpecTransformExpr::Sub(rhs_lhs, rhs_rhs))
        | (SpecTransformExpr::Mul(lhs_lhs, lhs_rhs), SpecTransformExpr::Mul(rhs_lhs, rhs_rhs))
        | (SpecTransformExpr::Div(lhs_lhs, lhs_rhs), SpecTransformExpr::Div(rhs_lhs, rhs_rhs)) => {
            transform_expr_eq(lhs_lhs, rhs_lhs) && transform_expr_eq(lhs_rhs, rhs_rhs)
        }
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_constraint_eq(lhs: &SpecTransformConstraint, rhs: &SpecTransformConstraint) -> bool {
    match (lhs, rhs) {
        (
            SpecTransformConstraint::Equal {
                lhs: lhs_expr,
                rhs: lhs_rhs,
                label_key: lhs_label_key,
            },
            SpecTransformConstraint::Equal {
                lhs: rhs_expr,
                rhs: rhs_rhs,
                label_key: rhs_label_key,
            },
        ) => {
            transform_expr_eq(lhs_expr, rhs_expr)
                && transform_expr_eq(lhs_rhs, rhs_rhs)
                && lhs_label_key == rhs_label_key
        }
        (
            SpecTransformConstraint::Boolean {
                signal_index: lhs_signal,
                signal_sort_key: lhs_signal_sort_key,
                label_key: lhs_label_key,
            },
            SpecTransformConstraint::Boolean {
                signal_index: rhs_signal,
                signal_sort_key: rhs_signal_sort_key,
                label_key: rhs_label_key,
            },
        ) => {
            lhs_signal == rhs_signal
                && lhs_signal_sort_key == rhs_signal_sort_key
                && lhs_label_key == rhs_label_key
        }
        (
            SpecTransformConstraint::Range {
                signal_index: lhs_signal,
                signal_sort_key: lhs_signal_sort_key,
                bits: lhs_bits,
                label_key: lhs_label_key,
            },
            SpecTransformConstraint::Range {
                signal_index: rhs_signal,
                signal_sort_key: rhs_signal_sort_key,
                bits: rhs_bits,
                label_key: rhs_label_key,
            },
        ) => {
            lhs_signal == rhs_signal
                && lhs_signal_sort_key == rhs_signal_sort_key
                && lhs_bits == rhs_bits
                && lhs_label_key == rhs_label_key
        }
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn constraint_equals_ignoring_label(
    lhs: &SpecTransformConstraint,
    rhs: &SpecTransformConstraint,
) -> bool {
    match (lhs, rhs) {
        (
            SpecTransformConstraint::Equal {
                lhs: lhs_expr,
                rhs: lhs_rhs,
                ..
            },
            SpecTransformConstraint::Equal {
                lhs: rhs_expr,
                rhs: rhs_rhs,
                ..
            },
        ) => transform_expr_eq(lhs_expr, rhs_expr) && transform_expr_eq(lhs_rhs, rhs_rhs),
        (
            SpecTransformConstraint::Boolean {
                signal_index: lhs_signal,
                ..
            },
            SpecTransformConstraint::Boolean {
                signal_index: rhs_signal,
                ..
            },
        ) => lhs_signal == rhs_signal,
        (
            SpecTransformConstraint::Range {
                signal_index: lhs_signal,
                bits: lhs_bits,
                ..
            },
            SpecTransformConstraint::Range {
                signal_index: rhs_signal,
                bits: rhs_bits,
                ..
            },
        ) => lhs_signal == rhs_signal && lhs_bits == rhs_bits,
        _ => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn dedup_constraints_ir(
    constraints: &[SpecTransformConstraint],
    report: &mut SpecOptimizeReport,
) -> Vec<SpecTransformConstraint> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            let mut deduped = dedup_constraints_ir(remaining_constraints, report);
            if contains_equivalent_ir_constraint(&deduped, constraint) {
                report.deduplicated_constraints += 1;
            } else {
                deduped = insert_constraint_sorted(constraint.clone(), &deduped);
            }
            deduped
        }
        None => Vec::new(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn dedup_constraints_zir(
    constraints: &[SpecTransformConstraint],
    report: &mut SpecOptimizeReport,
) -> Vec<SpecTransformConstraint> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            let mut deduped = dedup_constraints_zir(remaining_constraints, report);
            if contains_exact_constraint(&deduped, constraint) {
                report.deduplicated_constraints += 1;
            } else {
                deduped = insert_constraint_sorted(constraint.clone(), &deduped);
            }
            deduped
        }
        None => Vec::new(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn contains_equivalent_ir_constraint(
    constraints: &[SpecTransformConstraint],
    target: &SpecTransformConstraint,
) -> bool {
    match constraints.split_first() {
        Some((current, remaining)) => {
            constraint_equals_ignoring_label(current, target)
                || contains_equivalent_ir_constraint(remaining, target)
        }
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn contains_exact_constraint(
    constraints: &[SpecTransformConstraint],
    target: &SpecTransformConstraint,
) -> bool {
    match constraints.split_first() {
        Some((current, remaining)) => {
            transform_constraint_eq(current, target) || contains_exact_constraint(remaining, target)
        }
        None => false,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn filter_live_signals(
    program: &SpecTransformProgram,
    constraints: &[SpecTransformConstraint],
    report: &mut SpecOptimizeReport,
) -> Vec<SpecTransformSignal> {
    let referenced_marks = referenced_signal_marks(program, constraints);
    fn filter_live_signals_from(
        signals: &[SpecTransformSignal],
        referenced_marks: &[u8],
        report: &mut SpecOptimizeReport,
        mut kept_signals: Vec<SpecTransformSignal>,
    ) -> Vec<SpecTransformSignal> {
        match signals.split_first() {
            Some((signal, remaining_signals)) => {
                let keep = !matches!(signal.visibility, SpecTransformVisibility::Private)
                    || signal_index_is_marked(referenced_marks, signal.signal_index);
                if keep {
                    kept_signals.push(signal.clone());
                } else {
                    report.removed_private_signals += 1;
                }
                filter_live_signals_from(remaining_signals, referenced_marks, report, kept_signals)
            }
            None => kept_signals,
        }
    }
    filter_live_signals_from(&program.signals, &referenced_marks, report, Vec::new())
}

#[cfg_attr(hax, hax_lib::include)]
fn fold_constraints_for_ir_from(
    constraints: &[SpecTransformConstraint],
    field: FieldId,
    report: &mut SpecOptimizeReport,
    mut folded_constraints: Vec<SpecTransformConstraint>,
) -> Vec<SpecTransformConstraint> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            let folded =
                fold_transform_constraint(constraint, field, &mut report.folded_expr_nodes);
            if constraint_is_tautology(&folded) {
                report.removed_tautology_constraints += 1;
            } else {
                folded_constraints.push(folded);
            }
            fold_constraints_for_ir_from(remaining_constraints, field, report, folded_constraints)
        }
        None => folded_constraints,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn collect_signal_marks_from_signals(
    signals: &[SpecTransformSignal],
    signal_count: usize,
) -> Vec<u8> {
    let mut kept_signal_marks = vec![0; signal_count];
    for signal in signals {
        mark_signal_index(&mut kept_signal_marks, signal.signal_index);
    }
    kept_signal_marks
}

#[cfg_attr(hax, hax_lib::include)]
fn filter_assignments_by_signal_indices_from(
    assignments: &[SpecTransformAssignment],
    kept_signal_marks: &[u8],
    mut filtered_assignments: Vec<SpecTransformAssignment>,
) -> Vec<SpecTransformAssignment> {
    match assignments.split_first() {
        Some((assignment, remaining_assignments)) => {
            if signal_index_is_marked(kept_signal_marks, assignment.target_signal_index) {
                filtered_assignments.push(assignment.clone());
            }
            filter_assignments_by_signal_indices_from(
                remaining_assignments,
                kept_signal_marks,
                filtered_assignments,
            )
        }
        None => filtered_assignments,
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn filter_hints_by_signal_indices_from(
    hints: &[SpecTransformHint],
    kept_signal_marks: &[u8],
    mut filtered_hints: Vec<SpecTransformHint>,
) -> Vec<SpecTransformHint> {
    match hints.split_first() {
        Some((hint, remaining_hints)) => {
            if signal_index_is_marked(kept_signal_marks, hint.target_signal_index) {
                filtered_hints.push(hint.clone());
            }
            filter_hints_by_signal_indices_from(remaining_hints, kept_signal_marks, filtered_hints)
        }
        None => filtered_hints,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn optimize_supported_ir_program(program: &SpecTransformProgram) -> SpecOptimizeResult {
    let mut report = SpecOptimizeReport::default();
    let folded_constraints =
        fold_constraints_for_ir_from(&program.constraints, program.field, &mut report, Vec::new());

    let constraints = dedup_constraints_ir(&folded_constraints, &mut report);
    let signals = filter_live_signals(program, &constraints, &mut report);
    let kept_signal_marks = collect_signal_marks_from_signals(&signals, program.signals.len());
    let assignments = filter_assignments_by_signal_indices_from(
        &program.assignments,
        &kept_signal_marks,
        Vec::new(),
    );
    let hints = filter_hints_by_signal_indices_from(&program.hints, &kept_signal_marks, Vec::new());

    SpecOptimizeResult {
        program: SpecTransformProgram {
            field: program.field,
            signals,
            constraints,
            assignments,
            hints,
        },
        report,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn optimize_ir_program_output(program: &SpecTransformProgram) -> SpecTransformProgram {
    optimize_supported_ir_program(program).program
}

#[cfg_attr(hax, hax_lib::include)]
fn fold_constraints_for_zir_from(
    constraints: &[SpecTransformConstraint],
    field: FieldId,
    report: &mut SpecOptimizeReport,
    mut folded_constraints: Vec<SpecTransformConstraint>,
) -> Vec<SpecTransformConstraint> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            let folded =
                fold_transform_constraint(constraint, field, &mut report.folded_expr_nodes);
            if constraint_is_tautology(&folded) {
                report.removed_tautology_constraints += 1;
            } else {
                folded_constraints.push(folded);
            }
            fold_constraints_for_zir_from(remaining_constraints, field, report, folded_constraints)
        }
        None => folded_constraints,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn optimize_supported_zir_program(program: &SpecTransformProgram) -> SpecOptimizeResult {
    let mut report = SpecOptimizeReport::default();
    let folded_constraints =
        fold_constraints_for_zir_from(&program.constraints, program.field, &mut report, Vec::new());

    let constraints = dedup_constraints_zir(&folded_constraints, &mut report);
    let signals = filter_live_signals(program, &constraints, &mut report);
    SpecOptimizeResult {
        program: SpecTransformProgram {
            field: program.field,
            signals,
            constraints,
            assignments: program.assignments.clone(),
            hints: program.hints.clone(),
        },
        report,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn optimize_zir_program_output(program: &SpecTransformProgram) -> SpecTransformProgram {
    optimize_supported_zir_program(program).program
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_signal_value(
    witness: &SpecKernelWitness,
    signal_index: usize,
    field: FieldId,
) -> Result<SpecFieldValue, SpecKernelCheckError> {
    match witness.values.get(signal_index) {
        Some(Some(value)) => Ok(normalize_spec_value(value, field)),
        _ => Err(SpecKernelCheckError::MissingSignal { signal_index }),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_eval_exprs(
    values: &[SpecTransformExpr],
    witness: &SpecKernelWitness,
    field: FieldId,
    acc: SpecFieldValue,
) -> Result<SpecFieldValue, SpecKernelCheckError> {
    match values.split_first() {
        Some((value, remaining_values)) => match transform_eval_expr(value, witness, field) {
            Ok(evaluated) => transform_eval_exprs(
                remaining_values,
                witness,
                field,
                add_spec_values(&acc, &evaluated, field),
            ),
            Err(error) => Err(error),
        },
        None => Ok(acc),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn transform_eval_expr(
    expr: &SpecTransformExpr,
    witness: &SpecKernelWitness,
    field: FieldId,
) -> Result<SpecFieldValue, SpecKernelCheckError> {
    match expr {
        SpecTransformExpr::Const { value, .. } => Ok(normalize_spec_value(value, field)),
        SpecTransformExpr::Signal { signal_index, .. } => {
            transform_signal_value(witness, *signal_index, field)
        }
        SpecTransformExpr::Add(values) => {
            transform_eval_exprs(values, witness, field, zero_spec_value())
        }
        SpecTransformExpr::Sub(lhs, rhs) => match transform_eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match transform_eval_expr(rhs, witness, field) {
                Ok(rhs_value) => Ok(sub_spec_values(&lhs_value, &rhs_value, field)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        SpecTransformExpr::Mul(lhs, rhs) => match transform_eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match transform_eval_expr(rhs, witness, field) {
                Ok(rhs_value) => Ok(mul_spec_values(&lhs_value, &rhs_value, field)),
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
        SpecTransformExpr::Div(lhs, rhs) => match transform_eval_expr(lhs, witness, field) {
            Ok(lhs_value) => match transform_eval_expr(rhs, witness, field) {
                Ok(rhs_value) => match div_spec_values(&lhs_value, &rhs_value, field) {
                    Some(value) => Ok(value),
                    None => Err(SpecKernelCheckError::DivisionByZero),
                },
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        },
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_check_constraint(
    constraint: &SpecTransformConstraint,
    constraint_index: usize,
    program: &SpecTransformProgram,
    witness: &SpecKernelWitness,
) -> Result<(), SpecKernelCheckError> {
    match constraint {
        SpecTransformConstraint::Equal { lhs, rhs, .. } => {
            match transform_eval_expr(lhs, witness, program.field) {
                Ok(lhs_value) => match transform_eval_expr(rhs, witness, program.field) {
                    Ok(rhs_value) => {
                        if spec_values_equal(&lhs_value, &rhs_value, program.field) {
                            Ok(())
                        } else {
                            Err(SpecKernelCheckError::EqualViolation {
                                constraint_index,
                                lhs: lhs_value,
                                rhs: rhs_value,
                            })
                        }
                    }
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            }
        }
        SpecTransformConstraint::Boolean { signal_index, .. } => {
            match transform_signal_value(witness, *signal_index, program.field) {
                Ok(value) => {
                    if spec_value_is_boolean(&value, program.field) {
                        Ok(())
                    } else {
                        Err(SpecKernelCheckError::BooleanViolation {
                            constraint_index,
                            signal_index: *signal_index,
                            value,
                        })
                    }
                }
                Err(error) => Err(error),
            }
        }
        SpecTransformConstraint::Range {
            signal_index, bits, ..
        } => match transform_signal_value(witness, *signal_index, program.field) {
            Ok(value) => {
                if spec_value_fits_bits(&value, *bits, program.field) {
                    Ok(())
                } else {
                    Err(SpecKernelCheckError::RangeViolation {
                        constraint_index,
                        signal_index: *signal_index,
                        bits: *bits,
                        value,
                    })
                }
            }
            Err(error) => Err(error),
        },
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_check_constraints_from(
    constraints: &[SpecTransformConstraint],
    constraint_index: usize,
    program: &SpecTransformProgram,
    witness: &SpecKernelWitness,
) -> Result<(), SpecKernelCheckError> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            match transform_check_constraint(constraint, constraint_index, program, witness) {
                Ok(()) => transform_check_constraints_from(
                    remaining_constraints,
                    constraint_index + 1,
                    program,
                    witness,
                ),
                Err(error) => Err(error),
            }
        }
        None => Ok(()),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn to_kernel_expr(values: &[SpecTransformExpr], field: FieldId) -> SpecKernelExpr {
    match values.split_first() {
        Some((first, rest)) => {
            to_kernel_expr_from(rest, transform_expr_to_kernel(first, field), field)
        }
        None => SpecKernelExpr::Const(zero_spec_value()),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn to_kernel_expr_from(
    values: &[SpecTransformExpr],
    acc: SpecKernelExpr,
    field: FieldId,
) -> SpecKernelExpr {
    match values.split_first() {
        Some((value, remaining_values)) => to_kernel_expr_from(
            remaining_values,
            SpecKernelExpr::Add(
                Box::new(acc),
                Box::new(transform_expr_to_kernel(value, field)),
            ),
            field,
        ),
        None => acc,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn transform_expr_to_kernel(expr: &SpecTransformExpr, field: FieldId) -> SpecKernelExpr {
    match expr {
        SpecTransformExpr::Const { value, .. } => SpecKernelExpr::Const(value.clone()),
        SpecTransformExpr::Signal { signal_index, .. } => SpecKernelExpr::Signal(*signal_index),
        SpecTransformExpr::Add(values) => to_kernel_expr(values, field),
        SpecTransformExpr::Sub(lhs, rhs) => SpecKernelExpr::Sub(
            Box::new(transform_expr_to_kernel(lhs, field)),
            Box::new(transform_expr_to_kernel(rhs, field)),
        ),
        SpecTransformExpr::Mul(lhs, rhs) => SpecKernelExpr::Mul(
            Box::new(transform_expr_to_kernel(lhs, field)),
            Box::new(transform_expr_to_kernel(rhs, field)),
        ),
        SpecTransformExpr::Div(lhs, rhs) => SpecKernelExpr::Div(
            Box::new(transform_expr_to_kernel(lhs, field)),
            Box::new(transform_expr_to_kernel(rhs, field)),
        ),
    }
}

#[cfg_attr(hax, hax_lib::include)]
fn transform_constraints_to_kernel_from(
    constraints: &[SpecTransformConstraint],
    index: usize,
    mut kernel_constraints: Vec<SpecKernelConstraint>,
    field: FieldId,
) -> Vec<SpecKernelConstraint> {
    match constraints.split_first() {
        Some((constraint, remaining_constraints)) => {
            kernel_constraints.push(match constraint {
                SpecTransformConstraint::Equal { lhs, rhs, .. } => SpecKernelConstraint::Equal {
                    index,
                    lhs: transform_expr_to_kernel(lhs, field),
                    rhs: transform_expr_to_kernel(rhs, field),
                },
                SpecTransformConstraint::Boolean { signal_index, .. } => {
                    SpecKernelConstraint::Boolean {
                        index,
                        signal: *signal_index,
                    }
                }
                SpecTransformConstraint::Range {
                    signal_index, bits, ..
                } => SpecKernelConstraint::Range {
                    index,
                    signal: *signal_index,
                    bits: *bits,
                },
            });
            transform_constraints_to_kernel_from(
                remaining_constraints,
                index + 1,
                kernel_constraints,
                field,
            )
        }
        None => kernel_constraints,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn transform_program_to_kernel(program: &SpecTransformProgram) -> SpecKernelProgram {
    let constraints =
        transform_constraints_to_kernel_from(&program.constraints, 0, Vec::new(), program.field);

    SpecKernelProgram {
        field: program.field,
        constraints,
        lookup_tables: Vec::new(),
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn transform_check_program(
    program: &SpecTransformProgram,
    witness: &SpecKernelWitness,
) -> Result<(), SpecKernelCheckError> {
    transform_check_constraints_from(&program.constraints, 0, program, witness)
}

struct RuntimeTransformContext {
    signal_name_order: BTreeMap<String, usize>,
    label_order: BTreeMap<Option<String>, usize>,
    constant_order: BTreeMap<String, usize>,
}

#[cfg(feature = "full")]
fn make_runtime_context_from_zir(program: &crate::zir::Program) -> RuntimeTransformContext {
    let signal_name_order = program
        .signals
        .iter()
        .map(|signal| signal.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, index))
        .collect::<BTreeMap<_, _>>();
    let label_order = std::iter::once(None)
        .chain(
            program
                .constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    crate::zir::Constraint::Equal { label, .. }
                    | crate::zir::Constraint::Boolean { label, .. }
                    | crate::zir::Constraint::Range { label, .. } => label.clone(),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Some),
        )
        .enumerate()
        .map(|(index, label)| (label, index))
        .collect::<BTreeMap<_, _>>();
    let mut constant_strings = BTreeSet::new();
    constant_strings.insert(
        serde_json::to_string(&FieldElement::from_i64(0)).expect("zero field element serializes"),
    );
    collect_zir_constants(program, &mut constant_strings);
    let constant_order = constant_strings
        .into_iter()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect::<BTreeMap<_, _>>();

    RuntimeTransformContext {
        signal_name_order,
        label_order,
        constant_order,
    }
}

fn make_runtime_context_from_ir(program: &crate::ir::Program) -> RuntimeTransformContext {
    let signal_name_order = program
        .signals
        .iter()
        .map(|signal| signal.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, index))
        .collect::<BTreeMap<_, _>>();
    let label_order = std::iter::once(None)
        .chain(
            program
                .constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    crate::ir::Constraint::Equal { label, .. }
                    | crate::ir::Constraint::Boolean { label, .. }
                    | crate::ir::Constraint::Range { label, .. } => label.clone(),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Some),
        )
        .enumerate()
        .map(|(index, label)| (label, index))
        .collect::<BTreeMap<_, _>>();
    let mut constant_strings = BTreeSet::new();
    constant_strings.insert(
        serde_json::to_string(&FieldElement::from_i64(0)).expect("zero field element serializes"),
    );
    collect_ir_constants(program, &mut constant_strings);
    let constant_order = constant_strings
        .into_iter()
        .enumerate()
        .map(|(index, key)| (key, index))
        .collect::<BTreeMap<_, _>>();

    RuntimeTransformContext {
        signal_name_order,
        label_order,
        constant_order,
    }
}

#[cfg(feature = "full")]
fn collect_zir_constants(program: &crate::zir::Program, out: &mut BTreeSet<String>) {
    for signal in &program.signals {
        if let Some(constant) = &signal.constant {
            out.insert(serde_json::to_string(constant).expect("field element serializes"));
        }
    }
    for constraint in &program.constraints {
        if let crate::zir::Constraint::Equal { lhs, rhs, .. } = constraint {
            collect_zir_expr_constants(lhs, out);
            collect_zir_expr_constants(rhs, out);
        }
    }
    for assignment in &program.witness_plan.assignments {
        collect_zir_expr_constants(&assignment.expr, out);
    }
}

#[cfg(feature = "full")]
fn collect_zir_expr_constants(expr: &crate::zir::Expr, out: &mut BTreeSet<String>) {
    match expr {
        crate::zir::Expr::Const(value) => {
            out.insert(serde_json::to_string(value).expect("field element serializes"));
        }
        crate::zir::Expr::Signal(_) => {}
        crate::zir::Expr::Add(values) => {
            for value in values {
                collect_zir_expr_constants(value, out);
            }
        }
        crate::zir::Expr::Sub(lhs, rhs)
        | crate::zir::Expr::Mul(lhs, rhs)
        | crate::zir::Expr::Div(lhs, rhs) => {
            collect_zir_expr_constants(lhs, out);
            collect_zir_expr_constants(rhs, out);
        }
    }
}

fn collect_ir_constants(program: &crate::ir::Program, out: &mut BTreeSet<String>) {
    for signal in &program.signals {
        if let Some(constant) = &signal.constant {
            out.insert(serde_json::to_string(constant).expect("field element serializes"));
        }
    }
    for constraint in &program.constraints {
        if let crate::ir::Constraint::Equal { lhs, rhs, .. } = constraint {
            collect_ir_expr_constants(lhs, out);
            collect_ir_expr_constants(rhs, out);
        }
    }
    for assignment in &program.witness_plan.assignments {
        collect_ir_expr_constants(&assignment.expr, out);
    }
}

fn collect_ir_expr_constants(expr: &crate::ir::Expr, out: &mut BTreeSet<String>) {
    match expr {
        crate::ir::Expr::Const(value) => {
            out.insert(serde_json::to_string(value).expect("field element serializes"));
        }
        crate::ir::Expr::Signal(_) => {}
        crate::ir::Expr::Add(values) => {
            for value in values {
                collect_ir_expr_constants(value, out);
            }
        }
        crate::ir::Expr::Sub(lhs, rhs)
        | crate::ir::Expr::Mul(lhs, rhs)
        | crate::ir::Expr::Div(lhs, rhs) => {
            collect_ir_expr_constants(lhs, out);
            collect_ir_expr_constants(rhs, out);
        }
    }
}

fn map_visibility(visibility: crate::Visibility) -> SpecTransformVisibility {
    match visibility {
        crate::Visibility::Public => SpecTransformVisibility::Public,
        crate::Visibility::Constant => SpecTransformVisibility::Constant,
        crate::Visibility::Private => SpecTransformVisibility::Private,
    }
}

fn expr_const_sort_key(value: &FieldElement, context: &RuntimeTransformContext) -> usize {
    let rendered = serde_json::to_string(value).expect("field element serializes");
    *context.constant_order.get(&rendered).unwrap_or(&0usize)
}

fn label_key(label: &Option<String>, context: &RuntimeTransformContext) -> usize {
    *context.label_order.get(label).unwrap_or(&0usize)
}

#[cfg(feature = "full")]
fn translate_zir_expr(
    expr: &crate::zir::Expr,
    signal_indices: &BTreeMap<String, usize>,
    context: &RuntimeTransformContext,
) -> ZkfResult<SpecTransformExpr> {
    Ok(match expr {
        crate::zir::Expr::Const(value) => SpecTransformExpr::Const {
            value: SpecFieldValue::from_runtime(value),
            sort_key: expr_const_sort_key(value, context),
        },
        crate::zir::Expr::Signal(name) => SpecTransformExpr::Signal {
            signal_index: signal_indices.get(name).copied().ok_or_else(|| {
                ZkfError::UnknownSignal {
                    signal: name.clone(),
                }
            })?,
            sort_key: *context.signal_name_order.get(name).unwrap_or(&0usize),
        },
        crate::zir::Expr::Add(values) => SpecTransformExpr::Add(
            values
                .iter()
                .map(|value| translate_zir_expr(value, signal_indices, context))
                .collect::<ZkfResult<Vec<_>>>()?,
        ),
        crate::zir::Expr::Sub(lhs, rhs) => SpecTransformExpr::Sub(
            Box::new(translate_zir_expr(lhs, signal_indices, context)?),
            Box::new(translate_zir_expr(rhs, signal_indices, context)?),
        ),
        crate::zir::Expr::Mul(lhs, rhs) => SpecTransformExpr::Mul(
            Box::new(translate_zir_expr(lhs, signal_indices, context)?),
            Box::new(translate_zir_expr(rhs, signal_indices, context)?),
        ),
        crate::zir::Expr::Div(lhs, rhs) => SpecTransformExpr::Div(
            Box::new(translate_zir_expr(lhs, signal_indices, context)?),
            Box::new(translate_zir_expr(rhs, signal_indices, context)?),
        ),
    })
}

fn translate_ir_expr(
    expr: &crate::ir::Expr,
    signal_indices: &BTreeMap<String, usize>,
    context: &RuntimeTransformContext,
) -> ZkfResult<SpecTransformExpr> {
    Ok(match expr {
        crate::ir::Expr::Const(value) => SpecTransformExpr::Const {
            value: SpecFieldValue::from_runtime(value),
            sort_key: expr_const_sort_key(value, context),
        },
        crate::ir::Expr::Signal(name) => SpecTransformExpr::Signal {
            signal_index: signal_indices.get(name).copied().ok_or_else(|| {
                ZkfError::UnknownSignal {
                    signal: name.clone(),
                }
            })?,
            sort_key: *context.signal_name_order.get(name).unwrap_or(&0usize),
        },
        crate::ir::Expr::Add(values) => SpecTransformExpr::Add(
            values
                .iter()
                .map(|value| translate_ir_expr(value, signal_indices, context))
                .collect::<ZkfResult<Vec<_>>>()?,
        ),
        crate::ir::Expr::Sub(lhs, rhs) => SpecTransformExpr::Sub(
            Box::new(translate_ir_expr(lhs, signal_indices, context)?),
            Box::new(translate_ir_expr(rhs, signal_indices, context)?),
        ),
        crate::ir::Expr::Mul(lhs, rhs) => SpecTransformExpr::Mul(
            Box::new(translate_ir_expr(lhs, signal_indices, context)?),
            Box::new(translate_ir_expr(rhs, signal_indices, context)?),
        ),
        crate::ir::Expr::Div(lhs, rhs) => SpecTransformExpr::Div(
            Box::new(translate_ir_expr(lhs, signal_indices, context)?),
            Box::new(translate_ir_expr(rhs, signal_indices, context)?),
        ),
    })
}

#[cfg(feature = "full")]
pub(crate) fn supports_normalization_proof_subset(program: &crate::zir::Program) -> bool {
    program.lookup_tables.is_empty()
        && program.memory_regions.is_empty()
        && program.custom_gates.is_empty()
        && program.witness_plan.acir_program_bytes.is_none()
        && program.constraints.iter().all(|constraint| {
            matches!(
                constraint,
                crate::zir::Constraint::Equal { .. }
                    | crate::zir::Constraint::Boolean { .. }
                    | crate::zir::Constraint::Range { .. }
            )
        })
}

pub(crate) fn supports_optimizer_ir_proof_subset(program: &crate::ir::Program) -> bool {
    program.lookup_tables.is_empty()
        && program.witness_plan.acir_program_bytes.is_none()
        && program.constraints.iter().all(|constraint| {
            matches!(
                constraint,
                crate::ir::Constraint::Equal { .. }
                    | crate::ir::Constraint::Boolean { .. }
                    | crate::ir::Constraint::Range { .. }
            )
        })
}

#[cfg(feature = "full")]
pub(crate) fn supports_optimizer_zir_proof_subset(program: &crate::zir::Program) -> bool {
    supports_normalization_proof_subset(program)
}

#[cfg(feature = "full")]
fn translate_supported_zir_program(
    program: &crate::zir::Program,
) -> ZkfResult<SpecTransformProgram> {
    let context = make_runtime_context_from_zir(program);
    let signal_indices = program
        .signals
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.name.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let signals = program
        .signals
        .iter()
        .enumerate()
        .map(|(signal_index, signal)| SpecTransformSignal {
            signal_index,
            sort_key: *context
                .signal_name_order
                .get(&signal.name)
                .unwrap_or(&signal_index),
            visibility: map_visibility(signal.visibility.clone()),
            constant_value: signal.constant.as_ref().map(SpecFieldValue::from_runtime),
            required: signal.visibility != crate::Visibility::Constant,
        })
        .collect::<Vec<_>>();
    let constraints = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            crate::zir::Constraint::Equal { lhs, rhs, label } => {
                Ok(SpecTransformConstraint::Equal {
                    lhs: translate_zir_expr(lhs, &signal_indices, &context)?,
                    rhs: translate_zir_expr(rhs, &signal_indices, &context)?,
                    label_key: label_key(label, &context),
                })
            }
            crate::zir::Constraint::Boolean { signal, label } => {
                Ok(SpecTransformConstraint::Boolean {
                    signal_index: signal_indices.get(signal).copied().ok_or_else(|| {
                        ZkfError::UnknownSignal {
                            signal: signal.clone(),
                        }
                    })?,
                    signal_sort_key: *context.signal_name_order.get(signal).unwrap_or(&0usize),
                    label_key: label_key(label, &context),
                })
            }
            crate::zir::Constraint::Range {
                signal,
                bits,
                label,
            } => Ok(SpecTransformConstraint::Range {
                signal_index: signal_indices.get(signal).copied().ok_or_else(|| {
                    ZkfError::UnknownSignal {
                        signal: signal.clone(),
                    }
                })?,
                signal_sort_key: *context.signal_name_order.get(signal).unwrap_or(&0usize),
                bits: *bits,
                label_key: label_key(label, &context),
            }),
            other => Err(ZkfError::UnsupportedBackend {
                backend: "proof-transform-zir".to_string(),
                message: format!(
                    "constraint is outside the supported arithmetic proof subset: {other:?}"
                ),
            }),
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let assignments = program
        .witness_plan
        .assignments
        .iter()
        .map(|assignment| {
            Ok(SpecTransformAssignment {
                target_signal_index: signal_indices.get(&assignment.target).copied().ok_or_else(
                    || ZkfError::UnknownSignal {
                        signal: assignment.target.clone(),
                    },
                )?,
                expr: translate_zir_expr(&assignment.expr, &signal_indices, &context)?,
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let hints = program
        .witness_plan
        .hints
        .iter()
        .map(|hint| {
            Ok(SpecTransformHint {
                target_signal_index: signal_indices.get(&hint.target).copied().ok_or_else(
                    || ZkfError::UnknownSignal {
                        signal: hint.target.clone(),
                    },
                )?,
                source_signal_index: signal_indices.get(&hint.source).copied().ok_or_else(
                    || ZkfError::UnknownSignal {
                        signal: hint.source.clone(),
                    },
                )?,
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok(SpecTransformProgram {
        field: program.field,
        signals,
        constraints,
        assignments,
        hints,
    })
}

fn translate_supported_ir_program(program: &crate::ir::Program) -> ZkfResult<SpecTransformProgram> {
    let context = make_runtime_context_from_ir(program);
    let signal_indices = program
        .signals
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.name.clone(), index))
        .collect::<BTreeMap<_, _>>();
    let signals = program
        .signals
        .iter()
        .enumerate()
        .map(|(signal_index, signal)| SpecTransformSignal {
            signal_index,
            sort_key: *context
                .signal_name_order
                .get(&signal.name)
                .unwrap_or(&signal_index),
            visibility: map_visibility(signal.visibility.clone()),
            constant_value: signal.constant.as_ref().map(SpecFieldValue::from_runtime),
            required: signal.visibility != crate::Visibility::Constant,
        })
        .collect::<Vec<_>>();
    let constraints = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            crate::ir::Constraint::Equal { lhs, rhs, label } => {
                Ok(SpecTransformConstraint::Equal {
                    lhs: translate_ir_expr(lhs, &signal_indices, &context)?,
                    rhs: translate_ir_expr(rhs, &signal_indices, &context)?,
                    label_key: label_key(label, &context),
                })
            }
            crate::ir::Constraint::Boolean { signal, label } => {
                Ok(SpecTransformConstraint::Boolean {
                    signal_index: signal_indices.get(signal).copied().ok_or_else(|| {
                        ZkfError::UnknownSignal {
                            signal: signal.clone(),
                        }
                    })?,
                    signal_sort_key: *context.signal_name_order.get(signal).unwrap_or(&0usize),
                    label_key: label_key(label, &context),
                })
            }
            crate::ir::Constraint::Range {
                signal,
                bits,
                label,
            } => Ok(SpecTransformConstraint::Range {
                signal_index: signal_indices.get(signal).copied().ok_or_else(|| {
                    ZkfError::UnknownSignal {
                        signal: signal.clone(),
                    }
                })?,
                signal_sort_key: *context.signal_name_order.get(signal).unwrap_or(&0usize),
                bits: *bits,
                label_key: label_key(label, &context),
            }),
            other => Err(ZkfError::UnsupportedBackend {
                backend: "proof-transform-ir".to_string(),
                message: format!(
                    "constraint is outside the supported arithmetic proof subset: {other:?}"
                ),
            }),
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let assignments = program
        .witness_plan
        .assignments
        .iter()
        .map(|assignment| {
            Ok(SpecTransformAssignment {
                target_signal_index: signal_indices.get(&assignment.target).copied().ok_or_else(
                    || ZkfError::UnknownSignal {
                        signal: assignment.target.clone(),
                    },
                )?,
                expr: translate_ir_expr(&assignment.expr, &signal_indices, &context)?,
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let hints = program
        .witness_plan
        .hints
        .iter()
        .map(|hint| {
            Ok(SpecTransformHint {
                target_signal_index: signal_indices.get(&hint.target).copied().ok_or_else(
                    || ZkfError::UnknownSignal {
                        signal: hint.target.clone(),
                    },
                )?,
                source_signal_index: signal_indices.get(&hint.source).copied().ok_or_else(
                    || ZkfError::UnknownSignal {
                        signal: hint.source.clone(),
                    },
                )?,
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok(SpecTransformProgram {
        field: program.field,
        signals,
        constraints,
        assignments,
        hints,
    })
}

#[cfg(feature = "full")]
fn spec_expr_to_zir(expr: &SpecTransformExpr, signal_names: &[String]) -> crate::zir::Expr {
    match expr {
        SpecTransformExpr::Const { value, .. } => crate::zir::Expr::Const(value.to_runtime()),
        SpecTransformExpr::Signal { signal_index, .. } => {
            crate::zir::Expr::Signal(signal_names[*signal_index].clone())
        }
        SpecTransformExpr::Add(values) => crate::zir::Expr::Add(
            values
                .iter()
                .map(|value| spec_expr_to_zir(value, signal_names))
                .collect(),
        ),
        SpecTransformExpr::Sub(lhs, rhs) => crate::zir::Expr::Sub(
            Box::new(spec_expr_to_zir(lhs, signal_names)),
            Box::new(spec_expr_to_zir(rhs, signal_names)),
        ),
        SpecTransformExpr::Mul(lhs, rhs) => crate::zir::Expr::Mul(
            Box::new(spec_expr_to_zir(lhs, signal_names)),
            Box::new(spec_expr_to_zir(rhs, signal_names)),
        ),
        SpecTransformExpr::Div(lhs, rhs) => crate::zir::Expr::Div(
            Box::new(spec_expr_to_zir(lhs, signal_names)),
            Box::new(spec_expr_to_zir(rhs, signal_names)),
        ),
    }
}

fn spec_expr_to_ir(expr: &SpecTransformExpr, signal_names: &[String]) -> crate::ir::Expr {
    match expr {
        SpecTransformExpr::Const { value, .. } => crate::ir::Expr::Const(value.to_runtime()),
        SpecTransformExpr::Signal { signal_index, .. } => {
            crate::ir::Expr::Signal(signal_names[*signal_index].clone())
        }
        SpecTransformExpr::Add(values) => crate::ir::Expr::Add(
            values
                .iter()
                .map(|value| spec_expr_to_ir(value, signal_names))
                .collect(),
        ),
        SpecTransformExpr::Sub(lhs, rhs) => crate::ir::Expr::Sub(
            Box::new(spec_expr_to_ir(lhs, signal_names)),
            Box::new(spec_expr_to_ir(rhs, signal_names)),
        ),
        SpecTransformExpr::Mul(lhs, rhs) => crate::ir::Expr::Mul(
            Box::new(spec_expr_to_ir(lhs, signal_names)),
            Box::new(spec_expr_to_ir(rhs, signal_names)),
        ),
        SpecTransformExpr::Div(lhs, rhs) => crate::ir::Expr::Div(
            Box::new(spec_expr_to_ir(lhs, signal_names)),
            Box::new(spec_expr_to_ir(rhs, signal_names)),
        ),
    }
}

fn label_from_key(label_key: usize, labels: &[Option<String>]) -> Option<String> {
    labels.get(label_key).cloned().unwrap_or(None)
}

#[cfg(feature = "full")]
fn zir_signal_names(program: &crate::zir::Program) -> Vec<String> {
    program
        .signals
        .iter()
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>()
}

#[cfg(feature = "full")]
fn zir_constraint_labels(program: &crate::zir::Program) -> Vec<Option<String>> {
    std::iter::once(None)
        .chain(
            program
                .constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    crate::zir::Constraint::Equal { label, .. }
                    | crate::zir::Constraint::Boolean { label, .. }
                    | crate::zir::Constraint::Range { label, .. } => label.clone(),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Some),
        )
        .collect::<Vec<_>>()
}

#[cfg(feature = "full")]
fn runtime_zir_program_from_spec(
    program: &crate::zir::Program,
    normalized_program: &SpecTransformProgram,
) -> crate::zir::Program {
    let signal_names = zir_signal_names(program);
    let labels = zir_constraint_labels(program);
    let constraints = normalized_program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            SpecTransformConstraint::Equal {
                lhs,
                rhs,
                label_key,
            } => crate::zir::Constraint::Equal {
                lhs: spec_expr_to_zir(lhs, &signal_names),
                rhs: spec_expr_to_zir(rhs, &signal_names),
                label: label_from_key(*label_key, &labels),
            },
            SpecTransformConstraint::Boolean {
                signal_index,
                label_key,
                ..
            } => crate::zir::Constraint::Boolean {
                signal: signal_names[*signal_index].clone(),
                label: label_from_key(*label_key, &labels),
            },
            SpecTransformConstraint::Range {
                signal_index,
                bits,
                label_key,
                ..
            } => crate::zir::Constraint::Range {
                signal: signal_names[*signal_index].clone(),
                bits: *bits,
                label: label_from_key(*label_key, &labels),
            },
        })
        .collect::<Vec<_>>();
    let signals = normalized_program
        .signals
        .iter()
        .map(|signal| program.signals[signal.signal_index].clone())
        .collect::<Vec<_>>();

    crate::zir::Program {
        name: program.name.clone(),
        field: program.field,
        signals,
        constraints,
        witness_plan: program.witness_plan.clone(),
        lookup_tables: program.lookup_tables.clone(),
        memory_regions: program.memory_regions.clone(),
        custom_gates: program.custom_gates.clone(),
        metadata: program.metadata.clone(),
    }
}

#[cfg(feature = "full")]
pub(crate) struct RuntimeNormalizationIdempotency {
    pub(crate) report: crate::normalize::NormalizationReport,
    pub(crate) second_output_digest: String,
}

#[cfg(feature = "full")]
pub(crate) fn normalize_supported_program_idempotency_runtime(
    program: &crate::zir::Program,
) -> Option<RuntimeNormalizationIdempotency> {
    if !supports_normalization_proof_subset(program) {
        return None;
    }
    let spec_program = translate_supported_zir_program(program).ok()?;
    let normalized = normalize_supported_program(&spec_program);
    let result = runtime_zir_program_from_spec(program, &normalized.program);
    let output_digest = result.digest_hex();
    let second = normalize_supported_program(&normalized.program);
    let second_output_digest = if second.program == normalized.program {
        output_digest.clone()
    } else {
        runtime_zir_program_from_spec(program, &second.program).digest_hex()
    };

    Some(RuntimeNormalizationIdempotency {
        report: crate::normalize::NormalizationReport {
            algebraic_rewrites: normalized.report.algebraic_rewrites,
            constant_folds: normalized.report.constant_folds,
            cse_eliminations: 0,
            dead_signals_removed: normalized.report.dead_signals_removed,
            input_digest: program.digest_hex(),
            output_digest,
        },
        second_output_digest,
    })
}

#[cfg(feature = "full")]
pub(crate) fn normalize_supported_program_runtime(
    program: &crate::zir::Program,
) -> Option<(crate::zir::Program, crate::normalize::NormalizationReport)> {
    let spec_program = translate_supported_zir_program(program).ok()?;
    let normalized = normalize_supported_program(&spec_program);
    let result = runtime_zir_program_from_spec(program, &normalized.program);
    let output_digest = result.digest_hex();
    Some((
        result,
        crate::normalize::NormalizationReport {
            algebraic_rewrites: normalized.report.algebraic_rewrites,
            constant_folds: normalized.report.constant_folds,
            cse_eliminations: 0,
            dead_signals_removed: normalized.report.dead_signals_removed,
            input_digest: program.digest_hex(),
            output_digest,
        },
    ))
}

#[cfg(feature = "full")]
pub(crate) fn optimize_supported_ir_runtime(
    program: &crate::ir::Program,
) -> Option<(crate::ir::Program, crate::optimizer::OptimizeReport)> {
    if !supports_optimizer_ir_proof_subset(program) {
        return None;
    }
    let spec_program = translate_supported_ir_program(program).ok()?;
    let optimized = optimize_supported_ir_program(&spec_program);
    let signal_names = program
        .signals
        .iter()
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();
    let labels = std::iter::once(None)
        .chain(
            program
                .constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    crate::ir::Constraint::Equal { label, .. }
                    | crate::ir::Constraint::Boolean { label, .. }
                    | crate::ir::Constraint::Range { label, .. } => label.clone(),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Some),
        )
        .collect::<Vec<_>>();
    let constraints = optimized
        .program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            SpecTransformConstraint::Equal {
                lhs,
                rhs,
                label_key,
            } => crate::ir::Constraint::Equal {
                lhs: spec_expr_to_ir(lhs, &signal_names),
                rhs: spec_expr_to_ir(rhs, &signal_names),
                label: label_from_key(*label_key, &labels),
            },
            SpecTransformConstraint::Boolean {
                signal_index,
                label_key,
                ..
            } => crate::ir::Constraint::Boolean {
                signal: signal_names[*signal_index].clone(),
                label: label_from_key(*label_key, &labels),
            },
            SpecTransformConstraint::Range {
                signal_index,
                bits,
                label_key,
                ..
            } => crate::ir::Constraint::Range {
                signal: signal_names[*signal_index].clone(),
                bits: *bits,
                label: label_from_key(*label_key, &labels),
            },
        })
        .collect::<Vec<_>>();
    let signals = optimized
        .program
        .signals
        .iter()
        .map(|signal| program.signals[signal.signal_index].clone())
        .collect::<Vec<_>>();
    let assignments = optimized
        .program
        .assignments
        .iter()
        .map(|assignment| crate::WitnessAssignment {
            target: signal_names[assignment.target_signal_index].clone(),
            expr: spec_expr_to_ir(&assignment.expr, &signal_names),
        })
        .collect::<Vec<_>>();
    let hints = optimized
        .program
        .hints
        .iter()
        .map(|hint| crate::WitnessHint {
            target: signal_names[hint.target_signal_index].clone(),
            source: signal_names[hint.source_signal_index].clone(),
            kind: crate::WitnessHintKind::Copy,
        })
        .collect::<Vec<_>>();

    Some((
        crate::ir::Program {
            name: program.name.clone(),
            field: program.field,
            signals,
            constraints,
            witness_plan: crate::WitnessPlan {
                assignments,
                hints,
                input_aliases: program.witness_plan.input_aliases.clone(),
                acir_program_bytes: program.witness_plan.acir_program_bytes.clone(),
            },
            lookup_tables: program.lookup_tables.clone(),
            metadata: program.metadata.clone(),
        },
        crate::optimizer::OptimizeReport {
            input_signals: program.signals.len(),
            output_signals: optimized.program.signals.len(),
            input_constraints: program.constraints.len(),
            output_constraints: optimized.program.constraints.len(),
            folded_expr_nodes: optimized.report.folded_expr_nodes,
            deduplicated_constraints: optimized.report.deduplicated_constraints,
            removed_tautology_constraints: optimized.report.removed_tautology_constraints,
            removed_private_signals: optimized.report.removed_private_signals,
        },
    ))
}

#[cfg(feature = "full")]
pub(crate) fn optimize_supported_zir_runtime(
    program: &crate::zir::Program,
) -> Option<(crate::zir::Program, crate::optimizer_zir::ZirOptimizeReport)> {
    if !supports_optimizer_zir_proof_subset(program) {
        return None;
    }
    let spec_program = translate_supported_zir_program(program).ok()?;
    let optimized = optimize_supported_zir_program(&spec_program);
    let signal_names = program
        .signals
        .iter()
        .map(|signal| signal.name.clone())
        .collect::<Vec<_>>();
    let labels = std::iter::once(None)
        .chain(
            program
                .constraints
                .iter()
                .filter_map(|constraint| match constraint {
                    crate::zir::Constraint::Equal { label, .. }
                    | crate::zir::Constraint::Boolean { label, .. }
                    | crate::zir::Constraint::Range { label, .. } => label.clone(),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(Some),
        )
        .collect::<Vec<_>>();
    let constraints = optimized
        .program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            SpecTransformConstraint::Equal {
                lhs,
                rhs,
                label_key,
            } => crate::zir::Constraint::Equal {
                lhs: spec_expr_to_zir(lhs, &signal_names),
                rhs: spec_expr_to_zir(rhs, &signal_names),
                label: label_from_key(*label_key, &labels),
            },
            SpecTransformConstraint::Boolean {
                signal_index,
                label_key,
                ..
            } => crate::zir::Constraint::Boolean {
                signal: signal_names[*signal_index].clone(),
                label: label_from_key(*label_key, &labels),
            },
            SpecTransformConstraint::Range {
                signal_index,
                bits,
                label_key,
                ..
            } => crate::zir::Constraint::Range {
                signal: signal_names[*signal_index].clone(),
                bits: *bits,
                label: label_from_key(*label_key, &labels),
            },
        })
        .collect::<Vec<_>>();
    let signals = optimized
        .program
        .signals
        .iter()
        .map(|signal| program.signals[signal.signal_index].clone())
        .collect::<Vec<_>>();

    Some((
        crate::zir::Program {
            name: program.name.clone(),
            field: program.field,
            signals,
            constraints,
            witness_plan: program.witness_plan.clone(),
            lookup_tables: program.lookup_tables.clone(),
            memory_regions: program.memory_regions.clone(),
            custom_gates: program.custom_gates.clone(),
            metadata: program.metadata.clone(),
        },
        crate::optimizer_zir::ZirOptimizeReport {
            input_signals: program.signals.len(),
            output_signals: optimized.program.signals.len(),
            input_constraints: program.constraints.len(),
            output_constraints: optimized.program.constraints.len(),
            folded_expr_nodes: optimized.report.folded_expr_nodes,
            deduplicated_constraints: optimized.report.deduplicated_constraints,
            removed_tautology_constraints: optimized.report.removed_tautology_constraints,
            removed_private_signals: optimized.report.removed_private_signals,
        },
    ))
}
