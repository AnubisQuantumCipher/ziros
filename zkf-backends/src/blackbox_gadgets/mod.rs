//! BlackBox constraint lowering — converts `Constraint::BlackBox` into
//! equivalent arithmetic constraints (`Equal`, `Boolean`, `Range`) that
//! proving backends can actually enforce in-circuit.
//!
//! Without this lowering, BlackBox constraints are silently skipped during
//! circuit synthesis, creating a **soundness gap**: a malicious prover can
//! claim arbitrary outputs for hash functions, signature verifications, etc.
//! and the proof will verify.
//!
//! This module closes that gap by expressing each BlackBox operation as
//! field-arithmetic constraints over the program's native field.

mod bits;
mod blake2s;
mod ec_ops;
pub(crate) mod ecdsa;
mod keccak256;
pub mod lookup_lowering;
mod pedersen;
pub(crate) mod poseidon2;
mod schnorr;
pub(crate) mod sha256;

use num_bigint::BigInt;
use std::collections::BTreeMap;
use zkf_core::{
    BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, Witness,
    ZkfError, ZkfResult,
};

/// Result of lowering a single BlackBox constraint into arithmetic constraints.
#[derive(Debug, Clone, Default)]
pub struct LoweredBlackBox {
    /// New auxiliary signals needed for intermediate computations.
    pub signals: Vec<Signal>,
    /// Arithmetic constraints that enforce the BlackBox relationship.
    pub constraints: Vec<Constraint>,
}

impl LoweredBlackBox {
    fn add_private_signal(&mut self, name: impl Into<String>) -> String {
        let name = name.into();
        self.signals.push(Signal {
            name: name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        name
    }

    fn add_equal(&mut self, lhs: Expr, rhs: Expr, label: impl Into<String>) {
        self.constraints.push(Constraint::Equal {
            lhs,
            rhs,
            label: Some(label.into()),
        });
    }

    fn add_boolean(&mut self, signal: impl Into<String>, label: impl Into<String>) {
        self.constraints.push(Constraint::Boolean {
            signal: signal.into(),
            label: Some(label.into()),
        });
    }

    fn add_range(&mut self, signal: impl Into<String>, bits: u32, label: impl Into<String>) {
        self.constraints.push(Constraint::Range {
            signal: signal.into(),
            bits,
            label: Some(label.into()),
        });
    }
}

/// Counter for generating unique auxiliary signal names.
pub struct AuxCounter {
    prefix: String,
    count: usize,
}

impl AuxCounter {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            count: 0,
        }
    }

    pub fn next(&mut self, suffix: &str) -> String {
        let name = format!("__bb_{}_{suffix}_{}", self.prefix, self.count);
        self.count += 1;
        name
    }
}

pub(crate) fn constraint_instance_suffix(label: &Option<String>, index: usize) -> String {
    match label {
        Some(label) if !label.is_empty() => format!("{label}_{index}"),
        _ => index.to_string(),
    }
}

pub(crate) fn blackbox_aux_prefix(op: BlackBoxOp, label: &Option<String>, index: usize) -> String {
    format!(
        "{}_{}",
        op.as_str(),
        constraint_instance_suffix(label, index)
    )
}

/// Lower all `Constraint::BlackBox` in a program into arithmetic constraints.
///
/// Returns a new `Program` with no remaining BlackBox constraints (except
/// `RecursiveAggregationMarker` which is a proof-composition marker, not a
/// computation).
///
/// This must be called BEFORE circuit synthesis (compile) so the proving key
/// includes the expanded constraints.
pub fn lower_blackbox_program(program: &Program) -> ZkfResult<Program> {
    let mut new_signals = program.signals.clone();
    let mut new_constraints = Vec::with_capacity(program.constraints.len());

    for (idx, constraint) in program.constraints.iter().enumerate() {
        match constraint {
            Constraint::BlackBox {
                op,
                inputs,
                outputs,
                params,
                label,
            } => {
                // RecursiveAggregationMarker is a metadata-level composition marker,
                // NOT an in-circuit recursive verifier. The host re-verifies proofs
                // during composition; this marker is kept for backend metadata only.
                if *op == BlackBoxOp::RecursiveAggregationMarker {
                    new_constraints.push(constraint.clone());
                    continue;
                }

                let prefix = blackbox_aux_prefix(*op, label, idx);
                let mut aux = AuxCounter::new(&prefix);

                let lowered =
                    lower_single_blackbox(*op, inputs, outputs, params, program.field, &mut aux)
                        .map_err(|e| {
                            ZkfError::Backend(format!(
                                "failed to lower blackbox constraint {} ({}): {}",
                                idx,
                                op.as_str(),
                                e
                            ))
                        })?;

                new_signals.extend(lowered.signals);
                new_constraints.extend(lowered.constraints);
            }
            other => {
                new_constraints.push(other.clone());
            }
        }
    }

    let mut lowered = program.clone();
    lowered.signals = new_signals;
    lowered.constraints = new_constraints;
    Ok(lowered)
}

/// Compute auxiliary witness values for the lowered program.
///
/// After `lower_blackbox_program` adds auxiliary signals, this function
/// computes their values from the existing witness inputs/outputs.
pub fn compute_blackbox_aux_witness(
    original_program: &Program,
    _lowered_program: &Program,
    witness: &Witness,
) -> ZkfResult<Witness> {
    let mut new_values = witness.values.clone();

    for (constraint_index, constraint) in original_program.constraints.iter().enumerate() {
        let Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } = constraint
        else {
            continue;
        };

        if *op == BlackBoxOp::RecursiveAggregationMarker {
            continue;
        }

        let input_values: Vec<BigInt> = inputs
            .iter()
            .map(|expr| zkf_core::eval_expr(expr, &witness.values, original_program.field))
            .collect::<ZkfResult<Vec<_>>>()?;

        let outputs_present = outputs.iter().all(|name| witness.values.contains_key(name));
        let output_values: Vec<BigInt> = if outputs_present {
            outputs
                .iter()
                .map(|name| {
                    witness
                        .values
                        .get(name)
                        .ok_or_else(|| ZkfError::MissingWitnessValue {
                            signal: name.clone(),
                        })
                        .and_then(|fe| fe.normalized_bigint(original_program.field))
                })
                .collect::<ZkfResult<Vec<_>>>()?
        } else {
            Vec::new()
        };

        compute_single_blackbox_witness(
            *op,
            &input_values,
            &output_values,
            params,
            original_program.field,
            label,
            constraint_index,
            &mut new_values,
        )?;
    }

    Ok(Witness { values: new_values })
}

fn lower_single_blackbox(
    op: BlackBoxOp,
    inputs: &[Expr],
    outputs: &[String],
    params: &BTreeMap<String, String>,
    field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    match op {
        BlackBoxOp::Poseidon | BlackBoxOp::Sha256 => {
            crate::proof_blackbox_hash_spec::lower_hash_blackbox(
                op, inputs, outputs, params, field, aux,
            )
        }
        BlackBoxOp::Blake2s => blake2s::lower_blake2s(inputs, outputs, params, field, aux),
        BlackBoxOp::Keccak256 => keccak256::lower_keccak256(inputs, outputs, params, field, aux),
        BlackBoxOp::Pedersen => pedersen::lower_pedersen(inputs, outputs, params, field, aux),
        BlackBoxOp::EcdsaSecp256k1 => crate::proof_blackbox_ecdsa_spec::lower_ecdsa_blackbox(
            crate::proof_blackbox_ecdsa_spec::SupportedCriticalEcdsaCurve::Secp256k1,
            inputs,
            outputs,
            params,
            field,
            aux,
        ),
        BlackBoxOp::EcdsaSecp256r1 => crate::proof_blackbox_ecdsa_spec::lower_ecdsa_blackbox(
            crate::proof_blackbox_ecdsa_spec::SupportedCriticalEcdsaCurve::Secp256r1,
            inputs,
            outputs,
            params,
            field,
            aux,
        ),
        BlackBoxOp::SchnorrVerify => schnorr::lower_schnorr(inputs, outputs, params, field, aux),
        BlackBoxOp::ScalarMulG1 => ec_ops::lower_scalar_mul_g1(inputs, outputs, params, field, aux),
        BlackBoxOp::PointAddG1 => ec_ops::lower_point_add_g1(inputs, outputs, params, field, aux),
        BlackBoxOp::PairingCheck => {
            ec_ops::lower_pairing_check(inputs, outputs, params, field, aux)
        }
        BlackBoxOp::RecursiveAggregationMarker => {
            unreachable!("RecursiveAggregationMarker handled before dispatch")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_single_blackbox_witness(
    op: BlackBoxOp,
    input_values: &[BigInt],
    output_values: &[BigInt],
    params: &BTreeMap<String, String>,
    field: FieldId,
    label: &Option<String>,
    index: usize,
    witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    match op {
        BlackBoxOp::Poseidon | BlackBoxOp::Sha256 => {
            crate::proof_blackbox_hash_spec::compute_hash_aux_witness(
                op,
                input_values,
                output_values,
                params,
                field,
                label,
                witness_values,
            )
        }
        BlackBoxOp::Blake2s => blake2s::compute_blake2s_witness(
            input_values,
            output_values,
            params,
            field,
            label,
            witness_values,
        ),
        BlackBoxOp::Keccak256 => keccak256::compute_keccak256_witness(
            input_values,
            output_values,
            params,
            field,
            label,
            witness_values,
        ),
        BlackBoxOp::Pedersen => pedersen::compute_pedersen_witness(
            input_values,
            output_values,
            params,
            field,
            label,
            witness_values,
        ),
        BlackBoxOp::EcdsaSecp256k1 | BlackBoxOp::EcdsaSecp256r1 => {
            let curve = match op {
                BlackBoxOp::EcdsaSecp256k1 => {
                    crate::proof_blackbox_ecdsa_spec::SupportedCriticalEcdsaCurve::Secp256k1
                }
                BlackBoxOp::EcdsaSecp256r1 => {
                    crate::proof_blackbox_ecdsa_spec::SupportedCriticalEcdsaCurve::Secp256r1
                }
                _ => unreachable!("ecdsa witness dispatch only reaches ecdsa ops"),
            };
            crate::proof_blackbox_ecdsa_spec::compute_ecdsa_aux_witness(
                curve,
                input_values,
                output_values,
                params,
                field,
                label,
                index,
                witness_values,
            )
        }
        BlackBoxOp::SchnorrVerify => schnorr::compute_schnorr_witness(
            input_values,
            output_values,
            params,
            field,
            label,
            witness_values,
        ),
        BlackBoxOp::ScalarMulG1 | BlackBoxOp::PointAddG1 | BlackBoxOp::PairingCheck => {
            ec_ops::compute_ec_witness(
                op,
                input_values,
                output_values,
                params,
                field,
                label,
                index,
                witness_values,
            )
        }
        BlackBoxOp::RecursiveAggregationMarker => Ok(()),
    }
}

/// Enrich a witness with auxiliary signal values needed by the lowered program.
///
/// If `compiled.original_program` is `Some`, this resolves auxiliary signals
/// introduced by BlackBox lowering by evaluating constraints in order.
/// If no original program is stored (no BlackBox constraints were lowered),
/// returns the witness as-is.
#[allow(clippy::collapsible_if, clippy::single_match)]
pub fn enrich_witness_for_proving(
    compiled: &zkf_core::CompiledProgram,
    witness: &Witness,
) -> ZkfResult<Witness> {
    // Start with the user-provided witness values.
    let mut values = witness.values.clone();

    // Also set constant values for any aux signals that have constants defined.
    for signal in &compiled.program.signals {
        if let Some(constant) = &signal.constant {
            values
                .entry(signal.name.clone())
                .or_insert_with(|| constant.clone());
        }
    }

    // If the compiled artifact preserved the pre-lowering program, populate any
    // BlackBox-specific auxiliary witness values first. Generic Equal-based
    // solving cannot derive nonlinear EC/Pedersen internals such as lambda
    // slopes, so these need the operation-aware enrichers.
    if let Some(original_program) = &compiled.original_program {
        let base_witness = Witness {
            values: values.clone(),
        };
        let enriched =
            compute_blackbox_aux_witness(original_program, &compiled.program, &base_witness)?;
        values = enriched.values;
    }

    // Solve aux signals by iterating through lowered constraints.
    // Aux signals are those in the lowered program but NOT in the original.
    // For Equal constraints of the form `Signal(aux) = expr`, evaluate expr
    // to determine aux's value. We may need multiple passes since some aux
    // signals depend on other aux signals.
    let max_passes = 200;
    for _ in 0..max_passes {
        let mut progress = false;
        for constraint in &compiled.program.constraints {
            match constraint {
                Constraint::Equal { lhs, rhs, .. } => {
                    // Try: lhs is Signal(name) not yet known, rhs is evaluable
                    if let Expr::Signal(name) = lhs {
                        if !values.contains_key(name) {
                            if let Ok(val) = try_eval_expr(rhs, &values, compiled.program.field) {
                                values.insert(name.clone(), val);
                                progress = true;
                                continue;
                            }
                        }
                    }
                    // Try: rhs is Signal(name) not yet known, lhs is evaluable
                    if let Expr::Signal(name) = rhs {
                        if !values.contains_key(name) {
                            if let Ok(val) = try_eval_expr(lhs, &values, compiled.program.field) {
                                values.insert(name.clone(), val);
                                progress = true;
                                continue;
                            }
                        }
                    }
                    // Try bit decomposition pattern:
                    // value_expr = Add([Mul(coeff, Signal(bit_i)), ...])
                    // If value is known but bits are not, decompose.
                    if let Ok(val) = try_eval_expr(lhs, &values, compiled.program.field) {
                        if try_solve_bit_decompose(rhs, &val, compiled.program.field, &mut values) {
                            progress = true;
                            continue;
                        }
                    }
                    if let Ok(val) = try_eval_expr(rhs, &values, compiled.program.field) {
                        if try_solve_bit_decompose(lhs, &val, compiled.program.field, &mut values) {
                            progress = true;
                            continue;
                        }
                    }
                    // Try multi-unknown Equal: lhs has unknowns, rhs evaluable (or vice versa)
                    // Pattern: Add([Signal(result), Mul(2^32, Signal(carry))]) = known_sum
                    // Solve: result = known_sum mod 2^32, carry = known_sum / 2^32
                    if let Ok(rhs_val) = try_eval_expr(rhs, &values, compiled.program.field) {
                        if try_solve_sum_carry(lhs, &rhs_val, compiled.program.field, &mut values) {
                            progress = true;
                            continue;
                        }
                    }
                    if let Ok(lhs_val) = try_eval_expr(lhs, &values, compiled.program.field) {
                        if try_solve_sum_carry(rhs, &lhs_val, compiled.program.field, &mut values) {
                            progress = true;
                            continue;
                        }
                    }
                }
                _ => {}
            }
        }
        if !progress {
            break;
        }
    }

    // ── Lookup selector solver ──────────────────────────────────────────────
    // The lookup lowering creates N boolean indicator signals (selectors) for an
    // N-row table, constrained by:
    //   (1) Boolean: sel_i * (1 - sel_i) = 0
    //   (2) One-hot: sel_0 + sel_1 + ... + sel_{N-1} = 1
    //   (3) Column-match: input_j = sel_0 * v[0][j] + ... + sel_{N-1} * v[N-1][j]
    //
    // If all input signals are known but selectors are not, we can solve:
    //   find row r such that all column-match constraints are satisfied for r,
    //   then set sel_r = 1 and all other sel_i = 0.
    //
    // We detect this pattern by looking for boolean-constrained signals that
    // form a one-hot group (sum-to-1 constraint) and column-match constraints.
    let progress = solve_lookup_selectors(
        &compiled.program.constraints,
        &mut values,
        compiled.program.field,
    );
    let _ = progress;

    Ok(Witness { values })
}

/// Solve lookup indicator/selector signals from one-hot + column-match constraints.
///
/// Returns true if any selector values were newly determined.
fn solve_lookup_selectors(
    constraints: &[Constraint],
    values: &mut BTreeMap<String, FieldElement>,
    field: FieldId,
) -> bool {
    use std::collections::HashSet;

    // Collect boolean-constrained signals.
    let boolean_signals: HashSet<String> = constraints
        .iter()
        .filter_map(|c| {
            if let Constraint::Boolean { signal, .. } = c {
                Some(signal.clone())
            } else {
                None
            }
        })
        .collect();

    if boolean_signals.is_empty() {
        return false;
    }

    // Find one-hot groups: Equal { lhs: Add([sig0, sig1, ...]), rhs: Const(1) }
    // where all signals are boolean and unknown.
    let mut any_progress = false;

    'outer: for constraint in constraints {
        let Constraint::Equal { lhs, rhs, .. } = constraint else {
            continue;
        };

        // Normalise: one side is Const(1), the other is Add of signals.
        let (sum_expr, _const_one) = if matches!(rhs, Expr::Const(c) if c == &FieldElement::from_i64(1))
        {
            (lhs, rhs)
        } else if matches!(lhs, Expr::Const(c) if c == &FieldElement::from_i64(1)) {
            (rhs, lhs)
        } else {
            continue;
        };

        // The sum must be Add([Signal(s0), Signal(s1), ...]).
        let Expr::Add(terms) = sum_expr else { continue };

        let selector_names: Vec<String> = terms
            .iter()
            .filter_map(|t| {
                if let Expr::Signal(name) = t {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect();

        // All terms must be plain signals.
        if selector_names.len() != terms.len() {
            continue;
        }

        // All must be boolean-constrained.
        if !selector_names.iter().all(|s| boolean_signals.contains(s)) {
            continue;
        }

        // At least one selector must be unknown.
        if selector_names.iter().all(|s| values.contains_key(s)) {
            continue;
        }

        let n_rows = selector_names.len();

        // Find column-match constraints for this group:
        // Equal { lhs: Signal(known_input), rhs: Add([Mul(sel_i, Const(v_i)), ...]) }
        // or vice versa, where sel_i are from selector_names (in order).
        //
        // Collect table values per column: column_values[col] = [v_0, v_1, ..., v_{N-1}]
        let mut column_data: Vec<(String, Vec<FieldElement>)> = Vec::new();

        for c2 in constraints {
            let Constraint::Equal {
                lhs: l2, rhs: r2, ..
            } = c2
            else {
                continue;
            };

            // Identify: one side is Signal(input), other is Add of Mul(sel_i, Const)
            let (input_expr, mul_sum_expr) = if matches!(l2, Expr::Signal(_)) {
                (l2, r2)
            } else if matches!(r2, Expr::Signal(_)) {
                (r2, l2)
            } else {
                continue;
            };

            let Expr::Signal(input_name) = input_expr else {
                continue;
            };

            // The mul_sum must be Add([Mul(Signal(sel_i), Const(v_i)), ...]) for all n_rows selectors.
            let Expr::Add(mul_terms) = mul_sum_expr else {
                continue;
            };
            if mul_terms.len() != n_rows {
                continue;
            }

            let mut col_vals = vec![FieldElement::from_i64(0); n_rows];
            let mut matches_selectors = true;
            for (j, term) in mul_terms.iter().enumerate() {
                let Expr::Mul(a, b) = term else {
                    matches_selectors = false;
                    break;
                };
                let (sel_expr, val_expr) = match (a.as_ref(), b.as_ref()) {
                    (Expr::Signal(s), Expr::Const(v)) => (s, v),
                    (Expr::Const(v), Expr::Signal(s)) => (s, v),
                    _ => {
                        matches_selectors = false;
                        break;
                    }
                };
                // The sel must be selector_names[j] (order must match)
                if sel_expr != &selector_names[j] {
                    matches_selectors = false;
                    break;
                }
                col_vals[j] = val_expr.clone();
            }
            if !matches_selectors {
                continue;
            }
            column_data.push((input_name.clone(), col_vals));
        }

        if column_data.is_empty() {
            continue;
        }

        // Try to find a unique row that satisfies all column-match constraints
        // for the known input values.
        let mut matching_row: Option<usize> = None;
        'row: for row in 0..n_rows {
            for (input_name, col_vals) in &column_data {
                let Some(input_val) = values.get(input_name) else {
                    continue 'outer;
                };
                let input_bi = match input_val.normalized_bigint(field) {
                    Ok(v) => v,
                    Err(_) => continue 'outer,
                };
                let col_bi = match col_vals[row].normalized_bigint(field) {
                    Ok(v) => v,
                    Err(_) => continue 'outer,
                };
                if input_bi != col_bi {
                    continue 'row;
                }
            }
            // This row matches all column constraints.
            if matching_row.is_some() {
                // Ambiguous — more than one matching row, can't solve uniquely.
                continue 'outer;
            }
            matching_row = Some(row);
        }

        let Some(selected) = matching_row else {
            continue;
        };

        // Set sel_selected = 1, all others = 0.
        for (i, sel_name) in selector_names.iter().enumerate() {
            if !values.contains_key(sel_name) {
                let v = if i == selected {
                    FieldElement::from_i64(1)
                } else {
                    FieldElement::from_i64(0)
                };
                values.insert(sel_name.clone(), v);
                any_progress = true;
            }
        }
    }

    any_progress
}

/// Try to evaluate an expression using known witness values.
/// Returns Err if any referenced signal is unknown.
fn try_eval_expr(
    expr: &Expr,
    values: &BTreeMap<String, FieldElement>,
    field: FieldId,
) -> ZkfResult<FieldElement> {
    match expr {
        Expr::Const(v) => Ok(v.clone()),
        Expr::Signal(name) => {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: name.clone(),
                })
        }
        Expr::Add(items) => {
            let mut sum = BigInt::from(0);
            for item in items {
                let v = try_eval_expr(item, values, field)?;
                let bi = v.normalized_bigint(field)?;
                sum += bi;
            }
            Ok(FieldElement::from_bigint_with_field(sum, field))
        }
        Expr::Sub(a, b) => {
            let av = try_eval_expr(a, values, field)?.normalized_bigint(field)?;
            let bv = try_eval_expr(b, values, field)?.normalized_bigint(field)?;
            Ok(FieldElement::from_bigint_with_field(av - bv, field))
        }
        Expr::Mul(a, b) => {
            let av = try_eval_expr(a, values, field)?.normalized_bigint(field)?;
            let bv = try_eval_expr(b, values, field)?.normalized_bigint(field)?;
            Ok(FieldElement::from_bigint_with_field(av * bv, field))
        }
        Expr::Div(a, b) => {
            let av = try_eval_expr(a, values, field)?;
            let bv = try_eval_expr(b, values, field)?;
            // Use zkf_core's field division
            let av_bi = av.normalized_bigint(field)?;
            let bv_bi = bv.normalized_bigint(field)?;
            if bv_bi == BigInt::from(0) {
                return Err(ZkfError::Backend(
                    "division by zero in aux witness".to_string(),
                ));
            }
            // Field division: a * b^(-1) mod p
            let modulus = field.modulus().clone();
            let inv = mod_inverse(&bv_bi, &modulus).ok_or_else(|| {
                ZkfError::Backend("no modular inverse in aux witness".to_string())
            })?;
            let result = (av_bi * inv) % &modulus;
            Ok(FieldElement::from_bigint_with_field(result, field))
        }
    }
}

/// Try to solve a bit-decomposition pattern: `Add([Mul(2^i, Signal(bit_i)), ...])`
/// where `value` is the known value and some/all bit signals are unknown.
#[allow(clippy::collapsible_if)]
fn try_solve_bit_decompose(
    expr: &Expr,
    value: &FieldElement,
    field: FieldId,
    values: &mut BTreeMap<String, FieldElement>,
) -> bool {
    let Expr::Add(terms) = expr else {
        // Single-term case: Mul(coeff, Signal(bit))
        if let Expr::Mul(coeff_expr, sig_expr) = expr {
            if let (Expr::Const(coeff), Expr::Signal(name)) =
                (coeff_expr.as_ref(), sig_expr.as_ref())
            {
                if !values.contains_key(name) {
                    if let Ok(c) = coeff.normalized_bigint(field) {
                        if let Ok(v) = value.normalized_bigint(field) {
                            if c != BigInt::from(0) {
                                let modulus = field.modulus().clone();
                                if let Some(inv) = mod_inverse(&c, &modulus) {
                                    let bit_val = (v * inv) % &modulus;
                                    values.insert(
                                        name.clone(),
                                        FieldElement::from_bigint_with_field(bit_val, field),
                                    );
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    };

    // Check if this looks like a bit decomposition: Add([Mul(2^i, Signal), ...])
    // where coefficients are powers of 2
    let mut bit_entries: Vec<(u32, String)> = Vec::new();
    let mut all_power_of_two = true;

    for term in terms {
        match term {
            Expr::Mul(coeff_expr, sig_expr) => {
                if let (Expr::Const(coeff), Expr::Signal(name)) =
                    (coeff_expr.as_ref(), sig_expr.as_ref())
                {
                    if let Ok(c) = coeff.normalized_bigint(field) {
                        if let Some(bit_pos) = power_of_two_exponent(&c) {
                            bit_entries.push((bit_pos, name.clone()));
                            continue;
                        }
                    }
                }
                all_power_of_two = false;
                break;
            }
            _ => {
                all_power_of_two = false;
                break;
            }
        }
    }

    if !all_power_of_two || bit_entries.is_empty() {
        return false;
    }

    // Check if any bits are unknown
    let has_unknown = bit_entries
        .iter()
        .any(|(_, name)| !values.contains_key(name));
    if !has_unknown {
        return false;
    }

    // Decompose the value into bits
    if let Ok(v) = value.normalized_bigint(field) {
        let mut progress = false;
        for (bit_pos, name) in &bit_entries {
            if !values.contains_key(name) {
                let bit_val = (&v >> *bit_pos) & BigInt::from(1);
                values.insert(
                    name.clone(),
                    FieldElement::from_bigint_with_field(bit_val, field),
                );
                progress = true;
            }
        }
        return progress;
    }

    false
}

/// Check if a BigInt is a power of 2 and return the exponent.
fn power_of_two_exponent(n: &BigInt) -> Option<u32> {
    if *n <= BigInt::from(0) {
        return None;
    }
    let bits = n.bits();
    // A power of 2 has exactly one bit set
    if n == &(BigInt::from(1) << (bits - 1)) {
        Some((bits - 1) as u32)
    } else {
        None
    }
}

/// Try to solve a sum+carry pattern:
/// `Add([Signal(result), Mul(2^32, Signal(carry))]) = known_value`
/// where result = value mod 2^32 and carry = value / 2^32.
fn try_solve_sum_carry(
    expr: &Expr,
    total_value: &FieldElement,
    field: FieldId,
    values: &mut BTreeMap<String, FieldElement>,
) -> bool {
    let Expr::Add(terms) = expr else {
        return false;
    };
    if terms.len() != 2 {
        return false;
    }

    // Look for: Signal(result) + Mul(2^32, Signal(carry))
    let (result_name, carry_name) = match (&terms[0], &terms[1]) {
        (Expr::Signal(r), Expr::Mul(coeff, sig)) | (Expr::Mul(coeff, sig), Expr::Signal(r)) => {
            if let (Expr::Const(c), Expr::Signal(s)) = (coeff.as_ref(), sig.as_ref()) {
                if let Ok(cv) = c.normalized_bigint(field) {
                    if cv == (BigInt::from(1) << 32) {
                        (r.clone(), s.clone())
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        _ => return false,
    };

    // Only solve if both are unknown
    if values.contains_key(&result_name) || values.contains_key(&carry_name) {
        return false;
    }

    if let Ok(total) = total_value.normalized_bigint(field) {
        let mod32 = BigInt::from(1u64 << 32);
        let result_val = &total % &mod32;
        let carry_val = &total / &mod32;
        values.insert(
            result_name,
            FieldElement::from_bigint_with_field(result_val, field),
        );
        values.insert(
            carry_name,
            FieldElement::from_bigint_with_field(carry_val, field),
        );
        return true;
    }

    false
}

fn mod_inverse(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
    let zero = BigInt::from(0);
    let one = BigInt::from(1);

    let a = ((a % modulus) + modulus) % modulus;
    if a == zero {
        return None;
    }

    // Extended Euclidean algorithm
    let mut old_r = a;
    let mut r = modulus.clone();
    let mut old_s = one.clone();
    let mut s = zero.clone();

    while r != zero {
        let q = &old_r / &r;
        let temp_r = r.clone();
        r = old_r - &q * &r;
        old_r = temp_r;
        let temp_s = s.clone();
        s = old_s - &q * &s;
        old_s = temp_s;
    }

    if old_r != one {
        return None;
    }

    Some(((old_s % modulus) + modulus) % modulus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acir::FieldElement as AcirFieldElement;
    use bn254_blackbox_solver::poseidon2_permutation;
    #[cfg(feature = "native-blackbox-solvers")]
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    #[cfg(feature = "native-blackbox-solvers")]
    use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
    use num_bigint::{BigInt, Sign};
    #[cfg(feature = "native-blackbox-solvers")]
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use std::collections::BTreeSet;
    use zkf_core::{BackendKind, Witness, WitnessPlan, check_constraints};

    fn make_program_with_blackbox_shape(
        op: BlackBoxOp,
        input_count: usize,
        output_count: usize,
    ) -> Program {
        let mut signals = Vec::with_capacity(input_count + output_count);
        let mut inputs = Vec::with_capacity(input_count);
        let mut outputs = Vec::with_capacity(output_count);

        for index in 0..input_count {
            let name = format!("in{index}");
            signals.push(Signal {
                name: name.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            inputs.push(Expr::Signal(name));
        }

        for index in 0..output_count {
            let name = format!("out{index}");
            signals.push(Signal {
                name: name.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            outputs.push(name);
        }

        Program {
            name: "test_bb".to_string(),
            field: FieldId::Bn254,
            signals,
            constraints: vec![Constraint::BlackBox {
                op,
                inputs,
                outputs,
                params: BTreeMap::new(),
                label: Some("test".into()),
            }],
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        }
    }

    fn make_program_with_blackbox(op: BlackBoxOp) -> Program {
        make_program_with_blackbox_shape(op, 1, 1)
    }

    fn make_poseidon_program() -> Program {
        make_program_with_blackbox_shape(BlackBoxOp::Poseidon, 4, 4)
    }

    fn make_double_poseidon_program(label: &str) -> Program {
        let mut signals = Vec::new();
        let mut constraints = Vec::new();

        for call in 0..2 {
            let inputs = (0..4)
                .map(|i| {
                    let name = format!("in{call}_{i}");
                    signals.push(Signal {
                        name: name.clone(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    });
                    Expr::Signal(name)
                })
                .collect();
            let outputs = (0..4)
                .map(|i| {
                    let name = format!("out{call}_{i}");
                    signals.push(Signal {
                        name: name.clone(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    });
                    name
                })
                .collect();
            constraints.push(Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                inputs,
                outputs,
                params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
                label: Some(label.to_string()),
            });
        }

        Program {
            name: "double_poseidon".to_string(),
            field: FieldId::Bn254,
            signals,
            constraints,
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        }
    }

    fn make_ecdsa_program(op: BlackBoxOp) -> Program {
        make_program_with_blackbox_shape(op, 160, 1)
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn encode_ecdsa_abi(uncompressed_pubkey: &[u8], signature: &[u8], msg: &[u8; 32]) -> [u8; 160] {
        assert_eq!(
            uncompressed_pubkey.len(),
            65,
            "expected uncompressed SEC1 pubkey"
        );
        assert_eq!(
            uncompressed_pubkey[0], 0x04,
            "expected uncompressed SEC1 tag"
        );
        assert_eq!(
            signature.len(),
            64,
            "expected compact 64-byte ECDSA signature"
        );

        let mut input = [0u8; 160];
        input[..32].copy_from_slice(&uncompressed_pubkey[1..33]);
        input[32..64].copy_from_slice(&uncompressed_pubkey[33..65]);
        input[64..128].copy_from_slice(signature);
        input[128..160].copy_from_slice(msg);
        input
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn secp256k1_valid_input() -> [u8; 160] {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let signing_key = K256SigningKey::from_bytes(&secret.into()).expect("valid secp256k1 key");
        let msg = [0x11u8; 32];
        let signature: K256Signature = signing_key
            .sign_prehash(&msg)
            .expect("deterministic secp256k1 prehash signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let pubkey = signing_key.verifying_key().to_encoded_point(false);
        encode_ecdsa_abi(pubkey.as_bytes(), signature.to_bytes().as_slice(), &msg)
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn secp256r1_valid_input() -> [u8; 160] {
        let mut secret = [0u8; 32];
        secret[31] = 2;
        let signing_key = P256SigningKey::from_bytes(&secret.into()).expect("valid secp256r1 key");
        let msg = [0x22u8; 32];
        let signature: P256Signature = signing_key
            .sign_prehash(&msg)
            .expect("deterministic secp256r1 prehash signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let pubkey = signing_key.verifying_key().to_encoded_point(false);
        encode_ecdsa_abi(pubkey.as_bytes(), signature.to_bytes().as_slice(), &msg)
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn tamper_ecdsa_message(mut input: [u8; 160]) -> [u8; 160] {
        input[159] ^= 0x01;
        input
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn compiled_ecdsa_program(op: BlackBoxOp) -> zkf_core::CompiledProgram {
        let original = make_ecdsa_program(op);
        let lowered = lower_blackbox_program(&original).expect("ecdsa lowering should succeed");
        let mut compiled = zkf_core::CompiledProgram::new(BackendKind::ArkworksGroth16, lowered);
        compiled.original_program = Some(original);
        compiled
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_witness(input: &[u8; 160], claimed_result: bool) -> Witness {
        let mut values = BTreeMap::new();
        for (index, byte) in input.iter().enumerate() {
            values.insert(
                format!("in{index}"),
                FieldElement::from_i64(i64::from(*byte)),
            );
        }
        values.insert(
            "out0".to_string(),
            FieldElement::from_i64(if claimed_result { 1 } else { 0 }),
        );
        Witness { values }
    }

    #[cfg(feature = "native-blackbox-solvers")]
    fn assert_ecdsa_runtime_case(
        op: BlackBoxOp,
        input: [u8; 160],
        claimed_result: bool,
        should_satisfy: bool,
    ) {
        crate::with_serialized_heavy_backend_test(|| {
            let compiled = compiled_ecdsa_program(op);
            let enriched =
                enrich_witness_for_proving(&compiled, &ecdsa_witness(&input, claimed_result))
                    .expect("ecdsa aux witness enrichment should succeed");
            let checked = check_constraints(&compiled.program, &enriched);
            if should_satisfy {
                checked.expect("ecdsa runtime relation should satisfy lowered constraints");
            } else {
                let err =
                    checked.expect_err("ecdsa runtime relation should reject mismatched branch");
                assert!(
                    err.to_string().contains("constraint"),
                    "expected constraint failure for mismatched ecdsa result, got {err}"
                );
            }
        });
    }

    #[test]
    fn recursive_aggregation_marker_passes_through() {
        let program = make_program_with_blackbox(BlackBoxOp::RecursiveAggregationMarker);
        let lowered = lower_blackbox_program(&program).unwrap();
        assert!(lowered.constraints.iter().any(|c| matches!(
            c,
            Constraint::BlackBox {
                op: BlackBoxOp::RecursiveAggregationMarker,
                ..
            }
        )));
    }

    #[test]
    fn lowered_program_has_no_non_marker_blackbox() {
        // Poseidon lowering should replace the BlackBox with arithmetic constraints
        let mut program = make_poseidon_program();
        // Add state_len param needed by poseidon2
        if let Constraint::BlackBox { params, .. } = &mut program.constraints[0] {
            params.insert("state_len".into(), "4".into());
        }

        let lowered = lower_blackbox_program(&program).unwrap();
        let has_non_marker_bb = lowered.constraints.iter().any(|c| {
            matches!(c, Constraint::BlackBox { op, .. } if *op != BlackBoxOp::RecursiveAggregationMarker)
        });
        assert!(
            !has_non_marker_bb,
            "lowered program should have no non-marker BlackBox constraints"
        );
    }

    #[test]
    fn poseidon_lowering_namespaces_repeated_same_label_invocations() {
        let lowered = lower_blackbox_program(&make_double_poseidon_program("poseidon")).unwrap();
        let signal_names: Vec<_> = lowered
            .signals
            .iter()
            .map(|signal| signal.name.clone())
            .collect();
        let unique_names: BTreeSet<_> = signal_names.iter().cloned().collect();

        assert_eq!(
            signal_names.len(),
            unique_names.len(),
            "repeated same-label poseidon lowering produced duplicate signal names"
        );
        assert!(
            signal_names
                .iter()
                .any(|name| name.starts_with("__bb_poseidon_poseidon_0_")),
            "expected first poseidon invocation to keep its own namespace"
        );
        assert!(
            signal_names
                .iter()
                .any(|name| name.starts_with("__bb_poseidon_poseidon_1_")),
            "expected second poseidon invocation to keep its own namespace"
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256k1_valid_runtime_path_forces_result_one() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256k1,
            secp256k1_valid_input(),
            true,
            true,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256k1_tampered_runtime_path_forces_result_zero() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256k1,
            tamper_ecdsa_message(secp256k1_valid_input()),
            false,
            true,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256k1_valid_signature_rejects_claimed_zero() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256k1,
            secp256k1_valid_input(),
            false,
            false,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256k1_invalid_signature_rejects_claimed_one() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256k1,
            tamper_ecdsa_message(secp256k1_valid_input()),
            true,
            false,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256r1_valid_runtime_path_forces_result_one() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256r1,
            secp256r1_valid_input(),
            true,
            true,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256r1_tampered_runtime_path_forces_result_zero() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256r1,
            tamper_ecdsa_message(secp256r1_valid_input()),
            false,
            true,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256r1_valid_signature_rejects_claimed_zero() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256r1,
            secp256r1_valid_input(),
            false,
            false,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_secp256r1_invalid_signature_rejects_claimed_one() {
        assert_ecdsa_runtime_case(
            BlackBoxOp::EcdsaSecp256r1,
            tamper_ecdsa_message(secp256r1_valid_input()),
            true,
            false,
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_lowering_rejects_malformed_input_length() {
        let program = make_program_with_blackbox_shape(BlackBoxOp::EcdsaSecp256k1, 159, 1);
        let err = lower_blackbox_program(&program)
            .expect_err("ecdsa lowering must reject malformed input length");
        assert!(
            err.to_string().contains("inputs=159"),
            "expected malformed ABI rejection, got: {err}"
        );
    }

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn ecdsa_lowering_rejects_non_bn254_programs() {
        let mut program = make_ecdsa_program(BlackBoxOp::EcdsaSecp256k1);
        program.field = FieldId::Goldilocks;
        let err = lower_blackbox_program(&program)
            .expect_err("ecdsa lowering must reject non-BN254 programs");
        assert!(
            err.to_string().contains("field=goldilocks"),
            "expected non-BN254 rejection, got: {err}"
        );
    }

    #[test]
    fn enrich_witness_populates_scalar_mul_aux_signals_from_original_blackbox() {
        crate::with_serialized_heavy_backend_test(|| {
            let original = Program {
                name: "scalar_mul_aux".to_string(),
                field: FieldId::Bn254,
                signals: vec![
                    Signal {
                        name: "in_0".into(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "in_1".into(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "in_2".into(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "out_0".into(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                    Signal {
                        name: "out_1".into(),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    },
                ],
                constraints: vec![Constraint::BlackBox {
                    op: BlackBoxOp::ScalarMulG1,
                    inputs: vec![
                        Expr::Signal("in_0".into()),
                        Expr::Signal("in_1".into()),
                        Expr::Signal("in_2".into()),
                    ],
                    outputs: vec!["out_0".into(), "out_1".into()],
                    params: BTreeMap::new(),
                    label: Some("test".into()),
                }],
                witness_plan: WitnessPlan::default(),
                ..Default::default()
            };

            let lowered =
                lower_blackbox_program(&original).expect("scalar mul lowering should succeed");
            let mut compiled =
                zkf_core::CompiledProgram::new(BackendKind::ArkworksGroth16, lowered);
            compiled.original_program = Some(original);

            let mut values = BTreeMap::new();
            let base_x = BigInt::parse_bytes(
                b"054aa86a73cb8a34525e5bbed6e43ba1198e860f5f3950268f71df4591bde402",
                16,
            )
            .expect("valid base x hex");
            let base_y = BigInt::parse_bytes(
                b"209dcfbf2cfb57f9f6046f44d71ac6faf87254afc7407c04eb621a6287cac126",
                16,
            )
            .expect("valid base y hex");
            values.insert("in_0".into(), FieldElement::from_i64(1));
            values.insert(
                "in_1".into(),
                FieldElement::from_bigint_with_field(base_x, FieldId::Bn254),
            );
            values.insert(
                "in_2".into(),
                FieldElement::from_bigint_with_field(base_y, FieldId::Bn254),
            );
            values.insert(
                "out_0".into(),
                values.get("in_1").cloned().expect("base x present"),
            );
            values.insert(
                "out_1".into(),
                values.get("in_2").cloned().expect("base y present"),
            );

            let enriched = enrich_witness_for_proving(&compiled, &Witness { values })
                .expect("enrichment should populate nonlinear scalar mul auxiliaries");

            assert!(
                enriched
                    .values
                    .contains_key("__bb_scalar_mul_g1_test_0_smul_dbl253_l_257"),
                "operation-aware aux witness generation should populate doubled-step lambda"
            );
        });
    }

    #[test]
    fn poseidon_bn254_lowering_matches_reference_solver() {
        crate::with_serialized_heavy_backend_test(|| {
            let original = Program {
                name: "poseidon_bn254_roundtrip".to_string(),
                field: FieldId::Bn254,
                signals: (0..4)
                    .map(|i| Signal {
                        name: format!("in{i}"),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    })
                    .chain((0..4).map(|i| Signal {
                        name: format!("out{i}"),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    }))
                    .collect(),
                constraints: vec![Constraint::BlackBox {
                    op: BlackBoxOp::Poseidon,
                    inputs: (0..4).map(|i| Expr::Signal(format!("in{i}"))).collect(),
                    outputs: (0..4).map(|i| format!("out{i}")).collect(),
                    params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
                    label: Some("poseidon_bn254".to_string()),
                }],
                witness_plan: WitnessPlan::default(),
                ..Default::default()
            };

            let lowered =
                lower_blackbox_program(&original).expect("poseidon lowering should succeed");
            let mut compiled =
                zkf_core::CompiledProgram::new(BackendKind::ArkworksGroth16, lowered);
            compiled.original_program = Some(original);

            let expected =
                poseidon2_permutation(&vec![AcirFieldElement::zero(); 4], 4).expect("solver works");
            let mut values = BTreeMap::new();
            for i in 0..4 {
                values.insert(format!("in{i}"), FieldElement::from_i64(0));
                let out = BigInt::from_bytes_be(Sign::Plus, &expected[i].to_be_bytes());
                values.insert(
                    format!("out{i}"),
                    FieldElement::from_bigint_with_field(out, FieldId::Bn254),
                );
            }

            let enriched = enrich_witness_for_proving(&compiled, &Witness { values })
                .expect("poseidon aux witness enrichment should succeed");
            check_constraints(&compiled.program, &enriched)
                .expect("canonical poseidon lowering should satisfy constraints");
        });
    }

    #[test]
    fn poseidon_bn254_lowering_rejects_wrong_output() {
        crate::with_serialized_heavy_backend_test(|| {
            let original = Program {
                name: "poseidon_bn254_bad_output".to_string(),
                field: FieldId::Bn254,
                signals: (0..4)
                    .map(|i| Signal {
                        name: format!("in{i}"),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    })
                    .chain((0..4).map(|i| Signal {
                        name: format!("out{i}"),
                        visibility: Visibility::Private,
                        constant: None,
                        ty: None,
                    }))
                    .collect(),
                constraints: vec![Constraint::BlackBox {
                    op: BlackBoxOp::Poseidon,
                    inputs: (0..4).map(|i| Expr::Signal(format!("in{i}"))).collect(),
                    outputs: (0..4).map(|i| format!("out{i}")).collect(),
                    params: BTreeMap::from([("state_len".to_string(), "4".to_string())]),
                    label: Some("poseidon_bn254_bad".to_string()),
                }],
                witness_plan: WitnessPlan::default(),
                ..Default::default()
            };

            let lowered =
                lower_blackbox_program(&original).expect("poseidon lowering should succeed");
            let mut compiled =
                zkf_core::CompiledProgram::new(BackendKind::ArkworksGroth16, lowered);
            compiled.original_program = Some(original);

            let mut values = BTreeMap::new();
            for i in 0..4 {
                values.insert(format!("in{i}"), FieldElement::from_i64(0));
                values.insert(format!("out{i}"), FieldElement::from_i64(0));
            }

            let enriched = enrich_witness_for_proving(&compiled, &Witness { values })
                .expect("poseidon aux witness enrichment should succeed");
            let err = check_constraints(&compiled.program, &enriched)
                .expect_err("wrong poseidon output should fail constraints");
            assert!(
                err.to_string().contains("constraint"),
                "expected a constraint validation error, got {err}"
            );
        });
    }
}
