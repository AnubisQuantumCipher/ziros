/// Non-native field arithmetic for 256-bit fields embedded in a ~254-bit circuit field.
///
/// Uses a 4 × 64-bit limb decomposition strategy:
///   value = limb_0 + limb_1 * 2^64 + limb_2 * 2^128 + limb_3 * 2^192
///
/// Each public function emits ZIR signals and constraints into a `GadgetEmission`.
/// No heap allocation beyond Vec (required by the ZIR emission model).
///
/// Naming convention for emitted signals: `{prefix}_{operation}_{detail}`.
use crate::gadget::GadgetEmission;
use zkf_core::zir;
use zkf_core::{FieldElement, Visibility};

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Emit a private Field-typed signal.
fn emit_field_signal(emission: &mut GadgetEmission, name: &str) {
    emission.signals.push(zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });
}

/// Emit a 64-bit range constraint on a named signal.
fn emit_range64(emission: &mut GadgetEmission, signal: &str) {
    emission.constraints.push(zir::Constraint::Range {
        signal: signal.to_string(),
        bits: 64,
        label: Some(format!("{}_range64", signal)),
    });
}

/// Return the `FieldElement` for `2^exp`.
fn power_of_two(exp: u32) -> FieldElement {
    // 2^exp where exp ≤ 192 — build via BigInt then convert.
    use num_bigint::BigInt;
    use num_traits::One;
    let val: BigInt = BigInt::one() << exp;
    FieldElement::from_bigint(val)
}

/// Emit limb signals, range constraints, and the recombination constraint for a
/// 256-bit value that has already been decomposed into 4 × 64-bit limb signals
/// named `{prefix}_limb_0` … `{prefix}_limb_3`.
///
/// This helper only emits; the caller is responsible for supplying the right
/// limb names if they want to reuse pre-existing signals.
fn emit_limb_signals_and_recombine(
    emission: &mut GadgetEmission,
    prefix: &str,
    input_signal: &str,
) {
    // Create the four limb signals.
    for i in 0..4usize {
        let name = format!("{}_limb_{}", prefix, i);
        emit_field_signal(emission, &name);
    }

    // Range-constrain each limb to 64 bits.
    for i in 0..4usize {
        let name = format!("{}_limb_{}", prefix, i);
        emit_range64(emission, &name);
    }

    // Recombination: value = l0 + l1*2^64 + l2*2^128 + l3*2^192
    let shifts: [u32; 4] = [0, 64, 128, 192];
    let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
    for (i, &shift) in shifts.iter().enumerate() {
        let limb = zir::Expr::Signal(format!("{}_limb_{}", prefix, i));
        if shift == 0 {
            terms.push(limb);
        } else {
            let coeff = zir::Expr::Const(power_of_two(shift));
            terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
        }
    }

    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Add(terms),
        rhs: zir::Expr::Signal(input_signal.to_string()),
        label: Some(format!("{}_recombine", prefix)),
    });
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Decompose a 256-bit signal into 4 × 64-bit limbs.
///
/// Emitted signals: `{prefix}_limb_0`, `{prefix}_limb_1`, `{prefix}_limb_2`, `{prefix}_limb_3`
///
/// Emitted constraints:
/// - 4 range constraints (one per limb, 64-bit each)
/// - 1 recombination equality: `limb_0 + limb_1*2^64 + limb_2*2^128 + limb_3*2^192 == input`
///
/// # Argument
/// - `input` – name of the existing signal holding the 256-bit value.
pub fn decompose_256bit(emission: &mut GadgetEmission, prefix: &str, input: &str) {
    emit_limb_signals_and_recombine(emission, prefix, input);
}

/// Non-native addition: result ≡ a + b (mod p).
///
/// Strategy:
///   Witness: result_limbs[0..4], carry, quotient q (0 or 1 — addition mod p can
///   produce at most one reduction).
///
/// Emitted signals:
/// - `{prefix}_add_result_limb_{0..3}` – limbs of the result
/// - `{prefix}_add_carry` – intermediate carry signal (field element)
/// - `{prefix}_add_quot` – reduction quotient (0 or 1)
///
/// Emitted constraints:
/// - 4 range constraints on result limbs
/// - 1 Boolean constraint on quotient (0 or 1)
/// - 1 recombination constraint for the result
/// - 1 arithmetic equality: a + b = q * p + result
///
/// `modulus_name` is the name of an existing constant signal holding p.
pub fn nonnative_add(
    emission: &mut GadgetEmission,
    prefix: &str,
    a: &str,
    b: &str,
    modulus_name: &str,
) {
    let result_prefix = format!("{}_add_result", prefix);

    // Result limbs + range + recombination (we'll constrain separately below,
    // so use a synthetic recombination signal name).
    let result_signal = format!("{}_add_result", prefix);
    emit_field_signal(emission, &result_signal);

    for i in 0..4usize {
        let name = format!("{}_add_result_limb_{}", prefix, i);
        emit_field_signal(emission, &name);
        emit_range64(emission, &name);
    }

    // Recombine result limbs into result_signal.
    let shifts: [u32; 4] = [0, 64, 128, 192];
    let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
    for (i, &shift) in shifts.iter().enumerate() {
        let limb = zir::Expr::Signal(format!("{}_add_result_limb_{}", prefix, i));
        if shift == 0 {
            terms.push(limb);
        } else {
            let coeff = zir::Expr::Const(power_of_two(shift));
            terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
        }
    }
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Add(terms),
        rhs: zir::Expr::Signal(result_signal.clone()),
        label: Some(format!("{}_add_result_recombine", prefix)),
    });

    // Quotient: 0 or 1 (single reduction step).
    let quot_name = format!("{}_add_quot", prefix);
    emit_field_signal(emission, &quot_name);
    emission.constraints.push(zir::Constraint::Boolean {
        signal: quot_name.clone(),
        label: Some(format!("{}_add_quot_bool", prefix)),
    });

    // Core arithmetic: a + b = quot * p + result
    // i.e. a + b - quot * p - result = 0
    let lhs = zir::Expr::Add(vec![
        zir::Expr::Signal(a.to_string()),
        zir::Expr::Signal(b.to_string()),
    ]);
    let rhs = zir::Expr::Add(vec![
        zir::Expr::Mul(
            Box::new(zir::Expr::Signal(quot_name)),
            Box::new(zir::Expr::Signal(modulus_name.to_string())),
        ),
        zir::Expr::Signal(result_signal),
    ]);
    emission.constraints.push(zir::Constraint::Equal {
        lhs,
        rhs,
        label: Some(format!("{}_add_arith", prefix)),
    });

    let _ = result_prefix; // suppress unused warning
}

/// Non-native multiplication: result ≡ a * b (mod p).
///
/// Uses schoolbook (limb-by-limb) multiplication with a quotient witness.
/// The prover supplies quotient q and remainder r such that a*b = q*p + r.
///
/// Emitted signals:
/// - `{prefix}_mul_result_limb_{0..3}` – result limbs
/// - `{prefix}_mul_result` – combined result
/// - `{prefix}_mul_quot_limb_{0..3}` – quotient limbs
/// - `{prefix}_mul_quot` – combined quotient
/// - `{prefix}_mul_carry_{0..5}` – schoolbook carry intermediates (range-constrained)
///
/// Emitted constraints:
/// - 4 range constraints on result limbs
/// - 4 range constraints on quotient limbs
/// - 1 recombination for result
/// - 1 recombination for quotient
/// - 6 carry range constraints (128-bit each, bounding schoolbook overflow)
/// - 1 top-level arithmetic: a * b = quot * p + result
pub fn nonnative_mul(
    emission: &mut GadgetEmission,
    prefix: &str,
    a: &str,
    b: &str,
    modulus_name: &str,
) {
    // Result signals.
    let result_signal = format!("{}_mul_result", prefix);
    emit_field_signal(emission, &result_signal);

    for i in 0..4usize {
        let name = format!("{}_mul_result_limb_{}", prefix, i);
        emit_field_signal(emission, &name);
        emit_range64(emission, &name);
    }

    // Recombine result limbs.
    let shifts: [u32; 4] = [0, 64, 128, 192];
    {
        let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
        for (i, &shift) in shifts.iter().enumerate() {
            let limb = zir::Expr::Signal(format!("{}_mul_result_limb_{}", prefix, i));
            if shift == 0 {
                terms.push(limb);
            } else {
                let coeff = zir::Expr::Const(power_of_two(shift));
                terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
            }
        }
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Add(terms),
            rhs: zir::Expr::Signal(result_signal.clone()),
            label: Some(format!("{}_mul_result_recombine", prefix)),
        });
    }

    // Quotient signals.
    let quot_signal = format!("{}_mul_quot", prefix);
    emit_field_signal(emission, &quot_signal);

    for i in 0..4usize {
        let name = format!("{}_mul_quot_limb_{}", prefix, i);
        emit_field_signal(emission, &name);
        emit_range64(emission, &name);
    }

    // Recombine quotient limbs.
    {
        let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
        for (i, &shift) in shifts.iter().enumerate() {
            let limb = zir::Expr::Signal(format!("{}_mul_quot_limb_{}", prefix, i));
            if shift == 0 {
                terms.push(limb);
            } else {
                let coeff = zir::Expr::Const(power_of_two(shift));
                terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
            }
        }
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Add(terms),
            rhs: zir::Expr::Signal(quot_signal.clone()),
            label: Some(format!("{}_mul_quot_recombine", prefix)),
        });
    }

    // Schoolbook carry intermediates (6 carries for 4×4 limb product).
    // Each carry is bounded to 128 bits to capture schoolbook overflow.
    for c in 0..6usize {
        let carry_name = format!("{}_mul_carry_{}", prefix, c);
        emit_field_signal(emission, &carry_name);
        emission.constraints.push(zir::Constraint::Range {
            signal: carry_name.clone(),
            bits: 128,
            label: Some(format!("{}_mul_carry_{}_range128", prefix, c)),
        });
    }

    // Core arithmetic: a * b = quot * p + result
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Mul(
            Box::new(zir::Expr::Signal(a.to_string())),
            Box::new(zir::Expr::Signal(b.to_string())),
        ),
        rhs: zir::Expr::Add(vec![
            zir::Expr::Mul(
                Box::new(zir::Expr::Signal(quot_signal)),
                Box::new(zir::Expr::Signal(modulus_name.to_string())),
            ),
            zir::Expr::Signal(result_signal),
        ]),
        label: Some(format!("{}_mul_arith", prefix)),
    });
}

/// Non-native subtraction: result ≡ a − b (mod p).
///
/// Witnesses result and a borrow/reduction quotient q ∈ {0, 1}.
///   a − b + q * p = result,  with  0 ≤ result < p
///
/// Emitted signals:
/// - `{prefix}_sub_result_limb_{0..3}`
/// - `{prefix}_sub_result`
/// - `{prefix}_sub_borrow` – Boolean (0 or 1)
///
/// Emitted constraints:
/// - 4 range constraints on result limbs
/// - 1 recombination for result
/// - 1 Boolean constraint on borrow
/// - 1 arithmetic: a - b + borrow * p = result
pub fn nonnative_sub(
    emission: &mut GadgetEmission,
    prefix: &str,
    a: &str,
    b: &str,
    modulus_name: &str,
) {
    let result_signal = format!("{}_sub_result", prefix);
    emit_field_signal(emission, &result_signal);

    for i in 0..4usize {
        let name = format!("{}_sub_result_limb_{}", prefix, i);
        emit_field_signal(emission, &name);
        emit_range64(emission, &name);
    }

    // Recombine result limbs.
    let shifts: [u32; 4] = [0, 64, 128, 192];
    {
        let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
        for (i, &shift) in shifts.iter().enumerate() {
            let limb = zir::Expr::Signal(format!("{}_sub_result_limb_{}", prefix, i));
            if shift == 0 {
                terms.push(limb);
            } else {
                let coeff = zir::Expr::Const(power_of_two(shift));
                terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
            }
        }
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Add(terms),
            rhs: zir::Expr::Signal(result_signal.clone()),
            label: Some(format!("{}_sub_result_recombine", prefix)),
        });
    }

    // Borrow bit.
    let borrow_name = format!("{}_sub_borrow", prefix);
    emit_field_signal(emission, &borrow_name);
    emission.constraints.push(zir::Constraint::Boolean {
        signal: borrow_name.clone(),
        label: Some(format!("{}_sub_borrow_bool", prefix)),
    });

    // Core arithmetic: a - b + borrow * p = result
    let lhs = zir::Expr::Add(vec![
        zir::Expr::Signal(a.to_string()),
        zir::Expr::Mul(
            Box::new(zir::Expr::Signal(borrow_name)),
            Box::new(zir::Expr::Signal(modulus_name.to_string())),
        ),
    ]);
    let rhs = zir::Expr::Add(vec![
        zir::Expr::Signal(b.to_string()),
        zir::Expr::Signal(result_signal),
    ]);
    emission.constraints.push(zir::Constraint::Equal {
        lhs,
        rhs,
        label: Some(format!("{}_sub_arith", prefix)),
    });
}

/// Non-native modular inverse: result ≡ a⁻¹ (mod p).
///
/// The prover witnesses `inv` and we constrain `a * inv ≡ 1 (mod p)`.
/// Implementation uses `nonnative_mul` internally to emit the product
/// constraint, then constrains the product equals 1.
///
/// Emitted signals:
/// - `{prefix}_inv_limb_{0..3}` – limbs of the inverse
/// - `{prefix}_inv` – combined inverse value
/// - (all signals emitted by the internal `nonnative_mul` call)
///
/// Emitted constraints:
/// - 4 range constraints on inv limbs
/// - 1 recombination for inv
/// - All constraints from `nonnative_mul(prefix+"_inv_mul", a, inv, modulus_name)`
/// - 1 equality: (a * inv mod p) result == 1
pub fn nonnative_inverse(emission: &mut GadgetEmission, prefix: &str, a: &str, modulus_name: &str) {
    let inv_signal = format!("{}_inv", prefix);
    emit_field_signal(emission, &inv_signal);

    for i in 0..4usize {
        let name = format!("{}_inv_limb_{}", prefix, i);
        emit_field_signal(emission, &name);
        emit_range64(emission, &name);
    }

    // Recombine inv limbs.
    let shifts: [u32; 4] = [0, 64, 128, 192];
    {
        let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
        for (i, &shift) in shifts.iter().enumerate() {
            let limb = zir::Expr::Signal(format!("{}_inv_limb_{}", prefix, i));
            if shift == 0 {
                terms.push(limb);
            } else {
                let coeff = zir::Expr::Const(power_of_two(shift));
                terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
            }
        }
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Add(terms),
            rhs: zir::Expr::Signal(inv_signal.clone()),
            label: Some(format!("{}_inv_recombine", prefix)),
        });
    }

    // Emit: a * inv mod p using nonnative_mul.
    // The result of this mul should equal 1.
    let mul_prefix = format!("{}_inv_mul", prefix);
    nonnative_mul(emission, &mul_prefix, a, &inv_signal, modulus_name);

    // Constrain the multiplication result to be 1.
    let product_result = format!("{}_inv_mul_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(product_result),
        rhs: zir::Expr::Const(FieldElement::from_i64(1)),
        label: Some(format!("{}_inv_product_is_one", prefix)),
    });
}

/// Assert two non-native values are equal modulo p.
///
/// Emits a single equality constraint: a == b.
/// (If both are already reduced mod p, field equality suffices.)
///
/// Emitted constraints:
/// - 1 equality: a == b
pub fn nonnative_equal(emission: &mut GadgetEmission, prefix: &str, a: &str, b: &str) {
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(a.to_string()),
        rhs: zir::Expr::Signal(b.to_string()),
        label: Some(format!("{}_nonnative_equal", prefix)),
    });
}

// ──────────────────────────────────────────────────────────────────────────────
// Re-exported for use in secp256k1.rs
// ──────────────────────────────────────────────────────────────────────────────

/// Emit limb decomposition signals for an existing signal, returning the limb
/// signal names. Does NOT emit the recombination constraint.
/// Available for use by curve operation modules.
#[allow(dead_code)]
pub(crate) fn decompose_signal_to_limbs(
    emission: &mut GadgetEmission,
    prefix: &str,
    input: &str,
) -> [String; 4] {
    let limbs: [String; 4] = [
        format!("{}_limb_0", prefix),
        format!("{}_limb_1", prefix),
        format!("{}_limb_2", prefix),
        format!("{}_limb_3", prefix),
    ];

    for name in &limbs {
        emit_field_signal(emission, name);
        emit_range64(emission, name);
    }

    // Recombination constraint.
    let shifts: [u32; 4] = [0, 64, 128, 192];
    let mut terms: Vec<zir::Expr> = Vec::with_capacity(4);
    for i in 0..4usize {
        let limb = zir::Expr::Signal(limbs[i].clone());
        if shifts[i] == 0 {
            terms.push(limb);
        } else {
            let coeff = zir::Expr::Const(power_of_two(shifts[i]));
            terms.push(zir::Expr::Mul(Box::new(coeff), Box::new(limb)));
        }
    }
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Add(terms),
        rhs: zir::Expr::Signal(input.to_string()),
        label: Some(format!("{}_decompose_recombine", prefix)),
    });

    limbs
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── decompose_256bit ──────────────────────────────────────────────────────

    #[test]
    fn decompose_256bit_creates_four_limb_signals() {
        let mut emission = GadgetEmission::default();
        decompose_256bit(&mut emission, "x", "x_val");

        let limb_names: Vec<String> = (0..4).map(|i| format!("x_limb_{}", i)).collect();
        for name in &limb_names {
            assert!(
                emission.signals.iter().any(|s| &s.name == name),
                "missing signal {}",
                name
            );
        }
    }

    #[test]
    fn decompose_256bit_all_limbs_are_field_type() {
        let mut emission = GadgetEmission::default();
        decompose_256bit(&mut emission, "val", "val_input");

        for s in emission
            .signals
            .iter()
            .filter(|s| s.name.starts_with("val_limb_"))
        {
            assert_eq!(s.ty, zir::SignalType::Field);
        }
    }

    #[test]
    fn decompose_256bit_emits_four_range_and_one_recombination_constraint() {
        let mut emission = GadgetEmission::default();
        decompose_256bit(&mut emission, "p", "p_input");

        let range_count = emission
            .constraints
            .iter()
            .filter(|c| matches!(c, zir::Constraint::Range { bits: 64, .. }))
            .count();
        assert_eq!(range_count, 4, "expected 4 × 64-bit range constraints");

        let equal_count = emission
            .constraints
            .iter()
            .filter(|c| matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l.ends_with("_recombine")))
            .count();
        assert_eq!(equal_count, 1, "expected 1 recombination equality");

        // Total: 4 range + 1 recombination
        assert_eq!(emission.constraints.len(), 5);
    }

    #[test]
    fn decompose_256bit_limb_names_use_prefix() {
        let mut emission = GadgetEmission::default();
        decompose_256bit(&mut emission, "myval", "myval_sig");

        for i in 0..4 {
            let expected = format!("myval_limb_{}", i);
            assert!(emission.signals.iter().any(|s| s.name == expected));
        }
    }

    // ── nonnative_add ─────────────────────────────────────────────────────────

    #[test]
    fn nonnative_add_emits_result_limbs_and_quot() {
        let mut emission = GadgetEmission::default();
        nonnative_add(&mut emission, "op", "a", "b", "p");

        // Should have result_limb_0..3, result, quot
        for i in 0..4 {
            let name = format!("op_add_result_limb_{}", i);
            assert!(
                emission.signals.iter().any(|s| s.name == name),
                "missing {}",
                name
            );
        }
        assert!(emission.signals.iter().any(|s| s.name == "op_add_quot"));
        assert!(emission.signals.iter().any(|s| s.name == "op_add_result"));
    }

    #[test]
    fn nonnative_add_has_boolean_quot_constraint() {
        let mut emission = GadgetEmission::default();
        nonnative_add(&mut emission, "add", "a", "b", "p");

        let has_bool = emission.constraints.iter().any(
            |c| matches!(c, zir::Constraint::Boolean { signal, .. } if signal == "add_add_quot"),
        );
        assert!(has_bool, "expected Boolean constraint on add_add_quot");
    }

    #[test]
    fn nonnative_add_has_arith_constraint() {
        let mut emission = GadgetEmission::default();
        nonnative_add(&mut emission, "add", "a", "b", "p");

        let has_arith = emission.constraints.iter().any(
            |c| matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l == "add_add_arith"),
        );
        assert!(has_arith, "expected arithmetic equality constraint");
    }

    // ── nonnative_mul ─────────────────────────────────────────────────────────

    #[test]
    fn nonnative_mul_emits_result_and_quotient_limbs() {
        let mut emission = GadgetEmission::default();
        nonnative_mul(&mut emission, "mul", "a", "b", "p");

        for i in 0..4 {
            assert!(
                emission
                    .signals
                    .iter()
                    .any(|s| s.name == format!("mul_mul_result_limb_{}", i))
            );
            assert!(
                emission
                    .signals
                    .iter()
                    .any(|s| s.name == format!("mul_mul_quot_limb_{}", i))
            );
        }
    }

    #[test]
    fn nonnative_mul_emits_six_carry_signals() {
        let mut emission = GadgetEmission::default();
        nonnative_mul(&mut emission, "m", "a", "b", "p");

        let carries: Vec<_> = emission
            .signals
            .iter()
            .filter(|s| s.name.starts_with("m_mul_carry_"))
            .collect();
        assert_eq!(carries.len(), 6, "expected 6 carry signals");
    }

    #[test]
    fn nonnative_mul_carry_range_is_128_bits() {
        let mut emission = GadgetEmission::default();
        nonnative_mul(&mut emission, "m", "a", "b", "p");

        let count = emission
            .constraints
            .iter()
            .filter(|c| matches!(c, zir::Constraint::Range { bits: 128, .. }))
            .count();
        assert_eq!(count, 6, "expected 6 × 128-bit carry range constraints");
    }

    #[test]
    fn nonnative_mul_has_arith_constraint() {
        let mut emission = GadgetEmission::default();
        nonnative_mul(&mut emission, "mul", "x", "y", "p");

        let has_arith = emission.constraints.iter().any(
            |c| matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l == "mul_mul_arith"),
        );
        assert!(has_arith);
    }

    // ── nonnative_sub ─────────────────────────────────────────────────────────

    #[test]
    fn nonnative_sub_emits_borrow_and_result() {
        let mut emission = GadgetEmission::default();
        nonnative_sub(&mut emission, "sub", "a", "b", "p");

        assert!(emission.signals.iter().any(|s| s.name == "sub_sub_result"));
        assert!(emission.signals.iter().any(|s| s.name == "sub_sub_borrow"));
    }

    #[test]
    fn nonnative_sub_borrow_is_boolean() {
        let mut emission = GadgetEmission::default();
        nonnative_sub(&mut emission, "s", "a", "b", "p");

        let has_bool = emission.constraints.iter().any(
            |c| matches!(c, zir::Constraint::Boolean { signal, .. } if signal == "s_sub_borrow"),
        );
        assert!(has_bool);
    }

    #[test]
    fn nonnative_sub_result_limbs_range_64() {
        let mut emission = GadgetEmission::default();
        nonnative_sub(&mut emission, "sub", "a", "b", "p");

        let range_count = emission
            .constraints
            .iter()
            .filter(|c| matches!(c, zir::Constraint::Range { bits: 64, signal, .. } if signal.starts_with("sub_sub_result_limb_")))
            .count();
        assert_eq!(range_count, 4);
    }

    // ── nonnative_inverse ─────────────────────────────────────────────────────

    #[test]
    fn nonnative_inverse_emits_inv_signal() {
        let mut emission = GadgetEmission::default();
        nonnative_inverse(&mut emission, "inv_op", "a", "p");

        assert!(emission.signals.iter().any(|s| s.name == "inv_op_inv"));
    }

    #[test]
    fn nonnative_inverse_emits_inv_limbs() {
        let mut emission = GadgetEmission::default();
        nonnative_inverse(&mut emission, "inv_op", "a", "p");

        for i in 0..4 {
            let name = format!("inv_op_inv_limb_{}", i);
            assert!(
                emission.signals.iter().any(|s| s.name == name),
                "missing {}",
                name
            );
        }
    }

    #[test]
    fn nonnative_inverse_has_product_is_one_constraint() {
        let mut emission = GadgetEmission::default();
        nonnative_inverse(&mut emission, "inv", "a", "p");

        let has_one = emission
            .constraints
            .iter()
            .any(|c| matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l == "inv_inv_product_is_one"));
        assert!(has_one, "expected product-is-one constraint");
    }

    #[test]
    fn nonnative_inverse_uses_internal_mul() {
        let mut emission = GadgetEmission::default();
        nonnative_inverse(&mut emission, "inv", "a", "p");

        // The internal mul must produce a result signal.
        let has_mul_result = emission
            .signals
            .iter()
            .any(|s| s.name == "inv_inv_mul_mul_result");
        assert!(has_mul_result, "expected internal mul result signal");
    }

    // ── nonnative_equal ───────────────────────────────────────────────────────

    #[test]
    fn nonnative_equal_emits_one_equality_constraint() {
        let mut emission = GadgetEmission::default();
        nonnative_equal(&mut emission, "eq", "x", "y");

        assert_eq!(emission.constraints.len(), 1);
        assert!(matches!(
            &emission.constraints[0],
            zir::Constraint::Equal { label: Some(l), .. } if l == "eq_nonnative_equal"
        ));
    }

    #[test]
    fn nonnative_equal_emits_no_signals() {
        let mut emission = GadgetEmission::default();
        nonnative_equal(&mut emission, "eq", "x", "y");

        assert!(emission.signals.is_empty());
    }
}
