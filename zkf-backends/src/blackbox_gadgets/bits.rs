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

//! Bit decomposition helpers for lowering bitwise operations to arithmetic constraints.
//!
//! The core technique: decompose a value `v` into boolean signals `b[0..n-1]`
//! where `v = sum(b[i] * 2^i)`, with Boolean constraints on each bit.
//! Then express bitwise operations as field arithmetic over the boolean signals:
//!   XOR(a, b) = a + b - 2*a*b
//!   AND(a, b) = a * b
//!   NOT(a)    = 1 - a
//!   ROTR(x, r) = reindex bits (no constraints needed)

use super::{AuxCounter, LoweredBlackBox};
use zkf_core::{Expr, FieldElement};

/// Decompose a value into `n_bits` boolean signals.
///
/// Adds:
/// - `n_bits` boolean signals (named `{prefix}_bit_{i}`)
/// - `n_bits` Boolean constraints
/// - 1 Equal constraint: `value_expr == sum(bit_i * 2^i)`
///
/// Returns the bit signal names (LSB first).
pub fn decompose_to_bits(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    value_expr: Expr,
    n_bits: u32,
    prefix: &str,
) -> Vec<String> {
    let mut bit_names = Vec::with_capacity(n_bits as usize);

    for i in 0..n_bits {
        let name = aux.next(&format!("{prefix}_bit{i}"));
        lowered.add_private_signal(&name);
        lowered.add_boolean(&name, format!("{prefix}_bit{i}_bool"));
        bit_names.push(name);
    }

    // Constrain: value == sum(bit_i * 2^i)
    let recomposed = recompose_from_bits(&bit_names);
    lowered.add_equal(value_expr, recomposed, format!("{prefix}_decompose"));

    bit_names
}

/// Create an expression that recomposes a value from boolean bit signals (LSB first).
/// Returns: sum(bit_i * 2^i)
pub fn recompose_from_bits(bit_names: &[String]) -> Expr {
    let terms: Vec<Expr> = bit_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            // Use BigInt for bits ≥ 64 since field elements support arbitrary precision.
            let coeff_big = num_bigint::BigInt::from(1u64) << i;
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_bigint(coeff_big))),
                Box::new(Expr::Signal(name.clone())),
            )
        })
        .collect();

    if terms.is_empty() {
        Expr::Const(FieldElement::from_i64(0))
    } else if terms.len() == 1 {
        terms.into_iter().next().unwrap()
    } else {
        Expr::Add(terms)
    }
}

/// XOR of two boolean signals: result = a + b - 2*a*b
///
/// Adds 1 auxiliary signal and 1 Equal constraint.
/// Returns the name of the result signal.
pub fn xor_bits(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    label: &str,
) -> String {
    let result = aux.next(&format!("{label}_xor"));
    lowered.add_private_signal(&result);
    lowered.add_boolean(&result, format!("{label}_xor_bool"));

    // result = a + b - 2*a*b
    let ab = Expr::Mul(
        Box::new(Expr::Signal(a.to_string())),
        Box::new(Expr::Signal(b.to_string())),
    );
    let two_ab = Expr::Mul(
        Box::new(Expr::Const(FieldElement::from_i64(2))),
        Box::new(ab),
    );
    let xor_expr = Expr::Sub(
        Box::new(Expr::Add(vec![
            Expr::Signal(a.to_string()),
            Expr::Signal(b.to_string()),
        ])),
        Box::new(two_ab),
    );

    lowered.add_equal(
        Expr::Signal(result.clone()),
        xor_expr,
        format!("{label}_xor"),
    );
    result
}

/// AND of two boolean signals: result = a * b
pub fn and_bits(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    label: &str,
) -> String {
    let result = aux.next(&format!("{label}_and"));
    lowered.add_private_signal(&result);
    lowered.add_boolean(&result, format!("{label}_and_bool"));

    let and_expr = Expr::Mul(
        Box::new(Expr::Signal(a.to_string())),
        Box::new(Expr::Signal(b.to_string())),
    );

    lowered.add_equal(
        Expr::Signal(result.clone()),
        and_expr,
        format!("{label}_and"),
    );
    result
}

/// NOT of a boolean signal: result = 1 - a
pub fn not_bit(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    label: &str,
) -> String {
    let result = aux.next(&format!("{label}_not"));
    lowered.add_private_signal(&result);
    lowered.add_boolean(&result, format!("{label}_not_bool"));

    let not_expr = Expr::Sub(
        Box::new(Expr::Const(FieldElement::from_i64(1))),
        Box::new(Expr::Signal(a.to_string())),
    );

    lowered.add_equal(
        Expr::Signal(result.clone()),
        not_expr,
        format!("{label}_not"),
    );
    result
}

/// XOR three boolean values: result = a ^ b ^ c
/// Implemented as: t = XOR(a, b), result = XOR(t, c)
pub fn xor3_bits(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    c: &str,
    label: &str,
) -> String {
    let t = xor_bits(lowered, aux, a, b, &format!("{label}_ab"));
    xor_bits(lowered, aux, &t, c, &format!("{label}_abc"))
}

/// Rotate right: reindex bit signals.
/// Returns new bit names after rotation (no constraints needed, purely structural).
/// ROTR(x, r): bit at position i moves to position (i - r) mod n.
pub fn rotr(bits: &[String], amount: usize) -> Vec<String> {
    let n = bits.len();
    let mut rotated = vec![String::new(); n];
    for i in 0..n {
        rotated[(i + n - amount) % n] = bits[i].clone();
    }
    rotated
}

/// Right shift: reindex bits, high bits become zero constants.
/// Returns new bit expressions (not signals) after shift.
pub fn shr_bit_exprs(bits: &[String], amount: usize) -> Vec<Expr> {
    let n = bits.len();
    let mut shifted = Vec::with_capacity(n);
    for i in 0..n {
        if i + amount < n {
            shifted.push(Expr::Signal(bits[i + amount].clone()));
        } else {
            shifted.push(Expr::Const(FieldElement::from_i64(0)));
        }
    }
    shifted
}

/// Constrained modular addition of two 32-bit values.
///
/// Constrains: result + carry * 2^32 = a + b
/// where result is 32-bit (Range constrained) and carry is boolean.
///
/// Returns the name of the 32-bit result signal.
pub fn add_mod32(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a_expr: Expr,
    b_expr: Expr,
    label: &str,
) -> String {
    let result = aux.next(&format!("{label}_sum"));
    let carry = aux.next(&format!("{label}_carry"));

    lowered.add_private_signal(&result);
    lowered.add_range(&result, 32, format!("{label}_sum_range"));

    lowered.add_private_signal(&carry);
    lowered.add_boolean(&carry, format!("{label}_carry_bool"));

    // result + carry * 2^32 = a + b
    let carry_shifted = Expr::Mul(
        Box::new(Expr::Const(FieldElement::from_i64(1i64 << 32))),
        Box::new(Expr::Signal(carry.clone())),
    );
    let lhs = Expr::Add(vec![Expr::Signal(result.clone()), carry_shifted]);
    let rhs = Expr::Add(vec![a_expr, b_expr]);

    lowered.add_equal(lhs, rhs, format!("{label}_mod32_add"));

    result
}

/// Constrained modular addition of multiple 32-bit values.
///
/// Adds values pairwise, handling intermediate carries.
/// Returns the name of the final 32-bit result signal.
pub fn add_many_mod32(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    exprs: Vec<Expr>,
    label: &str,
) -> String {
    assert!(
        !exprs.is_empty(),
        "add_many_mod32 requires at least 1 value"
    );

    if exprs.len() == 1 {
        // Just constrain a new signal to the expression
        let result = aux.next(&format!("{label}_pass"));
        lowered.add_private_signal(&result);
        lowered.add_range(&result, 32, format!("{label}_pass_range"));
        lowered.add_equal(
            Expr::Signal(result.clone()),
            exprs.into_iter().next().unwrap(),
            format!("{label}_pass"),
        );
        return result;
    }

    // For multiple values: sum them all, then extract 32-bit result + carries
    let total_sum = Expr::Add(exprs.clone());
    let n_values = exprs.len();
    // Maximum possible sum: n * (2^32 - 1), which fits in ceil(log2(n)) + 32 bits
    let max_carry_bits = (n_values as f64).log2().ceil() as u32 + 1;

    let result = aux.next(&format!("{label}_sum"));
    let carry = aux.next(&format!("{label}_carry"));

    lowered.add_private_signal(&result);
    lowered.add_range(&result, 32, format!("{label}_sum_range"));

    lowered.add_private_signal(&carry);
    lowered.add_range(&carry, max_carry_bits, format!("{label}_carry_range"));

    // result + carry * 2^32 = sum(all values)
    let carry_shifted = Expr::Mul(
        Box::new(Expr::Const(FieldElement::from_i64(1i64 << 32))),
        Box::new(Expr::Signal(carry.clone())),
    );
    let lhs = Expr::Add(vec![Expr::Signal(result.clone()), carry_shifted]);

    lowered.add_equal(lhs, total_sum, format!("{label}_mod32_add_many"));

    result
}
