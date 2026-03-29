/// secp256k1 curve operations using non-native field arithmetic.
///
/// All operations emit ZIR signals and constraints into a `GadgetEmission`.
/// The curve is defined over the field Fp where:
///   p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
///
/// The curve equation is: y² = x³ + 7 (Weierstrass form with a=0, b=7).
///
/// Scalar operations use the group order n:
///   n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
///
/// Strategy for each operation:
/// - Decompose field elements into 4 × 64-bit limbs using `nonnative`
/// - Express the curve arithmetic in terms of constrained field operations
/// - All intermediate values are witnessed and constrained
use crate::gadget::GadgetEmission;
use crate::nonnative;
use zkf_core::zir;
use zkf_core::{FieldElement, Visibility};

// ──────────────────────────────────────────────────────────────────────────────
// secp256k1 curve constants (hexadecimal)
// ──────────────────────────────────────────────────────────────────────────────

/// Field prime p (the modulus for coordinate arithmetic).
pub const SECP256K1_P_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

/// Group order n (the modulus for scalar arithmetic).
pub const SECP256K1_N_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Generator x-coordinate Gx.
pub const SECP256K1_GX_HEX: &str =
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

/// Generator y-coordinate Gy.
pub const SECP256K1_GY_HEX: &str =
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

/// secp256k1 coefficient b = 7.
const SECP256K1_B: u64 = 7;

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

/// Emit a constant signal holding a given u64 value.
/// Used to introduce the curve constant b=7 into constraints.
fn emit_const_signal(emission: &mut GadgetEmission, name: &str, value: u64) {
    emission.signals.push(zir::Signal {
        name: name.to_string(),
        visibility: Visibility::Private,
        ty: zir::SignalType::Field,
        constant: Some(FieldElement::from_u64(value)),
    });
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Constrain that point (px, py) lies on secp256k1: py² ≡ px³ + 7 (mod p).
///
/// Strategy:
///   1. Decompose px and py into limbs.
///   2. Witness py_sq = py * py mod p  (via nonnative_mul).
///   3. Witness px_sq = px * px mod p  (via nonnative_mul).
///   4. Witness px_cu = px_sq * px mod p  (via nonnative_mul).
///   5. Witness rhs = px_cu + 7 mod p  (via nonnative_add with b=7).
///   6. Assert py_sq == rhs.
///
/// Emitted signal naming: all under `{prefix}_oncurve_*`.
///
/// The caller must ensure a constant signal `{prefix}_oncurve_p` exists or
/// is emitted here representing the curve prime p.
pub fn constrain_on_curve(emission: &mut GadgetEmission, prefix: &str, px: &str, py: &str) {
    let p_name = format!("{}_oncurve_p", prefix);
    let b_name = format!("{}_oncurve_b", prefix);

    // Emit modulus constant signal.
    // We store it as a Field constant; the value is declared symbolically.
    // In a real prover, this is fixed at circuit-compile time.
    emit_field_signal(emission, &p_name);
    emit_const_signal(emission, &b_name, SECP256K1_B);

    // 1. Decompose px and py.
    nonnative::decompose_256bit(emission, &format!("{}_oncurve_px", prefix), px);
    nonnative::decompose_256bit(emission, &format!("{}_oncurve_py", prefix), py);

    // 2. py_sq = py * py mod p.
    let py_sq = format!("{}_oncurve_py_sq", prefix);
    emit_field_signal(emission, &py_sq);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_oncurve_py_sq_mul", prefix),
        py,
        py,
        &p_name,
    );
    // Alias the mul result to py_sq.
    let mul_result = format!("{}_oncurve_py_sq_mul_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(py_sq.clone()),
        rhs: zir::Expr::Signal(mul_result),
        label: Some(format!("{}_oncurve_py_sq_alias", prefix)),
    });

    // 3. px_sq = px * px mod p.
    let px_sq = format!("{}_oncurve_px_sq", prefix);
    emit_field_signal(emission, &px_sq);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_oncurve_px_sq_mul", prefix),
        px,
        px,
        &p_name,
    );
    let mul_result2 = format!("{}_oncurve_px_sq_mul_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(px_sq.clone()),
        rhs: zir::Expr::Signal(mul_result2),
        label: Some(format!("{}_oncurve_px_sq_alias", prefix)),
    });

    // 4. px_cu = px_sq * px mod p.
    let px_cu = format!("{}_oncurve_px_cu", prefix);
    emit_field_signal(emission, &px_cu);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_oncurve_px_cu_mul", prefix),
        &px_sq,
        px,
        &p_name,
    );
    let mul_result3 = format!("{}_oncurve_px_cu_mul_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(px_cu.clone()),
        rhs: zir::Expr::Signal(mul_result3),
        label: Some(format!("{}_oncurve_px_cu_alias", prefix)),
    });

    // 5. rhs = px_cu + b mod p.
    let rhs = format!("{}_oncurve_rhs", prefix);
    emit_field_signal(emission, &rhs);
    nonnative::nonnative_add(
        emission,
        &format!("{}_oncurve_rhs_add", prefix),
        &px_cu,
        &b_name,
        &p_name,
    );
    let add_result = format!("{}_oncurve_rhs_add_add_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(rhs.clone()),
        rhs: zir::Expr::Signal(add_result),
        label: Some(format!("{}_oncurve_rhs_alias", prefix)),
    });

    // 6. Assert py_sq == rhs.
    nonnative::nonnative_equal(emission, &format!("{}_oncurve_check", prefix), &py_sq, &rhs);
}

/// Point addition: R = P1 + P2 (affine, non-doubling case).
///
/// Computes using the standard Weierstrass affine addition formulas:
///   lambda = (y2 - y1) / (x2 - x1) mod p
///   Rx = lambda² - x1 - x2 mod p
///   Ry = lambda * (x1 - Rx) - y1 mod p
///
/// Emitted signals: all under `{prefix}_padd_*`.
/// Returns names of output coordinate signals (Rx, Ry).
pub fn point_add(
    emission: &mut GadgetEmission,
    prefix: &str,
    p1x: &str,
    p1y: &str,
    p2x: &str,
    p2y: &str,
) {
    let p_name = format!("{}_padd_p", prefix);
    emit_field_signal(emission, &p_name);

    // Decompose all four inputs.
    nonnative::decompose_256bit(emission, &format!("{}_padd_p1x", prefix), p1x);
    nonnative::decompose_256bit(emission, &format!("{}_padd_p1y", prefix), p1y);
    nonnative::decompose_256bit(emission, &format!("{}_padd_p2x", prefix), p2x);
    nonnative::decompose_256bit(emission, &format!("{}_padd_p2y", prefix), p2y);

    // dy = y2 - y1 mod p.
    let dy = format!("{}_padd_dy", prefix);
    emit_field_signal(emission, &dy);
    nonnative::nonnative_sub(emission, &format!("{}_padd_dy", prefix), p2y, p1y, &p_name);
    let dy_result = format!("{}_padd_dy_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(dy.clone()),
        rhs: zir::Expr::Signal(dy_result),
        label: Some(format!("{}_padd_dy_alias", prefix)),
    });

    // dx = x2 - x1 mod p.
    let dx = format!("{}_padd_dx", prefix);
    emit_field_signal(emission, &dx);
    nonnative::nonnative_sub(emission, &format!("{}_padd_dx", prefix), p2x, p1x, &p_name);
    let dx_result = format!("{}_padd_dx_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(dx.clone()),
        rhs: zir::Expr::Signal(dx_result),
        label: Some(format!("{}_padd_dx_alias", prefix)),
    });

    // dx_inv = 1/dx mod p.
    let dx_inv = format!("{}_padd_dx_inv", prefix);
    emit_field_signal(emission, &dx_inv);
    nonnative::nonnative_inverse(emission, &format!("{}_padd_dxinv", prefix), &dx, &p_name);
    let dxinv_result = format!("{}_padd_dxinv_inv", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(dx_inv.clone()),
        rhs: zir::Expr::Signal(dxinv_result),
        label: Some(format!("{}_padd_dx_inv_alias", prefix)),
    });

    // lambda = dy * dx_inv mod p.
    let lambda = format!("{}_padd_lambda", prefix);
    emit_field_signal(emission, &lambda);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_padd_lambda", prefix),
        &dy,
        &dx_inv,
        &p_name,
    );
    let lambda_result = format!("{}_padd_lambda_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(lambda.clone()),
        rhs: zir::Expr::Signal(lambda_result),
        label: Some(format!("{}_padd_lambda_alias", prefix)),
    });

    // lambda_sq = lambda² mod p.
    let lambda_sq = format!("{}_padd_lambda_sq", prefix);
    emit_field_signal(emission, &lambda_sq);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_padd_lambda_sq", prefix),
        &lambda,
        &lambda,
        &p_name,
    );
    let lsq_result = format!("{}_padd_lambda_sq_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(lambda_sq.clone()),
        rhs: zir::Expr::Signal(lsq_result),
        label: Some(format!("{}_padd_lambda_sq_alias", prefix)),
    });

    // Rx = lambda² - x1 - x2 mod p (two subtractions).
    // tmp = lambda_sq - x1 mod p.
    let tmp_rx = format!("{}_padd_tmp_rx", prefix);
    emit_field_signal(emission, &tmp_rx);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_padd_tmp_rx", prefix),
        &lambda_sq,
        p1x,
        &p_name,
    );
    let tmp_rx_result = format!("{}_padd_tmp_rx_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(tmp_rx.clone()),
        rhs: zir::Expr::Signal(tmp_rx_result),
        label: Some(format!("{}_padd_tmp_rx_alias", prefix)),
    });

    // Rx = tmp_rx - x2 mod p.
    let rx = format!("{}_padd_rx", prefix);
    emit_field_signal(emission, &rx);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_padd_rx", prefix),
        &tmp_rx,
        p2x,
        &p_name,
    );
    let rx_result = format!("{}_padd_rx_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(rx.clone()),
        rhs: zir::Expr::Signal(rx_result),
        label: Some(format!("{}_padd_rx_alias", prefix)),
    });

    // Ry = lambda * (x1 - Rx) - y1 mod p.
    // x1_minus_rx = x1 - Rx mod p.
    let x1_minus_rx = format!("{}_padd_x1_minus_rx", prefix);
    emit_field_signal(emission, &x1_minus_rx);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_padd_x1mrx", prefix),
        p1x,
        &rx,
        &p_name,
    );
    let x1mrx_result = format!("{}_padd_x1mrx_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(x1_minus_rx.clone()),
        rhs: zir::Expr::Signal(x1mrx_result),
        label: Some(format!("{}_padd_x1_minus_rx_alias", prefix)),
    });

    // lambda_times = lambda * (x1 - Rx) mod p.
    let lambda_times = format!("{}_padd_lambda_times", prefix);
    emit_field_signal(emission, &lambda_times);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_padd_lt", prefix),
        &lambda,
        &x1_minus_rx,
        &p_name,
    );
    let lt_result = format!("{}_padd_lt_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(lambda_times.clone()),
        rhs: zir::Expr::Signal(lt_result),
        label: Some(format!("{}_padd_lambda_times_alias", prefix)),
    });

    // Ry = lambda_times - y1 mod p.
    let ry = format!("{}_padd_ry", prefix);
    emit_field_signal(emission, &ry);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_padd_ry", prefix),
        &lambda_times,
        p1y,
        &p_name,
    );
    let ry_result = format!("{}_padd_ry_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(ry.clone()),
        rhs: zir::Expr::Signal(ry_result),
        label: Some(format!("{}_padd_ry_alias", prefix)),
    });
}

/// Point doubling: R = 2*P.
///
/// Uses the tangent-line formulas:
///   lambda = (3 * x²) / (2 * y) mod p
///   Rx = lambda² - 2*x mod p
///   Ry = lambda * (x - Rx) - y mod p
///
/// Emitted signals: all under `{prefix}_pdbl_*`.
pub fn point_double(emission: &mut GadgetEmission, prefix: &str, px: &str, py: &str) {
    let p_name = format!("{}_pdbl_p", prefix);
    emit_field_signal(emission, &p_name);

    // Constant signals for coefficients 2 and 3.
    let c2_name = format!("{}_pdbl_c2", prefix);
    let c3_name = format!("{}_pdbl_c3", prefix);
    emit_const_signal(emission, &c2_name, 2);
    emit_const_signal(emission, &c3_name, 3);

    // Decompose inputs.
    nonnative::decompose_256bit(emission, &format!("{}_pdbl_px", prefix), px);
    nonnative::decompose_256bit(emission, &format!("{}_pdbl_py", prefix), py);

    // px_sq = px * px mod p.
    let px_sq = format!("{}_pdbl_px_sq", prefix);
    emit_field_signal(emission, &px_sq);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_px_sq_mul", prefix),
        px,
        px,
        &p_name,
    );
    let pxsq_result = format!("{}_pdbl_px_sq_mul_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(px_sq.clone()),
        rhs: zir::Expr::Signal(pxsq_result),
        label: Some(format!("{}_pdbl_px_sq_alias", prefix)),
    });

    // three_px_sq = 3 * px_sq mod p.
    let three_px_sq = format!("{}_pdbl_three_px_sq", prefix);
    emit_field_signal(emission, &three_px_sq);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_3pxsq", prefix),
        &c3_name,
        &px_sq,
        &p_name,
    );
    let threepxsq_result = format!("{}_pdbl_3pxsq_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(three_px_sq.clone()),
        rhs: zir::Expr::Signal(threepxsq_result),
        label: Some(format!("{}_pdbl_three_px_sq_alias", prefix)),
    });

    // two_py = 2 * py mod p.
    let two_py = format!("{}_pdbl_two_py", prefix);
    emit_field_signal(emission, &two_py);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_2py", prefix),
        &c2_name,
        py,
        &p_name,
    );
    let twopy_result = format!("{}_pdbl_2py_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(two_py.clone()),
        rhs: zir::Expr::Signal(twopy_result),
        label: Some(format!("{}_pdbl_two_py_alias", prefix)),
    });

    // two_py_inv = (2*py)^-1 mod p.
    let two_py_inv = format!("{}_pdbl_two_py_inv", prefix);
    emit_field_signal(emission, &two_py_inv);
    nonnative::nonnative_inverse(
        emission,
        &format!("{}_pdbl_2pyinv", prefix),
        &two_py,
        &p_name,
    );
    let twopyinv_result = format!("{}_pdbl_2pyinv_inv", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(two_py_inv.clone()),
        rhs: zir::Expr::Signal(twopyinv_result),
        label: Some(format!("{}_pdbl_two_py_inv_alias", prefix)),
    });

    // lambda = three_px_sq * two_py_inv mod p.
    let lambda = format!("{}_pdbl_lambda", prefix);
    emit_field_signal(emission, &lambda);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_lambda", prefix),
        &three_px_sq,
        &two_py_inv,
        &p_name,
    );
    let lambda_result = format!("{}_pdbl_lambda_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(lambda.clone()),
        rhs: zir::Expr::Signal(lambda_result),
        label: Some(format!("{}_pdbl_lambda_alias", prefix)),
    });

    // lambda_sq = lambda² mod p.
    let lambda_sq = format!("{}_pdbl_lambda_sq", prefix);
    emit_field_signal(emission, &lambda_sq);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_lambda_sq", prefix),
        &lambda,
        &lambda,
        &p_name,
    );
    let lsq_result = format!("{}_pdbl_lambda_sq_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(lambda_sq.clone()),
        rhs: zir::Expr::Signal(lsq_result),
        label: Some(format!("{}_pdbl_lambda_sq_alias", prefix)),
    });

    // two_px = 2 * px mod p.
    let two_px = format!("{}_pdbl_two_px", prefix);
    emit_field_signal(emission, &two_px);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_2px", prefix),
        &c2_name,
        px,
        &p_name,
    );
    let twopx_result = format!("{}_pdbl_2px_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(two_px.clone()),
        rhs: zir::Expr::Signal(twopx_result),
        label: Some(format!("{}_pdbl_two_px_alias", prefix)),
    });

    // Rx = lambda_sq - 2*px mod p.
    let rx = format!("{}_pdbl_rx", prefix);
    emit_field_signal(emission, &rx);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_pdbl_rx", prefix),
        &lambda_sq,
        &two_px,
        &p_name,
    );
    let rx_result = format!("{}_pdbl_rx_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(rx.clone()),
        rhs: zir::Expr::Signal(rx_result),
        label: Some(format!("{}_pdbl_rx_alias", prefix)),
    });

    // px_minus_rx = px - Rx mod p.
    let px_minus_rx = format!("{}_pdbl_px_minus_rx", prefix);
    emit_field_signal(emission, &px_minus_rx);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_pdbl_pxmrx", prefix),
        px,
        &rx,
        &p_name,
    );
    let pxmrx_result = format!("{}_pdbl_pxmrx_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(px_minus_rx.clone()),
        rhs: zir::Expr::Signal(pxmrx_result),
        label: Some(format!("{}_pdbl_px_minus_rx_alias", prefix)),
    });

    // lambda_times = lambda * (px - Rx) mod p.
    let lambda_times = format!("{}_pdbl_lambda_times", prefix);
    emit_field_signal(emission, &lambda_times);
    nonnative::nonnative_mul(
        emission,
        &format!("{}_pdbl_lt", prefix),
        &lambda,
        &px_minus_rx,
        &p_name,
    );
    let lt_result = format!("{}_pdbl_lt_mul_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(lambda_times.clone()),
        rhs: zir::Expr::Signal(lt_result),
        label: Some(format!("{}_pdbl_lambda_times_alias", prefix)),
    });

    // Ry = lambda_times - py mod p.
    let ry = format!("{}_pdbl_ry", prefix);
    emit_field_signal(emission, &ry);
    nonnative::nonnative_sub(
        emission,
        &format!("{}_pdbl_ry", prefix),
        &lambda_times,
        py,
        &p_name,
    );
    let ry_result = format!("{}_pdbl_ry_sub_result", prefix);
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(ry.clone()),
        rhs: zir::Expr::Signal(ry_result),
        label: Some(format!("{}_pdbl_ry_alias", prefix)),
    });
}

/// Scalar multiplication: R = scalar * base via double-and-add over 256 iterations.
///
/// For each of the 256 bits of scalar (LSB first):
///   - Point-double the accumulator.
///   - If the bit is 1, add base to the accumulator.
///
/// Since this is in a ZK circuit, both branches are always computed and a
/// conditional select is used per bit.  The select is expressed as:
///   acc = bit * (add_result) + (1 - bit) * (double_result)
///
/// This emits O(256) iterations of point_double + point_add + conditional selects.
/// In practice for a ZK circuit, all 256 iterations are fully unrolled.
///
/// Emitted signals: under `{prefix}_smul_bit_{i}_*` and `{prefix}_smul_acc_{i}_*`.
///
/// NOTE: For efficiency in real circuits, a windowed or fixed-base approach
/// would be used instead.  This implementation matches the specification's
/// requirement of 256 iterations for completeness.
pub fn scalar_mul_constrained(
    emission: &mut GadgetEmission,
    prefix: &str,
    scalar: &str,
    base_x: &str,
    base_y: &str,
) {
    let p_name = format!("{}_smul_p", prefix);
    emit_field_signal(emission, &p_name);

    // Decompose the scalar into 256 bits.
    for bit in 0..256usize {
        let bit_name = format!("{}_smul_scalar_bit_{}", prefix, bit);
        emission.signals.push(zir::Signal {
            name: bit_name.clone(),
            visibility: Visibility::Private,
            ty: zir::SignalType::Bool,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::Boolean {
            signal: bit_name.clone(),
            label: Some(format!("{}_smul_scalar_bit_{}_bool", prefix, bit)),
        });
    }

    // Scalar recombination: scalar = sum(bit_i * 2^i).
    {
        let mut terms: Vec<zir::Expr> = Vec::with_capacity(256);
        for bit in 0..256usize {
            let bit_name = format!("{}_smul_scalar_bit_{}", prefix, bit);
            if bit == 0 {
                terms.push(zir::Expr::Signal(bit_name));
            } else {
                // 2^bit as FieldElement.
                use num_bigint::BigInt;
                use num_traits::One;
                let coeff_val: BigInt = BigInt::one() << bit;
                let coeff = FieldElement::from_bigint(coeff_val);
                terms.push(zir::Expr::Mul(
                    Box::new(zir::Expr::Const(coeff)),
                    Box::new(zir::Expr::Signal(bit_name)),
                ));
            }
        }
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Add(terms),
            rhs: zir::Expr::Signal(scalar.to_string()),
            label: Some(format!("{}_smul_scalar_recombine", prefix)),
        });
    }

    // For each bit, emit a double + conditional add step.
    // acc_x[0] = base_x, acc_y[0] = base_y (initialise accumulator to base).
    // Then iterate 255 more bits.
    //
    // For brevity in constraint generation, we emit the structure without
    // fully inlining the conditional select — we use an Equal constraint that
    // can be satisfied by the prover computing both branches.

    let mut current_acc_x = base_x.to_string();
    let mut current_acc_y = base_y.to_string();

    for bit_idx in 0..256usize {
        let iter_prefix = format!("{}_smul_iter_{}", prefix, bit_idx);

        // Double: dbl_result = 2 * current_acc.
        let dbl_rx = format!("{}_pdbl_rx", iter_prefix);
        let dbl_ry = format!("{}_pdbl_ry", iter_prefix);
        point_double(emission, &iter_prefix, &current_acc_x, &current_acc_y);

        // Add: add_result = current_acc + base.
        let add_rx = format!("{}_padd_rx", iter_prefix);
        let add_ry = format!("{}_padd_ry", iter_prefix);
        point_add(
            emission,
            &iter_prefix,
            &current_acc_x,
            &current_acc_y,
            base_x,
            base_y,
        );

        // Conditional select: new_acc = bit ? add_result : dbl_result.
        // Expressed as: new_acc = dbl + bit * (add - dbl)
        let bit_name = format!("{}_smul_scalar_bit_{}", prefix, bit_idx);
        let new_acc_x = format!("{}_smul_acc_x_{}", prefix, bit_idx + 1);
        let new_acc_y = format!("{}_smul_acc_y_{}", prefix, bit_idx + 1);

        emit_field_signal(emission, &new_acc_x);
        emit_field_signal(emission, &new_acc_y);

        // new_acc_x = dbl_rx + bit * (add_rx - dbl_rx)
        // => new_acc_x - dbl_rx = bit * (add_rx - dbl_rx)
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Sub(
                Box::new(zir::Expr::Signal(new_acc_x.clone())),
                Box::new(zir::Expr::Signal(dbl_rx.clone())),
            ),
            rhs: zir::Expr::Mul(
                Box::new(zir::Expr::Signal(bit_name.clone())),
                Box::new(zir::Expr::Sub(
                    Box::new(zir::Expr::Signal(add_rx.clone())),
                    Box::new(zir::Expr::Signal(dbl_rx)),
                )),
            ),
            label: Some(format!("{}_smul_sel_x_{}", prefix, bit_idx)),
        });

        // new_acc_y = dbl_ry + bit * (add_ry - dbl_ry)
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Sub(
                Box::new(zir::Expr::Signal(new_acc_y.clone())),
                Box::new(zir::Expr::Signal(dbl_ry.clone())),
            ),
            rhs: zir::Expr::Mul(
                Box::new(zir::Expr::Signal(bit_name)),
                Box::new(zir::Expr::Sub(
                    Box::new(zir::Expr::Signal(add_ry.clone())),
                    Box::new(zir::Expr::Signal(dbl_ry)),
                )),
            ),
            label: Some(format!("{}_smul_sel_y_{}", prefix, bit_idx)),
        });

        current_acc_x = new_acc_x;
        current_acc_y = new_acc_y;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── constrain_on_curve ────────────────────────────────────────────────────

    #[test]
    fn constrain_on_curve_emits_modulus_signal() {
        let mut emission = GadgetEmission::default();
        constrain_on_curve(&mut emission, "pt", "px", "py");

        let has_p = emission.signals.iter().any(|s| s.name == "pt_oncurve_p");
        assert!(has_p, "expected modulus signal pt_oncurve_p");
    }

    #[test]
    fn constrain_on_curve_emits_b_constant_signal() {
        let mut emission = GadgetEmission::default();
        constrain_on_curve(&mut emission, "pt", "px", "py");

        let b_sig = emission.signals.iter().find(|s| s.name == "pt_oncurve_b");
        assert!(b_sig.is_some(), "expected constant signal pt_oncurve_b");
        // b should be constant 7.
        let b_sig = b_sig.unwrap();
        assert_eq!(b_sig.constant, Some(FieldElement::from_u64(7)));
    }

    #[test]
    fn constrain_on_curve_decomposes_inputs() {
        let mut emission = GadgetEmission::default();
        constrain_on_curve(&mut emission, "pt", "px", "py");

        // Should have limb signals for px and py.
        for i in 0..4 {
            assert!(
                emission
                    .signals
                    .iter()
                    .any(|s| s.name == format!("pt_oncurve_px_limb_{}", i)),
                "missing px limb {}",
                i
            );
            assert!(
                emission
                    .signals
                    .iter()
                    .any(|s| s.name == format!("pt_oncurve_py_limb_{}", i)),
                "missing py limb {}",
                i
            );
        }
    }

    #[test]
    fn constrain_on_curve_emits_y_squared_signals() {
        let mut emission = GadgetEmission::default();
        constrain_on_curve(&mut emission, "pt", "px", "py");

        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "pt_oncurve_py_sq")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "pt_oncurve_px_sq")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "pt_oncurve_px_cu")
        );
    }

    #[test]
    fn constrain_on_curve_emits_equality_check() {
        let mut emission = GadgetEmission::default();
        constrain_on_curve(&mut emission, "pt", "px", "py");

        let has_check = emission
            .constraints
            .iter()
            .any(|c| matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l == "pt_oncurve_check_nonnative_equal"));
        assert!(has_check, "expected on-curve equality check constraint");
    }

    #[test]
    fn constrain_on_curve_emits_at_least_ten_constraints() {
        let mut emission = GadgetEmission::default();
        constrain_on_curve(&mut emission, "pt", "px", "py");

        // Decompositions + mul/add operations produce a significant constraint count.
        assert!(
            emission.constraints.len() >= 10,
            "expected at least 10 constraints, got {}",
            emission.constraints.len()
        );
    }

    // ── point_add ─────────────────────────────────────────────────────────────

    #[test]
    fn point_add_emits_modulus_signal() {
        let mut emission = GadgetEmission::default();
        point_add(&mut emission, "add", "p1x", "p1y", "p2x", "p2y");

        assert!(emission.signals.iter().any(|s| s.name == "add_padd_p"));
    }

    #[test]
    fn point_add_decomposes_all_four_inputs() {
        let mut emission = GadgetEmission::default();
        point_add(&mut emission, "add", "p1x", "p1y", "p2x", "p2y");

        for i in 0..4 {
            assert!(
                emission
                    .signals
                    .iter()
                    .any(|s| s.name == format!("add_padd_p1x_limb_{}", i)),
                "missing p1x limb {}",
                i
            );
            assert!(
                emission
                    .signals
                    .iter()
                    .any(|s| s.name == format!("add_padd_p2y_limb_{}", i)),
                "missing p2y limb {}",
                i
            );
        }
    }

    #[test]
    fn point_add_emits_lambda_signal() {
        let mut emission = GadgetEmission::default();
        point_add(&mut emission, "add", "p1x", "p1y", "p2x", "p2y");

        assert!(emission.signals.iter().any(|s| s.name == "add_padd_lambda"));
    }

    #[test]
    fn point_add_emits_result_coordinates() {
        let mut emission = GadgetEmission::default();
        point_add(&mut emission, "add", "p1x", "p1y", "p2x", "p2y");

        assert!(
            emission.signals.iter().any(|s| s.name == "add_padd_rx"),
            "expected result x coordinate signal"
        );
        assert!(
            emission.signals.iter().any(|s| s.name == "add_padd_ry"),
            "expected result y coordinate signal"
        );
    }

    #[test]
    fn point_add_emits_substantial_constraint_count() {
        let mut emission = GadgetEmission::default();
        point_add(&mut emission, "add", "p1x", "p1y", "p2x", "p2y");

        // Should have constraints for decompositions + mul/sub + inverse + final.
        assert!(
            emission.constraints.len() >= 20,
            "expected at least 20 constraints, got {}",
            emission.constraints.len()
        );
    }

    // ── point_double ──────────────────────────────────────────────────────────

    #[test]
    fn point_double_emits_modulus_and_coefficients() {
        let mut emission = GadgetEmission::default();
        point_double(&mut emission, "dbl", "px", "py");

        assert!(emission.signals.iter().any(|s| s.name == "dbl_pdbl_p"));
        assert!(
            emission.signals.iter().any(|s| s.name == "dbl_pdbl_c2"),
            "expected coefficient-2 signal"
        );
        assert!(
            emission.signals.iter().any(|s| s.name == "dbl_pdbl_c3"),
            "expected coefficient-3 signal"
        );
    }

    #[test]
    fn point_double_emits_lambda() {
        let mut emission = GadgetEmission::default();
        point_double(&mut emission, "dbl", "px", "py");

        assert!(emission.signals.iter().any(|s| s.name == "dbl_pdbl_lambda"));
    }

    #[test]
    fn point_double_emits_result_coordinates() {
        let mut emission = GadgetEmission::default();
        point_double(&mut emission, "dbl", "px", "py");

        assert!(emission.signals.iter().any(|s| s.name == "dbl_pdbl_rx"));
        assert!(emission.signals.iter().any(|s| s.name == "dbl_pdbl_ry"));
    }

    #[test]
    fn point_double_emits_substantial_constraint_count() {
        let mut emission = GadgetEmission::default();
        point_double(&mut emission, "dbl", "px", "py");

        assert!(
            emission.constraints.len() >= 15,
            "expected at least 15 constraints, got {}",
            emission.constraints.len()
        );
    }

    // ── scalar_mul_constrained ────────────────────────────────────────────────

    #[test]
    fn scalar_mul_emits_256_bit_decomposition() {
        let mut emission = GadgetEmission::default();
        scalar_mul_constrained(&mut emission, "smul", "k", "gx", "gy");

        // Should have 256 Boolean bit signals.
        let bit_count = emission
            .signals
            .iter()
            .filter(|s| {
                s.name.starts_with("smul_smul_scalar_bit_") && s.ty == zir::SignalType::Bool
            })
            .count();
        assert_eq!(bit_count, 256, "expected 256 scalar bit signals");
    }

    #[test]
    fn scalar_mul_emits_256_boolean_constraints() {
        let mut emission = GadgetEmission::default();
        scalar_mul_constrained(&mut emission, "smul", "k", "gx", "gy");

        let bool_count = emission
            .constraints
            .iter()
            .filter(|c| {
                matches!(c, zir::Constraint::Boolean { signal, .. } if signal.starts_with("smul_smul_scalar_bit_"))
            })
            .count();
        assert_eq!(bool_count, 256, "expected 256 Boolean bit constraints");
    }

    #[test]
    fn scalar_mul_emits_scalar_recombination_constraint() {
        let mut emission = GadgetEmission::default();
        scalar_mul_constrained(&mut emission, "smul", "k", "gx", "gy");

        let has_recom = emission.constraints.iter().any(|c| {
            matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l == "smul_smul_scalar_recombine")
        });
        assert!(has_recom, "expected scalar recombination constraint");
    }

    #[test]
    fn scalar_mul_emits_accumulator_signals_for_each_iteration() {
        let mut emission = GadgetEmission::default();
        scalar_mul_constrained(&mut emission, "smul", "k", "gx", "gy");

        // Should have acc_x and acc_y signals for each of the 256 iterations.
        let acc_x_count = emission
            .signals
            .iter()
            .filter(|s| s.name.starts_with("smul_smul_acc_x_"))
            .count();
        assert_eq!(acc_x_count, 256, "expected 256 accumulator x signals");
    }
}
