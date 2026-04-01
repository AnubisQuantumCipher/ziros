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

//! EC point operations (ScalarMulG1, PointAddG1, PairingCheck) as constraints.

use super::{AuxCounter, LoweredBlackBox, blackbox_aux_prefix};
#[cfg(feature = "native-blackbox-solvers")]
use acir::FieldElement as AcirFieldElement;
#[cfg(feature = "native-blackbox-solvers")]
use acvm_blackbox_solver::BlackBoxFunctionSolver;
#[cfg(feature = "native-blackbox-solvers")]
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use num_bigint::BigInt;
use std::collections::BTreeMap;
#[cfg(feature = "native-blackbox-solvers")]
use zkf_core::mod_inverse_bigint;
use zkf_core::{BlackBoxOp, Expr, FieldElement, FieldId, ZkfError, ZkfResult, normalize_mod};

/// Lower ScalarMulG1: [scalar, base_x, base_y] -> [result_x, result_y]
pub fn lower_scalar_mul_g1(
    inputs: &[Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    if inputs.len() != 3 {
        return Err(format!(
            "scalar_mul_g1: expected 3 inputs (scalar, base_x, base_y), got {}",
            inputs.len()
        ));
    }
    if outputs.len() != 2 {
        return Err(format!(
            "scalar_mul_g1: expected 2 outputs (result_x, result_y), got {}",
            outputs.len()
        ));
    }

    let mut lowered = LoweredBlackBox::default();

    // Decompose scalar into 254 bits (BN254 field order)
    let scalar_bits =
        super::bits::decompose_to_bits(&mut lowered, aux, inputs[0].clone(), 254, "smul_scalar");

    // Double-and-add scalar multiplication
    let mut acc_x = lowered.add_private_signal(aux.next("smul_acc_x"));
    let mut acc_y = lowered.add_private_signal(aux.next("smul_acc_y"));
    let mut acc_is_identity = lowered.add_private_signal(aux.next("smul_acc_is_identity"));
    lowered.add_boolean(
        acc_is_identity.clone(),
        "smul_acc_is_identity_bool".to_string(),
    );

    // Start with identity (constrained to zero in affine; special handling needed)
    lowered.add_equal(
        Expr::Signal(acc_x.clone()),
        Expr::Const(FieldElement::from_i64(0)),
        "smul_acc_x_init".to_string(),
    );
    lowered.add_equal(
        Expr::Signal(acc_y.clone()),
        Expr::Const(FieldElement::from_i64(0)),
        "smul_acc_y_init".to_string(),
    );
    lowered.add_equal(
        Expr::Signal(acc_is_identity.clone()),
        Expr::Const(FieldElement::from_i64(1)),
        "smul_acc_is_identity_init".to_string(),
    );

    // For each bit from MSB to LSB: double then conditionally add
    for i in (0..254).rev() {
        let acc_is_not_identity = Expr::Sub(
            Box::new(Expr::Const(FieldElement::from_i64(1))),
            Box::new(Expr::Signal(acc_is_identity.clone())),
        );

        // Double
        let dbl_lambda = lowered.add_private_signal(aux.next(&format!("smul_dbl{i}_l")));
        let dbl_x = lowered.add_private_signal(aux.next(&format!("smul_dbl{i}_x")));
        let dbl_y = lowered.add_private_signal(aux.next(&format!("smul_dbl{i}_y")));

        // Identity-gated doubling constraints. When the accumulator is identity,
        // the doubled point stays at (0,0) and lambda is unconstrained.
        let acc_x_sq = Expr::Mul(
            Box::new(Expr::Signal(acc_x.clone())),
            Box::new(Expr::Signal(acc_x.clone())),
        );
        let three_x_sq = Expr::Mul(
            Box::new(Expr::Const(FieldElement::from_i64(3))),
            Box::new(acc_x_sq),
        );
        let two_y = Expr::Mul(
            Box::new(Expr::Const(FieldElement::from_i64(2))),
            Box::new(Expr::Signal(acc_y.clone())),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(acc_is_not_identity.clone()),
                Box::new(Expr::Sub(
                    Box::new(Expr::Mul(
                        Box::new(Expr::Signal(dbl_lambda.clone())),
                        Box::new(two_y),
                    )),
                    Box::new(three_x_sq),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_dbl{i}_lambda"),
        );

        // dbl_x = lambda² - 2*acc_x
        let lambda_sq = Expr::Mul(
            Box::new(Expr::Signal(dbl_lambda.clone())),
            Box::new(Expr::Signal(dbl_lambda.clone())),
        );
        let two_acc_x = Expr::Mul(
            Box::new(Expr::Const(FieldElement::from_i64(2))),
            Box::new(Expr::Signal(acc_x.clone())),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(acc_is_not_identity.clone()),
                Box::new(Expr::Sub(
                    Box::new(Expr::Signal(dbl_x.clone())),
                    Box::new(Expr::Sub(Box::new(lambda_sq), Box::new(two_acc_x))),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_dbl{i}_x"),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(Expr::Signal(acc_is_identity.clone())),
                Box::new(Expr::Signal(dbl_x.clone())),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_dbl{i}_x_identity"),
        );

        // dbl_y = lambda * (acc_x - dbl_x) - acc_y
        let diff = Expr::Sub(
            Box::new(Expr::Signal(acc_x.clone())),
            Box::new(Expr::Signal(dbl_x.clone())),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(acc_is_not_identity.clone()),
                Box::new(Expr::Sub(
                    Box::new(Expr::Signal(dbl_y.clone())),
                    Box::new(Expr::Sub(
                        Box::new(Expr::Mul(
                            Box::new(Expr::Signal(dbl_lambda)),
                            Box::new(diff),
                        )),
                        Box::new(Expr::Signal(acc_y.clone())),
                    )),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_dbl{i}_y"),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(Expr::Signal(acc_is_identity.clone())),
                Box::new(Expr::Signal(dbl_y.clone())),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_dbl{i}_y_identity"),
        );

        // Conditional add: if bit == 1, acc = dbl + base, else acc = dbl
        let add_lambda = lowered.add_private_signal(aux.next(&format!("smul_add{i}_l")));
        let add_x = lowered.add_private_signal(aux.next(&format!("smul_add{i}_x")));
        let add_y = lowered.add_private_signal(aux.next(&format!("smul_add{i}_y")));

        // When the doubled accumulator is still identity, selecting the add path
        // should yield the base point directly.
        lowered.add_equal(
            Expr::Mul(
                Box::new(Expr::Signal(acc_is_identity.clone())),
                Box::new(Expr::Sub(
                    Box::new(Expr::Signal(add_x.clone())),
                    Box::new(inputs[1].clone()),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_add{i}_x_identity"),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(Expr::Signal(acc_is_identity.clone())),
                Box::new(Expr::Sub(
                    Box::new(Expr::Signal(add_y.clone())),
                    Box::new(inputs[2].clone()),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_add{i}_y_identity"),
        );

        // Addition: lambda * (base_x - dbl_x) = base_y - dbl_y
        let base_x_minus_dbl_x = Expr::Sub(
            Box::new(inputs[1].clone()),
            Box::new(Expr::Signal(dbl_x.clone())),
        );
        let base_y_minus_dbl_y = Expr::Sub(
            Box::new(inputs[2].clone()),
            Box::new(Expr::Signal(dbl_y.clone())),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(acc_is_not_identity.clone()),
                Box::new(Expr::Sub(
                    Box::new(Expr::Mul(
                        Box::new(Expr::Signal(add_lambda.clone())),
                        Box::new(base_x_minus_dbl_x),
                    )),
                    Box::new(base_y_minus_dbl_y),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_add{i}_lambda"),
        );

        // add_x = lambda² - dbl_x - base_x
        let add_lambda_sq = Expr::Mul(
            Box::new(Expr::Signal(add_lambda.clone())),
            Box::new(Expr::Signal(add_lambda.clone())),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(acc_is_not_identity.clone()),
                Box::new(Expr::Sub(
                    Box::new(Expr::Signal(add_x.clone())),
                    Box::new(Expr::Sub(
                        Box::new(add_lambda_sq),
                        Box::new(Expr::Add(vec![
                            Expr::Signal(dbl_x.clone()),
                            inputs[1].clone(),
                        ])),
                    )),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_add{i}_x"),
        );

        // add_y = lambda * (dbl_x - add_x) - dbl_y
        let dbl_x_minus_add_x = Expr::Sub(
            Box::new(Expr::Signal(dbl_x.clone())),
            Box::new(Expr::Signal(add_x.clone())),
        );
        lowered.add_equal(
            Expr::Mul(
                Box::new(acc_is_not_identity.clone()),
                Box::new(Expr::Sub(
                    Box::new(Expr::Signal(add_y.clone())),
                    Box::new(Expr::Sub(
                        Box::new(Expr::Mul(
                            Box::new(Expr::Signal(add_lambda)),
                            Box::new(dbl_x_minus_add_x),
                        )),
                        Box::new(Expr::Signal(dbl_y.clone())),
                    )),
                )),
            ),
            Expr::Const(FieldElement::from_i64(0)),
            format!("smul_add{i}_y"),
        );

        // Select: new_acc = bit ? add : dbl
        let new_acc_x = lowered.add_private_signal(aux.next(&format!("smul_sel{i}_x")));
        let new_acc_y = lowered.add_private_signal(aux.next(&format!("smul_sel{i}_y")));
        let new_acc_is_identity =
            lowered.add_private_signal(aux.next(&format!("smul_sel{i}_is_identity")));
        lowered.add_boolean(
            new_acc_is_identity.clone(),
            format!("smul_sel{i}_is_identity_bool"),
        );

        // new_acc_x = dbl_x + bit * (add_x - dbl_x)
        let diff_x = Expr::Sub(
            Box::new(Expr::Signal(add_x)),
            Box::new(Expr::Signal(dbl_x.clone())),
        );
        lowered.add_equal(
            Expr::Signal(new_acc_x.clone()),
            Expr::Add(vec![
                Expr::Signal(dbl_x),
                Expr::Mul(
                    Box::new(Expr::Signal(scalar_bits[i].clone())),
                    Box::new(diff_x),
                ),
            ]),
            format!("smul_sel{i}_x"),
        );

        let diff_y = Expr::Sub(
            Box::new(Expr::Signal(add_y)),
            Box::new(Expr::Signal(dbl_y.clone())),
        );
        lowered.add_equal(
            Expr::Signal(new_acc_y.clone()),
            Expr::Add(vec![
                Expr::Signal(dbl_y),
                Expr::Mul(
                    Box::new(Expr::Signal(scalar_bits[i].clone())),
                    Box::new(diff_y),
                ),
            ]),
            format!("smul_sel{i}_y"),
        );
        lowered.add_equal(
            Expr::Signal(new_acc_is_identity.clone()),
            Expr::Sub(
                Box::new(Expr::Signal(acc_is_identity.clone())),
                Box::new(Expr::Mul(
                    Box::new(Expr::Signal(acc_is_identity.clone())),
                    Box::new(Expr::Signal(scalar_bits[i].clone())),
                )),
            ),
            format!("smul_sel{i}_is_identity"),
        );

        acc_x = new_acc_x;
        acc_y = new_acc_y;
        acc_is_identity = new_acc_is_identity;
    }

    // Final result
    lowered.add_equal(
        Expr::Signal(outputs[0].clone()),
        Expr::Signal(acc_x),
        "smul_result_x".to_string(),
    );
    lowered.add_equal(
        Expr::Signal(outputs[1].clone()),
        Expr::Signal(acc_y),
        "smul_result_y".to_string(),
    );

    Ok(lowered)
}

/// Lower PointAddG1: [x1, y1, x2, y2] -> [x3, y3]
pub fn lower_point_add_g1(
    inputs: &[Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    if inputs.len() != 4 {
        return Err(format!(
            "point_add_g1: expected 4 inputs (x1, y1, x2, y2), got {}",
            inputs.len()
        ));
    }
    if outputs.len() != 2 {
        return Err(format!(
            "point_add_g1: expected 2 outputs (x3, y3), got {}",
            outputs.len()
        ));
    }

    let mut lowered = LoweredBlackBox::default();

    let lambda = lowered.add_private_signal(aux.next("padd_lambda"));

    // lambda * (x2 - x1) = y2 - y1
    let dx = Expr::Sub(Box::new(inputs[2].clone()), Box::new(inputs[0].clone()));
    let dy = Expr::Sub(Box::new(inputs[3].clone()), Box::new(inputs[1].clone()));
    lowered.add_equal(
        Expr::Mul(Box::new(Expr::Signal(lambda.clone())), Box::new(dx)),
        dy,
        "padd_lambda_def".to_string(),
    );

    // x3 = lambda² - x1 - x2
    let lambda_sq = Expr::Mul(
        Box::new(Expr::Signal(lambda.clone())),
        Box::new(Expr::Signal(lambda.clone())),
    );
    lowered.add_equal(
        Expr::Signal(outputs[0].clone()),
        Expr::Sub(
            Box::new(lambda_sq),
            Box::new(Expr::Add(vec![inputs[0].clone(), inputs[2].clone()])),
        ),
        "padd_x3_def".to_string(),
    );

    // y3 = lambda * (x1 - x3) - y1
    let x1_minus_x3 = Expr::Sub(
        Box::new(inputs[0].clone()),
        Box::new(Expr::Signal(outputs[0].clone())),
    );
    lowered.add_equal(
        Expr::Signal(outputs[1].clone()),
        Expr::Sub(
            Box::new(Expr::Mul(
                Box::new(Expr::Signal(lambda)),
                Box::new(x1_minus_x3),
            )),
            Box::new(inputs[1].clone()),
        ),
        "padd_y3_def".to_string(),
    );

    Ok(lowered)
}

/// Lower PairingCheck: e(A, B) == e(C, D)
///
/// Pairing checks are extremely expensive in-circuit (~millions of constraints).
/// This is typically handled via recursive proof composition rather than
/// direct in-circuit verification.
pub fn lower_pairing_check(
    _inputs: &[Expr],
    _outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    // PairingCheck cannot be soundly lowered to R1CS:
    // A full BN254 Miller loop + final exponentiation requires ~500K+ constraints.
    // The previous stub only constrained the output to boolean (unsound: a prover
    // can forge any pairing check result). Return an explicit error so callers
    // use proof recursion/aggregation instead.
    Err(
        "PairingCheck lowering is not supported in R1CS: in-circuit pairing verification \
         requires ~500K+ constraints (Miller loop + final exponentiation) and is not sound \
         with a boolean-only stub. Use recursive proof composition or a pairing-friendly \
         circuit for cryptographic pairing verification."
            .to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "native-blackbox-solvers")]
pub fn compute_ec_witness(
    op: BlackBoxOp,
    input_values: &[BigInt],
    output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    field: FieldId,
    label: &Option<String>,
    index: usize,
    witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    if field != FieldId::Bn254 {
        return Ok(());
    }

    let modulus = field.modulus();
    let normalize = |value: BigInt| normalize_mod(value, modulus);
    let to_field = |value: BigInt| FieldElement::from_bigint_with_field(normalize(value), field);
    let to_acir = |value: &BigInt| {
        let normalized = normalize(value.clone());
        let (_, mut bytes) = normalized.to_bytes_be();
        if bytes.is_empty() {
            bytes.push(0);
        }
        AcirFieldElement::from_be_bytes_reduce(&bytes)
    };
    let from_acir = |value: AcirFieldElement| {
        normalize(BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &value.to_be_bytes(),
        ))
    };
    let inv = |value: BigInt| -> ZkfResult<BigInt> {
        mod_inverse_bigint(normalize(value), modulus).ok_or_else(|| {
            ZkfError::Backend(
                "ec gadget witness generation hit a non-invertible denominator".into(),
            )
        })
    };

    let prefix = blackbox_aux_prefix(op, label, index);
    let mut aux = AuxCounter::new(prefix);
    let solver = Bn254BlackBoxSolver::default();

    match op {
        BlackBoxOp::PointAddG1 => {
            if input_values.len() != 4 || output_values.len() != 2 {
                return Ok(());
            }
            let lambda_name = aux.next("padd_lambda");
            let x1 = normalize(input_values[0].clone());
            let y1 = normalize(input_values[1].clone());
            let x2 = normalize(input_values[2].clone());
            let y2 = normalize(input_values[3].clone());
            let x3 = normalize(output_values[0].clone());
            let denominator = normalize(x2.clone() - x1.clone());
            let lambda = normalize((normalize(y2.clone() - y1.clone())) * inv(denominator)?);
            let expected = solver
                .ec_add(&to_acir(&x1), &to_acir(&y1), &to_acir(&x2), &to_acir(&y2))
                .map_err(|err| {
                    ZkfError::Backend(format!("point_add_g1 witness generation failed: {err}"))
                })?;
            if from_acir(expected.0) != x3
                || from_acir(expected.1) != normalize(output_values[1].clone())
            {
                return Err(ZkfError::Backend(
                    "point_add_g1 output mismatch during witness enrichment".into(),
                ));
            }
            witness_values.insert(lambda_name, to_field(lambda));
            Ok(())
        }
        BlackBoxOp::ScalarMulG1 => {
            if input_values.len() != 3 || output_values.len() != 2 {
                return Ok(());
            }

            let scalar = normalize(input_values[0].clone());
            let base_x = normalize(input_values[1].clone());
            let base_y = normalize(input_values[2].clone());
            let base_x_acir = to_acir(&base_x);
            let base_y_acir = to_acir(&base_y);

            let scalar_bits = super::bits::decompose_to_bits(
                &mut LoweredBlackBox::default(),
                &mut aux,
                Expr::Const(FieldElement::from_i64(0)),
                254,
                "smul_scalar",
            );
            let acc_x_name = aux.next("smul_acc_x");
            let acc_y_name = aux.next("smul_acc_y");
            let acc_identity_name = aux.next("smul_acc_is_identity");

            for i in 0..254 {
                let bit = if ((&scalar >> i) & BigInt::from(1u8)) == BigInt::from(0u8) {
                    BigInt::from(0u8)
                } else {
                    BigInt::from(1u8)
                };
                witness_values.insert(scalar_bits[i as usize].clone(), to_field(bit));
            }

            witness_values.insert(acc_x_name, FieldElement::from_i64(0));
            witness_values.insert(acc_y_name, FieldElement::from_i64(0));
            witness_values.insert(acc_identity_name, FieldElement::from_i64(1));

            let mut acc_x = BigInt::from(0u8);
            let mut acc_y = BigInt::from(0u8);
            let mut acc_is_identity = true;

            for i in (0..254).rev() {
                let dbl_lambda_name = aux.next(&format!("smul_dbl{i}_l"));
                let dbl_x_name = aux.next(&format!("smul_dbl{i}_x"));
                let dbl_y_name = aux.next(&format!("smul_dbl{i}_y"));
                let add_lambda_name = aux.next(&format!("smul_add{i}_l"));
                let add_x_name = aux.next(&format!("smul_add{i}_x"));
                let add_y_name = aux.next(&format!("smul_add{i}_y"));
                let new_acc_x_name = aux.next(&format!("smul_sel{i}_x"));
                let new_acc_y_name = aux.next(&format!("smul_sel{i}_y"));
                let new_acc_identity_name = aux.next(&format!("smul_sel{i}_is_identity"));

                let (dbl_lambda, dbl_x, dbl_y, add_lambda, add_x, add_y) = if acc_is_identity {
                    (
                        BigInt::from(0u8),
                        BigInt::from(0u8),
                        BigInt::from(0u8),
                        BigInt::from(0u8),
                        base_x.clone(),
                        base_y.clone(),
                    )
                } else {
                    let (dbl_x_fe, dbl_y_fe) = solver
                        .ec_add(
                            &to_acir(&acc_x),
                            &to_acir(&acc_y),
                            &to_acir(&acc_x),
                            &to_acir(&acc_y),
                        )
                        .map_err(|err| {
                            ZkfError::Backend(format!("scalar_mul_g1 doubling failed: {err}"))
                        })?;
                    let dbl_x = from_acir(dbl_x_fe);
                    let dbl_y = from_acir(dbl_y_fe);
                    let dbl_lambda = normalize(
                        normalize(BigInt::from(3u8) * &acc_x * &acc_x)
                            * inv(BigInt::from(2u8) * &acc_y)?,
                    );

                    let (add_x_fe, add_y_fe) = solver
                        .ec_add(
                            &to_acir(&dbl_x),
                            &to_acir(&dbl_y),
                            &base_x_acir,
                            &base_y_acir,
                        )
                        .map_err(|err| {
                            ZkfError::Backend(format!("scalar_mul_g1 addition failed: {err}"))
                        })?;
                    let add_x = from_acir(add_x_fe);
                    let add_y = from_acir(add_y_fe);
                    let add_lambda = normalize(
                        normalize(base_y.clone() - &dbl_y) * inv(base_x.clone() - &dbl_x)?,
                    );

                    (dbl_lambda, dbl_x, dbl_y, add_lambda, add_x, add_y)
                };

                let bit_is_one = ((&scalar >> i) & BigInt::from(1u8)) != BigInt::from(0u8);
                let (new_acc_x, new_acc_y) = if bit_is_one {
                    (add_x.clone(), add_y.clone())
                } else {
                    (dbl_x.clone(), dbl_y.clone())
                };
                let new_acc_is_identity = acc_is_identity && !bit_is_one;

                witness_values.insert(dbl_lambda_name, to_field(dbl_lambda));
                witness_values.insert(dbl_x_name, to_field(dbl_x.clone()));
                witness_values.insert(dbl_y_name, to_field(dbl_y.clone()));
                witness_values.insert(add_lambda_name, to_field(add_lambda));
                witness_values.insert(add_x_name, to_field(add_x.clone()));
                witness_values.insert(add_y_name, to_field(add_y.clone()));
                witness_values.insert(new_acc_x_name, to_field(new_acc_x.clone()));
                witness_values.insert(new_acc_y_name, to_field(new_acc_y.clone()));
                witness_values.insert(
                    new_acc_identity_name,
                    FieldElement::from_i64(if new_acc_is_identity { 1 } else { 0 }),
                );

                acc_x = new_acc_x;
                acc_y = new_acc_y;
                acc_is_identity = new_acc_is_identity;
            }

            if acc_x != normalize(output_values[0].clone())
                || acc_y != normalize(output_values[1].clone())
            {
                return Err(ZkfError::Backend(
                    "scalar_mul_g1 output mismatch during witness enrichment".into(),
                ));
            }

            Ok(())
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(feature = "native-blackbox-solvers"))]
pub fn compute_ec_witness(
    op: BlackBoxOp,
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _index: usize,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    Err(ZkfError::Backend(format!(
        "{} witness enrichment requires native blackbox solver support",
        op.as_str()
    )))
}
