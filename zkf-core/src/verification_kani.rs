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

#![allow(dead_code)]

use crate::FieldElement;
#[cfg(feature = "kani-residual")]
use crate::FieldId;
#[cfg(feature = "kani-residual")]
use crate::field::{
    add as field_add, inv as field_inv, mul as field_mul, normalize as field_normalize,
    sub as field_sub,
};
#[cfg(feature = "kani-residual")]
use crate::proof_kernel::{self, KernelConstraint, KernelExpr, KernelProgram, KernelWitness};
#[cfg(feature = "kani-residual")]
use crate::proof_kernel_spec::{
    self, SpecFieldValue, SpecKernelConstraint, SpecKernelExpr, SpecKernelLookupTable,
    SpecKernelProgram, SpecKernelWitness,
};
#[cfg(feature = "kani-residual")]
use crate::proof_witness_generation_spec::{self, SpecWitnessGenerationProgram, SpecWitnessSignal};
#[cfg(feature = "kani-residual")]
use num_bigint::{BigInt, Sign};
#[cfg(feature = "kani-residual")]
use std::collections::BTreeMap;

#[cfg(feature = "kani-residual")]
fn direct_small_field(index: u8) -> FieldId {
    match index % 3 {
        0 => FieldId::Goldilocks,
        1 => FieldId::BabyBear,
        _ => FieldId::Mersenne31,
    }
}

#[cfg(feature = "kani-residual")]
fn small_field_modulus(field: FieldId) -> u128 {
    match field {
        FieldId::Goldilocks => 18_446_744_069_414_584_321u128,
        FieldId::BabyBear => 2_013_265_921u128,
        FieldId::Mersenne31 => 2_147_483_647u128,
        _ => panic!("only direct small fields are supported in this helper"),
    }
}

#[cfg(feature = "kani-residual")]
fn normalize_small(value: i128, modulus: u128) -> u128 {
    let modulus = modulus as i128;
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    reduced as u128
}

#[cfg(feature = "kani-residual")]
fn bigint_to_u128(value: &BigInt) -> u128 {
    let (sign, bytes) = value.to_bytes_le();
    assert_ne!(sign, Sign::Minus);
    bytes.iter().enumerate().fold(0u128, |acc, (index, byte)| {
        acc | (u128::from(*byte) << (index * 8))
    })
}

#[cfg(feature = "kani-residual")]
fn spec_value_from_u64(value: u64) -> SpecFieldValue {
    SpecFieldValue::from_runtime(&FieldElement::from_u64(value))
}

#[cfg(feature = "kani-residual")]
fn spec_value_from_i64(value: i64) -> SpecFieldValue {
    SpecFieldValue::from_runtime(&FieldElement::from_i64(value))
}

#[cfg(feature = "kani-residual")]
fn required_signal() -> SpecWitnessSignal {
    SpecWitnessSignal {
        constant_value: None,
        required: true,
    }
}

#[cfg(feature = "kani-residual")]
fn spec_add(lhs: SpecKernelExpr, rhs: SpecKernelExpr) -> SpecKernelExpr {
    SpecKernelExpr::Add(Box::new(lhs), Box::new(rhs))
}

#[cfg(feature = "kani-residual")]
fn kernel_eval_expr_fixture() -> KernelExpr {
    KernelExpr::Add(vec![
        KernelExpr::Signal(0),
        KernelExpr::Signal(1),
        KernelExpr::Const(BigInt::from(3u8)),
    ])
}

#[cfg(feature = "kani-residual")]
fn linear_kernel_program() -> KernelProgram {
    KernelProgram {
        field: FieldId::BabyBear,
        constraints: vec![KernelConstraint::Equal {
            index: 0,
            lhs: KernelExpr::Signal(2),
            rhs: KernelExpr::Add(vec![KernelExpr::Signal(0), KernelExpr::Signal(1)]),
            label: Some("out=x+y".to_string()),
        }],
        lookup_tables: BTreeMap::new(),
    }
}

#[cfg(feature = "kani-residual")]
fn linear_spec_kernel_program() -> SpecKernelProgram {
    SpecKernelProgram {
        field: FieldId::BabyBear,
        constraints: vec![SpecKernelConstraint::Equal {
            index: 0,
            lhs: SpecKernelExpr::Signal(2),
            rhs: spec_add(SpecKernelExpr::Signal(0), SpecKernelExpr::Signal(1)),
        }],
        lookup_tables: vec![],
    }
}

#[cfg(feature = "kani-residual")]
fn linear_spec_witness_program() -> SpecWitnessGenerationProgram {
    SpecWitnessGenerationProgram {
        kernel_program: linear_spec_kernel_program(),
        signals: vec![required_signal(), required_signal(), required_signal()],
        assignments: vec![],
        hints: vec![],
    }
}

#[cfg(feature = "kani-residual")]
fn lookup_spec_witness_program() -> SpecWitnessGenerationProgram {
    SpecWitnessGenerationProgram {
        kernel_program: SpecKernelProgram {
            field: FieldId::BabyBear,
            constraints: vec![SpecKernelConstraint::Lookup {
                index: 0,
                inputs: vec![SpecKernelExpr::Signal(0)],
                table_index: 0,
                outputs: Some(vec![1]),
            }],
            lookup_tables: vec![SpecKernelLookupTable {
                column_count: 2,
                rows: vec![
                    vec![spec_value_from_i64(0), spec_value_from_i64(5)],
                    vec![spec_value_from_i64(1), spec_value_from_i64(9)],
                ],
            }],
        },
        signals: vec![required_signal(), required_signal()],
        assignments: vec![],
        hints: vec![],
    }
}

#[cfg(feature = "kani-residual")]
fn radix_spec_witness_program() -> SpecWitnessGenerationProgram {
    SpecWitnessGenerationProgram {
        kernel_program: SpecKernelProgram {
            field: FieldId::BabyBear,
            constraints: vec![
                SpecKernelConstraint::Range {
                    index: 0,
                    signal: 1,
                    bits: 4,
                },
                SpecKernelConstraint::Range {
                    index: 1,
                    signal: 2,
                    bits: 4,
                },
                SpecKernelConstraint::Equal {
                    index: 2,
                    lhs: SpecKernelExpr::Signal(0),
                    rhs: spec_add(
                        SpecKernelExpr::Signal(1),
                        SpecKernelExpr::Mul(
                            Box::new(SpecKernelExpr::Const(spec_value_from_i64(16))),
                            Box::new(SpecKernelExpr::Signal(2)),
                        ),
                    ),
                },
            ],
            lookup_tables: vec![],
        },
        signals: vec![required_signal(), required_signal(), required_signal()],
        assignments: vec![],
        hints: vec![],
    }
}

#[kani::proof]
fn field_element_le_bytes_roundtrip_for_small_values() {
    let raw: [u8; 4] = kani::any();
    let element = FieldElement::from_le_bytes(&raw);
    let canonical = element.to_le_bytes();
    let expected_len = if raw[3] != 0 {
        4
    } else if raw[2] != 0 {
        3
    } else if raw[1] != 0 {
        2
    } else if raw[0] != 0 {
        1
    } else {
        0
    };

    assert_eq!(canonical.len(), expected_len);
    if expected_len > 0 {
        assert_eq!(canonical[0], raw[0]);
    }
    if expected_len > 1 {
        assert_eq!(canonical[1], raw[1]);
    }
    if expected_len > 2 {
        assert_eq!(canonical[2], raw[2]);
    }
    if expected_len > 3 {
        assert_eq!(canonical[3], raw[3]);
    }
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn direct_small_field_normalization_matches_expected_modulus() {
    let selector: u8 = kani::any();
    kani::assume(selector < 3);
    let value: i16 = kani::any();
    let field = direct_small_field(selector);
    let normalized = field_normalize(BigInt::from(i64::from(value)), field);
    let via_element = FieldElement::from_i64(i64::from(value))
        .normalized_bigint(field)
        .expect("field normalization");
    let expected = normalize_small(i128::from(value), small_field_modulus(field));

    assert_eq!(normalized, via_element);
    assert_eq!(bigint_to_u128(&normalized), expected);
}

#[cfg(feature = "kani-residual")]
fn assert_small_field_arithmetic_matches_expected_modulus(field: FieldId) {
    let lhs: u8 = kani::any();
    let rhs: u8 = kani::any();
    let modulus = small_field_modulus(field);
    let lhs_bigint = BigInt::from(u64::from(lhs));
    let rhs_bigint = BigInt::from(u64::from(rhs));

    let add_result = field_add(&lhs_bigint, &rhs_bigint, field);
    let sub_result = field_sub(&lhs_bigint, &rhs_bigint, field);
    let mul_result = field_mul(&lhs_bigint, &rhs_bigint, field);

    assert_eq!(
        bigint_to_u128(&add_result),
        (u128::from(lhs) + u128::from(rhs)) % modulus
    );
    assert_eq!(
        bigint_to_u128(&sub_result),
        normalize_small(i128::from(lhs) - i128::from(rhs), modulus)
    );
    assert_eq!(
        bigint_to_u128(&mul_result),
        (u128::from(lhs) * u128::from(rhs)) % modulus
    );
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn goldilocks_arithmetic_matches_expected_modulus() {
    assert_small_field_arithmetic_matches_expected_modulus(FieldId::Goldilocks);
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn babybear_arithmetic_matches_expected_modulus() {
    assert_small_field_arithmetic_matches_expected_modulus(FieldId::BabyBear);
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn mersenne31_arithmetic_matches_expected_modulus() {
    assert_small_field_arithmetic_matches_expected_modulus(FieldId::Mersenne31);
}

#[cfg(feature = "kani-residual")]
fn assert_small_field_inverse_yields_identity(field: FieldId) {
    let value: u8 = kani::any();
    kani::assume(value != 0);
    let inverse = field_inv(&BigInt::from(u64::from(value)), field).expect("non-zero inverse");
    let product = crate::normalize_mod(BigInt::from(u64::from(value)) * inverse, field.modulus());

    assert_eq!(product, BigInt::from(1u8));
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn goldilocks_inverse_yields_identity_on_small_inputs() {
    assert_small_field_inverse_yields_identity(FieldId::Goldilocks);
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn babybear_inverse_yields_identity_on_small_inputs() {
    assert_small_field_inverse_yields_identity(FieldId::BabyBear);
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn mersenne31_inverse_yields_identity_on_small_inputs() {
    assert_small_field_inverse_yields_identity(FieldId::Mersenne31);
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn eval_expr_matches_expected_sum_on_bounded_inputs() {
    let x: u8 = kani::any();
    let y: u8 = kani::any();
    let witness = KernelWitness {
        values: vec![
            Some(BigInt::from(u64::from(x))),
            Some(BigInt::from(u64::from(y))),
        ],
    };
    let value = proof_kernel::eval_expr(&kernel_eval_expr_fixture(), &witness, FieldId::BabyBear)
        .expect("expression evaluates");

    assert_eq!(value, BigInt::from(u64::from(x) + u64::from(y) + 3));
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn constant_time_eval_matches_standard_eval() {
    let expr = KernelExpr::Signal(0);
    let witness = KernelWitness {
        values: vec![Some(BigInt::from(2u8))],
    };
    let reference = proof_kernel::eval_expr_reference(&expr, &witness, FieldId::BabyBear)
        .expect("reference expression evaluates");
    let hardened = proof_kernel::eval_expr_constant_time(&expr, &witness, FieldId::BabyBear)
        .expect("constant-time expression evaluates");

    assert_eq!(reference, hardened);
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn witness_generation_respects_linear_constraints() {
    let x: u8 = kani::any();
    let y: u8 = kani::any();
    let program = linear_spec_witness_program();
    let witness = proof_witness_generation_spec::generate_non_blackbox_witness(
        &program,
        &[
            Some(spec_value_from_u64(u64::from(x))),
            Some(spec_value_from_u64(u64::from(y))),
            None,
        ],
    )
    .expect("witness generation");

    assert_eq!(
        witness.values[2].as_ref(),
        Some(&spec_value_from_u64(u64::from(x) + u64::from(y)))
    );
    proof_kernel_spec::check_program(&program.kernel_program, &witness).expect("constraint check");
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn lookup_generation_matches_non_blackbox_spec_subset() {
    let selector: u8 = kani::any();
    kani::assume(selector < 2);
    let program = lookup_spec_witness_program();
    let witness = proof_witness_generation_spec::generate_non_blackbox_witness(
        &program,
        &[Some(spec_value_from_u64(u64::from(selector))), None],
    )
    .expect("lookup witness generation");

    let expected = if selector == 0 { 5 } else { 9 };
    assert_eq!(
        witness.values[1].as_ref(),
        Some(&spec_value_from_u64(expected))
    );
    proof_kernel_spec::check_program(&program.kernel_program, &witness).expect("lookup validates");
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn radix_generation_matches_non_blackbox_spec_subset() {
    let value: u8 = kani::any();
    let program = radix_spec_witness_program();
    let witness = proof_witness_generation_spec::generate_non_blackbox_witness(
        &program,
        &[Some(spec_value_from_u64(u64::from(value))), None, None],
    )
    .expect("radix witness generation");

    assert_eq!(
        witness.values[1].as_ref(),
        Some(&spec_value_from_u64(u64::from(value & 0x0f)))
    );
    assert_eq!(
        witness.values[2].as_ref(),
        Some(&spec_value_from_u64(u64::from(value >> 4)))
    );
    proof_kernel_spec::check_program(&program.kernel_program, &witness).expect("radix validates");
}

#[cfg(feature = "kani-residual")]
#[kani::proof]
fn check_constraints_matches_spec_kernel_translation_for_valid_linear_witness() {
    let x: u8 = kani::any();
    let y: u8 = kani::any();
    let sum = u64::from(x) + u64::from(y);
    let kernel_witness = KernelWitness {
        values: vec![
            Some(BigInt::from(u64::from(x))),
            Some(BigInt::from(u64::from(y))),
            Some(BigInt::from(sum)),
        ],
    };
    let spec_witness = SpecKernelWitness {
        values: vec![
            Some(spec_value_from_u64(u64::from(x))),
            Some(spec_value_from_u64(u64::from(y))),
            Some(spec_value_from_u64(sum)),
        ],
    };

    proof_kernel::check_program(&linear_kernel_program(), &kernel_witness)
        .expect("runtime kernel validates");
    proof_kernel_spec::check_program(&linear_spec_kernel_program(), &spec_witness)
        .expect("spec kernel validates");
}

#[cfg(all(feature = "kani-residual", feature = "full"))]
#[kani::proof]
fn ccs_lookup_constraints_fail_closed() {
    let err = crate::ccs::lookup_constraint_fail_closed_for_verification()
        .expect_err("lookup constraints must fail closed");
    assert!(matches!(
        err,
        crate::ZkfError::UnsupportedCcsEncoding { .. }
    ));
}
