#![cfg_attr(not(test), allow(dead_code))]

use num_bigint::{BigInt, Sign};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zkf_core::{BlackBoxOp, Expr, FieldElement, ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::private_identity::poseidon_hash4_bn254;

pub(crate) const SCIENCE_SCALE_DECIMALS: usize = 9;

pub(crate) fn zero() -> BigInt {
    BigInt::from(0u8)
}

pub(crate) fn one() -> BigInt {
    BigInt::from(1u8)
}

pub(crate) fn two() -> BigInt {
    BigInt::from(2u8)
}

pub(crate) fn science_scale() -> BigInt {
    BigInt::from(10u8).pow(SCIENCE_SCALE_DECIMALS as u32)
}

pub(crate) fn science_scale_string() -> String {
    format!("10^{}", SCIENCE_SCALE_DECIMALS)
}

fn digits_to_bigint(digits: &str) -> BigInt {
    digits
        .bytes()
        .filter(|digit| digit.is_ascii_digit())
        .fold(zero(), |acc, digit| {
            acc * BigInt::from(10u8) + BigInt::from(u32::from(digit - b'0'))
        })
}

pub(crate) fn decimal_scaled(value: &str) -> BigInt {
    let negative = value.starts_with('-');
    let body = if negative { &value[1..] } else { value };
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    let whole_value = if whole.is_empty() {
        zero()
    } else {
        digits_to_bigint(whole)
    };
    let mut fraction_digits = fraction.to_string();
    if fraction_digits.len() > SCIENCE_SCALE_DECIMALS {
        fraction_digits.truncate(SCIENCE_SCALE_DECIMALS);
    }
    while fraction_digits.len() < SCIENCE_SCALE_DECIMALS {
        fraction_digits.push('0');
    }
    let fraction_value = if fraction_digits.is_empty() {
        zero()
    } else {
        digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * science_scale() + fraction_value;
    if negative { -scaled } else { scaled }
}

pub(crate) fn scaled_bigint_to_decimal_string(value: &BigInt) -> String {
    let negative = value.sign() == Sign::Minus;
    let abs = abs_bigint(value.clone());
    let scale = science_scale();
    let whole = &abs / &scale;
    let fraction = (&abs % &scale).to_str_radix(10);
    let mut fraction = format!("{fraction:0>width$}", width = SCIENCE_SCALE_DECIMALS);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    let mut out = if fraction.is_empty() {
        whole.to_str_radix(10)
    } else {
        format!("{}.{}", whole.to_str_radix(10), fraction)
    };
    if negative && out != "0" {
        out.insert(0, '-');
    }
    out
}

pub(crate) fn abs_bigint(value: BigInt) -> BigInt {
    if value.sign() == Sign::Minus {
        -value
    } else {
        value
    }
}

pub(crate) fn bits_for_bound(bound: &BigInt) -> u32 {
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
    }
}

pub(crate) fn field(value: BigInt) -> FieldElement {
    FieldElement::from_bigint(value)
}

pub(crate) fn field_ref(value: &BigInt) -> FieldElement {
    FieldElement::from_bigint(value.clone())
}

pub(crate) fn const_expr(value: &BigInt) -> Expr {
    Expr::Const(field_ref(value))
}

pub(crate) fn signal_expr(name: &str) -> Expr {
    Expr::signal(name)
}

pub(crate) fn add_expr(mut values: Vec<Expr>) -> Expr {
    if values.len() == 1 {
        values.remove(0)
    } else {
        Expr::Add(values)
    }
}

pub(crate) fn sub_expr(left: Expr, right: Expr) -> Expr {
    Expr::Sub(Box::new(left), Box::new(right))
}

pub(crate) fn mul_expr(left: Expr, right: Expr) -> Expr {
    Expr::Mul(Box::new(left), Box::new(right))
}

pub(crate) fn sha256_hex_strings(domain: &str, values: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    for value in values {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn sha256_hex_json<T: Serialize>(domain: &str, value: &T) -> ZkfResult<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| ZkfError::Serialization(format!("science metadata json: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn metadata_from_pairs(pairs: &[(&str, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

pub(crate) fn append_poseidon_commitment(
    builder: &mut ProgramBuilder,
    prefix: &str,
    inputs: &[Expr],
    output_name: &str,
) -> ZkfResult<()> {
    let zero_name = format!("{prefix}_zero");
    let seed_name = format!("{prefix}_seed");
    builder.constant_signal(&zero_name, FieldElement::ZERO)?;
    builder.constant_signal(&seed_name, FieldElement::ZERO)?;
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    let mut state = Expr::signal(&seed_name);
    for (chunk_index, chunk) in inputs.chunks(3).enumerate() {
        let state_names = [
            format!("{prefix}_round_{chunk_index}_state_0"),
            format!("{prefix}_round_{chunk_index}_state_1"),
            format!("{prefix}_round_{chunk_index}_state_2"),
            format!("{prefix}_round_{chunk_index}_state_3"),
        ];
        for name in &state_names {
            builder.private_signal(name)?;
        }
        let lane_0 = chunk
            .first()
            .cloned()
            .unwrap_or_else(|| Expr::signal(&zero_name));
        let lane_1 = chunk
            .get(1)
            .cloned()
            .unwrap_or_else(|| Expr::signal(&zero_name));
        let lane_2 = chunk
            .get(2)
            .cloned()
            .unwrap_or_else(|| Expr::signal(&zero_name));
        builder.constrain_blackbox(
            BlackBoxOp::Poseidon,
            &[state, lane_0, lane_1, lane_2],
            &[
                state_names[0].as_str(),
                state_names[1].as_str(),
                state_names[2].as_str(),
                state_names[3].as_str(),
            ],
            &params,
        )?;
        state = Expr::signal(&state_names[0]);
    }
    builder.constrain_equal(Expr::signal(output_name), state)?;
    Ok(())
}

pub(crate) fn poseidon_chain_commitment(values: &[FieldElement]) -> ZkfResult<FieldElement> {
    let mut state = FieldElement::ZERO;
    for chunk in values.chunks(3) {
        let lanes = [
            state.clone(),
            chunk.first().cloned().unwrap_or(FieldElement::ZERO),
            chunk.get(1).cloned().unwrap_or(FieldElement::ZERO),
            chunk.get(2).cloned().unwrap_or(FieldElement::ZERO),
        ];
        state = poseidon_hash4_bn254(&lanes).map_err(ZkfError::InvalidArtifact)?;
    }
    Ok(state)
}
