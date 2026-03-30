#![cfg_attr(not(test), allow(dead_code))]

use num_bigint::{BigInt, Sign};
use zkf_core::{ZkfError, ZkfResult};

pub fn zero() -> BigInt {
    BigInt::from(0u8)
}

pub fn one() -> BigInt {
    BigInt::from(1u8)
}

pub fn two() -> BigInt {
    BigInt::from(2u8)
}

pub fn fixed_scale(decimals: u32) -> BigInt {
    BigInt::from(10u8).pow(decimals)
}

fn digits_to_bigint(digits: &str) -> BigInt {
    digits
        .bytes()
        .filter(|digit| digit.is_ascii_digit())
        .fold(zero(), |acc, digit| {
            acc * BigInt::from(10u8) + BigInt::from(u32::from(digit - b'0'))
        })
}

pub fn decimal_scaled(value: &str, decimals: u32) -> BigInt {
    let negative = value.starts_with('-');
    let body = if negative { &value[1..] } else { value };
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    let whole_value = if whole.is_empty() {
        zero()
    } else {
        digits_to_bigint(whole)
    };
    let mut fraction_digits = fraction.to_string();
    if fraction_digits.len() > decimals as usize {
        fraction_digits.truncate(decimals as usize);
    }
    while fraction_digits.len() < decimals as usize {
        fraction_digits.push('0');
    }
    let fraction_value = if fraction_digits.is_empty() {
        zero()
    } else {
        digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * fixed_scale(decimals) + fraction_value;
    if negative { -scaled } else { scaled }
}

pub fn abs_bigint(value: &BigInt) -> BigInt {
    if value.sign() == Sign::Minus {
        -value.clone()
    } else {
        value.clone()
    }
}

pub fn bits_for_bound(bound: &BigInt) -> u32 {
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
    }
}

pub fn bigint_isqrt_floor(value: &BigInt) -> BigInt {
    if *value <= one() {
        return value.clone();
    }
    let mut low = one();
    let mut high = one() << ((bits_for_bound(value) / 2) + 2);
    while &low + &one() < high {
        let mid = (&low + &high) / two();
        let mid_sq = &mid * &mid;
        if mid_sq <= *value {
            low = mid;
        } else {
            high = mid;
        }
    }
    low
}

pub fn euclidean_division(
    numerator: &BigInt,
    denominator: &BigInt,
) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    if *denominator <= zero() {
        return Err(ZkfError::InvalidArtifact(
            "exact division denominator must be positive".to_string(),
        ));
    }
    let mut quotient = numerator / denominator;
    let mut remainder = numerator % denominator;
    if remainder.sign() == Sign::Minus {
        quotient -= one();
        remainder += denominator;
    }
    let slack = denominator - &remainder - one();
    if remainder < zero() || slack < zero() {
        return Err(ZkfError::InvalidArtifact(
            "exact division support underflow".to_string(),
        ));
    }
    Ok((quotient, remainder, slack))
}

pub fn floor_sqrt_support(value: &BigInt) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    if *value < zero() {
        return Err(ZkfError::InvalidArtifact(
            "sqrt support expects a nonnegative value".to_string(),
        ));
    }
    let sqrt = bigint_isqrt_floor(value);
    let remainder = value - (&sqrt * &sqrt);
    let next = &sqrt + one();
    let upper_slack = (&next * &next) - value - one();
    if remainder < zero() || upper_slack < zero() {
        return Err(ZkfError::InvalidArtifact(
            "sqrt support underflow".to_string(),
        ));
    }
    Ok((sqrt, remainder, upper_slack))
}

#[cfg(test)]
mod tests {
    use super::{bigint_isqrt_floor, decimal_scaled, euclidean_division, floor_sqrt_support, one};
    use num_bigint::BigInt;
    use zkf_core::ZkfError;

    #[test]
    fn decimal_scaled_handles_signed_values() {
        assert_eq!(decimal_scaled("12.34", 3), BigInt::from(12_340u32));
        assert_eq!(decimal_scaled("-0.125", 3), BigInt::from(-125i32));
    }

    #[test]
    fn euclidean_division_keeps_remainder_nonnegative() {
        let (q, r, slack) = euclidean_division(&BigInt::from(-7i32), &BigInt::from(3u8))
            .expect("euclidean division");
        assert_eq!(q, BigInt::from(-3i32));
        assert_eq!(r, BigInt::from(2u8));
        assert_eq!(slack, BigInt::from(0u8));
    }

    #[test]
    fn euclidean_division_rejects_nonpositive_denominator() {
        let error = euclidean_division(&one(), &BigInt::from(0u8)).expect_err("must fail");
        assert!(matches!(error, ZkfError::InvalidArtifact(_)));
    }

    #[test]
    fn floor_sqrt_support_brackets_the_input() {
        let (sqrt, remainder, upper_slack) =
            floor_sqrt_support(&BigInt::from(10u8)).expect("sqrt support");
        assert_eq!(sqrt, BigInt::from(3u8));
        assert_eq!(remainder, BigInt::from(1u8));
        assert_eq!(upper_slack, BigInt::from(5u8));
        assert_eq!(bigint_isqrt_floor(&BigInt::from(10u8)), BigInt::from(3u8));
    }
}
