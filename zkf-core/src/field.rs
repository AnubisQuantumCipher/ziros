use crate::ZkfResult;
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FieldId {
    #[default]
    Bn254,
    Bls12_381,
    PastaFp,
    PastaFq,
    Goldilocks,
    BabyBear,
    Mersenne31,
}

static MOD_BN254: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .expect("valid BN254 modulus")
});

static MOD_BLS12_381: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str(
        "52435875175126190479447740508185965837690552500527637822603658699938581184513",
    )
    .expect("valid BLS12-381 scalar modulus")
});

static MOD_PASTA_FP: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str(
        "28948022309329048855892746252171976963363056481941560715954676764349967630337",
    )
    .expect("valid Pasta Fp modulus")
});

static MOD_PASTA_FQ: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str(
        "28948022309329048855892746252171976963363056481941647379679742748393362948097",
    )
    .expect("valid Pasta Fq modulus")
});

static MOD_GOLDILOCKS: Lazy<BigInt> =
    Lazy::new(|| BigInt::from_str("18446744069414584321").expect("valid Goldilocks modulus"));
static MOD_BABY_BEAR: Lazy<BigInt> =
    Lazy::new(|| BigInt::from_str("2013265921").expect("valid BabyBear modulus"));
static MOD_MERSENNE31: Lazy<BigInt> =
    Lazy::new(|| BigInt::from_str("2147483647").expect("valid Mersenne31 modulus"));

const MOD_GOLDILOCKS_U64: u64 = 18_446_744_069_414_584_321;
const MOD_BABY_BEAR_U64: u64 = 2_013_265_921;
const MOD_MERSENNE31_U64: u64 = 2_147_483_647;

impl FieldId {
    pub fn as_str(self) -> &'static str {
        match self {
            FieldId::Bn254 => "bn254",
            FieldId::Bls12_381 => "bls12-381",
            FieldId::PastaFp => "pasta-fp",
            FieldId::PastaFq => "pasta-fq",
            FieldId::Goldilocks => "goldilocks",
            FieldId::BabyBear => "babybear",
            FieldId::Mersenne31 => "mersenne31",
        }
    }

    pub fn modulus(self) -> &'static BigInt {
        match self {
            FieldId::Bn254 => &MOD_BN254,
            FieldId::Bls12_381 => &MOD_BLS12_381,
            FieldId::PastaFp => &MOD_PASTA_FP,
            FieldId::PastaFq => &MOD_PASTA_FQ,
            FieldId::Goldilocks => &MOD_GOLDILOCKS,
            FieldId::BabyBear => &MOD_BABY_BEAR,
            FieldId::Mersenne31 => &MOD_MERSENNE31,
        }
    }
}

impl fmt::Display for FieldId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn small_field_modulus_u64(field: FieldId) -> Option<u64> {
    match field {
        FieldId::Goldilocks => Some(MOD_GOLDILOCKS_U64),
        FieldId::BabyBear => Some(MOD_BABY_BEAR_U64),
        FieldId::Mersenne31 => Some(MOD_MERSENNE31_U64),
        _ => None,
    }
}

fn reduce_le_bytes_mod_u64(bytes: &[u8], modulus: u64) -> u64 {
    let modulus = u128::from(modulus);
    let mut remainder = 0u128;

    for &byte in bytes.iter().rev() {
        remainder = ((remainder << 8) + u128::from(byte)) % modulus;
    }

    remainder as u64
}

fn normalize_small_field_u64(value: &BigInt, field: FieldId) -> Option<u64> {
    let modulus = small_field_modulus_u64(field)?;
    let (sign, bytes) = value.to_bytes_le();
    let magnitude = reduce_le_bytes_mod_u64(&bytes, modulus);
    let normalized = match sign {
        Sign::Minus if magnitude != 0 => modulus - magnitude,
        _ => magnitude,
    };

    Some(if normalized == modulus { 0 } else { normalized })
}

fn normalize_small_field_bigint(value: &BigInt, field: FieldId) -> Option<BigInt> {
    normalize_small_field_u64(value, field).map(BigInt::from)
}

fn mod_inverse_u64(value: u64, modulus: u64) -> Option<u64> {
    if value == 0 {
        return None;
    }

    let modulus = i128::from(modulus);
    let mut t = 0i128;
    let mut new_t = 1i128;
    let mut r = modulus;
    let mut new_r = i128::from(value);

    while new_r != 0 {
        let quotient = r / new_r;

        let next_t = t - quotient * new_t;
        t = new_t;
        new_t = next_t;

        let next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;
    }

    if r != 1 {
        return None;
    }

    if t < 0 {
        t += modulus;
    }

    Some(t as u64)
}

impl FromStr for FieldId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "bn254" => Ok(Self::Bn254),
            "bls12-381" | "bls12_381" => Ok(Self::Bls12_381),
            "pasta-fp" | "pasta_fp" => Ok(Self::PastaFp),
            "pasta-fq" | "pasta_fq" => Ok(Self::PastaFq),
            "goldilocks" => Ok(Self::Goldilocks),
            "babybear" | "baby-bear" | "baby_bear" => Ok(Self::BabyBear),
            "mersenne31" | "mersenne-31" | "mersenne_31" => Ok(Self::Mersenne31),
            other => Err(format!("unknown field '{other}'")),
        }
    }
}

/// A field element stored as a byte-backed integer (little-endian unsigned
/// magnitude + sign). No string parsing on arithmetic operations.
///
/// JSON serialization emits decimal strings for backward compatibility.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone)]
pub struct FieldElement {
    /// Little-endian unsigned magnitude, zero-padded to 32 bytes.
    bytes: [u8; 32],
    /// Number of active bytes (position of last nonzero byte + 1). 0 means value is zero.
    len: u8,
    /// True if the value is negative.
    negative: bool,
}

impl FieldElement {
    /// The zero element.
    pub const ZERO: Self = Self {
        bytes: [0u8; 32],
        len: 0,
        negative: false,
    };

    /// The one element.
    pub const ONE: Self = Self {
        bytes: {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        },
        len: 1,
        negative: false,
    };

    fn canonical_len(bytes: &[u8; 32]) -> u8 {
        let mut i = 31;
        loop {
            if bytes[i] != 0 {
                return (i + 1) as u8;
            }
            if i == 0 {
                return 0;
            }
            i -= 1;
        }
    }

    /// Construct from a decimal string (for backward compatibility).
    pub fn new(value: impl Into<String>) -> Self {
        let s = value.into();
        match BigInt::from_str(&s) {
            Ok(bigint) => Self::from_bigint(bigint),
            Err(_) => {
                // Fallback: store zero and flag as invalid.
                // This preserves existing behavior where invalid strings
                // would fail at to_bigint() time.
                // We encode the raw string as bytes so that to_bigint()
                // can return a meaningful error.
                // Actually, since we can't store arbitrary strings anymore,
                // and the old code would fail at to_bigint() time, we panic
                // in debug and store zero in release.
                debug_assert!(
                    false,
                    "FieldElement::new() called with non-numeric string: {s}"
                );
                Self::ZERO
            }
        }
    }

    /// Construct from an i64 value (no string parsing).
    pub fn from_i64(value: i64) -> Self {
        if value == 0 {
            return Self::ZERO;
        }
        let negative = value < 0;
        let magnitude = if negative {
            (value as i128).unsigned_abs() as u64
        } else {
            value as u64
        };
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&magnitude.to_le_bytes());
        let len = Self::canonical_len(&bytes);
        Self {
            bytes,
            len,
            negative,
        }
    }

    /// Construct from a u64 value (no string parsing).
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            return Self::ZERO;
        }
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        let len = Self::canonical_len(&bytes);
        Self {
            bytes,
            len,
            negative: false,
        }
    }

    /// Construct from little-endian bytes (unsigned).
    pub fn from_le_bytes(src: &[u8]) -> Self {
        if src.is_empty() || src.iter().all(|&b| b == 0) {
            return Self::ZERO;
        }
        let mut bytes = [0u8; 32];
        let copy_len = src.len().min(32);
        bytes[..copy_len].copy_from_slice(&src[..copy_len]);
        let len = Self::canonical_len(&bytes);
        Self {
            bytes,
            len,
            negative: false,
        }
    }

    /// Extract the active little-endian bytes.
    pub fn to_le_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Construct from a `BigInt` (no field normalization).
    pub fn from_bigint(value: BigInt) -> Self {
        if value.is_zero() {
            return Self::ZERO;
        }
        let negative = value.sign() == Sign::Minus;
        let (_, magnitude_bytes) = value.to_bytes_le();
        let mut bytes = [0u8; 32];
        let copy_len = magnitude_bytes.len().min(32);
        bytes[..copy_len].copy_from_slice(&magnitude_bytes[..copy_len]);
        let len = Self::canonical_len(&bytes);
        Self {
            bytes,
            len,
            negative,
        }
    }

    /// Infallible conversion to `BigInt`.
    pub fn as_bigint(&self) -> BigInt {
        if self.len == 0 {
            return BigInt::zero();
        }
        let sign = if self.negative {
            Sign::Minus
        } else {
            Sign::Plus
        };
        BigInt::from_bytes_le(sign, &self.bytes[..self.len as usize])
    }

    /// Fallible conversion to `BigInt` (for backward compatibility — always succeeds).
    pub fn to_bigint(&self) -> ZkfResult<BigInt> {
        Ok(self.as_bigint())
    }

    /// Normalize modulo the given field and return the non-negative result.
    pub fn normalized_bigint(&self, field: FieldId) -> ZkfResult<BigInt> {
        Ok(normalize(self.as_bigint(), field))
    }

    /// Construct from a `BigInt` after normalizing modulo the field.
    pub fn from_bigint_with_field(value: BigInt, field: FieldId) -> Self {
        Self::from_bigint(normalize(value, field))
    }

    /// Returns true if this element represents zero.
    pub fn is_zero(&self) -> bool {
        self.len == 0
    }

    /// Returns true if this element represents one (positive).
    pub fn is_one(&self) -> bool {
        !self.negative && self.len == 1 && self.bytes[0] == 1
    }

    /// Returns the decimal string representation.
    pub fn to_decimal_string(&self) -> String {
        self.as_bigint().to_string()
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        // Zero is equal regardless of sign
        if self.len == 0 && other.len == 0 {
            return true;
        }
        self.negative == other.negative
            && self.len == other.len
            && self.bytes[..self.len as usize] == other.bytes[..other.len as usize]
    }
}

impl Eq for FieldElement {}

impl Hash for FieldElement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.len == 0 {
            0u8.hash(state);
            return;
        }
        self.negative.hash(state);
        self.bytes[..self.len as usize].hash(state);
    }
}

impl Serialize for FieldElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_decimal_string())
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bigint = BigInt::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(Self::from_bigint(bigint))
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal_string())
    }
}

pub trait FieldValue: Sized + Clone + Eq + PartialEq {
    fn field(&self) -> FieldId;
    fn normalized_bigint(&self) -> BigInt;
    fn add(&self, rhs: &Self) -> Self;
    fn sub(&self, rhs: &Self) -> Self;
    fn mul(&self, rhs: &Self) -> Self;
    fn inv(&self) -> Option<Self>;
    fn div(&self, rhs: &Self) -> Option<Self> {
        rhs.inv().map(|inv| self.mul(&inv))
    }
    fn to_field_element(&self) -> FieldElement {
        FieldElement::from_bigint_with_field(self.normalized_bigint(), self.field())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BigIntFieldValue {
    field: FieldId,
    value: BigInt,
}

impl BigIntFieldValue {
    pub fn new(field: FieldId, value: BigInt) -> Self {
        Self {
            field,
            value: normalize(value, field),
        }
    }

    pub fn from_field_element(value: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        Ok(Self::new(field, value.as_bigint()))
    }

    pub fn from_i64(field: FieldId, value: i64) -> Self {
        Self::new(field, BigInt::from(value))
    }
}

impl FieldValue for BigIntFieldValue {
    fn field(&self) -> FieldId {
        self.field
    }

    fn normalized_bigint(&self) -> BigInt {
        self.value.clone()
    }

    fn add(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.field, rhs.field);
        Self::new(self.field, add(&self.value, &rhs.value, self.field))
    }

    fn sub(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.field, rhs.field);
        Self::new(self.field, sub(&self.value, &rhs.value, self.field))
    }

    fn mul(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.field, rhs.field);
        Self::new(self.field, mul(&self.value, &rhs.value, self.field))
    }

    fn inv(&self) -> Option<Self> {
        inv(&self.value, self.field).map(|inverse| Self::new(self.field, inverse))
    }
}

pub trait FieldBackend {
    type Value: FieldValue;
    fn parse_element(field: FieldId, value: &FieldElement) -> ZkfResult<Self::Value>;
    fn from_bigint(field: FieldId, value: BigInt) -> Self::Value;
}

pub struct BigIntFieldBackend;

impl FieldBackend for BigIntFieldBackend {
    type Value = BigIntFieldValue;

    fn parse_element(field: FieldId, value: &FieldElement) -> ZkfResult<Self::Value> {
        BigIntFieldValue::from_field_element(value, field)
    }

    fn from_bigint(field: FieldId, value: BigInt) -> Self::Value {
        BigIntFieldValue::new(field, value)
    }
}

mod large_prime_fiat {
    use super::{BigInt, FieldId, Sign, normalize_mod};
    use crate::fiat_generated::{bls12_381_scalar_64, bn254_scalar_64, pasta_fp_64, pasta_fq_64};

    const LIMBS: usize = 4;
    type Words = [u64; LIMBS];
    type SaturatedWords = [u64; LIMBS + 1];

    trait FiatFieldOps {
        const FIELD: FieldId;
        const NUM_BITS: usize;

        fn to_mont(out: &mut Words, arg: &Words);
        fn from_mont(out: &mut Words, arg: &Words);
        fn add(out: &mut Words, lhs: &Words, rhs: &Words);
        fn sub(out: &mut Words, lhs: &Words, rhs: &Words);
        fn mul(out: &mut Words, lhs: &Words, rhs: &Words);
        fn opp(out: &mut Words, value: &Words);
        fn one(out: &mut Words);
        fn selectznz(out: &mut Words, choice: u8, zero: &Words, nonzero: &Words);
        fn msat(out: &mut SaturatedWords);
        #[allow(clippy::too_many_arguments)]
        fn divstep(
            out1: &mut u64,
            out2: &mut SaturatedWords,
            out3: &mut SaturatedWords,
            out4: &mut Words,
            out5: &mut Words,
            arg1: u64,
            arg2: &SaturatedWords,
            arg3: &SaturatedWords,
            arg4: &Words,
            arg5: &Words,
        );
        fn divstep_precomp(out: &mut Words);
    }

    macro_rules! impl_fiat_field_ops {
        (
            $name:ident,
            $field_id:expr,
            $num_bits:expr,
            $module:ident,
            $mont:ident,
            $non_mont:ident,
            $to_mont:ident,
            $from_mont:ident,
            $add:ident,
            $sub:ident,
            $mul:ident,
            $opp:ident,
            $one:ident,
            $selectznz:ident,
            $msat:ident,
            $divstep:ident,
            $divstep_precomp:ident
        ) => {
            struct $name;

            impl FiatFieldOps for $name {
                const FIELD: FieldId = $field_id;
                const NUM_BITS: usize = $num_bits;

                fn to_mont(out: &mut Words, arg: &Words) {
                    let mut value = $module::$mont([0; LIMBS]);
                    $module::$to_mont(&mut value, &$module::$non_mont(*arg));
                    *out = value.0;
                }

                fn from_mont(out: &mut Words, arg: &Words) {
                    let mut value = $module::$non_mont([0; LIMBS]);
                    $module::$from_mont(&mut value, &$module::$mont(*arg));
                    *out = value.0;
                }

                fn add(out: &mut Words, lhs: &Words, rhs: &Words) {
                    let mut value = $module::$mont([0; LIMBS]);
                    $module::$add(&mut value, &$module::$mont(*lhs), &$module::$mont(*rhs));
                    *out = value.0;
                }

                fn sub(out: &mut Words, lhs: &Words, rhs: &Words) {
                    let mut value = $module::$mont([0; LIMBS]);
                    $module::$sub(&mut value, &$module::$mont(*lhs), &$module::$mont(*rhs));
                    *out = value.0;
                }

                fn mul(out: &mut Words, lhs: &Words, rhs: &Words) {
                    let mut value = $module::$mont([0; LIMBS]);
                    $module::$mul(&mut value, &$module::$mont(*lhs), &$module::$mont(*rhs));
                    *out = value.0;
                }

                fn opp(out: &mut Words, value: &Words) {
                    let mut negated = $module::$mont([0; LIMBS]);
                    $module::$opp(&mut negated, &$module::$mont(*value));
                    *out = negated.0;
                }

                fn one(out: &mut Words) {
                    let mut value = $module::$mont([0; LIMBS]);
                    $module::$one(&mut value);
                    *out = value.0;
                }

                fn selectznz(out: &mut Words, choice: u8, zero: &Words, nonzero: &Words) {
                    $module::$selectznz(out, choice, zero, nonzero);
                }

                fn msat(out: &mut SaturatedWords) {
                    $module::$msat(out);
                }

                fn divstep(
                    out1: &mut u64,
                    out2: &mut SaturatedWords,
                    out3: &mut SaturatedWords,
                    out4: &mut Words,
                    out5: &mut Words,
                    arg1: u64,
                    arg2: &SaturatedWords,
                    arg3: &SaturatedWords,
                    arg4: &Words,
                    arg5: &Words,
                ) {
                    $module::$divstep(out1, out2, out3, out4, out5, arg1, arg2, arg3, arg4, arg5);
                }

                fn divstep_precomp(out: &mut Words) {
                    $module::$divstep_precomp(out);
                }
            }
        };
    }

    impl_fiat_field_ops!(
        Bn254Ops,
        FieldId::Bn254,
        254,
        bn254_scalar_64,
        fiat_bn254_scalar_montgomery_domain_field_element,
        fiat_bn254_scalar_non_montgomery_domain_field_element,
        fiat_bn254_scalar_to_montgomery,
        fiat_bn254_scalar_from_montgomery,
        fiat_bn254_scalar_add,
        fiat_bn254_scalar_sub,
        fiat_bn254_scalar_mul,
        fiat_bn254_scalar_opp,
        fiat_bn254_scalar_set_one,
        fiat_bn254_scalar_selectznz,
        fiat_bn254_scalar_msat,
        fiat_bn254_scalar_divstep,
        fiat_bn254_scalar_divstep_precomp
    );

    impl_fiat_field_ops!(
        Bls12_381Ops,
        FieldId::Bls12_381,
        255,
        bls12_381_scalar_64,
        fiat_bls12_381_scalar_montgomery_domain_field_element,
        fiat_bls12_381_scalar_non_montgomery_domain_field_element,
        fiat_bls12_381_scalar_to_montgomery,
        fiat_bls12_381_scalar_from_montgomery,
        fiat_bls12_381_scalar_add,
        fiat_bls12_381_scalar_sub,
        fiat_bls12_381_scalar_mul,
        fiat_bls12_381_scalar_opp,
        fiat_bls12_381_scalar_set_one,
        fiat_bls12_381_scalar_selectznz,
        fiat_bls12_381_scalar_msat,
        fiat_bls12_381_scalar_divstep,
        fiat_bls12_381_scalar_divstep_precomp
    );

    impl_fiat_field_ops!(
        PastaFpOps,
        FieldId::PastaFp,
        255,
        pasta_fp_64,
        fiat_pasta_fp_montgomery_domain_field_element,
        fiat_pasta_fp_non_montgomery_domain_field_element,
        fiat_pasta_fp_to_montgomery,
        fiat_pasta_fp_from_montgomery,
        fiat_pasta_fp_add,
        fiat_pasta_fp_sub,
        fiat_pasta_fp_mul,
        fiat_pasta_fp_opp,
        fiat_pasta_fp_set_one,
        fiat_pasta_fp_selectznz,
        fiat_pasta_fp_msat,
        fiat_pasta_fp_divstep,
        fiat_pasta_fp_divstep_precomp
    );

    impl_fiat_field_ops!(
        PastaFqOps,
        FieldId::PastaFq,
        255,
        pasta_fq_64,
        fiat_pasta_fq_montgomery_domain_field_element,
        fiat_pasta_fq_non_montgomery_domain_field_element,
        fiat_pasta_fq_to_montgomery,
        fiat_pasta_fq_from_montgomery,
        fiat_pasta_fq_add,
        fiat_pasta_fq_sub,
        fiat_pasta_fq_mul,
        fiat_pasta_fq_opp,
        fiat_pasta_fq_set_one,
        fiat_pasta_fq_selectznz,
        fiat_pasta_fq_msat,
        fiat_pasta_fq_divstep,
        fiat_pasta_fq_divstep_precomp
    );

    fn bigint_to_words(value: &BigInt) -> Words {
        debug_assert_ne!(value.sign(), Sign::Minus);

        let (_, bytes) = value.to_bytes_le();
        let mut words = [0u64; LIMBS];
        for (index, chunk) in bytes.chunks(8).take(LIMBS).enumerate() {
            let mut word_bytes = [0u8; 8];
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            words[index] = u64::from_le_bytes(word_bytes);
        }
        words
    }

    fn words_to_bigint(words: &Words) -> BigInt {
        let mut bytes = [0u8; LIMBS * 8];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        BigInt::from_bytes_le(Sign::Plus, &bytes)
    }

    fn normalized_words<Ops: FiatFieldOps>(value: &BigInt) -> Words {
        bigint_to_words(&normalize_mod(value.clone(), Ops::FIELD.modulus()))
    }

    fn from_mont_words<Ops: FiatFieldOps>(value: &Words) -> Words {
        let mut out = [0u64; LIMBS];
        Ops::from_mont(&mut out, value);
        out
    }

    fn to_mont_words<Ops: FiatFieldOps>(value: &Words) -> Words {
        let mut out = [0u64; LIMBS];
        Ops::to_mont(&mut out, value);
        out
    }

    fn one_words<Ops: FiatFieldOps>() -> Words {
        let mut out = [0u64; LIMBS];
        Ops::one(&mut out);
        out
    }

    fn normalize_impl<Ops: FiatFieldOps>(value: BigInt) -> BigInt {
        let reduced = normalize_mod(value, Ops::FIELD.modulus());
        let canonical = bigint_to_words(&reduced);
        let mont = to_mont_words::<Ops>(&canonical);
        words_to_bigint(&from_mont_words::<Ops>(&mont))
    }

    fn binary_op_impl<Ops, F>(lhs: &BigInt, rhs: &BigInt, op: F) -> BigInt
    where
        Ops: FiatFieldOps,
        F: FnOnce(&mut Words, &Words, &Words),
    {
        let lhs = to_mont_words::<Ops>(&normalized_words::<Ops>(lhs));
        let rhs = to_mont_words::<Ops>(&normalized_words::<Ops>(rhs));
        let mut out = [0u64; LIMBS];
        op(&mut out, &lhs, &rhs);
        words_to_bigint(&from_mont_words::<Ops>(&out))
    }

    fn invert_impl<Ops: FiatFieldOps>(value: &BigInt) -> Option<BigInt> {
        let normalized = normalized_words::<Ops>(value);
        if normalized == [0u64; LIMBS] {
            return None;
        }

        let a = to_mont_words::<Ops>(&normalized);
        let mut d = 1u64;
        let mut f = [0u64; LIMBS + 1];
        Ops::msat(&mut f);
        let mut g = [0u64; LIMBS + 1];
        g[..LIMBS].copy_from_slice(&from_mont_words::<Ops>(&a));
        let mut v = [0u64; LIMBS];
        let mut r = one_words::<Ops>();
        let iterations = (49 * Ops::NUM_BITS + 57) / 17;
        let mut i = 0usize;

        while i + 1 < iterations {
            let mut out1 = 0u64;
            let mut out2 = [0u64; LIMBS + 1];
            let mut out3 = [0u64; LIMBS + 1];
            let mut out4 = [0u64; LIMBS];
            let mut out5 = [0u64; LIMBS];
            Ops::divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );

            Ops::divstep(
                &mut d, &mut f, &mut g, &mut v, &mut r, out1, &out2, &out3, &out4, &out5,
            );
            i += 2;
        }

        if iterations % 2 != 0 {
            let mut out1 = 0u64;
            let mut out2 = [0u64; LIMBS + 1];
            let mut out3 = [0u64; LIMBS + 1];
            let mut out4 = [0u64; LIMBS];
            let mut out5 = [0u64; LIMBS];
            Ops::divstep(
                &mut out1, &mut out2, &mut out3, &mut out4, &mut out5, d, &f, &g, &v, &r,
            );
            f = out2;
            v = out4;
        }

        let sign = ((f[LIMBS] >> (u64::BITS - 1)) & 1) as u8;
        let mut neg_v = [0u64; LIMBS];
        Ops::opp(&mut neg_v, &v);

        let mut selected = [0u64; LIMBS];
        Ops::selectznz(&mut selected, sign, &v, &neg_v);

        let mut precomp = [0u64; LIMBS];
        Ops::divstep_precomp(&mut precomp);

        let mut out = [0u64; LIMBS];
        Ops::mul(&mut out, &selected, &precomp);
        Some(words_to_bigint(&from_mont_words::<Ops>(&out)))
    }

    pub(super) fn normalize(value: BigInt, field: FieldId) -> BigInt {
        match field {
            FieldId::Bn254 => normalize_impl::<Bn254Ops>(value),
            FieldId::Bls12_381 => normalize_impl::<Bls12_381Ops>(value),
            FieldId::PastaFp => normalize_impl::<PastaFpOps>(value),
            FieldId::PastaFq => normalize_impl::<PastaFqOps>(value),
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => {
                unreachable!("small fields do not use Fiat-Crypto dispatch")
            }
        }
    }

    pub(super) fn add(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        match field {
            FieldId::Bn254 => binary_op_impl::<Bn254Ops, _>(lhs, rhs, Bn254Ops::add),
            FieldId::Bls12_381 => binary_op_impl::<Bls12_381Ops, _>(lhs, rhs, Bls12_381Ops::add),
            FieldId::PastaFp => binary_op_impl::<PastaFpOps, _>(lhs, rhs, PastaFpOps::add),
            FieldId::PastaFq => binary_op_impl::<PastaFqOps, _>(lhs, rhs, PastaFqOps::add),
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => {
                unreachable!("small fields do not use Fiat-Crypto dispatch")
            }
        }
    }

    pub(super) fn sub(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        match field {
            FieldId::Bn254 => binary_op_impl::<Bn254Ops, _>(lhs, rhs, Bn254Ops::sub),
            FieldId::Bls12_381 => binary_op_impl::<Bls12_381Ops, _>(lhs, rhs, Bls12_381Ops::sub),
            FieldId::PastaFp => binary_op_impl::<PastaFpOps, _>(lhs, rhs, PastaFpOps::sub),
            FieldId::PastaFq => binary_op_impl::<PastaFqOps, _>(lhs, rhs, PastaFqOps::sub),
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => {
                unreachable!("small fields do not use Fiat-Crypto dispatch")
            }
        }
    }

    pub(super) fn mul(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        match field {
            FieldId::Bn254 => binary_op_impl::<Bn254Ops, _>(lhs, rhs, Bn254Ops::mul),
            FieldId::Bls12_381 => binary_op_impl::<Bls12_381Ops, _>(lhs, rhs, Bls12_381Ops::mul),
            FieldId::PastaFp => binary_op_impl::<PastaFpOps, _>(lhs, rhs, PastaFpOps::mul),
            FieldId::PastaFq => binary_op_impl::<PastaFqOps, _>(lhs, rhs, PastaFqOps::mul),
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => {
                unreachable!("small fields do not use Fiat-Crypto dispatch")
            }
        }
    }

    pub(super) fn inv(value: &BigInt, field: FieldId) -> Option<BigInt> {
        match field {
            FieldId::Bn254 => invert_impl::<Bn254Ops>(value),
            FieldId::Bls12_381 => invert_impl::<Bls12_381Ops>(value),
            FieldId::PastaFp => invert_impl::<PastaFpOps>(value),
            FieldId::PastaFq => invert_impl::<PastaFqOps>(value),
            FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => {
                unreachable!("small fields do not use Fiat-Crypto dispatch")
            }
        }
    }
}

fn normalize_specialized(value: BigInt, field: FieldId) -> BigInt {
    if let Some(normalized) = normalize_small_field_bigint(&value, field) {
        return normalized;
    }

    match field {
        FieldId::Bn254 | FieldId::Bls12_381 | FieldId::PastaFp | FieldId::PastaFq => {
            large_prime_fiat::normalize(value, field)
        }
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => unreachable!(),
    }
}

pub(crate) fn normalize(value: BigInt, field: FieldId) -> BigInt {
    normalize_specialized(value, field)
}

pub(crate) fn add(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
    if let Some(modulus) = small_field_modulus_u64(field) {
        let lhs = u128::from(normalize_small_field_u64(lhs, field).expect("small field"));
        let rhs = u128::from(normalize_small_field_u64(rhs, field).expect("small field"));
        let modulus = u128::from(modulus);
        return BigInt::from(((lhs + rhs) % modulus) as u64);
    }

    large_prime_fiat::add(lhs, rhs, field)
}

pub(crate) fn sub(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
    if let Some(modulus) = small_field_modulus_u64(field) {
        let lhs = normalize_small_field_u64(lhs, field).expect("small field");
        let rhs = normalize_small_field_u64(rhs, field).expect("small field");
        let difference = if lhs >= rhs {
            lhs - rhs
        } else {
            modulus - (rhs - lhs)
        };
        return BigInt::from(difference);
    }

    large_prime_fiat::sub(lhs, rhs, field)
}

pub(crate) fn mul(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
    if let Some(modulus) = small_field_modulus_u64(field) {
        let lhs = u128::from(normalize_small_field_u64(lhs, field).expect("small field"));
        let rhs = u128::from(normalize_small_field_u64(rhs, field).expect("small field"));
        let modulus = u128::from(modulus);
        return BigInt::from(((lhs * rhs) % modulus) as u64);
    }

    large_prime_fiat::mul(lhs, rhs, field)
}

pub(crate) fn inv(value: &BigInt, field: FieldId) -> Option<BigInt> {
    if let Some(modulus) = small_field_modulus_u64(field) {
        let value = normalize_small_field_u64(value, field).expect("small field");
        return mod_inverse_u64(value, modulus).map(BigInt::from);
    }

    large_prime_fiat::inv(value, field)
}

pub(crate) fn div(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> Option<BigInt> {
    inv(rhs, field).map(|inverse| mul(lhs, &inverse, field))
}

pub(crate) fn equal(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> bool {
    if small_field_modulus_u64(field).is_some() {
        return normalize_small_field_u64(lhs, field) == normalize_small_field_u64(rhs, field);
    }

    normalize(lhs.clone(), field) == normalize(rhs.clone(), field)
}

pub(crate) fn is_boolean(value: &BigInt, field: FieldId) -> bool {
    if let Some(normalized) = normalize_small_field_u64(value, field) {
        return normalized == 0 || normalized == 1;
    }

    let normalized = normalize(value.clone(), field);
    normalized.is_zero() || normalized == BigInt::one()
}

pub(crate) fn fits_in_bits(value: &BigInt, bits: u32, field: FieldId) -> bool {
    if let Some(normalized) = normalize_small_field_u64(value, field) {
        return if bits >= u64::BITS {
            true
        } else {
            normalized < (1u64 << bits)
        };
    }

    let normalized = normalize(value.clone(), field);
    normalized < (BigInt::one() << bits)
}

pub fn normalize_mod(value: BigInt, modulus: &BigInt) -> BigInt {
    let mut reduced = value % modulus;
    if reduced.sign() == Sign::Minus {
        reduced += modulus;
    }
    if reduced.is_zero() {
        BigInt::zero()
    } else {
        reduced
    }
}

pub fn mod_inverse_bigint(value: BigInt, modulus: &BigInt) -> Option<BigInt> {
    if value.is_zero() {
        return None;
    }

    let mut t = BigInt::zero();
    let mut new_t = BigInt::from(1u8);
    let mut r = modulus.clone();
    let mut new_r = normalize_mod(value, modulus);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let next_t = &t - (&quotient * &new_t);
        t = new_t;
        new_t = next_t;

        let next_r = &r - (&quotient * &new_r);
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::from(1u8) {
        return None;
    }

    if t.sign() == Sign::Minus {
        t += modulus;
    }

    Some(normalize_mod(t, modulus))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn large_prime_field(index: u8) -> FieldId {
        match index % 4 {
            0 => FieldId::Bn254,
            1 => FieldId::Bls12_381,
            2 => FieldId::PastaFp,
            _ => FieldId::PastaFq,
        }
    }

    fn small_direct_field(index: u8) -> FieldId {
        match index % 3 {
            0 => FieldId::Goldilocks,
            1 => FieldId::BabyBear,
            _ => FieldId::Mersenne31,
        }
    }

    fn signed_bigint(bytes: [u8; 32], negative: bool) -> BigInt {
        let sign = if negative { Sign::Minus } else { Sign::Plus };
        BigInt::from_bytes_le(sign, &bytes)
    }

    fn canonical_bigint_from_words(words: [u64; 4]) -> BigInt {
        let mut bytes = [0u8; 32];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        BigInt::from_bytes_le(Sign::Plus, &bytes)
    }

    fn large_prime_adversarial_corpus(field: FieldId) -> Vec<BigInt> {
        let modulus = field.modulus().clone();
        let montgomery_radix = BigInt::one() << 256usize;
        let montgomery_r = normalize_mod(montgomery_radix.clone(), &modulus);
        let montgomery_r_squared =
            normalize_mod(montgomery_radix.clone() * montgomery_radix, &modulus);
        let carry_chain = canonical_bigint_from_words([u64::MAX, u64::MAX, 1, 0]);
        let alternating_a = canonical_bigint_from_words([
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
        ]);
        let alternating_b = canonical_bigint_from_words([
            0x5555555555555555,
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
            0xAAAAAAAAAAAAAAAA,
        ]);

        let seeds = [
            BigInt::zero(),
            BigInt::one(),
            -BigInt::one(),
            &modulus - BigInt::one(),
            modulus.clone(),
            &modulus + BigInt::one(),
            &modulus - BigInt::from(2u8),
            &modulus + BigInt::from(2u8),
            BigInt::one() - &modulus,
            -modulus.clone(),
            -(&modulus + BigInt::one()),
            montgomery_r.clone(),
            -montgomery_r.clone(),
            montgomery_r_squared.clone(),
            -montgomery_r_squared.clone(),
            &modulus + &montgomery_r,
            &modulus + &montgomery_r_squared,
            canonical_bigint_from_words([u64::MAX; 4]),
            canonical_bigint_from_words([u64::MAX, u64::MAX, u64::MAX, 0]),
            canonical_bigint_from_words([u64::MAX, 0, 0, 0]),
            canonical_bigint_from_words([0, u64::MAX, 0, 0]),
            canonical_bigint_from_words([0, 0, u64::MAX, 0]),
            canonical_bigint_from_words([0, 0, 0, u64::MAX]),
            carry_chain.clone(),
            -carry_chain,
            alternating_a.clone(),
            -alternating_a,
            alternating_b.clone(),
            -alternating_b,
        ];

        let mut corpus = BTreeSet::new();
        for seed in seeds {
            corpus.insert(seed.clone());
            corpus.insert(-seed.clone());
            corpus.insert(&modulus + &seed);
            corpus.insert(&modulus - &seed);
        }
        corpus.into_iter().collect()
    }

    fn oracle_normalize(value: &BigInt, field: FieldId) -> BigInt {
        normalize_mod(value.clone(), field.modulus())
    }

    fn oracle_add(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        normalize_mod(
            oracle_normalize(lhs, field) + oracle_normalize(rhs, field),
            field.modulus(),
        )
    }

    fn oracle_sub(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        normalize_mod(
            oracle_normalize(lhs, field) - oracle_normalize(rhs, field),
            field.modulus(),
        )
    }

    fn oracle_mul(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        normalize_mod(
            oracle_normalize(lhs, field) * oracle_normalize(rhs, field),
            field.modulus(),
        )
    }

    fn oracle_inv(value: &BigInt, field: FieldId) -> Option<BigInt> {
        mod_inverse_bigint(oracle_normalize(value, field), field.modulus())
    }

    fn oracle_div(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> Option<BigInt> {
        let lhs = oracle_normalize(lhs, field);
        oracle_inv(rhs, field).map(|inverse| normalize_mod(lhs * inverse, field.modulus()))
    }

    fn simulate_missing_final_subtraction(result: BigInt, field: FieldId) -> BigInt {
        let modulus = field.modulus();
        let threshold = modulus - BigInt::from(2u8);
        if result >= threshold {
            result + modulus
        } else {
            result
        }
    }

    fn broken_normalize_missing_final_subtraction(value: &BigInt, field: FieldId) -> BigInt {
        simulate_missing_final_subtraction(oracle_normalize(value, field), field)
    }

    fn broken_add_missing_final_subtraction(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        simulate_missing_final_subtraction(oracle_add(lhs, rhs, field), field)
    }

    fn broken_sub_missing_final_subtraction(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        simulate_missing_final_subtraction(oracle_sub(lhs, rhs, field), field)
    }

    fn broken_mul_missing_final_subtraction(lhs: &BigInt, rhs: &BigInt, field: FieldId) -> BigInt {
        simulate_missing_final_subtraction(oracle_mul(lhs, rhs, field), field)
    }

    fn broken_inv_missing_final_subtraction(value: &BigInt, field: FieldId) -> Option<BigInt> {
        oracle_inv(value, field).map(|result| simulate_missing_final_subtraction(result, field))
    }

    fn broken_div_missing_final_subtraction(
        lhs: &BigInt,
        rhs: &BigInt,
        field: FieldId,
    ) -> Option<BigInt> {
        oracle_div(lhs, rhs, field).map(|result| simulate_missing_final_subtraction(result, field))
    }

    #[test]
    fn roundtrip_zero() {
        let fe = FieldElement::from_i64(0);
        assert!(fe.is_zero());
        assert_eq!(fe.to_decimal_string(), "0");
        assert_eq!(fe.as_bigint(), BigInt::zero());
    }

    #[test]
    fn roundtrip_one() {
        let fe = FieldElement::from_i64(1);
        assert!(fe.is_one());
        assert!(!fe.is_zero());
        assert_eq!(fe.to_decimal_string(), "1");
    }

    #[test]
    fn roundtrip_negative() {
        let fe = FieldElement::from_i64(-1);
        assert_eq!(fe.to_decimal_string(), "-1");
        let norm = fe.normalized_bigint(FieldId::Bn254).unwrap();
        let expected = FieldId::Bn254.modulus() - BigInt::from(1u8);
        assert_eq!(norm, expected);
    }

    #[test]
    fn roundtrip_large_bigint() {
        let big = BigInt::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        let fe = FieldElement::from_bigint(big.clone());
        assert_eq!(fe.as_bigint(), big);
    }

    #[test]
    fn from_u64_roundtrip() {
        let fe = FieldElement::from_u64(42);
        assert_eq!(fe.as_bigint(), BigInt::from(42u64));
        assert_eq!(fe.to_decimal_string(), "42");
    }

    #[test]
    fn le_bytes_roundtrip() {
        let fe = FieldElement::from_u64(0x0102030405060708);
        let bytes = fe.to_le_bytes();
        let fe2 = FieldElement::from_le_bytes(bytes);
        assert_eq!(fe, fe2);
    }

    #[test]
    fn serde_json_compat() {
        let fe = FieldElement::from_u64(12345);
        let json = serde_json::to_string(&fe).unwrap();
        assert_eq!(json, "\"12345\"");
        let parsed: FieldElement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fe);
    }

    #[test]
    fn serde_json_negative() {
        let fe = FieldElement::from_i64(-42);
        let json = serde_json::to_string(&fe).unwrap();
        assert_eq!(json, "\"-42\"");
        let parsed: FieldElement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fe);
    }

    #[test]
    fn from_bigint_with_field_normalizes() {
        let fe = FieldElement::from_bigint_with_field(BigInt::from(-1), FieldId::BabyBear);
        let expected = FieldId::BabyBear.modulus() - BigInt::from(1u8);
        assert_eq!(fe.as_bigint(), expected);
        assert!(!fe.negative);
    }

    #[test]
    fn equality_zero_variants() {
        let a = FieldElement::ZERO;
        let b = FieldElement::from_i64(0);
        let c = FieldElement::from_u64(0);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FieldElement::from_u64(42));
        assert!(set.contains(&FieldElement::from_i64(42)));
    }

    #[test]
    fn new_backward_compat() {
        let fe = FieldElement::new("12345");
        assert_eq!(fe, FieldElement::from_u64(12345));
        let fe_neg = FieldElement::new("-7");
        assert_eq!(fe_neg, FieldElement::from_i64(-7));
    }

    #[test]
    fn montgomery_assurance_large_prime_operations_match_oracle() {
        for field in [
            FieldId::Bn254,
            FieldId::Bls12_381,
            FieldId::PastaFp,
            FieldId::PastaFq,
        ] {
            let corpus = large_prime_adversarial_corpus(field);
            for value in &corpus {
                assert_eq!(
                    normalize(value.clone(), field),
                    oracle_normalize(value, field),
                    "normalize mismatch for {} and value {}",
                    field,
                    value,
                );
                assert_eq!(
                    inv(value, field),
                    oracle_inv(value, field),
                    "inv mismatch for {} and value {}",
                    field,
                    value,
                );
            }

            for lhs in &corpus {
                for rhs in &corpus {
                    assert_eq!(
                        add(lhs, rhs, field),
                        oracle_add(lhs, rhs, field),
                        "add mismatch for {} and lhs={}, rhs={}",
                        field,
                        lhs,
                        rhs,
                    );
                    assert_eq!(
                        sub(lhs, rhs, field),
                        oracle_sub(lhs, rhs, field),
                        "sub mismatch for {} and lhs={}, rhs={}",
                        field,
                        lhs,
                        rhs,
                    );
                    assert_eq!(
                        mul(lhs, rhs, field),
                        oracle_mul(lhs, rhs, field),
                        "mul mismatch for {} and lhs={}, rhs={}",
                        field,
                        lhs,
                        rhs,
                    );
                    assert_eq!(
                        div(lhs, rhs, field),
                        oracle_div(lhs, rhs, field),
                        "div mismatch for {} and lhs={}, rhs={}",
                        field,
                        lhs,
                        rhs,
                    );
                }
            }
        }
    }

    #[test]
    fn montgomery_assurance_corpus_detects_missing_final_subtraction_bug() {
        for field in [
            FieldId::Bn254,
            FieldId::Bls12_381,
            FieldId::PastaFp,
            FieldId::PastaFq,
        ] {
            let corpus = large_prime_adversarial_corpus(field);
            let mut normalize_detected = false;
            let mut add_detected = false;
            let mut sub_detected = false;
            let mut mul_detected = false;
            let mut inv_detected = false;
            let mut div_detected = false;

            for value in &corpus {
                normalize_detected |= broken_normalize_missing_final_subtraction(value, field)
                    != oracle_normalize(value, field);
                inv_detected |=
                    broken_inv_missing_final_subtraction(value, field) != oracle_inv(value, field);
            }

            for lhs in &corpus {
                for rhs in &corpus {
                    add_detected |= broken_add_missing_final_subtraction(lhs, rhs, field)
                        != oracle_add(lhs, rhs, field);
                    sub_detected |= broken_sub_missing_final_subtraction(lhs, rhs, field)
                        != oracle_sub(lhs, rhs, field);
                    mul_detected |= broken_mul_missing_final_subtraction(lhs, rhs, field)
                        != oracle_mul(lhs, rhs, field);
                    div_detected |= broken_div_missing_final_subtraction(lhs, rhs, field)
                        != oracle_div(lhs, rhs, field);
                }
            }

            assert!(
                normalize_detected,
                "corpus failed to detect normalize missing-final-subtraction bug for {}",
                field,
            );
            assert!(
                add_detected,
                "corpus failed to detect add missing-final-subtraction bug for {}",
                field,
            );
            assert!(
                sub_detected,
                "corpus failed to detect sub missing-final-subtraction bug for {}",
                field,
            );
            assert!(
                mul_detected,
                "corpus failed to detect mul missing-final-subtraction bug for {}",
                field,
            );
            assert!(
                inv_detected,
                "corpus failed to detect inv missing-final-subtraction bug for {}",
                field,
            );
            assert!(
                div_detected,
                "corpus failed to detect div missing-final-subtraction bug for {}",
                field,
            );
        }
    }

    proptest! {
        #[test]
        fn specialized_small_field_arithmetic_matches_reference_backend(
            field_index in 0u8..3,
            lhs_bytes in prop::array::uniform32(any::<u8>()),
            lhs_negative in any::<bool>(),
            rhs_bytes in prop::array::uniform32(any::<u8>()),
            rhs_negative in any::<bool>(),
        ) {
            let field = small_direct_field(field_index);
            let lhs = signed_bigint(lhs_bytes, lhs_negative);
            let rhs = signed_bigint(rhs_bytes, rhs_negative);

            let lhs_norm = normalize_mod(lhs.clone(), field.modulus());
            let rhs_norm = normalize_mod(rhs.clone(), field.modulus());

            prop_assert_eq!(normalize(lhs.clone(), field), lhs_norm.clone());
            prop_assert_eq!(normalize(rhs.clone(), field), rhs_norm.clone());
            prop_assert_eq!(
                add(&lhs, &rhs, field),
                normalize_mod(lhs_norm.clone() + rhs_norm.clone(), field.modulus())
            );
            prop_assert_eq!(
                sub(&lhs, &rhs, field),
                normalize_mod(lhs_norm.clone() - rhs_norm.clone(), field.modulus())
            );
            prop_assert_eq!(
                mul(&lhs, &rhs, field),
                normalize_mod(lhs_norm.clone() * rhs_norm.clone(), field.modulus())
            );
            prop_assert_eq!(inv(&lhs, field), mod_inverse_bigint(lhs_norm.clone(), field.modulus()));

            let expected_div = mod_inverse_bigint(rhs_norm.clone(), field.modulus())
                .map(|inverse| normalize_mod(lhs_norm.clone() * inverse, field.modulus()));
            prop_assert_eq!(div(&lhs, &rhs, field), expected_div);

            let encoded = FieldElement::from_bigint_with_field(lhs.clone(), field);
            prop_assert_eq!(encoded.normalized_bigint(field).expect("encoded value should normalize"), lhs_norm);
        }

        #[test]
        fn specialized_large_prime_arithmetic_matches_reference_backend(
            field_index in 0u8..4,
            lhs_bytes in prop::array::uniform32(any::<u8>()),
            lhs_negative in any::<bool>(),
            rhs_bytes in prop::array::uniform32(any::<u8>()),
            rhs_negative in any::<bool>(),
        ) {
            let field = large_prime_field(field_index);
            let lhs = signed_bigint(lhs_bytes, lhs_negative);
            let rhs = signed_bigint(rhs_bytes, rhs_negative);

            let lhs_norm = normalize_mod(lhs.clone(), field.modulus());
            let rhs_norm = normalize_mod(rhs.clone(), field.modulus());

            prop_assert_eq!(normalize(lhs.clone(), field), lhs_norm.clone());
            prop_assert_eq!(normalize(rhs.clone(), field), rhs_norm.clone());
            prop_assert_eq!(
                add(&lhs, &rhs, field),
                normalize_mod(lhs_norm.clone() + rhs_norm.clone(), field.modulus())
            );
            prop_assert_eq!(
                sub(&lhs, &rhs, field),
                normalize_mod(lhs_norm.clone() - rhs_norm.clone(), field.modulus())
            );
            prop_assert_eq!(
                mul(&lhs, &rhs, field),
                normalize_mod(lhs_norm.clone() * rhs_norm.clone(), field.modulus())
            );
            prop_assert_eq!(inv(&lhs, field), mod_inverse_bigint(lhs_norm.clone(), field.modulus()));

            let expected_div = mod_inverse_bigint(rhs_norm.clone(), field.modulus())
                .map(|inverse| normalize_mod(lhs_norm.clone() * inverse, field.modulus()));
            prop_assert_eq!(div(&lhs, &rhs, field), expected_div);

            let encoded = FieldElement::from_bigint_with_field(lhs.clone(), field);
            prop_assert_eq!(encoded.normalized_bigint(field).expect("encoded value should normalize"), lhs_norm);
        }
    }
}
