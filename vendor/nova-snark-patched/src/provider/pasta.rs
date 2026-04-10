//! This module implements the Nova traits for `pallas::Point`, `pallas::Scalar`, `vesta::Point`, `vesta::Scalar`.
use crate::{
  impl_traits_no_dlog_ext,
  provider::{
    msm::{msm_pallas, msm_small, msm_small_with_max_num_bits, msm_vesta},
    traits::{DlogGroup, DlogGroupExt},
  },
  traits::{Group, PrimeFieldExt, TranscriptReprTrait},
};
use digest::{ExtendableOutput, Update};
use ff::FromUniformBytes;
use halo2curves::{
  CurveAffine, CurveExt,
  group::{Curve, Group as AnotherGroup, cofactor::CofactorCurveAffine},
  pasta::{Pallas, PallasAffine, Vesta, VestaAffine},
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Num, ToPrimitive};
use rayon::prelude::*;
use sha3::Shake256;

/// Re-exports that give access to the standard aliases used in the code base, for pallas
pub mod pallas {
  pub use halo2curves::pasta::{Fp as Base, Fq as Scalar, Pallas as Point, PallasAffine as Affine};
}

/// Re-exports that give access to the standard aliases used in the code base, for vesta
pub mod vesta {
  pub use halo2curves::pasta::{Fp as Scalar, Fq as Base, Vesta as Point, VestaAffine as Affine};
}

impl_traits_no_dlog_ext!(
  pallas,
  Pallas,
  PallasAffine,
  "40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001",
  "40000000000000000000000000000000224698fc094cf91b992d30ed00000001"
);

impl DlogGroupExt for pallas::Point {
  fn vartime_multiscalar_mul(scalars: &[Self::Scalar], bases: &[Self::AffineGroupElement]) -> Self {
    msm_pallas(scalars, bases)
  }

  fn vartime_multiscalar_mul_small<T: Integer + Into<u64> + Copy + Sync + ToPrimitive>(
    scalars: &[T],
    bases: &[Self::AffineGroupElement],
  ) -> Self {
    msm_small(scalars, bases)
  }

  fn vartime_multiscalar_mul_small_with_max_num_bits<
    T: Integer + Into<u64> + Copy + Sync + ToPrimitive,
  >(
    scalars: &[T],
    bases: &[Self::AffineGroupElement],
    max_num_bits: usize,
  ) -> Self {
    msm_small_with_max_num_bits(scalars, bases, max_num_bits)
  }
}

impl_traits_no_dlog_ext!(
  vesta,
  Vesta,
  VestaAffine,
  "40000000000000000000000000000000224698fc094cf91b992d30ed00000001",
  "40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001"
);

impl DlogGroupExt for vesta::Point {
  fn vartime_multiscalar_mul(scalars: &[Self::Scalar], bases: &[Self::AffineGroupElement]) -> Self {
    msm_vesta(scalars, bases)
  }

  fn vartime_multiscalar_mul_small<T: Integer + Into<u64> + Copy + Sync + ToPrimitive>(
    scalars: &[T],
    bases: &[Self::AffineGroupElement],
  ) -> Self {
    msm_small(scalars, bases)
  }

  fn vartime_multiscalar_mul_small_with_max_num_bits<
    T: Integer + Into<u64> + Copy + Sync + ToPrimitive,
  >(
    scalars: &[T],
    bases: &[Self::AffineGroupElement],
    max_num_bits: usize,
  ) -> Self {
    msm_small_with_max_num_bits(scalars, bases, max_num_bits)
  }
}
