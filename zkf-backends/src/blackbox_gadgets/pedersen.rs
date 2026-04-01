//! Pedersen commitment/hash as arithmetic constraints.
//!
//! Pedersen commitment: C = sum(input[i] * G[i]) where G[i] are generator points.
//! This requires EC scalar multiplication and point addition in-circuit.
//!
//! For BN254, each scalar multiplication over a 254-bit scalar uses ~254
//! point doublings + conditional additions, each requiring EC addition gadgets.
//! Total: ~4,000-5,000 constraints per scalar multiplication.

use super::{AuxCounter, LoweredBlackBox};
use num_bigint::BigInt;
use std::collections::BTreeMap;
use zkf_core::{Expr, FieldElement, FieldId, ZkfResult};

pub fn lower_pedersen(
    _inputs: &[Expr],
    _outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    // Pedersen hash on BN254 is defined over the Grumpkin companion curve.
    // The current implementation uses approximate BN254 G1 generator points
    // (not the actual Grumpkin generators from Noir's spec) which makes it
    // not sound against a proper Grumpkin-based verifier.
    // Use SHA256 or Poseidon2 for sound commitments within BN254 R1CS.
    Err(
        "Pedersen commitment lowering is not sound: BN254 Pedersen uses Grumpkin curve \
         arithmetic which requires embedded curve constraints not available in a standard \
         BN254 R1CS circuit. Use SHA256 or Poseidon2 for sound hash commitments."
            .to_string(),
    )
}

pub fn compute_pedersen_witness(
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    Ok(())
}
