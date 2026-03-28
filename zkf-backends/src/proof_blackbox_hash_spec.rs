#![allow(dead_code)]

#[cfg(not(hax))]
use crate::blackbox_gadgets::poseidon2;
#[cfg(not(hax))]
use crate::blackbox_gadgets::sha256;
#[cfg(not(hax))]
use crate::blackbox_gadgets::{AuxCounter, LoweredBlackBox};
#[cfg(not(hax))]
use num_bigint::BigInt;
#[cfg(not(hax))]
use std::collections::BTreeMap;
#[cfg(not(hax))]
use zkf_core::{BlackBoxOp, FieldId};
#[cfg(not(hax))]
use zkf_core::{Expr, FieldElement, ZkfResult};

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SupportedCriticalHashOp {
    PoseidonBn254Width4,
    PoseidonBls12381Width4,
    Sha256BytesToDigest,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CriticalHashAuxWitnessMode {
    ConstraintSolverDerived,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SpecCriticalHashBlackBoxOp {
    Poseidon,
    Sha256,
    Other,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SpecCriticalHashFieldId {
    Bn254,
    Bls12_381,
    Goldilocks,
    BabyBear,
    Mersenne31,
    Other,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CriticalHashLoweringSemantics {
    pub supported_op: SupportedCriticalHashOp,
    pub supported_inputs_len: usize,
    pub supported_outputs_len: usize,
    pub aux_witness_mode: CriticalHashAuxWitnessMode,
}

#[cfg(not(hax))]
fn spec_hash_op(op: BlackBoxOp) -> SpecCriticalHashBlackBoxOp {
    match op {
        BlackBoxOp::Poseidon => SpecCriticalHashBlackBoxOp::Poseidon,
        BlackBoxOp::Sha256 => SpecCriticalHashBlackBoxOp::Sha256,
        _ => SpecCriticalHashBlackBoxOp::Other,
    }
}

#[cfg(not(hax))]
fn spec_hash_field(field: FieldId) -> SpecCriticalHashFieldId {
    match field {
        FieldId::Bn254 => SpecCriticalHashFieldId::Bn254,
        FieldId::Bls12_381 => SpecCriticalHashFieldId::Bls12_381,
        FieldId::Goldilocks => SpecCriticalHashFieldId::Goldilocks,
        FieldId::BabyBear => SpecCriticalHashFieldId::BabyBear,
        FieldId::Mersenne31 => SpecCriticalHashFieldId::Mersenne31,
        _ => SpecCriticalHashFieldId::Other,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_hash_proof_surface(
    op: SpecCriticalHashBlackBoxOp,
    field: SpecCriticalHashFieldId,
    inputs_len: usize,
    outputs_len: usize,
) -> Option<SupportedCriticalHashOp> {
    match op {
        SpecCriticalHashBlackBoxOp::Poseidon => match field {
            SpecCriticalHashFieldId::Bn254 if inputs_len == 4 && outputs_len == 4 => {
                Some(SupportedCriticalHashOp::PoseidonBn254Width4)
            }
            SpecCriticalHashFieldId::Bls12_381 if inputs_len == 4 && outputs_len == 4 => {
                Some(SupportedCriticalHashOp::PoseidonBls12381Width4)
            }
            _ => None,
        },
        SpecCriticalHashBlackBoxOp::Sha256 if outputs_len == 32 => {
            Some(SupportedCriticalHashOp::Sha256BytesToDigest)
        }
        _ => None,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_hash_aux_witness_mode(
    supported_op: SupportedCriticalHashOp,
) -> CriticalHashAuxWitnessMode {
    let _ = supported_op;
    CriticalHashAuxWitnessMode::ConstraintSolverDerived
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_hash_lowering_semantics(
    op: SpecCriticalHashBlackBoxOp,
    field: SpecCriticalHashFieldId,
    inputs_len: usize,
    outputs_len: usize,
) -> Option<CriticalHashLoweringSemantics> {
    critical_hash_proof_surface(op, field, inputs_len, outputs_len).map(|supported_op| {
        CriticalHashLoweringSemantics {
            supported_op,
            supported_inputs_len: inputs_len,
            supported_outputs_len: outputs_len,
            aux_witness_mode: critical_hash_aux_witness_mode(supported_op),
        }
    })
}

#[cfg(not(hax))]
pub fn lower_hash_blackbox(
    op: BlackBoxOp,
    inputs: &[Expr],
    outputs: &[String],
    params: &BTreeMap<String, String>,
    field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    let surface = critical_hash_lowering_semantics(
        spec_hash_op(op),
        spec_hash_field(field),
        inputs.len(),
        outputs.len(),
    )
    .ok_or_else(|| {
        format!(
            "hash proof kernel only handles supported poseidon/sha256 surfaces, found op={}, field={}, inputs={}, outputs={}",
            op.as_str(),
            field,
            inputs.len(),
            outputs.len()
        )
    })?;
    let _ = surface;
    match op {
        BlackBoxOp::Poseidon => poseidon2::lower_poseidon2(inputs, outputs, params, field, aux),
        BlackBoxOp::Sha256 => sha256::lower_sha256(inputs, outputs, params, field, aux),
        _ => Err(format!(
            "hash proof kernel only handles poseidon/sha256, found {}",
            op.as_str()
        )),
    }
}

#[cfg(not(hax))]
pub fn compute_hash_aux_witness(
    op: BlackBoxOp,
    input_values: &[BigInt],
    output_values: &[BigInt],
    params: &BTreeMap<String, String>,
    field: FieldId,
    label: &Option<String>,
    witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    let inputs_len = input_values.len();
    let outputs_len = output_values.len();
    let op_spec = spec_hash_op(op);
    let field_spec = spec_hash_field(field);
    let Some(surface) = critical_hash_lowering_semantics(
        op_spec,
        field_spec,
        inputs_len,
        outputs_len,
    )
    .or_else(|| {
        if outputs_len != 0 {
            return None;
        }
        match (op_spec, field_spec, inputs_len) {
            (SpecCriticalHashBlackBoxOp::Poseidon, SpecCriticalHashFieldId::Bn254, 4) => {
                Some(CriticalHashLoweringSemantics {
                    supported_op: SupportedCriticalHashOp::PoseidonBn254Width4,
                    supported_inputs_len: 4,
                    supported_outputs_len: 4,
                    aux_witness_mode: CriticalHashAuxWitnessMode::ConstraintSolverDerived,
                })
            }
            (SpecCriticalHashBlackBoxOp::Poseidon, SpecCriticalHashFieldId::Bls12_381, 4) => {
                Some(CriticalHashLoweringSemantics {
                    supported_op: SupportedCriticalHashOp::PoseidonBls12381Width4,
                    supported_inputs_len: 4,
                    supported_outputs_len: 4,
                    aux_witness_mode: CriticalHashAuxWitnessMode::ConstraintSolverDerived,
                })
            }
            (SpecCriticalHashBlackBoxOp::Sha256, _, _) => Some(CriticalHashLoweringSemantics {
                supported_op: SupportedCriticalHashOp::Sha256BytesToDigest,
                supported_inputs_len: inputs_len,
                supported_outputs_len: 32,
                aux_witness_mode: CriticalHashAuxWitnessMode::ConstraintSolverDerived,
            }),
            _ => None,
        }
    }) else {
        unreachable!("hash proof kernel only dispatches supported poseidon/sha256 surfaces");
    };
    match op {
        BlackBoxOp::Poseidon => poseidon2::compute_poseidon2_witness(
            input_values,
            output_values,
            params,
            field,
            label,
            witness_values,
        ),
        BlackBoxOp::Sha256 => sha256::compute_sha256_witness(
            input_values,
            output_values,
            params,
            field,
            label,
            witness_values,
        ),
        _ => unreachable!("hash proof kernel only dispatches poseidon/sha256"),
    }
    .map(|()| match surface.aux_witness_mode {
        CriticalHashAuxWitnessMode::ConstraintSolverDerived => (),
    })
}

#[cfg(test)]
mod tests {
    use super::compute_hash_aux_witness;
    use super::{
        CriticalHashAuxWitnessMode, SpecCriticalHashBlackBoxOp, SpecCriticalHashFieldId,
        SupportedCriticalHashOp, critical_hash_aux_witness_mode, critical_hash_lowering_semantics,
        critical_hash_proof_surface,
    };
    use std::collections::BTreeMap;
    use zkf_core::{BlackBoxOp, FieldId};

    #[test]
    fn critical_hash_surface_is_bn254_poseidon_and_sha256_only() {
        assert_eq!(
            critical_hash_proof_surface(
                SpecCriticalHashBlackBoxOp::Poseidon,
                SpecCriticalHashFieldId::Bn254,
                4,
                4
            ),
            Some(SupportedCriticalHashOp::PoseidonBn254Width4)
        );
        assert_eq!(
            critical_hash_proof_surface(
                SpecCriticalHashBlackBoxOp::Poseidon,
                SpecCriticalHashFieldId::Bls12_381,
                4,
                4
            ),
            Some(SupportedCriticalHashOp::PoseidonBls12381Width4)
        );
        assert_eq!(
            critical_hash_proof_surface(
                SpecCriticalHashBlackBoxOp::Sha256,
                SpecCriticalHashFieldId::Goldilocks,
                80,
                32
            ),
            Some(SupportedCriticalHashOp::Sha256BytesToDigest)
        );
        assert_eq!(
            critical_hash_proof_surface(
                SpecCriticalHashBlackBoxOp::Poseidon,
                SpecCriticalHashFieldId::Goldilocks,
                4,
                4
            ),
            None
        );
        assert_eq!(
            critical_hash_aux_witness_mode(SupportedCriticalHashOp::Sha256BytesToDigest),
            CriticalHashAuxWitnessMode::ConstraintSolverDerived
        );
        assert_eq!(
            critical_hash_lowering_semantics(
                SpecCriticalHashBlackBoxOp::Sha256,
                SpecCriticalHashFieldId::Goldilocks,
                80,
                32
            )
            .map(|surface| surface.supported_outputs_len),
            Some(32)
        );
    }

    #[test]
    fn aux_witness_dispatch_accepts_missing_hash_outputs() {
        let mut witness_values = BTreeMap::new();
        compute_hash_aux_witness(
            BlackBoxOp::Poseidon,
            &[1u8.into(), 2u8.into(), 3u8.into(), 4u8.into()],
            &[],
            &BTreeMap::from([("width".to_string(), "4".to_string())]),
            FieldId::Bn254,
            &None,
            &mut witness_values,
        )
        .expect("poseidon aux witness should accept missing outputs");

        compute_hash_aux_witness(
            BlackBoxOp::Sha256,
            &[42u8.into()],
            &[],
            &BTreeMap::new(),
            FieldId::Bn254,
            &None,
            &mut witness_values,
        )
        .expect("sha256 aux witness should accept missing outputs");
    }
}
