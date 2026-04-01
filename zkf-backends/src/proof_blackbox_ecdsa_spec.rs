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

#[cfg(not(hax))]
use crate::blackbox_gadgets::ecdsa;
#[cfg(not(hax))]
use crate::blackbox_gadgets::{AuxCounter, LoweredBlackBox};
#[cfg(not(hax))]
use num_bigint::BigInt;
#[cfg(not(hax))]
use std::collections::BTreeMap;
#[cfg(not(hax))]
use zkf_core::BlackBoxOp;
#[cfg(not(hax))]
use zkf_core::{FieldElement, FieldId, ZkfResult};

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SupportedCriticalEcdsaCurve {
    Secp256k1,
    Secp256r1,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CriticalEcdsaAuxWitnessMode {
    ArithmeticAuxWitness,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CriticalEcdsaRuntimeRelation {
    pub valid_signature_forces_one: bool,
    pub invalid_signature_forces_zero: bool,
    pub malformed_abi_fails_closed: bool,
    pub low_s_is_required: bool,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SpecCriticalEcdsaOp {
    Secp256k1,
    Secp256r1,
    Other,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SpecCriticalEcdsaFieldId {
    Bn254,
    Other,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CriticalEcdsaByteAbiSemantics {
    pub supported_curve: SupportedCriticalEcdsaCurve,
    pub supported_field: SpecCriticalEcdsaFieldId,
    pub supported_inputs_len: usize,
    pub supported_outputs_len: usize,
    pub result_is_boolean: bool,
    pub aux_witness_mode: CriticalEcdsaAuxWitnessMode,
    pub runtime_relation: CriticalEcdsaRuntimeRelation,
}

#[cfg(not(hax))]
fn spec_ecdsa_op(op: BlackBoxOp) -> SpecCriticalEcdsaOp {
    match op {
        BlackBoxOp::EcdsaSecp256k1 => SpecCriticalEcdsaOp::Secp256k1,
        BlackBoxOp::EcdsaSecp256r1 => SpecCriticalEcdsaOp::Secp256r1,
        _ => SpecCriticalEcdsaOp::Other,
    }
}

#[cfg(not(hax))]
fn spec_ecdsa_field(field: FieldId) -> SpecCriticalEcdsaFieldId {
    match field {
        FieldId::Bn254 => SpecCriticalEcdsaFieldId::Bn254,
        _ => SpecCriticalEcdsaFieldId::Other,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_ecdsa_proof_surface(
    op: SpecCriticalEcdsaOp,
    field: SpecCriticalEcdsaFieldId,
    inputs_len: usize,
    outputs_len: usize,
) -> Option<SupportedCriticalEcdsaCurve> {
    match field {
        SpecCriticalEcdsaFieldId::Bn254 => match op {
            SpecCriticalEcdsaOp::Secp256k1 if inputs_len == 160 && outputs_len == 1 => {
                Some(SupportedCriticalEcdsaCurve::Secp256k1)
            }
            SpecCriticalEcdsaOp::Secp256r1 if inputs_len == 160 && outputs_len == 1 => {
                Some(SupportedCriticalEcdsaCurve::Secp256r1)
            }
            _ => None,
        },
        SpecCriticalEcdsaFieldId::Other => None,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_ecdsa_aux_witness_mode(
    curve: SupportedCriticalEcdsaCurve,
) -> CriticalEcdsaAuxWitnessMode {
    let _ = curve;
    CriticalEcdsaAuxWitnessMode::ArithmeticAuxWitness
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_ecdsa_runtime_relation(
    curve: SupportedCriticalEcdsaCurve,
) -> CriticalEcdsaRuntimeRelation {
    let _ = curve;
    CriticalEcdsaRuntimeRelation {
        valid_signature_forces_one: true,
        invalid_signature_forces_zero: true,
        malformed_abi_fails_closed: true,
        low_s_is_required: true,
    }
}

#[cfg_attr(hax, hax_lib::include)]
pub fn critical_ecdsa_byte_abi_semantics(
    op: SpecCriticalEcdsaOp,
    field: SpecCriticalEcdsaFieldId,
    inputs_len: usize,
    outputs_len: usize,
) -> Option<CriticalEcdsaByteAbiSemantics> {
    critical_ecdsa_proof_surface(op, field, inputs_len, outputs_len).map(|curve| {
        CriticalEcdsaByteAbiSemantics {
            supported_curve: curve,
            supported_field: field,
            supported_inputs_len: inputs_len,
            supported_outputs_len: outputs_len,
            result_is_boolean: true,
            aux_witness_mode: critical_ecdsa_aux_witness_mode(curve),
            runtime_relation: critical_ecdsa_runtime_relation(curve),
        }
    })
}

#[cfg_attr(hax, hax_lib::include)]
pub fn ecdsa_curve_name(curve: SupportedCriticalEcdsaCurve) -> &'static str {
    match curve {
        SupportedCriticalEcdsaCurve::Secp256k1 => "secp256k1",
        SupportedCriticalEcdsaCurve::Secp256r1 => "secp256r1",
    }
}

#[cfg(not(hax))]
pub fn lower_ecdsa_blackbox(
    curve: SupportedCriticalEcdsaCurve,
    inputs: &[zkf_core::Expr],
    outputs: &[String],
    params: &BTreeMap<String, String>,
    field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    let _ = critical_ecdsa_byte_abi_semantics(
        match curve {
            SupportedCriticalEcdsaCurve::Secp256k1 => SpecCriticalEcdsaOp::Secp256k1,
            SupportedCriticalEcdsaCurve::Secp256r1 => SpecCriticalEcdsaOp::Secp256r1,
        },
        spec_ecdsa_field(field),
        inputs.len(),
        outputs.len(),
    )
    .ok_or_else(|| {
        format!(
            "ecdsa proof kernel only handles supported BN254 byte ABI surfaces, found curve={}, field={}, inputs={}, outputs={}",
            ecdsa_curve_name(curve),
            field,
            inputs.len(),
            outputs.len()
        )
    })?;
    ecdsa::lower_ecdsa(inputs, outputs, params, field, aux, ecdsa_curve_name(curve))
}

#[cfg(not(hax))]
#[allow(clippy::too_many_arguments)]
pub fn compute_ecdsa_aux_witness(
    curve: SupportedCriticalEcdsaCurve,
    input_values: &[BigInt],
    output_values: &[BigInt],
    params: &BTreeMap<String, String>,
    field: FieldId,
    label: &Option<String>,
    index: usize,
    witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    let _ = critical_ecdsa_byte_abi_semantics(
        match curve {
            SupportedCriticalEcdsaCurve::Secp256k1 => SpecCriticalEcdsaOp::Secp256k1,
            SupportedCriticalEcdsaCurve::Secp256r1 => SpecCriticalEcdsaOp::Secp256r1,
        },
        spec_ecdsa_field(field),
        input_values.len(),
        1,
    )
    .filter(|surface| surface.supported_inputs_len == input_values.len())
    .expect("ecdsa proof kernel only dispatches supported BN254 byte ABI surfaces");
    ecdsa::compute_ecdsa_witness(
        curve,
        input_values,
        output_values,
        params,
        field,
        label,
        index,
        witness_values,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CriticalEcdsaAuxWitnessMode, SpecCriticalEcdsaFieldId, SpecCriticalEcdsaOp,
        SupportedCriticalEcdsaCurve, critical_ecdsa_aux_witness_mode,
        critical_ecdsa_byte_abi_semantics, critical_ecdsa_proof_surface,
        critical_ecdsa_runtime_relation, ecdsa_curve_name,
    };

    #[test]
    fn critical_ecdsa_surface_keeps_the_shipped_abi() {
        assert_eq!(
            critical_ecdsa_proof_surface(
                SpecCriticalEcdsaOp::Secp256k1,
                SpecCriticalEcdsaFieldId::Bn254,
                160,
                1
            ),
            Some(SupportedCriticalEcdsaCurve::Secp256k1)
        );
        assert_eq!(
            critical_ecdsa_proof_surface(
                SpecCriticalEcdsaOp::Secp256r1,
                SpecCriticalEcdsaFieldId::Bn254,
                160,
                1
            ),
            Some(SupportedCriticalEcdsaCurve::Secp256r1)
        );
        assert_eq!(
            critical_ecdsa_proof_surface(
                SpecCriticalEcdsaOp::Secp256k1,
                SpecCriticalEcdsaFieldId::Bn254,
                159,
                1
            ),
            None
        );
        assert_eq!(
            critical_ecdsa_proof_surface(
                SpecCriticalEcdsaOp::Secp256k1,
                SpecCriticalEcdsaFieldId::Other,
                160,
                1
            ),
            None
        );
        assert_eq!(
            ecdsa_curve_name(SupportedCriticalEcdsaCurve::Secp256k1),
            "secp256k1"
        );
        assert_eq!(
            critical_ecdsa_aux_witness_mode(SupportedCriticalEcdsaCurve::Secp256r1),
            CriticalEcdsaAuxWitnessMode::ArithmeticAuxWitness
        );
        assert_eq!(
            critical_ecdsa_byte_abi_semantics(
                SpecCriticalEcdsaOp::Secp256k1,
                SpecCriticalEcdsaFieldId::Bn254,
                160,
                1
            )
            .map(|surface| surface.result_is_boolean),
            Some(true)
        );
        assert_eq!(
            critical_ecdsa_runtime_relation(SupportedCriticalEcdsaCurve::Secp256k1)
                .invalid_signature_forces_zero,
            true
        );
    }
}
