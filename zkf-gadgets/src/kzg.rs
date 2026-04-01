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

use crate::gadget::{
    Gadget, GadgetEmission, builtin_supported_fields, validate_builtin_field_support,
};
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{FieldId, ZkfError, ZkfResult};

/// KZG polynomial commitment verification gadget.
///
/// Verifies a KZG polynomial commitment opening proof in-circuit.
/// The pairing check is: e(C - [v]G1, G2) == e(pi, [s]G2 - [z]G2)
///
/// Inputs (in order):
/// 0. `commitment` — The polynomial commitment C (G1 point)
/// 1. `evaluation` — The claimed evaluation value v
/// 2. `point` — The evaluation point z
/// 3. `proof` — The opening proof pi (G1 point)
///
/// Outputs:
/// 0. `valid` — Boolean (1 if valid, 0 if not)
///
/// This gadget uses non-native field arithmetic for curve operations
/// and decomposes the pairing check into verifiable sub-constraints.
pub struct KzgGadget;

impl Gadget for KzgGadget {
    fn name(&self) -> &str {
        "kzg"
    }

    fn supported_fields(&self) -> Vec<FieldId> {
        builtin_supported_fields(self.name()).unwrap_or_default()
    }

    fn emit(
        &self,
        inputs: &[zir::Expr],
        outputs: &[String],
        field: FieldId,
        params: &BTreeMap<String, String>,
    ) -> ZkfResult<GadgetEmission> {
        validate_builtin_field_support(self.name(), field)?;
        if inputs.len() < 4 {
            return Err(ZkfError::InvalidArtifact(
                "kzg gadget requires 4 inputs: commitment, evaluation, point, proof".into(),
            ));
        }
        if outputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "kzg gadget requires at least 1 output (valid flag)".into(),
            ));
        }

        let curve = params
            .get("curve")
            .map(String::as_str)
            .unwrap_or(match field {
                FieldId::Bn254 => "bn254",
                FieldId::Bls12_381 => "bls12-381",
                _ => "bn254",
            });

        let mut emission = GadgetEmission::default();
        let mut aux_idx = 0usize;
        let mut next_aux = |prefix: &str| -> String {
            let name = format!("__kzg_{prefix}_{aux_idx}");
            aux_idx += 1;
            name
        };

        // Input decomposition signals
        let commitment = &inputs[0];
        let evaluation = &inputs[1];
        let point = &inputs[2];
        let proof = &inputs[3];

        // Step 1: Compute C - [v]G1
        // This requires scalar multiplication and point subtraction in-circuit.
        // We emit these as structured BlackBox constraints that backends can
        // handle natively or decompose further.
        let v_times_g1 = next_aux("v_g1");
        emission.signals.push(zir::Signal {
            name: v_times_g1.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Field,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::ScalarMulG1,
            inputs: vec![evaluation.clone()],
            outputs: vec![v_times_g1.clone()],
            params: {
                let mut p = BTreeMap::new();
                p.insert("curve".to_string(), curve.to_string());
                p
            },
            label: Some("kzg_scalar_mul_v_g1".to_string()),
        });

        // C - [v]G1
        let lhs_g1 = next_aux("lhs_g1");
        emission.signals.push(zir::Signal {
            name: lhs_g1.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Field,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::PointAddG1,
            inputs: vec![commitment.clone(), zir::Expr::Signal(v_times_g1)],
            outputs: vec![lhs_g1.clone()],
            params: {
                let mut p = BTreeMap::new();
                p.insert("ec_op".to_string(), "point_sub".to_string());
                p.insert("curve".to_string(), curve.to_string());
                p
            },
            label: Some("kzg_c_minus_vg1".to_string()),
        });

        // Step 2: Compute [s]G2 - [z]G2 = [s-z]G2
        let s_minus_z_g2 = next_aux("s_z_g2");
        emission.signals.push(zir::Signal {
            name: s_minus_z_g2.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Field,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::ScalarMulG1,
            inputs: vec![point.clone()],
            outputs: vec![s_minus_z_g2.clone()],
            params: {
                let mut p = BTreeMap::new();
                p.insert("target".to_string(), "g2".to_string());
                p.insert("ec_op".to_string(), "srs_minus_z_g2".to_string());
                p.insert("curve".to_string(), curve.to_string());
                p
            },
            label: Some("kzg_s_minus_z_g2".to_string()),
        });

        // Step 3: Pairing check e(lhs_g1, G2) == e(proof, [s-z]G2)
        let pairing_result = next_aux("pairing");
        emission.signals.push(zir::Signal {
            name: pairing_result.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Bool,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::PairingCheck,
            inputs: vec![
                zir::Expr::Signal(lhs_g1),
                proof.clone(),
                zir::Expr::Signal(s_minus_z_g2),
            ],
            outputs: vec![pairing_result.clone()],
            params: {
                let mut p = BTreeMap::new();
                p.insert("curve".to_string(), curve.to_string());
                p
            },
            label: Some("kzg_pairing_check".to_string()),
        });

        // Step 4: Output = pairing result
        for output in outputs {
            emission.signals.push(zir::Signal {
                name: output.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Bool,
                constant: None,
            });
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(output.clone()),
                rhs: zir::Expr::Signal(pairing_result.clone()),
                label: Some(format!("kzg_output_{output}")),
            });
        }

        Ok(emission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kzg_emits_pairing_constraints() {
        let gadget = KzgGadget;
        let inputs = vec![
            zir::Expr::Signal("commitment".into()),
            zir::Expr::Signal("evaluation".into()),
            zir::Expr::Signal("point".into()),
            zir::Expr::Signal("proof".into()),
        ];

        let emission = gadget
            .emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new())
            .unwrap();

        assert!(!emission.signals.is_empty());
        assert!(!emission.constraints.is_empty());
        // Should have scalar mul, point sub, srs computation, pairing check, output
        assert!(emission.constraints.len() >= 5);
    }

    #[test]
    fn kzg_rejects_insufficient_inputs() {
        let gadget = KzgGadget;
        let inputs = vec![
            zir::Expr::Signal("commitment".into()),
            zir::Expr::Signal("evaluation".into()),
        ];
        let result = gadget.emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn kzg_supported_fields() {
        let gadget = KzgGadget;
        let fields = gadget.supported_fields();
        assert!(fields.contains(&FieldId::Bn254));
        assert!(fields.contains(&FieldId::Bls12_381));
        assert!(!fields.contains(&FieldId::Goldilocks));
    }

    #[test]
    fn kzg_emits_correct_op_variants() {
        let gadget = KzgGadget;
        let inputs = vec![
            zir::Expr::Signal("commitment".into()),
            zir::Expr::Signal("evaluation".into()),
            zir::Expr::Signal("point".into()),
            zir::Expr::Signal("proof".into()),
        ];

        let emission = gadget
            .emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new())
            .unwrap();

        let ops: Vec<_> = emission
            .constraints
            .iter()
            .filter_map(|c| match c {
                zir::Constraint::BlackBox { op, .. } => Some(op.as_str()),
                _ => None,
            })
            .collect();

        assert!(ops.contains(&"scalar_mul_g1"), "should use ScalarMulG1");
        assert!(ops.contains(&"point_add_g1"), "should use PointAddG1");
        assert!(ops.contains(&"pairing_check"), "should use PairingCheck");
        assert!(
            !ops.contains(&"ecdsa_secp256k1"),
            "should NOT use EcdsaSecp256k1 for EC ops"
        );
    }

    #[test]
    fn kzg_with_bls_curve_param() {
        let gadget = KzgGadget;
        let inputs = vec![
            zir::Expr::Signal("c".into()),
            zir::Expr::Signal("v".into()),
            zir::Expr::Signal("z".into()),
            zir::Expr::Signal("pi".into()),
        ];
        let mut params = BTreeMap::new();
        params.insert("curve".to_string(), "bls12-381".to_string());

        let emission = gadget
            .emit(&inputs, &["ok".into()], FieldId::Bls12_381, &params)
            .unwrap();
        assert!(!emission.constraints.is_empty());
    }
}
