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

/// Poseidon hash gadget.
///
/// Params:
/// - `width`: permutation width (2 or 4, default 2 = 3-wide including capacity)
/// - `alpha`: S-box exponent (default 5 for BN254, 7 for Goldilocks)
///
/// For backend optimization, this emits BlackBox constraints that backends
/// can specialize (e.g., Halo2 → custom gate with lookup S-box).
pub struct PoseidonGadget;

impl Gadget for PoseidonGadget {
    fn name(&self) -> &str {
        "poseidon"
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
        if inputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "poseidon requires at least 1 input".into(),
            ));
        }
        if outputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "poseidon requires at least 1 output".into(),
            ));
        }

        let alpha = params
            .get("alpha")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or_else(|| default_alpha(field));

        let mut emission = GadgetEmission::default();

        // Output signals.
        for output in outputs {
            emission.signals.push(zir::Signal {
                name: output.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });
        }

        // Emit as BlackBox Poseidon — backends that support native Poseidon
        // will handle this directly; others will decompose into round constraints.
        let mut bb_params = BTreeMap::new();
        bb_params.insert("alpha".to_string(), alpha.to_string());
        if let Some(width) = params.get("width") {
            bb_params.insert("width".to_string(), width.clone());
        }

        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::Poseidon,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            params: bb_params,
            label: Some("poseidon_hash".to_string()),
        });

        Ok(emission)
    }
}

fn default_alpha(field: FieldId) -> u32 {
    match field {
        FieldId::Goldilocks | FieldId::BabyBear => 7,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_emits_blackbox() {
        let gadget = PoseidonGadget;
        let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];

        let emission = gadget
            .emit(&inputs, &["hash".into()], FieldId::Bn254, &BTreeMap::new())
            .unwrap();
        assert_eq!(emission.signals.len(), 1);
        assert_eq!(emission.constraints.len(), 1);
        assert!(matches!(
            &emission.constraints[0],
            zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Poseidon,
                ..
            }
        ));
    }

    #[test]
    fn poseidon_uses_alpha_7_for_goldilocks() {
        let gadget = PoseidonGadget;
        let inputs = vec![zir::Expr::Signal("x".into())];

        let emission = gadget
            .emit(
                &inputs,
                &["h".into()],
                FieldId::Goldilocks,
                &BTreeMap::new(),
            )
            .unwrap();
        if let zir::Constraint::BlackBox { params, .. } = &emission.constraints[0] {
            assert_eq!(params.get("alpha").unwrap(), "7");
        }
    }
}
