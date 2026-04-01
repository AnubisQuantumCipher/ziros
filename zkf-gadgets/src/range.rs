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
use zkf_core::{FieldElement, FieldId, ZkfError, ZkfResult};

/// Range check gadget: constrains a signal to fit within `bits` bits.
///
/// Params:
/// - `bits`: number of bits (required)
///
/// Emits bit decomposition with boolean constraints and recombination.
pub struct RangeGadget;

impl Gadget for RangeGadget {
    fn name(&self) -> &str {
        "range"
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
        let bits: u32 = params
            .get("bits")
            .ok_or_else(|| ZkfError::InvalidArtifact("range gadget requires 'bits' param".into()))?
            .parse()
            .map_err(|_| ZkfError::InvalidArtifact("bits must be a number".into()))?;

        if inputs.len() != 1 {
            return Err(ZkfError::InvalidArtifact(
                "range gadget requires exactly 1 input".into(),
            ));
        }

        let prefix = outputs.first().map(|s| s.as_str()).unwrap_or("__range");
        let mut emission = GadgetEmission::default();

        // Create bit signals and boolean constraints.
        let mut bit_names = Vec::new();
        for bit in 0..bits {
            let bit_name = format!("{}_bit_{}", prefix, bit);
            emission.signals.push(zir::Signal {
                name: bit_name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Bool,
                constant: None,
            });
            emission.constraints.push(zir::Constraint::Boolean {
                signal: bit_name.clone(),
                label: Some(format!("{}_bit_{}_bool", prefix, bit)),
            });
            bit_names.push(bit_name);
        }

        // Recombination constraint: sum(bit_i * 2^i) == input.
        let mut recombination_terms = Vec::new();
        for (i, bit_name) in bit_names.iter().enumerate() {
            let coeff = FieldElement::from_u64(1u64 << i);
            recombination_terms.push(zir::Expr::Mul(
                Box::new(zir::Expr::Const(coeff)),
                Box::new(zir::Expr::Signal(bit_name.clone())),
            ));
        }
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Add(recombination_terms),
            rhs: inputs[0].clone(),
            label: Some(format!("{}_recombine", prefix)),
        });

        Ok(emission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_8_emits_8_bits_and_recombination() {
        let gadget = RangeGadget;
        let inputs = vec![zir::Expr::Signal("v".into())];
        let mut params = BTreeMap::new();
        params.insert("bits".into(), "8".into());

        let emission = gadget
            .emit(&inputs, &["v_range".into()], FieldId::Bn254, &params)
            .unwrap();
        assert_eq!(emission.signals.len(), 8);
        // 8 boolean + 1 recombination
        assert_eq!(emission.constraints.len(), 9);
    }
}
