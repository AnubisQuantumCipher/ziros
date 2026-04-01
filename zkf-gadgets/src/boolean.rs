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

/// Boolean logic gadget: AND, OR, XOR, NOT over boolean signals.
///
/// Operations (set via `params["op"]`):
/// - `and`: a * b
/// - `or`: a + b - a*b
/// - `xor`: a + b - 2*a*b
/// - `not`: 1 - a
pub struct BooleanGadget;

impl Gadget for BooleanGadget {
    fn name(&self) -> &str {
        "boolean"
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
        let op = params.get("op").ok_or_else(|| {
            ZkfError::InvalidArtifact("boolean gadget requires 'op' param".into())
        })?;

        let output = outputs.first().ok_or_else(|| {
            ZkfError::InvalidArtifact("boolean gadget requires one output".into())
        })?;

        let mut emission = GadgetEmission::default();

        // Output signal.
        emission.signals.push(zir::Signal {
            name: output.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Bool,
            constant: None,
        });

        match op.as_str() {
            "and" => {
                // out = a * b
                if inputs.len() != 2 {
                    return Err(ZkfError::InvalidArtifact("AND requires 2 inputs".into()));
                }
                let expr = zir::Expr::Mul(Box::new(inputs[0].clone()), Box::new(inputs[1].clone()));
                emission.assignments.push(zir::WitnessAssignment {
                    target: output.clone(),
                    expr: expr.clone(),
                });
                emission.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Signal(output.clone()),
                    rhs: expr,
                    label: Some(format!("{}_and", output)),
                });
            }
            "or" => {
                // out = a + b - a*b
                if inputs.len() != 2 {
                    return Err(ZkfError::InvalidArtifact("OR requires 2 inputs".into()));
                }
                let ab = zir::Expr::Mul(Box::new(inputs[0].clone()), Box::new(inputs[1].clone()));
                let expr = zir::Expr::Sub(
                    Box::new(zir::Expr::Add(vec![inputs[0].clone(), inputs[1].clone()])),
                    Box::new(ab),
                );
                emission.assignments.push(zir::WitnessAssignment {
                    target: output.clone(),
                    expr: expr.clone(),
                });
                emission.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Signal(output.clone()),
                    rhs: expr,
                    label: Some(format!("{}_or", output)),
                });
            }
            "xor" => {
                // out = a + b - 2*a*b
                if inputs.len() != 2 {
                    return Err(ZkfError::InvalidArtifact("XOR requires 2 inputs".into()));
                }
                let ab = zir::Expr::Mul(Box::new(inputs[0].clone()), Box::new(inputs[1].clone()));
                let two_ab = zir::Expr::Mul(
                    Box::new(zir::Expr::Const(FieldElement::from_i64(2))),
                    Box::new(ab),
                );
                let expr = zir::Expr::Sub(
                    Box::new(zir::Expr::Add(vec![inputs[0].clone(), inputs[1].clone()])),
                    Box::new(two_ab),
                );
                emission.assignments.push(zir::WitnessAssignment {
                    target: output.clone(),
                    expr: expr.clone(),
                });
                emission.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Signal(output.clone()),
                    rhs: expr,
                    label: Some(format!("{}_xor", output)),
                });
            }
            "not" => {
                // out = 1 - a
                if inputs.is_empty() {
                    return Err(ZkfError::InvalidArtifact("NOT requires 1 input".into()));
                }
                let expr = zir::Expr::Sub(
                    Box::new(zir::Expr::Const(FieldElement::from_i64(1))),
                    Box::new(inputs[0].clone()),
                );
                emission.assignments.push(zir::WitnessAssignment {
                    target: output.clone(),
                    expr: expr.clone(),
                });
                emission.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Signal(output.clone()),
                    rhs: expr,
                    label: Some(format!("{}_not", output)),
                });
            }
            _ => {
                return Err(ZkfError::InvalidArtifact(format!(
                    "unknown boolean op: {}",
                    op
                )));
            }
        }

        Ok(emission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_gadget_emits_constraints() {
        let gadget = BooleanGadget;
        let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
        let mut params = BTreeMap::new();
        params.insert("op".into(), "and".into());

        let emission = gadget
            .emit(&inputs, &["out".into()], FieldId::Bn254, &params)
            .unwrap();
        assert_eq!(emission.signals.len(), 1);
        assert_eq!(emission.constraints.len(), 1);
        assert_eq!(emission.assignments.len(), 1);
    }

    #[test]
    fn xor_gadget_emits_constraints() {
        let gadget = BooleanGadget;
        let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
        let mut params = BTreeMap::new();
        params.insert("op".into(), "xor".into());

        let emission = gadget
            .emit(&inputs, &["out".into()], FieldId::Bn254, &params)
            .unwrap();
        assert_eq!(emission.constraints.len(), 1);
    }
}
