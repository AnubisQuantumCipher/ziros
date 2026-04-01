use crate::gadget::{
    Gadget, GadgetEmission, builtin_supported_fields, validate_builtin_field_support,
};
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{FieldId, ZkfError, ZkfResult};

/// Binary Merkle membership proof gadget using Poseidon hash.
///
/// Params:
/// - `depth`: tree depth (required)
///
/// Inputs: [leaf, path_element_0, path_bit_0, path_element_1, path_bit_1, ...]
/// Outputs: [root]
///
/// Verifies that `leaf` is in a Merkle tree with the given root by hashing
/// up the authentication path.
pub struct MerkleGadget;

impl Gadget for MerkleGadget {
    fn name(&self) -> &str {
        "merkle"
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
        let depth: usize = params
            .get("depth")
            .ok_or_else(|| ZkfError::InvalidArtifact("merkle requires 'depth' param".into()))?
            .parse()
            .map_err(|_| ZkfError::InvalidArtifact("depth must be a number".into()))?;

        // Expected inputs: leaf + depth * (sibling, direction_bit)
        let expected_inputs = 1 + depth * 2;
        if inputs.len() != expected_inputs {
            return Err(ZkfError::InvalidArtifact(format!(
                "merkle depth {} requires {} inputs (leaf + {} pairs), got {}",
                depth,
                expected_inputs,
                depth,
                inputs.len()
            )));
        }

        let root_output = outputs
            .first()
            .ok_or_else(|| ZkfError::InvalidArtifact("merkle requires one output (root)".into()))?;

        let mut emission = GadgetEmission::default();

        // Hash up the path: at each level, hash (left, right) where left/right
        // is determined by the direction bit.
        let mut current = "merkle_current_0".to_string();
        emission.signals.push(zir::Signal {
            name: current.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Field,
            constant: None,
        });
        // current_0 = leaf
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Signal(current.clone()),
            rhs: inputs[0].clone(),
            label: Some("merkle_leaf".to_string()),
        });

        for level in 0..depth {
            let sibling = &inputs[1 + level * 2];
            let bit = &inputs[2 + level * 2];

            // Boolean constraint on direction bit.
            let bit_name = format!("merkle_bit_{}", level);
            emission.signals.push(zir::Signal {
                name: bit_name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Bool,
                constant: None,
            });
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(bit_name.clone()),
                rhs: bit.clone(),
                label: Some(format!("merkle_bit_{}_eq", level)),
            });
            emission.constraints.push(zir::Constraint::Boolean {
                signal: bit_name.clone(),
                label: Some(format!("merkle_bit_{}_bool", level)),
            });

            // Compute left/right based on direction:
            // left = current * (1-bit) + sibling * bit
            // right = sibling * (1-bit) + current * bit
            let left_name = format!("merkle_left_{}", level);
            let right_name = format!("merkle_right_{}", level);

            emission.signals.push(zir::Signal {
                name: left_name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });
            emission.signals.push(zir::Signal {
                name: right_name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });

            // left = current + bit * (sibling - current)
            let diff = zir::Expr::Sub(
                Box::new(sibling.clone()),
                Box::new(zir::Expr::Signal(current.clone())),
            );
            let left_expr = zir::Expr::Add(vec![
                zir::Expr::Signal(current.clone()),
                zir::Expr::Mul(
                    Box::new(zir::Expr::Signal(bit_name.clone())),
                    Box::new(diff.clone()),
                ),
            ]);
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(left_name.clone()),
                rhs: left_expr.clone(),
                label: Some(format!("merkle_left_{}_eq", level)),
            });
            emission.assignments.push(zir::WitnessAssignment {
                target: left_name.clone(),
                expr: left_expr,
            });

            // right = sibling + bit * (current - sibling)
            let diff_inv = zir::Expr::Sub(
                Box::new(zir::Expr::Signal(current.clone())),
                Box::new(sibling.clone()),
            );
            let right_expr = zir::Expr::Add(vec![
                sibling.clone(),
                zir::Expr::Mul(
                    Box::new(zir::Expr::Signal(bit_name.clone())),
                    Box::new(diff_inv),
                ),
            ]);
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(right_name.clone()),
                rhs: right_expr.clone(),
                label: Some(format!("merkle_right_{}_eq", level)),
            });
            emission.assignments.push(zir::WitnessAssignment {
                target: right_name.clone(),
                expr: right_expr,
            });

            // Hash: next = poseidon(left, right)
            let next = format!("merkle_current_{}", level + 1);
            emission.signals.push(zir::Signal {
                name: next.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Poseidon,
                inputs: vec![zir::Expr::Signal(left_name), zir::Expr::Signal(right_name)],
                outputs: vec![next.clone()],
                params: BTreeMap::new(),
                label: Some(format!("merkle_hash_{}", level)),
            });

            current = next;
        }

        // Output: computed root == expected root.
        emission.signals.push(zir::Signal {
            name: root_output.clone(),
            visibility: zkf_core::Visibility::Public,
            ty: zir::SignalType::Field,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Signal(root_output.clone()),
            rhs: zir::Expr::Signal(current),
            label: Some("merkle_root_eq".to_string()),
        });

        Ok(emission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_depth_3_emits_correct_structure() {
        let gadget = MerkleGadget;
        // leaf + 3 * (sibling, bit)
        let inputs = vec![
            zir::Expr::Signal("leaf".into()),
            zir::Expr::Signal("sib_0".into()),
            zir::Expr::Signal("dir_0".into()),
            zir::Expr::Signal("sib_1".into()),
            zir::Expr::Signal("dir_1".into()),
            zir::Expr::Signal("sib_2".into()),
            zir::Expr::Signal("dir_2".into()),
        ];
        let mut params = BTreeMap::new();
        params.insert("depth".into(), "3".into());

        let emission = gadget
            .emit(&inputs, &["root".into()], FieldId::Bn254, &params)
            .unwrap();

        // Per level: bit signal + left signal + right signal + current signal
        // = 4 signals * 3 levels + initial current + root = 14 signals
        assert!(emission.signals.len() >= 13);
        // Has Poseidon hash constraints for each level.
        let poseidon_count = emission
            .constraints
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    zir::Constraint::BlackBox {
                        op: zir::BlackBoxOp::Poseidon,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(poseidon_count, 3);
    }
}
