//! Merkle membership proof as arithmetic constraints.
//!
//! Lowers `BlackBoxOp::MerkleMembership` into a chain of Poseidon hashes
//! with conditional swaps controlled by direction bits.
//!
//! Input format: [leaf, sibling_0, dir_bit_0, sibling_1, dir_bit_1, ..., expected_root]
//! Params: "depth" (required), "hash" (optional, default "poseidon")
//! Output: [verified] where verified ∈ {0, 1}

use super::{AuxCounter, LoweredBlackBox};
use num_bigint::BigInt;
use std::collections::BTreeMap;
use zkf_core::{Expr, FieldElement, FieldId, ZkfResult};

pub fn lower_merkle_membership(
    inputs: &[Expr],
    outputs: &[String],
    params: &BTreeMap<String, String>,
    field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    let depth: usize = params
        .get("depth")
        .ok_or_else(|| "merkle_membership: 'depth' param required".to_string())?
        .parse()
        .map_err(|_| "merkle_membership: 'depth' must be a number".to_string())?;

    // Expected inputs: leaf + depth * (sibling, dir_bit) + expected_root
    let expected_inputs = 1 + depth * 2 + 1;
    if inputs.len() != expected_inputs {
        return Err(format!(
            "merkle_membership depth {}: expected {} inputs \
             (leaf + {} * (sibling, dir_bit) + root), got {}",
            depth, expected_inputs, depth, inputs.len()
        ));
    }

    if outputs.len() != 1 {
        return Err(format!(
            "merkle_membership: expected 1 output (verified), got {}",
            outputs.len()
        ));
    }

    let mut lowered = LoweredBlackBox::default();

    let leaf_expr = &inputs[0];
    let expected_root = &inputs[inputs.len() - 1];

    // Initialize: current = leaf
    let mut current_name = lowered.add_private_signal(aux.next("merkle_cur"));
    lowered.add_equal(
        Expr::Signal(current_name.clone()),
        leaf_expr.clone(),
        "merkle_leaf",
    );

    for level in 0..depth {
        let sibling = &inputs[1 + level * 2];
        let dir_bit = &inputs[2 + level * 2];

        // Create and constrain direction bit as boolean
        let bit_name = lowered.add_private_signal(aux.next("merkle_bit"));
        lowered.add_equal(
            Expr::Signal(bit_name.clone()),
            dir_bit.clone(),
            format!("merkle_bit_{level}"),
        );
        lowered.add_boolean(bit_name.clone(), format!("merkle_bit_{level}_bool"));

        // Conditional swap: if bit=0, left=current, right=sibling
        //                    if bit=1, left=sibling, right=current
        // left = current + bit * (sibling - current)
        // right = sibling + bit * (current - sibling)
        let left_name = lowered.add_private_signal(aux.next("merkle_left"));
        let right_name = lowered.add_private_signal(aux.next("merkle_right"));

        // left = current + bit * (sibling - current)
        let diff = Expr::Sub(
            Box::new(sibling.clone()),
            Box::new(Expr::Signal(current_name.clone())),
        );
        let left_expr = Expr::Add(vec![
            Expr::Signal(current_name.clone()),
            Expr::Mul(
                Box::new(Expr::Signal(bit_name.clone())),
                Box::new(diff),
            ),
        ]);
        lowered.add_equal(
            Expr::Signal(left_name.clone()),
            left_expr,
            format!("merkle_left_{level}"),
        );

        // right = sibling + bit * (current - sibling)
        let diff_inv = Expr::Sub(
            Box::new(Expr::Signal(current_name.clone())),
            Box::new(sibling.clone()),
        );
        let right_expr = Expr::Add(vec![
            sibling.clone(),
            Expr::Mul(
                Box::new(Expr::Signal(bit_name)),
                Box::new(diff_inv),
            ),
        ]);
        lowered.add_equal(
            Expr::Signal(right_name.clone()),
            right_expr,
            format!("merkle_right_{level}"),
        );

        // Hash: next = poseidon(left, right)
        // We inline the Poseidon lowering by delegating to the poseidon2 module.
        // For now, emit a BlackBox Poseidon constraint that will be lowered
        // in a second pass (or emit the poseidon lowering inline).
        let next_name = lowered.add_private_signal(aux.next("merkle_hash"));

        // Emit Poseidon hash as sub-constraint. The outer lowering pass
        // will lower this BlackBox further into arithmetic constraints.
        // However, since lower_blackbox_program processes constraints in order,
        // and we're already inside a lowering, we inline the Poseidon call
        // as an Equal constraint binding the hash output.
        // For proper end-to-end soundness, we delegate to poseidon2::lower_poseidon2.
        // Poseidon2 compression: hash(left, right) with width-4 permutation.
        // The Poseidon2 BN254 implementation requires exactly width=4 inputs/outputs.
        // We use a 2-to-1 compression: [left, right, 0, 0] → [hash, _, _, _]
        // where only the first output element is used as the hash digest.
        let padding_zero_1 = lowered.add_private_signal(aux.next("merkle_pad0"));
        lowered.add_equal(
            Expr::Signal(padding_zero_1.clone()),
            Expr::Const(FieldElement::from_i64(0)),
            format!("merkle_pad0_{level}"),
        );
        let padding_zero_2 = lowered.add_private_signal(aux.next("merkle_pad1"));
        lowered.add_equal(
            Expr::Signal(padding_zero_2.clone()),
            Expr::Const(FieldElement::from_i64(0)),
            format!("merkle_pad1_{level}"),
        );
        // Extra output signals for width-4 (discarded)
        let discard_out_1 = lowered.add_private_signal(aux.next("merkle_dout1"));
        let discard_out_2 = lowered.add_private_signal(aux.next("merkle_dout2"));
        let discard_out_3 = lowered.add_private_signal(aux.next("merkle_dout3"));

        let poseidon_inputs = vec![
            Expr::Signal(left_name),
            Expr::Signal(right_name),
            Expr::Signal(padding_zero_1),
            Expr::Signal(padding_zero_2),
        ];
        let poseidon_outputs = vec![
            next_name.clone(),
            discard_out_1,
            discard_out_2,
            discard_out_3,
        ];
        let mut poseidon_params = BTreeMap::new();
        poseidon_params.insert("state_len".to_string(), "4".to_string());

        let poseidon_result = super::poseidon2::lower_poseidon2(
            &poseidon_inputs,
            &poseidon_outputs,
            &poseidon_params,
            field,
            aux,
        )?;

        lowered.signals.extend(poseidon_result.signals);
        lowered.constraints.extend(poseidon_result.constraints);

        current_name = next_name;
    }

    // Final: computed root == expected root
    lowered.add_equal(
        Expr::Signal(current_name),
        expected_root.clone(),
        "merkle_root_eq",
    );

    // Output: verified = 1 (constraints enforce correctness; if all pass, proof is valid)
    lowered.add_equal(
        Expr::Signal(outputs[0].clone()),
        Expr::Const(FieldElement::from_i64(1)),
        "merkle_verified",
    );

    Ok(lowered)
}

pub fn compute_merkle_witness(
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    // Witness computation for Merkle is handled by the constraint solver
    // in enrich_witness_for_proving — the conditional swap and Poseidon
    // intermediate values are solved iteratively from the input witness.
    Ok(())
}
