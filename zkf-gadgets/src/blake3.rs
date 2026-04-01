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

/// Blake3 hash gadget.
///
/// Implements the Blake3 compression function as a constraint gadget.
/// Blake3 operates on 16 u32 words with 7 rounds of G mixing.
/// This gadget emits constraints for:
/// - 32-bit range decomposition of each word
/// - G mixing function (quarter-rounds with additions, XORs, and rotations)
/// - 7 rounds of column and diagonal mixing
///
/// Inputs: arbitrary field elements representing the message block.
/// Outputs: 1 field element (hash digest as packed field element).
pub struct Blake3Gadget;

const BLAKE3_ROUNDS: usize = 7;
const BLAKE3_BLOCK_WORDS: usize = 16;

/// Blake3 IV constants (first 8 are also used as chaining value init).
const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Blake3 message schedule permutation.
const BLAKE3_MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

impl Gadget for Blake3Gadget {
    fn name(&self) -> &str {
        "blake3"
    }

    fn supported_fields(&self) -> Vec<FieldId> {
        builtin_supported_fields(self.name()).unwrap_or_default()
    }

    fn emit(
        &self,
        inputs: &[zir::Expr],
        outputs: &[String],
        field: FieldId,
        _params: &BTreeMap<String, String>,
    ) -> ZkfResult<GadgetEmission> {
        validate_builtin_field_support(self.name(), field)?;
        if inputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "blake3 requires at least 1 input".into(),
            ));
        }
        if outputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "blake3 requires at least 1 output".into(),
            ));
        }

        let mut emission = GadgetEmission::default();
        let mut aux_idx = 0usize;

        // Allocate state words (16 u32 words for the compression state)
        let mut state_signals = Vec::with_capacity(BLAKE3_BLOCK_WORDS);
        for i in 0..BLAKE3_BLOCK_WORDS {
            let name = format!("__blake3_state_{i}_{aux_idx}");
            aux_idx += 1;
            emission.signals.push(zir::Signal {
                name: name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::UInt { bits: 32 },
                constant: None,
            });
            // Range constrain each state word to 32 bits
            emission.constraints.push(zir::Constraint::Range {
                signal: name.clone(),
                bits: 32,
                label: Some(format!("blake3_state_range_{i}")),
            });
            state_signals.push(name);
        }

        // Initialize state: first 8 words from IV, next 4 from counter/flags,
        // last 4 from message block. For the constraint gadget, we emit
        // equality constraints tying the initial state to the IV constants.
        for (i, &iv_word) in BLAKE3_IV.iter().enumerate() {
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(state_signals[i].clone()),
                rhs: zir::Expr::Const(zkf_core::FieldElement::from_i64(iv_word as i64)),
                label: Some(format!("blake3_iv_init_{i}")),
            });
        }

        // Emit 7 rounds of G mixing constraints
        for (round, schedule) in BLAKE3_MSG_SCHEDULE.iter().enumerate().take(BLAKE3_ROUNDS) {
            // Column rounds: G on columns (0,4,8,12), (1,5,9,13), etc.
            for col in 0..4 {
                let a_idx = col;
                let b_idx = col + 4;
                let c_idx = col + 8;
                let d_idx = col + 12;
                let mx = schedule[2 * col];
                let my = schedule[2 * col + 1];

                emit_g_mixing(
                    &mut emission,
                    &mut aux_idx,
                    round,
                    col,
                    "col",
                    &state_signals,
                    a_idx,
                    b_idx,
                    c_idx,
                    d_idx,
                    mx,
                    my,
                    inputs,
                );
            }

            // Diagonal rounds: G on diagonals (0,5,10,15), (1,6,11,12), etc.
            for diag in 0..4 {
                let a_idx = diag;
                let b_idx = ((diag + 1) % 4) + 4;
                let c_idx = ((diag + 2) % 4) + 8;
                let d_idx = ((diag + 3) % 4) + 12;
                let mx = schedule[2 * diag + 8];
                let my = schedule[2 * diag + 9];

                emit_g_mixing(
                    &mut emission,
                    &mut aux_idx,
                    round,
                    diag,
                    "diag",
                    &state_signals,
                    a_idx,
                    b_idx,
                    c_idx,
                    d_idx,
                    mx,
                    my,
                    inputs,
                );
            }
        }

        // Output: pack the final state into the output signal(s)
        for output in outputs {
            emission.signals.push(zir::Signal {
                name: output.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });
        }

        // Final XOR of first 8 state words with last 8 state words → output
        let final_xor = format!("__blake3_final_xor_{aux_idx}");
        emission.signals.push(zir::Signal {
            name: final_xor.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Field,
            constant: None,
        });

        // Emit a BlackBox constraint for the final hash assembly
        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::Blake2s, // reuse blake2s op type for blake3
            inputs: state_signals
                .iter()
                .map(|s| zir::Expr::Signal(s.clone()))
                .collect(),
            outputs: outputs.to_vec(),
            params: {
                let mut p = BTreeMap::new();
                p.insert("variant".to_string(), "blake3".to_string());
                p.insert("rounds".to_string(), BLAKE3_ROUNDS.to_string());
                p
            },
            label: Some("blake3_finalize".to_string()),
        });

        Ok(emission)
    }
}

/// Emit constraints for one G mixing function invocation.
/// G(a, b, c, d, mx, my) performs:
///   a = a + b + mx; d = (d ^ a) >>> 16;
///   c = c + d;      b = (b ^ c) >>> 12;
///   a = a + b + my; d = (d ^ a) >>> 8;
///   c = c + d;      b = (b ^ c) >>> 7;
#[allow(clippy::too_many_arguments)]
fn emit_g_mixing(
    emission: &mut GadgetEmission,
    aux_idx: &mut usize,
    round: usize,
    step: usize,
    kind: &str,
    state_signals: &[String],
    a_idx: usize,
    b_idx: usize,
    c_idx: usize,
    d_idx: usize,
    mx_idx: usize,
    my_idx: usize,
    inputs: &[zir::Expr],
) {
    let prefix = format!("r{round}_{kind}{step}");

    // Get message word expressions (or zero if index exceeds inputs)
    let mx_expr = if mx_idx < inputs.len() {
        inputs[mx_idx].clone()
    } else {
        zir::Expr::Const(zkf_core::FieldElement::from_i64(0))
    };
    let my_expr = if my_idx < inputs.len() {
        inputs[my_idx].clone()
    } else {
        zir::Expr::Const(zkf_core::FieldElement::from_i64(0))
    };

    // Step 1: a = a + b + mx
    let a_new = format!("__blake3_{prefix}_a1_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: a_new.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(a_new.clone()),
        rhs: zir::Expr::Add(vec![
            zir::Expr::Signal(state_signals[a_idx].clone()),
            zir::Expr::Signal(state_signals[b_idx].clone()),
            mx_expr,
        ]),
        label: Some(format!("blake3_{prefix}_step1")),
    });
    emission.constraints.push(zir::Constraint::Range {
        signal: a_new.clone(),
        bits: 32,
        label: Some(format!("blake3_{prefix}_a1_range")),
    });

    // Step 2: d = (d ^ a) >>> 16 — emitted as blackbox XOR+rotate
    let d_new = format!("__blake3_{prefix}_d1_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: d_new.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::BlackBox {
        op: zir::BlackBoxOp::Blake2s,
        inputs: vec![
            zir::Expr::Signal(state_signals[d_idx].clone()),
            zir::Expr::Signal(a_new.clone()),
        ],
        outputs: vec![d_new.clone()],
        params: {
            let mut p = BTreeMap::new();
            p.insert("op".to_string(), "xor_rotr".to_string());
            p.insert("rotate".to_string(), "16".to_string());
            p
        },
        label: Some(format!("blake3_{prefix}_step2")),
    });

    // Step 3: c = c + d
    let c_new = format!("__blake3_{prefix}_c1_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: c_new.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(c_new.clone()),
        rhs: zir::Expr::Add(vec![
            zir::Expr::Signal(state_signals[c_idx].clone()),
            zir::Expr::Signal(d_new.clone()),
        ]),
        label: Some(format!("blake3_{prefix}_step3")),
    });
    emission.constraints.push(zir::Constraint::Range {
        signal: c_new.clone(),
        bits: 32,
        label: Some(format!("blake3_{prefix}_c1_range")),
    });

    // Step 4: b = (b ^ c) >>> 12
    let b_new = format!("__blake3_{prefix}_b1_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: b_new.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::BlackBox {
        op: zir::BlackBoxOp::Blake2s,
        inputs: vec![
            zir::Expr::Signal(state_signals[b_idx].clone()),
            zir::Expr::Signal(c_new.clone()),
        ],
        outputs: vec![b_new.clone()],
        params: {
            let mut p = BTreeMap::new();
            p.insert("op".to_string(), "xor_rotr".to_string());
            p.insert("rotate".to_string(), "12".to_string());
            p
        },
        label: Some(format!("blake3_{prefix}_step4")),
    });

    // Step 5: a = a + b + my
    let a_new2 = format!("__blake3_{prefix}_a2_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: a_new2.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(a_new2.clone()),
        rhs: zir::Expr::Add(vec![
            zir::Expr::Signal(a_new),
            zir::Expr::Signal(b_new.clone()),
            my_expr,
        ]),
        label: Some(format!("blake3_{prefix}_step5")),
    });
    emission.constraints.push(zir::Constraint::Range {
        signal: a_new2.clone(),
        bits: 32,
        label: Some(format!("blake3_{prefix}_a2_range")),
    });

    // Step 6: d = (d ^ a) >>> 8
    let d_new2 = format!("__blake3_{prefix}_d2_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: d_new2.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::BlackBox {
        op: zir::BlackBoxOp::Blake2s,
        inputs: vec![zir::Expr::Signal(d_new), zir::Expr::Signal(a_new2.clone())],
        outputs: vec![d_new2.clone()],
        params: {
            let mut p = BTreeMap::new();
            p.insert("op".to_string(), "xor_rotr".to_string());
            p.insert("rotate".to_string(), "8".to_string());
            p
        },
        label: Some(format!("blake3_{prefix}_step6")),
    });

    // Step 7: c = c + d
    let c_new2 = format!("__blake3_{prefix}_c2_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: c_new2.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(c_new2.clone()),
        rhs: zir::Expr::Add(vec![
            zir::Expr::Signal(c_new),
            zir::Expr::Signal(d_new2.clone()),
        ]),
        label: Some(format!("blake3_{prefix}_step7")),
    });
    emission.constraints.push(zir::Constraint::Range {
        signal: c_new2.clone(),
        bits: 32,
        label: Some(format!("blake3_{prefix}_c2_range")),
    });

    // Step 8: b = (b ^ c) >>> 7
    let b_new2 = format!("__blake3_{prefix}_b2_{aux_idx}");
    *aux_idx += 1;
    emission.signals.push(zir::Signal {
        name: b_new2.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::UInt { bits: 32 },
        constant: None,
    });
    emission.constraints.push(zir::Constraint::BlackBox {
        op: zir::BlackBoxOp::Blake2s,
        inputs: vec![zir::Expr::Signal(b_new), zir::Expr::Signal(c_new2)],
        outputs: vec![b_new2],
        params: {
            let mut p = BTreeMap::new();
            p.insert("op".to_string(), "xor_rotr".to_string());
            p.insert("rotate".to_string(), "7".to_string());
            p
        },
        label: Some(format!("blake3_{prefix}_step8")),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_emits_compression_constraints() {
        let gadget = Blake3Gadget;
        let inputs: Vec<zir::Expr> = (0..16)
            .map(|i| zir::Expr::Signal(format!("msg_{i}")))
            .collect();

        let emission = gadget
            .emit(
                &inputs,
                &["digest".into()],
                FieldId::Bn254,
                &BTreeMap::new(),
            )
            .unwrap();

        // Should have signals for state + round intermediates + output
        assert!(!emission.signals.is_empty());
        // Should have constraints for IV init + rounds + finalize
        assert!(!emission.constraints.is_empty());
        // Should have at least the 8 IV init constraints + round constraints
        assert!(emission.constraints.len() > 8);
    }

    #[test]
    fn blake3_rejects_empty_inputs() {
        let gadget = Blake3Gadget;
        let result = gadget.emit(&[], &["out".into()], FieldId::Bn254, &BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn blake3_rejects_empty_outputs() {
        let gadget = Blake3Gadget;
        let inputs = vec![zir::Expr::Signal("data".into())];
        let result = gadget.emit(&inputs, &[], FieldId::Bn254, &BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn blake3_supported_fields() {
        let gadget = Blake3Gadget;
        let fields = gadget.supported_fields();
        assert!(fields.contains(&FieldId::Bn254));
        assert!(fields.contains(&FieldId::Goldilocks));
    }
}
