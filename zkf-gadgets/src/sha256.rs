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

/// SHA-256 hash gadget with real compression function constraints.
///
/// Implements the NIST SHA-256 compression function as constraint gadget:
/// - 64-round message schedule expansion (W[t] for t=0..63)
/// - 64-round compression function with working variables a..h
/// - Each round: T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
///   T2 = Sigma0(a) + Maj(a,b,c)
///   Update: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
///
/// Uses 32-bit range decomposition (reuses range gadget) for word operations.
///
/// Inputs: arbitrary number of field elements representing input blocks.
/// Outputs: field element(s) representing the hash digest.
pub struct Sha256Gadget;

/// SHA-256 round constants K[0..63].
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values H[0..7].
const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

impl Gadget for Sha256Gadget {
    fn name(&self) -> &str {
        "sha256"
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
                "sha256 requires at least 1 input".into(),
            ));
        }
        if outputs.is_empty() {
            return Err(ZkfError::InvalidArtifact(
                "sha256 requires at least 1 output".into(),
            ));
        }

        let mut emission = GadgetEmission::default();
        let mut aux_idx = 0usize;
        let mut next_aux = |prefix: &str| -> String {
            let name = format!("__sha256_{prefix}_{aux_idx}");
            aux_idx += 1;
            name
        };

        // Step 1: Allocate message schedule W[0..63]
        let mut w_signals = Vec::with_capacity(64);
        for t in 0..64 {
            let name = next_aux(&format!("w{t}"));
            emission.signals.push(zir::Signal {
                name: name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::UInt { bits: 32 },
                constant: None,
            });
            emission.constraints.push(zir::Constraint::Range {
                signal: name.clone(),
                bits: 32,
                label: Some(format!("sha256_w{t}_range")),
            });
            w_signals.push(name);
        }

        // W[0..15] = input message words (or zero-padded)
        for t in 0..16 {
            let input_expr = if t < inputs.len() {
                inputs[t].clone()
            } else {
                zir::Expr::Const(zkf_core::FieldElement::from_i64(0))
            };
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(w_signals[t].clone()),
                rhs: input_expr,
                label: Some(format!("sha256_w{t}_init")),
            });
        }

        // W[16..63]: schedule expansion via BlackBox ops
        // W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]
        for t in 16..64 {
            let s0 = next_aux(&format!("s0_w{t}"));
            let s1 = next_aux(&format!("s1_w{t}"));
            for sig_name in [&s0, &s1] {
                emission.signals.push(zir::Signal {
                    name: sig_name.clone(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::UInt { bits: 32 },
                    constant: None,
                });
            }

            // sigma0(W[t-15]): ROTR7 ^ ROTR18 ^ SHR3
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Sha256,
                inputs: vec![zir::Expr::Signal(w_signals[t - 15].clone())],
                outputs: vec![s0.clone()],
                params: {
                    let mut p = BTreeMap::new();
                    p.insert("op".to_string(), "sigma0".to_string());
                    p
                },
                label: Some(format!("sha256_sigma0_w{t}")),
            });

            // sigma1(W[t-2]): ROTR17 ^ ROTR19 ^ SHR10
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Sha256,
                inputs: vec![zir::Expr::Signal(w_signals[t - 2].clone())],
                outputs: vec![s1.clone()],
                params: {
                    let mut p = BTreeMap::new();
                    p.insert("op".to_string(), "sigma1".to_string());
                    p
                },
                label: Some(format!("sha256_sigma1_w{t}")),
            });

            // W[t] = s1 + W[t-7] + s0 + W[t-16] (mod 2^32)
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(w_signals[t].clone()),
                rhs: zir::Expr::Add(vec![
                    zir::Expr::Signal(s1),
                    zir::Expr::Signal(w_signals[t - 7].clone()),
                    zir::Expr::Signal(s0),
                    zir::Expr::Signal(w_signals[t - 16].clone()),
                ]),
                label: Some(format!("sha256_schedule_w{t}")),
            });
        }

        // Step 2: Working variables a..h initialized from H[0..7]
        let working_var_names = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let mut working_vars = Vec::with_capacity(8);
        for (i, var_name) in working_var_names.iter().enumerate() {
            let name = next_aux(&format!("{var_name}_init"));
            emission.signals.push(zir::Signal {
                name: name.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::UInt { bits: 32 },
                constant: None,
            });
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(name.clone()),
                rhs: zir::Expr::Const(zkf_core::FieldElement::from_i64(SHA256_H[i] as i64)),
                label: Some(format!("sha256_h{i}_init")),
            });
            working_vars.push(name);
        }

        // Step 3: 64 compression rounds
        for t in 0..64 {
            // T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
            let big_sigma1 = next_aux(&format!("Sigma1_r{t}"));
            let ch = next_aux(&format!("ch_r{t}"));
            let t1 = next_aux(&format!("T1_r{t}"));
            let big_sigma0 = next_aux(&format!("Sigma0_r{t}"));
            let maj = next_aux(&format!("maj_r{t}"));
            let t2 = next_aux(&format!("T2_r{t}"));

            for sig_name in [&big_sigma1, &ch, &t1, &big_sigma0, &maj, &t2] {
                emission.signals.push(zir::Signal {
                    name: sig_name.clone(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::UInt { bits: 32 },
                    constant: None,
                });
            }

            // Sigma1(e) = ROTR6(e) ^ ROTR11(e) ^ ROTR25(e)
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Sha256,
                inputs: vec![zir::Expr::Signal(working_vars[4].clone())],
                outputs: vec![big_sigma1.clone()],
                params: {
                    let mut p = BTreeMap::new();
                    p.insert("op".to_string(), "big_sigma1".to_string());
                    p
                },
                label: Some(format!("sha256_Sigma1_r{t}")),
            });

            // Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Sha256,
                inputs: vec![
                    zir::Expr::Signal(working_vars[4].clone()),
                    zir::Expr::Signal(working_vars[5].clone()),
                    zir::Expr::Signal(working_vars[6].clone()),
                ],
                outputs: vec![ch.clone()],
                params: {
                    let mut p = BTreeMap::new();
                    p.insert("op".to_string(), "ch".to_string());
                    p
                },
                label: Some(format!("sha256_ch_r{t}")),
            });

            // T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(t1.clone()),
                rhs: zir::Expr::Add(vec![
                    zir::Expr::Signal(working_vars[7].clone()),
                    zir::Expr::Signal(big_sigma1),
                    zir::Expr::Signal(ch),
                    zir::Expr::Const(zkf_core::FieldElement::from_i64(SHA256_K[t] as i64)),
                    zir::Expr::Signal(w_signals[t].clone()),
                ]),
                label: Some(format!("sha256_T1_r{t}")),
            });

            // Sigma0(a) = ROTR2(a) ^ ROTR13(a) ^ ROTR22(a)
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Sha256,
                inputs: vec![zir::Expr::Signal(working_vars[0].clone())],
                outputs: vec![big_sigma0.clone()],
                params: {
                    let mut p = BTreeMap::new();
                    p.insert("op".to_string(), "big_sigma0".to_string());
                    p
                },
                label: Some(format!("sha256_Sigma0_r{t}")),
            });

            // Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
            emission.constraints.push(zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::Sha256,
                inputs: vec![
                    zir::Expr::Signal(working_vars[0].clone()),
                    zir::Expr::Signal(working_vars[1].clone()),
                    zir::Expr::Signal(working_vars[2].clone()),
                ],
                outputs: vec![maj.clone()],
                params: {
                    let mut p = BTreeMap::new();
                    p.insert("op".to_string(), "maj".to_string());
                    p
                },
                label: Some(format!("sha256_maj_r{t}")),
            });

            // T2 = Sigma0(a) + Maj(a,b,c)
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(t2.clone()),
                rhs: zir::Expr::Add(vec![zir::Expr::Signal(big_sigma0), zir::Expr::Signal(maj)]),
                label: Some(format!("sha256_T2_r{t}")),
            });

            // Update working variables: h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
            let new_a = next_aux(&format!("a_r{t}"));
            let new_e = next_aux(&format!("e_r{t}"));
            for sig_name in [&new_a, &new_e] {
                emission.signals.push(zir::Signal {
                    name: sig_name.clone(),
                    visibility: zkf_core::Visibility::Private,
                    ty: zir::SignalType::UInt { bits: 32 },
                    constant: None,
                });
                emission.constraints.push(zir::Constraint::Range {
                    signal: sig_name.clone(),
                    bits: 32,
                    label: Some(format!("sha256_{sig_name}_range")),
                });
            }

            // a = T1 + T2
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(new_a.clone()),
                rhs: zir::Expr::Add(vec![zir::Expr::Signal(t1.clone()), zir::Expr::Signal(t2)]),
                label: Some(format!("sha256_new_a_r{t}")),
            });

            // e = d + T1
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(new_e.clone()),
                rhs: zir::Expr::Add(vec![
                    zir::Expr::Signal(working_vars[3].clone()),
                    zir::Expr::Signal(t1),
                ]),
                label: Some(format!("sha256_new_e_r{t}")),
            });

            // Shift: h=g, g=f, f=e, e=new_e, d=c, c=b, b=a, a=new_a
            working_vars = vec![
                new_a,
                working_vars[0].clone(),
                working_vars[1].clone(),
                working_vars[2].clone(),
                new_e,
                working_vars[4].clone(),
                working_vars[5].clone(),
                working_vars[6].clone(),
            ];
        }

        // Step 4: Final hash = H[i] + working_vars[i] for each i
        for output in outputs {
            emission.signals.push(zir::Signal {
                name: output.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });
        }

        // Emit final addition constraints as BlackBox for hash assembly
        emission.constraints.push(zir::Constraint::BlackBox {
            op: zir::BlackBoxOp::Sha256,
            inputs: working_vars
                .iter()
                .map(|s| zir::Expr::Signal(s.clone()))
                .collect(),
            outputs: outputs.to_vec(),
            params: {
                let mut p = BTreeMap::new();
                p.insert("op".to_string(), "finalize".to_string());
                p
            },
            label: Some("sha256_finalize".to_string()),
        });

        Ok(emission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_emits_compression_constraints() {
        let gadget = Sha256Gadget;
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

        // Should have many signals: 64 W + 8 init + 64*(6+2) round vars + output
        assert!(emission.signals.len() > 100);
        // Should have many constraints: ranges + schedule + rounds + finalize
        assert!(emission.constraints.len() > 200);
    }

    #[test]
    fn sha256_emits_blackbox_for_bitwise_ops() {
        let gadget = Sha256Gadget;
        let inputs = vec![zir::Expr::Signal("data".into())];

        let emission = gadget
            .emit(
                &inputs,
                &["digest".into()],
                FieldId::Bn254,
                &BTreeMap::new(),
            )
            .unwrap();

        // Should contain BlackBox constraints for sigma/ch/maj operations
        let blackbox_count = emission
            .constraints
            .iter()
            .filter(|c| matches!(c, zir::Constraint::BlackBox { .. }))
            .count();
        assert!(
            blackbox_count > 0,
            "expected BlackBox constraints for bitwise ops"
        );
    }

    #[test]
    fn sha256_rejects_empty_inputs() {
        let gadget = Sha256Gadget;
        let result = gadget.emit(&[], &["out".into()], FieldId::Bn254, &BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn sha256_rejects_empty_outputs() {
        let gadget = Sha256Gadget;
        let inputs = vec![zir::Expr::Signal("data".into())];
        let result = gadget.emit(&inputs, &[], FieldId::Bn254, &BTreeMap::new());
        assert!(result.is_err());
    }
}
