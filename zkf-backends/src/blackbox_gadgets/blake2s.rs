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

//! Blake2s as arithmetic constraints.
//!
//! Uses the same bit-decomposition approach as SHA-256.
//! Blake2s operates on 32-bit words with XOR, ROTR, and modular addition.

use super::bits;
use super::{AuxCounter, LoweredBlackBox};
use num_bigint::BigInt;
use std::collections::BTreeMap;
use zkf_core::{Expr, FieldElement, FieldId, ZkfResult};

const BLAKE2S_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLAKE2S_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

pub fn lower_blake2s(
    inputs: &[Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    if outputs.len() != 32 {
        return Err(format!(
            "blake2s: expected 32 output bytes, got {}",
            outputs.len()
        ));
    }

    let mut lowered = LoweredBlackBox::default();

    // Initialize state from IV
    let mut h: Vec<String> = Vec::with_capacity(8);
    for (i, &iv) in BLAKE2S_IV.iter().enumerate() {
        let name = lowered.add_private_signal(aux.next(&format!("h_init{i}")));
        lowered.add_equal(
            Expr::Signal(name.clone()),
            Expr::Const(FieldElement::from_i64(iv as i64)),
            format!("blake2s_h{i}_init"),
        );
        h.push(name);
    }

    // XOR personalization into h[0] (hash length = 32, key length = 0, fanout = 1, depth = 1)
    let p0: u32 = 0x01010000 ^ 32;
    let h0_xored = lowered.add_private_signal(aux.next("h0_xor"));
    lowered.add_range(&h0_xored, 32, "blake2s_h0_xor_range");

    let h0_bits =
        bits::decompose_to_bits(&mut lowered, aux, Expr::Signal(h[0].clone()), 32, "h0_orig");
    let _p0_const = FieldElement::from_i64(p0 as i64);
    let p0_bits = decompose_constant_to_bits(p0, 32);

    let mut h0_xor_bits = Vec::with_capacity(32);
    for i in 0..32 {
        if p0_bits[i] {
            let flipped = bits::not_bit(&mut lowered, aux, &h0_bits[i], &format!("h0xor_b{i}"));
            // XOR with 1 = NOT
            h0_xor_bits.push(flipped);
        } else {
            h0_xor_bits.push(h0_bits[i].clone());
        }
    }
    let h0_xor_expr = bits::recompose_from_bits(&h0_xor_bits);
    lowered.add_equal(
        Expr::Signal(h0_xored.clone()),
        h0_xor_expr,
        "blake2s_h0_personalize",
    );
    h[0] = h0_xored;

    // Pad input bytes into 16 message words (64 bytes per block)
    let padded_len = inputs.len().max(1).div_ceil(64) * 64;
    let n_blocks = padded_len / 64;

    let mut message_bytes: Vec<Expr> = inputs.to_vec();
    while message_bytes.len() < padded_len {
        message_bytes.push(Expr::Const(FieldElement::from_i64(0)));
    }

    // Process blocks
    let total_bytes = inputs.len();
    for block_idx in 0..n_blocks {
        let block_start = block_idx * 64;
        let bytes_so_far = ((block_idx + 1) * 64).min(total_bytes);
        let is_last = block_idx == n_blocks - 1;

        // Pack block into 16 words (little-endian for Blake2s)
        let mut m_signals = Vec::with_capacity(16);
        for w in 0..16 {
            let byte_off = block_start + w * 4;
            let word_expr = Expr::Add(vec![
                message_bytes[byte_off].clone(),
                Expr::Mul(
                    Box::new(Expr::Const(FieldElement::from_i64(1 << 8))),
                    Box::new(message_bytes[byte_off + 1].clone()),
                ),
                Expr::Mul(
                    Box::new(Expr::Const(FieldElement::from_i64(1 << 16))),
                    Box::new(message_bytes[byte_off + 2].clone()),
                ),
                Expr::Mul(
                    Box::new(Expr::Const(FieldElement::from_i64(1 << 24))),
                    Box::new(message_bytes[byte_off + 3].clone()),
                ),
            ]);
            let m_name = lowered.add_private_signal(aux.next(&format!("blk{block_idx}_m{w}")));
            lowered.add_range(&m_name, 32, format!("blake2s_blk{block_idx}_m{w}_range"));
            lowered.add_equal(
                Expr::Signal(m_name.clone()),
                word_expr,
                format!("blake2s_blk{block_idx}_m{w}_pack"),
            );
            m_signals.push(m_name);
        }

        h = blake2s_compress(
            &mut lowered,
            aux,
            &h,
            &m_signals,
            bytes_so_far as u64,
            is_last,
            &format!("blk{block_idx}"),
        )?;
    }

    // Extract output bytes (little-endian from hash words)
    for (word_idx, h_signal) in h.iter().enumerate() {
        let word_bits = bits::decompose_to_bits(
            &mut lowered,
            aux,
            Expr::Signal(h_signal.clone()),
            32,
            &format!("out_w{word_idx}"),
        );

        for byte_idx in 0..4 {
            let out_byte_idx = word_idx * 4 + byte_idx;
            if out_byte_idx >= 32 {
                break;
            }
            // Little-endian: byte 0 = bits[7..0]
            let bit_start = byte_idx * 8;
            let byte_bits = &word_bits[bit_start..bit_start + 8];
            let byte_expr = bits::recompose_from_bits(byte_bits);

            lowered.add_equal(
                Expr::Signal(outputs[out_byte_idx].clone()),
                byte_expr,
                format!("blake2s_out_byte{out_byte_idx}"),
            );
        }
    }

    Ok(lowered)
}

fn blake2s_compress(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    h: &[String],
    m: &[String],
    t: u64,
    last: bool,
    prefix: &str,
) -> Result<Vec<String>, String> {
    // Initialize working vector v[0..15]
    let mut v: Vec<String> = Vec::with_capacity(16);
    for h_value in h.iter().take(8) {
        v.push(h_value.clone());
    }
    for (i, iv) in BLAKE2S_IV.iter().copied().enumerate() {
        let iv_name = lowered.add_private_signal(aux.next(&format!("{prefix}_v{}", i + 8)));
        lowered.add_equal(
            Expr::Signal(iv_name.clone()),
            Expr::Const(FieldElement::from_i64(iv as i64)),
            format!("{prefix}_v{}_init", i + 8),
        );
        v.push(iv_name);
    }

    // XOR counter into v[12], v[13]
    let t_lo = (t & 0xFFFFFFFF) as u32;
    let t_hi = ((t >> 32) & 0xFFFFFFFF) as u32;

    v[12] = xor_with_constant(lowered, aux, &v[12], t_lo, &format!("{prefix}_v12_tlo"))?;
    v[13] = xor_with_constant(lowered, aux, &v[13], t_hi, &format!("{prefix}_v13_thi"))?;

    if last {
        v[14] = xor_with_constant(
            lowered,
            aux,
            &v[14],
            0xFFFFFFFF,
            &format!("{prefix}_v14_last"),
        )?;
    }

    // 10 rounds of mixing
    for (round, s) in BLAKE2S_SIGMA.iter().enumerate() {
        let rl = &format!("{prefix}_r{round}");

        g_mix(
            lowered,
            aux,
            &mut v,
            0,
            4,
            8,
            12,
            &m[s[0]],
            &m[s[1]],
            &format!("{rl}_g0"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            1,
            5,
            9,
            13,
            &m[s[2]],
            &m[s[3]],
            &format!("{rl}_g1"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            2,
            6,
            10,
            14,
            &m[s[4]],
            &m[s[5]],
            &format!("{rl}_g2"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            3,
            7,
            11,
            15,
            &m[s[6]],
            &m[s[7]],
            &format!("{rl}_g3"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            0,
            5,
            10,
            15,
            &m[s[8]],
            &m[s[9]],
            &format!("{rl}_g4"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            1,
            6,
            11,
            12,
            &m[s[10]],
            &m[s[11]],
            &format!("{rl}_g5"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            2,
            7,
            8,
            13,
            &m[s[12]],
            &m[s[13]],
            &format!("{rl}_g6"),
        )?;
        g_mix(
            lowered,
            aux,
            &mut v,
            3,
            4,
            9,
            14,
            &m[s[14]],
            &m[s[15]],
            &format!("{rl}_g7"),
        )?;
    }

    // Finalize: h'[i] = h[i] XOR v[i] XOR v[i+8]
    let mut h_out = Vec::with_capacity(8);
    for i in 0..8 {
        let t = xor_words(lowered, aux, &h[i], &v[i], &format!("{prefix}_fin_a{i}"))?;
        let result = xor_words(lowered, aux, &t, &v[i + 8], &format!("{prefix}_fin_b{i}"))?;
        h_out.push(result);
    }

    Ok(h_out)
}

#[allow(clippy::too_many_arguments)]
fn g_mix(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    v: &mut [String],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    mx: &str,
    my: &str,
    label: &str,
) -> Result<(), String> {
    // a = a + b + mx
    let va = bits::add_many_mod32(
        lowered,
        aux,
        vec![
            Expr::Signal(v[a].clone()),
            Expr::Signal(v[b].clone()),
            Expr::Signal(mx.to_string()),
        ],
        &format!("{label}_a1"),
    );
    v[a] = va;

    // d = (d XOR a) >>> 16
    let d_xor = xor_words(lowered, aux, &v[d], &v[a], &format!("{label}_dxa"))?;
    v[d] = rotr_word(lowered, aux, &d_xor, 16, &format!("{label}_dr16"))?;

    // c = c + d
    v[c] = bits::add_mod32(
        lowered,
        aux,
        Expr::Signal(v[c].clone()),
        Expr::Signal(v[d].clone()),
        &format!("{label}_c1"),
    );

    // b = (b XOR c) >>> 12
    let b_xor = xor_words(lowered, aux, &v[b], &v[c], &format!("{label}_bxc1"))?;
    v[b] = rotr_word(lowered, aux, &b_xor, 12, &format!("{label}_br12"))?;

    // a = a + b + my
    v[a] = bits::add_many_mod32(
        lowered,
        aux,
        vec![
            Expr::Signal(v[a].clone()),
            Expr::Signal(v[b].clone()),
            Expr::Signal(my.to_string()),
        ],
        &format!("{label}_a2"),
    );

    // d = (d XOR a) >>> 8
    let d_xor2 = xor_words(lowered, aux, &v[d], &v[a], &format!("{label}_dxa2"))?;
    v[d] = rotr_word(lowered, aux, &d_xor2, 8, &format!("{label}_dr8"))?;

    // c = c + d
    v[c] = bits::add_mod32(
        lowered,
        aux,
        Expr::Signal(v[c].clone()),
        Expr::Signal(v[d].clone()),
        &format!("{label}_c2"),
    );

    // b = (b XOR c) >>> 7
    let b_xor2 = xor_words(lowered, aux, &v[b], &v[c], &format!("{label}_bxc2"))?;
    v[b] = rotr_word(lowered, aux, &b_xor2, 7, &format!("{label}_br7"))?;

    Ok(())
}

fn xor_words(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    label: &str,
) -> Result<String, String> {
    let a_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(a.to_string()),
        32,
        &format!("{label}_a"),
    );
    let b_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(b.to_string()),
        32,
        &format!("{label}_b"),
    );

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        let r = bits::xor_bits(
            lowered,
            aux,
            &a_bits[i],
            &b_bits[i],
            &format!("{label}_b{i}"),
        );
        result_bits.push(r);
    }

    let result_expr = bits::recompose_from_bits(&result_bits);
    let result = lowered.add_private_signal(aux.next(&format!("{label}_result")));
    lowered.add_range(&result, 32, format!("{label}_result_range"));
    lowered.add_equal(
        Expr::Signal(result.clone()),
        result_expr,
        format!("{label}_result"),
    );
    Ok(result)
}

fn xor_with_constant(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    signal: &str,
    constant: u32,
    label: &str,
) -> Result<String, String> {
    let bits_signal = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(signal.to_string()),
        32,
        &format!("{label}_sig"),
    );
    let const_bits = decompose_constant_to_bits(constant, 32);

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        if const_bits[i] {
            // XOR with 1 = NOT
            let r = bits::not_bit(lowered, aux, &bits_signal[i], &format!("{label}_b{i}"));
            result_bits.push(r);
        } else {
            result_bits.push(bits_signal[i].clone());
        }
    }

    let result_expr = bits::recompose_from_bits(&result_bits);
    let result = lowered.add_private_signal(aux.next(&format!("{label}_result")));
    lowered.add_range(&result, 32, format!("{label}_result_range"));
    lowered.add_equal(
        Expr::Signal(result.clone()),
        result_expr,
        format!("{label}_result"),
    );
    Ok(result)
}

fn rotr_word(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    signal: &str,
    amount: usize,
    label: &str,
) -> Result<String, String> {
    let in_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(signal.to_string()),
        32,
        &format!("{label}_in"),
    );
    let rotated = bits::rotr(&in_bits, amount);
    let result_expr = bits::recompose_from_bits(&rotated);
    let result = lowered.add_private_signal(aux.next(&format!("{label}_result")));
    lowered.add_range(&result, 32, format!("{label}_result_range"));
    lowered.add_equal(
        Expr::Signal(result.clone()),
        result_expr,
        format!("{label}_result"),
    );
    Ok(result)
}

fn decompose_constant_to_bits(value: u32, n_bits: u32) -> Vec<bool> {
    (0..n_bits).map(|i| (value >> i) & 1 == 1).collect()
}

pub fn compute_blake2s_witness(
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    Ok(())
}
