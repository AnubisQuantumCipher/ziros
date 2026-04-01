//! SHA-256 compression function as arithmetic constraints.
//!
//! Implements the NIST FIPS 180-4 SHA-256 compression function using
//! bit decomposition and boolean arithmetic:
//!   - Each 32-bit word is decomposed into 32 boolean signals
//!   - XOR(a,b) = a + b - 2*a*b
//!   - AND(a,b) = a * b
//!   - NOT(a)   = 1 - a
//!   - ROTR = bit reindexing (no constraints)
//!   - Addition mod 2^32 = result + carry * 2^32 = sum (carry is boolean)
//!
//! Cost: ~25,000 R1CS constraints per SHA-256 compression call.

use super::bits;
use super::{AuxCounter, LoweredBlackBox};
use num_bigint::BigInt;
use std::collections::BTreeMap;
use zkf_core::{Expr, FieldElement, FieldId, ZkfResult};

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

const SHA256_H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Lower a SHA-256 BlackBox constraint into arithmetic constraints.
///
/// Each input byte is expected as a separate field element.
/// Outputs are the 32 digest bytes as separate field elements.
pub fn lower_sha256(
    inputs: &[Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    if outputs.len() != 32 {
        return Err(format!(
            "sha256: expected 32 output bytes, got {}",
            outputs.len()
        ));
    }

    let mut lowered = LoweredBlackBox::default();

    // Step 1: Pack input bytes into 16 message words (W[0..15])
    // Each word is 4 big-endian bytes.
    let padded_len = (inputs.len() + 9).div_ceil(64) * 64; // SHA-256 padding
    let n_blocks = padded_len / 64;

    // For single-block messages (most common case):
    // Pad to 64 bytes, process one block.
    let mut message_bytes: Vec<Expr> = inputs.to_vec();

    // Add padding: 0x80, then zeros, then 64-bit big-endian length
    message_bytes.push(Expr::Const(FieldElement::from_i64(0x80)));
    while message_bytes.len() < padded_len - 8 {
        message_bytes.push(Expr::Const(FieldElement::from_i64(0)));
    }

    // Append message length in bits as 64-bit big-endian
    let bit_len = (inputs.len() * 8) as u64;
    for i in (0..8).rev() {
        let byte = ((bit_len >> (i * 8)) & 0xFF) as i64;
        message_bytes.push(Expr::Const(FieldElement::from_i64(byte)));
    }

    // Initialize hash values
    let mut h_values: Vec<String> = Vec::with_capacity(8);
    for (i, &h_init) in SHA256_H.iter().enumerate() {
        let name = lowered.add_private_signal(aux.next(&format!("h_init{i}")));
        lowered.add_equal(
            Expr::Signal(name.clone()),
            Expr::Const(FieldElement::from_i64(h_init as i64)),
            format!("sha256_h{i}_init"),
        );
        h_values.push(name);
    }

    // Process each 64-byte block
    for block_idx in 0..n_blocks {
        let block_start = block_idx * 64;
        let block_bytes = &message_bytes[block_start..block_start + 64];

        h_values = compress_block(
            &mut lowered,
            aux,
            block_bytes,
            &h_values,
            &format!("blk{block_idx}"),
        )?;
    }

    // Extract output bytes from final hash values
    // Each h_value is a 32-bit word → 4 big-endian bytes
    for (word_idx, h_signal) in h_values.iter().enumerate() {
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

            // Big-endian: byte 0 of word = bits[31..24]
            let bit_start = (3 - byte_idx) * 8;
            let byte_bits = &word_bits[bit_start..bit_start + 8];
            let byte_expr = bits::recompose_from_bits(byte_bits);

            lowered.add_equal(
                Expr::Signal(outputs[out_byte_idx].clone()),
                byte_expr,
                format!("sha256_out_byte{out_byte_idx}"),
            );
        }
    }

    Ok(lowered)
}

/// SHA-256 compression function for a single 64-byte block.
fn compress_block(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    block_bytes: &[Expr],
    h_in: &[String],
    prefix: &str,
) -> Result<Vec<String>, String> {
    // Step 1: Build message schedule W[0..63]
    // W[0..15] from block bytes (big-endian 32-bit words)
    let mut w_signals = Vec::with_capacity(64);

    for t in 0..16 {
        let byte_offset = t * 4;
        // Big-endian pack: word = b0*2^24 + b1*2^16 + b2*2^8 + b3
        let word_expr = Expr::Add(vec![
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_i64(1 << 24))),
                Box::new(block_bytes[byte_offset].clone()),
            ),
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_i64(1 << 16))),
                Box::new(block_bytes[byte_offset + 1].clone()),
            ),
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_i64(1 << 8))),
                Box::new(block_bytes[byte_offset + 2].clone()),
            ),
            block_bytes[byte_offset + 3].clone(),
        ]);

        let w_name = lowered.add_private_signal(aux.next(&format!("{prefix}_w{t}")));
        lowered.add_range(&w_name, 32, format!("{prefix}_w{t}_range"));
        lowered.add_equal(
            Expr::Signal(w_name.clone()),
            word_expr,
            format!("{prefix}_w{t}_pack"),
        );
        w_signals.push(w_name);
    }

    // W[16..63]: schedule expansion
    // W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16] mod 2^32
    for t in 16..64 {
        let s0 = sigma0(
            lowered,
            aux,
            &w_signals[t - 15],
            &format!("{prefix}_ws0_{t}"),
        )?;
        let s1 = sigma1(
            lowered,
            aux,
            &w_signals[t - 2],
            &format!("{prefix}_ws1_{t}"),
        )?;

        let w_name = bits::add_many_mod32(
            lowered,
            aux,
            vec![
                Expr::Signal(s1),
                Expr::Signal(w_signals[t - 7].clone()),
                Expr::Signal(s0),
                Expr::Signal(w_signals[t - 16].clone()),
            ],
            &format!("{prefix}_w{t}"),
        );

        w_signals.push(w_name);
    }

    // Step 2: Initialize working variables
    let mut a = h_in[0].clone();
    let mut b = h_in[1].clone();
    let mut c = h_in[2].clone();
    let mut d = h_in[3].clone();
    let mut e = h_in[4].clone();
    let mut f = h_in[5].clone();
    let mut g = h_in[6].clone();
    let mut h = h_in[7].clone();

    // Step 3: 64 compression rounds
    for t in 0..64 {
        let big_s1 = big_sigma1(lowered, aux, &e, &format!("{prefix}_S1_r{t}"))?;
        let ch_val = ch(lowered, aux, &e, &f, &g, &format!("{prefix}_ch_r{t}"))?;

        // T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
        let t1 = bits::add_many_mod32(
            lowered,
            aux,
            vec![
                Expr::Signal(h.clone()),
                Expr::Signal(big_s1),
                Expr::Signal(ch_val),
                Expr::Const(FieldElement::from_i64(SHA256_K[t] as i64)),
                Expr::Signal(w_signals[t].clone()),
            ],
            &format!("{prefix}_T1_r{t}"),
        );

        let big_s0 = big_sigma0(lowered, aux, &a, &format!("{prefix}_S0_r{t}"))?;
        let maj_val = maj(lowered, aux, &a, &b, &c, &format!("{prefix}_maj_r{t}"))?;

        // T2 = Sigma0(a) + Maj(a,b,c)
        let t2 = bits::add_mod32(
            lowered,
            aux,
            Expr::Signal(big_s0),
            Expr::Signal(maj_val),
            &format!("{prefix}_T2_r{t}"),
        );

        // Update working variables
        h = g;
        g = f;
        f = e;
        e = bits::add_mod32(
            lowered,
            aux,
            Expr::Signal(d.clone()),
            Expr::Signal(t1.clone()),
            &format!("{prefix}_e_r{t}"),
        );
        d = c;
        c = b;
        b = a;
        a = bits::add_mod32(
            lowered,
            aux,
            Expr::Signal(t1),
            Expr::Signal(t2),
            &format!("{prefix}_a_r{t}"),
        );
    }

    // Step 4: Compute new hash values
    let working = [a, b, c, d, e, f, g, h];
    let mut h_out = Vec::with_capacity(8);
    for (i, (w, h_prev)) in working.iter().zip(h_in.iter()).enumerate() {
        let new_h = bits::add_mod32(
            lowered,
            aux,
            Expr::Signal(h_prev.clone()),
            Expr::Signal(w.clone()),
            &format!("{prefix}_hout{i}"),
        );
        h_out.push(new_h);
    }

    Ok(h_out)
}

// ─── SHA-256 helper functions ───────────────────────────────────────────────

/// sigma0(x) = ROTR7(x) XOR ROTR18(x) XOR SHR3(x)
fn sigma0(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    x: &str,
    label: &str,
) -> Result<String, String> {
    let x_bits = bits::decompose_to_bits(lowered, aux, Expr::Signal(x.to_string()), 32, label);
    let r7 = bits::rotr(&x_bits, 7);
    let r18 = bits::rotr(&x_bits, 18);
    let sh3 = bits::shr_bit_exprs(&x_bits, 3);

    // XOR all three, bit by bit, then recompose
    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        let sh3_name = lowered.add_private_signal(aux.next(&format!("{label}_sh3b{i}")));
        lowered.add_boolean(&sh3_name, format!("{label}_sh3b{i}_bool"));
        lowered.add_equal(
            Expr::Signal(sh3_name.clone()),
            sh3[i].clone(),
            format!("{label}_sh3b{i}"),
        );

        let t = bits::xor_bits(lowered, aux, &r7[i], &r18[i], &format!("{label}_b{i}_a"));
        let r = bits::xor_bits(lowered, aux, &t, &sh3_name, &format!("{label}_b{i}_b"));
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

/// sigma1(x) = ROTR17(x) XOR ROTR19(x) XOR SHR10(x)
fn sigma1(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    x: &str,
    label: &str,
) -> Result<String, String> {
    let x_bits = bits::decompose_to_bits(lowered, aux, Expr::Signal(x.to_string()), 32, label);
    let r17 = bits::rotr(&x_bits, 17);
    let r19 = bits::rotr(&x_bits, 19);
    let sh10 = bits::shr_bit_exprs(&x_bits, 10);

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        let sh10_name = lowered.add_private_signal(aux.next(&format!("{label}_sh10b{i}")));
        lowered.add_boolean(&sh10_name, format!("{label}_sh10b{i}_bool"));
        lowered.add_equal(
            Expr::Signal(sh10_name.clone()),
            sh10[i].clone(),
            format!("{label}_sh10b{i}"),
        );

        let t = bits::xor_bits(lowered, aux, &r17[i], &r19[i], &format!("{label}_b{i}_a"));
        let r = bits::xor_bits(lowered, aux, &t, &sh10_name, &format!("{label}_b{i}_b"));
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

/// Sigma0(x) = ROTR2(x) XOR ROTR13(x) XOR ROTR22(x)
fn big_sigma0(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    x: &str,
    label: &str,
) -> Result<String, String> {
    let x_bits = bits::decompose_to_bits(lowered, aux, Expr::Signal(x.to_string()), 32, label);
    let r2 = bits::rotr(&x_bits, 2);
    let r13 = bits::rotr(&x_bits, 13);
    let r22 = bits::rotr(&x_bits, 22);

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        let r = bits::xor3_bits(
            lowered,
            aux,
            &r2[i],
            &r13[i],
            &r22[i],
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

/// Sigma1(x) = ROTR6(x) XOR ROTR11(x) XOR ROTR25(x)
fn big_sigma1(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    x: &str,
    label: &str,
) -> Result<String, String> {
    let x_bits = bits::decompose_to_bits(lowered, aux, Expr::Signal(x.to_string()), 32, label);
    let r6 = bits::rotr(&x_bits, 6);
    let r11 = bits::rotr(&x_bits, 11);
    let r25 = bits::rotr(&x_bits, 25);

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        let r = bits::xor3_bits(
            lowered,
            aux,
            &r6[i],
            &r11[i],
            &r25[i],
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

/// Ch(e, f, g) = (e AND f) XOR (NOT e AND g)
/// Per bit: ch = e*f + (1-e)*g = g + e*(f - g)
fn ch(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    e: &str,
    f: &str,
    g: &str,
    label: &str,
) -> Result<String, String> {
    let e_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(e.to_string()),
        32,
        &format!("{label}_e"),
    );
    let f_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(f.to_string()),
        32,
        &format!("{label}_f"),
    );
    let g_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(g.to_string()),
        32,
        &format!("{label}_g"),
    );

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        // ch_bit = g + e*(f - g)
        let ch_name = lowered.add_private_signal(aux.next(&format!("{label}_ch_b{i}")));
        lowered.add_boolean(&ch_name, format!("{label}_ch_b{i}_bool"));

        let f_minus_g = Expr::Sub(
            Box::new(Expr::Signal(f_bits[i].clone())),
            Box::new(Expr::Signal(g_bits[i].clone())),
        );
        let e_times_f_minus_g = Expr::Mul(
            Box::new(Expr::Signal(e_bits[i].clone())),
            Box::new(f_minus_g),
        );
        let ch_expr = Expr::Add(vec![Expr::Signal(g_bits[i].clone()), e_times_f_minus_g]);

        lowered.add_equal(
            Expr::Signal(ch_name.clone()),
            ch_expr,
            format!("{label}_ch_b{i}"),
        );
        result_bits.push(ch_name);
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

/// Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c)
/// Per bit: maj = ab + ac + bc - 2*abc
fn maj(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    c: &str,
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
    let c_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(c.to_string()),
        32,
        &format!("{label}_c"),
    );

    let mut result_bits = Vec::with_capacity(32);
    for i in 0..32 {
        let maj_name = lowered.add_private_signal(aux.next(&format!("{label}_maj_b{i}")));
        lowered.add_boolean(&maj_name, format!("{label}_maj_b{i}_bool"));

        // maj = ab + ac + bc - 2abc
        let ab = Expr::Mul(
            Box::new(Expr::Signal(a_bits[i].clone())),
            Box::new(Expr::Signal(b_bits[i].clone())),
        );
        let ac = Expr::Mul(
            Box::new(Expr::Signal(a_bits[i].clone())),
            Box::new(Expr::Signal(c_bits[i].clone())),
        );
        let bc = Expr::Mul(
            Box::new(Expr::Signal(b_bits[i].clone())),
            Box::new(Expr::Signal(c_bits[i].clone())),
        );
        let abc = Expr::Mul(
            Box::new(ab.clone()),
            Box::new(Expr::Signal(c_bits[i].clone())),
        );
        let two_abc = Expr::Mul(
            Box::new(Expr::Const(FieldElement::from_i64(2))),
            Box::new(abc),
        );
        let maj_expr = Expr::Sub(Box::new(Expr::Add(vec![ab, ac, bc])), Box::new(two_abc));

        lowered.add_equal(
            Expr::Signal(maj_name.clone()),
            maj_expr,
            format!("{label}_maj_b{i}"),
        );
        result_bits.push(maj_name);
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

pub fn compute_sha256_witness(
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    // Auxiliary witness values for SHA-256 (bit decompositions, intermediate
    // words, round variables) are computed by the backend's constraint solver
    // when it evaluates the Equal constraints that define them.
    Ok(())
}
