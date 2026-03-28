//! Keccak-256 as arithmetic constraints.
//!
//! Keccak uses 64-bit lanes and operates on a 5x5 state matrix.
//! Each round applies: theta, rho, pi, chi, iota.
//! All operations are bitwise (XOR, AND, NOT, ROTR) which we express
//! as field arithmetic over boolean signals.
//!
//! Cost: ~150,000 R1CS constraints per Keccak-256 call (very expensive
//! in R1CS; better suited for STARK/PLONK with lookup tables).

use super::bits;
use super::{AuxCounter, LoweredBlackBox};
use num_bigint::BigInt;
use std::collections::BTreeMap;
use zkf_core::{Expr, FieldElement, FieldId, ZkfResult};

const KECCAK_ROUNDS: usize = 24;

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTATIONS: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

pub fn lower_keccak256(
    inputs: &[Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    aux: &mut AuxCounter,
) -> Result<LoweredBlackBox, String> {
    if outputs.len() != 32 {
        return Err(format!(
            "keccak256: expected 32 output bytes, got {}",
            outputs.len()
        ));
    }

    let mut lowered = LoweredBlackBox::default();

    // Initialize 5x5 state of 64-bit lanes (all zeros)
    let mut state: Vec<Vec<String>> = Vec::with_capacity(5);
    for x in 0..5 {
        let mut row = Vec::with_capacity(5);
        for y in 0..5 {
            let name = lowered.add_private_signal(aux.next(&format!("st_{x}_{y}")));
            lowered.add_equal(
                Expr::Signal(name.clone()),
                Expr::Const(FieldElement::from_i64(0)),
                format!("keccak_init_{x}_{y}"),
            );
            row.push(name);
        }
        state.push(row);
    }

    // Absorb input (rate = 136 bytes = 17 lanes for Keccak-256)
    let rate_bytes = 136;
    let rate_lanes = rate_bytes / 8;

    // Pad input (Keccak pad10*1)
    let mut padded = Vec::new();
    for input in inputs {
        padded.push(input.clone());
    }
    padded.push(Expr::Const(FieldElement::from_i64(0x01))); // domain separation
    while (padded.len() % rate_bytes) != rate_bytes - 1 {
        padded.push(Expr::Const(FieldElement::from_i64(0)));
    }
    padded.push(Expr::Const(FieldElement::from_i64(0x80))); // final padding bit

    let n_blocks = padded.len() / rate_bytes;

    for block_idx in 0..n_blocks {
        let block_start = block_idx * rate_bytes;

        // XOR block into state (absorb)
        for lane_idx in 0..rate_lanes {
            let x = lane_idx % 5;
            let y = lane_idx / 5;
            let byte_offset = block_start + lane_idx * 8;

            // Pack 8 little-endian bytes into a 64-bit lane
            let mut lane_terms = Vec::with_capacity(8);
            for b in 0..8 {
                if byte_offset + b < padded.len() {
                    lane_terms.push(Expr::Mul(
                        Box::new(Expr::Const(FieldElement::from_i64(1i64 << (b * 8)))),
                        Box::new(padded[byte_offset + b].clone()),
                    ));
                }
            }

            if !lane_terms.is_empty() {
                let lane_value = Expr::Add(lane_terms);
                let xored =
                    lowered.add_private_signal(aux.next(&format!("abs_{block_idx}_{x}_{y}")));

                // XOR via bit decomposition would be very expensive for 64-bit lanes.
                // Instead, for the absorb phase where the state starts at zero (first block)
                // or we need full XOR, we add the lane value directly (since XOR with 0 = identity).
                // For subsequent blocks, we need proper 64-bit XOR which is 64 * 2 constraints.
                if block_idx == 0 {
                    // State is zero, XOR = identity
                    lowered.add_equal(
                        Expr::Signal(xored.clone()),
                        lane_value,
                        format!("keccak_absorb_{block_idx}_{x}_{y}"),
                    );
                } else {
                    // Full 64-bit XOR needed
                    let s_bits = bits::decompose_to_bits(
                        &mut lowered,
                        aux,
                        Expr::Signal(state[x][y].clone()),
                        64,
                        &format!("abs_s_{block_idx}_{x}_{y}"),
                    );

                    let lane_sig = lowered
                        .add_private_signal(aux.next(&format!("abs_lane_{block_idx}_{x}_{y}")));
                    lowered.add_equal(
                        Expr::Signal(lane_sig.clone()),
                        lane_value,
                        format!("keccak_lane_{block_idx}_{x}_{y}"),
                    );

                    let l_bits = bits::decompose_to_bits(
                        &mut lowered,
                        aux,
                        Expr::Signal(lane_sig),
                        64,
                        &format!("abs_l_{block_idx}_{x}_{y}"),
                    );

                    let mut xor_bits = Vec::with_capacity(64);
                    for bit in 0..64 {
                        let r = bits::xor_bits(
                            &mut lowered,
                            aux,
                            &s_bits[bit],
                            &l_bits[bit],
                            &format!("abs_xor_{block_idx}_{x}_{y}_b{bit}"),
                        );
                        xor_bits.push(r);
                    }

                    let xor_expr = bits::recompose_from_bits(&xor_bits);
                    lowered.add_equal(
                        Expr::Signal(xored.clone()),
                        xor_expr,
                        format!("keccak_absorb_{block_idx}_{x}_{y}"),
                    );
                }

                state[x][y] = xored;
            }
        }

        // Apply Keccak-f[1600] permutation (24 rounds)
        for (round, rc) in RC.iter().copied().enumerate().take(KECCAK_ROUNDS) {
            state = keccak_round(
                &mut lowered,
                aux,
                &state,
                rc,
                &format!("blk{block_idx}_r{round}"),
            )?;
        }
    }

    // Squeeze: extract 32 bytes (4 lanes) from state
    for (byte_idx, output_name) in outputs.iter().enumerate().take(32) {
        let lane_idx = byte_idx / 8;
        let byte_in_lane = byte_idx % 8;
        let x = lane_idx % 5;
        let y = lane_idx / 5;

        let lane_bits = bits::decompose_to_bits(
            &mut lowered,
            aux,
            Expr::Signal(state[x][y].clone()),
            64,
            &format!("squeeze_{x}_{y}_{byte_idx}"),
        );

        let bit_start = byte_in_lane * 8;
        let byte_bits = &lane_bits[bit_start..bit_start + 8];
        let byte_expr = bits::recompose_from_bits(byte_bits);

        lowered.add_equal(
            Expr::Signal(output_name.clone()),
            byte_expr,
            format!("keccak_out_byte{byte_idx}"),
        );
    }

    Ok(lowered)
}

#[allow(clippy::needless_range_loop)]
fn keccak_round(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    state: &[Vec<String>],
    rc: u64,
    prefix: &str,
) -> Result<Vec<Vec<String>>, String> {
    // Theta: C[x] = state[x][0] XOR ... XOR state[x][4]
    //        D[x] = C[x-1] XOR ROT(C[x+1], 1)
    //        state[x][y] ^= D[x]
    let mut c_bits: Vec<Vec<String>> = Vec::with_capacity(5);
    for x in 0..5 {
        let mut col_bits: Vec<String> = bits::decompose_to_bits(
            lowered,
            aux,
            Expr::Signal(state[x][0].clone()),
            64,
            &format!("{prefix}_theta_c{x}_0"),
        );
        for y in 1..5 {
            let y_bits = bits::decompose_to_bits(
                lowered,
                aux,
                Expr::Signal(state[x][y].clone()),
                64,
                &format!("{prefix}_theta_c{x}_{y}"),
            );
            let mut new_bits = Vec::with_capacity(64);
            for bit in 0..64 {
                let r = bits::xor_bits(
                    lowered,
                    aux,
                    &col_bits[bit],
                    &y_bits[bit],
                    &format!("{prefix}_theta_c{x}_{y}_b{bit}"),
                );
                new_bits.push(r);
            }
            col_bits = new_bits;
        }
        c_bits.push(col_bits);
    }

    // D[x] = C[(x+4)%5] XOR ROT(C[(x+1)%5], 1)
    let mut new_state: Vec<Vec<String>> = (0..5).map(|_| Vec::with_capacity(5)).collect();

    for x in 0..5 {
        let c_prev = &c_bits[(x + 4) % 5];
        let c_next_rotated = bits::rotr(&c_bits[(x + 1) % 5], 63); // ROT left by 1 = ROTR by 63

        let mut d_bits = Vec::with_capacity(64);
        for bit in 0..64 {
            let r = bits::xor_bits(
                lowered,
                aux,
                &c_prev[bit],
                &c_next_rotated[bit],
                &format!("{prefix}_theta_d{x}_b{bit}"),
            );
            d_bits.push(r);
        }

        for y in 0..5 {
            let s_bits = bits::decompose_to_bits(
                lowered,
                aux,
                Expr::Signal(state[x][y].clone()),
                64,
                &format!("{prefix}_theta_s{x}_{y}"),
            );

            let mut xor_bits_vec = Vec::with_capacity(64);
            for bit in 0..64 {
                let r = bits::xor_bits(
                    lowered,
                    aux,
                    &s_bits[bit],
                    &d_bits[bit],
                    &format!("{prefix}_theta_xd_{x}_{y}_b{bit}"),
                );
                xor_bits_vec.push(r);
            }

            // Rho: rotate by ROTATIONS[x][y]
            let rot_amount = ROTATIONS[x][y] as usize;
            let rho_bits = if rot_amount > 0 {
                bits::rotr(&xor_bits_vec, 64 - rot_amount) // ROT left = ROTR by (64 - amount)
            } else {
                xor_bits_vec
            };

            // Pi: state'[y][(2*x + 3*y) % 5] = rho result
            let new_x = y;
            let new_y = (2 * x + 3 * y) % 5;

            let result_expr = bits::recompose_from_bits(&rho_bits);
            let result =
                lowered.add_private_signal(aux.next(&format!("{prefix}_rp_{new_x}_{new_y}")));
            lowered.add_equal(
                Expr::Signal(result.clone()),
                result_expr,
                format!("{prefix}_rhopi_{new_x}_{new_y}"),
            );

            new_state[new_x].push(result);
        }
    }

    // Chi: state[x][y] = state[x][y] XOR (NOT state[(x+1)%5][y] AND state[(x+2)%5][y])
    let mut chi_state: Vec<Vec<String>> = (0..5).map(|_| Vec::with_capacity(5)).collect();

    for x in 0..5 {
        for y in 0..5 {
            let a_bits = bits::decompose_to_bits(
                lowered,
                aux,
                Expr::Signal(new_state[x][y].clone()),
                64,
                &format!("{prefix}_chi_a_{x}_{y}"),
            );
            let b_bits = bits::decompose_to_bits(
                lowered,
                aux,
                Expr::Signal(new_state[(x + 1) % 5][y].clone()),
                64,
                &format!("{prefix}_chi_b_{x}_{y}"),
            );
            let c_bits_local = bits::decompose_to_bits(
                lowered,
                aux,
                Expr::Signal(new_state[(x + 2) % 5][y].clone()),
                64,
                &format!("{prefix}_chi_c_{x}_{y}"),
            );

            let mut chi_bits = Vec::with_capacity(64);
            for bit in 0..64 {
                // NOT b AND c
                let not_b = bits::not_bit(
                    lowered,
                    aux,
                    &b_bits[bit],
                    &format!("{prefix}_chi_nb_{x}_{y}_b{bit}"),
                );
                let not_b_and_c = bits::and_bits(
                    lowered,
                    aux,
                    &not_b,
                    &c_bits_local[bit],
                    &format!("{prefix}_chi_nbc_{x}_{y}_b{bit}"),
                );
                // a XOR (NOT b AND c)
                let r = bits::xor_bits(
                    lowered,
                    aux,
                    &a_bits[bit],
                    &not_b_and_c,
                    &format!("{prefix}_chi_{x}_{y}_b{bit}"),
                );
                chi_bits.push(r);
            }

            let result_expr = bits::recompose_from_bits(&chi_bits);
            let result = lowered.add_private_signal(aux.next(&format!("{prefix}_chi_{x}_{y}")));
            lowered.add_equal(
                Expr::Signal(result.clone()),
                result_expr,
                format!("{prefix}_chi_{x}_{y}"),
            );

            chi_state[x].push(result);
        }
    }

    // Iota: state[0][0] ^= RC
    let rc_bits = (0..64).map(|i| (rc >> i) & 1 == 1).collect::<Vec<_>>();
    let s00_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(chi_state[0][0].clone()),
        64,
        &format!("{prefix}_iota"),
    );

    let mut iota_bits = Vec::with_capacity(64);
    for bit in 0..64 {
        if rc_bits[bit] {
            let r = bits::not_bit(
                lowered,
                aux,
                &s00_bits[bit],
                &format!("{prefix}_iota_b{bit}"),
            );
            // XOR with 1 = NOT — wait, this is wrong for XOR with RC bits.
            // NOT gives 1-x, but we want x XOR 1 which IS 1-x for booleans. OK, correct.
            iota_bits.push(r);
        } else {
            iota_bits.push(s00_bits[bit].clone());
        }
    }

    let iota_expr = bits::recompose_from_bits(&iota_bits);
    let iota_result = lowered.add_private_signal(aux.next(&format!("{prefix}_iota_00")));
    lowered.add_equal(
        Expr::Signal(iota_result.clone()),
        iota_expr,
        format!("{prefix}_iota_00"),
    );
    chi_state[0][0] = iota_result;

    Ok(chi_state)
}

pub fn compute_keccak256_witness(
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    Ok(())
}
