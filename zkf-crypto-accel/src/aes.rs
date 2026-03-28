//! Hardware-accelerated AES using ARM FEAT_AES intrinsics.
//!
//! Uses `AESE`/`AESD`/`AESMC`/`AESIMC` instructions for AES-128/256
//! operations. Useful for PRNG (AES-CTR) and optional AES-based S-boxes.

use crate::detect::CryptoExtensions;

/// AES-128 encrypt a single 16-byte block with the given 11 round keys.
pub fn aes128_encrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    if crate::is_enabled() && CryptoExtensions::detect().aes {
        aes128_encrypt_hw(block, round_keys)
    } else {
        aes128_encrypt_sw(block, round_keys)
    }
}

/// AES-CTR PRNG: generate `n` bytes of pseudorandom output from a 16-byte key
/// and 16-byte nonce/counter.
pub fn aes_ctr_prng(key: &[u8; 16], nonce: &[u8; 16], n: usize) -> Vec<u8> {
    let round_keys = aes128_key_expand(key);
    let mut result = Vec::with_capacity(n);
    let mut counter = u128::from_le_bytes(*nonce);

    while result.len() < n {
        let block_in: [u8; 16] = counter.to_le_bytes();
        let block_out = aes128_encrypt_block(&block_in, &round_keys);
        let remaining = n - result.len();
        let take = remaining.min(16);
        result.extend_from_slice(&block_out[..take]);
        counter = counter.wrapping_add(1);
    }

    result
}

// ─── Hardware path ──────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
fn aes128_encrypt_hw(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    use core::arch::aarch64::*;

    unsafe {
        let mut state = vld1q_u8(block.as_ptr());

        // Rounds 0..9: AESE + AESMC
        for rk_bytes in round_keys.iter().take(9) {
            let rk = vld1q_u8(rk_bytes.as_ptr());
            state = vaeseq_u8(state, rk);
            state = vaesmcq_u8(state);
        }

        // Final round: AESE only (no MixColumns)
        let rk9 = vld1q_u8(round_keys[9].as_ptr());
        state = vaeseq_u8(state, rk9);

        // XOR with last round key
        let rk10 = vld1q_u8(round_keys[10].as_ptr());
        state = veorq_u8(state, rk10);

        let mut result = [0u8; 16];
        vst1q_u8(result.as_mut_ptr(), state);
        result
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn aes128_encrypt_hw(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    aes128_encrypt_sw(block, round_keys)
}

// ─── Software fallback ──────────────────────────────────────────────────

fn aes128_encrypt_sw(block: &[u8; 16], round_keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = *block;

    // AddRoundKey(state, round_keys[0])
    xor_block(&mut state, &round_keys[0]);

    // Rounds 1..9
    for round_key in round_keys.iter().take(10).skip(1) {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        xor_block(&mut state, round_key);
    }

    // Final round (no MixColumns)
    sub_bytes(&mut state);
    shift_rows(&mut state);
    xor_block(&mut state, &round_keys[10]);

    state
}

/// AES-128 key expansion: generate 11 round keys from 16-byte key.
pub fn aes128_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut round_keys = [[0u8; 16]; 11];
    round_keys[0] = *key;

    for i in 1..11 {
        let prev = round_keys[i - 1];
        let mut temp = [prev[12], prev[13], prev[14], prev[15]];

        // RotWord + SubWord + Rcon
        temp.rotate_left(1);
        for b in &mut temp {
            *b = SBOX[*b as usize];
        }
        temp[0] ^= rcon[i - 1];

        for j in 0..4 {
            for k in 0..4 {
                round_keys[i][j * 4 + k] = prev[j * 4 + k] ^ temp[k];
            }
            temp = [
                round_keys[i][j * 4],
                round_keys[i][j * 4 + 1],
                round_keys[i][j * 4 + 2],
                round_keys[i][j * 4 + 3],
            ];
        }
    }

    round_keys
}

fn xor_block(state: &mut [u8; 16], key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let t = *state;
    // Row 0: no shift
    // Row 1: shift left 1
    state[1] = t[5];
    state[5] = t[9];
    state[9] = t[13];
    state[13] = t[1];
    // Row 2: shift left 2
    state[2] = t[10];
    state[6] = t[14];
    state[10] = t[2];
    state[14] = t[6];
    // Row 3: shift left 3
    state[3] = t[15];
    state[7] = t[3];
    state[11] = t[7];
    state[15] = t[11];
}

fn mix_columns(state: &mut [u8; 16]) {
    for i in 0..4 {
        let s0 = state[4 * i];
        let s1 = state[4 * i + 1];
        let s2 = state[4 * i + 2];
        let s3 = state[4 * i + 3];
        let t = s0 ^ s1 ^ s2 ^ s3;
        state[4 * i] = s0 ^ xtime(s0 ^ s1) ^ t;
        state[4 * i + 1] = s1 ^ xtime(s1 ^ s2) ^ t;
        state[4 * i + 2] = s2 ^ xtime(s2 ^ s3) ^ t;
        state[4 * i + 3] = s3 ^ xtime(s3 ^ s0) ^ t;
    }
}

fn xtime(x: u8) -> u8 {
    let shifted = (x as u16) << 1;
    (shifted ^ if shifted & 0x100 != 0 { 0x11b } else { 0 }) as u8
}

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_nist_test_vector() {
        // NIST FIPS 197 Appendix B test vector
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];

        let round_keys = aes128_key_expand(&key);
        let ciphertext = aes128_encrypt_block(&plaintext, &round_keys);
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn aes_ctr_deterministic() {
        let key = [0u8; 16];
        let nonce = [0u8; 16];
        let output1 = aes_ctr_prng(&key, &nonce, 64);
        let output2 = aes_ctr_prng(&key, &nonce, 64);
        assert_eq!(output1, output2);
        assert_eq!(output1.len(), 64);
    }
}
