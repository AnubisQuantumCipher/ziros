//! Hardware-accelerated SHA-256 using ARM FEAT_SHA256 intrinsics.
//!
//! Uses `SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1` instructions which
//! process 4 rounds per instruction pair (vs 64 scalar rounds).
//! Falls back to pure-Rust implementation on non-aarch64 targets.

use crate::detect::CryptoExtensions;

/// SHA-256 initial hash values (FIPS 180-4 §5.3.3).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-256 hash of `data`, returning 32 bytes.
/// Uses hardware acceleration when available, otherwise pure-Rust.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    if crate::is_enabled() && CryptoExtensions::detect().sha256 {
        sha256_hw(data)
    } else {
        sha256_sw(data)
    }
}

/// Batch SHA-256: hash `n` messages, each `msg_len` bytes.
/// `data` must be exactly `n * msg_len` bytes.
/// Returns `n * 32` bytes of digests.
pub fn batch_sha256(data: &[u8], msg_len: usize) -> Vec<u8> {
    if msg_len == 0 {
        let empty_hash = sha256(&[]);
        let n = if data.is_empty() { 1 } else { data.len() };
        return std::iter::repeat_n(empty_hash, n)
            .flat_map(|h| h.into_iter())
            .collect();
    }
    let n = data.len() / msg_len;
    let mut result = Vec::with_capacity(n * 32);
    for i in 0..n {
        let chunk = &data[i * msg_len..(i + 1) * msg_len];
        result.extend_from_slice(&sha256(chunk));
    }
    result
}

// ─── Hardware path (aarch64 with FEAT_SHA256) ───────────────────────────

#[cfg(target_arch = "aarch64")]
fn sha256_hw(data: &[u8]) -> [u8; 32] {
    use core::arch::aarch64::*;

    let padded = sha256_pad(data);

    unsafe {
        // Load initial hash state into NEON registers
        // ABCD = [A, B, C, D], EFGH = [E, F, G, H]
        let mut abcd = vld1q_u32(H_INIT.as_ptr());
        let mut efgh = vld1q_u32(H_INIT.as_ptr().add(4));

        for block in padded.chunks_exact(64) {
            let abcd_save = abcd;
            let efgh_save = efgh;

            // Load message block (big-endian u32 words)
            let mut w: [uint32x4_t; 4] = [
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr()))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32)))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48)))),
            ];

            // Rounds 0-3
            let mut tmp = vaddq_u32(w[0], vld1q_u32(K.as_ptr()));
            let mut tmp2 = abcd;
            abcd = vsha256hq_u32(abcd, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, tmp2, tmp);
            w[0] = vsha256su1q_u32(vsha256su0q_u32(w[0], w[1]), w[2], w[3]);

            // Rounds 4-7
            tmp = vaddq_u32(w[1], vld1q_u32(K.as_ptr().add(4)));
            tmp2 = abcd;
            abcd = vsha256hq_u32(abcd, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, tmp2, tmp);
            w[1] = vsha256su1q_u32(vsha256su0q_u32(w[1], w[2]), w[3], w[0]);

            // Rounds 8-11
            tmp = vaddq_u32(w[2], vld1q_u32(K.as_ptr().add(8)));
            tmp2 = abcd;
            abcd = vsha256hq_u32(abcd, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, tmp2, tmp);
            w[2] = vsha256su1q_u32(vsha256su0q_u32(w[2], w[3]), w[0], w[1]);

            // Rounds 12-15
            tmp = vaddq_u32(w[3], vld1q_u32(K.as_ptr().add(12)));
            tmp2 = abcd;
            abcd = vsha256hq_u32(abcd, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, tmp2, tmp);
            w[3] = vsha256su1q_u32(vsha256su0q_u32(w[3], w[0]), w[1], w[2]);

            // Rounds 16-63 (same pattern, unrolled in groups of 4)
            for round_group in 4..16 {
                let wi = round_group % 4;
                let k_ptr = K.as_ptr().add(round_group * 4);
                tmp = vaddq_u32(w[wi], vld1q_u32(k_ptr));
                tmp2 = abcd;
                abcd = vsha256hq_u32(abcd, efgh, tmp);
                efgh = vsha256h2q_u32(efgh, tmp2, tmp);
                if round_group < 15 {
                    w[wi] = vsha256su1q_u32(
                        vsha256su0q_u32(w[wi], w[(wi + 1) % 4]),
                        w[(wi + 2) % 4],
                        w[(wi + 3) % 4],
                    );
                }
            }

            // Add saved state
            abcd = vaddq_u32(abcd, abcd_save);
            efgh = vaddq_u32(efgh, efgh_save);
        }

        // Extract hash as big-endian bytes
        let mut result = [0u8; 32];
        let abcd_be = vrev32q_u8(vreinterpretq_u8_u32(abcd));
        let efgh_be = vrev32q_u8(vreinterpretq_u8_u32(efgh));
        vst1q_u8(result.as_mut_ptr(), abcd_be);
        vst1q_u8(result.as_mut_ptr().add(16), efgh_be);

        // The hardware stores words in register order, but we need big-endian
        // word order. Re-extract properly.
        let mut hash = [0u32; 8];
        vst1q_u32(hash.as_mut_ptr(), abcd);
        vst1q_u32(hash.as_mut_ptr().add(4), efgh);
        for (i, word) in hash.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        result
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn sha256_hw(data: &[u8]) -> [u8; 32] {
    sha256_sw(data)
}

// ─── Software fallback ──────────────────────────────────────────────────

fn sha256_sw(data: &[u8]) -> [u8; 32] {
    let padded = sha256_pad(data);
    let mut h = H_INIT;

    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                block[t * 4],
                block[t * 4 + 1],
                block[t * 4 + 2],
                block[t * 4 + 3],
            ]);
        }
        for t in 16..64 {
            w[t] = small_sigma1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(small_sigma0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for t in 0..64 {
            let t1 = hh
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    result
}

fn sha256_pad(data: &[u8]) -> Vec<u8> {
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    padded
}

#[inline(always)]
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}

#[inline(always)]
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        let hash = sha256(&[]);
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn sw_matches_known() {
        let hash = sha256_sw(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn batch_sha256_works() {
        let data = [0u8; 64]; // two 32-byte messages
        let result = batch_sha256(&data, 32);
        assert_eq!(result.len(), 64); // two 32-byte hashes
        assert_eq!(&result[..32], &result[32..]); // identical inputs → identical hashes
    }
}
