/// Poseidon2 permutation over Goldilocks, implemented as BN254 R1CS constraints.
///
/// Matches the exact round schedule, S-box (x^7), MDS matrices, and round
/// constants used by Plonky3's `Poseidon2Goldilocks<16>`.
///
/// The constants are regenerated from the same deterministic RNG seed that
/// Plonky3 uses, ensuring bit-for-bit consistency.
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_poseidon2::{ExternalLayerConstants, poseidon2_round_numbers_128};
use rand09::SeedableRng;
use rand09::rngs::SmallRng;

use super::nonnative_goldilocks::GoldilocksVar;

/// Width of the Poseidon2 permutation used by Plonky3 for Goldilocks.
pub const POSEIDON2_WIDTH: usize = 16;

/// The diagonal entries of the internal diffusion matrix (minus identity),
/// matching `MATRIX_DIAG_16_GOLDILOCKS` from p3-goldilocks.
pub const MATRIX_DIAG_16: [u64; 16] = [
    0xde9b91a467d6afc0,
    0xc5f16b9c76a9be17,
    0x0ab0fef2d540ac55,
    0x3001d27009d05773,
    0xed23b1f906d3d9eb,
    0x5ce73743cba97054,
    0x1c3bab944af4ba24,
    0x2faa105854dbafae,
    0x53ffb3ae6d421a10,
    0xbcda9df8884ba396,
    0xfc1273e4a31807bb,
    0xc77952573d5142c0,
    0x56683339a819b85e,
    0x328fcbd8f0ddc8eb,
    0xb5101e303fce9cb7,
    0x774487b8c40089bb,
];

/// Precomputed Poseidon2 round constants for a given seed.
///
/// Contains all external (initial + terminal) and internal round constants
/// as Goldilocks u64 values, ready for embedding into BN254 R1CS.
#[derive(Clone, Debug)]
pub struct Poseidon2Constants {
    /// External initial round constants: rounds_f/2 arrays of WIDTH elements.
    pub external_initial: Vec<[u64; POSEIDON2_WIDTH]>,
    /// External terminal round constants: rounds_f/2 arrays of WIDTH elements.
    pub external_terminal: Vec<[u64; POSEIDON2_WIDTH]>,
    /// Internal round constants: one per internal round.
    pub internal: Vec<u64>,
    /// Number of external rounds (total, split half/half).
    pub rounds_f: usize,
    /// Number of internal rounds.
    pub rounds_p: usize,
}

impl Poseidon2Constants {
    /// Generate Poseidon2 constants for the given seed, matching Plonky3's
    /// `Poseidon2Goldilocks::<16>::new_from_rng_128(&mut SmallRng::seed_from_u64(seed))`.
    pub fn from_seed(seed: u64) -> Self {
        let (rounds_f, rounds_p) = poseidon2_round_numbers_128::<Goldilocks>(POSEIDON2_WIDTH, 7)
            .expect("Goldilocks Poseidon2 round numbers should be available");

        let mut rng = SmallRng::seed_from_u64(seed);

        // Generate external constants (same RNG sequence as p3-poseidon2)
        let ext_consts: ExternalLayerConstants<Goldilocks, POSEIDON2_WIDTH> =
            ExternalLayerConstants::new_from_rng(rounds_f, &mut rng);

        // Convert to u64 arrays
        let external_initial: Vec<[u64; POSEIDON2_WIDTH]> = ext_consts
            .get_initial_constants()
            .iter()
            .map(|arr| arr.map(|g| g.as_canonical_u64()))
            .collect();
        let external_terminal: Vec<[u64; POSEIDON2_WIDTH]> = ext_consts
            .get_terminal_constants()
            .iter()
            .map(|arr| arr.map(|g| g.as_canonical_u64()))
            .collect();

        // Generate internal constants (same RNG sequence as p3-poseidon2)
        use rand09::Rng;
        let internal: Vec<u64> = (0..rounds_p)
            .map(|_| {
                let g: Goldilocks = rng.random();
                g.as_canonical_u64()
            })
            .collect();

        Self {
            external_initial,
            external_terminal,
            internal,
            rounds_f,
            rounds_p,
        }
    }
}

/// Poseidon2 permutation gadget operating on `POSEIDON2_WIDTH` GoldilocksVar elements.
pub struct Poseidon2GoldilocksGadget {
    pub constants: Poseidon2Constants,
}

impl Poseidon2GoldilocksGadget {
    pub fn new(seed: u64) -> Self {
        Self {
            constants: Poseidon2Constants::from_seed(seed),
        }
    }

    /// Apply the full Poseidon2 permutation to a state of WIDTH GoldilocksVar elements.
    pub fn permute(
        &self,
        cs: ConstraintSystemRef<Fr>,
        state: &mut [GoldilocksVar; POSEIDON2_WIDTH],
    ) -> Result<(), SynthesisError> {
        // Initial external linear layer
        self.external_mds(cs.clone(), state)?;

        // Initial external rounds
        for round_consts in &self.constants.external_initial {
            self.external_round(cs.clone(), state, round_consts)?;
        }

        // Internal rounds
        for rc in &self.constants.internal {
            self.internal_round(cs.clone(), state, *rc)?;
        }

        // Terminal external rounds
        for round_consts in &self.constants.external_terminal {
            self.external_round(cs.clone(), state, round_consts)?;
        }

        Ok(())
    }

    /// Hash two Goldilocks elements using Poseidon2 sponge (rate=8, capacity=8).
    ///
    /// This matches Plonky3's `PaddingFreeSponge<Poseidon2Goldilocks<16>, 16, 8, 8>`:
    /// - State width = 16
    /// - Rate = 8 (absorb into state[0..8])
    /// - Capacity = 8 (state[8..16] stays zero initially)
    /// - Squeeze 8 elements from state[0..8]
    ///
    /// For hashing two elements, we place them in the first two rate positions
    /// and zero-pad the rest, then permute once and extract.
    pub fn hash_two(
        &self,
        cs: ConstraintSystemRef<Fr>,
        a: &GoldilocksVar,
        b: &GoldilocksVar,
    ) -> Result<GoldilocksVar, SynthesisError> {
        let mut state: [GoldilocksVar; POSEIDON2_WIDTH] = std::array::from_fn(|i| {
            if i == 0 {
                a.clone()
            } else if i == 1 {
                b.clone()
            } else {
                GoldilocksVar::constant(cs.clone(), 0).unwrap()
            }
        });

        self.permute(cs, &mut state)?;

        // Return the first element as the hash output
        Ok(state[0].clone())
    }

    /// Compress two 8-element Goldilocks digests into one, matching Plonky3's
    /// `TruncatedPermutation<Poseidon2Goldilocks<16>, 2, 8, 16>`.
    ///
    /// Concatenates left || right into a 16-element state, permutes, returns first 8.
    pub fn compress_two(
        &self,
        cs: ConstraintSystemRef<Fr>,
        left: &[GoldilocksVar; 8],
        right: &[GoldilocksVar; 8],
    ) -> Result<[GoldilocksVar; 8], SynthesisError> {
        let mut state: [GoldilocksVar; POSEIDON2_WIDTH] = std::array::from_fn(|i| {
            if i < 8 {
                left[i].clone()
            } else {
                right[i - 8].clone()
            }
        });
        self.permute(cs, &mut state)?;
        Ok(std::array::from_fn(|i| state[i].clone()))
    }

    /// Hash leaf data into an 8-element digest, matching Plonky3's
    /// `PaddingFreeSponge<Poseidon2Goldilocks<16>, 16, 8, 8>`.
    ///
    /// Uses sponge construction: absorbs RATE=8 elements at a time.
    /// Matches Plonky3's exact semantics: partial final chunks do NOT zero
    /// the remaining rate positions (they retain values from previous permutation).
    pub fn hash_leaf(
        &self,
        cs: ConstraintSystemRef<Fr>,
        data: &[GoldilocksVar],
    ) -> Result<[GoldilocksVar; 8], SynthesisError> {
        const RATE: usize = 8;
        let mut state: [GoldilocksVar; POSEIDON2_WIDTH] =
            std::array::from_fn(|_| GoldilocksVar::constant(cs.clone(), 0).unwrap());
        let mut iter = data.iter();
        'outer: loop {
            for i in 0..RATE {
                if let Some(elem) = iter.next() {
                    state[i] = elem.clone();
                } else {
                    if i != 0 {
                        self.permute(cs.clone(), &mut state)?;
                    }
                    break 'outer;
                }
            }
            self.permute(cs.clone(), &mut state)?;
        }
        Ok(std::array::from_fn(|i| state[i].clone()))
    }

    /// External round: add round constants, apply S-box to all elements, then MDS.
    fn external_round(
        &self,
        cs: ConstraintSystemRef<Fr>,
        state: &mut [GoldilocksVar; POSEIDON2_WIDTH],
        round_consts: &[u64; POSEIDON2_WIDTH],
    ) -> Result<(), SynthesisError> {
        // Add round constants and apply S-box (x^7)
        for i in 0..POSEIDON2_WIDTH {
            let rc = GoldilocksVar::constant(cs.clone(), round_consts[i])?;
            state[i] = state[i].add(cs.clone(), &rc)?;
            state[i] = state[i].sbox7(cs.clone())?;
        }

        // External linear layer (MDSMat4-based)
        self.external_mds(cs, state)?;

        Ok(())
    }

    /// Internal round: add round constant to state[0], apply S-box to state[0], internal diffusion.
    fn internal_round(
        &self,
        cs: ConstraintSystemRef<Fr>,
        state: &mut [GoldilocksVar; POSEIDON2_WIDTH],
        rc: u64,
    ) -> Result<(), SynthesisError> {
        // Add round constant and S-box only to state[0]
        let rc_var = GoldilocksVar::constant(cs.clone(), rc)?;
        state[0] = state[0].add(cs.clone(), &rc_var)?;
        state[0] = state[0].sbox7(cs.clone())?;

        // Internal diffusion: state[i] = state[i] * diag[i] + sum(state)
        self.internal_diffusion(cs, state)?;

        Ok(())
    }

    /// External MDS: apply the circulant [2,3,1,1] 4x4 matrix to each chunk of 4,
    /// then add the sum of each position mod 4 across chunks.
    ///
    /// This matches `mds_light_permutation` with `MDSMat4` for WIDTH=16.
    fn external_mds(
        &self,
        cs: ConstraintSystemRef<Fr>,
        state: &mut [GoldilocksVar; POSEIDON2_WIDTH],
    ) -> Result<(), SynthesisError> {
        // Step 1: Apply circulant [2,3,1,1] to each group of 4
        for chunk_start in (0..POSEIDON2_WIDTH).step_by(4) {
            let s0 = state[chunk_start].clone();
            let s1 = state[chunk_start + 1].clone();
            let s2 = state[chunk_start + 2].clone();
            let s3 = state[chunk_start + 3].clone();

            // t01 = s0 + s1
            let t01 = s0.add(cs.clone(), &s1)?;
            // t23 = s2 + s3
            let t23 = s2.add(cs.clone(), &s3)?;
            // t0123 = t01 + t23
            let t0123 = t01.add(cs.clone(), &t23)?;
            // t01123 = t0123 + s1
            let t01123 = t0123.add(cs.clone(), &s1)?;
            // t01233 = t0123 + s3
            let t01233 = t0123.add(cs.clone(), &s3)?;

            // new[0] = t01123 + t01 = 2*s0 + 3*s1 + s2 + s3
            state[chunk_start] = t01123.add(cs.clone(), &t01)?;
            // new[1] = t01123 + 2*s2 = s0 + 2*s1 + 3*s2 + s3
            let s2_2 = s2.add(cs.clone(), &s2)?;
            state[chunk_start + 1] = t01123.add(cs.clone(), &s2_2)?;

            // new[2] = t01233 + t23 = s0 + s1 + 2*s2 + 3*s3
            // new[3] = t01233 + 2*s0 = 3*s0 + s1 + s2 + 2*s3
            let s0_2 = s0.add(cs.clone(), &s0)?;
            state[chunk_start + 3] = t01233.add(cs.clone(), &s0_2)?;
            state[chunk_start + 2] = t01233.add(cs.clone(), &t23)?;
        }

        // Step 2: For each position mod 4, compute the sum across all chunks
        let mut sums: [GoldilocksVar; 4] = std::array::from_fn(|k| state[k].clone());
        for chunk_start in (4..POSEIDON2_WIDTH).step_by(4) {
            for k in 0..4 {
                sums[k] = sums[k].add(cs.clone(), &state[chunk_start + k])?;
            }
        }

        // Step 3: Add the sum to each element
        for i in 0..POSEIDON2_WIDTH {
            state[i] = state[i].add(cs.clone(), &sums[i % 4])?;
        }

        Ok(())
    }

    /// Internal diffusion: matmul_internal with diagonal matrix.
    /// state[i] = state[i] * diag[i] + sum(state)
    fn internal_diffusion(
        &self,
        cs: ConstraintSystemRef<Fr>,
        state: &mut [GoldilocksVar; POSEIDON2_WIDTH],
    ) -> Result<(), SynthesisError> {
        // Compute sum of all state elements
        let mut sum = state[0].clone();
        for value in state.iter().take(POSEIDON2_WIDTH).skip(1) {
            sum = sum.add(cs.clone(), value)?;
        }

        // state[i] = state[i] * diag[i] + sum
        for i in 0..POSEIDON2_WIDTH {
            let diag = GoldilocksVar::constant(cs.clone(), MATRIX_DIAG_16[i])?;
            let scaled = state[i].mul(cs.clone(), &diag)?;
            state[i] = scaled.add(cs.clone(), &sum)?;
        }

        Ok(())
    }
}

/// Compute Poseidon2 permutation of two Goldilocks u64 values natively,
/// returning the full 16-word output state.
///
/// Uses the actual p3-goldilocks `Poseidon2Goldilocks<16>` permutation to
/// ensure exact consistency with Plonky3's Merkle trees.
pub fn poseidon2_goldilocks_native_full(seed: u64, a: u64, b: u64) -> [u64; POSEIDON2_WIDTH] {
    use p3_goldilocks::Poseidon2Goldilocks;
    use p3_symmetric::Permutation;

    let mut rng = SmallRng::seed_from_u64(seed);
    let perm = Poseidon2Goldilocks::<POSEIDON2_WIDTH>::new_from_rng_128(&mut rng);

    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    state[0] = Goldilocks::from_u64(a);
    state[1] = Goldilocks::from_u64(b);

    perm.permute_mut(&mut state);

    std::array::from_fn(|i| state[i].as_canonical_u64())
}

/// Compute Poseidon2 hash of two Goldilocks u64 values natively (no R1CS).
/// Returns only state[0] (the standard sponge output).
pub fn poseidon2_goldilocks_native(seed: u64, a: u64, b: u64) -> u64 {
    poseidon2_goldilocks_native_full(seed, a, b)[0]
}

/// Compress two 8-element digests natively, matching Plonky3's TruncatedPermutation.
pub fn compress_two_native(seed: u64, left: &[u64; 8], right: &[u64; 8]) -> [u64; 8] {
    use p3_goldilocks::Poseidon2Goldilocks;
    use p3_symmetric::Permutation;

    let mut rng = SmallRng::seed_from_u64(seed);
    let perm = Poseidon2Goldilocks::<POSEIDON2_WIDTH>::new_from_rng_128(&mut rng);

    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    for i in 0..8 {
        state[i] = Goldilocks::from_u64(left[i]);
        state[i + 8] = Goldilocks::from_u64(right[i]);
    }
    perm.permute_mut(&mut state);
    std::array::from_fn(|i| state[i].as_canonical_u64())
}

/// Hash leaf data natively into an 8-element digest, matching Plonky3's PaddingFreeSponge.
/// Uses sponge construction: absorbs RATE=8 elements at a time.
/// Matches Plonky3's exact semantics for partial final chunks.
pub fn hash_leaf_native(seed: u64, data: &[u64]) -> [u64; 8] {
    use p3_goldilocks::Poseidon2Goldilocks;
    use p3_symmetric::Permutation;

    const RATE: usize = 8;
    let mut rng = SmallRng::seed_from_u64(seed);
    let perm = Poseidon2Goldilocks::<POSEIDON2_WIDTH>::new_from_rng_128(&mut rng);

    let mut state = [Goldilocks::ZERO; POSEIDON2_WIDTH];
    let mut iter = data.iter();
    'outer: loop {
        for i in 0..RATE {
            if let Some(&v) = iter.next() {
                state[i] = Goldilocks::from_u64(v);
            } else {
                if i != 0 {
                    perm.permute_mut(&mut state);
                }
                break 'outer;
            }
        }
        perm.permute_mut(&mut state);
    }
    std::array::from_fn(|i| state[i].as_canonical_u64())
}

/// Compute Merkle root natively using 8-element digests over Goldilocks.
pub fn merkle_root_8_native(
    seed: u64,
    leaf_hash: &[u64; 8],
    siblings: &[[u64; 8]],
    direction_bits: &[bool],
) -> [u64; 8] {
    assert_eq!(siblings.len(), direction_bits.len());
    let mut current = *leaf_hash;
    for (sib, &dir) in siblings.iter().zip(direction_bits.iter()) {
        let (left, right) = if dir {
            (sib, &current)
        } else {
            (&current, sib)
        };
        current = compress_two_native(seed, left, right);
    }
    current
}

/// Compute Merkle root natively using Poseidon2 over Goldilocks.
pub fn merkle_root_poseidon2_native(
    seed: u64,
    leaf: u64,
    siblings: &[u64],
    direction_bits: &[bool],
) -> u64 {
    assert_eq!(siblings.len(), direction_bits.len());
    let mut current = leaf;
    for (&sib, &dir) in siblings.iter().zip(direction_bits.iter()) {
        let (left, right) = if dir { (sib, current) } else { (current, sib) };
        current = poseidon2_goldilocks_native(seed, left, right);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn fresh_cs() -> ConstraintSystemRef<Fr> {
        ConstraintSystem::<Fr>::new_ref()
    }

    #[test]
    fn poseidon2_constants_are_deterministic() {
        let c1 = Poseidon2Constants::from_seed(42);
        let c2 = Poseidon2Constants::from_seed(42);
        assert_eq!(c1.external_initial, c2.external_initial);
        assert_eq!(c1.external_terminal, c2.external_terminal);
        assert_eq!(c1.internal, c2.internal);
        assert_eq!(c1.rounds_f, c2.rounds_f);
        assert_eq!(c1.rounds_p, c2.rounds_p);
    }

    #[test]
    fn poseidon2_constants_differ_for_different_seeds() {
        let c1 = Poseidon2Constants::from_seed(1);
        let c2 = Poseidon2Constants::from_seed(2);
        assert_ne!(c1.external_initial, c2.external_initial);
    }

    #[test]
    fn poseidon2_native_is_deterministic() {
        let h1 = poseidon2_goldilocks_native(42, 1, 2);
        let h2 = poseidon2_goldilocks_native(42, 1, 2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon2_native_differs_for_different_inputs() {
        let h1 = poseidon2_goldilocks_native(42, 1, 2);
        let h2 = poseidon2_goldilocks_native(42, 2, 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon2_gadget_matches_native() {
        let seed = 42u64;
        let a_val = 12345u64;
        let b_val = 67890u64;

        // Native computation
        let native_result = poseidon2_goldilocks_native(seed, a_val, b_val);

        // R1CS computation
        let cs = fresh_cs();
        let gadget = Poseidon2GoldilocksGadget::new(seed);
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(a_val)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(b_val)).unwrap();
        let result = gadget.hash_two(cs.clone(), &a, &b).unwrap();

        assert_eq!(
            result.value(),
            Some(native_result),
            "R1CS Poseidon2 must match native computation"
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "Poseidon2 R1CS constraints must be satisfied"
        );

        let num_constraints = cs.num_constraints();
        println!("Poseidon2 hash_two: {num_constraints} constraints");
    }

    /// Golden vector test: hardcoded expected output for Poseidon2Goldilocks<16>
    /// with seed=42, input=[12345, 67890, 0, ..., 0].
    ///
    /// Captured from p3-goldilocks v0.4.2. This test does NOT depend on Plonky3
    /// at runtime for the expected values — it catches drift in both upstream
    /// (if we upgrade p3 crates) and our gadget (if we refactor internals).
    ///
    /// Three safety nets:
    ///   1. Native p3 output matches golden u64 values (catches upstream drift)
    ///   2. R1CS gadget output matches golden u64 values (catches our drift)
    ///   3. Serialized LE bytes match golden bytes (catches canonicalization /
    ///      endianness bugs in the proof-parsing ↔ R1CS embedding pipeline)
    #[test]
    fn poseidon2_golden_vector() {
        use super::super::nonnative_goldilocks::GOLDILOCKS_PRIME;
        use ark_bn254::Fr;
        use ark_serialize::CanonicalSerialize;

        // Expected full 16-word state after Poseidon2 permutation.
        // Source: p3-goldilocks 0.4.2, Poseidon2Goldilocks::<16>::new_from_rng_128
        //         with SmallRng::seed_from_u64(42), input = [12345, 67890, 0×14].
        const EXPECTED: [u64; 16] = [
            0xdcfb2f7d8d417b5b, // state[0]
            0x6876895bf9575193, // state[1]
            0x90bd412a43f20077, // state[2]
            0x074f4e474e56c486, // state[3]
            0x1f83bf002930935b, // state[4]
            0x75c3419055d75624, // state[5]
            0x2f63a8055d62f0b3, // state[6]
            0xf3dd5e4ba55f7e63, // state[7]
            0x9c72c243250cf50e, // state[8]
            0x206df890ef41a718, // state[9]
            0xbd7f02f242e585b7, // state[10]
            0x3e1249b7c2a0a12e, // state[11]
            0xc59030e61bfe32bb, // state[12]
            0x47f2231a2b674637, // state[13]
            0x112a64e1d2c5aea4, // state[14]
            0xa02dd5cfce1ceaf5, // state[15]
        ];

        // Expected serialized form: 16 lanes × 8 bytes each, little-endian.
        // This is the exact byte representation the wrapper uses when parsing
        // proof bytes (Goldilocks canonical u64 → LE bytes) and when extracting
        // values from R1CS witnesses (Fr → serialize_compressed → LE bytes → u64).
        #[rustfmt::skip]
        const EXPECTED_LE_BYTES: [u8; 128] = [
            0x5b, 0x7b, 0x41, 0x8d, 0x7d, 0x2f, 0xfb, 0xdc, // state[0]
            0x93, 0x51, 0x57, 0xf9, 0x5b, 0x89, 0x76, 0x68, // state[1]
            0x77, 0x00, 0xf2, 0x43, 0x2a, 0x41, 0xbd, 0x90, // state[2]
            0x86, 0xc4, 0x56, 0x4e, 0x47, 0x4e, 0x4f, 0x07, // state[3]
            0x5b, 0x93, 0x30, 0x29, 0x00, 0xbf, 0x83, 0x1f, // state[4]
            0x24, 0x56, 0xd7, 0x55, 0x90, 0x41, 0xc3, 0x75, // state[5]
            0xb3, 0xf0, 0x62, 0x5d, 0x05, 0xa8, 0x63, 0x2f, // state[6]
            0x63, 0x7e, 0x5f, 0xa5, 0x4b, 0x5e, 0xdd, 0xf3, // state[7]
            0x0e, 0xf5, 0x0c, 0x25, 0x43, 0xc2, 0x72, 0x9c, // state[8]
            0x18, 0xa7, 0x41, 0xef, 0x90, 0xf8, 0x6d, 0x20, // state[9]
            0xb7, 0x85, 0xe5, 0x42, 0xf2, 0x02, 0x7f, 0xbd, // state[10]
            0x2e, 0xa1, 0xa0, 0xc2, 0xb7, 0x49, 0x12, 0x3e, // state[11]
            0xbb, 0x32, 0xfe, 0x1b, 0xe6, 0x30, 0x90, 0xc5, // state[12]
            0x37, 0x46, 0x67, 0x2b, 0x1a, 0x23, 0xf2, 0x47, // state[13]
            0xa4, 0xae, 0xc5, 0xd2, 0xe1, 0x64, 0x2a, 0x11, // state[14]
            0xf5, 0xea, 0x1c, 0xce, 0xcf, 0xd5, 0x2d, 0xa0, // state[15]
        ];

        // ---- Safety net 1: native p3 output matches golden u64 values ----
        let native = poseidon2_goldilocks_native_full(42, 12345, 67890);
        assert_eq!(
            native, EXPECTED,
            "native Poseidon2 output drifted from golden vector \
             (p3-goldilocks upgrade or RNG change?)"
        );

        // ---- Safety net 2: R1CS gadget matches golden u64 values ----
        let cs = fresh_cs();
        let gadget = Poseidon2GoldilocksGadget::new(42);
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(12345)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(67890)).unwrap();
        let result = gadget.hash_two(cs.clone(), &a, &b).unwrap();

        assert_eq!(
            result.value().unwrap(),
            EXPECTED[0],
            "R1CS gadget output drifted from golden vector"
        );
        assert!(cs.is_satisfied().unwrap());

        // ---- Safety net 3: serialization round-trip matches golden bytes ----
        // This catches endianness/canonicalization bugs between:
        //   proof parsing (as_canonical_u64 → u64)
        //     ↔ R1CS embedding (u64 → Fr::from → BN254 witness)
        //     ↔ R1CS extraction (Fr → serialize_compressed → LE bytes → u64)
        for (i, &expected_u64) in EXPECTED.iter().enumerate() {
            // Verify u64 → LE bytes matches golden bytes
            let le_bytes = expected_u64.to_le_bytes();
            assert_eq!(
                le_bytes,
                EXPECTED_LE_BYTES[i * 8..(i + 1) * 8],
                "LE byte encoding mismatch at state[{i}]"
            );

            // Verify the full round-trip:
            //   u64 → Fr::from → serialize_compressed → from_le_bytes → u64
            // This is the exact path used in the wrapper pipeline.
            let fr = Fr::from(expected_u64);
            let mut ser_buf = [0u8; 32];
            fr.serialize_compressed(&mut ser_buf[..]).unwrap();
            let recovered = u64::from_le_bytes(ser_buf[..8].try_into().unwrap());
            assert_eq!(
                recovered, expected_u64,
                "Fr round-trip broke canonical form at state[{i}]: \
                 0x{expected_u64:016x} → Fr → serialize → 0x{recovered:016x}"
            );

            // Verify high bytes are zero (Goldilocks fits in 64 bits)
            assert!(
                ser_buf[8..].iter().all(|&b| b == 0),
                "Goldilocks value at state[{i}] has non-zero high bytes in Fr \
                 serialization — embedding assumption violated"
            );

            // Verify the value is in canonical Goldilocks range
            assert!(
                expected_u64 < GOLDILOCKS_PRIME,
                "Golden vector state[{i}] = 0x{expected_u64:016x} >= GOLDILOCKS_PRIME"
            );
        }
    }

    #[test]
    fn compress_two_gadget_matches_native() {
        let seed = 42u64;
        let left: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let right: [u64; 8] = [9, 10, 11, 12, 13, 14, 15, 16];

        let native_result = compress_two_native(seed, &left, &right);

        let cs = fresh_cs();
        let gadget = Poseidon2GoldilocksGadget::new(seed);
        let left_vars: [GoldilocksVar; 8] = std::array::from_fn(|i| {
            GoldilocksVar::alloc_witness(cs.clone(), Some(left[i])).unwrap()
        });
        let right_vars: [GoldilocksVar; 8] = std::array::from_fn(|i| {
            GoldilocksVar::alloc_witness(cs.clone(), Some(right[i])).unwrap()
        });
        let result = gadget
            .compress_two(cs.clone(), &left_vars, &right_vars)
            .unwrap();

        for i in 0..8 {
            assert_eq!(
                result[i].value().unwrap(),
                native_result[i],
                "compress_two mismatch at index {i}"
            );
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn hash_leaf_gadget_matches_native() {
        let seed = 42u64;
        let data: Vec<u64> = vec![100, 200, 300];

        let native_result = hash_leaf_native(seed, &data);

        let cs = fresh_cs();
        let gadget = Poseidon2GoldilocksGadget::new(seed);
        let data_vars: Vec<GoldilocksVar> = data
            .iter()
            .map(|&v| GoldilocksVar::alloc_witness(cs.clone(), Some(v)).unwrap())
            .collect();
        let result = gadget.hash_leaf(cs.clone(), &data_vars).unwrap();

        for i in 0..8 {
            assert_eq!(
                result[i].value().unwrap(),
                native_result[i],
                "hash_leaf mismatch at index {i}"
            );
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn external_mds_matches_reference() {
        // Verify external_mds against the reference MDSMat4 circulant [2,3,1,1].
        // For a single 4-element chunk [a, b, c, d], the outputs should be:
        //   [2a+3b+c+d, a+2b+3c+d, a+b+2c+3d, 3a+b+c+2d]
        let cs = fresh_cs();
        let gadget = Poseidon2GoldilocksGadget::new(42);

        // Use simple input: state = [1, 2, 3, 4, 0, 0, ..., 0]
        let mut state: [GoldilocksVar; POSEIDON2_WIDTH] = std::array::from_fn(|i| {
            let val = if i < 4 { (i + 1) as u64 } else { 0 };
            GoldilocksVar::alloc_witness(cs.clone(), Some(val)).unwrap()
        });
        gadget.external_mds(cs.clone(), &mut state).unwrap();

        // For chunk [1,2,3,4]:
        // new[0] = 2*1 + 3*2 + 3 + 4 = 15
        // new[1] = 1 + 2*2 + 3*3 + 4 = 18
        // new[2] = 1 + 2 + 2*3 + 3*4 = 21
        // new[3] = 3*1 + 2 + 3 + 2*4 = 16
        // After step 2 (sum across chunks), since other chunks are [0,0,0,0],
        // sums = [15, 18, 21, 16]
        // After step 3 (add sums), state[0..4] = [15+15, 18+18, 21+21, 16+16] = [30, 36, 42, 32]
        assert_eq!(state[0].value().unwrap(), 30);
        assert_eq!(state[1].value().unwrap(), 36);
        assert_eq!(state[2].value().unwrap(), 42);
        assert_eq!(state[3].value().unwrap(), 32);

        // Verify all-zero chunks remain zero (sums contribution only)
        for i in 4..POSEIDON2_WIDTH {
            let expected = [15u64, 18, 21, 16][i % 4];
            assert_eq!(
                state[i].value().unwrap(),
                expected,
                "state[{i}] should equal sums[{mod4}] = {expected}",
                mod4 = i % 4
            );
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn merkle_root_native_depth_2() {
        let seed = 42u64;
        let leaf = 100u64;
        let siblings = [200u64, 300u64];
        let dirs = [false, true];

        let root = merkle_root_poseidon2_native(seed, leaf, &siblings, &dirs);
        assert_ne!(root, 0, "Merkle root should be non-zero");

        // Verify determinism
        let root2 = merkle_root_poseidon2_native(seed, leaf, &siblings, &dirs);
        assert_eq!(root, root2);
    }
}
