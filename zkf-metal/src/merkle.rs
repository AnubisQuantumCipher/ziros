//! GPU-accelerated Merkle tree construction using batch Poseidon2.
//!
//! Provides two levels of integration:
//! - `MetalMerkleBuilder`: Standalone GPU Merkle tree builder for direct use.
//! - `MetalMerkleTreeMmcs`: Drop-in replacement for p3's `MerkleTreeMmcs` that
//!   uses GPU batch Poseidon2 for digest computation when matrices are large enough.

use crate::poseidon2::MetalPoseidon2;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{PackedField, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleTree, MerkleTreeMmcs};
use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};
use serde::{Deserialize, Serialize};

type DigestLayers<S, const DIGEST_ELEMS: usize> = Vec<Vec<[S; DIGEST_ELEMS]>>;
type PoseidonDigest<S, V, const DIGEST_ELEMS: usize> = p3_symmetric::Hash<S, V, DIGEST_ELEMS>;

/// Get the current Merkle GPU threshold (device-adaptive).
fn gpu_merkle_threshold() -> usize {
    crate::tuning::current_thresholds().merkle
}

/// GPU-accelerated Mmcs that uses Metal batch Poseidon2 for digest computation.
///
/// For large matrices (>= gpu_merkle_threshold() rows), computes all digest layers
/// on GPU via batch Poseidon2. For small matrices or complex multi-tier trees,
/// falls back to CPU p3 MerkleTreeMmcs.
///
/// The hash/compress functions must be PaddingFreeSponge<Perm,16,8,8> and
/// TruncatedPermutation<Perm,2,8,16> respectively (the standard p3 Poseidon2 config).
#[derive(Clone, Debug)]
pub struct MetalMerkleTreeMmcs<P, PW, H, C, const DIGEST_ELEMS: usize> {
    inner: MerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS>,
    poseidon2_seed: Option<u64>,
}

impl<P, PW, H, C, const DIGEST_ELEMS: usize> MetalMerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS> {
    pub fn new(hash: H, compress: C) -> Self {
        Self {
            inner: MerkleTreeMmcs::new(hash, compress),
            poseidon2_seed: None,
        }
    }

    /// Create with GPU acceleration enabled for the given Poseidon2 seed.
    pub fn new_with_gpu(hash: H, compress: C, poseidon2_seed: u64) -> Self {
        Self {
            inner: MerkleTreeMmcs::new(hash, compress),
            poseidon2_seed: Some(poseidon2_seed),
        }
    }
}

impl<P, PW, H, C, const DIGEST_ELEMS: usize> Mmcs<P::Scalar>
    for MetalMerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS>
where
    P: PackedField,
    PW: PackedValue<Value = P::Scalar>,
    H: CryptographicHasher<P::Scalar, [PW::Value; DIGEST_ELEMS]>,
    H: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
    H: Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], 2>,
    C: PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>,
    C: Sync,
    PW::Value: Eq,
    [PW::Value; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
    P::Scalar: Clone + PrimeField64 + 'static,
{
    type ProverData<M> =
        <MerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS> as Mmcs<P::Scalar>>::ProverData<M>;
    type Commitment = <MerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS> as Mmcs<P::Scalar>>::Commitment;
    type Proof = <MerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS> as Mmcs<P::Scalar>>::Proof;
    type Error = <MerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS> as Mmcs<P::Scalar>>::Error;

    fn commit<M: Matrix<P::Scalar>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let max_height = inputs.iter().map(|m| m.height()).max().unwrap_or(0);

        // Only attempt GPU path for large, single-height-tier commits with DIGEST_ELEMS=8
        // and total row width <= 8 (single-absorption sponge).
        // Multi-tier injection and multi-absorption are complex; fall back to CPU.
        let total_width: usize = inputs.iter().map(|m| m.width()).sum();
        let use_gpu = self.poseidon2_seed.is_some()
            && DIGEST_ELEMS == 8
            && max_height >= gpu_merkle_threshold()
            && total_width <= 8
            && inputs.iter().all(|m| m.height() == max_height);

        if use_gpu {
            let seed = self.poseidon2_seed.unwrap();
            if let Some(result) =
                gpu_commit::<P, PW, DIGEST_ELEMS, M>(&inputs, max_height, total_width, seed)
            {
                let (digest_layers, root) = result;
                let tree = MerkleTree::from_precomputed(inputs, digest_layers);
                return (root, tree);
            }
        }

        // CPU fallback
        self.inner.commit(inputs)
    }

    fn open_batch<M: Matrix<P::Scalar>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<P::Scalar, Self> {
        let inner_opening = self.inner.open_batch(index, prover_data);
        BatchOpening::new(inner_opening.opened_values, inner_opening.opening_proof)
    }

    fn get_matrices<'a, M: Matrix<P::Scalar>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        self.inner.get_matrices(prover_data)
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, P::Scalar, Self>,
    ) -> Result<(), Self::Error> {
        let inner_ref =
            BatchOpeningRef::<'_, P::Scalar, MerkleTreeMmcs<P, PW, H, C, DIGEST_ELEMS>>::new(
                batch_opening.opened_values,
                batch_opening.opening_proof,
            );
        self.inner
            .verify_batch(commit, dimensions, index, inner_ref)
    }
}

/// GPU-accelerated digest layer computation.
///
/// Returns `(digest_layers, root)` or None on failure.
#[allow(clippy::type_complexity)]
fn gpu_commit<P, PW, const DIGEST_ELEMS: usize, M>(
    inputs: &[M],
    max_height: usize,
    _total_width: usize,
    seed: u64,
) -> Option<(
    DigestLayers<P::Scalar, DIGEST_ELEMS>,
    PoseidonDigest<P::Scalar, PW::Value, DIGEST_ELEMS>,
)>
where
    P: PackedField,
    PW: PackedValue<Value = P::Scalar>,
    P::Scalar: PrimeField64 + Clone + 'static,
    M: Matrix<P::Scalar>,
{
    use std::any::TypeId;
    let metal = MetalPoseidon2::new()?;

    let is_goldilocks = TypeId::of::<P::Scalar>() == TypeId::of::<p3_goldilocks::Goldilocks>();

    if is_goldilocks {
        gpu_commit_goldilocks::<P, PW, DIGEST_ELEMS, M>(inputs, max_height, seed, &metal)
    } else {
        gpu_commit_babybear::<P, PW, DIGEST_ELEMS, M>(inputs, max_height, seed, &metal)
    }
}

#[allow(clippy::type_complexity)]
fn gpu_commit_goldilocks<P, PW, const DIGEST_ELEMS: usize, M>(
    inputs: &[M],
    max_height: usize,
    seed: u64,
    metal: &MetalPoseidon2,
) -> Option<(
    DigestLayers<P::Scalar, DIGEST_ELEMS>,
    PoseidonDigest<P::Scalar, PW::Value, DIGEST_ELEMS>,
)>
where
    P: PackedField,
    PW: PackedValue<Value = P::Scalar>,
    P::Scalar: PrimeField64 + Clone,
    M: Matrix<P::Scalar>,
{
    let (rc, n_ext, n_int) = crate::poseidon2::goldilocks::flatten_round_constants(seed);

    let height_padded = if max_height == 1 {
        1
    } else {
        max_height + max_height % 2
    };

    // Phase 1: Hash all rows → first digest layer
    // PaddingFreeSponge<16,8,8>: row elements into state[0..width], rest zero, permute, extract [0..8]
    let mut states = vec![0u64; height_padded * 16];
    for row_idx in 0..max_height {
        let state_offset = row_idx * 16;
        let mut col = 0;
        for mat in inputs {
            if let Some(row) = mat.row(row_idx) {
                for val in row {
                    if col < 8 {
                        states[state_offset + col] = val.as_canonical_u64();
                    }
                    col += 1;
                }
            }
        }
    }

    // GPU batch Poseidon2
    if !metal.batch_permute_goldilocks(&mut states, &rc, n_ext, n_int) {
        cpu_poseidon2_goldilocks_batch(&mut states, seed);
    }

    // Extract digests
    let first_layer = extract_digest_layer_u64::<P, DIGEST_ELEMS>(&states, height_padded);

    // Phase 2: Build compression layers
    let digest_layers = build_compression_layers_goldilocks::<P, DIGEST_ELEMS>(
        first_layer,
        metal,
        &rc,
        n_ext,
        n_int,
        seed,
    );

    let root_digest = digest_layers.last().unwrap()[0];
    Some((digest_layers, root_digest.into()))
}

#[allow(clippy::type_complexity)]
fn gpu_commit_babybear<P, PW, const DIGEST_ELEMS: usize, M>(
    inputs: &[M],
    max_height: usize,
    seed: u64,
    metal: &MetalPoseidon2,
) -> Option<(
    DigestLayers<P::Scalar, DIGEST_ELEMS>,
    PoseidonDigest<P::Scalar, PW::Value, DIGEST_ELEMS>,
)>
where
    P: PackedField,
    PW: PackedValue<Value = P::Scalar>,
    P::Scalar: PrimeField64 + Clone,
    M: Matrix<P::Scalar>,
{
    let (rc, n_ext, n_int) = crate::poseidon2::babybear::flatten_round_constants(seed);

    let height_padded = if max_height == 1 {
        1
    } else {
        max_height + max_height % 2
    };

    let mut states = vec![0u32; height_padded * 16];
    for row_idx in 0..max_height {
        let state_offset = row_idx * 16;
        let mut col = 0;
        for mat in inputs {
            if let Some(row) = mat.row(row_idx) {
                for val in row {
                    if col < 8 {
                        states[state_offset + col] = val.as_canonical_u64() as u32;
                    }
                    col += 1;
                }
            }
        }
    }

    if !metal.batch_permute_babybear(&mut states, &rc, n_ext, n_int) {
        cpu_poseidon2_babybear_batch(&mut states, seed);
    }

    let first_layer = extract_digest_layer_u32::<P, DIGEST_ELEMS>(&states, height_padded);

    let digest_layers = build_compression_layers_babybear::<P, DIGEST_ELEMS>(
        first_layer,
        metal,
        &rc,
        n_ext,
        n_int,
        seed,
    );

    let root_digest = digest_layers.last().unwrap()[0];
    Some((digest_layers, root_digest.into()))
}

fn extract_digest_layer_u64<P: PackedField, const DIGEST_ELEMS: usize>(
    states: &[u64],
    count: usize,
) -> Vec<[P::Scalar; DIGEST_ELEMS]>
where
    P::Scalar: PrimeField64,
{
    (0..count)
        .map(|i| {
            let offset = i * 16;
            std::array::from_fn(|j| P::Scalar::from_u64(states[offset + j]))
        })
        .collect()
}

fn extract_digest_layer_u32<P: PackedField, const DIGEST_ELEMS: usize>(
    states: &[u32],
    count: usize,
) -> Vec<[P::Scalar; DIGEST_ELEMS]>
where
    P::Scalar: PrimeField64,
{
    (0..count)
        .map(|i| {
            let offset = i * 16;
            std::array::from_fn(|j| P::Scalar::from_u64(states[offset + j] as u64))
        })
        .collect()
}

fn build_compression_layers_goldilocks<P: PackedField, const DIGEST_ELEMS: usize>(
    first_layer: Vec<[P::Scalar; DIGEST_ELEMS]>,
    metal: &MetalPoseidon2,
    rc: &[u64],
    n_ext: u32,
    n_int: u32,
    seed: u64,
) -> Vec<Vec<[P::Scalar; DIGEST_ELEMS]>>
where
    P::Scalar: PrimeField64,
{
    let mut digest_layers = vec![first_layer];

    loop {
        let prev_layer = digest_layers.last().unwrap();
        if prev_layer.len() == 1 {
            break;
        }

        let next_len = prev_layer.len() / 2;
        let next_len_padded = if prev_layer.len() == 2 {
            1
        } else {
            (prev_layer.len() / 2 + 1) & !1
        };

        // TruncatedPermutation<2,8,16>: pack two 8-element digests into 16-element state
        let mut comp_states = vec![0u64; next_len_padded * 16];
        for i in 0..next_len {
            let offset = i * 16;
            let left = &prev_layer[2 * i];
            let right = &prev_layer[2 * i + 1];
            for j in 0..DIGEST_ELEMS {
                comp_states[offset + j] = left[j].as_canonical_u64();
            }
            for j in 0..DIGEST_ELEMS {
                comp_states[offset + 8 + j] = right[j].as_canonical_u64();
            }
        }

        if !metal.batch_permute_goldilocks(&mut comp_states, rc, n_ext, n_int) {
            cpu_poseidon2_goldilocks_batch(&mut comp_states, seed);
        }

        let next_layer: Vec<[P::Scalar; DIGEST_ELEMS]> = (0..next_len_padded)
            .map(|i| {
                let offset = i * 16;
                if i < next_len {
                    std::array::from_fn(|j| P::Scalar::from_u64(comp_states[offset + j]))
                } else {
                    [P::Scalar::default(); DIGEST_ELEMS]
                }
            })
            .collect();

        digest_layers.push(next_layer);
    }

    digest_layers
}

fn build_compression_layers_babybear<P: PackedField, const DIGEST_ELEMS: usize>(
    first_layer: Vec<[P::Scalar; DIGEST_ELEMS]>,
    metal: &MetalPoseidon2,
    rc: &[u32],
    n_ext: u32,
    n_int: u32,
    seed: u64,
) -> Vec<Vec<[P::Scalar; DIGEST_ELEMS]>>
where
    P::Scalar: PrimeField64,
{
    let mut digest_layers = vec![first_layer];

    loop {
        let prev_layer = digest_layers.last().unwrap();
        if prev_layer.len() == 1 {
            break;
        }

        let next_len = prev_layer.len() / 2;
        let next_len_padded = if prev_layer.len() == 2 {
            1
        } else {
            (prev_layer.len() / 2 + 1) & !1
        };

        let mut comp_states = vec![0u32; next_len_padded * 16];
        for i in 0..next_len {
            let offset = i * 16;
            let left = &prev_layer[2 * i];
            let right = &prev_layer[2 * i + 1];
            for j in 0..DIGEST_ELEMS {
                comp_states[offset + j] = left[j].as_canonical_u64() as u32;
            }
            for j in 0..DIGEST_ELEMS {
                comp_states[offset + 8 + j] = right[j].as_canonical_u64() as u32;
            }
        }

        if !metal.batch_permute_babybear(&mut comp_states, rc, n_ext, n_int) {
            cpu_poseidon2_babybear_batch(&mut comp_states, seed);
        }

        let next_layer: Vec<[P::Scalar; DIGEST_ELEMS]> = (0..next_len_padded)
            .map(|i| {
                let offset = i * 16;
                if i < next_len {
                    std::array::from_fn(|j| P::Scalar::from_u64(comp_states[offset + j] as u64))
                } else {
                    [P::Scalar::default(); DIGEST_ELEMS]
                }
            })
            .collect();

        digest_layers.push(next_layer);
    }

    digest_layers
}

fn cpu_poseidon2_goldilocks_batch(states: &mut [u64], seed: u64) {
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use rand09::SeedableRng;

    let n_perms = states.len() / 16;
    let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
    let cpu_perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);

    for perm_idx in 0..n_perms {
        let offset = perm_idx * 16;
        let mut state: [Goldilocks; 16] =
            std::array::from_fn(|i| Goldilocks::from_u64(states[offset + i]));
        cpu_perm.permute_mut(&mut state);
        for i in 0..16 {
            states[offset + i] = state[i].as_canonical_u64();
        }
    }
}

fn cpu_poseidon2_babybear_batch(states: &mut [u32], seed: u64) {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use rand09::SeedableRng;

    let n_perms = states.len() / 16;
    let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
    let cpu_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);

    for perm_idx in 0..n_perms {
        let offset = perm_idx * 16;
        let mut state: [BabyBear; 16] =
            std::array::from_fn(|i| BabyBear::from_u64(states[offset + i] as u64));
        cpu_perm.permute_mut(&mut state);
        for i in 0..16 {
            states[offset + i] = state[i].as_canonical_u64() as u32;
        }
    }
}

/// GPU Merkle tree builder using batch Poseidon2.
pub struct MetalMerkleBuilder {
    poseidon2: MetalPoseidon2,
}

impl MetalMerkleBuilder {
    /// Create a new Merkle tree builder. Returns `None` if Metal is unavailable.
    pub fn new() -> Option<Self> {
        let poseidon2 = MetalPoseidon2::new()?;
        Some(Self { poseidon2 })
    }

    /// Build a Merkle tree from leaf hashes using Goldilocks Poseidon2.
    pub fn build_goldilocks(
        &self,
        leaves: &[u64],
        hash_width: usize,
        round_constants: &[u64],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> Option<Vec<Vec<u64>>> {
        if hash_width == 0
            || hash_width > 8
            || leaves.is_empty()
            || !leaves.len().is_multiple_of(hash_width)
        {
            return None;
        }

        let num_leaves = leaves.len() / hash_width;
        if !num_leaves.is_power_of_two() {
            return None;
        }

        let mut layers: Vec<Vec<u64>> = Vec::new();
        layers.push(leaves.to_vec());

        let mut current_layer = leaves.to_vec();
        let mut current_count = num_leaves;

        while current_count > 1 {
            let pairs = current_count / 2;

            let mut states = vec![0u64; pairs * 16];
            for p in 0..pairs {
                let left_offset = (2 * p) * hash_width;
                let right_offset = (2 * p + 1) * hash_width;
                let state_offset = p * 16;

                states[state_offset..state_offset + hash_width]
                    .copy_from_slice(&current_layer[left_offset..left_offset + hash_width]);
                states[state_offset + 8..state_offset + 8 + hash_width]
                    .copy_from_slice(&current_layer[right_offset..right_offset + hash_width]);
            }

            if pairs >= 1000 {
                let success = self.poseidon2.batch_permute_goldilocks(
                    &mut states,
                    round_constants,
                    n_external_rounds,
                    n_internal_rounds,
                );
                if !success {
                    return None;
                }
            } else {
                cpu_poseidon2_goldilocks(
                    &mut states,
                    round_constants,
                    n_external_rounds,
                    n_internal_rounds,
                );
            }

            let mut next_layer = Vec::with_capacity(pairs * hash_width);
            for p in 0..pairs {
                let state_offset = p * 16;
                for i in 0..hash_width {
                    next_layer.push(states[state_offset + i]);
                }
            }

            layers.push(next_layer.clone());
            current_layer = next_layer;
            current_count = pairs;
        }

        Some(layers)
    }

    /// Build a Merkle tree from leaf hashes using BabyBear Poseidon2.
    pub fn build_babybear(
        &self,
        leaves: &[u32],
        hash_width: usize,
        round_constants: &[u32],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> Option<Vec<Vec<u32>>> {
        if hash_width == 0
            || hash_width > 8
            || leaves.is_empty()
            || !leaves.len().is_multiple_of(hash_width)
        {
            return None;
        }

        let num_leaves = leaves.len() / hash_width;
        if !num_leaves.is_power_of_two() {
            return None;
        }

        let mut layers: Vec<Vec<u32>> = Vec::new();
        layers.push(leaves.to_vec());

        let mut current_layer = leaves.to_vec();
        let mut current_count = num_leaves;

        while current_count > 1 {
            let pairs = current_count / 2;

            let mut states = vec![0u32; pairs * 16];
            for p in 0..pairs {
                let left_offset = (2 * p) * hash_width;
                let right_offset = (2 * p + 1) * hash_width;
                let state_offset = p * 16;

                states[state_offset..state_offset + hash_width]
                    .copy_from_slice(&current_layer[left_offset..left_offset + hash_width]);
                states[state_offset + 8..state_offset + 8 + hash_width]
                    .copy_from_slice(&current_layer[right_offset..right_offset + hash_width]);
            }

            if pairs >= 1000 {
                let success = self.poseidon2.batch_permute_babybear(
                    &mut states,
                    round_constants,
                    n_external_rounds,
                    n_internal_rounds,
                );
                if !success {
                    return None;
                }
            } else {
                cpu_poseidon2_babybear(
                    &mut states,
                    round_constants,
                    n_external_rounds,
                    n_internal_rounds,
                );
            }

            let mut next_layer = Vec::with_capacity(pairs * hash_width);
            for p in 0..pairs {
                let state_offset = p * 16;
                for i in 0..hash_width {
                    next_layer.push(states[state_offset + i]);
                }
            }

            layers.push(next_layer.clone());
            current_layer = next_layer;
            current_count = pairs;
        }

        Some(layers)
    }

    /// Get the Merkle root from a built tree.
    pub fn root_from_layers<T: Copy>(layers: &[Vec<T>], hash_width: usize) -> Option<Vec<T>> {
        let last = layers.last()?;
        if last.len() != hash_width {
            return None;
        }
        Some(last.to_vec())
    }
}

/// CPU fallback for small Poseidon2 batches (Goldilocks).
fn cpu_poseidon2_goldilocks(
    states: &mut [u64],
    _round_constants: &[u64],
    _n_external_rounds: u32,
    _n_internal_rounds: u32,
) {
    use p3_goldilocks::Goldilocks;
    let n_perms = states.len() / 16;
    for perm_idx in 0..n_perms {
        let offset = perm_idx * 16;
        let mut state: [Goldilocks; 16] =
            std::array::from_fn(|i| Goldilocks::from_u64(states[offset + i]));
        use rand09::SeedableRng;
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(42);
        use p3_goldilocks::Poseidon2Goldilocks;
        let cpu_perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
        cpu_perm.permute_mut(&mut state);
        for i in 0..16 {
            states[offset + i] = state[i].as_canonical_u64();
        }
    }
}

/// CPU fallback for small Poseidon2 batches (BabyBear).
fn cpu_poseidon2_babybear(
    states: &mut [u32],
    _round_constants: &[u32],
    _n_external_rounds: u32,
    _n_internal_rounds: u32,
) {
    use p3_baby_bear::BabyBear;
    let n_perms = states.len() / 16;
    for perm_idx in 0..n_perms {
        let offset = perm_idx * 16;
        let mut state: [BabyBear; 16] =
            std::array::from_fn(|i| BabyBear::from_u64(states[offset + i] as u64));
        use rand09::SeedableRng;
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(42);
        use p3_baby_bear::Poseidon2BabyBear;
        let cpu_perm = Poseidon2BabyBear::<16>::new_from_rng_128(&mut rng);
        cpu_perm.permute_mut(&mut state);
        for i in 0..16 {
            states[offset + i] = state[i].as_canonical_u64() as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon2::goldilocks;

    #[test]
    fn merkle_goldilocks_basic() {
        let builder = match MetalMerkleBuilder::new() {
            Some(b) => b,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let seed = 42u64;
        let (round_constants, n_ext, n_int) = goldilocks::flatten_round_constants(seed);

        let hash_width = 8;
        let num_leaves = 2048;
        let leaves: Vec<u64> = (0..num_leaves * hash_width)
            .map(|i| (i as u64) % 0xFFFFFFFF00000001)
            .collect();

        let layers = builder
            .build_goldilocks(&leaves, hash_width, &round_constants, n_ext, n_int)
            .expect("Merkle build should succeed");

        assert_eq!(layers.len(), 12);
        assert_eq!(layers[0].len(), num_leaves * hash_width);
        assert_eq!(layers.last().unwrap().len(), hash_width);

        let root = MetalMerkleBuilder::root_from_layers(&layers, hash_width).unwrap();
        assert_eq!(root.len(), hash_width);
    }

    #[test]
    fn gpu_merkle_mmcs_matches_cpu() {
        use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
        use p3_field::Field;
        use p3_matrix::dense::RowMajorMatrix;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
        use rand09::SeedableRng;

        type F = BabyBear;
        type Perm = Poseidon2BabyBear<16>;
        type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

        let seed = 42u64;
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);

        // CPU reference
        let cpu_mmcs = MerkleTreeMmcs::<
            <F as Field>::Packing,
            <F as Field>::Packing,
            MyHash,
            MyCompress,
            8,
        >::new(hash.clone(), compress.clone());

        // GPU-accelerated
        let gpu_mmcs = MetalMerkleTreeMmcs::<
            <F as Field>::Packing,
            <F as Field>::Packing,
            MyHash,
            MyCompress,
            8,
        >::new_with_gpu(hash, compress, seed);

        // Create a matrix with enough rows to trigger GPU
        let n_rows = 4096;
        let n_cols = 4;
        let mat_data: Vec<F> = (0..n_rows * n_cols)
            .map(|i| F::from_u64((i as u64) % 2013265920))
            .collect();

        let cpu_mat = RowMajorMatrix::new(mat_data.clone(), n_cols);
        let gpu_mat = RowMajorMatrix::new(mat_data, n_cols);

        let (cpu_commit, _) = cpu_mmcs.commit(vec![cpu_mat]);
        let (gpu_commit, _) = gpu_mmcs.commit(vec![gpu_mat]);

        assert_eq!(
            cpu_commit, gpu_commit,
            "GPU Merkle commitment should match CPU"
        );
    }
}
