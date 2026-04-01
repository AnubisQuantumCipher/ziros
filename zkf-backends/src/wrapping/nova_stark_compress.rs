//! Nova-based STARK proof compression.
//!
//! Folds 32 FRI query verification steps via Nova IVC, then compresses
//! the resulting recursive SNARK into a ~10KB Spartan proof. This replaces
//! the ~46M-constraint direct FRI verifier circuit with a ~500K-1M constraint
//! Nova verifier circuit for the final Groth16 wrapping.
//!
//! Architecture:
//! ```text
//! STARK Proof (Goldilocks)
//!     ↓
//! [Nova IVC: fold 32 query verification steps] — Pallas/Vesta cycle
//!     ↓
//! CompressedSNARK (Spartan, ~10KB)
//!     ↓
//! [Nova verifier as Groth16 R1CS] — BN254 (~500K-1M constraints)
//!     ↓
//! Groth16 proof (128 bytes)
//! ```
#[cfg(feature = "nova-compression")]
use super::fri_query_step::{ACCUMULATOR_SIZE, FriQueryStep, FriQueryWitness};
#[cfg(feature = "nova-compression")]
use ff::Field;
#[cfg(feature = "nova-compression")]
use ff::PrimeField as FfPrimeField;
#[cfg(feature = "nova-compression")]
use nova_snark::nova::{
    CompressedSNARK as ClassicCompressedSNARK, PublicParams as ClassicPublicParams,
    RecursiveSNARK as ClassicRecursiveSnark,
};
#[cfg(feature = "nova-compression")]
use nova_snark::provider::ipa_pc::EvaluationEngine;
#[cfg(feature = "nova-compression")]
use nova_snark::provider::{PallasEngine, VestaEngine};
#[cfg(feature = "nova-compression")]
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
#[cfg(feature = "nova-compression")]
use nova_snark::traits::Engine;
#[cfg(feature = "nova-compression")]
use nova_snark::traits::snark::default_ck_hint;
#[cfg(feature = "nova-compression")]
use std::fs;
#[cfg(feature = "nova-compression")]
use std::path::PathBuf;
#[cfg(feature = "nova-compression")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "nova-compression")]
use std::time::Instant;

#[cfg(feature = "nova-compression")]
use once_cell::sync::Lazy;
#[cfg(feature = "nova-compression")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "nova-compression")]
use sha2::{Digest, Sha256};
#[cfg(feature = "nova-compression")]
use zkf_core::{ZkfError, ZkfResult};

#[cfg(feature = "nova-compression")]
use crate::{BoundedStringCache, bounded_cache_limit};

#[cfg(feature = "nova-compression")]
type PallasScalar = <PallasEngine as Engine>::Scalar;
#[cfg(feature = "nova-compression")]
type PrimarySpartan = RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>;
#[cfg(feature = "nova-compression")]
type SecondarySpartan = RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>;
#[cfg(feature = "nova-compression")]
type NovaParams = ClassicPublicParams<PallasEngine, VestaEngine, FriQueryStep>;
#[cfg(feature = "nova-compression")]
type NovaRecursive = ClassicRecursiveSnark<PallasEngine, VestaEngine, FriQueryStep>;
#[cfg(feature = "nova-compression")]
type NovaCompressed = ClassicCompressedSNARK<
    PallasEngine,
    VestaEngine,
    FriQueryStep,
    PrimarySpartan,
    SecondarySpartan,
>;

/// Cache for Nova public parameters, keyed by circuit shape hash.
#[cfg(feature = "nova-compression")]
static NOVA_PP_CACHE: Lazy<Mutex<BoundedStringCache<Arc<NovaParams>>>> = Lazy::new(|| {
    Mutex::new(BoundedStringCache::new(bounded_cache_limit(
        "ZKF_NOVA_PP_CACHE_LIMIT",
        2,
    )))
});

#[cfg(all(test, feature = "nova-compression"))]
pub(crate) fn clear_test_caches() {
    if let Ok(mut cache) = NOVA_PP_CACHE.lock() {
        cache.clear();
    }
}

#[cfg(all(test, not(feature = "nova-compression")))]
pub(crate) fn clear_test_caches() {}

/// Result of Nova STARK compression.
#[cfg(feature = "nova-compression")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedStarkProof {
    /// Serialized CompressedSNARK (Spartan)
    pub compressed_snark_bytes: Vec<u8>,
    /// Nova public parameters hash (for cache lookup during Groth16 wrapping)
    pub pp_hash: String,
    /// Final IVC output (accumulator state after all 32 query steps)
    pub final_accumulator: Vec<u8>,
    /// Number of queries folded
    pub num_queries: u32,
    /// Circuit shape parameters (for reproducing the step circuit)
    pub max_depth: usize,
    pub leaf_width: usize,
    pub num_fri_rounds: usize,
}

/// Orchestrates Nova-based STARK proof compression.
#[cfg(feature = "nova-compression")]
pub struct NovaStarkCompressor;

#[cfg(feature = "nova-compression")]
impl NovaStarkCompressor {
    /// Compress a STARK proof by folding FRI query verifications via Nova IVC.
    ///
    /// Steps:
    /// 1. Extract FRI query witnesses from the STARK proof
    /// 2. Get/compute Nova public parameters (cached by shape hash)
    /// 3. Fold all query steps into a recursive SNARK
    /// 4. Compress to a Spartan proof (~10KB)
    pub fn compress(
        query_witnesses: Vec<FriQueryWitness>,
        public_inputs: &[u64],
        max_depth: usize,
        leaf_width: usize,
        num_fri_rounds: usize,
    ) -> ZkfResult<CompressedStarkProof> {
        let num_queries = query_witnesses.len() as u32;
        if num_queries == 0 {
            return Err(ZkfError::InvalidArtifact(
                "Nova compression requires at least one FRI query witness".to_string(),
            ));
        }
        let start = Instant::now();

        // Compute shape hash for PP caching (depth/width kept in hash for cache invalidation
        // but the step circuit shape now only depends on num_fri_rounds)
        let shape_hash = compute_shape_hash(max_depth, leaf_width, num_fri_rounds);

        // Get or compute Nova public parameters
        let pp = get_or_compute_pp(&shape_hash, num_fri_rounds)?;

        eprintln!(
            "[nova-compress] PP ready in {:.1}s (shape={})",
            start.elapsed().as_secs_f64(),
            &shape_hash[..16]
        );

        // Create initial accumulator state
        let z0 = initial_accumulator(public_inputs);

        // Build step circuits for each query
        let steps: Vec<FriQueryStep> = query_witnesses
            .into_iter()
            .map(|w| FriQueryStep::new(Some(w), num_fri_rounds))
            .collect();

        // Fold all steps via Nova IVC
        let fold_start = Instant::now();
        let mut recursive_snark = NovaRecursive::new(&pp, &steps[0], &z0)
            .map_err(|e| ZkfError::Backend(format!("Nova IVC init failed: {e}")))?;

        // Nova seeds the first circuit in `new`, but it still expects `prove_step`
        // to be called for every step. The first call simply advances internal state.
        for (i, step) in steps.iter().enumerate() {
            recursive_snark
                .prove_step(&pp, step)
                .map_err(|e| ZkfError::Backend(format!("Nova IVC step {i} failed: {e}")))?;
        }

        eprintln!(
            "[nova-compress] Folded {} queries in {:.1}s",
            num_queries,
            fold_start.elapsed().as_secs_f64()
        );

        // Verify the recursive SNARK (sanity check)
        recursive_snark
            .verify(&pp, num_queries as usize, &z0)
            .map_err(|e| ZkfError::Backend(format!("Nova IVC verification failed: {e}")))?;

        // Compress to Spartan
        let compress_start = Instant::now();
        let (pk, vk) = NovaCompressed::setup(&pp)
            .map_err(|e| ZkfError::Backend(format!("Nova Spartan setup failed: {e}")))?;

        let compressed = NovaCompressed::prove(&pp, &pk, &recursive_snark)
            .map_err(|e| ZkfError::Backend(format!("Nova Spartan compression failed: {e}")))?;

        // Verify compressed proof
        compressed
            .verify(&vk, num_queries as usize, &z0)
            .map_err(|e| ZkfError::Backend(format!("Nova compressed verification failed: {e}")))?;

        eprintln!(
            "[nova-compress] Spartan compression in {:.1}s",
            compress_start.elapsed().as_secs_f64()
        );

        // Serialize
        let compressed_bytes = bincode::serialize(&compressed)
            .map_err(|e| ZkfError::Backend(format!("Failed to serialize compressed SNARK: {e}")))?;

        let final_acc = serialize_accumulator_outputs(recursive_snark.outputs())?;

        eprintln!(
            "[nova-compress] Total: {:.1}s, compressed proof: {} bytes",
            start.elapsed().as_secs_f64(),
            compressed_bytes.len()
        );

        Ok(CompressedStarkProof {
            compressed_snark_bytes: compressed_bytes,
            pp_hash: shape_hash,
            final_accumulator: final_acc,
            num_queries,
            max_depth,
            leaf_width,
            num_fri_rounds,
        })
    }
}

#[cfg(feature = "nova-compression")]
pub fn verify_compressed_stark_proof(
    proof: &CompressedStarkProof,
    public_inputs: &[u64],
) -> ZkfResult<()> {
    let pp = get_or_compute_pp(&proof.pp_hash, proof.num_fri_rounds)?;
    let (_pk, vk) = NovaCompressed::setup(&pp)
        .map_err(|e| ZkfError::Backend(format!("Nova Spartan setup failed: {e}")))?;
    let compressed: NovaCompressed = bincode::deserialize(&proof.compressed_snark_bytes)
        .map_err(|e| ZkfError::Backend(format!("Failed to deserialize compressed SNARK: {e}")))?;
    let z0 = initial_accumulator(public_inputs);
    let outputs = compressed
        .verify(&vk, proof.num_queries as usize, &z0)
        .map_err(|e| ZkfError::Backend(format!("Nova compressed verification failed: {e}")))?;
    let expected = serialize_accumulator_outputs(&outputs)?;
    if expected != proof.final_accumulator {
        return Err(ZkfError::InvalidArtifact(
            "compressed proof accumulator bytes do not match serialized outputs".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "nova-compression")]
fn compute_shape_hash(max_depth: usize, leaf_width: usize, num_fri_rounds: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nova-fri-step-v1");
    hasher.update(max_depth.to_le_bytes());
    hasher.update(leaf_width.to_le_bytes());
    hasher.update(num_fri_rounds.to_le_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(feature = "nova-compression")]
fn get_or_compute_pp(shape_hash: &str, num_fri_rounds: usize) -> ZkfResult<Arc<NovaParams>> {
    // Check memory cache
    {
        let mut cache = NOVA_PP_CACHE.lock().unwrap();
        if let Some(pp) = cache.get_cloned(shape_hash) {
            return Ok(pp);
        }
    }

    // Check disk cache
    let cache_dir = dirs_cache_path();
    let cache_file = cache_dir.join(format!("nova_pp_{}.bin", &shape_hash[..32]));

    if cache_file.exists()
        && let Ok(bytes) = fs::read(&cache_file)
        && let Ok(pp) = bincode::deserialize::<NovaParams>(&bytes)
    {
        let pp = Arc::new(pp);
        let mut cache = NOVA_PP_CACHE.lock().unwrap();
        cache.insert(shape_hash.to_string(), Arc::clone(&pp));
        return Ok(pp);
    }

    // Compute fresh public parameters
    let sizing_circuit = FriQueryStep::sizing_instance(num_fri_rounds);

    let pp = NovaParams::setup(&sizing_circuit, &*default_ck_hint(), &*default_ck_hint())
        .map_err(|e| ZkfError::Backend(format!("Nova PP setup failed: {e}")))?;

    // Save to disk cache
    if let Ok(bytes) = bincode::serialize(&pp) {
        let _ = fs::create_dir_all(&cache_dir);
        let _ = fs::write(&cache_file, &bytes);
    }

    let pp = Arc::new(pp);
    let mut cache = NOVA_PP_CACHE.lock().unwrap();
    cache.insert(shape_hash.to_string(), Arc::clone(&pp));
    Ok(pp)
}

#[cfg(feature = "nova-compression")]
fn initial_accumulator(public_inputs: &[u64]) -> Vec<PallasScalar> {
    use ff::Field;
    let mut z0 = vec![PallasScalar::ZERO; ACCUMULATOR_SIZE];
    z0[0] = PallasScalar::ONE; // fold_valid_status = 1 (valid, AND-accumulated)
    // z0[1] = 0 (queries_verified_count starts at 0)
    let (query_hash_lo, query_hash_hi) = public_input_digest_limbs(public_inputs);
    z0[2] = query_hash_lo;
    z0[3] = query_hash_hi;
    z0[4] = PallasScalar::ONE; // initial_x_accumulator = 1 (multiplicative identity)
    z0
}

#[cfg(feature = "nova-compression")]
fn public_input_digest_limbs(public_inputs: &[u64]) -> (PallasScalar, PallasScalar) {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-nova-wrap-public-inputs-v1");
    for value in public_inputs {
        hasher.update(value.to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut lo = <PallasScalar as FfPrimeField>::Repr::default();
    let mut hi = <PallasScalar as FfPrimeField>::Repr::default();
    lo.as_mut()[..16].copy_from_slice(&digest[..16]);
    hi.as_mut()[..16].copy_from_slice(&digest[16..32]);
    (
        Option::from(PallasScalar::from_repr(lo)).unwrap_or(PallasScalar::ZERO),
        Option::from(PallasScalar::from_repr(hi)).unwrap_or(PallasScalar::ZERO),
    )
}

#[cfg(feature = "nova-compression")]
fn serialize_accumulator_outputs(outputs: &[PallasScalar]) -> ZkfResult<Vec<u8>> {
    if outputs.len() != ACCUMULATOR_SIZE {
        return Err(ZkfError::Backend(format!(
            "Nova accumulator length mismatch: expected {}, found {}",
            ACCUMULATOR_SIZE,
            outputs.len()
        )));
    }
    let mut bytes = Vec::with_capacity(outputs.len() * 32);
    for scalar in outputs {
        let repr = scalar.to_repr();
        bytes.extend_from_slice(repr.as_ref());
    }
    Ok(bytes)
}

#[cfg(feature = "nova-compression")]
fn dirs_cache_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".cache").join("zkf").join("nova")
}

// Re-export hex encoding since we reference it
#[cfg(feature = "nova-compression")]
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(all(test, feature = "nova-compression"))]
mod tests {
    use super::*;

    fn make_valid_query_witness(query_index: u32) -> FriQueryWitness {
        FriQueryWitness {
            query_index,
            x_values: vec![1],
            f_evals_pos: vec![2],
            f_evals_neg: vec![2],
            f_evals_folded: vec![2],
            folding_challenges: vec![0],
            merkle_path: vec![],
            round_commitments: vec![],
        }
    }

    #[test]
    fn recursive_snark_verifies_when_all_steps_are_proved() {
        let num_fri_rounds = 1usize;
        let shape_hash = compute_shape_hash(1, 1, num_fri_rounds);
        let pp = get_or_compute_pp(&shape_hash, num_fri_rounds).unwrap();
        let z0 = initial_accumulator(&[7, 5]);
        let steps = vec![
            FriQueryStep::new(Some(make_valid_query_witness(0)), num_fri_rounds),
            FriQueryStep::new(Some(make_valid_query_witness(1)), num_fri_rounds),
        ];

        let mut recursive_snark = NovaRecursive::new(&pp, &steps[0], &z0).unwrap();
        for step in &steps {
            recursive_snark.prove_step(&pp, step).unwrap();
        }

        recursive_snark
            .verify(&pp, steps.len(), &z0)
            .expect("all query steps should be folded into the final recursive proof");
    }
}
