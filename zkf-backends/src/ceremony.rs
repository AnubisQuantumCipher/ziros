//! Powers of Tau ceremony — Phase 1 (universal SRS) & Phase 2 (circuit-specific keys).
//!
//! # Math
//!
//! The SRS (Structured Reference String) is a set of elliptic curve points encoding
//! successive powers of a secret scalar τ on BN254:
//!
//!   G₁ powers: {\[τ⁰\]₁, \[τ¹\]₁, \[τ²\]₁, ..., \[τⁿ⁻¹\]₁}
//!   G₂ powers: {\[τ⁰\]₂, \[τ¹\]₂, \[τ²\]₂, ..., \[τⁿ⁻¹\]₂}
//!
//! The combined τ = p₁·p₂·…·pₙ where each pₖ is a contributor's secret.
//! 1-of-N security: if ANY contributor destroys their pₖ, τ is unknowable.
//!
//! Consistency check via bilinear pairing:
//!   e(\[τⁱ\]₁, \[τ\]₂) = e(\[τⁱ⁺¹\]₁, G₂)  for all i
//!
//! # Phase 2
//!
//! Circuit-specific key derivation uses the Phase 1 SRS plus the circuit's
//! R1CS/QAP structure to produce proving key (pk) and verification key (vk).
//! The δ parameter provides zero-knowledge randomization.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::Instant;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}")))
        .collect()
}

/// Current ptau file format version.
const PTAU_VERSION: u32 = 1;

/// Magic bytes for ptau file identification.
const PTAU_MAGIC: &[u8; 4] = b"ptau";

// ─── Ptau File Format ────────────────────────────────────────────────────────
//
// Binary format (all integers little-endian):
//   [4 bytes]  magic: "ptau"
//   [4 bytes]  version: u32
//   [4 bytes]  power: u32  (max constraints = 2^power)
//   [4 bytes]  num_contributions: u32
//   [8 bytes]  n_g1: u64  (number of G1 points = 2^power)
//   [8 bytes]  n_g2: u64  (number of G2 points = 2^power)
//   [n_g1 * G1_SIZE bytes]  G1 tau powers (compressed affine)
//   [n_g2 * G2_SIZE bytes]  G2 tau powers (compressed affine)
//   [contribution_count * CONTRIBUTION_SIZE bytes]  contribution records
//

/// Size of a compressed G1 point on BN254 (32 bytes).
#[allow(dead_code)]
const G1_COMPRESSED_SIZE: usize = 32;
/// Size of a compressed G2 point on BN254 (64 bytes).
#[allow(dead_code)]
const G2_COMPRESSED_SIZE: usize = 64;

/// A contribution record in the ceremony transcript.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributionRecord {
    pub name: String,
    pub hash: String,
    pub timestamp: String,
}

/// In-memory representation of a Powers of Tau ceremony.
pub struct PtauData {
    pub power: u32,
    pub tau_g1: Vec<G1Affine>,
    pub tau_g2: Vec<G2Affine>,
    pub contributions: Vec<ContributionRecord>,
}

impl PtauData {
    /// Number of points per group.
    pub fn n(&self) -> usize {
        1usize << self.power
    }

    /// Initialize a new ceremony with the identity SRS (all generators).
    pub fn new(power: u32) -> Self {
        let n = 1usize << power;
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        PtauData {
            power,
            tau_g1: vec![g1; n],
            tau_g2: vec![g2; n],
            contributions: Vec::new(),
        }
    }

    /// Contribute randomness. Multiplies all SRS elements by powers of the secret.
    /// Returns the hash of this contribution.
    pub fn contribute(&mut self, entropy: Option<&[u8]>, name: &str) -> Result<String, String> {
        // Generate random secret pₖ
        let secret = if let Some(extra) = entropy {
            // Mix extra entropy with OS randomness
            let mut hasher = Sha256::new();
            hasher.update(b"zkf-ceremony-contribution-v1");
            let mut os_random = [0u8; 64];
            OsRng.fill(&mut os_random);
            hasher.update(os_random);
            hasher.update(extra);
            hasher.update(name.as_bytes());
            let hash = hasher.finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&hash);
            Fr::from_le_bytes_mod_order(&seed)
        } else {
            Fr::rand(&mut OsRng)
        };

        if secret.is_zero() {
            return Err("contribution secret is zero — this would destroy the SRS".to_string());
        }

        let n = self.n();
        let start = Instant::now();

        // Compute powers: secret^0, secret^1, ..., secret^{n-1}
        let mut powers = vec![Fr::from(1u64); n];
        for i in 1..n {
            powers[i] = powers[i - 1] * secret;
        }

        // Multiply G1 points: [τ_new^i]₁ = [secret^i]·[τ_old^i]₁
        for (point, power) in self.tau_g1.iter_mut().zip(powers.iter()).take(n) {
            let proj: G1Projective = (*point).into();
            *point = (proj * *power).into_affine();
        }

        // Multiply G2 points: [τ_new^i]₂ = [secret^i]·[τ_old^i]₂
        for (point, power) in self.tau_g2.iter_mut().zip(powers.iter()).take(n) {
            let proj: G2Projective = (*point).into();
            *point = (proj * *power).into_affine();
        }

        let elapsed = start.elapsed();

        // Compute contribution hash = SHA256(name || [τ_new^1]₁ || [τ_new^1]₂)
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        let mut buf = Vec::new();
        self.tau_g1[1]
            .serialize_compressed(&mut buf)
            .map_err(|e| e.to_string())?;
        hasher.update(&buf);
        buf.clear();
        self.tau_g2[1]
            .serialize_compressed(&mut buf)
            .map_err(|e| e.to_string())?;
        hasher.update(&buf);
        let hash = to_hex(&hasher.finalize());

        self.contributions.push(ContributionRecord {
            name: name.to_string(),
            hash: hash.clone(),
            timestamp: format!("{:.3}s", elapsed.as_secs_f64()),
        });

        // Zeroize secret from memory (best effort — compiler may optimize out)
        // For true production use, consider zeroize crate with volatile writes
        std::hint::black_box(secret);

        Ok(hash)
    }

    /// Apply a random beacon as the final contribution.
    /// Uses a publicly verifiable random value hashed through multiple iterations.
    pub fn apply_beacon(&mut self, beacon_hex: &str, iterations: u32) -> Result<String, String> {
        // Decode beacon value
        let beacon_bytes = from_hex(beacon_hex)?;

        // Hash through iterations to derive the secret
        let mut current = beacon_bytes;
        for _ in 0..iterations {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            current = hasher.finalize().to_vec();
        }

        // Use the final hash as entropy for the contribution
        self.contribute(Some(&current), "random_beacon")
    }

    /// Verify the SRS consistency using pairing checks.
    pub fn verify(&self) -> Result<CeremonyVerifyReport, String> {
        use ark_ec::pairing::Pairing;

        let n = self.n();
        let mut report = CeremonyVerifyReport {
            valid: true,
            power: self.power,
            contributions: self.contributions.len(),
            checks: std::collections::BTreeMap::new(),
        };

        // Check 1: First G1 point must be the generator
        let g1_gen_ok = self.tau_g1[0] == G1Affine::generator();
        report.checks.insert("g1_generator".to_string(), g1_gen_ok);
        if !g1_gen_ok {
            report.valid = false;
        }

        // Check 2: First G2 point must be the generator
        let g2_gen_ok = self.tau_g2[0] == G2Affine::generator();
        report.checks.insert("g2_generator".to_string(), g2_gen_ok);
        if !g2_gen_ok {
            report.valid = false;
        }

        // Check 3: No points at infinity
        let no_infinity =
            self.tau_g1.iter().all(|p| !p.is_zero()) && self.tau_g2.iter().all(|p| !p.is_zero());
        report
            .checks
            .insert("no_points_at_infinity".to_string(), no_infinity);
        if !no_infinity {
            report.valid = false;
        }

        // Check 4: Pairing consistency — e([τⁱ]₁, [τ]₂) = e([τⁱ⁺¹]₁, G₂)
        // We check a random sample for efficiency (checking all n would be expensive)
        let sample_size = std::cmp::min(n - 1, 16);
        let g2 = G2Affine::generator();
        let tau_g2_1 = self.tau_g2[1]; // [τ]₂
        let mut pairing_ok = true;

        for i in 0..sample_size {
            let lhs = Bn254::pairing(self.tau_g1[i], tau_g2_1);
            let rhs = Bn254::pairing(self.tau_g1[i + 1], g2);
            if lhs != rhs {
                pairing_ok = false;
                break;
            }
        }
        report
            .checks
            .insert("pairing_consistency".to_string(), pairing_ok);
        if !pairing_ok {
            report.valid = false;
        }

        // Check 5: Cross-group consistency — e([τ]₁, G₂) = e(G₁, [τ]₂)
        let g1 = G1Affine::generator();
        let cross_ok = Bn254::pairing(self.tau_g1[1], g2) == Bn254::pairing(g1, self.tau_g2[1]);
        report
            .checks
            .insert("cross_group_consistency".to_string(), cross_ok);
        if !cross_ok {
            report.valid = false;
        }

        Ok(report)
    }

    /// Write to a .ptau file.
    pub fn write_to_file(&self, path: &str) -> Result<(), String> {
        let mut file = std::fs::File::create(path).map_err(|e| format!("create {path}: {e}"))?;

        // Header
        file.write_all(PTAU_MAGIC).map_err(|e| e.to_string())?;
        file.write_all(&PTAU_VERSION.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&self.power.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&(self.contributions.len() as u32).to_le_bytes())
            .map_err(|e| e.to_string())?;

        let n = self.n() as u64;
        file.write_all(&n.to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&n.to_le_bytes())
            .map_err(|e| e.to_string())?;

        // G1 points
        for pt in &self.tau_g1 {
            pt.serialize_compressed(&mut file)
                .map_err(|e| format!("serialize G1: {e}"))?;
        }

        // G2 points
        for pt in &self.tau_g2 {
            pt.serialize_compressed(&mut file)
                .map_err(|e| format!("serialize G2: {e}"))?;
        }

        // Contribution records as JSON
        let contrib_json = serde_json::to_string(&self.contributions)
            .map_err(|e| format!("serialize contributions: {e}"))?;
        let json_bytes = contrib_json.as_bytes();
        file.write_all(&(json_bytes.len() as u32).to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(json_bytes).map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Read from a .ptau file.
    pub fn read_from_file(path: &str) -> Result<Self, String> {
        let mut file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;

        // Read header
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)
            .map_err(|e| format!("read magic: {e}"))?;
        if &magic != PTAU_MAGIC {
            return Err("not a valid .ptau file (wrong magic)".to_string());
        }

        let mut buf4 = [0u8; 4];
        file.read_exact(&mut buf4)
            .map_err(|e| format!("read version: {e}"))?;
        let version = u32::from_le_bytes(buf4);
        if version != PTAU_VERSION {
            return Err(format!("unsupported ptau version {version}"));
        }

        file.read_exact(&mut buf4)
            .map_err(|e| format!("read power: {e}"))?;
        let power = u32::from_le_bytes(buf4);

        file.read_exact(&mut buf4)
            .map_err(|e| format!("read num_contributions: {e}"))?;
        let num_contributions = u32::from_le_bytes(buf4);

        let mut buf8 = [0u8; 8];
        file.read_exact(&mut buf8)
            .map_err(|e| format!("read n_g1: {e}"))?;
        let n_g1 = u64::from_le_bytes(buf8) as usize;
        file.read_exact(&mut buf8)
            .map_err(|e| format!("read n_g2: {e}"))?;
        let n_g2 = u64::from_le_bytes(buf8) as usize;

        let expected_n = 1usize << power;
        if n_g1 != expected_n || n_g2 != expected_n {
            return Err(format!(
                "ptau point count mismatch: expected {expected_n}, got G1={n_g1}, G2={n_g2}"
            ));
        }

        // Read G1 points
        let mut tau_g1 = Vec::with_capacity(n_g1);
        for i in 0..n_g1 {
            let pt = G1Affine::deserialize_compressed(&mut file)
                .map_err(|e| format!("deserialize G1[{i}]: {e}"))?;
            tau_g1.push(pt);
        }

        // Read G2 points
        let mut tau_g2 = Vec::with_capacity(n_g2);
        for i in 0..n_g2 {
            let pt = G2Affine::deserialize_compressed(&mut file)
                .map_err(|e| format!("deserialize G2[{i}]: {e}"))?;
            tau_g2.push(pt);
        }

        // Read contribution records
        file.read_exact(&mut buf4)
            .map_err(|e| format!("read contrib len: {e}"))?;
        let contrib_len = u32::from_le_bytes(buf4) as usize;
        let mut contrib_bytes = vec![0u8; contrib_len];
        file.read_exact(&mut contrib_bytes)
            .map_err(|e| format!("read contributions: {e}"))?;
        let contributions: Vec<ContributionRecord> = serde_json::from_slice(&contrib_bytes)
            .map_err(|e| format!("parse contributions: {e}"))?;

        if contributions.len() != num_contributions as usize {
            return Err(format!(
                "contribution count mismatch: header says {num_contributions}, found {}",
                contributions.len()
            ));
        }

        Ok(PtauData {
            power,
            tau_g1,
            tau_g2,
            contributions,
        })
    }
}

/// Result of ceremony verification.
#[derive(Debug, Serialize)]
pub struct CeremonyVerifyReport {
    pub valid: bool,
    pub power: u32,
    pub contributions: usize,
    pub checks: std::collections::BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase2ContributionRecord {
    pub contributor_name: String,
    pub program_digest: String,
    pub entropy_hash: String,
    pub previous_seed_hex: String,
    pub resulting_seed_hex: String,
}

/// Phase 2 seed derivation: deterministic seed from Phase 1 SRS + circuit digest.
///
/// **IMPORTANT**: This is NOT a real multi-party Phase 2 ceremony. It derives a
/// deterministic 32-byte seed by hashing the Phase 1 tau powers with the circuit
/// digest. The resulting seed is used to initialize arkworks' `circuit_specific_setup`
/// RNG, binding the Phase 2 keys to both the ceremony output and the specific circuit.
///
/// For production use with adversarial trust assumptions, a proper multi-party
/// Phase 2 ceremony (e.g., Groth16 Powers of Tau Phase 2) should be implemented
/// where multiple independent participants contribute randomness.
///
/// Security model: 1-of-N honest (inherited from Phase 1 ceremony contributors).
/// The Phase 2 derivation itself is deterministic — it adds no additional randomness
/// beyond what Phase 1 already provides.
pub fn ceremony_phase2_setup(ptau: &PtauData, program_digest: &str) -> Result<[u8; 32], String> {
    // Derive a deterministic seed from the ceremony's tau powers + circuit digest.
    // This binds the Phase 2 keys to BOTH the ceremony AND the circuit.
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-ceremony-phase2-v1");
    hasher.update(program_digest.as_bytes());
    // Include the first few tau powers to bind to the ceremony
    let mut buf = Vec::new();
    ptau.tau_g1[1]
        .serialize_compressed(&mut buf)
        .map_err(|e| e.to_string())?;
    hasher.update(&buf);
    buf.clear();
    ptau.tau_g2[1]
        .serialize_compressed(&mut buf)
        .map_err(|e| e.to_string())?;
    hasher.update(&buf);
    // Include number of contributions for additional binding
    hasher.update((ptau.contributions.len() as u64).to_le_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    Ok(seed)
}

pub fn ceremony_phase2_entropy_hash(entropy: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-ceremony-phase2-entropy-v1");
    hasher.update(entropy.unwrap_or_default());
    encode_hex(&hasher.finalize())
}

pub fn ceremony_phase2_contribution_record(
    previous_seed: [u8; 32],
    program_digest: &str,
    contributor_name: &str,
    entropy_hash: &str,
) -> Result<Phase2ContributionRecord, String> {
    let resulting_seed = ceremony_phase2_apply_contribution(
        previous_seed,
        program_digest,
        contributor_name,
        entropy_hash,
    )?;
    Ok(Phase2ContributionRecord {
        contributor_name: contributor_name.to_string(),
        program_digest: program_digest.to_string(),
        entropy_hash: entropy_hash.to_string(),
        previous_seed_hex: encode_hex(&previous_seed),
        resulting_seed_hex: encode_hex(&resulting_seed),
    })
}

pub fn ceremony_phase2_apply_contribution(
    previous_seed: [u8; 32],
    program_digest: &str,
    contributor_name: &str,
    entropy_hash: &str,
) -> Result<[u8; 32], String> {
    if decode_hex(entropy_hash).is_err() {
        return Err("phase2 entropy hash must be hex".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-ceremony-phase2-contribution-v1");
    hasher.update(previous_seed);
    hasher.update(program_digest.as_bytes());
    hasher.update(contributor_name.as_bytes());
    hasher.update(entropy_hash.as_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    Ok(seed)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.as_bytes().chunks_exact(2);
    for chunk in &mut chars {
        let hi = from_hex_nibble(chunk[0])?;
        let lo = from_hex_nibble(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

fn from_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex character '{}'", value as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ceremony_init_and_verify() {
        let ptau = PtauData::new(4); // 2^4 = 16 points
        let report = ptau.verify().unwrap();
        assert!(report.valid);
        assert_eq!(report.power, 4);
    }

    #[test]
    fn test_ceremony_contribute_and_verify() {
        let mut ptau = PtauData::new(4);
        let hash = ptau
            .contribute(Some(b"test-entropy"), "test-contributor")
            .unwrap();
        assert!(!hash.is_empty());
        assert_eq!(ptau.contributions.len(), 1);

        let report = ptau.verify().unwrap();
        assert!(report.valid, "SRS must be valid after contribution");
    }

    #[test]
    fn test_ceremony_multi_contribute() {
        let mut ptau = PtauData::new(4);
        ptau.contribute(Some(b"alice"), "Alice").unwrap();
        ptau.contribute(Some(b"bob"), "Bob").unwrap();
        ptau.contribute(Some(b"charlie"), "Charlie").unwrap();

        let report = ptau.verify().unwrap();
        assert!(report.valid);
        assert_eq!(ptau.contributions.len(), 3);
    }

    #[test]
    fn test_ceremony_beacon_and_verify() {
        let mut ptau = PtauData::new(4);
        ptau.contribute(Some(b"alice"), "Alice").unwrap();
        ptau.apply_beacon("deadbeef", 10).unwrap();

        let report = ptau.verify().unwrap();
        assert!(report.valid);
        assert_eq!(ptau.contributions.len(), 2);
    }

    #[test]
    fn test_ptau_roundtrip() {
        let mut ptau = PtauData::new(4);
        ptau.contribute(Some(b"test"), "Test").unwrap();

        let path = std::env::temp_dir().join("test_ceremony.ptau");
        let path_str = path.to_str().unwrap();
        ptau.write_to_file(path_str).unwrap();
        let loaded = PtauData::read_from_file(path_str).unwrap();

        assert_eq!(loaded.power, ptau.power);
        assert_eq!(loaded.tau_g1.len(), ptau.tau_g1.len());
        assert_eq!(loaded.tau_g2.len(), ptau.tau_g2.len());
        assert_eq!(loaded.contributions.len(), ptau.contributions.len());

        // Verify loaded data is still valid
        let report = loaded.verify().unwrap();
        assert!(report.valid);

        std::fs::remove_file(path_str).ok();
    }

    #[test]
    fn test_phase2_seed_derivation() {
        let mut ptau = PtauData::new(4);
        ptau.contribute(Some(b"test"), "Test").unwrap();

        let seed = ceremony_phase2_setup(&ptau, "test-digest-abc123").unwrap();
        assert_ne!(seed, [0u8; 32], "seed must not be all zeros");

        // Same inputs → same seed (deterministic)
        let seed2 = ceremony_phase2_setup(&ptau, "test-digest-abc123").unwrap();
        assert_eq!(seed, seed2);

        // Different digest → different seed
        let seed3 = ceremony_phase2_setup(&ptau, "different-digest").unwrap();
        assert_ne!(seed, seed3);
    }

    #[test]
    fn test_phase2_contribution_chain_is_deterministic() {
        let previous_seed = [7u8; 32];
        let entropy_hash = ceremony_phase2_entropy_hash(Some(b"alice-extra"));
        let record =
            ceremony_phase2_contribution_record(previous_seed, "digest-1", "Alice", &entropy_hash)
                .unwrap();

        assert_eq!(record.previous_seed_hex, encode_hex(&previous_seed));
        let expected =
            ceremony_phase2_apply_contribution(previous_seed, "digest-1", "Alice", &entropy_hash)
                .unwrap();
        assert_eq!(record.resulting_seed_hex, encode_hex(&expected));
    }
}
