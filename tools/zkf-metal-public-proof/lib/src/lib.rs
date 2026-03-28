#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const PUBLIC_INPUT_SCHEMA: &str = "zkf-metal-public-proof-inputs-v2";
pub const PUBLIC_GROTH16_PROOF_SCHEMA: &str = "zkf-metal-public-groth16-proof-v1";
pub const PUBLIC_PROOF_SYSTEM: &str = "zkf-groth16";
pub const PUBLIC_PROOF_BACKEND: &str = "arkworks-groth16";
pub const BUNDLE_EVIDENCE_SCHEMA: &str = "zkf-metal-public-bundle-evidence-v1";
pub const PROOF_PLAN_SCHEMA: &str = "zkf-metal-public-proof-plan-v1";
pub const EXPECTED_PUBLIC_INPUT_BYTES: usize = 32 * 6;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TheoremRecord {
    pub theorem_id: String,
    pub checker: String,
    pub decl_name: String,
    pub module_name: String,
    pub proof_artifact_kind: String,
    pub proof_artifact_digest: String,
    pub allowed_axioms_only: bool,
    pub axioms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TheoremClosureBundleEvidence {
    pub bundle_id: String,
    pub theorem_ids: Vec<String>,
    pub toolchain_identity_digest: String,
    pub theorem_records: Vec<TheoremRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildIntegrityBundleEvidence {
    pub bundle_id: String,
    pub theorem_ids: Vec<String>,
    pub private_source_commitment_root: String,
    pub toolchain_identity_digest: String,
    pub metallib_digests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleEvidence {
    TheoremClosure(TheoremClosureBundleEvidence),
    BuildIntegrity(BuildIntegrityBundleEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum HumanReadableBundleEvidence {
    TheoremClosure(TheoremClosureBundleEvidence),
    BuildIntegrity(BuildIntegrityBundleEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum BinaryBundleEvidence {
    TheoremClosure(TheoremClosureBundleEvidence),
    BuildIntegrity(BuildIntegrityBundleEvidence),
}

impl Serialize for BundleEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let value = match self {
                BundleEvidence::TheoremClosure(inner) => {
                    HumanReadableBundleEvidence::TheoremClosure(inner.clone())
                }
                BundleEvidence::BuildIntegrity(inner) => {
                    HumanReadableBundleEvidence::BuildIntegrity(inner.clone())
                }
            };
            value.serialize(serializer)
        } else {
            let value = match self {
                BundleEvidence::TheoremClosure(inner) => {
                    BinaryBundleEvidence::TheoremClosure(inner.clone())
                }
                BundleEvidence::BuildIntegrity(inner) => {
                    BinaryBundleEvidence::BuildIntegrity(inner.clone())
                }
            };
            value.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for BundleEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            match HumanReadableBundleEvidence::deserialize(deserializer)? {
                HumanReadableBundleEvidence::TheoremClosure(inner) => {
                    Ok(BundleEvidence::TheoremClosure(inner))
                }
                HumanReadableBundleEvidence::BuildIntegrity(inner) => {
                    Ok(BundleEvidence::BuildIntegrity(inner))
                }
            }
        } else {
            match BinaryBundleEvidence::deserialize(deserializer)? {
                BinaryBundleEvidence::TheoremClosure(inner) => {
                    Ok(BundleEvidence::TheoremClosure(inner))
                }
                BinaryBundleEvidence::BuildIntegrity(inner) => {
                    Ok(BundleEvidence::BuildIntegrity(inner))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleWitness {
    pub bundle_id: String,
    pub theorem_ids: Vec<String>,
    pub statement_bundle_digest: String,
    pub private_source_commitment_root: String,
    pub metallib_digest_set_root: String,
    pub attestation_manifest_digest: String,
    pub toolchain_identity_digest: String,
    pub bundle_evidence: BundleEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuestBundleEvidence {
    TheoremClosure(TheoremClosureBundleEvidence),
    BuildIntegrity(BuildIntegrityBundleEvidence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestBundleWitness {
    pub bundle_id: String,
    pub theorem_ids: Vec<String>,
    pub statement_bundle_digest: String,
    pub private_source_commitment_root: String,
    pub metallib_digest_set_root: String,
    pub attestation_manifest_digest: String,
    pub toolchain_identity_digest: String,
    pub bundle_evidence: GuestBundleEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofGenerationPlan {
    pub schema: String,
    pub proof_mode: String,
    pub requests: Vec<BundleWitness>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicGroth16ProvingLane {
    pub backend: String,
    pub curve: String,
    pub groth16_msm_engine: String,
    pub qap_witness_map_engine: String,
    pub metal_no_cpu_fallback: bool,
    pub metal_gpu_busy_ratio: String,
    pub metal_counter_source: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub release_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicGroth16ProofBundle {
    pub schema: String,
    pub proof_system: String,
    pub backend: String,
    pub proof_bytes: Vec<u8>,
    pub public_input_bytes: Vec<u8>,
    pub proving_lane: PublicGroth16ProvingLane,
}

impl BundleEvidence {
    pub fn bundle_id(&self) -> &str {
        match self {
            BundleEvidence::TheoremClosure(value) => value.bundle_id.as_str(),
            BundleEvidence::BuildIntegrity(value) => value.bundle_id.as_str(),
        }
    }

    pub fn theorem_ids(&self) -> &[String] {
        match self {
            BundleEvidence::TheoremClosure(value) => value.theorem_ids.as_slice(),
            BundleEvidence::BuildIntegrity(value) => value.theorem_ids.as_slice(),
        }
    }

    pub fn toolchain_identity_digest(&self) -> &str {
        match self {
            BundleEvidence::TheoremClosure(value) => value.toolchain_identity_digest.as_str(),
            BundleEvidence::BuildIntegrity(value) => value.toolchain_identity_digest.as_str(),
        }
    }
}

impl From<BundleEvidence> for GuestBundleEvidence {
    fn from(value: BundleEvidence) -> Self {
        match value {
            BundleEvidence::TheoremClosure(inner) => GuestBundleEvidence::TheoremClosure(inner),
            BundleEvidence::BuildIntegrity(inner) => GuestBundleEvidence::BuildIntegrity(inner),
        }
    }
}

impl From<GuestBundleEvidence> for BundleEvidence {
    fn from(value: GuestBundleEvidence) -> Self {
        match value {
            GuestBundleEvidence::TheoremClosure(inner) => BundleEvidence::TheoremClosure(inner),
            GuestBundleEvidence::BuildIntegrity(inner) => BundleEvidence::BuildIntegrity(inner),
        }
    }
}

impl From<BundleWitness> for GuestBundleWitness {
    fn from(value: BundleWitness) -> Self {
        GuestBundleWitness {
            bundle_id: value.bundle_id,
            theorem_ids: value.theorem_ids,
            statement_bundle_digest: value.statement_bundle_digest,
            private_source_commitment_root: value.private_source_commitment_root,
            metallib_digest_set_root: value.metallib_digest_set_root,
            attestation_manifest_digest: value.attestation_manifest_digest,
            toolchain_identity_digest: value.toolchain_identity_digest,
            bundle_evidence: value.bundle_evidence.into(),
        }
    }
}

impl From<GuestBundleWitness> for BundleWitness {
    fn from(value: GuestBundleWitness) -> Self {
        BundleWitness {
            bundle_id: value.bundle_id,
            theorem_ids: value.theorem_ids,
            statement_bundle_digest: value.statement_bundle_digest,
            private_source_commitment_root: value.private_source_commitment_root,
            metallib_digest_set_root: value.metallib_digest_set_root,
            attestation_manifest_digest: value.attestation_manifest_digest,
            toolchain_identity_digest: value.toolchain_identity_digest,
            bundle_evidence: value.bundle_evidence.into(),
        }
    }
}

fn write_field(hasher: &mut Sha256, key: &str, value: &str) {
    hasher.update(key.as_bytes());
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    hasher.update([0xffu8]);
}

fn write_bool_field(hasher: &mut Sha256, key: &str, value: bool) {
    write_field(hasher, key, if value { "true" } else { "false" });
}

fn write_sorted_string_list(hasher: &mut Sha256, key: &str, values: &[String]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    write_field(hasher, &format!("{key}_len"), &sorted.len().to_string());
    for value in sorted {
        write_field(hasher, key, &value);
    }
}

fn theorem_record_cmp(lhs: &TheoremRecord, rhs: &TheoremRecord) -> Ordering {
    lhs.theorem_id
        .cmp(&rhs.theorem_id)
        .then_with(|| lhs.checker.cmp(&rhs.checker))
        .then_with(|| lhs.decl_name.cmp(&rhs.decl_name))
}

pub fn canonical_bundle_evidence_digest(evidence: &BundleEvidence) -> String {
    let mut hasher = Sha256::new();
    write_field(&mut hasher, "schema", BUNDLE_EVIDENCE_SCHEMA);
    match evidence {
        BundleEvidence::TheoremClosure(value) => {
            write_field(&mut hasher, "kind", "theorem_closure");
            write_field(&mut hasher, "bundle_id", &value.bundle_id);
            write_field(
                &mut hasher,
                "toolchain_identity_digest",
                &value.toolchain_identity_digest,
            );
            write_sorted_string_list(&mut hasher, "theorem_id", &value.theorem_ids);
            let mut records = value.theorem_records.clone();
            records.sort_by(theorem_record_cmp);
            write_field(&mut hasher, "record_len", &records.len().to_string());
            for record in records {
                write_field(&mut hasher, "record_theorem_id", &record.theorem_id);
                write_field(&mut hasher, "record_checker", &record.checker);
                write_field(&mut hasher, "record_decl_name", &record.decl_name);
                write_field(&mut hasher, "record_module_name", &record.module_name);
                write_field(
                    &mut hasher,
                    "record_proof_artifact_kind",
                    &record.proof_artifact_kind,
                );
                write_field(
                    &mut hasher,
                    "record_proof_artifact_digest",
                    &record.proof_artifact_digest,
                );
                write_bool_field(
                    &mut hasher,
                    "record_allowed_axioms_only",
                    record.allowed_axioms_only,
                );
                write_sorted_string_list(&mut hasher, "record_axiom", &record.axioms);
            }
        }
        BundleEvidence::BuildIntegrity(value) => {
            write_field(&mut hasher, "kind", "build_integrity");
            write_field(&mut hasher, "bundle_id", &value.bundle_id);
            write_sorted_string_list(&mut hasher, "theorem_id", &value.theorem_ids);
            write_field(
                &mut hasher,
                "private_source_commitment_root",
                &value.private_source_commitment_root,
            );
            write_field(
                &mut hasher,
                "toolchain_identity_digest",
                &value.toolchain_identity_digest,
            );
            write_sorted_string_list(&mut hasher, "metallib_digest", &value.metallib_digests);
        }
    }
    format!("{:x}", hasher.finalize())
}

fn decode_digest_hex(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be a 64-character SHA-256 digest"));
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < 32 {
        let high = decode_hex_nibble(bytes[index * 2])
            .ok_or_else(|| format!("{label} contains a non-hex character"))?;
        let low = decode_hex_nibble(bytes[index * 2 + 1])
            .ok_or_else(|| format!("{label} contains a non-hex character"))?;
        out[index] = (high << 4) | low;
        index += 1;
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn ensure_sorted_match(expected: &[String], found: &[String], label: &str) -> Result<(), String> {
    let mut lhs = expected.to_vec();
    let mut rhs = found.to_vec();
    lhs.sort();
    rhs.sort();
    lhs.dedup();
    rhs.dedup();
    if lhs != rhs {
        return Err(format!(
            "{label} drifted between witness and bundle evidence"
        ));
    }
    Ok(())
}

pub fn validate_bundle_evidence(witness: &BundleWitness) -> Result<String, String> {
    if witness.bundle_id != witness.bundle_evidence.bundle_id() {
        return Err("bundle evidence bundle_id drifted from witness".to_string());
    }
    ensure_sorted_match(
        witness.theorem_ids.as_slice(),
        witness.bundle_evidence.theorem_ids(),
        "theorem ids",
    )?;
    if witness.toolchain_identity_digest != witness.bundle_evidence.toolchain_identity_digest() {
        return Err("toolchain identity digest drifted from bundle evidence".to_string());
    }
    match &witness.bundle_evidence {
        BundleEvidence::TheoremClosure(value) => {
            if value.theorem_records.len() != value.theorem_ids.len() {
                return Err("theorem closure evidence count does not match theorem ids".to_string());
            }
            for record in &value.theorem_records {
                if !value
                    .theorem_ids
                    .iter()
                    .any(|item| item == &record.theorem_id)
                {
                    return Err(
                        "theorem closure evidence referenced an unexpected theorem".to_string()
                    );
                }
                if !record.allowed_axioms_only {
                    return Err("theorem closure evidence reported a disallowed axiom".to_string());
                }
                let _ = decode_digest_hex(&record.proof_artifact_digest, "proof_artifact_digest")?;
            }
        }
        BundleEvidence::BuildIntegrity(value) => {
            if value.private_source_commitment_root != witness.private_source_commitment_root {
                return Err(
                    "build-integrity evidence private source commitment drifted from witness"
                        .to_string(),
                );
            }
            if value.metallib_digests.is_empty() {
                return Err("build-integrity evidence has no metallib digests".to_string());
            }
            for digest in &value.metallib_digests {
                let _ = decode_digest_hex(digest, "metallib_digest")?;
            }
        }
    }
    Ok(canonical_bundle_evidence_digest(&witness.bundle_evidence))
}

pub fn expected_public_values(
    statement_bundle_digest: &str,
    private_source_commitment_root: &str,
    metallib_digest_set_root: &str,
    attestation_manifest_digest: &str,
    toolchain_identity_digest: &str,
    bundle_evidence_digest: &str,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(EXPECTED_PUBLIC_INPUT_BYTES);
    for (label, value) in [
        ("statement_bundle_digest", statement_bundle_digest),
        (
            "private_source_commitment_root",
            private_source_commitment_root,
        ),
        ("metallib_digest_set_root", metallib_digest_set_root),
        ("attestation_manifest_digest", attestation_manifest_digest),
        ("toolchain_identity_digest", toolchain_identity_digest),
        ("bundle_evidence_digest", bundle_evidence_digest),
    ] {
        let decoded = decode_digest_hex(value, label)?;
        out.extend_from_slice(decoded.as_slice());
    }
    Ok(out)
}

pub fn validate_public_input_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != EXPECTED_PUBLIC_INPUT_BYTES {
        return Err(format!(
            "public input bytes length mismatch: expected {EXPECTED_PUBLIC_INPUT_BYTES}, got {}",
            bytes.len()
        ));
    }
    Ok(())
}

pub fn validate_public_groth16_proving_lane(
    proving_lane: &PublicGroth16ProvingLane,
) -> Result<(), String> {
    if proving_lane.backend != PUBLIC_PROOF_BACKEND {
        return Err(format!(
            "public proof backend mismatch: expected {PUBLIC_PROOF_BACKEND}, got {}",
            proving_lane.backend
        ));
    }
    if proving_lane.curve != "bn254" {
        return Err(format!(
            "public proof curve mismatch: expected bn254, got {}",
            proving_lane.curve
        ));
    }
    if !proving_lane.groth16_msm_engine.starts_with("metal-") {
        return Err(format!(
            "Groth16 MSM proving lane is not Metal-backed: {}",
            proving_lane.groth16_msm_engine
        ));
    }
    if !proving_lane.qap_witness_map_engine.starts_with("metal-") {
        return Err(format!(
            "QAP witness-map lane is not Metal-backed: {}",
            proving_lane.qap_witness_map_engine
        ));
    }
    if !proving_lane.metal_no_cpu_fallback {
        return Err("public proving lane reported CPU fallback".to_string());
    }
    let busy_ratio = proving_lane
        .metal_gpu_busy_ratio
        .parse::<f64>()
        .map_err(|err| format!("parse metal_gpu_busy_ratio: {err}"))?;
    if busy_ratio.partial_cmp(&0.0) != Some(Ordering::Greater) {
        return Err(format!(
            "metal_gpu_busy_ratio must be > 0 for the public proving lane, got {}",
            proving_lane.metal_gpu_busy_ratio
        ));
    }
    Ok(())
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn theorem_closure_evidence() -> BundleEvidence {
        BundleEvidence::TheoremClosure(TheoremClosureBundleEvidence {
            bundle_id: "kernel-families".to_string(),
            theorem_ids: vec!["gpu.hash_differential_bounded".to_string()],
            toolchain_identity_digest: "1".repeat(64),
            theorem_records: vec![TheoremRecord {
                theorem_id: "gpu.hash_differential_bounded".to_string(),
                checker: "lean".to_string(),
                decl_name: "hash_family_exact_digest_sound".to_string(),
                module_name: "Hash".to_string(),
                proof_artifact_kind: "olean".to_string(),
                proof_artifact_digest: "2".repeat(64),
                allowed_axioms_only: true,
                axioms: vec!["Quot.sound".to_string()],
            }],
        })
    }

    fn build_integrity_evidence() -> BundleEvidence {
        BundleEvidence::BuildIntegrity(BuildIntegrityBundleEvidence {
            bundle_id: "build-integrity".to_string(),
            theorem_ids: vec!["public.build_integrity_commitment".to_string()],
            private_source_commitment_root: "3".repeat(64),
            toolchain_identity_digest: "4".repeat(64),
            metallib_digests: vec!["5".repeat(64)],
        })
    }

    fn witness(evidence: BundleEvidence) -> BundleWitness {
        BundleWitness {
            bundle_id: evidence.bundle_id().to_string(),
            theorem_ids: evidence.theorem_ids().to_vec(),
            statement_bundle_digest: "6".repeat(64),
            private_source_commitment_root: "7".repeat(64),
            metallib_digest_set_root: "8".repeat(64),
            attestation_manifest_digest: "9".repeat(64),
            toolchain_identity_digest: evidence.toolchain_identity_digest().to_string(),
            bundle_evidence: evidence,
        }
    }

    #[test]
    fn human_readable_bundle_evidence_keeps_kind_tag() {
        let serialized =
            serde_json::to_string(&theorem_closure_evidence()).expect("serialize json");
        assert!(serialized.contains("\"kind\":\"theorem_closure\""));
    }

    #[test]
    fn binary_bundle_evidence_round_trips_theorem_closure() {
        let encoded =
            bincode::serialize(&witness(theorem_closure_evidence())).expect("serialize bincode");
        let decoded: BundleWitness = bincode::deserialize(&encoded).expect("deserialize bincode");
        assert_eq!(decoded.bundle_id, "kernel-families");
        match decoded.bundle_evidence {
            BundleEvidence::TheoremClosure(inner) => {
                assert_eq!(inner.theorem_records.len(), 1);
            }
            BundleEvidence::BuildIntegrity(_) => panic!("expected theorem closure"),
        }
    }

    #[test]
    fn binary_bundle_evidence_round_trips_build_integrity() {
        let encoded =
            bincode::serialize(&witness(build_integrity_evidence())).expect("serialize bincode");
        let decoded: BundleWitness = bincode::deserialize(&encoded).expect("deserialize bincode");
        assert_eq!(decoded.bundle_id, "build-integrity");
        match decoded.bundle_evidence {
            BundleEvidence::BuildIntegrity(inner) => {
                assert_eq!(inner.metallib_digests.len(), 1);
            }
            BundleEvidence::TheoremClosure(_) => panic!("expected build integrity"),
        }
    }

    #[test]
    fn expected_public_values_concatenates_all_roots() {
        let bytes = expected_public_values(
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            &"4".repeat(64),
            &"5".repeat(64),
            &"6".repeat(64),
        )
        .expect("public inputs");
        assert_eq!(bytes.len(), EXPECTED_PUBLIC_INPUT_BYTES);
        assert_eq!(bytes[0..32], vec![0x11; 32]);
        assert_eq!(bytes[32..64], vec![0x22; 32]);
        assert_eq!(bytes[64..96], vec![0x33; 32]);
        assert_eq!(bytes[96..128], vec![0x44; 32]);
        assert_eq!(bytes[128..160], vec![0x55; 32]);
        assert_eq!(bytes[160..192], vec![0x66; 32]);
    }

    #[test]
    fn groth16_proving_lane_requires_metal_and_no_cpu_fallback() {
        let lane = PublicGroth16ProvingLane {
            backend: PUBLIC_PROOF_BACKEND.to_string(),
            curve: "bn254".to_string(),
            groth16_msm_engine: "metal-bn254-msm".to_string(),
            qap_witness_map_engine: "metal-bn254-ntt+streamed-reduction".to_string(),
            metal_no_cpu_fallback: true,
            metal_gpu_busy_ratio: "1.000".to_string(),
            metal_counter_source: "release-proof".to_string(),
            release_metadata: BTreeMap::new(),
        };
        validate_public_groth16_proving_lane(&lane).expect("valid proving lane");
        validate_public_input_bytes(&vec![0u8; EXPECTED_PUBLIC_INPUT_BYTES])
            .expect("correct byte count");
    }

    #[test]
    fn groth16_proving_lane_rejects_cpu_fallback() {
        let lane = PublicGroth16ProvingLane {
            backend: PUBLIC_PROOF_BACKEND.to_string(),
            curve: "bn254".to_string(),
            groth16_msm_engine: "cpu-msm".to_string(),
            qap_witness_map_engine: "ark-libsnark-reduction".to_string(),
            metal_no_cpu_fallback: false,
            metal_gpu_busy_ratio: "0.000".to_string(),
            metal_counter_source: "not-measured".to_string(),
            release_metadata: BTreeMap::new(),
        };
        assert!(validate_public_groth16_proving_lane(&lane).is_err());
    }
}
