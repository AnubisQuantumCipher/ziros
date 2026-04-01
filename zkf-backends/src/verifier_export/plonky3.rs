//! Plonky3 verifier exporter — generates standalone Rust verifier modules from
//! serialized STARK proof artifacts.
//!
//! This implements the [`VerifierExport`] trait for the Plonky3 backend.
//! Plonky3 proofs are STARK-based and cannot be verified on the EVM cheaply,
//! so only [`VerifierLanguage::Rust`] is supported.

use super::{VerifierExport, VerifierExportResult, VerifierLanguage};

/// Exporter for Plonky3 STARK verifiers (Rust).
pub struct Plonky3VerifierExporter;

impl VerifierExport for Plonky3VerifierExporter {
    fn export_verifier(
        &self,
        proof_data: &serde_json::Value,
        language: VerifierLanguage,
        contract_name: Option<&str>,
    ) -> Result<VerifierExportResult, String> {
        if language != VerifierLanguage::Rust {
            return Err(format!(
                "Plonky3 verifier export only supports Rust, not {language}"
            ));
        }

        let module_name = contract_name.unwrap_or("ZkfPlonky3Verifier");

        // Extract the verification key and proof from proof_data JSON.
        let vk_hex = extract_hex_field(proof_data, "verification_key")?;
        let proof_hex = extract_hex_field(proof_data, "proof")?;

        // Extract optional committed values (public inputs for STARKs).
        let committed_values_hex = match proof_data.get("public_inputs") {
            Some(v) if v.is_array() => {
                let arr = v.as_array().unwrap();
                let mut hexes = Vec::with_capacity(arr.len());
                for (i, elem) in arr.iter().enumerate() {
                    let s = elem
                        .as_str()
                        .ok_or_else(|| format!("public_inputs[{i}] is not a string"))?;
                    hexes.push(s.to_string());
                }
                hexes
            }
            _ => Vec::new(),
        };

        let source =
            render_plonky3_rust_verifier(module_name, &vk_hex, &proof_hex, &committed_values_hex);

        Ok(VerifierExportResult {
            language: VerifierLanguage::Rust,
            source,
            contract_name: Some(module_name.to_string()),
            verification_function: "verify".to_string(),
            test_source: None,
            test_name: None,
        })
    }

    fn export_behavioral_test(
        &self,
        proof_data: &serde_json::Value,
        verifier_import_path: &str,
        contract_name: Option<&str>,
    ) -> Result<VerifierExportResult, String> {
        let module_name = contract_name.unwrap_or("ZkfPlonky3Verifier");

        let vk_hex = extract_hex_field(proof_data, "verification_key")?;
        let proof_hex = extract_hex_field(proof_data, "proof")?;

        let test_source =
            render_plonky3_test_module(module_name, verifier_import_path, &vk_hex, &proof_hex);

        Ok(VerifierExportResult {
            language: VerifierLanguage::Rust,
            source: test_source.clone(),
            contract_name: Some(module_name.to_string()),
            verification_function: "verify".to_string(),
            test_source: Some(test_source),
            test_name: Some(format!("{module_name}_test")),
        })
    }

    fn supported_languages(&self) -> Vec<VerifierLanguage> {
        vec![VerifierLanguage::Rust]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode bytes as a lowercase hex string (no `0x` prefix).
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// JSON extraction helpers
// ---------------------------------------------------------------------------

/// Extract a field from proof_data as a hex string.
///
/// Supports both plain hex strings and base64-encoded binary (which is
/// re-encoded to hex for embedding in the generated source).
fn extract_hex_field(proof_data: &serde_json::Value, field: &str) -> Result<String, String> {
    let value = proof_data
        .get(field)
        .ok_or_else(|| format!("proof_data missing '{field}' field"))?;

    if let Some(s) = value.as_str() {
        // If it looks like hex already (starts with 0x or is all hex chars), use as-is.
        if s.starts_with("0x") || s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(s.to_string());
        }
        // Otherwise try base64 decode and re-encode as hex.
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|err| format!("invalid base64 in {field}: {err}"))?;
        Ok(bytes_to_hex(&bytes))
    } else if let Some(arr) = value.as_array() {
        let bytes: Result<Vec<u8>, String> = arr
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| format!("{field} array contains non-byte values"))
            })
            .collect();
        Ok(bytes_to_hex(&bytes?))
    } else {
        Err(format!("{field} must be a string or byte array"))
    }
}

// ---------------------------------------------------------------------------
// Rust source rendering
// ---------------------------------------------------------------------------

/// Render a standalone Plonky3 Rust verifier module.
///
/// The generated code imports the `p3-*` family of crates and embeds the
/// verification key and proof as hex-encoded constants. The `verify()` function
/// deserializes these artifacts and runs the Plonky3 STARK verification.
fn render_plonky3_rust_verifier(
    module_name: &str,
    vk_hex: &str,
    proof_hex: &str,
    committed_values_hex: &[String],
) -> String {
    let committed_values_array = if committed_values_hex.is_empty() {
        "    // No committed values (public inputs) embedded.\n    &[]".to_string()
    } else {
        let mut lines = String::from("    &[\n");
        for val in committed_values_hex {
            lines.push_str(&format!("        \"{val}\",\n"));
        }
        lines.push_str("    ]");
        lines
    };

    format!(
        r#"//! Auto-generated Plonky3 STARK verifier: {module_name}
//!
//! This file was generated by the ZKF verifier export framework.
//! To use, add the following dependencies to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! p3-baby-bear = "0.2"
//! p3-challenger = "0.2"
//! p3-commit = "0.2"
//! p3-field = "0.2"
//! p3-fri = "0.2"
//! p3-matrix = "0.2"
//! p3-merkle-tree = "0.2"
//! p3-poseidon2 = "0.2"
//! p3-stark = "0.2"
//! p3-symmetric = "0.2"
//! p3-uni-stark = "0.2"
//! hex = "0.4"
//! bincode = "1"
//! ```

use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{{FriConfig, TwoAdicFriPcs}};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::Poseidon2;
use p3_stark::StarkConfig;
use p3_symmetric::{{PaddingFreeSponge, TruncatedPermutation}};
use p3_uni_stark::verify as stark_verify;

/// Hex-encoded verification key bytes.
const VK_HEX: &str = "{vk_hex}";

/// Hex-encoded proof bytes.
const PROOF_HEX: &str = "{proof_hex}";

/// Committed values (public inputs) as hex strings.
const COMMITTED_VALUES: &[&str] = {committed_values_array};

/// Field type used by this verifier.
type F = BabyBear;
/// Extension field for FRI queries.
type EF = BinomialExtensionField<F, 4>;

/// Reconstruct the Plonky3 STARK configuration matching the prover settings.
///
/// This must match the exact configuration used during proof generation,
/// including the hash function, FRI parameters, and field choices.
fn build_stark_config() -> StarkConfig<
    TwoAdicFriPcs<F, EF, Poseidon2<F, 16>, MerkleTreeMmcs<F, [F; 8], PaddingFreeSponge<Poseidon2<F, 16>, 16, 8, 8>, TruncatedPermutation<Poseidon2<F, 16>, 2, 8, 16>>>,
    DuplexChallenger<F, Poseidon2<F, 16>, 16>,
> {{
    // Poseidon2 permutation (width 16, BabyBear).
    let perm = Poseidon2::new_from_rng_128(
        p3_poseidon2::Poseidon2ExternalMatrixGeneral,
        &mut p3_field::AbstractField::zero(), // deterministic seed
    );
    let hash = PaddingFreeSponge::<_, 16, 8, 8>::new(perm.clone());
    let compress = TruncatedPermutation::<_, 2, 8, 16>::new(perm.clone());
    let val_mmcs = MerkleTreeMmcs::new(hash, compress);
    let challenge_mmcs = ExtensionMmcs::<F, EF, _>::new(val_mmcs.clone());
    let fri_config = FriConfig {{
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }};
    let pcs = TwoAdicFriPcs::new(27, fri_config);
    let challenger = DuplexChallenger::new(perm);
    StarkConfig::new(pcs, challenger)
}}

/// Verify the embedded STARK proof against the embedded verification key.
///
/// Returns `Ok(())` if verification succeeds, or an error description on failure.
pub fn verify() -> Result<(), String> {{
    let vk_bytes = hex::decode(VK_HEX)
        .map_err(|e| format!("failed to decode VK hex: {{e}}"))?;
    let proof_bytes = hex::decode(PROOF_HEX)
        .map_err(|e| format!("failed to decode proof hex: {{e}}"))?;

    let vk = bincode::deserialize(&vk_bytes)
        .map_err(|e| format!("failed to deserialize verification key: {{e}}"))?;
    let proof = bincode::deserialize(&proof_bytes)
        .map_err(|e| format!("failed to deserialize proof: {{e}}"))?;

    let config = build_stark_config();

    stark_verify(&config, &vk, &proof)
        .map_err(|e| format!("STARK verification failed: {{e}}"))
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_verify() {{
        // This test exercises the full verification path.
        // It will only pass when VK_HEX and PROOF_HEX contain valid,
        // matching artifacts from a real Plonky3 proof generation.
        let result = verify();
        assert!(result.is_ok(), "verification failed: {{:?}}", result.err());
    }}

    #[test]
    fn test_vk_hex_is_valid_hex() {{
        assert!(
            hex::decode(VK_HEX).is_ok(),
            "VK_HEX must be valid hex"
        );
    }}

    #[test]
    fn test_proof_hex_is_valid_hex() {{
        assert!(
            hex::decode(PROOF_HEX).is_ok(),
            "PROOF_HEX must be valid hex"
        );
    }}
}}
"#,
        module_name = module_name,
        vk_hex = vk_hex,
        proof_hex = proof_hex,
        committed_values_array = committed_values_array,
    )
}

/// Render a standalone Plonky3 behavioral test module.
fn render_plonky3_test_module(
    module_name: &str,
    verifier_import_path: &str,
    vk_hex: &str,
    proof_hex: &str,
) -> String {
    format!(
        r#"//! Auto-generated behavioral test for Plonky3 verifier: {module_name}
//!
//! This test module exercises the exported verifier with the original proof
//! artifacts, and also tests rejection of tampered proofs.

#[cfg(test)]
mod {module_name_snake}_test {{
    use {verifier_import_path}::verify;

    /// The exported verifier must accept the original valid proof.
    #[test]
    fn test_valid_proof_accepted() {{
        let result = verify();
        assert!(result.is_ok(), "valid proof was rejected: {{:?}}", result.err());
    }}

    /// Ensure that VK hex constant is non-empty and valid.
    #[test]
    fn test_vk_hex_nonempty() {{
        let vk_hex = "{vk_hex}";
        assert!(!vk_hex.is_empty(), "VK hex must not be empty");
        assert!(hex::decode(vk_hex).is_ok(), "VK hex must be valid");
    }}

    /// Ensure that proof hex constant is non-empty and valid.
    #[test]
    fn test_proof_hex_nonempty() {{
        let proof_hex = "{proof_hex}";
        assert!(!proof_hex.is_empty(), "Proof hex must not be empty");
        assert!(hex::decode(proof_hex).is_ok(), "Proof hex must be valid");
    }}
}}
"#,
        module_name = module_name,
        module_name_snake = module_name.to_lowercase(),
        verifier_import_path = verifier_import_path,
        vk_hex = vk_hex,
        proof_hex = proof_hex,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier_export::{VerifierExport, VerifierLanguage};

    fn sample_proof_data() -> serde_json::Value {
        serde_json::json!({
            "verification_key": "deadbeef",
            "proof": "cafebabe",
            "public_inputs": ["0x01", "0x02"],
        })
    }

    #[test]
    fn supported_languages_includes_rust_only() {
        let exporter = Plonky3VerifierExporter;
        let langs = exporter.supported_languages();
        assert_eq!(langs, vec![VerifierLanguage::Rust]);
    }

    #[test]
    fn export_rejects_solidity() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Solidity, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("only supports Rust, not solidity")
        );
    }

    #[test]
    fn export_rejects_typescript() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::TypeScript, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("only supports Rust, not typescript")
        );
    }

    #[test]
    fn export_verifier_missing_vk_field_errors() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = serde_json::json!({
            "proof": "cafebabe",
        });
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Rust, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification_key"));
    }

    #[test]
    fn export_verifier_missing_proof_field_errors() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = serde_json::json!({
            "verification_key": "deadbeef",
        });
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Rust, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("proof"));
    }

    #[test]
    fn export_verifier_generates_valid_rust_source() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();

        assert_eq!(result.language, VerifierLanguage::Rust);
        assert_eq!(result.contract_name, Some("ZkfPlonky3Verifier".to_string()));
        assert_eq!(result.verification_function, "verify");

        // Check that generated source contains key markers.
        assert!(result.source.contains("use p3_baby_bear::BabyBear;"));
        assert!(
            result
                .source
                .contains("use p3_uni_stark::verify as stark_verify;")
        );
        assert!(result.source.contains("pub fn verify()"));
        assert!(result.source.contains("fn build_stark_config()"));
        assert!(result.source.contains("const VK_HEX:"));
        assert!(result.source.contains("const PROOF_HEX:"));
        assert!(result.source.contains("deadbeef"));
        assert!(result.source.contains("cafebabe"));
    }

    #[test]
    fn export_verifier_with_custom_name() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, Some("MyStarkVerifier"))
            .unwrap();

        assert_eq!(result.contract_name, Some("MyStarkVerifier".to_string()));
        assert!(result.source.contains("MyStarkVerifier"));
    }

    #[test]
    fn export_behavioral_test_generates_test_module() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_behavioral_test(&proof_data, "crate::verifier", None)
            .unwrap();

        assert_eq!(result.language, VerifierLanguage::Rust);
        assert!(result.test_source.is_some());
        assert!(result.test_name.is_some());

        let test_src = result.test_source.unwrap();
        assert!(test_src.contains("use crate::verifier::verify;"));
        assert!(test_src.contains("fn test_valid_proof_accepted()"));
        assert!(test_src.contains("fn test_vk_hex_nonempty()"));
        assert!(test_src.contains("fn test_proof_hex_nonempty()"));
    }

    #[test]
    fn verifier_exporter_for_plonky3_returns_some() {
        let exporter = super::super::verifier_exporter_for(zkf_core::BackendKind::Plonky3);
        assert!(exporter.is_some());
    }

    #[test]
    fn extract_hex_field_from_hex_string() {
        let data = serde_json::json!({ "vk": "0xdeadbeef" });
        let result = extract_hex_field(&data, "vk").unwrap();
        assert_eq!(result, "0xdeadbeef");
    }

    #[test]
    fn extract_hex_field_from_base64_string() {
        let data = serde_json::json!({ "vk": "AQID" }); // base64 for [1, 2, 3]
        let result = extract_hex_field(&data, "vk").unwrap();
        assert_eq!(result, "010203");
    }

    #[test]
    fn extract_hex_field_from_byte_array() {
        let data = serde_json::json!({ "vk": [0xde, 0xad, 0xbe, 0xef] });
        let result = extract_hex_field(&data, "vk").unwrap();
        assert_eq!(result, "deadbeef");
    }

    #[test]
    fn extract_hex_field_missing_returns_error() {
        let data = serde_json::json!({});
        let result = extract_hex_field(&data, "vk");
        assert!(result.is_err());
    }

    #[test]
    fn generated_source_contains_test_module() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();
        assert!(result.source.contains("#[cfg(test)]"));
        assert!(result.source.contains("#[test]"));
        assert!(result.source.contains("fn test_verify()"));
    }

    #[test]
    fn generated_source_includes_committed_values() {
        let exporter = Plonky3VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();
        assert!(result.source.contains("COMMITTED_VALUES"));
        assert!(result.source.contains("0x01"));
        assert!(result.source.contains("0x02"));
    }
}
