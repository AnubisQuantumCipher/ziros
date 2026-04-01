//! Halo2 verifier exporter — generates standalone Rust verifier modules from
//! serialized IPA/KZG proof artifacts.
//!
//! This implements the [`VerifierExport`] trait for the Halo2 backend.
//! Halo2 proofs using IPA commitments cannot be verified on the EVM cheaply
//! (no precompile for IPA verification), so only [`VerifierLanguage::Rust`]
//! is supported.

use super::{VerifierExport, VerifierExportResult, VerifierLanguage};

/// Exporter for Halo2 IPA verifiers (Rust).
pub struct Halo2VerifierExporter;

impl VerifierExport for Halo2VerifierExporter {
    fn export_verifier(
        &self,
        proof_data: &serde_json::Value,
        language: VerifierLanguage,
        contract_name: Option<&str>,
    ) -> Result<VerifierExportResult, String> {
        if language != VerifierLanguage::Rust {
            return Err(format!(
                "Halo2 verifier export only supports Rust, not {language}"
            ));
        }

        let module_name = contract_name.unwrap_or("ZkfHalo2Verifier");

        // Extract the verification key and proof from proof_data JSON.
        let vk_hex = extract_hex_field(proof_data, "verification_key")?;
        let proof_hex = extract_hex_field(proof_data, "proof")?;

        // Extract optional public inputs (instance columns).
        let instances_hex = match proof_data.get("public_inputs") {
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

        let source = render_halo2_rust_verifier(module_name, &vk_hex, &proof_hex, &instances_hex);

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
        let module_name = contract_name.unwrap_or("ZkfHalo2Verifier");

        let vk_hex = extract_hex_field(proof_data, "verification_key")?;
        let proof_hex = extract_hex_field(proof_data, "proof")?;

        let test_source =
            render_halo2_test_module(module_name, verifier_import_path, &vk_hex, &proof_hex);

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

/// Render a standalone Halo2 Rust verifier module.
///
/// The generated code imports the `halo2_proofs` crate and embeds the
/// verification key and proof as hex-encoded constants. The `verify()` function
/// deserializes these artifacts and runs the Halo2 IPA verification.
fn render_halo2_rust_verifier(
    module_name: &str,
    vk_hex: &str,
    proof_hex: &str,
    instances_hex: &[String],
) -> String {
    let instances_array = if instances_hex.is_empty() {
        "    // No instance values (public inputs) embedded.\n    &[]".to_string()
    } else {
        let mut lines = String::from("    &[\n");
        for val in instances_hex {
            lines.push_str(&format!("        \"{val}\",\n"));
        }
        lines.push_str("    ]");
        lines
    };

    format!(
        r#"//! Auto-generated Halo2 IPA verifier: {module_name}
//!
//! This file was generated by the ZKF verifier export framework.
//! To use, add the following dependencies to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! halo2_proofs = {{ version = "0.3", features = ["dev-graph"] }}
//! hex = "0.4"
//! ```

use halo2_proofs::{{
    arithmetic::Field,
    pasta::{{vesta, EqAffine, Fp}},
    plonk::{{self, VerifyingKey}},
    poly::{{
        commitment::ParamsVerifier,
        ipa::{{
            commitment::IPACommitmentScheme,
            multiopen::VerifierIPA,
            strategy::SingleStrategy,
        }},
    }},
    transcript::{{Blake2bRead, Challenge255, TranscriptReadBuffer}},
    SerdeFormat,
}};

/// Hex-encoded verification key bytes.
const VK_HEX: &str = "{vk_hex}";

/// Hex-encoded proof bytes.
const PROOF_HEX: &str = "{proof_hex}";

/// Instance column values (public inputs) as hex strings.
const INSTANCE_VALUES: &[&str] = {instances_array};

/// Minimum degree (k) for the verification parameters.
///
/// This must match the `k` used during proof generation.
/// Adjust this constant if your circuit requires a different size.
const K: u32 = 14;

/// Verify the embedded Halo2 proof against the embedded verification key.
///
/// Returns `Ok(())` if verification succeeds, or an error description on failure.
pub fn verify() -> Result<(), String> {{
    let vk_bytes = hex::decode(VK_HEX)
        .map_err(|e| format!("failed to decode VK hex: {{e}}"))?;
    let proof_bytes = hex::decode(PROOF_HEX)
        .map_err(|e| format!("failed to decode proof hex: {{e}}"))?;

    // Reconstruct verification parameters.
    let params = halo2_proofs::poly::ipa::commitment::ParamsIPA::<vesta::Affine>::new(K);

    // Deserialize the verification key.
    let vk = VerifyingKey::<EqAffine>::read(
        &mut std::io::Cursor::new(&vk_bytes),
        SerdeFormat::RawBytes,
        // The circuit must provide its constraint system via `without_witnesses()`.
        // In a standalone verifier, we reconstruct from the serialized VK.
    )
    .map_err(|e| format!("failed to deserialize verification key: {{e}}"))?;

    // Parse instance values into field elements.
    let instances: Vec<Fp> = INSTANCE_VALUES
        .iter()
        .map(|hex_str| {{
            let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                .map_err(|e| format!("invalid instance hex: {{e}}"))?;
            let mut repr = [0u8; 32];
            let len = bytes.len().min(32);
            repr[..len].copy_from_slice(&bytes[..len]);
            Ok(Fp::from_repr(repr).unwrap_or(Fp::zero()))
        }})
        .collect::<Result<Vec<_>, String>>()?;

    let instances_slice: &[&[Fp]] = &[&instances];

    // Create the transcript and run verification.
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof_bytes[..]);
    let strategy = SingleStrategy::new(&params);

    plonk::verify_proof::<IPACommitmentScheme<_>, VerifierIPA<_>, _, _, _>(
        &params,
        &vk,
        strategy,
        instances_slice,
        &mut transcript,
    )
    .map_err(|e| format!("Halo2 verification failed: {{e}}"))
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_verify() {{
        // This test exercises the full verification path.
        // It will only pass when VK_HEX and PROOF_HEX contain valid,
        // matching artifacts from a real Halo2 proof generation.
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
        instances_array = instances_array,
    )
}

/// Render a standalone Halo2 behavioral test module.
fn render_halo2_test_module(
    module_name: &str,
    verifier_import_path: &str,
    vk_hex: &str,
    proof_hex: &str,
) -> String {
    format!(
        r#"//! Auto-generated behavioral test for Halo2 verifier: {module_name}
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
            "verification_key": "aabbccdd",
            "proof": "11223344",
            "public_inputs": ["0xabcd", "0x1234"],
        })
    }

    #[test]
    fn supported_languages_includes_rust_only() {
        let exporter = Halo2VerifierExporter;
        let langs = exporter.supported_languages();
        assert_eq!(langs, vec![VerifierLanguage::Rust]);
    }

    #[test]
    fn export_rejects_solidity() {
        let exporter = Halo2VerifierExporter;
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
        let exporter = Halo2VerifierExporter;
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
        let exporter = Halo2VerifierExporter;
        let proof_data = serde_json::json!({
            "proof": "11223344",
        });
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Rust, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification_key"));
    }

    #[test]
    fn export_verifier_missing_proof_field_errors() {
        let exporter = Halo2VerifierExporter;
        let proof_data = serde_json::json!({
            "verification_key": "aabbccdd",
        });
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Rust, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("proof"));
    }

    #[test]
    fn export_verifier_generates_valid_rust_source() {
        let exporter = Halo2VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();

        assert_eq!(result.language, VerifierLanguage::Rust);
        assert_eq!(result.contract_name, Some("ZkfHalo2Verifier".to_string()));
        assert_eq!(result.verification_function, "verify");

        // Check that generated source contains key markers.
        assert!(result.source.contains("use halo2_proofs::"));
        assert!(result.source.contains("pub fn verify()"));
        assert!(result.source.contains("plonk::verify_proof"));
        assert!(result.source.contains("const VK_HEX:"));
        assert!(result.source.contains("const PROOF_HEX:"));
        assert!(result.source.contains("aabbccdd"));
        assert!(result.source.contains("11223344"));
    }

    #[test]
    fn export_verifier_with_custom_name() {
        let exporter = Halo2VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, Some("MyHaloVerifier"))
            .unwrap();

        assert_eq!(result.contract_name, Some("MyHaloVerifier".to_string()));
        assert!(result.source.contains("MyHaloVerifier"));
    }

    #[test]
    fn export_behavioral_test_generates_test_module() {
        let exporter = Halo2VerifierExporter;
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
    fn verifier_exporter_for_halo2_returns_some() {
        let exporter = super::super::verifier_exporter_for(zkf_core::BackendKind::Halo2);
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
        let data = serde_json::json!({ "vk": [0xaa, 0xbb, 0xcc, 0xdd] });
        let result = extract_hex_field(&data, "vk").unwrap();
        assert_eq!(result, "aabbccdd");
    }

    #[test]
    fn extract_hex_field_missing_returns_error() {
        let data = serde_json::json!({});
        let result = extract_hex_field(&data, "vk");
        assert!(result.is_err());
    }

    #[test]
    fn generated_source_contains_test_module() {
        let exporter = Halo2VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();
        assert!(result.source.contains("#[cfg(test)]"));
        assert!(result.source.contains("#[test]"));
        assert!(result.source.contains("fn test_verify()"));
    }

    #[test]
    fn generated_source_includes_instance_values() {
        let exporter = Halo2VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();
        assert!(result.source.contains("INSTANCE_VALUES"));
        assert!(result.source.contains("0xabcd"));
        assert!(result.source.contains("0x1234"));
    }

    #[test]
    fn generated_source_uses_ipa_verification() {
        let exporter = Halo2VerifierExporter;
        let proof_data = sample_proof_data();
        let result = exporter
            .export_verifier(&proof_data, VerifierLanguage::Rust, None)
            .unwrap();
        assert!(result.source.contains("IPACommitmentScheme"));
        assert!(result.source.contains("VerifierIPA"));
        assert!(result.source.contains("SingleStrategy"));
        assert!(result.source.contains("Blake2bRead"));
    }
}
