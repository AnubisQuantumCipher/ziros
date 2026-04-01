//! Groth16 verifier exporter — generates Solidity verifier contracts and Foundry tests
//! from serialized proof artifacts.
//!
//! This implements the [`VerifierExport`] trait for the ArkworksGroth16 backend.
//! It reuses the existing [`groth16_vk`](crate::groth16_vk) and
//! [`foundry_test`](crate::foundry_test) modules for the heavy lifting.

use super::{VerifierExport, VerifierExportResult, VerifierLanguage};

/// Exporter for Groth16 BN254 verifiers (Solidity).
pub struct Groth16VerifierExporter;

impl VerifierExport for Groth16VerifierExporter {
    fn export_verifier(
        &self,
        proof_data: &serde_json::Value,
        language: VerifierLanguage,
        contract_name: Option<&str>,
    ) -> Result<VerifierExportResult, String> {
        if language != VerifierLanguage::Solidity {
            return Err(format!(
                "Groth16 verifier export only supports Solidity, not {language}"
            ));
        }

        let contract_name = contract_name.unwrap_or("ZkfGroth16Verifier");

        // Extract the verification key bytes (base64-encoded in ProofArtifact JSON).
        let vk_bytes = extract_vk_bytes(proof_data)?;
        let parsed_vk = crate::groth16_vk::decode_groth16_vk(&vk_bytes).ok_or(
            "failed to decode Groth16 verification key: refusing to emit verifier with invalid VK",
        )?;

        let source = render_groth16_solidity(&parsed_vk, contract_name);

        Ok(VerifierExportResult {
            language: VerifierLanguage::Solidity,
            source,
            contract_name: Some(contract_name.to_string()),
            verification_function: "verifyProof".to_string(),
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
        let contract_name = contract_name.unwrap_or("ZkfGroth16Verifier");

        // Extract proof bytes and public inputs.
        let proof_bytes = extract_proof_bytes(proof_data)?;
        let public_inputs = extract_public_inputs(proof_data)?;

        let public_inputs_fe: Vec<zkf_core::FieldElement> = public_inputs
            .iter()
            .map(|s| zkf_core::FieldElement::new(s.as_str()))
            .collect();

        let test_output = crate::foundry_test::generate_foundry_test_from_artifact(
            &proof_bytes,
            &public_inputs_fe,
            verifier_import_path,
            contract_name,
        )?;

        Ok(VerifierExportResult {
            language: VerifierLanguage::Solidity,
            source: test_output.source.clone(),
            contract_name: Some(contract_name.to_string()),
            verification_function: "verifyProof".to_string(),
            test_source: Some(test_output.source),
            test_name: Some(test_output.test_name),
        })
    }

    fn supported_languages(&self) -> Vec<VerifierLanguage> {
        vec![VerifierLanguage::Solidity]
    }
}

// ---------------------------------------------------------------------------
// JSON extraction helpers
// ---------------------------------------------------------------------------

/// Extract `verification_key` from a proof artifact JSON value.
///
/// Supports both base64-encoded strings (matching `ProofArtifact` serialization)
/// and raw byte arrays.
fn extract_vk_bytes(proof_data: &serde_json::Value) -> Result<Vec<u8>, String> {
    let vk_value = proof_data
        .get("verification_key")
        .ok_or("proof_data missing 'verification_key' field")?;

    if let Some(b64) = vk_value.as_str() {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|err| format!("invalid base64 in verification_key: {err}"))
    } else if let Some(arr) = vk_value.as_array() {
        arr.iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| "verification_key array contains non-byte values".to_string())
            })
            .collect()
    } else {
        Err("verification_key must be a base64 string or byte array".to_string())
    }
}

/// Extract `proof` bytes from a proof artifact JSON value.
fn extract_proof_bytes(proof_data: &serde_json::Value) -> Result<Vec<u8>, String> {
    let proof_value = proof_data
        .get("proof")
        .ok_or("proof_data missing 'proof' field")?;

    if let Some(b64) = proof_value.as_str() {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|err| format!("invalid base64 in proof: {err}"))
    } else if let Some(arr) = proof_value.as_array() {
        arr.iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| "proof array contains non-byte values".to_string())
            })
            .collect()
    } else {
        Err("proof must be a base64 string or byte array".to_string())
    }
}

/// Extract public inputs from a proof artifact JSON value.
///
/// Returns decimal string representations of each public input.
fn extract_public_inputs(proof_data: &serde_json::Value) -> Result<Vec<String>, String> {
    let inputs = proof_data
        .get("public_inputs")
        .and_then(|v| v.as_array())
        .ok_or("proof_data missing 'public_inputs' array")?;

    inputs
        .iter()
        .enumerate()
        .map(|(i, v)| {
            // ProofArtifact serializes FieldElement; try string first, then number.
            if let Some(s) = v.as_str() {
                Ok(s.to_string())
            } else if let Some(n) = v.as_i64() {
                Ok(n.to_string())
            } else if let Some(obj) = v.as_object() {
                // FieldElement serializes as {"value": "..."} or similar.
                if let Some(val) = obj.get("value").and_then(|v| v.as_str()) {
                    Ok(val.to_string())
                } else {
                    let repr = serde_json::to_string(v)
                        .unwrap_or_else(|_| v.to_string());
                    Err(format!(
                        "public input at index {i} missing or unparseable: object has no 'value' string field: {repr}"
                    ))
                }
            } else {
                Err(format!(
                    "public_inputs[{i}] is not a recognized format: {v}"
                ))
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Solidity rendering
// ---------------------------------------------------------------------------

/// Render a complete Groth16 Solidity verifier contract from parsed VK data.
///
/// This produces the same Pairing-library-based contract that the CLI deploy
/// flow generates, ensuring on-chain compatibility.
fn render_groth16_solidity(
    parsed: &crate::groth16_vk::Groth16VkHex,
    contract_name: &str,
) -> String {
    let alpha_x = &parsed.alpha_g1[0];
    let alpha_y = &parsed.alpha_g1[1];
    let beta_x1 = &parsed.beta_g2[0];
    let beta_x2 = &parsed.beta_g2[1];
    let beta_y1 = &parsed.beta_g2[2];
    let beta_y2 = &parsed.beta_g2[3];
    let gamma_x1 = &parsed.gamma_g2[0];
    let gamma_x2 = &parsed.gamma_g2[1];
    let gamma_y1 = &parsed.gamma_g2[2];
    let gamma_y2 = &parsed.gamma_g2[3];
    let delta_x1 = &parsed.delta_g2[0];
    let delta_x2 = &parsed.delta_g2[1];
    let delta_y1 = &parsed.delta_g2[2];
    let delta_y2 = &parsed.delta_g2[3];

    let mut ic_elements = String::new();
    for (idx, point) in parsed.ic.iter().enumerate() {
        ic_elements.push_str(&format!(
            "        vk.IC[{idx}] = Pairing.G1Point(uint256({x}), uint256({y}));\n",
            x = point[0],
            y = point[1],
        ));
    }

    let ic_len = parsed.ic.len();

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library Pairing {{
    struct G1Point {{
        uint256 X;
        uint256 Y;
    }}

    struct G2Point {{
        uint256[2] X;
        uint256[2] Y;
    }}

    function negate(G1Point memory p) internal pure returns (G1Point memory r) {{
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }}

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            switch success case 0 {{ invalid() }}
        }}
        require(success, "pairing-add-failed");
    }}

    function scalarMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {{
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success case 0 {{ invalid() }}
        }}
        require(success, "pairing-mul-failed");
    }}

    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {{
        require(p1.length == p2.length, "pairing-lengths-failed");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {{
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }}
        uint256[1] memory out;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            switch success case 0 {{ invalid() }}
        }}
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }}

    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {{
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1; p2[0] = a2;
        p1[1] = b1; p2[1] = b2;
        p1[2] = c1; p2[2] = c2;
        p1[3] = d1; p2[3] = d2;
        return pairing(p1, p2);
    }}
}}

contract {contract_name} {{
    using Pairing for *;

    struct VerifyingKey {{
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }}

    struct Proof {{
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }}

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {{
        vk.alpha1 = Pairing.G1Point(uint256({alpha_x}), uint256({alpha_y}));
        vk.beta2 = Pairing.G2Point([uint256({beta_x1}), uint256({beta_x2})], [uint256({beta_y1}), uint256({beta_y2})]);
        vk.gamma2 = Pairing.G2Point([uint256({gamma_x1}), uint256({gamma_x2})], [uint256({gamma_y1}), uint256({gamma_y2})]);
        vk.delta2 = Pairing.G2Point([uint256({delta_x1}), uint256({delta_x2})], [uint256({delta_y1}), uint256({delta_y2})]);
        vk.IC = new Pairing.G1Point[]({ic_len});
{ic_elements}    }}

    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {{
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {{
            require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalarMul(vk.IC[i + 1], input[i]));
        }}
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd4(
            Pairing.negate(proof.A), proof.B,
            vk.alpha1, vk.beta2,
            vk_x, vk.gamma2,
            proof.C, vk.delta2
        )) return false;
        return true;
    }}

    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input
    ) public view returns (bool r) {{
        Proof memory proof = Proof({{
            A: Pairing.G1Point(a[0], a[1]),
            B: Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]),
            C: Pairing.G1Point(c[0], c[1])
        }});
        return verify(input, proof);
    }}
}}
"#,
        contract_name = contract_name,
        alpha_x = alpha_x,
        alpha_y = alpha_y,
        beta_x1 = beta_x1,
        beta_x2 = beta_x2,
        beta_y1 = beta_y1,
        beta_y2 = beta_y2,
        gamma_x1 = gamma_x1,
        gamma_x2 = gamma_x2,
        gamma_y1 = gamma_y1,
        gamma_y2 = gamma_y2,
        delta_x1 = delta_x1,
        delta_x2 = delta_x2,
        delta_y1 = delta_y1,
        delta_y2 = delta_y2,
        ic_len = ic_len,
        ic_elements = ic_elements,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier_export::{VerifierExport, VerifierLanguage};

    #[test]
    fn supported_languages_includes_solidity() {
        let exporter = Groth16VerifierExporter;
        let langs = exporter.supported_languages();
        assert_eq!(langs, vec![VerifierLanguage::Solidity]);
    }

    #[test]
    fn export_rejects_unsupported_language() {
        let exporter = Groth16VerifierExporter;
        let proof_data = serde_json::json!({});
        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Rust, None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("only supports Solidity, not rust")
        );
    }

    #[test]
    fn export_verifier_rejects_invalid_vk() {
        // When VK bytes are empty/invalid, the exporter must return an error
        // instead of silently producing a verifier with zeroed constants.
        let exporter = Groth16VerifierExporter;
        let proof_data = serde_json::json!({
            "verification_key": "",  // empty base64 -> decode to empty bytes
            "proof": "",
            "public_inputs": [],
        });

        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Solidity, None);
        assert!(
            result.is_err(),
            "invalid VK must produce an error, not a zeroed verifier"
        );
        assert!(result.unwrap_err().contains("verification key"));
    }

    #[test]
    fn export_verifier_missing_vk_field_errors() {
        let exporter = Groth16VerifierExporter;
        let proof_data = serde_json::json!({
            "proof": "",
            "public_inputs": [],
        });

        let result = exporter.export_verifier(&proof_data, VerifierLanguage::Solidity, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification_key"));
    }

    #[test]
    fn verifier_exporter_for_groth16_returns_some() {
        let exporter = super::super::verifier_exporter_for(zkf_core::BackendKind::ArkworksGroth16);
        assert!(exporter.is_some());
    }

    #[test]
    fn verifier_exporter_for_unsupported_returns_none() {
        assert!(super::super::verifier_exporter_for(zkf_core::BackendKind::Nova).is_none());
    }

    #[test]
    fn render_groth16_solidity_contains_pairing_library() {
        let hex =
            || "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
        let vk = crate::groth16_vk::Groth16VkHex {
            alpha_g1: [hex(), hex()],
            beta_g2: [hex(), hex(), hex(), hex()],
            gamma_g2: [hex(), hex(), hex(), hex()],
            delta_g2: [hex(), hex(), hex(), hex()],
            ic: vec![[hex(), hex()]],
        };
        let source = render_groth16_solidity(&vk, "TestVerifier");
        assert!(source.contains("library Pairing"));
        assert!(source.contains("function scalarMul"));
        assert!(source.contains("function pairingProd4"));
        assert!(source.contains("contract TestVerifier"));
    }

    #[test]
    fn extract_vk_bytes_from_base64() {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &[1u8, 2, 3, 4]);
        let proof_data = serde_json::json!({ "verification_key": encoded });
        let bytes = extract_vk_bytes(&proof_data).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn extract_vk_bytes_from_array() {
        let proof_data = serde_json::json!({ "verification_key": [10, 20, 30] });
        let bytes = extract_vk_bytes(&proof_data).unwrap();
        assert_eq!(bytes, vec![10, 20, 30]);
    }

    #[test]
    fn extract_public_inputs_from_strings() {
        let proof_data = serde_json::json!({ "public_inputs": ["42", "100"] });
        let inputs = extract_public_inputs(&proof_data).unwrap();
        assert_eq!(inputs, vec!["42", "100"]);
    }

    #[test]
    fn extract_public_inputs_from_numbers() {
        let proof_data = serde_json::json!({ "public_inputs": [42, 100] });
        let inputs = extract_public_inputs(&proof_data).unwrap();
        assert_eq!(inputs, vec!["42", "100"]);
    }

    #[test]
    fn verifier_language_display() {
        assert_eq!(format!("{}", VerifierLanguage::Solidity), "solidity");
        assert_eq!(format!("{}", VerifierLanguage::Rust), "rust");
        assert_eq!(format!("{}", VerifierLanguage::TypeScript), "typescript");
    }

    #[test]
    fn verifier_language_serde_roundtrip() {
        let lang = VerifierLanguage::Solidity;
        let json = serde_json::to_string(&lang).unwrap();
        assert_eq!(json, "\"solidity\"");
        let back: VerifierLanguage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, lang);
    }

    #[test]
    fn verifier_export_result_serde_roundtrip() {
        let result = VerifierExportResult {
            language: VerifierLanguage::Solidity,
            source: "pragma solidity ^0.8.0;".to_string(),
            contract_name: Some("TestVerifier".to_string()),
            verification_function: "verifyProof".to_string(),
            test_source: None,
            test_name: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: VerifierExportResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.language, result.language);
        assert_eq!(back.contract_name, result.contract_name);
        assert_eq!(back.verification_function, result.verification_function);
    }
}
