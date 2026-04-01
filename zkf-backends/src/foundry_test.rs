// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! Shared Foundry test generator for Groth16 verifier behavioral correctness.
//!
//! Generates a `.t.sol` file with fail-closed verifier tests:
//! 1. Valid proof passes verification
//! 2. Tampered proof (mutated A.x) reverts or returns false
//! 3. Wrong public input fails
//! 4. Wrong public-input arity fails closed
//! 5. Scalar-field overflow input fails closed
//! 6. Fuzzed public-input deltas fail closed
//! 7. Fuzzed proof-coordinate tampering fails closed
//!
//! Used by both the CLI (`zkf deploy --emit-test`) and the FFI layer (`zkf_emit_foundry_test`).

use crate::groth16_hex::tamper_hex;
use crate::groth16_proof::Groth16ProofHex;

/// Parameters for generating a Foundry test file.
pub struct FoundryTestParams<'a> {
    /// The decoded proof with hex coordinates.
    pub decoded: &'a Groth16ProofHex,
    /// Public inputs already converted to 0x-prefixed hex.
    pub public_inputs_hex: &'a [String],
    /// Import path for the verifier contract (e.g., `"./Verifier.sol"`).
    pub import_path: &'a str,
    /// Name of the verifier contract (e.g., `"ZkfGroth16Verifier"`).
    pub contract_name: &'a str,
}

/// Result of generating a Foundry test.
pub struct FoundryTestOutput {
    /// The Solidity test source code.
    pub source: String,
    /// The name of the test contract (e.g., `"ZkfGroth16VerifierTest"`).
    pub test_name: String,
    /// Names of the individual test functions.
    pub test_functions: Vec<String>,
}

fn canonicalize_foundry_import_path(import_path: &str) -> String {
    if let Some(path) = import_path.strip_prefix("./src/") {
        return format!("../src/{path}");
    }
    if let Some(path) = import_path.strip_prefix("src/") {
        return format!("../src/{path}");
    }
    import_path.to_string()
}

/// Generate Solidity source for a Foundry behavioral test of a Groth16 verifier.
pub fn generate_foundry_test(params: &FoundryTestParams<'_>) -> FoundryTestOutput {
    let FoundryTestParams {
        decoded,
        public_inputs_hex,
        import_path,
        contract_name,
    } = params;

    let n_inputs = public_inputs_hex.len();

    // Build the public input array initializer.
    let input_init = if public_inputs_hex.is_empty() {
        "        uint[] memory input = new uint[](0);\n        return input;".to_string()
    } else {
        let mut s = format!("        uint[] memory input = new uint[]({n_inputs});\n");
        for (i, hex) in public_inputs_hex.iter().enumerate() {
            s.push_str(&format!("        input[{i}] = uint256({hex});\n"));
        }
        s.push_str("        return input;");
        s
    };

    // Build a wrong-input array with a caller-provided nonzero delta.
    let wrong_input_init = if public_inputs_hex.is_empty() {
        "        uint[] memory wrongInput = new uint[](1);\n        wrongInput[0] = delta;\n        return wrongInput;".to_string()
    } else {
        let mut s = format!("        uint[] memory wrongInput = new uint[]({n_inputs});\n");
        for (i, hex) in public_inputs_hex.iter().enumerate() {
            if i == 0 {
                s.push_str(&format!(
                    "        wrongInput[0] = (uint256({hex}) + delta) % SNARK_SCALAR_FIELD;\n"
                ));
            } else {
                s.push_str(&format!("        wrongInput[{i}] = uint256({hex});\n"));
            }
        }
        s.push_str("        return wrongInput;");
        s
    };
    let wrong_arity_len = if n_inputs == 0 { 1 } else { n_inputs + 1 };
    let wrong_arity_init = if public_inputs_hex.is_empty() {
        format!(
            "        uint[] memory wrongArity = new uint[]({wrong_arity_len});\n        wrongArity[0] = 1;\n        return wrongArity;"
        )
    } else {
        let mut s = format!("        uint[] memory wrongArity = new uint[]({wrong_arity_len});\n");
        for (i, hex) in public_inputs_hex.iter().enumerate() {
            s.push_str(&format!("        wrongArity[{i}] = uint256({hex});\n"));
        }
        s.push_str(&format!("        wrongArity[{n_inputs}] = 1;\n"));
        s.push_str("        return wrongArity;");
        s
    };
    let overflow_input_init = if public_inputs_hex.is_empty() {
        "        uint[] memory overflowInput = new uint[](1);\n        overflowInput[0] = SNARK_SCALAR_FIELD;\n        return overflowInput;".to_string()
    } else {
        let mut s = format!("        uint[] memory overflowInput = new uint[]({n_inputs});\n");
        for (i, hex) in public_inputs_hex.iter().enumerate() {
            if i == 0 {
                s.push_str("        overflowInput[0] = SNARK_SCALAR_FIELD;\n");
            } else {
                s.push_str(&format!("        overflowInput[{i}] = uint256({hex});\n"));
            }
        }
        s.push_str("        return overflowInput;");
        s
    };

    // Tampered A.x — flip the last hex digit
    let tampered_ax = tamper_hex(&decoded.a[0]);

    let test_name = format!("{contract_name}Test");

    let import_path = canonicalize_foundry_import_path(import_path);

    let source = format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
import "{import_path}";

/// @title {test_name}
/// @notice Auto-generated Foundry test for Groth16 verifier behavioral correctness.
/// @dev Generated by ZKF. The suite locks valid verification plus fail-closed
///      rejection for tampering, wrong public inputs, wrong arity, and field overflow.
contract {test_name} {{
    uint256 internal constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    {contract_name} verifier;

    function assertTrue(bool condition, string memory message) internal pure {{
        require(condition, message);
    }}

    function assertFalse(bool condition, string memory message) internal pure {{
        require(!condition, message);
    }}

    function setUp() public {{
        verifier = new {contract_name}();
    }}

    function proofFixture()
        internal
        pure
        returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c)
    {{
        a = [
            uint256({a0}),
            uint256({a1})
        ];
        b = [
            [uint256({b00}), uint256({b01})],
            [uint256({b10}), uint256({b11})]
        ];
        c = [
            uint256({c0}),
            uint256({c1})
        ];
    }}

    function validInputFixture() internal pure returns (uint[] memory) {{
{input_init}
    }}

    function wrongInputFixture(uint256 delta) internal pure returns (uint[] memory) {{
{wrong_input_init}
    }}

    function wrongArityInputFixture() internal pure returns (uint[] memory) {{
{wrong_arity_init}
    }}

    function overflowInputFixture() internal pure returns (uint[] memory) {{
{overflow_input_init}
    }}

    function assertRejected(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input,
        string memory message
    ) internal view {{
        try verifier.verifyProof(a, b, c, input) returns (bool result) {{
            assertFalse(result, message);
        }} catch {{
            assertTrue(true, message);
        }}
    }}

    /// @notice Valid proof must pass.
    function test_validProof() public view {{
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        uint[] memory input = validInputFixture();

        bool result = verifier.verifyProof(a, b, c, input);
        assertTrue(result, "valid proof must pass");
    }}

    /// @notice Tampered proof (A.x mutated) must not verify.
    /// An off-curve point causes the EVM pairing precompile to revert,
    /// while a still-on-curve but wrong point returns false. Both are correct rejections.
    function test_tamperedProofFails() public view {{
        (, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        uint[2] memory a = [
            uint256({tampered_ax}),
            uint256({a1})
        ];
        uint[] memory input = validInputFixture();

        assertRejected(a, b, c, input, "tampered proof must fail closed");
    }}

    /// @notice Wrong public input must fail.
    function test_wrongInputFails() public view {{
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        uint[] memory wrongInput = wrongInputFixture(1);

        assertRejected(a, b, c, wrongInput, "wrong input must fail closed");
    }}

    /// @notice Wrong public-input arity must fail closed.
    function test_wrongPublicInputArityFails() public view {{
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        uint[] memory wrongArity = wrongArityInputFixture();

        assertRejected(a, b, c, wrongArity, "wrong public-input arity must fail closed");
    }}

    /// @notice Inputs equal to the scalar field modulus must fail closed.
    function test_scalarFieldOverflowInputFails() public view {{
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        uint[] memory overflowInput = overflowInputFixture();

        assertRejected(a, b, c, overflowInput, "scalar-field overflow input must fail closed");
    }}

    /// @notice Fuzzing a nonzero public-input delta must always fail closed.
    function testFuzz_nonZeroPublicInputDeltaFails(uint256 deltaRaw) public view {{
        uint256 delta = deltaRaw % SNARK_SCALAR_FIELD;
        if (delta == 0) {{
            delta = 1;
        }}
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        uint[] memory wrongInput = wrongInputFixture(delta);

        assertRejected(a, b, c, wrongInput, "fuzzed nonzero public-input delta must fail closed");
    }}

    /// @notice Fuzzing proof-coordinate tampering must always fail closed.
    function testFuzz_proofCoordinateTamperingFails(uint256 deltaRaw) public view {{
        uint256 delta = (deltaRaw % 17) + 1;
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = proofFixture();
        if (a[0] > delta) {{
            a[0] = a[0] - delta;
        }} else {{
            a[0] = a[0] + delta;
        }}
        uint[] memory input = validInputFixture();

        assertRejected(a, b, c, input, "fuzzed proof-coordinate tampering must fail closed");
    }}
}}
"#,
        import_path = import_path,
        test_name = test_name,
        contract_name = contract_name,
        a0 = decoded.a[0],
        a1 = decoded.a[1],
        b00 = decoded.b[0][0],
        b01 = decoded.b[0][1],
        b10 = decoded.b[1][0],
        b11 = decoded.b[1][1],
        c0 = decoded.c[0],
        c1 = decoded.c[1],
        tampered_ax = tampered_ax,
        input_init = input_init,
        wrong_input_init = wrong_input_init,
        wrong_arity_init = wrong_arity_init,
        overflow_input_init = overflow_input_init,
    );

    let test_functions = vec![
        "test_validProof".to_string(),
        "test_tamperedProofFails".to_string(),
        "test_wrongInputFails".to_string(),
        "test_wrongPublicInputArityFails".to_string(),
        "test_scalarFieldOverflowInputFails".to_string(),
        "testFuzz_nonZeroPublicInputDeltaFails".to_string(),
        "testFuzz_proofCoordinateTamperingFails".to_string(),
    ];

    FoundryTestOutput {
        source,
        test_name,
        test_functions,
    }
}

/// Decode a proof artifact's proof bytes and public inputs into calldata JSON.
///
/// Returns the JSON value with `a`, `b`, `c` coordinates and `public_inputs` as hex.
/// This is the single source of truth for calldata construction — used by both CLI and FFI.
pub fn proof_to_calldata_json(
    proof_bytes: &[u8],
    public_inputs: &[zkf_core::FieldElement],
) -> Result<serde_json::Value, String> {
    let decoded = crate::groth16_proof::decode_groth16_proof(proof_bytes).ok_or_else(|| {
        "failed to decode Groth16 proof bytes — proof may be corrupt or not arkworks-compressed"
            .to_string()
    })?;

    let public_inputs_hex: Vec<String> = public_inputs
        .iter()
        .map(|pi| crate::groth16_hex::public_input_to_hex(&pi.to_decimal_string()))
        .collect();

    Ok(serde_json::json!({
        "a": [decoded.a[0], decoded.a[1]],
        "b": [[decoded.b[0][0], decoded.b[0][1]], [decoded.b[1][0], decoded.b[1][1]]],
        "c": [decoded.c[0], decoded.c[1]],
        "public_inputs": public_inputs_hex,
    }))
}

/// Decode proof bytes and public inputs, then generate a Foundry test.
///
/// Convenience function that combines proof decoding + test generation in a single call,
/// avoiding redundant proof deserialization.
pub fn generate_foundry_test_from_artifact(
    proof_bytes: &[u8],
    public_inputs: &[zkf_core::FieldElement],
    import_path: &str,
    contract_name: &str,
) -> Result<FoundryTestOutput, String> {
    let decoded = crate::groth16_proof::decode_groth16_proof(proof_bytes)
        .ok_or_else(|| "failed to decode Groth16 proof bytes for test generation".to_string())?;

    let public_inputs_hex: Vec<String> = public_inputs
        .iter()
        .map(|pi| crate::groth16_hex::public_input_to_hex(&pi.to_decimal_string()))
        .collect();

    let params = FoundryTestParams {
        decoded: &decoded,
        public_inputs_hex: &public_inputs_hex,
        import_path,
        contract_name,
    };

    Ok(generate_foundry_test(&params))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_decoded() -> Groth16ProofHex {
        Groth16ProofHex {
            a: ["0x1".to_string(), "0x2".to_string()],
            b: [
                ["0x3".to_string(), "0x4".to_string()],
                ["0x5".to_string(), "0x6".to_string()],
            ],
            c: ["0x7".to_string(), "0x8".to_string()],
        }
    }

    #[test]
    fn foundry_test_rewrites_project_root_src_imports_for_test_directory() {
        let decoded = sample_decoded();
        let output = generate_foundry_test(&FoundryTestParams {
            decoded: &decoded,
            public_inputs_hex: &[],
            import_path: "./src/Verifier.sol",
            contract_name: "Verifier",
        });

        assert!(output.source.contains("import \"../src/Verifier.sol\";"));
        assert!(
            output
                .test_functions
                .contains(&"test_wrongPublicInputArityFails".to_string())
        );
        assert!(
            output
                .test_functions
                .contains(&"test_scalarFieldOverflowInputFails".to_string())
        );
        assert!(
            output
                .source
                .contains("function testFuzz_nonZeroPublicInputDeltaFails")
        );
        assert!(
            output
                .source
                .contains("function test_tamperedProofFails() public view")
        );
    }
}
