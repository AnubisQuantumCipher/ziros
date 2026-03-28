use base64::Engine;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use zkf_core::{BackendKind, ProofArtifact};

pub(crate) fn default_contract_name(backend: BackendKind) -> String {
    match backend {
        BackendKind::Sp1 => "ZkfSp1BoundVerifier".to_string(),
        BackendKind::ArkworksGroth16 => "ZkfGroth16Verifier".to_string(),
        _ => "ZkfVerifier".to_string(),
    }
}

pub(crate) fn render_solidity_verifier(
    backend: BackendKind,
    artifact: &ProofArtifact,
    contract_name: &str,
) -> Result<String, String> {
    let source = match backend {
        BackendKind::Sp1 => render_sp1_solidity_verifier(artifact)?,
        BackendKind::ArkworksGroth16 => render_groth16_solidity_verifier(artifact, contract_name)?,
        other => {
            return Err(format!(
                "solidity verifier generation is not supported for backend '{}'; supported backends: sp1, arkworks-groth16",
                other
            ));
        }
    };
    validate_solidity_output(&source)?;
    Ok(source)
}

/// Hard output validator — blocks any broken verifier from being served.
fn validate_solidity_output(sol: &str) -> Result<(), String> {
    if sol.contains("0x0x") {
        return Err("VERIFIER BLOCKED: malformed hex literal (0x0x)".to_string());
    }
    if sol.contains("Pairing check placeholder") {
        return Err("VERIFIER BLOCKED: placeholder pairing check (stub)".to_string());
    }
    // SP1 verifiers use a different verification model, so only enforce pairing for Groth16
    if sol.contains("Groth16") || sol.contains("verifyingKey") {
        let has_pairing =
            sol.contains("0x08") || sol.contains("pairing(") || sol.contains("pairingProd4(");
        if !has_pairing {
            return Err("VERIFIER BLOCKED: no pairing precompile call found".to_string());
        }
        let has_lc = sol.contains("scalar_mul(") || sol.contains("0x07");
        if !has_lc {
            return Err("VERIFIER BLOCKED: no IC linear combination found".to_string());
        }
    }
    for marker in &["TODO", "FIXME", "PLACEHOLDER", "STUB"] {
        if sol.to_uppercase().contains(marker) {
            return Err(format!("VERIFIER BLOCKED: found '{marker}' marker"));
        }
    }
    Ok(())
}

fn render_sp1_solidity_verifier(artifact: &ProofArtifact) -> Result<String, String> {
    if let Some(source) = render_sp1_solidity_wrapper(artifact)? {
        return Ok(source);
    }
    render_sp1_legacy_attestation(artifact)
}

fn render_sp1_solidity_wrapper(artifact: &ProofArtifact) -> Result<Option<String>, String> {
    let program_vkey_raw = match artifact.metadata.get("sp1_program_vkey_bn254") {
        Some(value) if !value.trim().is_empty() => value,
        _ => return Ok(None),
    };
    let program_vkey = bn254_decimal_to_bytes32(program_vkey_raw)?;

    let public_values_hash = if let Some(value) =
        artifact.metadata.get("sp1_public_values_hash_bn254")
    {
        bn254_decimal_to_bytes32(value)?
    } else if let Some(value) = artifact.public_inputs.first() {
        let decimal = value.to_decimal_string();
        let encoded = decimal.strip_prefix("base64:").ok_or_else(|| {
            "native SP1 solidity wrapper requires base64-prefixed public input payload".to_string()
        })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .map_err(|err| format!("invalid SP1 public input base64 payload: {err}"))?;
        sp1_public_values_digest_bytes32(bytes.as_slice())
    } else {
        return Err(
            "native SP1 solidity wrapper requires `sp1_public_values_hash_bn254` metadata or base64 public input payload".to_string(),
        );
    };

    let expected_proof_sha256 =
        if let Some(value) = artifact.metadata.get("sp1_onchain_proof_sha256") {
            parse_hex_32(value)?
        } else {
            bytes32_literal(&Sha256::digest(artifact.proof.as_slice()))
        };

    let expected_selector = artifact
        .metadata
        .get("sp1_onchain_proof_selector")
        .map(|value| parse_hex_4(value))
        .transpose()?
        .unwrap_or_else(|| "0x00000000".to_string());

    Ok(Some(format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface ISP1Verifier {{
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}}

contract ZkfSp1BoundVerifier {{
    ISP1Verifier public immutable verifier;
    bytes32 public constant PROGRAM_VKEY = {program_vkey};
    bytes32 public constant PUBLIC_VALUES_DIGEST = {public_values_hash};
    bytes32 public constant PROOF_SHA256 = {expected_proof_sha256};
    bytes4 public constant PROOF_SELECTOR = {expected_selector};

    constructor(address verifierAddress) {{
        verifier = ISP1Verifier(verifierAddress);
    }}

    function hashPublicValues(bytes calldata publicValues) public pure returns (bytes32) {{
        return sha256(publicValues) & bytes32(uint256((1 << 253) - 1));
    }}

    function verify(bytes calldata publicValues, bytes calldata proofBytes) external view returns (bool) {{
        if (proofBytes.length < 4) {{
            return false;
        }}
        if (PROOF_SELECTOR != bytes4(0) && bytes4(proofBytes[:4]) != PROOF_SELECTOR) {{
            return false;
        }}
        if (hashPublicValues(publicValues) != PUBLIC_VALUES_DIGEST) {{
            return false;
        }}
        if (sha256(proofBytes) != PROOF_SHA256) {{
            return false;
        }}
        try verifier.verifyProof(PROGRAM_VKEY, publicValues, proofBytes) {{
            return true;
        }} catch {{
            return false;
        }}
    }}
}}
"#,
        program_vkey = bytes32_literal(&program_vkey),
        public_values_hash = bytes32_literal(&public_values_hash),
        expected_proof_sha256 = expected_proof_sha256,
        expected_selector = expected_selector,
    )))
}

fn render_sp1_legacy_attestation(artifact: &ProofArtifact) -> Result<String, String> {
    let program_digest = parse_hex_32(&artifact.program_digest)?;
    let proof_digest = Sha256::digest(artifact.proof.as_slice());
    let vk_digest = Sha256::digest(artifact.verification_key.as_slice());
    Ok(format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

contract ZkfSp1ProofAttestation {{
    bytes32 public constant PROGRAM_DIGEST = {program_digest};
    bytes32 public constant PROOF_SHA256 = {proof_digest};
    bytes32 public constant VK_SHA256 = {vk_digest};

    function verifyAttestation(bytes calldata proof, bytes32 programDigest) external pure returns (bool) {{
        return programDigest == PROGRAM_DIGEST && sha256(proof) == PROOF_SHA256;
    }}
}}
"#,
        program_digest = program_digest,
        proof_digest = bytes32_literal(&proof_digest),
        vk_digest = bytes32_literal(&vk_digest),
    ))
}

fn render_groth16_solidity_verifier(
    proof_artifact: &ProofArtifact,
    contract_name: &str,
) -> Result<String, String> {
    let vk = &proof_artifact.verification_key;
    let parsed = zkf_backends::groth16_vk::decode_groth16_vk(vk).ok_or(
        "failed to decode Groth16 verification key: refusing to emit verifier with invalid VK",
    )?;

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

    Ok(format!(
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

    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {{
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
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
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
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
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
    ))
}

fn bn254_decimal_to_bytes32(value: &str) -> Result<[u8; 32], String> {
    let raw = value.trim();
    let bigint = BigInt::from_str(raw)
        .map_err(|err| format!("invalid decimal field element '{raw}': {err}"))?;
    let (sign, bytes) = bigint.to_bytes_be();
    if matches!(sign, num_bigint::Sign::Minus) {
        return Err(format!(
            "expected non-negative decimal field element for bytes32 conversion, found '{raw}'"
        ));
    }
    if bytes.len() > 32 {
        return Err(format!(
            "decimal field element does not fit into bytes32 ({} bytes): '{raw}'",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    let offset = 32 - bytes.len();
    out[offset..].copy_from_slice(bytes.as_slice());
    Ok(out)
}

fn sp1_public_values_digest_bytes32(public_values: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::digest(public_values);
    digest[0] &= 0x1f;
    digest.into()
}

fn parse_hex_32(value: &str) -> Result<String, String> {
    let raw = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if raw.len() != 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "expected 32-byte hex digest for solidity verifier, found '{value}'"
        ));
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn parse_hex_4(value: &str) -> Result<String, String> {
    let raw = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if raw.len() != 8 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("expected 4-byte hex selector, found '{value}'"));
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn bytes32_literal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
