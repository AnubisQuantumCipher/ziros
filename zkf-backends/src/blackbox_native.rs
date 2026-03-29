use crate::blackbox_gadgets::poseidon2::poseidon2_permutation_native;
use acir::FieldElement as AcirFieldElement;
#[cfg(feature = "native-blackbox-solvers")]
use acvm_blackbox_solver::{
    BlackBoxFunctionSolver, blake2s, ecdsa_secp256k1_verify, ecdsa_secp256r1_verify, keccak256,
    sha256,
};
#[cfg(feature = "native-blackbox-solvers")]
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use num_bigint::BigInt;
use sha2::Digest as _;
use std::collections::BTreeMap;
use zkf_core::{
    BackendKind, BlackBoxOp, Constraint, Expr, FieldId, Program, Witness, ZkfError, ZkfResult,
    mod_inverse_bigint, normalize_mod,
};

#[cfg(feature = "native-blackbox-solvers")]
pub(crate) fn supported_blackbox_ops() -> Vec<String> {
    vec![
        BlackBoxOp::Poseidon.as_str().to_string(),
        BlackBoxOp::Sha256.as_str().to_string(),
        BlackBoxOp::Keccak256.as_str().to_string(),
        BlackBoxOp::Pedersen.as_str().to_string(),
        BlackBoxOp::EcdsaSecp256k1.as_str().to_string(),
        BlackBoxOp::EcdsaSecp256r1.as_str().to_string(),
        BlackBoxOp::SchnorrVerify.as_str().to_string(),
        BlackBoxOp::Blake2s.as_str().to_string(),
        BlackBoxOp::RecursiveAggregationMarker.as_str().to_string(),
        BlackBoxOp::ScalarMulG1.as_str().to_string(),
        BlackBoxOp::PointAddG1.as_str().to_string(),
        BlackBoxOp::PairingCheck.as_str().to_string(),
    ]
}

#[cfg(not(feature = "native-blackbox-solvers"))]
pub(crate) fn supported_blackbox_ops() -> Vec<String> {
    vec![BlackBoxOp::RecursiveAggregationMarker.as_str().to_string()]
}

#[cfg(feature = "native-blackbox-solvers")]
fn bn254_solver() -> Bn254BlackBoxSolver {
    Bn254BlackBoxSolver::default()
}

#[cfg(feature = "native-blackbox-solvers")]
fn build_numeric_values(witness: &Witness, field: FieldId) -> ZkfResult<BTreeMap<String, BigInt>> {
    witness
        .values
        .iter()
        .map(|(name, value)| Ok((name.clone(), value.normalized_bigint(field)?)))
        .collect()
}

#[cfg(feature = "native-blackbox-solvers")]
fn eval_expr_cached(
    expr: &Expr,
    values: &BTreeMap<String, BigInt>,
    field: FieldId,
) -> ZkfResult<BigInt> {
    match expr {
        Expr::Const(value) => value.normalized_bigint(field),
        Expr::Signal(name) => {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: name.clone(),
                })
        }
        Expr::Add(items) => {
            let mut acc = BigInt::from(0u8);
            for item in items {
                acc = normalize_mod(
                    acc + eval_expr_cached(item, values, field)?,
                    field.modulus(),
                );
            }
            Ok(acc)
        }
        Expr::Sub(lhs, rhs) => Ok(normalize_mod(
            eval_expr_cached(lhs, values, field)? - eval_expr_cached(rhs, values, field)?,
            field.modulus(),
        )),
        Expr::Mul(lhs, rhs) => Ok(normalize_mod(
            eval_expr_cached(lhs, values, field)? * eval_expr_cached(rhs, values, field)?,
            field.modulus(),
        )),
        Expr::Div(lhs, rhs) => {
            let numerator = eval_expr_cached(lhs, values, field)?;
            let denominator = eval_expr_cached(rhs, values, field)?;
            let inverse =
                mod_inverse_bigint(denominator, field.modulus()).ok_or(ZkfError::DivisionByZero)?;
            Ok(normalize_mod(numerator * inverse, field.modulus()))
        }
    }
}

#[cfg(feature = "native-blackbox-solvers")]
pub(crate) fn validate_blackbox_constraints(
    backend: BackendKind,
    program: &Program,
    witness: &Witness,
) -> ZkfResult<()> {
    let bn254_solver = bn254_solver();
    let numeric_values = build_numeric_values(witness, program.field)?;

    for (index, constraint) in program.constraints.iter().enumerate() {
        let Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label,
        } = constraint
        else {
            continue;
        };

        let input_values = inputs
            .iter()
            .map(|expr| eval_expr_cached(expr, &numeric_values, program.field))
            .collect::<ZkfResult<Vec<_>>>()?;
        let input_bits = parse_input_num_bits(params, inputs.len())?;

        match op {
            BlackBoxOp::Poseidon => {
                let state_len = parse_poseidon_state_len(
                    params,
                    input_values.len(),
                    outputs.len(),
                    backend,
                    index,
                    label,
                )?;
                let expected_bigints = if program.field == FieldId::Bn254 {
                    let acir_inputs = input_values
                        .iter()
                        .map(bigint_to_acir_field)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("invalid poseidon input: {err}"),
                            )
                        })?;
                    let expected = bn254_solver
                        .poseidon2_permutation(&acir_inputs, state_len)
                        .map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("poseidon solver failed: {err}"),
                            )
                        })?;
                    expected
                        .iter()
                        .map(bigint_from_acir_field)
                        .collect::<Result<Vec<_>, _>>()
                        .map(|values| {
                            values
                                .into_iter()
                                .map(|value| normalize_mod(value, program.field.modulus()))
                                .collect::<Vec<_>>()
                        })
                        .map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("invalid poseidon output: {err}"),
                            )
                        })?
                } else {
                    poseidon2_permutation_native(&input_values, params, program.field).map_err(
                        |err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!(
                                    "poseidon native validation failed for {}: {err}",
                                    program.field
                                ),
                            )
                        },
                    )?
                };
                expect_output_bigints(
                    index,
                    label,
                    program,
                    witness,
                    outputs,
                    expected_bigints.as_slice(),
                    "poseidon",
                )?;
            }
            BlackBoxOp::Sha256 => {
                let message = encode_message_bytes(&input_values, &input_bits)?;
                let digest = sha256(&message).map_err(|err| {
                    blackbox_error(
                        backend,
                        index,
                        label,
                        format!("sha256 solver failed: {err}"),
                    )
                })?;
                expect_output_bytes(backend, index, label, program, witness, outputs, &digest)?;
            }
            BlackBoxOp::Keccak256 => {
                let message = if !input_bits.is_empty() && *input_bits.last().unwrap_or(&8) > 8 {
                    let msg_len =
                        input_values
                            .last()
                            .and_then(bigint_to_usize)
                            .ok_or_else(|| {
                                blackbox_error(
                                    backend,
                                    index,
                                    label,
                                    "keccak256 var_message_size input is not a valid usize"
                                        .to_string(),
                                )
                            })?;
                    let mut bytes = encode_message_bytes(
                        &input_values[..input_values.len().saturating_sub(1)],
                        &input_bits[..input_bits.len().saturating_sub(1)],
                    )?;
                    if msg_len > bytes.len() {
                        return Err(blackbox_error(
                            backend,
                            index,
                            label,
                            format!(
                                "keccak256 var_message_size {} exceeds provided input bytes {}",
                                msg_len,
                                bytes.len()
                            ),
                        ));
                    }
                    bytes.truncate(msg_len);
                    bytes
                } else {
                    encode_message_bytes(&input_values, &input_bits)?
                };
                let digest = keccak256(&message).map_err(|err| {
                    blackbox_error(
                        backend,
                        index,
                        label,
                        format!("keccak256 solver failed: {err}"),
                    )
                })?;
                expect_output_bytes(backend, index, label, program, witness, outputs, &digest)?;
            }
            BlackBoxOp::Blake2s => {
                let message = encode_message_bytes(&input_values, &input_bits)?;
                let digest = blake2s(&message).map_err(|err| {
                    blackbox_error(
                        backend,
                        index,
                        label,
                        format!("blake2s solver failed: {err}"),
                    )
                })?;
                expect_output_bytes(backend, index, label, program, witness, outputs, &digest)?;
            }
            BlackBoxOp::EcdsaSecp256k1 => {
                let bytes = encode_message_bytes(&input_values, &input_bits)?;
                if bytes.len() != 160 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "ecdsa_secp256k1 expects 160 byte inputs (pkx[32], pky[32], sig[64], msg[32]), found {}",
                            bytes.len()
                        ),
                    ));
                }
                let public_key_x: [u8; 32] = bytes[0..32].try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected slice length mismatch".to_string())
                })?;
                let public_key_y: [u8; 32] = bytes[32..64].try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected slice length mismatch".to_string())
                })?;
                let signature: [u8; 64] = bytes[64..128].try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected slice length mismatch".to_string())
                })?;
                let msg = &bytes[128..160];
                let verified =
                    ecdsa_secp256k1_verify(msg, &public_key_x, &public_key_y, &signature).map_err(
                        |err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("ecdsa_secp256k1 solver failed: {err}"),
                            )
                        },
                    )?;
                expect_single_boolean_output(
                    index,
                    label,
                    program,
                    witness,
                    outputs,
                    verified,
                    "ecdsa_secp256k1",
                )?;
            }
            BlackBoxOp::EcdsaSecp256r1 => {
                let bytes = encode_message_bytes(&input_values, &input_bits)?;
                if bytes.len() != 160 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "ecdsa_secp256r1 expects 160 byte inputs (pkx[32], pky[32], sig[64], msg[32]), found {}",
                            bytes.len()
                        ),
                    ));
                }
                let public_key_x: [u8; 32] = bytes[0..32].try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected slice length mismatch".to_string())
                })?;
                let public_key_y: [u8; 32] = bytes[32..64].try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected slice length mismatch".to_string())
                })?;
                let signature: [u8; 64] = bytes[64..128].try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected slice length mismatch".to_string())
                })?;
                let msg = &bytes[128..160];
                let verified =
                    ecdsa_secp256r1_verify(msg, &public_key_x, &public_key_y, &signature).map_err(
                        |err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("ecdsa_secp256r1 solver failed: {err}"),
                            )
                        },
                    )?;
                expect_single_boolean_output(
                    index,
                    label,
                    program,
                    witness,
                    outputs,
                    verified,
                    "ecdsa_secp256r1",
                )?;
            }
            BlackBoxOp::SchnorrVerify => {
                if program.field != FieldId::Bn254 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "schnorr_verify is currently supported only for BN254 programs; found {}",
                            program.field
                        ),
                    ));
                }
                if input_values.len() < 66 || input_bits.len() < 66 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "schnorr_verify expects at least 66 inputs (pkx, pky, sig[64], msg[..]), found {}",
                            input_values.len()
                        ),
                    ));
                }
                let public_key_x = bigint_to_acir_field(&input_values[0]).map_err(|err| {
                    blackbox_error(
                        backend,
                        index,
                        label,
                        format!("invalid schnorr public_key_x: {err}"),
                    )
                })?;
                let public_key_y = bigint_to_acir_field(&input_values[1]).map_err(|err| {
                    blackbox_error(
                        backend,
                        index,
                        label,
                        format!("invalid schnorr public_key_y: {err}"),
                    )
                })?;

                let signature_bytes =
                    encode_message_bytes(&input_values[2..66], &input_bits[2..66])?;
                if signature_bytes.len() != 64 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "schnorr_verify signature must be 64 bytes, found {}",
                            signature_bytes.len()
                        ),
                    ));
                }
                let signature: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| {
                    ZkfError::InvalidArtifact("unexpected signature length mismatch".to_string())
                })?;
                let message = encode_message_bytes(&input_values[66..], &input_bits[66..])?;

                let verified = bn254_solver
                    .schnorr_verify(&public_key_x, &public_key_y, &signature, &message)
                    .map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("schnorr solver failed: {err}"),
                        )
                    })?;
                expect_single_boolean_output(
                    index,
                    label,
                    program,
                    witness,
                    outputs,
                    verified,
                    "schnorr_verify",
                )?;
            }
            BlackBoxOp::Pedersen => {
                if program.field != FieldId::Bn254 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "pedersen is currently supported only for BN254 programs; found {}",
                            program.field
                        ),
                    ));
                }
                let acir_inputs = input_values
                    .iter()
                    .map(bigint_to_acir_field)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("invalid pedersen input: {err}"),
                        )
                    })?;
                let domain_separator = params
                    .get("domain_separator")
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(0);
                match outputs.len() {
                    1 => {
                        let expected = bn254_solver
                            .pedersen_hash(&acir_inputs, domain_separator)
                            .map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("pedersen hash solver failed: {err}"),
                            )
                        })?;
                        let expected = bigint_from_acir_field(&expected).map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("invalid pedersen hash output: {err}"),
                            )
                        })?;
                        expect_output_bigints(
                            index,
                            label,
                            program,
                            witness,
                            outputs,
                            &[expected],
                            "pedersen_hash",
                        )?;
                    }
                    2 => {
                        let (x, y) = bn254_solver
                            .pedersen_commitment(&acir_inputs, domain_separator)
                            .map_err(|err| {
                                blackbox_error(
                                    backend,
                                    index,
                                    label,
                                    format!("pedersen commitment solver failed: {err}"),
                                )
                            })?;
                        let expected_x = bigint_from_acir_field(&x).map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("invalid pedersen commitment x output: {err}"),
                            )
                        })?;
                        let expected_y = bigint_from_acir_field(&y).map_err(|err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("invalid pedersen commitment y output: {err}"),
                            )
                        })?;
                        expect_output_bigints(
                            index,
                            label,
                            program,
                            witness,
                            outputs,
                            &[expected_x, expected_y],
                            "pedersen_commitment",
                        )?;
                    }
                    other => {
                        return Err(blackbox_error(
                            backend,
                            index,
                            label,
                            format!("pedersen expects 1 or 2 outputs, found {other}"),
                        ));
                    }
                }
            }
            BlackBoxOp::ScalarMulG1 | BlackBoxOp::PointAddG1 | BlackBoxOp::PairingCheck => {
                // EC operations are circuit-level constraints handled by the proving backend.
                // At native execution time, we only verify the witness values are present
                // (actual curve arithmetic is performed by the backend's constraint system).
                for output_name in outputs {
                    if !witness.values.contains_key(output_name) {
                        return Err(blackbox_error(
                            backend,
                            index,
                            label,
                            format!(
                                "{} output signal '{}' missing from witness",
                                op.as_str(),
                                output_name
                            ),
                        ));
                    }
                }
            }
            BlackBoxOp::RecursiveAggregationMarker => {
                if !outputs.is_empty() {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "recursive_aggregation_marker expects 0 outputs, found {}",
                            outputs.len()
                        ),
                    ));
                }
                if input_values.len() != 3 {
                    return Err(blackbox_error(
                        backend,
                        index,
                        label,
                        format!(
                            "recursive_aggregation_marker expects exactly 3 inputs (statement,vk,public_inputs), found {}",
                            input_values.len()
                        ),
                    ));
                }

                let statement_digest = required_param(
                    params,
                    "statement_digest",
                    backend,
                    index,
                    label,
                    "recursive_aggregation_marker",
                )?;
                let vk_digest = required_param(
                    params,
                    "verification_key_digest",
                    backend,
                    index,
                    label,
                    "recursive_aggregation_marker",
                )?;
                let public_input_commitment = required_param(
                    params,
                    "public_input_commitment",
                    backend,
                    index,
                    label,
                    "recursive_aggregation_marker",
                )?;

                let expected_statement =
                    digest_hex_to_field_bigint(statement_digest, program.field).map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("invalid statement_digest param: {err}"),
                        )
                    })?;
                let expected_vk =
                    digest_hex_to_field_bigint(vk_digest, program.field).map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("invalid verification_key_digest param: {err}"),
                        )
                    })?;
                let expected_public_inputs =
                    digest_hex_to_field_bigint(public_input_commitment, program.field).map_err(
                        |err| {
                            blackbox_error(
                                backend,
                                index,
                                label,
                                format!("invalid public_input_commitment param: {err}"),
                            )
                        },
                    )?;

                let expected = [expected_statement, expected_vk, expected_public_inputs];
                for (input_i, (actual, expected_value)) in
                    input_values.iter().zip(expected.iter()).enumerate()
                {
                    if actual != expected_value {
                        return Err(blackbox_error(
                            backend,
                            index,
                            label,
                            format!(
                                "recursive_aggregation_marker input {} mismatch: expected {}, found {}",
                                input_i, expected_value, actual
                            ),
                        ));
                    }
                }

                if let Some(statement_v2) = params.get("statement_digest_v2") {
                    let carried_backend = required_param(
                        params,
                        "carried_backend",
                        backend,
                        index,
                        label,
                        "recursive_aggregation_marker",
                    )?;
                    let proof_digest = required_param(
                        params,
                        "proof_digest",
                        backend,
                        index,
                        label,
                        "recursive_aggregation_marker",
                    )?;
                    let program_digest = required_param(
                        params,
                        "program_digest",
                        backend,
                        index,
                        label,
                        "recursive_aggregation_marker",
                    )?;

                    ensure_hex_digest_len(statement_v2, "statement_digest_v2").map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("invalid statement_digest_v2 param: {err}"),
                        )
                    })?;
                    ensure_hex_digest_len(proof_digest, "proof_digest").map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("invalid proof_digest param: {err}"),
                        )
                    })?;
                    ensure_hex_digest_len(program_digest, "program_digest").map_err(|err| {
                        blackbox_error(
                            backend,
                            index,
                            label,
                            format!("invalid program_digest param: {err}"),
                        )
                    })?;

                    let expected_v2 = recursive_marker_statement_v2_digest(
                        carried_backend,
                        program_digest,
                        proof_digest,
                        vk_digest,
                        public_input_commitment,
                    );
                    if expected_v2 != statement_v2.to_ascii_lowercase() {
                        return Err(blackbox_error(
                            backend,
                            index,
                            label,
                            format!(
                                "statement_digest_v2 mismatch: expected {}, found {}",
                                expected_v2, statement_v2
                            ),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "native-blackbox-solvers")]
    fn supported_blackbox_ops_include_ecdsa_when_native_runtime_is_enabled() {
        let supported = supported_blackbox_ops();
        assert!(
            supported.contains(&BlackBoxOp::EcdsaSecp256k1.as_str().to_string()),
            "capabilities should advertise secp256k1 ECDSA when the shipped runtime relation is enabled"
        );
        assert!(
            supported.contains(&BlackBoxOp::EcdsaSecp256r1.as_str().to_string()),
            "capabilities should advertise secp256r1 ECDSA when the shipped runtime relation is enabled"
        );
    }

    #[test]
    #[cfg(not(feature = "native-blackbox-solvers"))]
    fn supported_blackbox_ops_keep_ecdsa_disabled_without_native_runtime() {
        let supported = supported_blackbox_ops();
        assert!(
            !supported.contains(&BlackBoxOp::EcdsaSecp256k1.as_str().to_string()),
            "capabilities must not advertise secp256k1 ECDSA without native runtime support"
        );
        assert!(
            !supported.contains(&BlackBoxOp::EcdsaSecp256r1.as_str().to_string()),
            "capabilities must not advertise secp256r1 ECDSA without native runtime support"
        );
    }
}

#[cfg(not(feature = "native-blackbox-solvers"))]
pub(crate) fn validate_blackbox_constraints(
    backend: BackendKind,
    program: &Program,
    _witness: &Witness,
) -> ZkfResult<()> {
    for (index, constraint) in program.constraints.iter().enumerate() {
        let Constraint::BlackBox { op, label, .. } = constraint else {
            continue;
        };
        if *op == BlackBoxOp::RecursiveAggregationMarker {
            continue;
        }
        return Err(blackbox_error(
            backend,
            index,
            label,
            "native blackbox solver support is not enabled in this build".to_string(),
        ));
    }
    Ok(())
}

fn parse_input_num_bits(
    params: &BTreeMap<String, String>,
    input_len: usize,
) -> ZkfResult<Vec<u32>> {
    let Some(raw) = params.get("input_num_bits") else {
        return Ok(vec![8; input_len]);
    };
    if raw.trim().is_empty() {
        return Ok(vec![8; input_len]);
    }
    let mut bits = Vec::new();
    for segment in raw.split(',') {
        let parsed = segment.trim().parse::<u32>().map_err(|_| {
            ZkfError::InvalidArtifact(format!("invalid input_num_bits segment '{segment}'"))
        })?;
        bits.push(parsed);
    }
    if bits.len() != input_len {
        return Ok(vec![8; input_len]);
    }
    Ok(bits)
}

fn required_param<'a>(
    params: &'a BTreeMap<String, String>,
    key: &str,
    backend: BackendKind,
    index: usize,
    label: &Option<String>,
    op: &str,
) -> ZkfResult<&'a str> {
    params.get(key).map(String::as_str).ok_or_else(|| {
        blackbox_error(
            backend,
            index,
            label,
            format!("{op} missing required param '{key}'"),
        )
    })
}

fn digest_hex_to_field_bigint(digest: &str, field: FieldId) -> Result<BigInt, String> {
    let trimmed = digest.trim();
    ensure_hex_digest_len(trimmed, "digest")?;
    let value = BigInt::parse_bytes(trimmed.as_bytes(), 16)
        .ok_or_else(|| format!("failed to parse digest '{}'", trimmed))?;
    Ok(normalize_mod(value, field.modulus()))
}

fn ensure_hex_digest_len(value: &str, name: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{name} is empty"));
    }
    if trimmed.len() != 64 {
        return Err(format!(
            "{name} must be 64 hex chars, found length {}",
            trimmed.len()
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{name} is not valid hex"));
    }
    Ok(())
}

fn recursive_marker_statement_v2_digest(
    carried_backend: &str,
    program_digest: &str,
    proof_digest: &str,
    verification_key_digest: &str,
    public_input_commitment: &str,
) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"zkf-recursive-marker-statement-v2");
    hasher.update(carried_backend.as_bytes());
    hasher.update(program_digest.as_bytes());
    hasher.update(proof_digest.as_bytes());
    hasher.update(verification_key_digest.as_bytes());
    hasher.update(public_input_commitment.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn parse_poseidon_state_len(
    params: &BTreeMap<String, String>,
    input_len: usize,
    output_len: usize,
    backend: BackendKind,
    index: usize,
    label: &Option<String>,
) -> ZkfResult<u32> {
    if let Some(raw) = params.get("state_len").or_else(|| params.get("len")) {
        return raw.trim().parse::<u32>().map_err(|_| {
            blackbox_error(
                backend,
                index,
                label,
                format!("invalid poseidon state length '{raw}'"),
            )
        });
    }
    if input_len == output_len {
        return u32::try_from(input_len).map_err(|_| {
            blackbox_error(
                backend,
                index,
                label,
                format!("poseidon state length {} exceeds u32 range", input_len),
            )
        });
    }
    Err(blackbox_error(
        backend,
        index,
        label,
        format!(
            "poseidon requires explicit state length (input_count={input_len}, output_count={output_len})"
        ),
    ))
}

fn encode_message_bytes(values: &[BigInt], bits: &[u32]) -> ZkfResult<Vec<u8>> {
    let mut out = Vec::new();
    for (value, num_bits) in values.iter().zip(bits.iter()) {
        let mut bytes = encode_bigint_to_bytes(value, *num_bits)?;
        out.append(&mut bytes);
    }
    Ok(out)
}

fn encode_bigint_to_bytes(value: &BigInt, num_bits: u32) -> ZkfResult<Vec<u8>> {
    if num_bits == 0 {
        return Err(ZkfError::InvalidArtifact(
            "blackbox input_num_bits must be >= 1".to_string(),
        ));
    }
    let limit = BigInt::from(1u8) << num_bits;
    if value >= &limit {
        return Err(ZkfError::InvalidArtifact(format!(
            "blackbox input value {value} exceeds declared bit width {num_bits}"
        )));
    }

    let byte_len = num_bits.div_ceil(8) as usize;
    let (_, mut bytes) = value.to_bytes_be();
    if bytes.len() > byte_len {
        return Err(ZkfError::InvalidArtifact(format!(
            "blackbox input value {value} does not fit in {byte_len} bytes"
        )));
    }
    if bytes.len() < byte_len {
        let mut padded = vec![0u8; byte_len - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    Ok(bytes)
}

fn expect_output_bytes(
    backend: BackendKind,
    index: usize,
    label: &Option<String>,
    program: &Program,
    witness: &Witness,
    outputs: &[String],
    expected: &[u8],
) -> ZkfResult<()> {
    if outputs.len() != expected.len() {
        return Err(blackbox_error(
            backend,
            index,
            label,
            format!(
                "expected {} outputs for hash constraint, found {}",
                expected.len(),
                outputs.len()
            ),
        ));
    }

    let expected_bigints = expected
        .iter()
        .map(|byte| BigInt::from(*byte))
        .collect::<Vec<_>>();
    expect_output_bigints(
        index,
        label,
        program,
        witness,
        outputs,
        &expected_bigints,
        "hash",
    )
}

fn expect_single_boolean_output(
    index: usize,
    label: &Option<String>,
    program: &Program,
    witness: &Witness,
    outputs: &[String],
    expected: bool,
    op_name: &str,
) -> ZkfResult<()> {
    if outputs.len() != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "{op_name} expects a single boolean output, found {} outputs",
            outputs.len()
        )));
    }

    let actual = output_bigint(program, witness, &outputs[0])?;
    let expected_bigint = if expected {
        BigInt::from(1u8)
    } else {
        BigInt::from(0u8)
    };
    if actual != expected_bigint {
        return Err(ZkfError::Backend(format!(
            "blackbox constraint index={} label={} expected {} output {} but found {}",
            index,
            label.as_deref().unwrap_or("<none>"),
            op_name,
            outputs[0],
            actual
        )));
    }
    Ok(())
}

fn expect_output_bigints(
    index: usize,
    label: &Option<String>,
    program: &Program,
    witness: &Witness,
    outputs: &[String],
    expected: &[BigInt],
    op_name: &str,
) -> ZkfResult<()> {
    if outputs.len() != expected.len() {
        return Err(ZkfError::InvalidArtifact(format!(
            "{op_name} expected {} outputs, found {}",
            expected.len(),
            outputs.len()
        )));
    }

    for (signal, expected_value) in outputs.iter().zip(expected.iter()) {
        let actual = output_bigint(program, witness, signal)?;
        if &actual != expected_value {
            return Err(ZkfError::Backend(format!(
                "blackbox constraint index={} label={} expected output {}={} but found {}",
                index,
                label.as_deref().unwrap_or("<none>"),
                signal,
                expected_value,
                actual
            )));
        }
    }
    Ok(())
}

fn output_bigint(program: &Program, witness: &Witness, signal: &str) -> ZkfResult<BigInt> {
    let value = witness
        .values
        .get(signal)
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: signal.to_string(),
        })?;
    value.normalized_bigint(program.field)
}

fn bigint_to_acir_field(value: &BigInt) -> Result<AcirFieldElement, String> {
    AcirFieldElement::try_from_str(&value.to_str_radix(10))
        .ok_or_else(|| format!("cannot represent value {} as ACIR field element", value))
}

fn bigint_from_acir_field(value: &AcirFieldElement) -> Result<BigInt, String> {
    Ok(BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        &value.to_be_bytes(),
    ))
}

fn bigint_to_usize(value: &BigInt) -> Option<usize> {
    if value.sign() == num_bigint::Sign::Minus {
        return None;
    }
    value.to_str_radix(10).parse::<usize>().ok()
}

fn blackbox_error(
    backend: BackendKind,
    index: usize,
    label: &Option<String>,
    message: String,
) -> ZkfError {
    ZkfError::Backend(format!(
        "{} blackbox constraint index={} label={} failed: {}",
        backend,
        index,
        label.as_deref().unwrap_or("<none>"),
        message
    ))
}
