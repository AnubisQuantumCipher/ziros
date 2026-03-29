use proptest::prelude::*;
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::{
    enrich_witness_for_proving, lookup_lowering, lower_blackbox_program,
};
use zkf_core::ir::LookupTable;
use zkf_core::{
    BackendKind, BlackBoxOp, CompiledProgram, Constraint, Expr, FieldElement, FieldId, Program,
    Signal, Visibility, Witness, WitnessPlan, check_constraints, generate_witness,
};

fn lookup_program() -> Program {
    Program {
        name: "lookup-lowering-prop".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "selector".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "mapped".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Lookup {
            inputs: vec![Expr::Signal("selector".to_string())],
            table: "table".to_string(),
            outputs: Some(vec!["mapped".to_string()]),
            label: Some("selector_lookup".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        lookup_tables: vec![LookupTable {
            name: "table".to_string(),
            columns: vec!["selector".to_string(), "mapped".to_string()],
            values: vec![
                vec![FieldElement::from_i64(0), FieldElement::from_i64(5)],
                vec![FieldElement::from_i64(1), FieldElement::from_i64(9)],
                vec![FieldElement::from_i64(2), FieldElement::from_i64(17)],
                vec![FieldElement::from_i64(3), FieldElement::from_i64(33)],
            ],
        }],
        ..Default::default()
    }
}

proptest! {
    #[test]
    fn lookup_lowering_preserves_bounded_witnesses(selector in 0u8..4) {
        let original = lookup_program();
        let original_witness = generate_witness(
            &original,
            &BTreeMap::from([(
                "selector".to_string(),
                FieldElement::from_u64(u64::from(selector)),
            )]),
        ).expect("original lookup witness");
        check_constraints(&original, &original_witness).expect("original witness must satisfy original constraints");

        let lowered = lookup_lowering::lower_lookup_constraints(&original).expect("lookup lowering");
        let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, lowered.clone());
        compiled.original_program = Some(original.clone());

        let enriched = enrich_witness_for_proving(&compiled, &original_witness)
            .expect("aux witness enrichment should succeed");
        check_constraints(&compiled.program, &enriched)
            .expect("lowered witness must satisfy lowered constraints");

        prop_assert_eq!(
            enriched.values.get("mapped"),
            original_witness.values.get("mapped")
        );
    }
}

fn blackbox_program(
    op: BlackBoxOp,
    field: FieldId,
    input_count: usize,
    output_count: usize,
    params: BTreeMap<String, String>,
) -> Program {
    let mut signals = Vec::with_capacity(input_count + output_count);
    let mut inputs = Vec::with_capacity(input_count);
    let mut outputs = Vec::with_capacity(output_count);

    for index in 0..input_count {
        let name = format!("in{index}");
        signals.push(Signal {
            name: name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        inputs.push(Expr::Signal(name));
    }

    for index in 0..output_count {
        let name = format!("out{index}");
        signals.push(Signal {
            name: name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        outputs.push(name);
    }

    Program {
        name: format!("{}-runtime-checks", op.as_str()),
        field,
        signals,
        constraints: vec![Constraint::BlackBox {
            op,
            inputs,
            outputs,
            params,
            label: Some("runtime-check".to_string()),
        }],
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    }
}

fn compiled_blackbox_program(original: Program) -> CompiledProgram {
    let lowered = lower_blackbox_program(&original).expect("blackbox lowering");
    let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, lowered);
    compiled.original_program = Some(original);
    compiled
}

fn runtime_check_blackbox(
    compiled: &CompiledProgram,
    witness: &Witness,
) -> zkf_core::ZkfResult<Witness> {
    let enriched = enrich_witness_for_proving(compiled, witness)?;
    check_constraints(&compiled.program, &enriched)?;
    Ok(enriched)
}

fn sha256_program() -> Program {
    blackbox_program(BlackBoxOp::Sha256, FieldId::Bn254, 1, 32, BTreeMap::new())
}

fn sha256_correct_witness(input: u8) -> Witness {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest([input]);
    let mut values = BTreeMap::new();
    values.insert("in0".to_string(), FieldElement::from_u64(u64::from(input)));
    for (index, byte) in digest.iter().enumerate() {
        values.insert(
            format!("out{index}"),
            FieldElement::from_u64(u64::from(*byte)),
        );
    }
    Witness { values }
}

fn sha256_wrong_witness(input: u8) -> Witness {
    let mut witness = sha256_correct_witness(input);
    let value = witness
        .values
        .get_mut("out0")
        .expect("sha256 witness should contain first output byte");
    *value = if *value == FieldElement::from_u64(0) {
        FieldElement::from_u64(1)
    } else {
        FieldElement::from_u64(0)
    };
    witness
}

fn poseidon_program() -> Program {
    blackbox_program(
        BlackBoxOp::Poseidon,
        FieldId::Bn254,
        4,
        4,
        BTreeMap::from([("state_len".to_string(), "4".to_string())]),
    )
}

fn poseidon_correct_witness() -> Witness {
    use acir::FieldElement as AcirFieldElement;
    use bn254_blackbox_solver::poseidon2_permutation;
    use num_bigint::{BigInt, Sign};

    let inputs = vec![
        AcirFieldElement::from(1u128),
        AcirFieldElement::from(2u128),
        AcirFieldElement::from(3u128),
        AcirFieldElement::from(4u128),
    ];
    let outputs = poseidon2_permutation(&inputs, 4).expect("poseidon reference permutation");
    let mut values = BTreeMap::new();
    for (index, input) in inputs.into_iter().enumerate() {
        let bigint = BigInt::from_bytes_be(Sign::Plus, &input.to_be_bytes());
        values.insert(
            format!("in{index}"),
            FieldElement::from_bigint_with_field(bigint, FieldId::Bn254),
        );
    }
    for (index, output) in outputs.into_iter().enumerate() {
        let bigint = BigInt::from_bytes_be(Sign::Plus, &output.to_be_bytes());
        values.insert(
            format!("out{index}"),
            FieldElement::from_bigint_with_field(bigint, FieldId::Bn254),
        );
    }
    Witness { values }
}

fn poseidon_wrong_witness() -> Witness {
    let mut witness = poseidon_correct_witness();
    witness
        .values
        .insert("out0".to_string(), FieldElement::from_u64(0));
    witness
}

#[cfg(feature = "native-blackbox-solvers")]
fn ecdsa_program(op: BlackBoxOp, input_count: usize) -> Program {
    blackbox_program(op, FieldId::Bn254, input_count, 1, BTreeMap::new())
}

#[cfg(feature = "native-blackbox-solvers")]
fn encode_ecdsa_abi(uncompressed_pubkey: &[u8], signature: &[u8], msg: &[u8; 32]) -> [u8; 160] {
    let mut input = [0u8; 160];
    input[..32].copy_from_slice(&uncompressed_pubkey[1..33]);
    input[32..64].copy_from_slice(&uncompressed_pubkey[33..65]);
    input[64..128].copy_from_slice(signature);
    input[128..160].copy_from_slice(msg);
    input
}

#[cfg(feature = "native-blackbox-solvers")]
fn ecdsa_witness(input: &[u8; 160], claimed_result: bool) -> Witness {
    let mut values = BTreeMap::new();
    for (index, byte) in input.iter().enumerate() {
        values.insert(
            format!("in{index}"),
            FieldElement::from_u64(u64::from(*byte)),
        );
    }
    values.insert(
        "out0".to_string(),
        FieldElement::from_u64(u64::from(claimed_result)),
    );
    Witness { values }
}

#[cfg(feature = "native-blackbox-solvers")]
fn secp256k1_valid_input() -> [u8; 160] {
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};

    let mut secret = [0u8; 32];
    secret[31] = 1;
    let signing_key = K256SigningKey::from_bytes(&secret.into()).expect("valid secp256k1 key");
    let msg = [0x11u8; 32];
    let signature: K256Signature = signing_key
        .sign_prehash(&msg)
        .expect("deterministic secp256k1 prehash signature");
    let signature = signature.normalize_s().unwrap_or(signature);
    let pubkey = signing_key.verifying_key().to_encoded_point(false);
    encode_ecdsa_abi(pubkey.as_bytes(), signature.to_bytes().as_slice(), &msg)
}

#[cfg(feature = "native-blackbox-solvers")]
fn secp256r1_valid_input() -> [u8; 160] {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

    let mut secret = [0u8; 32];
    secret[31] = 2;
    let signing_key = P256SigningKey::from_bytes(&secret.into()).expect("valid secp256r1 key");
    let msg = [0x22u8; 32];
    let signature: P256Signature = signing_key
        .sign_prehash(&msg)
        .expect("deterministic secp256r1 prehash signature");
    let signature = signature.normalize_s().unwrap_or(signature);
    let pubkey = signing_key.verifying_key().to_encoded_point(false);
    encode_ecdsa_abi(pubkey.as_bytes(), signature.to_bytes().as_slice(), &msg)
}

#[cfg(feature = "native-blackbox-solvers")]
fn tamper_ecdsa_message(mut input: [u8; 160]) -> [u8; 160] {
    input[159] ^= 0x01;
    input
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn sha256_runtime_blackbox_path_accepts_correct_outputs(input in any::<u8>()) {
        let compiled = compiled_blackbox_program(sha256_program());
        let witness = sha256_correct_witness(input);
        let enriched = runtime_check_blackbox(&compiled, &witness)
            .expect("correct sha256 witness should survive lower -> enrich -> check");
        prop_assert_eq!(
            enriched.values.get("out0"),
            witness.values.get("out0")
        );
    }

    #[test]
    fn sha256_runtime_blackbox_path_rejects_wrong_outputs(input in any::<u8>()) {
        let compiled = compiled_blackbox_program(sha256_program());
        let err = runtime_check_blackbox(&compiled, &sha256_wrong_witness(input))
            .expect_err("wrong sha256 output must fail closed");
        prop_assert!(
            err.to_string().contains("constraint"),
            "expected constraint failure, got {err}"
        );
    }
}

#[test]
fn poseidon_runtime_blackbox_path_accepts_reference_outputs() {
    let compiled = compiled_blackbox_program(poseidon_program());
    runtime_check_blackbox(&compiled, &poseidon_correct_witness())
        .expect("correct poseidon witness should survive lower -> enrich -> check");
}

#[test]
fn poseidon_runtime_blackbox_path_rejects_wrong_outputs() {
    let compiled = compiled_blackbox_program(poseidon_program());
    let err = runtime_check_blackbox(&compiled, &poseidon_wrong_witness())
        .expect_err("wrong poseidon output must fail closed");
    assert!(
        err.to_string().contains("constraint"),
        "expected constraint failure, got {err}"
    );
}

#[cfg(feature = "native-blackbox-solvers")]
#[test]
fn ecdsa_secp256k1_runtime_blackbox_path_accepts_valid_and_rejects_wrong_branch() {
    let compiled = compiled_blackbox_program(ecdsa_program(BlackBoxOp::EcdsaSecp256k1, 160));
    runtime_check_blackbox(&compiled, &ecdsa_witness(&secp256k1_valid_input(), true))
        .expect("valid secp256k1 witness should survive lower -> enrich -> check");
    let err = runtime_check_blackbox(&compiled, &ecdsa_witness(&secp256k1_valid_input(), false))
        .expect_err("valid secp256k1 signature claiming false must fail");
    assert!(
        err.to_string().contains("constraint"),
        "expected constraint failure, got {err}"
    );
}

#[cfg(feature = "native-blackbox-solvers")]
#[test]
fn ecdsa_secp256k1_runtime_blackbox_path_rejects_tampered_claimed_true() {
    let compiled = compiled_blackbox_program(ecdsa_program(BlackBoxOp::EcdsaSecp256k1, 160));
    let err = runtime_check_blackbox(
        &compiled,
        &ecdsa_witness(&tamper_ecdsa_message(secp256k1_valid_input()), true),
    )
    .expect_err("tampered secp256k1 signature claiming true must fail");
    assert!(
        err.to_string().contains("constraint"),
        "expected constraint failure, got {err}"
    );
}

#[cfg(feature = "native-blackbox-solvers")]
#[test]
fn ecdsa_secp256r1_runtime_blackbox_path_accepts_valid_and_rejects_wrong_branch() {
    let compiled = compiled_blackbox_program(ecdsa_program(BlackBoxOp::EcdsaSecp256r1, 160));
    runtime_check_blackbox(&compiled, &ecdsa_witness(&secp256r1_valid_input(), true))
        .expect("valid secp256r1 witness should survive lower -> enrich -> check");
    let err = runtime_check_blackbox(&compiled, &ecdsa_witness(&secp256r1_valid_input(), false))
        .expect_err("valid secp256r1 signature claiming false must fail");
    assert!(
        err.to_string().contains("constraint"),
        "expected constraint failure, got {err}"
    );
}

#[cfg(feature = "native-blackbox-solvers")]
#[test]
fn ecdsa_secp256r1_runtime_blackbox_path_rejects_tampered_claimed_true() {
    let compiled = compiled_blackbox_program(ecdsa_program(BlackBoxOp::EcdsaSecp256r1, 160));
    let err = runtime_check_blackbox(
        &compiled,
        &ecdsa_witness(&tamper_ecdsa_message(secp256r1_valid_input()), true),
    )
    .expect_err("tampered secp256r1 signature claiming true must fail");
    assert!(
        err.to_string().contains("constraint"),
        "expected constraint failure, got {err}"
    );
}

#[cfg(feature = "native-blackbox-solvers")]
#[test]
fn ecdsa_runtime_blackbox_path_rejects_malformed_abi() {
    let err = lower_blackbox_program(&ecdsa_program(BlackBoxOp::EcdsaSecp256k1, 159))
        .expect_err("malformed ecdsa ABI must fail closed");
    assert!(
        err.to_string().contains("inputs=159"),
        "expected malformed ABI rejection, got {err}"
    );
}
