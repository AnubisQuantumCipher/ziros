#[path = "../src/spec.rs"]
mod spec;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_lib::{export_groth16_solidity_verifier, foundry_project_dir, FieldElement, WitnessInputs};

fn inputs(balance: i64, purchase: i64, fee: i64) -> WitnessInputs {
    BTreeMap::from([
        ("balance_cents".to_string(), FieldElement::from_i64(balance)),
        (
            "purchase_cents".to_string(),
            FieldElement::from_i64(purchase),
        ),
        ("fee_cents".to_string(), FieldElement::from_i64(fee)),
    ])
}

fn expected_commitment(balance: i64) -> FieldElement {
    zkf_lib::poseidon_hash4_bn254(&[
        FieldElement::from_i64(balance),
        FieldElement::ZERO,
        FieldElement::ZERO,
        FieldElement::ZERO,
    ])
    .expect("poseidon commitment")
}

fn assert_public_outputs(
    outputs: &[FieldElement],
    approved: i64,
    total_cents: i64,
    commitment: &FieldElement,
) {
    assert_eq!(
        outputs.len(),
        3,
        "expected approved, total_cents, balance_commitment"
    );
    assert_eq!(
        outputs[0],
        FieldElement::from_i64(approved),
        "approved mismatch"
    );
    assert_eq!(
        outputs[1],
        FieldElement::from_i64(total_cents),
        "total_cents mismatch"
    );
    assert_eq!(outputs[2], *commitment, "balance_commitment mismatch");
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough for tests")
        .as_nanos();
    std::env::temp_dir().join(format!("private_budget_approval_{label}_{stamp}"))
}

#[test]
fn budget_approval_builder_app_proves_verifies_and_exports() {
    let handle = std::thread::Builder::new()
        .name("private-budget-approval-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            let (spec, program) = spec::load_program().expect("program");
            assert_eq!(
                spec.public_outputs,
                vec![
                    "approved".to_string(),
                    "total_cents".to_string(),
                    "balance_commitment".to_string(),
                ]
            );

            let cases = [
                (10_000, 7_500, 200, 1, 7_700),
                (7_700, 7_500, 200, 1, 7_700),
                (7_600, 7_500, 200, 0, 7_700),
            ];
            let mut export_artifact: Option<zkf_lib::EmbeddedProof> = None;

            for (balance, purchase, fee, approved, total) in cases {
                let witness_inputs = inputs(balance, purchase, fee);
                let checked = zkf_lib::check(&program, &witness_inputs, None, None)
                    .expect("check should pass");
                let commitment = expected_commitment(balance);
                assert_public_outputs(&checked.public_inputs, approved, total, &commitment);

                let embedded =
                    zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                        zkf_lib::compile_and_prove_default(&program, &witness_inputs, None, None)
                    })
                    .expect("proof should succeed");

                assert_eq!(embedded.artifact.public_inputs, checked.public_inputs);
                assert!(
                    zkf_lib::verify(&embedded.compiled, &embedded.artifact).expect("verify"),
                    "proof should verify"
                );
                if balance == 10_000 {
                    export_artifact = Some(embedded);
                }
            }

            let embedded = export_artifact.expect("expected a reusable valid proof artifact");

            let mut tampered = embedded.artifact.clone();
            tampered.public_inputs[0] = FieldElement::from_i64(0);
            let tampered_verified = zkf_lib::verify(&embedded.compiled, &tampered).unwrap_or(false);
            assert!(
                !tampered_verified,
                "tampered public inputs must fail verification"
            );

            let verifier = export_groth16_solidity_verifier(
                &embedded.artifact,
                Some("PrivateBudgetApprovalVerifier"),
            )
            .expect("solidity verifier export");
            assert!(verifier.contains("contract PrivateBudgetApprovalVerifier"));

            let calldata =
                proof_to_calldata_json(&embedded.artifact.proof, &embedded.artifact.public_inputs)
                    .expect("calldata json");
            assert!(calldata.get("public_inputs").is_some());

            let foundry_output = generate_foundry_test_from_artifact(
                &embedded.artifact.proof,
                &embedded.artifact.public_inputs,
                "src/PrivateBudgetApprovalVerifier.sol",
                "PrivateBudgetApprovalVerifier",
            )
            .expect("foundry test generation");
            assert!(foundry_output.source.contains("test_tamperedProofFails"));

            let export_dir = unique_temp_dir("export");
            let foundry_dir = foundry_project_dir(&export_dir);
            fs::create_dir_all(&export_dir).expect("export dir");
            zkf_lib::ensure_foundry_layout(&foundry_dir).expect("foundry layout");
            fs::write(export_dir.join("verifier.sol"), verifier).expect("write verifier");
            fs::write(
                export_dir.join("calldata.json"),
                serde_json::to_string_pretty(&calldata).expect("serialize calldata"),
            )
            .expect("write calldata");
            fs::write(
                foundry_dir
                    .join("src")
                    .join("PrivateBudgetApprovalVerifier.sol"),
                export_groth16_solidity_verifier(
                    &embedded.artifact,
                    Some("PrivateBudgetApprovalVerifier"),
                )
                .expect("regenerate verifier"),
            )
            .expect("write foundry verifier");
            fs::write(
                foundry_dir
                    .join("test")
                    .join("PrivateBudgetApprovalVerifier.t.sol"),
                foundry_output.source,
            )
            .expect("write foundry test");

            assert!(foundry_dir.join("foundry.toml").exists());
            assert!(fs::read_to_string(
                foundry_dir
                    .join("test")
                    .join("PrivateBudgetApprovalVerifier.t.sol")
            )
            .expect("read foundry test")
            .contains("test_tamperedProofFails"));

            let _ = fs::remove_dir_all(export_dir);
        })
        .expect("spawn smoke thread");

    handle.join().expect("smoke thread should succeed");
}
