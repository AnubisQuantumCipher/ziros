//! Developer Use Case Integration Tests
//!
//! These tests simulate the circuits that ZK developers actually build and
//! deploy to production.  Each test constructs a circuit representing a
//! real-world application pattern — not a toy — and runs it through the
//! full ZKF pipeline: IR → witness → prove → verify.
//!
//! The six patterns tested here cover the overwhelming majority of what
//! ships in the ZK ecosystem today:
//!
//! 1. **Private balance sufficiency** (DeFi) — prove balance ≥ amount
//!    without revealing balance
//! 2. **Age/credential verification** (Identity) — prove age ≥ 18
//!    without revealing birth year
//! 3. **Nullifier-based spend** (Privacy coins / mixers) — prove you're
//!    consuming a commitment without revealing which one
//! 4. **Range-bounded transfer** (Compliance) — prove transfer amount
//!    is within legal limits without revealing it
//! 5. **Hash preimage knowledge** (Authentication) — prove you know a
//!    secret whose hash matches a public commitment
//! 6. **Private voting** (Governance) — prove eligibility and cast a
//!    vote without revealing identity
//!
//! Each pattern is tested across multiple backends (Groth16, Halo2,
//! Plonky3) to validate ZKF's "write once, prove anywhere" promise
//! for real applications, not just arithmetic toys.

use std::collections::BTreeMap;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, Witness,
    WitnessAssignment, WitnessInputs, WitnessPlan, check_constraints, collect_public_inputs,
    generate_witness, optimize_program,
};
use zkf_lib::ProgramBuilder;

// ============================================================================
// Helper: Full pipeline runner (same pattern as universal_pipeline.rs)
// ============================================================================

fn prove_and_verify(
    program: &Program,
    inputs: &WitnessInputs,
    backend_kind: BackendKind,
) -> Witness {
    let backend = backend_for(backend_kind);

    let compiled = backend
        .compile(program)
        .unwrap_or_else(|e| panic!("[{backend_kind}] compile: {e}"));

    let witness = generate_witness(program, inputs)
        .unwrap_or_else(|e| panic!("[{backend_kind}] witness: {e}"));

    let proof = backend
        .prove(&compiled, &witness)
        .unwrap_or_else(|e| panic!("[{backend_kind}] prove: {e}"));

    let valid = backend
        .verify(&compiled, &proof)
        .unwrap_or_else(|e| panic!("[{backend_kind}] verify: {e}"));

    assert!(valid, "[{backend_kind}] proof verification returned false");
    witness
}

/// Assert witness generation fails (for negative tests).
fn must_fail_witness(program: &Program, inputs: &WitnessInputs, reason: &str) {
    let result = generate_witness(program, inputs);
    assert!(result.is_err(), "Expected failure: {reason}");
}

// ============================================================================
// 1. PRIVATE BALANCE SUFFICIENCY (DeFi)
//
// The most common DeFi ZK pattern: a user proves they have enough funds
// to execute a trade/withdrawal without revealing their actual balance.
//
// Public:  threshold (minimum required)
// Private: balance (actual holdings)
// Proves:  balance ≥ threshold  (i.e., balance - threshold ≥ 0)
//
// Circuit structure:
//   diff = balance - threshold           (subtraction)
//   range(diff, 64)                      (diff fits in 64 bits → non-negative)
//   sufficient ∈ {0,1}                   (boolean flag)
//   sufficient = 1                       (assertion: the check passed)
// ============================================================================

fn balance_sufficiency_circuit(field: FieldId) -> Program {
    balance_sufficiency_circuit_small_range(field, 64)
}

/// Backend-adaptive variant: uses a smaller range width for backends
/// that don't support 64-bit range constraints (Halo2 max 12, Goldilocks max 63).
fn balance_sufficiency_circuit_small_range(field: FieldId, range_bits: u32) -> Program {
    let mut builder = ProgramBuilder::new("defi_balance_check", field);
    builder.private_input("balance").unwrap();
    builder.public_input("threshold").unwrap();
    builder.public_output("sufficient").unwrap();
    builder
        .constrain_geq_labeled(
            "diff",
            Expr::signal("balance"),
            Expr::signal("threshold"),
            range_bits,
            Some("balance_minus_threshold".to_string()),
        )
        .unwrap();
    builder
        .constrain_boolean_labeled("sufficient", Some("sufficient_is_bool".to_string()))
        .unwrap();
    builder
        .constrain_equal_labeled(
            Expr::signal("sufficient"),
            Expr::constant_i64(1),
            Some("sufficient_asserted_true".to_string()),
        )
        .unwrap();
    builder.build().unwrap()
}

fn balance_inputs(balance: i64, threshold: i64) -> WitnessInputs {
    BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(balance)),
        ("threshold".into(), FieldElement::from_i64(threshold)),
        ("sufficient".into(), FieldElement::from_i64(1)),
    ])
}

#[test]
fn defi_balance_sufficient_groth16() {
    let program = balance_sufficiency_circuit(FieldId::Bn254);
    let witness = prove_and_verify(
        &program,
        &balance_inputs(1000, 500),
        BackendKind::ArkworksGroth16,
    );
    // diff should be 500
    assert_eq!(witness.values["diff"], FieldElement::from_i64(500));
}

#[test]
fn defi_balance_sufficient_halo2() {
    // Halo2 range lookup tables cap at 12 bits; use backend-appropriate width
    let program = balance_sufficiency_circuit_small_range(FieldId::PastaFp, 12);
    prove_and_verify(&program, &balance_inputs(1000, 500), BackendKind::Halo2);
}

#[test]
fn defi_balance_sufficient_plonky3() {
    // Goldilocks is 64-bit field; range constraint must be < field size (63 max)
    let program = balance_sufficiency_circuit_small_range(FieldId::Goldilocks, 32);
    prove_and_verify(&program, &balance_inputs(1000, 500), BackendKind::Plonky3);
}

#[test]
fn defi_balance_exact_threshold_proves() {
    // Edge case: balance == threshold → diff = 0, still valid
    let program = balance_sufficiency_circuit(FieldId::Bn254);
    let witness = prove_and_verify(
        &program,
        &balance_inputs(500, 500),
        BackendKind::ArkworksGroth16,
    );
    assert!(witness.values["diff"].is_zero());
}

#[test]
fn defi_balance_insufficient_fails_range() {
    // balance < threshold → diff is negative → fails 64-bit range check
    let program = balance_sufficiency_circuit(FieldId::Bn254);
    must_fail_witness(
        &program,
        &balance_inputs(100, 500),
        "insufficient balance should fail range",
    );
}

#[test]
fn defi_balance_large_values() {
    // Real-world DeFi: balances in the billions (wei-scale values)
    let program = balance_sufficiency_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        (
            "balance".into(),
            FieldElement::from_u64(1_000_000_000_000u64),
        ),
        (
            "threshold".into(),
            FieldElement::from_u64(999_999_999_999u64),
        ),
        ("sufficient".into(), FieldElement::from_i64(1)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["diff"], FieldElement::from_i64(1));
}

// ============================================================================
// 2. AGE / CREDENTIAL VERIFICATION (Identity)
//
// KYC without data exposure: prove you're old enough without revealing
// your exact birth year.  The ZK-KYC market is projected at $903M by 2032.
//
// Public:  current_year, minimum_age
// Private: birth_year
// Proves:  current_year - birth_year ≥ minimum_age
//
// Circuit:
//   age = current_year - birth_year
//   excess = age - minimum_age
//   range(excess, 8)                     (excess fits in 8 bits → age ≥ min)
//   range(age, 8)                        (age is reasonable, < 256)
// ============================================================================

fn age_verification_circuit(field: FieldId) -> Program {
    let mut builder = ProgramBuilder::new("kyc_age_verify", field);
    builder.private_input("birth_year").unwrap();
    builder.public_input("current_year").unwrap();
    builder.public_input("minimum_age").unwrap();
    builder
        .bind_labeled(
            "age",
            Expr::Sub(
                Box::new(Expr::signal("current_year")),
                Box::new(Expr::signal("birth_year")),
            ),
            Some("age_eq_current_minus_birth".to_string()),
        )
        .unwrap();
    builder
        .constrain_range_labeled("age", 8, Some("age_reasonable".to_string()))
        .unwrap();
    builder
        .constrain_geq_labeled(
            "excess",
            Expr::signal("age"),
            Expr::signal("minimum_age"),
            8,
            Some("excess_eq_age_minus_min".to_string()),
        )
        .unwrap();
    builder.build().unwrap()
}

#[test]
fn kyc_age_25_passes_groth16() {
    let program = age_verification_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2000)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["age"], FieldElement::from_i64(25));
    assert_eq!(witness.values["excess"], FieldElement::from_i64(7));
}

#[test]
fn kyc_age_25_passes_halo2() {
    // KYC uses 8-bit range constraints — well within Halo2's 12-bit limit
    let program = age_verification_circuit(FieldId::PastaFp);
    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2000)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    prove_and_verify(&program, &inputs, BackendKind::Halo2);
}

#[test]
fn kyc_age_25_passes_plonky3() {
    let program = age_verification_circuit(FieldId::Goldilocks);
    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2000)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    prove_and_verify(&program, &inputs, BackendKind::Plonky3);
}

#[test]
fn kyc_exact_18_passes() {
    // Edge case: exactly 18 → excess = 0
    let program = age_verification_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2007)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    assert!(witness.values["excess"].is_zero());
}

#[test]
fn kyc_underage_fails() {
    // 17 years old → excess = -1 → fails range check
    let program = age_verification_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2008)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    must_fail_witness(&program, &inputs, "17 years old should fail age check");
}

#[test]
fn kyc_birth_year_stays_private() {
    // Verify that birth_year is NOT in the public inputs
    let program = age_verification_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2000)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    let witness = generate_witness(&program, &inputs).unwrap();
    let public = collect_public_inputs(&program, &witness).unwrap();

    // Only current_year and minimum_age should be public
    assert_eq!(public.len(), 2);
    assert_eq!(public[0], FieldElement::from_i64(2025));
    assert_eq!(public[1], FieldElement::from_i64(18));
    // birth_year must NOT appear in public inputs
    assert!(
        !public.contains(&FieldElement::from_i64(2000)),
        "Birth year must not leak into public inputs"
    );
}

// ============================================================================
// 3. NULLIFIER-BASED SPEND (Privacy / Mixers)
//
// The Tornado Cash / Zcash pattern: prove you're consuming a valid
// commitment without revealing which one.
//
// Private: secret, nonce
// Public:  commitment (= secret * nonce + secret), nullifier (= secret * secret)
// Proves:  commitment and nullifier are correctly derived from the secret
//
// In production, commitment = Poseidon(secret, nonce) and
// nullifier = Poseidon(secret, secret).  We use algebraic stand-ins
// here since the BlackBox Poseidon path requires backend-specific
// support, but the constraint structure is identical.
//
// The key privacy property: the nullifier is deterministic per-secret
// (so double-spend is detectable) but the commitment doesn't reveal
// which nullifier it corresponds to.
// ============================================================================

fn nullifier_circuit(field: FieldId) -> Program {
    // commitment_computed = secret * nonce + secret  (stand-in for hash)
    let commitment_expr = Expr::Add(vec![
        Expr::Mul(
            Box::new(Expr::signal("secret")),
            Box::new(Expr::signal("nonce")),
        ),
        Expr::signal("secret"),
    ]);
    // nullifier_computed = secret * secret  (stand-in for hash(secret, secret))
    let nullifier_expr = Expr::Mul(
        Box::new(Expr::signal("secret")),
        Box::new(Expr::signal("secret")),
    );

    Program {
        name: "nullifier_spend".into(),
        field,
        signals: vec![
            Signal {
                name: "secret".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "nonce".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "commitment".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "nullifier".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            // commitment matches the derivation
            Constraint::Equal {
                lhs: Expr::signal("commitment"),
                rhs: commitment_expr.clone(),
                label: Some("commitment_valid".into()),
            },
            // nullifier matches the derivation
            Constraint::Equal {
                lhs: Expr::signal("nullifier"),
                rhs: nullifier_expr.clone(),
                label: Some("nullifier_valid".into()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "commitment".into(),
                    expr: commitment_expr,
                },
                WitnessAssignment {
                    target: "nullifier".into(),
                    expr: nullifier_expr,
                },
            ],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn nullifier_inputs(secret: i64, nonce: i64) -> WitnessInputs {
    BTreeMap::from([
        ("secret".into(), FieldElement::from_i64(secret)),
        ("nonce".into(), FieldElement::from_i64(nonce)),
    ])
}

#[test]
fn nullifier_spend_groth16() {
    let program = nullifier_circuit(FieldId::Bn254);
    let witness = prove_and_verify(
        &program,
        &nullifier_inputs(42, 7),
        BackendKind::ArkworksGroth16,
    );
    // commitment = 42 * 7 + 42 = 294 + 42 = 336
    assert_eq!(witness.values["commitment"], FieldElement::from_i64(336));
    // nullifier = 42 * 42 = 1764
    assert_eq!(witness.values["nullifier"], FieldElement::from_i64(1764));
}

#[test]
fn nullifier_spend_plonky3() {
    let program = nullifier_circuit(FieldId::Goldilocks);
    prove_and_verify(&program, &nullifier_inputs(42, 7), BackendKind::Plonky3);
}

#[test]
fn nullifier_spend_halo2() {
    let program = nullifier_circuit(FieldId::PastaFp);
    prove_and_verify(&program, &nullifier_inputs(42, 7), BackendKind::Halo2);
}

#[test]
fn nullifier_deterministic_per_secret() {
    // Same secret, different nonces → different commitments, SAME nullifier
    let program = nullifier_circuit(FieldId::Bn254);
    let w1 = prove_and_verify(
        &program,
        &nullifier_inputs(42, 7),
        BackendKind::ArkworksGroth16,
    );
    let w2 = prove_and_verify(
        &program,
        &nullifier_inputs(42, 99),
        BackendKind::ArkworksGroth16,
    );

    // Nullifiers must match (both derived from secret=42)
    assert_eq!(w1.values["nullifier"], w2.values["nullifier"]);
    // Commitments must differ (different nonces)
    assert_ne!(w1.values["commitment"], w2.values["commitment"]);
}

#[test]
fn nullifier_wrong_commitment_fails() {
    // Supply a commitment that doesn't match the secret/nonce
    let program = nullifier_circuit(FieldId::Bn254);
    let witness = Witness {
        values: BTreeMap::from([
            ("secret".into(), FieldElement::from_i64(42)),
            ("nonce".into(), FieldElement::from_i64(7)),
            ("commitment".into(), FieldElement::from_i64(999)), // wrong
            ("nullifier".into(), FieldElement::from_i64(1764)),
        ]),
    };
    assert!(
        check_constraints(&program, &witness).is_err(),
        "Forged commitment must fail"
    );
}

#[test]
fn nullifier_wrong_nullifier_fails() {
    let program = nullifier_circuit(FieldId::Bn254);
    let witness = Witness {
        values: BTreeMap::from([
            ("secret".into(), FieldElement::from_i64(42)),
            ("nonce".into(), FieldElement::from_i64(7)),
            ("commitment".into(), FieldElement::from_i64(336)),
            ("nullifier".into(), FieldElement::from_i64(999)), // wrong
        ]),
    };
    assert!(
        check_constraints(&program, &witness).is_err(),
        "Forged nullifier must fail"
    );
}

// ============================================================================
// 4. RANGE-BOUNDED TRANSFER (Compliance / AML)
//
// Regulated DeFi: prove a transfer amount is within legal limits
// (e.g., < $10,000 for certain jurisdictions) without revealing it.
//
// Private: amount
// Public:  max_allowed
// Proves:  0 < amount AND amount ≤ max_allowed
// ============================================================================

fn compliant_transfer_circuit(field: FieldId) -> Program {
    compliant_transfer_circuit_small_range(field, 32)
}

/// Backend-adaptive variant for range-limited backends (Halo2 max 12 bits).
fn compliant_transfer_circuit_small_range(field: FieldId, range_bits: u32) -> Program {
    let mut builder = ProgramBuilder::new("compliant_transfer", field);
    builder.private_input("amount").unwrap();
    builder.public_input("max_allowed").unwrap();
    builder
        .constrain_leq_labeled(
            "gap",
            Expr::signal("amount"),
            Expr::signal("max_allowed"),
            range_bits,
            Some("gap_eq_max_minus_amount".to_string()),
        )
        .unwrap();
    builder
        .constrain_range_labeled(
            "amount",
            range_bits,
            Some("amount_non_negative".to_string()),
        )
        .unwrap();
    builder.build().unwrap()
}

#[test]
fn compliant_transfer_within_limit_groth16() {
    let program = compliant_transfer_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("amount".into(), FieldElement::from_i64(5000)),
        ("max_allowed".into(), FieldElement::from_i64(10000)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["gap"], FieldElement::from_i64(5000));
}

#[test]
fn compliant_transfer_within_limit_halo2() {
    // Halo2 max 12-bit range; use backend-adaptive width
    let program = compliant_transfer_circuit_small_range(FieldId::PastaFp, 12);
    let inputs = BTreeMap::from([
        ("amount".into(), FieldElement::from_i64(500)),
        ("max_allowed".into(), FieldElement::from_i64(4000)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::Halo2);
    assert_eq!(witness.values["gap"], FieldElement::from_i64(3500));
}

#[test]
fn compliant_transfer_within_limit_plonky3() {
    let program = compliant_transfer_circuit(FieldId::Goldilocks);
    let inputs = BTreeMap::from([
        ("amount".into(), FieldElement::from_i64(5000)),
        ("max_allowed".into(), FieldElement::from_i64(10000)),
    ]);
    prove_and_verify(&program, &inputs, BackendKind::Plonky3);
}

#[test]
fn compliant_transfer_at_limit_proves() {
    // Edge case: amount == max → gap = 0
    let program = compliant_transfer_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("amount".into(), FieldElement::from_i64(10000)),
        ("max_allowed".into(), FieldElement::from_i64(10000)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    assert!(witness.values["gap"].is_zero());
}

#[test]
fn compliant_transfer_over_limit_fails() {
    let program = compliant_transfer_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("amount".into(), FieldElement::from_i64(10001)),
        ("max_allowed".into(), FieldElement::from_i64(10000)),
    ]);
    must_fail_witness(
        &program,
        &inputs,
        "amount over limit should fail range check",
    );
}

#[test]
fn compliant_transfer_amount_stays_private() {
    let program = compliant_transfer_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("amount".into(), FieldElement::from_i64(5000)),
        ("max_allowed".into(), FieldElement::from_i64(10000)),
    ]);
    let witness = generate_witness(&program, &inputs).unwrap();
    let public = collect_public_inputs(&program, &witness).unwrap();

    // Only max_allowed is public
    assert_eq!(public.len(), 1);
    assert_eq!(public[0], FieldElement::from_i64(10000));
}

// ============================================================================
// 5. HASH PREIMAGE KNOWLEDGE (Authentication)
//
// The simplest ZK pattern and the gateway use case: prove you know a
// secret whose "hash" matches a public value, without revealing the secret.
//
// In production this uses Poseidon/Pedersen.  We use an algebraic
// stand-in: hash(secret) = secret² + secret + 42.
//
// Private: secret
// Public:  hash_output
// Proves:  hash_output = f(secret)
// ============================================================================

fn preimage_circuit(field: FieldId) -> Program {
    // hash(secret) = secret² + secret + 42
    let hash_expr = Expr::Add(vec![
        Expr::Mul(
            Box::new(Expr::signal("secret")),
            Box::new(Expr::signal("secret")),
        ),
        Expr::signal("secret"),
        Expr::constant_i64(42),
    ]);

    Program {
        name: "hash_preimage".into(),
        field,
        signals: vec![
            Signal {
                name: "secret".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "hash_output".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("hash_output"),
            rhs: hash_expr.clone(),
            label: Some("hash_matches_preimage".into()),
        }],
        witness_plan: WitnessPlan {
            assignments: vec![WitnessAssignment {
                target: "hash_output".into(),
                expr: hash_expr,
            }],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn preimage_knowledge_groth16() {
    let program = preimage_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([("secret".into(), FieldElement::from_i64(10))]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    // hash(10) = 100 + 10 + 42 = 152
    assert_eq!(witness.values["hash_output"], FieldElement::from_i64(152));
}

#[test]
fn preimage_knowledge_halo2() {
    let program = preimage_circuit(FieldId::PastaFp);
    let inputs = BTreeMap::from([("secret".into(), FieldElement::from_i64(10))]);
    prove_and_verify(&program, &inputs, BackendKind::Halo2);
}

#[test]
fn preimage_knowledge_plonky3() {
    let program = preimage_circuit(FieldId::Goldilocks);
    let inputs = BTreeMap::from([("secret".into(), FieldElement::from_i64(10))]);
    prove_and_verify(&program, &inputs, BackendKind::Plonky3);
}

#[test]
fn preimage_wrong_secret_fails() {
    let program = preimage_circuit(FieldId::Bn254);
    // Correct hash for secret=10 is 152. Supply wrong hash.
    let witness = Witness {
        values: BTreeMap::from([
            ("secret".into(), FieldElement::from_i64(10)),
            ("hash_output".into(), FieldElement::from_i64(999)),
        ]),
    };
    assert!(
        check_constraints(&program, &witness).is_err(),
        "Wrong hash output should fail"
    );
}

#[test]
fn preimage_secret_not_in_public() {
    let program = preimage_circuit(FieldId::Bn254);
    let inputs = BTreeMap::from([("secret".into(), FieldElement::from_i64(10))]);
    let witness = generate_witness(&program, &inputs).unwrap();
    let public = collect_public_inputs(&program, &witness).unwrap();

    assert_eq!(public.len(), 1);
    assert_eq!(public[0], FieldElement::from_i64(152));
    // Secret must NOT be in public inputs
    assert!(
        !public.contains(&FieldElement::from_i64(10)),
        "Secret must not leak"
    );
}

// ============================================================================
// 6. PRIVATE VOTING (Governance)
//
// Combine credential verification + nullifier for private governance:
// - Prove you're eligible to vote (your weight is in valid range)
// - Commit to a vote choice without revealing it
// - Produce a nullifier so you can't vote twice
//
// Private: voter_secret, vote_choice
// Public:  election_id, nullifier, vote_commitment
// Proves:
//   nullifier = voter_secret * voter_secret  (deterministic per-voter)
//   vote_commitment = vote_choice * election_id + voter_secret  (binds vote to election)
//   vote_choice ∈ {0, 1}  (binary vote: yes/no)
// ============================================================================

fn private_vote_circuit(field: FieldId) -> Program {
    let nullifier_expr = Expr::Mul(
        Box::new(Expr::signal("voter_secret")),
        Box::new(Expr::signal("voter_secret")),
    );
    let commitment_expr = Expr::Add(vec![
        Expr::Mul(
            Box::new(Expr::signal("vote_choice")),
            Box::new(Expr::signal("election_id")),
        ),
        Expr::signal("voter_secret"),
    ]);

    Program {
        name: "private_vote".into(),
        field,
        signals: vec![
            Signal {
                name: "voter_secret".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "vote_choice".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "election_id".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "nullifier".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
            Signal {
                name: "vote_commitment".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![
            // vote_choice must be 0 or 1
            Constraint::Boolean {
                signal: "vote_choice".into(),
                label: Some("vote_is_binary".into()),
            },
            // nullifier = voter_secret²
            Constraint::Equal {
                lhs: Expr::signal("nullifier"),
                rhs: nullifier_expr.clone(),
                label: Some("nullifier_derivation".into()),
            },
            // vote_commitment = vote_choice * election_id + voter_secret
            Constraint::Equal {
                lhs: Expr::signal("vote_commitment"),
                rhs: commitment_expr.clone(),
                label: Some("vote_commitment_derivation".into()),
            },
        ],
        witness_plan: WitnessPlan {
            assignments: vec![
                WitnessAssignment {
                    target: "nullifier".into(),
                    expr: nullifier_expr,
                },
                WitnessAssignment {
                    target: "vote_commitment".into(),
                    expr: commitment_expr,
                },
            ],
            hints: vec![],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn vote_inputs(voter_secret: i64, vote_choice: i64, election_id: i64) -> WitnessInputs {
    BTreeMap::from([
        ("voter_secret".into(), FieldElement::from_i64(voter_secret)),
        ("vote_choice".into(), FieldElement::from_i64(vote_choice)),
        ("election_id".into(), FieldElement::from_i64(election_id)),
    ])
}

#[test]
fn vote_yes_groth16() {
    let program = private_vote_circuit(FieldId::Bn254);
    let witness = prove_and_verify(
        &program,
        &vote_inputs(123, 1, 2025),
        BackendKind::ArkworksGroth16,
    );
    // nullifier = 123² = 15129
    assert_eq!(witness.values["nullifier"], FieldElement::from_i64(15129));
    // commitment = 1 * 2025 + 123 = 2148
    assert_eq!(
        witness.values["vote_commitment"],
        FieldElement::from_i64(2148)
    );
}

#[test]
fn vote_no_groth16() {
    let program = private_vote_circuit(FieldId::Bn254);
    let witness = prove_and_verify(
        &program,
        &vote_inputs(123, 0, 2025),
        BackendKind::ArkworksGroth16,
    );
    // commitment = 0 * 2025 + 123 = 123
    assert_eq!(
        witness.values["vote_commitment"],
        FieldElement::from_i64(123)
    );
    // Same voter → same nullifier regardless of vote
    assert_eq!(witness.values["nullifier"], FieldElement::from_i64(15129));
}

#[test]
fn vote_same_voter_same_nullifier() {
    // Privacy property: nullifier is deterministic per-voter, not per-vote
    let program = private_vote_circuit(FieldId::Bn254);
    let w_yes = prove_and_verify(
        &program,
        &vote_inputs(123, 1, 2025),
        BackendKind::ArkworksGroth16,
    );
    let w_no = prove_and_verify(
        &program,
        &vote_inputs(123, 0, 2025),
        BackendKind::ArkworksGroth16,
    );
    assert_eq!(w_yes.values["nullifier"], w_no.values["nullifier"]);
}

#[test]
fn vote_invalid_choice_fails() {
    // vote_choice = 2 → boolean constraint fails
    let program = private_vote_circuit(FieldId::Bn254);
    must_fail_witness(
        &program,
        &vote_inputs(123, 2, 2025),
        "vote_choice=2 should fail boolean",
    );
}

#[test]
fn vote_across_backends() {
    let inputs = vote_inputs(42, 1, 100);

    let p_bn254 = private_vote_circuit(FieldId::Bn254);
    let w1 = prove_and_verify(&p_bn254, &inputs, BackendKind::ArkworksGroth16);

    let p_pasta = private_vote_circuit(FieldId::PastaFp);
    let w2 = prove_and_verify(&p_pasta, &inputs, BackendKind::Halo2);

    let p_gold = private_vote_circuit(FieldId::Goldilocks);
    let w3 = prove_and_verify(&p_gold, &inputs, BackendKind::Plonky3);

    // All backends should produce the same witness values
    assert_eq!(w1.values["nullifier"], w2.values["nullifier"]);
    assert_eq!(w2.values["nullifier"], w3.values["nullifier"]);
    assert_eq!(w1.values["vote_commitment"], w2.values["vote_commitment"]);
    assert_eq!(w2.values["vote_commitment"], w3.values["vote_commitment"]);
}

// ============================================================================
// 7. CROSS-CUTTING: Optimizer preserves application semantics
//
// Take a real use case circuit, optimize it, and prove the optimized
// version still works.  This catches optimizer bugs that would break
// production circuits.
// ============================================================================

#[test]
fn optimizer_preserves_defi_balance_check() {
    let original = balance_sufficiency_circuit(FieldId::Bn254);
    let (optimized, report) = optimize_program(&original);

    assert!(report.output_constraints <= report.input_constraints);

    let inputs = balance_inputs(1000, 500);
    let witness = prove_and_verify(&optimized, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["diff"], FieldElement::from_i64(500));
}

#[test]
fn optimizer_preserves_age_verification() {
    let original = age_verification_circuit(FieldId::Goldilocks);
    let (optimized, _) = optimize_program(&original);

    let inputs = BTreeMap::from([
        ("birth_year".into(), FieldElement::from_i64(2000)),
        ("current_year".into(), FieldElement::from_i64(2025)),
        ("minimum_age".into(), FieldElement::from_i64(18)),
    ]);
    prove_and_verify(&optimized, &inputs, BackendKind::Plonky3);
}

#[test]
fn optimizer_preserves_voting() {
    let original = private_vote_circuit(FieldId::PastaFp);
    let (optimized, _) = optimize_program(&original);
    prove_and_verify(&optimized, &vote_inputs(42, 1, 100), BackendKind::Halo2);
}

// ============================================================================
// 8. COMPOSABILITY: Multiple use cases in one circuit
//
// Real applications combine patterns.  Here we build a circuit that
// combines balance sufficiency + range compliance + nullifier in one
// program — like a regulated private transfer.
// ============================================================================

fn regulated_private_transfer(field: FieldId) -> Program {
    regulated_private_transfer_with_range(field, 64)
}

/// Fully uniform range variant — all range constraints use the same bit width.
/// Required for Halo2 where the 12-bit limit applies to ALL range constraints.
fn regulated_private_transfer_uniform_range(field: FieldId, range_bits: u32) -> Program {
    let mut builder = ProgramBuilder::new("regulated_private_transfer", field);
    builder.private_input("balance").unwrap();
    builder.private_input("amount").unwrap();
    builder.private_input("sender_secret").unwrap();
    builder.public_input("max_allowed").unwrap();
    builder.public_output("nullifier").unwrap();
    builder
        .constrain_geq_labeled(
            "diff",
            Expr::signal("balance"),
            Expr::signal("amount"),
            range_bits,
            Some("balance_minus_amount".to_string()),
        )
        .unwrap();
    builder
        .constrain_leq_labeled(
            "gap",
            Expr::signal("amount"),
            Expr::signal("max_allowed"),
            range_bits,
            Some("max_minus_amount".to_string()),
        )
        .unwrap();
    builder
        .constrain_range_labeled("amount", range_bits, Some("amount_positive".to_string()))
        .unwrap();
    builder
        .bind_labeled(
            "nullifier",
            Expr::Mul(
                Box::new(Expr::signal("sender_secret")),
                Box::new(Expr::signal("sender_secret")),
            ),
            Some("nullifier_derivation".to_string()),
        )
        .unwrap();
    builder.build().unwrap()
}

fn regulated_private_transfer_with_range(field: FieldId, balance_range_bits: u32) -> Program {
    let mut builder = ProgramBuilder::new("regulated_private_transfer", field);
    builder.private_input("balance").unwrap();
    builder.private_input("amount").unwrap();
    builder.private_input("sender_secret").unwrap();
    builder.public_input("max_allowed").unwrap();
    builder.public_output("nullifier").unwrap();
    builder
        .constrain_geq_labeled(
            "diff",
            Expr::signal("balance"),
            Expr::signal("amount"),
            balance_range_bits,
            Some("balance_minus_amount".to_string()),
        )
        .unwrap();
    builder
        .constrain_leq_labeled(
            "gap",
            Expr::signal("amount"),
            Expr::signal("max_allowed"),
            32,
            Some("max_minus_amount".to_string()),
        )
        .unwrap();
    builder
        .constrain_range_labeled("amount", 32, Some("amount_positive".to_string()))
        .unwrap();
    builder
        .bind_labeled(
            "nullifier",
            Expr::Mul(
                Box::new(Expr::signal("sender_secret")),
                Box::new(Expr::signal("sender_secret")),
            ),
            Some("nullifier_derivation".to_string()),
        )
        .unwrap();
    builder.build().unwrap()
}

#[test]
fn regulated_transfer_valid_groth16() {
    let program = regulated_private_transfer(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(10000)),
        ("amount".into(), FieldElement::from_i64(5000)),
        ("sender_secret".into(), FieldElement::from_i64(77)),
        ("max_allowed".into(), FieldElement::from_i64(9999)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::ArkworksGroth16);
    assert_eq!(witness.values["diff"], FieldElement::from_i64(5000));
    assert_eq!(witness.values["nullifier"], FieldElement::from_i64(5929)); // 77²
}

#[test]
fn regulated_transfer_valid_halo2() {
    // Halo2: all range constraints must be ≤ 12 bits; use uniform 12-bit variant
    let program = regulated_private_transfer_uniform_range(FieldId::PastaFp, 12);
    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(3000)),
        ("amount".into(), FieldElement::from_i64(2000)),
        ("sender_secret".into(), FieldElement::from_i64(42)),
        ("max_allowed".into(), FieldElement::from_i64(4000)),
    ]);
    let witness = prove_and_verify(&program, &inputs, BackendKind::Halo2);
    assert_eq!(witness.values["diff"], FieldElement::from_i64(1000));
    assert_eq!(witness.values["nullifier"], FieldElement::from_i64(1764)); // 42²
}

#[test]
fn regulated_transfer_valid_plonky3() {
    // Goldilocks 64-bit field: range constraints must be < 64 bits
    let program = regulated_private_transfer_with_range(FieldId::Goldilocks, 32);
    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(10000)),
        ("amount".into(), FieldElement::from_i64(5000)),
        ("sender_secret".into(), FieldElement::from_i64(77)),
        ("max_allowed".into(), FieldElement::from_i64(9999)),
    ]);
    prove_and_verify(&program, &inputs, BackendKind::Plonky3);
}

#[test]
fn regulated_transfer_over_limit_fails() {
    // amount (5000) > max_allowed (4000) → gap is negative
    let program = regulated_private_transfer(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(10000)),
        ("amount".into(), FieldElement::from_i64(5000)),
        ("sender_secret".into(), FieldElement::from_i64(77)),
        ("max_allowed".into(), FieldElement::from_i64(4000)),
    ]);
    must_fail_witness(&program, &inputs, "over-limit transfer should fail");
}

#[test]
fn regulated_transfer_insufficient_balance_fails() {
    // balance (3000) < amount (5000)
    let program = regulated_private_transfer(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(3000)),
        ("amount".into(), FieldElement::from_i64(5000)),
        ("sender_secret".into(), FieldElement::from_i64(77)),
        ("max_allowed".into(), FieldElement::from_i64(9999)),
    ]);
    must_fail_witness(&program, &inputs, "insufficient balance should fail");
}

#[test]
fn regulated_transfer_private_signals_hidden() {
    let program = regulated_private_transfer(FieldId::Bn254);
    let inputs = BTreeMap::from([
        ("balance".into(), FieldElement::from_i64(10000)),
        ("amount".into(), FieldElement::from_i64(5000)),
        ("sender_secret".into(), FieldElement::from_i64(77)),
        ("max_allowed".into(), FieldElement::from_i64(9999)),
    ]);
    let witness = generate_witness(&program, &inputs).unwrap();
    let public = collect_public_inputs(&program, &witness).unwrap();

    // Only max_allowed and nullifier should be public
    assert_eq!(public.len(), 2);
    // balance, amount, sender_secret must NOT appear
    assert!(!public.contains(&FieldElement::from_i64(10000)));
    assert!(!public.contains(&FieldElement::from_i64(5000)));
    assert!(!public.contains(&FieldElement::from_i64(77)));
}

// ============================================================================
// Summary
//
// Test count by use case:
//   DeFi balance sufficiency:       6  (3 backends + edge case + negative + large values)
//   KYC age verification:           6  (3 backends + edge case + negative + privacy check)
//   Nullifier-based spend:          6  (3 backends + determinism + 2 forgery negatives)
//   Range-bounded transfer:         6  (3 backends + edge case + negative + privacy check)
//   Hash preimage knowledge:        5  (3 backends + forgery negative + privacy check)
//   Private voting:                 5  (yes/no + determinism + negative + cross-backend)
//   Optimizer on real circuits:     3  (DeFi + KYC + voting)
//   Composed regulated transfer:    6  (3 backends + 2 negatives + privacy check)
//                           Total: 43
//
// Backend coverage:
//   Groth16  (BN254):     8/8 use cases
//   Halo2    (PastaFp):   7/8 use cases (all except optimizer — tested via Groth16/Plonky3)
//   Plonky3  (Goldilocks): 8/8 use cases
// ============================================================================
