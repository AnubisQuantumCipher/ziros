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

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zkf_core::{BackendKind, FrontendProvenance, PackageManifest};
use zkf_lib::{
    Expr, FieldElement, FieldId, MerklePathNodeV1, Program, ProgramBuilder, WitnessInputs,
    ZkfError, ZkfResult, poseidon_hash4_bn254,
};

const MERKLE_DEPTH: usize = 3;
const MERKLE_LEAVES: usize = 1 << MERKLE_DEPTH;
const SERVICE_ID: u64 = 1001;
const ALT_SERVICE_ID: u64 = 2002;
const CURRENT_YEAR: u64 = 2025;
const EXPIRY_FLOOR_YEAR: u64 = CURRENT_YEAR + 1;
const BASIC_MIN_BALANCE: u64 = 1_000;
const PREMIUM_MIN_BALANCE_EXCLUSIVE: u64 = 50_001;
const BASIC_MAX_BALANCE: u64 = 50_000;
const REJECT_MAX_BALANCE: u64 = 999;

#[derive(Clone)]
struct CircuitConfig {
    name: &'static str,
    service_id: u64,
    registry_root: FieldElement,
}

#[derive(Clone)]
struct RegistryFixture {
    root: FieldElement,
    path: Vec<MerklePathNodeV1>,
    leaf_index: usize,
}

#[derive(Serialize)]
struct ExampleSummary {
    valid_public_outputs: BTreeMap<String, String>,
    low_balance_public_outputs: BTreeMap<String, String>,
    hand_checked_private_values: BTreeMap<String, String>,
    registry: BTreeMap<String, String>,
    counts: BTreeMap<String, usize>,
    package_manifest: String,
    premium_floor_note: String,
    witness_pipeline_note: String,
}

fn signal(name: &str) -> Expr {
    Expr::signal(name)
}

fn constant(value: i64) -> Expr {
    Expr::constant_i64(value)
}

fn add(terms: Vec<Expr>) -> Expr {
    Expr::Add(terms)
}

fn sub(lhs: Expr, rhs: Expr) -> Expr {
    Expr::Sub(Box::new(lhs), Box::new(rhs))
}

fn mul(lhs: Expr, rhs: Expr) -> Expr {
    Expr::Mul(Box::new(lhs), Box::new(rhs))
}

fn assign_and_bind(builder: &mut ProgramBuilder, target: &str, expr: Expr) -> ZkfResult<()> {
    builder.add_assignment(target, expr.clone())?;
    builder.constrain_equal(signal(target), expr)?;
    Ok(())
}

fn constrain_boolean_explicit(builder: &mut ProgramBuilder, name: &str) -> ZkfResult<()> {
    builder.constrain_boolean(name)?;
    builder.constrain_equal(
        mul(
            signal(name),
            sub(Expr::Const(FieldElement::ONE), signal(name)),
        ),
        Expr::Const(FieldElement::ZERO),
    )?;
    Ok(())
}

fn conditional_gap(
    builder: &mut ProgramBuilder,
    flag: &str,
    gap: &str,
    expr: Expr,
    bits: u32,
) -> ZkfResult<()> {
    builder.constrain_range(gap, bits)?;
    builder.constrain_equal(
        mul(signal(flag), sub(signal(gap), expr)),
        Expr::Const(FieldElement::ZERO),
    )?;
    Ok(())
}

fn anchor_with_one(builder: &mut ProgramBuilder, signal_name: &str) -> ZkfResult<()> {
    builder.constrain_equal(
        mul(signal(signal_name), signal("__nonlinear_anchor_one")),
        signal(signal_name),
    )?;
    Ok(())
}

fn poseidon_round(
    builder: &mut ProgramBuilder,
    prefix: &str,
    inputs: &[Expr],
    first_output: &str,
    first_output_predeclared: bool,
) -> ZkfResult<String> {
    let output_names = [
        first_output.to_string(),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ];
    for (index, output) in output_names.iter().enumerate() {
        if index == 0 && first_output_predeclared {
            continue;
        }
        builder.private_signal(output)?;
    }
    builder.poseidon_hash(
        inputs,
        &[
            output_names[0].as_str(),
            output_names[1].as_str(),
            output_names[2].as_str(),
            output_names[3].as_str(),
        ],
    )?;
    Ok(output_names[0].clone())
}

fn append_registry_membership(
    builder: &mut ProgramBuilder,
    leaf_signal: &str,
    root_signal: &str,
) -> ZkfResult<()> {
    let mut current = Expr::signal(leaf_signal);

    for level in 0..MERKLE_DEPTH {
        let sibling = format!("registry_sibling_{level}");
        let direction = format!("registry_direction_{level}");
        let left = format!("registry_left_{level}");
        let right = format!("registry_right_{level}");

        builder.private_input(&sibling)?;
        builder.private_input(&direction)?;
        builder.private_signal(&left)?;
        builder.private_signal(&right)?;
        constrain_boolean_explicit(builder, &direction)?;

        let left_expr = add(vec![
            current.clone(),
            mul(signal(&direction), sub(signal(&sibling), current.clone())),
        ]);
        let right_expr = add(vec![
            signal(&sibling),
            mul(signal(&direction), sub(current.clone(), signal(&sibling))),
        ]);
        builder.add_assignment(&left, left_expr.clone())?;
        builder.constrain_equal(signal(&left), left_expr)?;
        builder.add_assignment(&right, right_expr.clone())?;
        builder.constrain_equal(signal(&right), right_expr)?;

        let next = poseidon_round(
            builder,
            &format!("__registry_level_{level}"),
            &[
                signal(&left),
                signal(&right),
                signal("__registry_zero_0"),
                signal("__registry_zero_1"),
            ],
            &format!("__registry_level_{level}_state_0"),
            false,
        )?;
        current = signal(&next);
    }

    builder.constrain_equal(current, signal(root_signal))?;
    Ok(())
}

fn build_program(config: &CircuitConfig) -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new(config.name, FieldId::Bn254);
    builder.metadata_entry(
        "report_public_surface",
        "service_id,qualified,tier,identity_commitment,eligibility_score",
    )?;
    builder.metadata_entry("registry_mode", "constant-root-depth-3-merkle-membership")?;
    builder.metadata_entry("tier_encoding", "0=rejected,1=basic,2=premium")?;
    builder.metadata_entry("premium_floor", PREMIUM_MIN_BALANCE_EXCLUSIVE.to_string())?;
    builder.metadata_entry(
        "witness_pipeline_expectation",
        "poseidon-blackbox-values-derived-via-prepared-compiled-witness",
    )?;

    for name in [
        "service_id",
        "qualified",
        "tier",
        "identity_commitment",
        "eligibility_score",
    ] {
        builder.public_output(name)?;
    }

    for name in [
        "age",
        "balance",
        "credential_number",
        "expiry_year",
        "name_code",
        "identity_blinding",
        "rejected_flag",
        "basic_flag",
        "premium_flag",
        "reject_gap",
        "basic_gap",
        "basic_ceiling_gap",
        "premium_gap",
    ] {
        builder.private_input(name)?;
    }

    for name in [
        "age_min_surplus",
        "age_max_surplus",
        "expiry_surplus",
        "age_pass",
        "expiry_pass",
        "registry_pass",
        "balance_pass",
    ] {
        builder.private_signal(name)?;
    }

    for (name, bits) in [
        ("age", 8),
        ("balance", 20),
        ("credential_number", 32),
        ("expiry_year", 16),
        ("name_code", 20),
        ("identity_blinding", 32),
    ] {
        builder.constrain_range(name, bits)?;
    }

    builder.constant_signal(
        "__service_id_constant",
        FieldElement::from_u64(config.service_id),
    )?;
    builder.constant_signal("__registry_root_constant", config.registry_root.clone())?;
    builder.constant_signal("__registry_zero_0", FieldElement::ZERO)?;
    builder.constant_signal("__registry_zero_1", FieldElement::ZERO)?;
    builder.constant_signal("__nonlinear_anchor_one", FieldElement::ONE)?;

    assign_and_bind(
        &mut builder,
        "service_id",
        Expr::Const(FieldElement::from_u64(config.service_id)),
    )?;
    builder.constrain_range("service_id", 16)?;

    let commitment_state = poseidon_round(
        &mut builder,
        "__identity_commitment",
        &[
            signal("credential_number"),
            signal("name_code"),
            signal("identity_blinding"),
            signal("__registry_zero_0"),
        ],
        "identity_commitment",
        true,
    )?;
    builder.constrain_equal(signal("identity_commitment"), signal(&commitment_state))?;

    assign_and_bind(
        &mut builder,
        "age_min_surplus",
        sub(signal("age"), constant(18)),
    )?;
    anchor_with_one(&mut builder, "age_min_surplus")?;
    builder.constrain_range("age_min_surplus", 8)?;
    assign_and_bind(
        &mut builder,
        "age_max_surplus",
        sub(constant(120), signal("age")),
    )?;
    anchor_with_one(&mut builder, "age_max_surplus")?;
    builder.constrain_range("age_max_surplus", 8)?;
    assign_and_bind(
        &mut builder,
        "expiry_surplus",
        sub(signal("expiry_year"), constant(EXPIRY_FLOOR_YEAR as i64)),
    )?;
    anchor_with_one(&mut builder, "expiry_surplus")?;
    builder.constrain_range("expiry_surplus", 16)?;

    assign_and_bind(&mut builder, "age_pass", Expr::Const(FieldElement::ONE))?;
    constrain_boolean_explicit(&mut builder, "age_pass")?;
    assign_and_bind(&mut builder, "expiry_pass", Expr::Const(FieldElement::ONE))?;
    constrain_boolean_explicit(&mut builder, "expiry_pass")?;
    assign_and_bind(
        &mut builder,
        "registry_pass",
        Expr::Const(FieldElement::ONE),
    )?;
    constrain_boolean_explicit(&mut builder, "registry_pass")?;

    constrain_boolean_explicit(&mut builder, "rejected_flag")?;
    constrain_boolean_explicit(&mut builder, "basic_flag")?;
    constrain_boolean_explicit(&mut builder, "premium_flag")?;
    builder.constrain_equal(
        add(vec![
            signal("rejected_flag"),
            signal("basic_flag"),
            signal("premium_flag"),
        ]),
        Expr::Const(FieldElement::ONE),
    )?;

    conditional_gap(
        &mut builder,
        "rejected_flag",
        "reject_gap",
        sub(constant(REJECT_MAX_BALANCE as i64), signal("balance")),
        17,
    )?;
    conditional_gap(
        &mut builder,
        "basic_flag",
        "basic_gap",
        sub(signal("balance"), constant(BASIC_MIN_BALANCE as i64)),
        17,
    )?;
    conditional_gap(
        &mut builder,
        "basic_flag",
        "basic_ceiling_gap",
        sub(constant(BASIC_MAX_BALANCE as i64), signal("balance")),
        17,
    )?;
    conditional_gap(
        &mut builder,
        "premium_flag",
        "premium_gap",
        sub(
            signal("balance"),
            constant(PREMIUM_MIN_BALANCE_EXCLUSIVE as i64),
        ),
        17,
    )?;

    assign_and_bind(
        &mut builder,
        "balance_pass",
        add(vec![signal("basic_flag"), signal("premium_flag")]),
    )?;
    constrain_boolean_explicit(&mut builder, "balance_pass")?;

    assign_and_bind(
        &mut builder,
        "tier",
        add(vec![
            signal("basic_flag"),
            mul(
                Expr::Const(FieldElement::from_u64(2)),
                signal("premium_flag"),
            ),
        ]),
    )?;
    builder.constrain_range("tier", 2)?;

    assign_and_bind(
        &mut builder,
        "qualified",
        mul(
            mul(signal("age_pass"), signal("expiry_pass")),
            mul(signal("registry_pass"), signal("balance_pass")),
        ),
    )?;
    constrain_boolean_explicit(&mut builder, "qualified")?;
    builder.constrain_equal(
        signal("qualified"),
        sub(Expr::Const(FieldElement::ONE), signal("rejected_flag")),
    )?;
    assign_and_bind(
        &mut builder,
        "eligibility_score",
        mul(
            signal("qualified"),
            add(vec![
                Expr::Const(FieldElement::from_u64(500)),
                signal("age_min_surplus"),
                signal("expiry_surplus"),
                mul(
                    Expr::Const(FieldElement::from_u64(100)),
                    signal("basic_flag"),
                ),
                mul(
                    Expr::Const(FieldElement::from_u64(200)),
                    signal("premium_flag"),
                ),
            ]),
        ),
    )?;
    builder.constrain_range("eligibility_score", 12)?;

    append_registry_membership(
        &mut builder,
        "identity_commitment",
        "__registry_root_constant",
    )?;

    builder.build()
}

fn identity_commitment(
    credential_number: u64,
    name_code: u64,
    identity_blinding: u64,
) -> ZkfResult<FieldElement> {
    poseidon_hash4_bn254(&[
        FieldElement::from_u64(credential_number),
        FieldElement::from_u64(name_code),
        FieldElement::from_u64(identity_blinding),
        FieldElement::ZERO,
    ])
    .map_err(ZkfError::InvalidArtifact)
}

fn merkle_parent(left: &FieldElement, right: &FieldElement) -> ZkfResult<FieldElement> {
    poseidon_hash4_bn254(&[
        left.clone(),
        right.clone(),
        FieldElement::ZERO,
        FieldElement::ZERO,
    ])
    .map_err(ZkfError::InvalidArtifact)
}

fn registry_fixture(leaf: FieldElement, index: usize) -> ZkfResult<RegistryFixture> {
    let mut leaves = (0..MERKLE_LEAVES)
        .map(|slot| FieldElement::from_u64(1_000 + slot as u64))
        .collect::<Vec<_>>();
    leaves[index] = leaf;

    let mut path = Vec::with_capacity(MERKLE_DEPTH);
    let mut nodes = leaves.clone();
    let mut current_index = index;

    for _ in 0..MERKLE_DEPTH {
        let sibling_index = if current_index.is_multiple_of(2) {
            current_index + 1
        } else {
            current_index - 1
        };
        path.push(MerklePathNodeV1 {
            sibling: nodes[sibling_index].clone(),
            direction: (!current_index.is_multiple_of(2)) as u8,
        });
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| merkle_parent(&pair[0], &pair[1]))
            .collect::<ZkfResult<Vec<_>>>()?;
        current_index /= 2;
    }

    Ok(RegistryFixture {
        root: nodes
            .into_iter()
            .next()
            .ok_or_else(|| ZkfError::InvalidArtifact("registry root missing".to_string()))?,
        path,
        leaf_index: index,
    })
}

fn insert_u64(inputs: &mut WitnessInputs, name: &str, value: u64) {
    inputs.insert(name.to_string(), FieldElement::from_u64(value));
}

fn insert_bool(inputs: &mut WitnessInputs, name: &str, value: bool) {
    inputs.insert(
        name.to_string(),
        if value {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        },
    );
}

fn insert_path(inputs: &mut WitnessInputs, path: &[MerklePathNodeV1]) {
    for (level, node) in path.iter().enumerate() {
        inputs.insert(format!("registry_sibling_{level}"), node.sibling.clone());
        inputs.insert(
            format!("registry_direction_{level}"),
            FieldElement::from_u64(node.direction.into()),
        );
    }
}

fn base_inputs(path: &[MerklePathNodeV1]) -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    insert_u64(&mut inputs, "age", 35);
    insert_u64(&mut inputs, "balance", 75_000);
    insert_u64(&mut inputs, "credential_number", 918_273_645);
    insert_u64(&mut inputs, "expiry_year", 2030);
    insert_u64(&mut inputs, "name_code", 424_242);
    insert_u64(&mut inputs, "identity_blinding", 777_777);
    insert_bool(&mut inputs, "rejected_flag", false);
    insert_bool(&mut inputs, "basic_flag", false);
    insert_bool(&mut inputs, "premium_flag", true);
    insert_u64(&mut inputs, "reject_gap", 0);
    insert_u64(&mut inputs, "basic_gap", 0);
    insert_u64(&mut inputs, "basic_ceiling_gap", 0);
    insert_u64(
        &mut inputs,
        "premium_gap",
        75_000 - PREMIUM_MIN_BALANCE_EXCLUSIVE,
    );
    insert_path(&mut inputs, path);
    inputs
}

fn low_balance_inputs(path: &[MerklePathNodeV1]) -> WitnessInputs {
    let mut inputs = base_inputs(path);
    insert_u64(&mut inputs, "balance", 500);
    insert_bool(&mut inputs, "rejected_flag", true);
    insert_bool(&mut inputs, "basic_flag", false);
    insert_bool(&mut inputs, "premium_flag", false);
    insert_u64(&mut inputs, "reject_gap", REJECT_MAX_BALANCE - 500);
    insert_u64(&mut inputs, "basic_gap", 0);
    insert_u64(&mut inputs, "basic_ceiling_gap", 0);
    insert_u64(&mut inputs, "premium_gap", 0);
    inputs
}

fn underage_inputs(path: &[MerklePathNodeV1]) -> WitnessInputs {
    let mut inputs = base_inputs(path);
    insert_u64(&mut inputs, "age", 16);
    inputs
}

fn expired_inputs(path: &[MerklePathNodeV1]) -> WitnessInputs {
    let mut inputs = base_inputs(path);
    insert_u64(&mut inputs, "expiry_year", 2020);
    inputs
}

fn expected_outputs(
    program: &Program,
    manifest_path: &Path,
    commitment: &FieldElement,
    registry: &RegistryFixture,
) -> ExampleSummary {
    ExampleSummary {
        valid_public_outputs: BTreeMap::from([
            ("service_id".to_string(), SERVICE_ID.to_string()),
            ("qualified".to_string(), "1".to_string()),
            ("tier".to_string(), "2".to_string()),
            ("identity_commitment".to_string(), commitment.to_decimal_string()),
            (
                "eligibility_score".to_string(),
                (500 + (35 - 18) + (2030 - EXPIRY_FLOOR_YEAR) + 200).to_string(),
            ),
        ]),
        low_balance_public_outputs: BTreeMap::from([
            ("service_id".to_string(), SERVICE_ID.to_string()),
            ("qualified".to_string(), "0".to_string()),
            ("tier".to_string(), "0".to_string()),
            ("identity_commitment".to_string(), commitment.to_decimal_string()),
            ("eligibility_score".to_string(), "0".to_string()),
        ]),
        hand_checked_private_values: BTreeMap::from([
            ("age_min_surplus".to_string(), (35 - 18).to_string()),
            ("age_max_surplus".to_string(), (120 - 35).to_string()),
            (
                "expiry_surplus".to_string(),
                (2030 - EXPIRY_FLOOR_YEAR).to_string(),
            ),
            ("premium_gap".to_string(), (75_000 - PREMIUM_MIN_BALANCE_EXCLUSIVE).to_string()),
            ("identity_blinding".to_string(), "777777".to_string()),
        ]),
        registry: BTreeMap::from([
            ("root".to_string(), registry.root.to_decimal_string()),
            ("leaf_index".to_string(), registry.leaf_index.to_string()),
            ("depth".to_string(), MERKLE_DEPTH.to_string()),
        ]),
        counts: BTreeMap::from([
            ("signals".to_string(), program.signals.len()),
            ("constraints".to_string(), program.constraints.len()),
            (
                "witness_assignments".to_string(),
                program.witness_plan.assignments.len(),
            ),
        ]),
        package_manifest: manifest_path.display().to_string(),
        premium_floor_note: format!(
            "Premium is encoded as balance >= {PREMIUM_MIN_BALANCE_EXCLUSIVE} to satisfy the 'above 50000' requirement exactly."
        ),
        witness_pipeline_note: "Inputs intentionally omit Poseidon output states so the CLI must derive them through the prepared compiled-witness path.".to_string(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| ZkfError::InvalidArtifact(format!("serialize {}: {err}", path.display())))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| ZkfError::Io(format!("create {}: {err}", parent.display())))?;
    }
    fs::write(path, bytes)
        .map_err(|err| ZkfError::Io(format!("write {}: {err}", path.display())))?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_json_and_hash(path: &Path, value: &impl Serialize) -> ZkfResult<String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| ZkfError::InvalidArtifact(format!("serialize {}: {err}", path.display())))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| ZkfError::Io(format!("create {}: {err}", parent.display())))?;
    }
    fs::write(path, &bytes)
        .map_err(|err| ZkfError::Io(format!("write {}: {err}", path.display())))?;
    Ok(sha256_hex(&bytes))
}

fn write_package_manifest(package_root: &Path, program: &Program) -> ZkfResult<PathBuf> {
    let program_rel = PathBuf::from("ir/program.json");
    let original_rel = PathBuf::from("frontends/native/original.json");
    let program_path = package_root.join(&program_rel);
    let original_path = package_root.join(&original_rel);

    let program_sha = write_json_and_hash(&program_path, program)?;
    let original_sha = write_json_and_hash(
        &original_path,
        &serde_json::json!({
            "kind": "native-zkf",
            "note": "generated by zkf-lib example private_identity_service_tier"
        }),
    )?;

    let mut manifest = PackageManifest::from_program(
        program,
        FrontendProvenance::new("native-zkf"),
        program_rel.display().to_string(),
        original_rel.display().to_string(),
    );
    manifest.backend_targets = vec![
        BackendKind::ArkworksGroth16,
        BackendKind::Halo2,
        BackendKind::Plonky3,
    ];
    manifest.files.program.sha256 = program_sha;
    manifest.files.original_artifact.sha256 = original_sha;

    let manifest_path = package_root.join("manifest.json");
    write_json(&manifest_path, &manifest)?;
    Ok(manifest_path)
}

fn output_dir() -> PathBuf {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/zkf-post-fix-private-identity-service-tier"))
}

fn main() -> ZkfResult<()> {
    let out_dir = output_dir();
    fs::create_dir_all(&out_dir)
        .map_err(|err| ZkfError::Io(format!("create {}: {err}", out_dir.display())))?;

    let commitment = identity_commitment(918_273_645, 424_242, 777_777)?;
    let registry = registry_fixture(commitment.clone(), 5)?;

    let config = CircuitConfig {
        name: "private_identity_service_tier",
        service_id: SERVICE_ID,
        registry_root: registry.root.clone(),
    };
    let alt_config = CircuitConfig {
        name: "private_identity_service_tier_alt",
        service_id: ALT_SERVICE_ID,
        registry_root: registry.root.clone(),
    };

    let program = build_program(&config)?;
    let alt_program = build_program(&alt_config)?;
    let valid = base_inputs(&registry.path);
    let underage = underage_inputs(&registry.path);
    let low_balance = low_balance_inputs(&registry.path);
    let expired = expired_inputs(&registry.path);

    let package_manifest = write_package_manifest(&out_dir.join("package"), &program)?;
    let summary = expected_outputs(&program, &package_manifest, &commitment, &registry);

    let program_path = out_dir.join("private_identity_service_tier.program.json");
    let alt_program_path = out_dir.join("private_identity_service_tier_alt.program.json");
    let valid_path = out_dir.join("private_identity_service_tier.valid.inputs.json");
    let underage_path = out_dir.join("private_identity_service_tier.underage.inputs.json");
    let low_balance_path = out_dir.join("private_identity_service_tier.low_balance.inputs.json");
    let expired_path = out_dir.join("private_identity_service_tier.expired.inputs.json");
    let summary_path = out_dir.join("private_identity_service_tier.expected.json");

    write_json(&program_path, &program)?;
    write_json(&alt_program_path, &alt_program)?;
    write_json(&valid_path, &valid)?;
    write_json(&underage_path, &underage)?;
    write_json(&low_balance_path, &low_balance)?;
    write_json(&expired_path, &expired)?;
    write_json(&summary_path, &summary)?;

    println!("{}", program_path.display());
    println!("{}", alt_program_path.display());
    println!("{}", valid_path.display());
    println!("{}", underage_path.display());
    println!("{}", low_balance_path.display());
    println!("{}", expired_path.display());
    println!("{}", package_manifest.display());
    println!("{}", summary_path.display());
    Ok(())
}
