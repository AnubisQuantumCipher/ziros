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
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zkf_lib::{Expr, FieldElement, FieldId, Program, ProgramBuilder, WitnessInputs, ZkfResult};

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

fn anchor_with_constant_one(
    builder: &mut ProgramBuilder,
    target: &str,
    anchor_signal: &str,
) -> ZkfResult<()> {
    builder.constrain_equal(mul(signal(target), signal(anchor_signal)), signal(target))?;
    Ok(())
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

fn build_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("financial_loan_qualification", FieldId::Bn254);

    for name in [
        "requested_loan",
        "credit_score",
        "monthly_income",
        "monthly_debt",
        "collateral_value",
        "account_age_months",
        "missed_payments",
    ] {
        builder.private_input(name)?;
    }
    for name in ["kyc_passed", "no_recent_default", "no_recent_liquidation"] {
        builder.private_input(name)?;
    }
    for name in ["loan_amount", "qualified", "composite_risk_score"] {
        builder.public_output(name)?;
    }
    for name in [
        "credit_surplus",
        "income_floor_surplus",
        "debt_capacity_gap",
        "collateral_surplus",
        "account_age_surplus",
        "payment_slack",
        "loan_ceiling_slack",
        "liquidity_buffer",
        "history_ok",
        "compliance_ok",
        "weighted_credit",
        "weighted_income",
        "weighted_collateral",
        "risk_threshold_surplus",
    ] {
        builder.private_signal(name)?;
    }
    builder.constant_signal("__financial_anchor_one", FieldElement::ONE)?;

    builder.constrain_range("requested_loan", 12)?;
    builder.constrain_range("credit_score", 10)?;
    builder.constrain_range("monthly_income", 12)?;
    builder.constrain_range("monthly_debt", 12)?;
    builder.constrain_range("collateral_value", 13)?;
    builder.constrain_range("account_age_months", 8)?;
    builder.constrain_range("missed_payments", 3)?;
    builder.constrain_boolean("kyc_passed")?;
    builder.constrain_boolean("no_recent_default")?;
    builder.constrain_boolean("no_recent_liquidation")?;

    assign_and_bind(&mut builder, "loan_amount", signal("requested_loan"))?;
    assign_and_bind(
        &mut builder,
        "credit_surplus",
        sub(signal("credit_score"), constant(650)),
    )?;
    assign_and_bind(
        &mut builder,
        "income_floor_surplus",
        sub(signal("monthly_income"), constant(400)),
    )?;
    assign_and_bind(
        &mut builder,
        "debt_capacity_gap",
        sub(
            signal("monthly_income"),
            mul(constant(2), signal("monthly_debt")),
        ),
    )?;
    assign_and_bind(
        &mut builder,
        "collateral_surplus",
        sub(
            mul(constant(2), signal("collateral_value")),
            mul(constant(3), signal("requested_loan")),
        ),
    )?;
    assign_and_bind(
        &mut builder,
        "account_age_surplus",
        sub(signal("account_age_months"), constant(12)),
    )?;
    assign_and_bind(
        &mut builder,
        "payment_slack",
        sub(constant(3), signal("missed_payments")),
    )?;
    assign_and_bind(
        &mut builder,
        "loan_ceiling_slack",
        sub(constant(1200), signal("requested_loan")),
    )?;
    assign_and_bind(
        &mut builder,
        "liquidity_buffer",
        sub(signal("monthly_income"), signal("monthly_debt")),
    )?;
    assign_and_bind(
        &mut builder,
        "history_ok",
        mul(signal("kyc_passed"), signal("no_recent_default")),
    )?;
    assign_and_bind(
        &mut builder,
        "compliance_ok",
        mul(signal("history_ok"), signal("no_recent_liquidation")),
    )?;
    assign_and_bind(&mut builder, "qualified", signal("compliance_ok"))?;
    assign_and_bind(
        &mut builder,
        "weighted_credit",
        mul(constant(2), signal("credit_surplus")),
    )?;
    assign_and_bind(
        &mut builder,
        "weighted_income",
        add(vec![
            signal("income_floor_surplus"),
            signal("debt_capacity_gap"),
        ]),
    )?;
    assign_and_bind(
        &mut builder,
        "weighted_collateral",
        add(vec![
            signal("collateral_surplus"),
            signal("liquidity_buffer"),
        ]),
    )?;
    assign_and_bind(
        &mut builder,
        "composite_risk_score",
        add(vec![
            signal("weighted_credit"),
            signal("weighted_income"),
            signal("weighted_collateral"),
            signal("account_age_surplus"),
            signal("payment_slack"),
            signal("loan_ceiling_slack"),
            signal("history_ok"),
            signal("compliance_ok"),
        ]),
    )?;
    assign_and_bind(
        &mut builder,
        "risk_threshold_surplus",
        sub(signal("composite_risk_score"), constant(1800)),
    )?;

    for name in [
        "credit_surplus",
        "income_floor_surplus",
        "debt_capacity_gap",
        "collateral_surplus",
        "account_age_surplus",
        "payment_slack",
        "loan_ceiling_slack",
        "liquidity_buffer",
        "history_ok",
        "compliance_ok",
        "weighted_credit",
        "weighted_income",
        "weighted_collateral",
        "risk_threshold_surplus",
    ] {
        anchor_with_constant_one(&mut builder, name, "__financial_anchor_one")?;
    }

    for (name, bits) in [
        ("loan_amount", 12),
        ("credit_surplus", 10),
        ("income_floor_surplus", 12),
        ("debt_capacity_gap", 12),
        ("collateral_surplus", 15),
        ("account_age_surplus", 8),
        ("payment_slack", 2),
        ("loan_ceiling_slack", 11),
        ("liquidity_buffer", 12),
        ("weighted_credit", 11),
        ("weighted_income", 13),
        ("weighted_collateral", 15),
        ("composite_risk_score", 16),
        ("risk_threshold_surplus", 12),
    ] {
        builder.constrain_range(name, bits)?;
    }
    for name in ["history_ok", "compliance_ok", "qualified"] {
        builder.constrain_boolean(name)?;
    }
    builder.constrain_equal(signal("qualified"), constant(1))?;

    builder.build()
}

fn valid_inputs() -> WitnessInputs {
    let mut inputs = WitnessInputs::new();
    insert_u64(&mut inputs, "requested_loan", 800);
    insert_u64(&mut inputs, "credit_score", 720);
    insert_u64(&mut inputs, "monthly_income", 900);
    insert_u64(&mut inputs, "monthly_debt", 300);
    insert_u64(&mut inputs, "collateral_value", 1500);
    insert_u64(&mut inputs, "account_age_months", 36);
    insert_u64(&mut inputs, "missed_payments", 1);
    insert_bool(&mut inputs, "kyc_passed", true);
    insert_bool(&mut inputs, "no_recent_default", true);
    insert_bool(&mut inputs, "no_recent_liquidation", true);
    inputs
}

fn rejected_low_credit_inputs() -> WitnessInputs {
    let mut inputs = valid_inputs();
    insert_u64(&mut inputs, "credit_score", 600);
    inputs
}

#[derive(Serialize)]
struct ExpectedOutputs {
    public_outputs: BTreeMap<String, String>,
    private_derived_signals: BTreeMap<String, String>,
    counts: BTreeMap<String, usize>,
}

fn expected_outputs(program: &Program) -> ExpectedOutputs {
    let public_outputs = BTreeMap::from([
        ("loan_amount".to_string(), "800".to_string()),
        ("qualified".to_string(), "1".to_string()),
        ("composite_risk_score".to_string(), "2568".to_string()),
    ]);
    let private_derived_signals = BTreeMap::from([
        ("credit_surplus".to_string(), "70".to_string()),
        ("income_floor_surplus".to_string(), "500".to_string()),
        ("debt_capacity_gap".to_string(), "300".to_string()),
        ("collateral_surplus".to_string(), "600".to_string()),
        ("account_age_surplus".to_string(), "24".to_string()),
        ("payment_slack".to_string(), "2".to_string()),
        ("loan_ceiling_slack".to_string(), "400".to_string()),
        ("liquidity_buffer".to_string(), "600".to_string()),
        ("history_ok".to_string(), "1".to_string()),
        ("compliance_ok".to_string(), "1".to_string()),
        ("weighted_credit".to_string(), "140".to_string()),
        ("weighted_income".to_string(), "800".to_string()),
        ("weighted_collateral".to_string(), "1200".to_string()),
        ("risk_threshold_surplus".to_string(), "768".to_string()),
    ]);
    let counts = BTreeMap::from([
        ("signals".to_string(), program.signals.len()),
        ("constraints".to_string(), program.constraints.len()),
        (
            "witness_assignments".to_string(),
            program.witness_plan.assignments.len(),
        ),
    ]);
    ExpectedOutputs {
        public_outputs,
        private_derived_signals,
        counts,
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        zkf_lib::ZkfError::InvalidArtifact(format!("serialize {}: {error}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|error| zkf_lib::ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

fn output_dir() -> PathBuf {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/zkf-financial-loan"))
}

fn main() -> ZkfResult<()> {
    let out_dir = output_dir();
    fs::create_dir_all(&out_dir)
        .map_err(|error| zkf_lib::ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;

    let program = build_program()?;
    let valid = valid_inputs();
    let rejected = rejected_low_credit_inputs();
    let expected = expected_outputs(&program);

    let program_path = out_dir.join("financial_loan_qualification.program.json");
    let valid_path = out_dir.join("financial_loan_qualification.valid.inputs.json");
    let rejected_path =
        out_dir.join("financial_loan_qualification.rejected_low_credit.inputs.json");
    let expected_path = out_dir.join("financial_loan_qualification.expected.json");

    write_json(&program_path, &program)?;
    write_json(&valid_path, &valid)?;
    write_json(&rejected_path, &rejected)?;
    write_json(&expected_path, &expected)?;

    println!("{}", program_path.display());
    println!("{}", valid_path.display());
    println!("{}", rejected_path.display());
    println!("{}", expected_path.display());
    Ok(())
}
