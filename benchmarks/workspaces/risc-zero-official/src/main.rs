use clap::{Parser, ValueEnum};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Scenario {
    SingleCircuitProve,
    DeveloperWorkload,
    RecursiveWorkflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Mode {
    Prove,
    Verify,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    scenario: Scenario,
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long)]
    out_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WorkloadInput {
    kind: u32,
    values: [u32; 8],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WorkloadOutput {
    kind: u32,
    result: u32,
}

fn scenario_id(scenario: Scenario) -> &'static str {
    match scenario {
        Scenario::SingleCircuitProve => "single_circuit_prove",
        Scenario::DeveloperWorkload => "developer_workload",
        Scenario::RecursiveWorkflow => "recursive_workflow",
    }
}

fn scenario_input(scenario: Scenario) -> WorkloadInput {
    match scenario {
        Scenario::SingleCircuitProve => WorkloadInput {
            kind: 0,
            values: [3, 7, 0, 0, 0, 0, 0, 0],
        },
        Scenario::DeveloperWorkload => WorkloadInput {
            kind: 1,
            values: [1, 2, 3, 4, 4, 3, 2, 1],
        },
        Scenario::RecursiveWorkflow => WorkloadInput {
            kind: 2,
            values: [1, 1, 0, 0, 0, 0, 0, 0],
        },
    }
}

fn compute_result(input: &WorkloadInput) -> u32 {
    match input.kind {
        0 => input.values[0].saturating_mul(input.values[1]),
        1 => input.values[..4]
            .iter()
            .zip(input.values[4..].iter())
            .map(|(left, right)| left.saturating_mul(*right))
            .sum(),
        2 => {
            let mut a = input.values[0];
            let mut b = input.values[1];
            for _ in 0..8 {
                let next = a.saturating_add(b);
                a = b;
                b = next;
            }
            b
        }
        _ => 0,
    }
}

fn prove(scenario: Scenario, out_dir: &PathBuf) -> Result<(), String> {
    let input = scenario_input(scenario);
    let expected = compute_result(&input);
    let env = ExecutorEnv::builder()
        .write(&input)
        .map_err(|e| format!("write input failed: {e}"))?
        .build()
        .map_err(|e| format!("build executor env failed: {e}"))?;
    let receipt = default_prover()
        .prove(env, GUEST_ELF)
        .map_err(|e| format!("prove failed: {e}"))?
        .receipt;
    receipt
        .verify(GUEST_ID)
        .map_err(|e| format!("verify failed: {e}"))?;
    let output: WorkloadOutput = receipt
        .journal
        .decode()
        .map_err(|e| format!("decode journal failed: {e}"))?;
    if output.kind != input.kind || output.result != expected {
        return Err("journal output mismatch".to_string());
    }

    fs::create_dir_all(out_dir).map_err(|e| format!("create out dir: {e}"))?;
    fs::write(
        out_dir.join("proof.bin"),
        bincode::serialize(&receipt).map_err(|e| format!("serialize receipt: {e}"))?,
    )
    .map_err(|e| format!("write proof: {e}"))?;
    fs::write(
        out_dir.join("summary.json"),
        serde_json::to_vec_pretty(&json!({
            "scenario": scenario_id(scenario),
            "expected": expected,
            "result": output.result,
            "verified": true,
        }))
        .map_err(|e| format!("encode summary: {e}"))?,
    )
    .map_err(|e| format!("write summary: {e}"))?;
    Ok(())
}

fn verify(scenario: Scenario, out_dir: &PathBuf) -> Result<(), String> {
    let payload: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("summary.json")).map_err(|e| format!("read summary: {e}"))?,
    )
    .map_err(|e| format!("parse summary: {e}"))?;
    if payload.get("scenario").and_then(serde_json::Value::as_str) != Some(scenario_id(scenario)) {
        return Err("summary scenario mismatch".to_string());
    }
    if payload.get("verified").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("summary recorded verified=false".to_string());
    }
    let receipt: Receipt = bincode::deserialize(
        &fs::read(out_dir.join("proof.bin")).map_err(|e| format!("read proof: {e}"))?,
    )
    .map_err(|e| format!("deserialize proof: {e}"))?;
    receipt
        .verify(GUEST_ID)
        .map_err(|e| format!("verify failed: {e}"))?;
    let output: WorkloadOutput = receipt
        .journal
        .decode()
        .map_err(|e| format!("decode journal failed: {e}"))?;
    let expected = compute_result(&scenario_input(scenario));
    if output.result != expected {
        return Err("verified journal output mismatch".to_string());
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    let result = match args.mode {
        Mode::Prove => prove(args.scenario, &args.out_dir),
        Mode::Verify => verify(args.scenario, &args.out_dir),
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
