use clap::{Parser, ValueEnum};
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{create_test_fri_params, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};
use rand::rngs::SmallRng;
use rand::SeedableRng;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

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

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
type MyProof = Proof<MyConfig>;

fn new_config() -> MyConfig {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 2);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

fn scenario_id(scenario: Scenario) -> &'static str {
    match scenario {
        Scenario::SingleCircuitProve => "single_circuit_prove",
        Scenario::DeveloperWorkload => "developer_workload",
        Scenario::RecursiveWorkflow => "recursive_workflow",
    }
}

const SIMPLE_WIDTH: usize = 3;
const FIB_TRACE_ROWS: usize = 16;
const FIB_OUTPUT_ROW: usize = 8;
const FIB_SELECTOR_OFFSET: usize = 2;
const FIB_WIDTH: usize = FIB_SELECTOR_OFFSET + FIB_TRACE_ROWS;

struct SingleCircuitAir;

impl<F> BaseAir<F> for SingleCircuitAir {
    fn width(&self) -> usize {
        SIMPLE_WIDTH
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for SingleCircuitAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let left = pis[0].clone();
        let right = pis[1].clone();
        let expected = pis[2].clone();
        let local = main.row_slice(0).expect("trace must have at least one row");
        let next = main
            .row_slice(1)
            .expect("trace must have at least two rows");

        builder.when_first_row().assert_eq(local[0].clone(), left);
        builder.when_first_row().assert_eq(local[1].clone(), right);
        builder
            .when_transition()
            .assert_eq(local[0].clone(), next[0].clone());
        builder
            .when_transition()
            .assert_eq(local[1].clone(), next[1].clone());
        builder
            .when_transition()
            .assert_eq(local[2].clone(), next[2].clone());
        builder.assert_zero(local[0].clone() * local[1].clone() - local[2].clone());
        builder
            .when_last_row()
            .assert_eq(local[2].clone(), expected);
    }
}

struct DeveloperWorkloadAir;

impl<F> BaseAir<F> for DeveloperWorkloadAir {
    fn width(&self) -> usize {
        SIMPLE_WIDTH
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for DeveloperWorkloadAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let expected = builder.public_values()[0].clone();
        let local = main.row_slice(0).expect("trace must have at least one row");
        let next = main
            .row_slice(1)
            .expect("trace must have at least two rows");

        builder
            .when_first_row()
            .assert_eq(local[2].clone(), local[0].clone() * local[1].clone());
        builder.when_transition().assert_eq(
            next[2].clone(),
            local[2].clone() + next[0].clone() * next[1].clone(),
        );
        builder
            .when_last_row()
            .assert_eq(local[2].clone(), expected);
    }
}

struct FibonacciAir;

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        FIB_WIDTH
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let left_seed = pis[0].clone();
        let right_seed = pis[1].clone();
        let expected = pis[2].clone();
        let local = main.row_slice(0).expect("trace must have at least one row");
        let next = main
            .row_slice(1)
            .expect("trace must have at least two rows");

        builder
            .when_first_row()
            .assert_eq(local[0].clone(), left_seed);
        builder
            .when_first_row()
            .assert_eq(local[1].clone(), right_seed);
        builder
            .when_transition()
            .assert_eq(local[1].clone(), next[0].clone());
        builder
            .when_transition()
            .assert_eq(local[0].clone() + local[1].clone(), next[1].clone());

        builder
            .when_first_row()
            .assert_eq(local[FIB_SELECTOR_OFFSET].clone(), AB::Expr::ONE);
        for selector_idx in 1..FIB_TRACE_ROWS {
            builder
                .when_first_row()
                .assert_zero(local[FIB_SELECTOR_OFFSET + selector_idx].clone());
        }
        builder
            .when_transition()
            .assert_zero(next[FIB_SELECTOR_OFFSET].clone());
        for selector_idx in 0..(FIB_TRACE_ROWS - 1) {
            builder.when_transition().assert_eq(
                next[FIB_SELECTOR_OFFSET + selector_idx + 1].clone(),
                local[FIB_SELECTOR_OFFSET + selector_idx].clone(),
            );
        }
        builder
            .when(local[FIB_SELECTOR_OFFSET + FIB_OUTPUT_ROW].clone())
            .assert_eq(local[1].clone(), expected);
    }
}

fn single_trace() -> RowMajorMatrix<Val> {
    let mut values = Val::zero_vec(8 * SIMPLE_WIDTH);
    for row in 0..8 {
        let offset = row * SIMPLE_WIDTH;
        values[offset] = Val::from_u32(3);
        values[offset + 1] = Val::from_u32(7);
        values[offset + 2] = Val::from_u32(21);
    }
    RowMajorMatrix::new(values, SIMPLE_WIDTH)
}

fn developer_trace() -> RowMajorMatrix<Val> {
    let pairs = [
        (1u32, 4u32),
        (2, 3),
        (3, 2),
        (4, 1),
        (0, 0),
        (0, 0),
        (0, 0),
        (0, 0),
    ];
    let mut cumulative = 0u32;
    let mut values = Val::zero_vec(8 * SIMPLE_WIDTH);
    for (row, (left, right)) in pairs.iter().enumerate() {
        cumulative = cumulative.saturating_add(left.saturating_mul(*right));
        let offset = row * SIMPLE_WIDTH;
        values[offset] = Val::from_u32(*left);
        values[offset + 1] = Val::from_u32(*right);
        values[offset + 2] = Val::from_u32(cumulative);
    }
    RowMajorMatrix::new(values, SIMPLE_WIDTH)
}

fn fibonacci_trace() -> RowMajorMatrix<Val> {
    let mut values = Val::zero_vec(FIB_TRACE_ROWS * FIB_WIDTH);
    let mut left = Val::ONE;
    let mut right = Val::ONE;
    for row in 0..FIB_TRACE_ROWS {
        let offset = row * FIB_WIDTH;
        values[offset] = left;
        values[offset + 1] = right;
        values[offset + FIB_SELECTOR_OFFSET + row] = Val::ONE;
        let next = left + right;
        left = right;
        right = next;
    }
    RowMajorMatrix::new(values, FIB_WIDTH)
}

fn prove_single(out_dir: &PathBuf) -> Result<(), String> {
    let config = new_config();
    let public_values = vec![Val::from_u32(3), Val::from_u32(7), Val::from_u32(21)];
    let proof = prove(&config, &SingleCircuitAir, single_trace(), &public_values);
    verify(&config, &SingleCircuitAir, &proof, &public_values)
        .map_err(|e| format!("verify failed: {e:?}"))?;
    write_artifacts(out_dir, "single_circuit_prove", &proof, 21)
}

fn prove_developer(out_dir: &PathBuf) -> Result<(), String> {
    let config = new_config();
    let public_values = vec![Val::from_u32(20)];
    let proof = prove(
        &config,
        &DeveloperWorkloadAir,
        developer_trace(),
        &public_values,
    );
    verify(&config, &DeveloperWorkloadAir, &proof, &public_values)
        .map_err(|e| format!("verify failed: {e:?}"))?;
    write_artifacts(out_dir, "developer_workload", &proof, 20)
}

fn prove_recursive(out_dir: &PathBuf) -> Result<(), String> {
    let config = new_config();
    let public_values = vec![Val::ONE, Val::ONE, Val::from_u32(55)];
    let proof = prove(&config, &FibonacciAir, fibonacci_trace(), &public_values);
    verify(&config, &FibonacciAir, &proof, &public_values)
        .map_err(|e| format!("verify failed: {e:?}"))?;
    write_artifacts(out_dir, "recursive_workflow", &proof, 55)
}

fn write_artifacts(
    out_dir: &PathBuf,
    scenario: &str,
    proof: &MyProof,
    expected: u32,
) -> Result<(), String> {
    fs::create_dir_all(out_dir).map_err(|e| format!("create out dir: {e}"))?;
    fs::write(
        out_dir.join("proof.bin"),
        postcard::to_allocvec(proof).map_err(|e| format!("serialize proof: {e}"))?,
    )
    .map_err(|e| format!("write proof: {e}"))?;
    fs::write(
        out_dir.join("summary.json"),
        serde_json::to_vec_pretty(&json!({
            "scenario": scenario,
            "expected": expected,
            "verified": true
        }))
        .map_err(|e| format!("encode summary: {e}"))?,
    )
    .map_err(|e| format!("write summary: {e}"))?;
    Ok(())
}

fn verify_single(out_dir: &PathBuf) -> Result<(), String> {
    let config = new_config();
    let public_values = vec![Val::from_u32(3), Val::from_u32(7), Val::from_u32(21)];
    let proof: MyProof = postcard::from_bytes(
        &fs::read(out_dir.join("proof.bin")).map_err(|e| format!("read proof: {e}"))?,
    )
    .map_err(|e| format!("deserialize proof: {e}"))?;
    verify(&config, &SingleCircuitAir, &proof, &public_values)
        .map_err(|e| format!("verify failed: {e:?}"))
}

fn verify_developer(out_dir: &PathBuf) -> Result<(), String> {
    let config = new_config();
    let public_values = vec![Val::from_u32(20)];
    let proof: MyProof = postcard::from_bytes(
        &fs::read(out_dir.join("proof.bin")).map_err(|e| format!("read proof: {e}"))?,
    )
    .map_err(|e| format!("deserialize proof: {e}"))?;
    verify(&config, &DeveloperWorkloadAir, &proof, &public_values)
        .map_err(|e| format!("verify failed: {e:?}"))
}

fn verify_recursive(out_dir: &PathBuf) -> Result<(), String> {
    let config = new_config();
    let public_values = vec![Val::ONE, Val::ONE, Val::from_u32(55)];
    let proof: MyProof = postcard::from_bytes(
        &fs::read(out_dir.join("proof.bin")).map_err(|e| format!("read proof: {e}"))?,
    )
    .map_err(|e| format!("deserialize proof: {e}"))?;
    verify(&config, &FibonacciAir, &proof, &public_values)
        .map_err(|e| format!("verify failed: {e:?}"))
}

fn ensure_summary(out_dir: &PathBuf, scenario: &str) -> Result<(), String> {
    let payload: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("summary.json")).map_err(|e| format!("read summary: {e}"))?,
    )
    .map_err(|e| format!("parse summary: {e}"))?;
    if payload.get("scenario").and_then(serde_json::Value::as_str) != Some(scenario) {
        return Err("summary scenario mismatch".to_string());
    }
    if payload.get("verified").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("summary recorded verified=false".to_string());
    }
    Ok(())
}

fn prove_scenario(scenario: Scenario, out_dir: &PathBuf) -> Result<(), String> {
    match scenario {
        Scenario::SingleCircuitProve => prove_single(out_dir),
        Scenario::DeveloperWorkload => prove_developer(out_dir),
        Scenario::RecursiveWorkflow => prove_recursive(out_dir),
    }
}

fn verify_scenario(scenario: Scenario, out_dir: &PathBuf) -> Result<(), String> {
    ensure_summary(out_dir, scenario_id(scenario))?;
    match scenario {
        Scenario::SingleCircuitProve => verify_single(out_dir),
        Scenario::DeveloperWorkload => verify_developer(out_dir),
        Scenario::RecursiveWorkflow => verify_recursive(out_dir),
    }
}

fn main() {
    let args = Args::parse();
    let result = match args.mode {
        Mode::Prove => prove_scenario(args.scenario, &args.out_dir),
        Mode::Verify => verify_scenario(args.scenario, &args.out_dir),
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
