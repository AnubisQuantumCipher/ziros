#![no_main]
#![no_std]

risc0_zkvm::guest::entry!(main);

use serde::{Deserialize, Serialize};

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

fn main() {
    let input = risc0_zkvm::guest::env::read::<WorkloadInput>();
    let output = WorkloadOutput {
        kind: input.kind,
        result: compute_result(&input),
    };
    risc0_zkvm::guest::env::commit(&output);
}
