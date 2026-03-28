#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_workload_lib::{WorkloadInput, compute_result};

pub fn main() {
    let input = sp1_zkvm::io::read::<WorkloadInput>();
    let result = compute_result(&input);
    sp1_zkvm::io::commit_slice(&result.to_le_bytes());
}
