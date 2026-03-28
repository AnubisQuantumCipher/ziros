use zkf_dsl::circuit;

/// ZK Private Credit Underwriter
/// Proves a user's total creditworthiness across 3 accounts without revealing balances.
/// 
/// Constraints:
/// 1. Each balance is bound to a public commitment: commitment_i = (balance_i * 17) + salt_i
/// 2. Total balance >= public threshold
/// 3. Each balance is a valid 32-bit integer (prevents underflow/overflow)
#[circuit(field = "bn254")]
fn weighted_threshold_verifier(
    b1: Private<u32>,
    s1: Private<u32>,
    c1: Public<u32>,
    b2: Private<u32>,
    s2: Private<u32>,
    c2: Public<u32>,
    b3: Private<u32>,
    s3: Private<u32>,
    c3: Public<u32>,
    threshold: Public<u32>,
) -> Public<u32> {
    // 1. Verify commitments (Provenance Check)
    // In production, this would be a signature check or Poseidon hash.
    assert_eq((b1 * 17) + s1, c1);
    assert_eq((b2 * 17) + s2, c2);
    assert_eq((b3 * 17) + s3, c3);

    // 2. Range Checks (Soundness)
    assert_range(b1, 32);
    assert_range(b2, 32);
    assert_range(b3, 32);

    // 3. Threshold Check (Logic)
    let total = b1 + b2 + b3;
    let diff = total - threshold;
    assert_range(diff, 32); // Enforces total >= threshold

    total
}

fn main() {
    // Generate ZIR
    let zir_program = weighted_threshold_verifier_program();
    
    // Convert to IR v2 (Universal Format)
    let program_v2 = zkf_core::program_zir_to_v2(&zir_program).unwrap();
    
    // Inputs:
    // Account 1: $5,000 (salt 123) -> c1 = 5000 * 17 + 123 = 85123
    // Account 2: $3,000 (salt 456) -> c2 = 3000 * 17 + 456 = 51456
    // Account 3: $4,500 (salt 789) -> c3 = 4500 * 17 + 789 = 77289
    // Threshold: $10,000
    // Total: $12,500 (PASSED)
    let inputs = weighted_threshold_verifier_inputs(
        "5000", "123", "85123",
        "3000", "456", "51456",
        "4500", "789", "77289",
        "10000"
    );

    // Save artifacts
    let prog_json = serde_json::to_string_pretty(&program_v2).unwrap();
    std::fs::write("contract.ir.json", prog_json).unwrap();
    std::fs::write("inputs.json", serde_json::to_string_pretty(&inputs).unwrap()).unwrap();
    
    println!("Private Underwriter circuit and inputs generated!");
}