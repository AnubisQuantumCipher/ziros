use zkf_dsl::circuit;

/// Advanced Zero-Knowledge KYC Identity Verifier
/// Proves that a user possesses a specific identity ID, is over the age of 18, 
/// and earns over a certain salary threshold, without revealing the underlying data.
/// It uses a computationally expensive polynomial hashing mechanism to bind the private data.
#[circuit(field = "bn254")]
fn verify_kyc_identity(
    identity_id: Private<u32>,
    age: Private<u32>,
    salary: Private<u32>,
    age_threshold: Public<u32>,
    salary_threshold: Public<u32>,
    expected_commitment: Public<u32>,
) {
    // 1. Verify attributes (prevent overflow attacks)
    assert_range(age, 8); 
    assert_range(salary, 32); 
    
    // Age >= Threshold -> age - threshold >= 0 -> diff fits in 8 bits
    let age_diff = age - age_threshold;
    assert_range(age_diff, 8);
    
    // Salary >= Threshold
    let salary_diff = salary - salary_threshold;
    assert_range(salary_diff, 32);

    // 2. Cryptographic binding via high-degree polynomial (stresses the constraints)
    // H = ID^3 + Age^2 * 17 + Salary * 31 + 42
    
    let id_sq = identity_id * identity_id;
    let id_cb = id_sq * identity_id;
    
    let age_sq = age * age;
    let age_term = age_sq * 17;
    
    let salary_term = salary * 31;
    
    let hash_sum = id_cb + age_term;
    let hash_total = hash_sum + salary_term;
    let final_hash = hash_total + 42;
    
    // 3. Ensure the computed hash matches the expected public commitment
    assert_eq(final_hash, expected_commitment);
}

fn main() {
    let program = verify_kyc_identity_program();
    
    // Inputs: ID=7, Age=25, Salary=100,000, age_thresh=18, salary_thresh=50,000
    // ID^3 = 343
    // Age^2 * 17 = 625 * 17 = 10,625
    // Salary * 31 = 100,000 * 31 = 3,100,000
    // Total = 343 + 10625 + 3100000 + 42 = 3,111,010
    
    let inputs = verify_kyc_identity_inputs(
        "7", 
        "25", 
        "100000", 
        "18", 
        "50000", 
        "3111010"
    );
    
    let prog_json = serde_json::to_string_pretty(&program).unwrap();
    std::fs::write("kyc.ir.json", prog_json).unwrap();
    
    let inputs_json = serde_json::to_string_pretty(&inputs).unwrap();
    std::fs::write("kyc_inputs.json", inputs_json).unwrap();
    
    println!("KYC Circuit and inputs generated successfully!");
}
