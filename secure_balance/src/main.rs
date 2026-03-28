use std::fs::File;
use zkf_dsl::circuit;

/// Secure balance transfer circuit.
/// Fixes the under-constrained vulnerability by introducing:
/// 1. A public state commitment (hash) that binds the private balance to an on-chain record.
/// 2. A mathematical range check to ensure `bal >= amt` without underflow.
#[circuit(field = "bn254")]
fn secure_transfer(
    bal: Private<u32>,
    amt: Private<u32>,
    user_id: Private<u32>,
    expected_commitment: Public<u32>,
) -> Public<u32> {
    // 1. Verify the private balance belongs to the public commitment.
    // In a real app, this would be a full Poseidon hash or Merkle path. 
    // Here we use a simple arithmetic binding for demonstration.
    let computed_hash = (bal * 13) + user_id;
    assert_eq(computed_hash, expected_commitment);

    // 2. Prevent infinite money / finite field underflow glitch.
    // By enforcing that the difference fits in 32 bits, we guarantee 
    // `bal >= amt`. If `amt > bal`, the difference wraps around the BN254 
    // modulus to a massive 254-bit number, which will fail the 32-bit range check.
    let remaining = bal - amt;
    assert_range(remaining, 32);

    remaining
}

fn main() {
    let program = zkf_core::program_zir_to_v2(&secure_transfer_program()).unwrap();
    
    // Valid transaction: User 42 has 100 tokens, sends 35.
    // expected_commitment = (100 * 13) + 42 = 1342
    let valid_inputs = secure_transfer_inputs("100", "35", "42", "1342");
    
    // Malicious transaction (The forgery attempt): 
    // User claims they have 1000 tokens and sends 935.
    // Because they must provide the REAL commitment (1342), the hash check will fail 
    // unless they change user_id, which would mean they are spending someone else's money.
    // If they try to leave user_id = 42, then (1000 * 13) + 42 = 13042 != 1342.
    let malicious_inputs = secure_transfer_inputs("1000", "935", "42", "1342");
    
    // Edge case: Overspend attempt. User has 100 tokens, tries to send 150.
    let overspend_inputs = secure_transfer_inputs("100", "150", "42", "1342");
    
    let prog_json = serde_json::to_string_pretty(&program).unwrap();
    std::fs::write("circuit.ir.json", prog_json).unwrap();
    
    std::fs::write("valid.json", serde_json::to_string_pretty(&valid_inputs).unwrap()).unwrap();
    std::fs::write("forgery.json", serde_json::to_string_pretty(&malicious_inputs).unwrap()).unwrap();
    std::fs::write("overspend.json", serde_json::to_string_pretty(&overspend_inputs).unwrap()).unwrap();
    
    println!("Secure circuit and test inputs generated successfully!");
}