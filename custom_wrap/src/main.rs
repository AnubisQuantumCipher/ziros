use zkf_dsl::circuit;

#[circuit(field = "goldilocks")]
fn hash_preimage(
    preimage: Private<u32>,
    salt: Private<u32>,
    expected_hash: Public<u32>,
) {
    let internal_val = preimage * salt;
    let computed_hash = internal_val + 42; // A simple dummy hash logic for demonstration
    assert_eq(computed_hash, expected_hash);
}

fn main() {
    let program = hash_preimage_program();
    let inputs = hash_preimage_inputs("10", "5", "92"); // 10 * 5 + 42 = 92
    
    // Save program to IR json
    let prog_json = serde_json::to_string_pretty(&program).unwrap();
    std::fs::write("circuit.ir.json", prog_json).unwrap();
    
    // Save inputs to json
    let inputs_json = serde_json::to_string_pretty(&inputs).unwrap();
    std::fs::write("inputs.json", inputs_json).unwrap();
    
    println!("Circuit and inputs generated successfully!");
}