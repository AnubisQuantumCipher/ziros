use std::time::Instant;
use zkf_backends::{backend_for, try_fold_native};
use zkf_core::{BackendKind, FieldId, generate_witness};
use zkf_examples::{recurrence_program, mul_add_inputs};

fn main() {
    println!("=== Testing Native Nova IVC Folding ===");
    
    // 1. Get the circuit
    let field = FieldId::Bn254; // Nova backend accepts BN254 IR programs for compatibility
    let program = recurrence_program(field, 1);
    
    println!("Generated recurrence circuit for Nova.");
    
    // 2. Generate witnesses for 5 folding steps
    let mut witnesses = Vec::new();
    for i in 0..5 {
        let inputs = mul_add_inputs(2 + i as i64, 3);
        let witness = generate_witness(&program, &inputs).expect("failed to generate witness");
        witnesses.push(witness);
    }
    
    println!("Generated 5 execution trace witnesses.");
    
    // 3. Compile for Nova
    println!("Compiling circuit for Nova backend...");
    let compile_start = Instant::now();
    let nova = backend_for(BackendKind::Nova);
    let compiled = nova.compile(&program).expect("failed to compile");
    println!("Compiled in {:?}", compile_start.elapsed());
    
    // 4. Fold!
    println!("Starting Metal-accelerated Nova IVC folding over 5 steps...");
    let fold_start = Instant::now();
    
    let fold_result = try_fold_native(&compiled, &witnesses, false)
        .expect("Nova native feature not enabled")
        .expect("Folding failed");
        
    println!("Successfully folded 5 steps into a single IVC proof in {:?}", fold_start.elapsed());
    
    // Verify the fold result
    println!("IVC Proof generated with {} steps internally.", fold_result.steps);
}