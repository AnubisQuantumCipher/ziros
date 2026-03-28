use std::time::Instant;
use zkf_backends::{backend_for, try_fold_native};
use zkf_core::{BackendKind, FieldId, generate_witness};
use zkf_dsl::circuit;

/// Verifiable Hash Chain Step (Logical PastaFp, Proved on Pasta Fp)
#[circuit(field = "pasta_fp")]
fn hash_chain_step(h_in: Public<Field>) -> Public<Field> {
    let sq = h_in * h_in;
    let cb = sq * h_in;
    (cb + 1337) * 31
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZK-Hash-Chain: Robust 100-Step Folding (Cross-Field) ===");

    let zir = hash_chain_step_program();
    let program = zkf_core::program_zir_to_v2(&zir)?;

    println!("Circuit Signals:");
    for sig in &program.signals {
        println!("  - {}: {:?}", sig.name, sig.visibility);
    }

    let nova = backend_for(BackendKind::Nova);
    let compiled = nova.compile(&program)?;

    // TRUTH: Nova primary scalar field is PastaFp.
    let field = FieldId::PastaFp;
    let modulus = field.modulus();
    let mut current_hash = zkf_core::FieldElement::from_i64(42);
    let mut witnesses = Vec::new();

    println!("Sequencing 100 hash steps using Prover Native Modulus (Pasta Fp)...");
    for i in 0..100 {
        let val = current_hash.as_bigint();
        let next_val = (((&val * &val * &val) + 1337u32) * 31u32) % modulus;
        let next_hash = zkf_core::FieldElement::from_bigint_with_field(next_val.clone(), field);

        if !(3..=97).contains(&i) {
            println!(
                "Step {}: h_in={}, h_out={}",
                i,
                current_hash.to_decimal_string(),
                next_hash.to_decimal_string()
            );
        }

        let inputs = hash_chain_step_inputs(&current_hash.to_decimal_string());
        let witness = generate_witness(&program, &inputs)?;
        witnesses.push(witness);

        current_hash = next_hash;
    }

    println!("Executing Nova IVC folding over 100 steps...");
    let start = Instant::now();
    let fold_result = try_fold_native(&compiled, &witnesses, false)
        .ok_or_else(|| std::io::Error::other("Nova feature missing"))??;

    println!("=== SUCCESS ===");
    println!("100-step recursive proof produced in {:?}", start.elapsed());
    println!("Folded steps: {}", fold_result.steps);
    println!("Final hash state: {}", current_hash.to_decimal_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_chain_step_lowers_to_pasta_fp_program() {
        let zir = hash_chain_step_program();
        let program = zkf_core::program_zir_to_v2(&zir).expect("lower to ir-v2");

        assert_eq!(program.field, FieldId::PastaFp);
        assert!(!program.signals.is_empty());
        assert!(!program.constraints.is_empty());
    }

    #[test]
    fn hash_chain_step_inputs_include_public_hash() {
        let inputs = hash_chain_step_inputs("42");
        assert_eq!(
            inputs.get("h_in").map(|value| value.to_decimal_string()),
            Some("42".to_string())
        );
    }
}
