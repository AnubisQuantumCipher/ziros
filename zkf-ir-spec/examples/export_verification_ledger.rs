use zkf_ir_spec::verification_ledger;

fn main() {
    let json = serde_json::to_string_pretty(&verification_ledger())
        .expect("verification ledger should serialize");
    println!("{json}");
}
