fn main() {
    let ledger = zkf_ir_spec::verification_ledger();
    println!("{}", serde_json::to_string_pretty(&ledger).expect("serialize ledger"));
}
