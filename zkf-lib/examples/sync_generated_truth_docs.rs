fn main() -> Result<(), Box<dyn std::error::Error>> {
    let written = zkf_lib::app::evidence::sync_generated_truth_documents()?;
    for path in written {
        println!("{path}");
    }
    Ok(())
}
