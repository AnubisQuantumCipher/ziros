use zkf_tui::{
    resize_smoke_profiles, supported_terminal_profiles, validate_reference_dashboard,
    validate_reference_proof_demo,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("AegisVault terminal validation");
    println!(
        "Runtime terminal: TERM_PROGRAM={} TERM={}",
        std::env::var("TERM_PROGRAM").unwrap_or_else(|_| "-".to_string()),
        std::env::var("TERM").unwrap_or_else(|_| "-".to_string())
    );

    for profile in supported_terminal_profiles()
        .iter()
        .chain(resize_smoke_profiles().iter())
    {
        let result = validate_reference_dashboard(*profile).map_err(std::io::Error::other)?;
        println!(
            "[{}] {} ({}x{})",
            if result.passed() { "PASS" } else { "FAIL" },
            profile.name,
            profile.width,
            profile.height
        );
        if !result.passed() {
            println!("  missing markers: {}", result.missing_markers.join(", "));
            return Err("terminal validation failed".into());
        }
    }

    let progress_lines = validate_reference_proof_demo().map_err(std::io::Error::other)?;
    println!("[PASS] proof progress");
    for line in progress_lines {
        println!("  {line}");
    }

    Ok(())
}
