#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::PathBuf;

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut manifest_dir = repo_root.join("proofs").join("manifests");
    let mut lean_dir = repo_root.join("proofs").join("lean");
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--out-dir" => {
                manifest_dir = PathBuf::from(args.next().ok_or("--out-dir requires a path")?);
            }
            "--lean-dir" => {
                lean_dir = PathBuf::from(args.next().ok_or("--lean-dir requires a path")?);
            }
            _ => {
                return Err("usage: cargo run -p zkf-metal --example export_gpu_proof_artifacts [--out-dir PATH] [--lean-dir PATH]".into());
            }
        }
    }

    zkf_metal::proof_ir::export_checked_gpu_proof_artifacts(&manifest_dir, &lean_dir)?;
    println!("{}", manifest_dir.display());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("export_gpu_proof_artifacts is only available on macOS hosts");
    std::process::exit(1);
}
