use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "zkf-verify",
    about = "Verify the public zkf-metal artifact repository."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    VerifyAll {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::VerifyAll { repo, json } => match zkf_verify::verify_all(&repo) {
            Ok(payload) if json => serde_json::to_string_pretty(&payload)
                .map(|json| {
                    println!("{json}");
                })
                .map_err(|err| format!("serialize verification summary: {err}")),
            Ok(payload) => {
                println!(
                    "verified {} bundles and {} checksums under {}",
                    payload.bundles_verified, payload.checksums_verified, payload.repo
                );
                Ok(())
            }
            Err(err) => Err(err),
        },
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
