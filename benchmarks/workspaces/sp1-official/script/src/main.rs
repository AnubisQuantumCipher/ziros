use clap::{Parser, ValueEnum};
use serde_json::json;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use sp1_workload_lib::WorkloadInput;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const WORKLOAD_ELF: Elf = include_elf!("workload-program");
const MACOS_SP1_DOCKER_MIN_MEMORY_BYTES: u64 = 32_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Scenario {
    SingleCircuitProve,
    DeveloperWorkload,
    RecursiveWorkflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Mode {
    Prove,
    Verify,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, value_enum)]
    scenario: Scenario,
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long)]
    out_dir: PathBuf,
}

fn scenario_input(scenario: Scenario) -> WorkloadInput {
    match scenario {
        Scenario::SingleCircuitProve => WorkloadInput {
            kind: 0,
            values: [3, 7, 0, 0, 0, 0, 0, 0],
        },
        Scenario::DeveloperWorkload => WorkloadInput {
            kind: 1,
            values: [1, 2, 3, 4, 4, 3, 2, 1],
        },
        Scenario::RecursiveWorkflow => WorkloadInput {
            kind: 2,
            values: [1, 1, 0, 0, 0, 0, 0, 0],
        },
    }
}

fn scenario_id(scenario: Scenario) -> &'static str {
    match scenario {
        Scenario::SingleCircuitProve => "single_circuit_prove",
        Scenario::DeveloperWorkload => "developer_workload",
        Scenario::RecursiveWorkflow => "recursive_workflow",
    }
}

fn ensure_docker_ready() -> Result<(), String> {
    let output = Command::new("docker")
        .args(["info", "--format", "{{json .ServerVersion}}"])
        .output()
        .map_err(|e| {
            format!(
                "docker prerequisite failed: {e}. Install Docker Desktop or start Colima before running the SP1 competition lane"
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!(
            "docker prerequisite failed: {}. Start Docker Desktop or Colima so `docker info` succeeds before running the SP1 competition lane",
            if detail.is_empty() {
                "docker is installed but unavailable".to_string()
            } else {
                detail
            }
        ));
    }
    Ok(())
}

fn format_gib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

fn configure_docker_platform() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if std::env::var_os("DOCKER_DEFAULT_PLATFORM").is_none() {
            // The stable SP1 gnark image currently ships without a linux/arm64
            // manifest, so Apple Silicon hosts need amd64 emulation for Groth16
            // recursion proving until Succinct publishes a matching arm64 tag.
            unsafe { std::env::set_var("DOCKER_DEFAULT_PLATFORM", "linux/amd64") };
        }
    }
}

fn configure_shared_temp_dir() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Colima mounts the user's home directory by default, but not /var/folders.
        // The upstream SP1 gnark FFI bind-mounts tempfile paths into Docker, so force
        // those temp files into a shared home-directory path on macOS.
        let home = env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
        let temp_dir = PathBuf::from(home)
            .join(".zkf-competition-tools")
            .join("sp1-tmp");
        fs::create_dir_all(&temp_dir).map_err(|e| format!("create SP1 temp dir: {e}"))?;
        unsafe {
            env::set_var("TMPDIR", &temp_dir);
            env::set_var("TMP", &temp_dir);
            env::set_var("TEMP", &temp_dir);
        }
    }
    Ok(())
}

fn ensure_docker_capacity() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("docker")
            .args(["info", "--format", "{{json .MemTotal}}"])
            .output()
            .map_err(|e| format!("docker memory probe failed: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            return Err(format!(
                "docker memory probe failed: {}. Increase Docker Desktop or Colima memory to at least 32GB before running the SP1 Groth16 lane on macOS",
                if detail.is_empty() {
                    "docker is installed but unavailable".to_string()
                } else {
                    detail
                }
            ));
        }
        let observed = String::from_utf8_lossy(&output.stdout)
            .trim()
            .trim_matches('"')
            .parse::<u64>()
            .map_err(|_| "docker memory probe returned an invalid value".to_string())?;
        if observed < MACOS_SP1_DOCKER_MIN_MEMORY_BYTES {
            return Err(format!(
                "docker memory is {}GiB, below the 32GB minimum recommended for SP1 Groth16 aggregation on macOS. Restart Docker Desktop or Colima with more memory; for Colima use `colima stop && colima start --cpu 8 --memory 32 --disk 80`",
                format_gib(observed)
            ));
        }
    }
    Ok(())
}

fn prove(scenario: Scenario, out_dir: &PathBuf) -> Result<(), String> {
    ensure_docker_ready()?;
    ensure_docker_capacity()?;
    configure_docker_platform();
    configure_shared_temp_dir()?;
    let client = ProverClient::from_env();
    let pk = client
        .setup(WORKLOAD_ELF)
        .map_err(|e| format!("setup failed: {e}"))?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&scenario_input(scenario));
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .map_err(|e| format!("prove failed: {e}"))?;
    client
        .verify(&proof, pk.verifying_key(), None)
        .map_err(|e| format!("verify failed: {e}"))?;

    fs::create_dir_all(out_dir).map_err(|e| format!("create out dir: {e}"))?;
    fs::write(out_dir.join("proof.bin"), proof.bytes()).map_err(|e| format!("write proof: {e}"))?;
    fs::write(
        out_dir.join("summary.json"),
        serde_json::to_vec_pretty(&json!({
            "scenario": scenario_id(scenario),
            "verified": true
        }))
        .map_err(|e| format!("encode summary: {e}"))?,
    )
    .map_err(|e| format!("write summary: {e}"))?;
    Ok(())
}

fn verify(scenario: Scenario, out_dir: &PathBuf) -> Result<(), String> {
    let payload: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("summary.json")).map_err(|e| format!("read summary: {e}"))?,
    )
    .map_err(|e| format!("parse summary: {e}"))?;
    if payload.get("scenario").and_then(serde_json::Value::as_str) != Some(scenario_id(scenario)) {
        return Err("summary scenario mismatch".to_string());
    }
    if payload.get("verified").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err("summary recorded verified=false".to_string());
    }
    if !out_dir.join("proof.bin").exists() {
        return Err("proof.bin is missing".to_string());
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    let result = match args.mode {
        Mode::Prove => prove(args.scenario, &args.out_dir),
        Mode::Verify => verify(args.scenario, &args.out_dir),
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
