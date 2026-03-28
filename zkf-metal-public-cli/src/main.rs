use clap::{Parser, Subcommand};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};
use zkf_backends::metal_runtime::{CapabilityReport, GpuStageCoverage, MetalRuntimeReport};
use zkf_backends::{
    capabilities_report, metal_runtime_report, strict_bn254_auto_route_ready_with_runtime,
    strict_bn254_gpu_stage_coverage,
};
use zkf_lib::{
    CompiledProgram, Program, ProofArtifact, WitnessInputs, compile_and_prove,
    compile_and_prove_default, load_inputs, load_program, verify,
};

#[derive(Debug, Parser)]
#[command(name = "zkf-metal", about = "Public artifact-only zkf-metal runtime.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Version,
    MetalDoctor {
        #[arg(long)]
        json: bool,
    },
    Prove {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        compiled_out: PathBuf,
        #[arg(long)]
        proof_out: PathBuf,
        #[arg(long)]
        backend: Option<String>,
    },
    Verify {
        #[arg(long)]
        compiled: PathBuf,
        #[arg(long)]
        proof: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct PublicMetalDoctorReport {
    version: &'static str,
    runtime: MetalRuntimeReport,
    strict_bn254_ready: bool,
    strict_gpu_stage_coverage: GpuStageCoverage,
    backends: Vec<CapabilityReport>,
}

#[derive(Debug, Serialize)]
struct ProveReport {
    backend: String,
    program_digest: String,
    compiled_path: String,
    proof_path: String,
    proof_bytes: usize,
    public_inputs: usize,
    metal_runtime: MetalRuntimeReport,
}

#[derive(Debug, Serialize)]
struct VerifyReport {
    backend: String,
    program_digest: String,
    verified: bool,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Version => {
            println!("{}", zkf_lib::version());
            Ok(())
        }
        Commands::MetalDoctor { json } => run_metal_doctor(json),
        Commands::Prove {
            program,
            inputs,
            compiled_out,
            proof_out,
            backend,
        } => run_prove(program, inputs, compiled_out, proof_out, backend),
        Commands::Verify { compiled, proof } => run_verify(compiled, proof),
    };

    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run_metal_doctor(json: bool) -> Result<(), String> {
    if !json {
        return Err("public zkf-metal only supports `metal-doctor --json`".to_string());
    }
    let runtime = metal_runtime_report();
    let report = PublicMetalDoctorReport {
        version: zkf_lib::version(),
        strict_bn254_ready: strict_bn254_auto_route_ready_with_runtime(&runtime),
        strict_gpu_stage_coverage: strict_bn254_gpu_stage_coverage(&runtime),
        backends: capabilities_report(),
        runtime,
    };
    print_json(&report)
}

fn run_prove(
    program_path: PathBuf,
    inputs_path: PathBuf,
    compiled_out: PathBuf,
    proof_out: PathBuf,
    backend: Option<String>,
) -> Result<(), String> {
    let program = load_program_path(&program_path)?;
    let inputs = load_inputs_path(&inputs_path)?;
    let embedded = match backend.as_deref() {
        Some(name) => compile_and_prove(&program, &inputs, name, None, None),
        None => compile_and_prove_default(&program, &inputs, None, None),
    }
    .map_err(|err| {
        format!(
            "prove {} with {}: {err}",
            program_path.display(),
            inputs_path.display()
        )
    })?;

    write_json_file(&compiled_out, &embedded.compiled)?;
    write_json_file(&proof_out, &embedded.artifact)?;

    let report = ProveReport {
        backend: embedded.compiled.backend.as_str().to_string(),
        program_digest: embedded.compiled.program_digest.clone(),
        compiled_path: compiled_out.display().to_string(),
        proof_path: proof_out.display().to_string(),
        proof_bytes: embedded.artifact.proof.len(),
        public_inputs: embedded.artifact.public_inputs.len(),
        metal_runtime: metal_runtime_report(),
    };
    print_json(&report)
}

fn run_verify(compiled_path: PathBuf, proof_path: PathBuf) -> Result<(), String> {
    let compiled: CompiledProgram = read_json_file(&compiled_path)?;
    let artifact: ProofArtifact = read_json_file(&proof_path)?;
    let verified = verify(&compiled, &artifact).map_err(|err| {
        format!(
            "verify {} against {}: {err}",
            proof_path.display(),
            compiled_path.display()
        )
    })?;
    let report = VerifyReport {
        backend: compiled.backend.as_str().to_string(),
        program_digest: compiled.program_digest.clone(),
        verified,
    };
    print_json(&report)?;
    if verified {
        Ok(())
    } else {
        Err("proof verification returned false".to_string())
    }
}

fn load_program_path(path: &Path) -> Result<Program, String> {
    load_program(&path.display().to_string())
        .map_err(|err| format!("load program {}: {err}", path.display()))
}

fn load_inputs_path(path: &Path) -> Result<WitnessInputs, String> {
    load_inputs(&path.display().to_string())
        .map_err(|err| format!("load inputs {}: {err}", path.display()))
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|err| format!("serialize JSON output: {err}"))?;
    println!("{json}");
    Ok(())
}

fn write_json_file<T: Serialize>(path: &PathBuf, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("serialize {}: {err}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create {}: {err}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|err| format!("write {}: {err}", path.display()))
}

fn read_json_file<T: DeserializeOwned>(path: &PathBuf) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|err| format!("parse {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
    struct DemoRecord {
        value: u32,
    }

    #[test]
    fn cli_parses_prove_command() {
        let cli = Cli::parse_from([
            "zkf-metal",
            "prove",
            "--program",
            "/tmp/program.json",
            "--inputs",
            "/tmp/inputs.json",
            "--compiled-out",
            "/tmp/compiled.json",
            "--proof-out",
            "/tmp/proof.json",
            "--backend",
            "plonky3",
        ]);

        match cli.command {
            Commands::Prove {
                program,
                inputs,
                compiled_out,
                proof_out,
                backend,
            } => {
                assert_eq!(program, PathBuf::from("/tmp/program.json"));
                assert_eq!(inputs, PathBuf::from("/tmp/inputs.json"));
                assert_eq!(compiled_out, PathBuf::from("/tmp/compiled.json"));
                assert_eq!(proof_out, PathBuf::from("/tmp/proof.json"));
                assert_eq!(backend.as_deref(), Some("plonky3"));
            }
            other => panic!("expected prove command, got {other:?}"),
        }
    }

    #[test]
    fn json_helpers_roundtrip_payload() {
        let root =
            std::env::temp_dir().join(format!("zkf-metal-public-cli-json-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temp dir");
        let path = root.join("payload.json");

        write_json_file(&path, &DemoRecord { value: 7 }).expect("write");
        let restored: DemoRecord = read_json_file(&path).expect("read");
        assert_eq!(restored, DemoRecord { value: 7 });

        let _ = fs::remove_dir_all(&root);
    }
}
