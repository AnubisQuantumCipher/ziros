mod spec;

use std::fs;
use std::path::{Path, PathBuf};

use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_lib::{
    export_groth16_solidity_verifier, foundry_project_dir, json_pretty, AppSpecV1, CompiledProgram,
    FieldElement, ProofArtifact,
};

const CONTRACT_NAME: &str = "PrivateBudgetApprovalVerifier";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("demo") => {
            run_demo()?;
        }
        Some("prove") => {
            let inputs_path = required_arg(args.next(), "usage: prove <inputs.json> <out_dir>")?;
            let out_dir = required_arg(args.next(), "usage: prove <inputs.json> <out_dir>")?;
            prove_into(Path::new(&inputs_path), Path::new(&out_dir))?;
        }
        Some("verify") => {
            let compiled_path =
                required_arg(args.next(), "usage: verify <compiled.json> <proof.json>")?;
            let proof_path =
                required_arg(args.next(), "usage: verify <compiled.json> <proof.json>")?;
            verify_from_files(Path::new(&compiled_path), Path::new(&proof_path))?;
        }
        Some("export") => {
            let proof_path = required_arg(args.next(), "usage: export <proof.json> <out_dir>")?;
            let out_dir = required_arg(args.next(), "usage: export <proof.json> <out_dir>")?;
            export_from_artifact(Path::new(&proof_path), Path::new(&out_dir))?;
        }
        Some(other) => {
            return Err(format!(
                "unknown command '{other}'\ncommands: demo | prove <inputs.json> <out_dir> | verify <compiled.json> <proof.json> | export <proof.json> <out_dir>"
            )
            .into());
        }
    }

    Ok(())
}

fn required_arg(
    value: Option<String>,
    usage: &'static str,
) -> Result<String, Box<dyn std::error::Error>> {
    value.ok_or_else(|| usage.into())
}

fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    let (spec, program) = spec::load_program()?;
    let inputs = load_manifest_inputs("inputs.example.json")?;
    let checked = zkf_lib::check(&program, &inputs, None, None)?;
    let embedded = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        zkf_lib::compile_and_prove_default(&program, &inputs, None, None)
    })?;
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)?;
    if !verified {
        return Err("verification failed".into());
    }

    println!(
        "program={} backend={} verified={}",
        program.name, embedded.compiled.backend, verified
    );
    print_public_outputs(&spec, &checked.public_inputs)?;
    Ok(())
}

fn prove_into(inputs_path: &Path, out_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (spec, program) = spec::load_program()?;
    let inputs = zkf_lib::load_inputs(
        inputs_path
            .to_str()
            .ok_or("inputs path must be valid UTF-8")?,
    )?;
    let checked = zkf_lib::check(&program, &inputs, None, None)?;
    let embedded = zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
        zkf_lib::compile_and_prove_default(&program, &inputs, None, None)
    })?;

    fs::create_dir_all(out_dir)?;
    write_json(
        &out_dir.join("compiled.json"),
        &serde_json::to_value(&embedded.compiled)?,
    )?;
    write_json(
        &out_dir.join("proof.json"),
        &serde_json::to_value(&embedded.artifact)?,
    )?;
    write_json(
        &out_dir.join("public_outputs.json"),
        &named_public_outputs(&spec, &checked.public_inputs)?,
    )?;

    println!("wrote {}", out_dir.display());
    print_public_outputs(&spec, &checked.public_inputs)?;
    Ok(())
}

fn verify_from_files(
    compiled_path: &Path,
    proof_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let compiled: CompiledProgram = serde_json::from_str(&fs::read_to_string(compiled_path)?)?;
    let artifact: ProofArtifact = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    let verified = zkf_lib::verify(&compiled, &artifact)?;
    if !verified {
        return Err("verification failed".into());
    }
    println!("verified=true backend={}", compiled.backend);
    Ok(())
}

fn export_from_artifact(
    proof_path: &Path,
    out_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let artifact: ProofArtifact = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
    let verifier = export_groth16_solidity_verifier(&artifact, Some(CONTRACT_NAME))?;
    let calldata = proof_to_calldata_json(&artifact.proof, &artifact.public_inputs)
        .map_err(|message| format!("failed to build calldata JSON: {message}"))?;

    fs::create_dir_all(out_dir)?;
    write_text(&out_dir.join("verifier.sol"), &verifier)?;
    write_json(&out_dir.join("calldata.json"), &calldata)?;

    let foundry_dir = foundry_project_dir(out_dir);
    zkf_lib::ensure_foundry_layout(&foundry_dir)?;
    let contract_path = foundry_dir.join("src").join(format!("{CONTRACT_NAME}.sol"));
    write_text(&contract_path, &verifier)?;

    let foundry_test = generate_foundry_test_from_artifact(
        &artifact.proof,
        &artifact.public_inputs,
        &format!("src/{CONTRACT_NAME}.sol"),
        CONTRACT_NAME,
    )
    .map_err(|message| format!("failed to build foundry test: {message}"))?;
    let foundry_test_path = foundry_dir
        .join("test")
        .join(format!("{CONTRACT_NAME}.t.sol"));
    write_text(&foundry_test_path, &foundry_test.source)?;

    println!(
        "exported verifier={}, calldata={}, foundry={}",
        out_dir.join("verifier.sol").display(),
        out_dir.join("calldata.json").display(),
        foundry_dir.display()
    );
    Ok(())
}

fn load_manifest_inputs(name: &str) -> Result<zkf_lib::WitnessInputs, Box<dyn std::error::Error>> {
    let path = manifest_path(name);
    zkf_lib::load_inputs(path.to_str().ok_or("manifest path must be valid UTF-8")?)
        .map_err(Into::into)
}

fn manifest_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}

fn named_public_outputs(
    spec: &AppSpecV1,
    outputs: &[FieldElement],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if spec.public_outputs.len() != outputs.len() {
        return Err(format!(
            "public output count mismatch: spec has {}, witness has {}",
            spec.public_outputs.len(),
            outputs.len()
        )
        .into());
    }

    let mut map = serde_json::Map::new();
    for (name, value) in spec.public_outputs.iter().zip(outputs) {
        let entry = if name == "approved" {
            serde_json::Value::Bool(value.to_decimal_string() == "1")
        } else {
            serde_json::Value::String(value.to_decimal_string())
        };
        map.insert(name.clone(), entry);
    }
    Ok(serde_json::Value::Object(map))
}

fn print_public_outputs(
    spec: &AppSpecV1,
    outputs: &[FieldElement],
) -> Result<(), Box<dyn std::error::Error>> {
    let rendered = named_public_outputs(spec, outputs)?;
    println!("{}", json_pretty(&rendered));
    Ok(())
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn write_text(path: &Path, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, text)?;
    Ok(())
}
