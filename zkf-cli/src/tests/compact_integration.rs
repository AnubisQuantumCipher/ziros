use super::*;

use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn compact_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn compactc_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("COMPACTC_BIN").map(PathBuf::from)
        && path.exists()
    {
        return Some(path);
    }

    let home_candidate = std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".compact")
            .join("versions")
            .join("0.30.0")
            .join("aarch64-darwin")
            .join("compactc")
    });
    if let Some(path) = home_candidate
        && path.exists()
    {
        return Some(path);
    }

    None
}

fn compactc_is_supported(path: &Path) -> bool {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|version| version.trim() == "0.30.0")
}

fn compile_compact_contract(
    root: &Path,
    filename: &str,
    source: &str,
    circuit_name: &str,
) -> Option<PathBuf> {
    let compactc = compactc_path()?;
    if !compactc_is_supported(&compactc) {
        eprintln!("skipping Compact live test because compactc 0.30.0 is not available");
        return None;
    }

    let source_path = root.join(filename);
    let out_dir = root.join("compact-out");
    fs::write(&source_path, source).expect("write compact source");
    let output = Command::new(&compactc)
        .arg("--skip-zk")
        .arg(&source_path)
        .arg(&out_dir)
        .output()
        .expect("compactc should launch");
    assert!(
        output.status.success(),
        "compactc failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(out_dir.join("zkir").join(format!("{circuit_name}.zkir")))
}

fn import_compact_zkir(zkir_path: &Path, out_path: &Path) {
    cmd::import::handle_import(cmd::import::HandleImportArgs {
        frontend: "compact".to_string(),
        input: zkir_path.to_path_buf(),
        out: out_path.to_path_buf(),
        name: None,
        field: None,
        ir_family: "ir-v2".to_string(),
        allow_unsupported_version: false,
        package_out: None,
        json: false,
    })
    .expect("import compact zkir");
}

#[test]
fn live_compact_set_contract_imports_proves_and_verifies_on_halo2_bls12_381() {
    let _guard = compact_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = tempfile::tempdir().expect("tempdir");
    let Some(zkir_path) = compile_compact_contract(
        root.path(),
        "set.compact",
        r#"
pragma language_version >= 0.21.0;

import CompactStandardLibrary;

ledger counter: Uint<64>;

constructor() {
  counter = 0;
}

export circuit set(value: Uint<64>): [] {
  counter = disclose(value);
}
"#,
        "set",
    ) else {
        return;
    };

    let program_path = root.path().join("set.program.json");
    let inputs_path = root.path().join("set.inputs.json");
    let proof_path = root.path().join("set.proof.json");
    let compiled_path = root.path().join("set.compiled.json");
    import_compact_zkir(&zkir_path, &program_path);
    write_json(
        &inputs_path,
        &WitnessInputs::from([("value".to_string(), FieldElement::from_i64(7))]),
    )
    .expect("inputs");

    cmd::prove::handle_prove(
        cmd::prove::ProveArgs {
            program: program_path.clone(),
            inputs: inputs_path,
            json: false,
            backend: None,
            objective: "fastest-prove".to_string(),
            mode: None,
            export: None,
            allow_attestation: false,
            out: proof_path.clone(),
            compiled_out: Some(compiled_path.clone()),
            solver: None,
            seed: None,
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: false,
            hybrid: false,
        },
        false,
    )
    .expect("prove set");

    let compiled: zkf_core::CompiledProgram = read_json(&compiled_path).expect("compiled");
    assert_eq!(compiled.backend, BackendKind::Halo2Bls12381);
    let artifact: ProofArtifact = read_json(&proof_path).expect("artifact");
    assert_eq!(artifact.backend, BackendKind::Halo2Bls12381);

    cmd::prove::handle_verify(
        program_path,
        proof_path,
        "halo2-bls12-381".to_string(),
        Some(compiled_path),
        None,
        None,
        false,
        false,
        false,
    )
    .expect("verify set proof");
}

#[test]
fn live_compact_underconstrained_contract_returns_structured_audit_json() {
    let _guard = compact_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = tempfile::tempdir().expect("tempdir");
    let Some(zkir_path) = compile_compact_contract(
        root.path(),
        "publish_sum.compact",
        r#"
pragma language_version >= 0.21.0;

import CompactStandardLibrary;

ledger total: Uint<128>;

constructor() {
  total = 0;
}

export circuit publish_sum(a: Uint<64>, b: Uint<64>): [] {
  total = disclose(a + b);
}
"#,
        "publish_sum",
    ) else {
        return;
    };

    let program_path = root.path().join("publish_sum.program.json");
    let inputs_path = root.path().join("publish_sum.inputs.json");
    let proof_path = root.path().join("publish_sum.proof.json");
    import_compact_zkir(&zkir_path, &program_path);
    write_json(
        &inputs_path,
        &WitnessInputs::from([
            ("a".to_string(), FieldElement::from_i64(3)),
            ("b".to_string(), FieldElement::from_i64(5)),
        ]),
    )
    .expect("inputs");

    let err = cmd::prove::handle_prove(
        cmd::prove::ProveArgs {
            program: program_path,
            inputs: inputs_path,
            json: true,
            backend: None,
            objective: "fastest-prove".to_string(),
            mode: None,
            export: None,
            allow_attestation: false,
            out: proof_path.clone(),
            compiled_out: None,
            solver: None,
            seed: None,
            groth16_setup_blob: None,
            allow_dev_deterministic_groth16: false,
            hybrid: false,
        },
        false,
    )
    .expect_err("underconstrained compact contract should fail audit");

    let payload = raw_cli_error_payload(&err).expect("raw json error payload");
    let payload: Value = serde_json::from_str(payload).expect("audit json");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["error_kind"], "audit_failure");
    assert!(
        payload["failed_categories"]
            .as_array()
            .expect("failed_categories array")
            .iter()
            .any(|value| value == "underconstrained_signals"),
        "expected underconstrained_signals category in payload"
    );
    assert!(
        payload["audit_report"]["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .any(|finding| {
                finding["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("nonlinear anchoring"))
            }),
        "expected nonlinear anchoring finding in audit payload"
    );
    assert!(
        payload["underconstraint_analysis"]["linear_nullity"]
            .as_u64()
            .expect("linear_nullity")
            > 0
    );
    assert!(
        !proof_path.exists(),
        "audit failure should prevent proof artifact creation"
    );
}
