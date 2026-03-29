use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use zkf_core::{FieldElement, FieldId, check_constraints};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};

#[test]
fn circom_r1cs_json_imports_to_ir_program() {
    let engine = frontend_for(FrontendKind::Circom);
    let value = json!({
        "name": "circom_demo",
        "nVars": 4,
        "nOutputs": 1,
        "nPubInputs": 1,
        "constraints": [
            [
                { "1": "1", "2": "1" },
                { "0": "1" },
                { "3": "1" }
            ]
        ]
    });

    let program = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect("circom import should succeed");
    assert_eq!(program.name, "circom_demo");
    assert_eq!(program.field, FieldId::Bn254);
    assert_eq!(program.constraints.len(), 1);
    assert_eq!(program.signals.len(), 4);
    assert_eq!(program.signals[0].name, "w0");
    assert_eq!(program.signals[0].constant, Some(FieldElement::from_i64(1)));
}

#[test]
fn circom_r1cs_program_accepts_valid_witness() {
    let engine = frontend_for(FrontendKind::Circom);
    let value = json!({
        "nVars": 4,
        "nOutputs": 1,
        "nPubInputs": 1,
        "constraints": [
            [
                { "1": "1", "2": "1" },
                { "0": "1" },
                { "3": "1" }
            ]
        ]
    });
    let program = engine
        .compile_to_ir(&value, &FrontendImportOptions::default())
        .expect("circom import should succeed");

    let witness = zkf_core::Witness {
        values: BTreeMap::from([
            ("w1".to_string(), FieldElement::new("7")),
            ("w2".to_string(), FieldElement::new("5")),
            ("w3".to_string(), FieldElement::new("12")),
        ]),
    };
    check_constraints(&program, &witness).expect("witness should satisfy imported R1CS");
}

#[test]
fn parse_frontend_kind_accepts_circom_aliases() {
    assert_eq!(
        "circom".parse::<FrontendKind>().expect("circom kind"),
        FrontendKind::Circom
    );
    assert_eq!(
        "r1cs".parse::<FrontendKind>().expect("r1cs alias"),
        FrontendKind::Circom
    );
    assert_eq!(
        "snarkjs-r1cs"
            .parse::<FrontendKind>()
            .expect("snarkjs alias"),
        FrontendKind::Circom
    );
}

#[test]
fn circom_execute_reads_witness_values_descriptor() {
    let engine = frontend_for(FrontendKind::Circom);
    let witness = engine
        .execute(
            &json!({
                "witness_values": {
                    "w1": "5",
                    "w2": 9
                }
            }),
            &Default::default(),
        )
        .expect("circom execute from witness_values should pass");
    assert_eq!(witness.values["w1"], FieldElement::new("5"));
    assert_eq!(witness.values["w2"], FieldElement::new("9"));
}

#[test]
fn circom_execute_runs_witness_command_and_loads_file() {
    let root = std::env::temp_dir().join(format!(
        "zkf-circom-exec-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create temp dir");
    let witness_path = root.join("witness.json");
    let command = format!(
        "printf '%s' '{{\"values\":{{\"w1\":\"11\"}}}}' > '{}'",
        witness_path.display()
    );

    let engine = frontend_for(FrontendKind::Circom);
    let witness = engine
        .execute(
            &json!({
                "witness_command": command,
                "witness_path": witness_path.display().to_string()
            }),
            &Default::default(),
        )
        .expect("circom execute command path should pass");
    assert_eq!(witness.values["w1"], FieldElement::new("11"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn circom_execute_witness_runner_command_loads_snarkjs_array_json() {
    let root = std::env::temp_dir().join(format!(
        "zkf-circom-runner-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create temp dir");
    let witness_path = root.join("witness.json");
    let command = format!(
        "printf '%s' '[\"1\",\"9\",\"13\"]' > '{}'",
        witness_path.display()
    );

    let engine = frontend_for(FrontendKind::Circom);
    let witness = engine
        .execute(
            &json!({
                "witness_runner": {
                    "kind": "command",
                    "command": command,
                    "witness_path": witness_path.display().to_string()
                }
            }),
            &Default::default(),
        )
        .expect("circom witness_runner command path should pass");
    assert_eq!(witness.values["w0"], FieldElement::new("1"));
    assert_eq!(witness.values["w1"], FieldElement::new("9"));
    assert_eq!(witness.values["w2"], FieldElement::new("13"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn circom_execute_reads_snarkjs_array_from_witness_path() {
    let root = std::env::temp_dir().join(format!(
        "zkf-circom-array-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("create temp dir");
    let witness_path = root.join("witness.json");
    fs::write(&witness_path, "[\"1\",\"5\",\"8\"]").expect("write witness");

    let engine = frontend_for(FrontendKind::Circom);
    let witness = engine
        .execute(
            &json!({
                "witness_path": witness_path.display().to_string()
            }),
            &Default::default(),
        )
        .expect("circom witness array parse should pass");
    assert_eq!(witness.values["w0"], FieldElement::new("1"));
    assert_eq!(witness.values["w1"], FieldElement::new("5"));
    assert_eq!(witness.values["w2"], FieldElement::new("8"));

    let _ = fs::remove_dir_all(root);
}
