use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe,
};
use num_bigint::BigInt;
use num_traits::Zero;
use serde_json::{Map as JsonMap, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, ToolRequirement, Visibility, Witness,
    WitnessInputs, WitnessPlan, ZkfError, ZkfResult,
};

pub struct CircomFrontend;

impl FrontendEngine for CircomFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Circom
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Circom,
            can_compile_to_ir: true,
            can_execute: true,
            input_formats: vec![
                "circom-r1cs-json".to_string(),
                "zkf-program-json".to_string(),
                "frontend-descriptor-json".to_string(),
            ],
            notes: "Circom frontend supports snarkjs-style R1CS JSON import (`constraints`, `nVars`) and descriptor/direct Program passthrough; execution supports native witness-runner descriptors (`witness_runner.kind=snarkjs`) plus command hooks and descriptor witness loading."
                .to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let has_descriptor = value.get("program").is_some()
            || value.get("ir_program").is_some()
            || value.get("compiled_ir_path").is_some();
        let has_r1cs = r1cs_constraints_value(value).is_some()
            && extract_u32(value, &["nVars", "n_vars", "num_vars"]).is_some();
        let accepted = has_descriptor || has_r1cs;

        FrontendProbe {
            accepted,
            format: if has_r1cs {
                Some("circom-r1cs-json".to_string())
            } else if has_descriptor {
                Some("frontend-descriptor-json".to_string())
            } else {
                None
            },
            noir_version: None,
            notes: if accepted {
                vec![]
            } else {
                vec![
                    "expected Circom/snarkjs R1CS JSON (`constraints` + `nVars`) or descriptor with `program`/`ir_program`/`compiled_ir_path`".to_string(),
                ]
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        if let Some(program) = load_program_from_descriptor(value)? {
            return apply_import_overrides(program, options);
        }
        let program = parse_r1cs_json(value, options)?;
        Ok(program)
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let program = self.compile_to_ir(value, &FrontendImportOptions::default())?;
        let mut opcode_counts = BTreeMap::new();
        opcode_counts.insert("r1cs_constraint".to_string(), program.constraints.len());

        Ok(FrontendInspection {
            frontend: FrontendKind::Circom,
            format: probe.format,
            version: None,
            functions: 1,
            unconstrained_functions: 0,
            opcode_counts,
            blackbox_counts: BTreeMap::new(),
            required_capabilities: vec!["r1cs".to_string(), "assert-zero".to_string()],
            dropped_features: Vec::new(),
            requires_hints: false,
        })
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "circom".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Circom compiler CLI".to_string()),
                required: false,
            },
            ToolRequirement {
                tool: "snarkjs".to_string(),
                args: vec!["--version".to_string()],
                note: Some(
                    "snarkjs tooling for exporting R1CS JSON / witness generation".to_string(),
                ),
                required: false,
            },
        ]
    }

    fn execute(&self, value: &Value, inputs: &WitnessInputs) -> ZkfResult<Witness> {
        if let Some(runner_witness) = execute_witness_runner(value, inputs)? {
            return Ok(runner_witness);
        }
        if let Some(command) = value.get("witness_command").and_then(Value::as_str) {
            run_shell_command(command, "frontend/circom/execute")?;
        }
        load_witness_from_descriptor(value)
    }
}

fn parse_r1cs_json(value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
    let constraints_value = r1cs_constraints_value(value).ok_or_else(|| {
        ZkfError::InvalidArtifact(
            "circom frontend expects `constraints` array in R1CS JSON input".to_string(),
        )
    })?;
    let constraints_array = constraints_value.as_array().ok_or_else(|| {
        ZkfError::InvalidArtifact("`constraints` must be an array of R1CS constraints".to_string())
    })?;

    let n_vars = extract_u32(value, &["nVars", "n_vars", "num_vars"]).ok_or_else(|| {
        ZkfError::InvalidArtifact("missing `nVars`/`n_vars` in R1CS JSON".to_string())
    })?;
    if n_vars == 0 {
        return Err(ZkfError::InvalidArtifact(
            "R1CS JSON declares nVars=0".to_string(),
        ));
    }

    let n_outputs = extract_u32(value, &["nOutputs", "n_outputs"]).unwrap_or(0);
    let n_pub_inputs = extract_u32(value, &["nPubInputs", "n_pub_inputs"]).unwrap_or(0);
    let public_limit = n_outputs.saturating_add(n_pub_inputs).saturating_add(1);

    let field = options
        .field
        .or_else(|| infer_field_from_prime(value))
        .unwrap_or(FieldId::Bn254);

    let mut constraints = Vec::with_capacity(constraints_array.len());
    for (index, entry) in constraints_array.iter().enumerate() {
        let (a_raw, b_raw, c_raw) = parse_constraint_triple(entry, index)?;
        let a_expr = linear_combination_to_expr(parse_linear_combination(a_raw, field)?);
        let b_expr = linear_combination_to_expr(parse_linear_combination(b_raw, field)?);
        let c_expr = linear_combination_to_expr(parse_linear_combination(c_raw, field)?);
        constraints.push(Constraint::Equal {
            lhs: Expr::Mul(Box::new(a_expr), Box::new(b_expr)),
            rhs: c_expr,
            label: Some(format!("circom_r1cs_{index}")),
        });
    }

    let mut signals = Vec::with_capacity(n_vars as usize);
    for index in 0..n_vars {
        let name = format!("w{index}");
        let (visibility, constant) = if index == 0 {
            (Visibility::Constant, Some(FieldElement::from_i64(1)))
        } else if index <= public_limit {
            (Visibility::Public, None)
        } else {
            (Visibility::Private, None)
        };
        signals.push(Signal {
            name,
            visibility,
            constant,
            ty: None,
        });
    }

    let mut program = Program {
        name: options
            .program_name
            .clone()
            .or_else(|| {
                value
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| "circom_import".to_string()),
        field,
        signals,
        constraints,
        witness_plan: WitnessPlan::default(),
        ..Default::default()
    };
    if let Some(name) = options.program_name.as_ref() {
        program.name = name.clone();
    }
    if let Some(field) = options.field {
        program.field = field;
    }
    Ok(program)
}

fn parse_constraint_triple(value: &Value, index: usize) -> ZkfResult<(&Value, &Value, &Value)> {
    if let Some(items) = value.as_array()
        && items.len() == 3
    {
        return Ok((&items[0], &items[1], &items[2]));
    }
    if let Some(map) = value.as_object() {
        if let (Some(a), Some(b), Some(c)) = (map.get("A"), map.get("B"), map.get("C")) {
            return Ok((a, b, c));
        }
        if let (Some(a), Some(b), Some(c)) = (map.get("a"), map.get("b"), map.get("c")) {
            return Ok((a, b, c));
        }
    }

    Err(ZkfError::InvalidArtifact(format!(
        "invalid R1CS constraint at index {index}; expected [A,B,C] or {{A,B,C}}"
    )))
}

fn parse_linear_combination(value: &Value, field: FieldId) -> ZkfResult<Vec<(u32, FieldElement)>> {
    let mut terms = BTreeMap::<u32, BigInt>::new();
    let mut seen = BTreeSet::new();

    match value {
        Value::Object(map) => {
            for (wire, coeff) in map {
                let index = wire.parse::<u32>().map_err(|_| {
                    ZkfError::InvalidArtifact(format!(
                        "R1CS linear-combination key '{wire}' is not a valid witness index"
                    ))
                })?;
                let coeff = parse_bigint(coeff, "R1CS object coefficient")?;
                *terms.entry(index).or_insert_with(BigInt::zero) += coeff;
                seen.insert(index);
            }
        }
        Value::Array(entries) => {
            for (term_index, entry) in entries.iter().enumerate() {
                let (index, coeff) = parse_lc_term(entry, term_index)?;
                *terms.entry(index).or_insert_with(BigInt::zero) += coeff;
                seen.insert(index);
            }
        }
        _ => {
            return Err(ZkfError::InvalidArtifact(
                "R1CS linear combination must be object or array".to_string(),
            ));
        }
    }

    let mut out = Vec::new();
    for index in seen {
        let coeff = terms.remove(&index).unwrap_or_else(BigInt::zero);
        if coeff.is_zero() {
            continue;
        }
        out.push((index, FieldElement::from_bigint_with_field(coeff, field)));
    }
    Ok(out)
}

fn parse_lc_term(value: &Value, term_index: usize) -> ZkfResult<(u32, BigInt)> {
    if let Some(items) = value.as_array()
        && items.len() == 2
    {
        let index = parse_u32_value(&items[0], "R1CS term witness index")?;
        let coeff = parse_bigint(&items[1], "R1CS term coefficient")?;
        return Ok((index, coeff));
    }
    if let Some(map) = value.as_object() {
        let index = map
            .get("index")
            .or_else(|| map.get("var"))
            .or_else(|| map.get("wire"))
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "R1CS term {term_index} is missing index/var/wire field"
                ))
            })
            .and_then(|raw| parse_u32_value(raw, "R1CS term witness index"))?;
        let coeff = map
            .get("value")
            .or_else(|| map.get("coeff"))
            .or_else(|| map.get("coefficient"))
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "R1CS term {term_index} is missing value/coeff/coefficient field"
                ))
            })
            .and_then(|raw| parse_bigint(raw, "R1CS term coefficient"))?;
        return Ok((index, coeff));
    }
    Err(ZkfError::InvalidArtifact(format!(
        "invalid R1CS linear-combination term at index {term_index}"
    )))
}

fn linear_combination_to_expr(terms: Vec<(u32, FieldElement)>) -> Expr {
    if terms.is_empty() {
        return Expr::Const(FieldElement::from_i64(0));
    }

    let mut expr_terms = Vec::with_capacity(terms.len());
    for (index, coeff) in terms {
        let term = if index == 0 {
            Expr::Const(coeff.clone())
        } else {
            let signal = Expr::Signal(format!("w{index}"));
            if coeff.is_one() {
                signal
            } else {
                Expr::Mul(Box::new(Expr::Const(coeff)), Box::new(signal))
            }
        };
        expr_terms.push(term);
    }
    if expr_terms.len() == 1 {
        expr_terms
            .into_iter()
            .next()
            .unwrap_or_else(|| Expr::Const(FieldElement::from_i64(0)))
    } else {
        Expr::Add(expr_terms)
    }
}

fn load_program_from_descriptor(value: &Value) -> ZkfResult<Option<Program>> {
    if let Some(program_value) = value.get("program").or(value.get("ir_program")) {
        let program = serde_json::from_value(program_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize embedded program: {err}"))
        })?;
        return Ok(Some(program));
    }

    if let Some(path) = value.get("compiled_ir_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        let content = fs::read_to_string(&path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading compiled_ir_path '{}': {err}",
                path.display()
            ))
        })?;
        let program = serde_json::from_str::<Program>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize program from '{}': {err}",
                path.display()
            ))
        })?;
        return Ok(Some(program));
    }

    if let Ok(program) = serde_json::from_value::<Program>(value.clone()) {
        return Ok(Some(program));
    }

    Ok(None)
}

fn load_witness_from_descriptor(value: &Value) -> ZkfResult<Witness> {
    if let Some(witness_value) = value.get("witness") {
        return parse_witness_value_flexible(witness_value, "embedded circom witness");
    }

    if let Some(path) = value.get("witness_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        return load_witness_from_path_flexible(&path);
    }

    if let Some(values) = value.get("witness_values").and_then(Value::as_object) {
        let mut mapped = BTreeMap::new();
        for (name, raw) in values {
            let rendered = match raw {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                other => {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "witness_values['{}'] must be string/number, found {}",
                        name, other
                    )));
                }
            };
            mapped.insert(name.clone(), FieldElement::new(rendered));
        }
        return Ok(Witness { values: mapped });
    }

    Err(ZkfError::UnsupportedBackend {
        backend: "frontend/circom/execute".to_string(),
        message: "descriptor missing `witness`, `witness_path`, or `witness_values`".to_string(),
    })
}

fn execute_witness_runner(value: &Value, inputs: &WitnessInputs) -> ZkfResult<Option<Witness>> {
    let Some(runner_value) = value.get("witness_runner") else {
        return Ok(None);
    };
    let runner = runner_value.as_object().ok_or_else(|| {
        ZkfError::InvalidArtifact("`witness_runner` must be a JSON object".to_string())
    })?;
    let kind = runner
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("snarkjs");
    match kind {
        "snarkjs" => execute_snarkjs_runner(runner, inputs).map(Some),
        "command" => execute_command_runner(runner).map(Some),
        other => Err(ZkfError::UnsupportedBackend {
            backend: "frontend/circom/witness-runner".to_string(),
            message: format!("unsupported circom witness_runner.kind '{other}'"),
        }),
    }
}

fn execute_command_runner(runner: &JsonMap<String, Value>) -> ZkfResult<Witness> {
    let command = runner
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("witness_runner(kind=command) requires `command`".to_string())
        })?;
    run_shell_command(command, "frontend/circom/witness-runner/command")?;
    let witness_path = runner
        .get("witness_path")
        .or_else(|| runner.get("witness_json_path"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "witness_runner(kind=command) requires `witness_path` or `witness_json_path`"
                    .to_string(),
            )
        })?;
    load_witness_from_path_flexible(&PathBuf::from(witness_path))
}

fn execute_snarkjs_runner(
    runner: &JsonMap<String, Value>,
    inputs: &WitnessInputs,
) -> ZkfResult<Witness> {
    let snarkjs_bin = runner
        .get("snarkjs_bin")
        .and_then(Value::as_str)
        .unwrap_or("snarkjs");
    let wasm_path = runner
        .get("wasm_path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "witness_runner(kind=snarkjs) requires `wasm_path`".to_string(),
            )
        })?;
    let input_path = match runner.get("input_path").and_then(Value::as_str) {
        Some(path) => PathBuf::from(path),
        None => write_temp_inputs_json(inputs)?,
    };
    let wtns_path = runner
        .get("wtns_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| unique_temp_path("circom-witness", "wtns"));
    let witness_json_path = runner
        .get("witness_json_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| unique_temp_path("circom-witness", "json"));

    let status = Command::new(snarkjs_bin)
        .arg("wtns")
        .arg("calculate")
        .arg(wasm_path)
        .arg(&input_path)
        .arg(&wtns_path)
        .status()
        .map_err(|err| {
            ZkfError::Io(format!(
                "frontend/circom/witness-runner/snarkjs: failed running witness calculation: {err}"
            ))
        })?;
    if !status.success() {
        return Err(ZkfError::Backend(format!(
            "frontend/circom/witness-runner/snarkjs: `{} wtns calculate` failed with status {status}",
            snarkjs_bin
        )));
    }

    let export_status = Command::new(snarkjs_bin)
        .arg("wtns")
        .arg("export")
        .arg("json")
        .arg(&wtns_path)
        .arg(&witness_json_path)
        .status()
        .map_err(|err| {
            ZkfError::Io(format!(
                "frontend/circom/witness-runner/snarkjs: failed exporting witness json: {err}"
            ))
        })?;
    if !export_status.success() {
        return Err(ZkfError::Backend(format!(
            "frontend/circom/witness-runner/snarkjs: `{} wtns export json` failed with status {export_status}",
            snarkjs_bin
        )));
    }

    load_witness_from_path_flexible(&witness_json_path)
}

fn write_temp_inputs_json(inputs: &WitnessInputs) -> ZkfResult<PathBuf> {
    if inputs.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "witness_runner(kind=snarkjs) requires `input_path` or non-empty `--inputs`"
                .to_string(),
        ));
    }
    let path = unique_temp_path("circom-inputs", "json");
    let mut obj = JsonMap::new();
    for (key, value) in inputs {
        obj.insert(key.clone(), Value::String(value.to_decimal_string()));
    }
    let rendered = serde_json::to_string_pretty(&Value::Object(obj))
        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
    fs::write(&path, rendered).map_err(|err| {
        ZkfError::Io(format!(
            "failed writing temporary input file '{}': {err}",
            path.display()
        ))
    })?;
    Ok(path)
}

fn unique_temp_path(prefix: &str, ext: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{nonce}.{ext}"))
}

fn load_witness_from_path_flexible(path: &Path) -> ZkfResult<Witness> {
    let content = fs::read_to_string(path).map_err(|err| {
        ZkfError::Io(format!(
            "failed reading witness '{}': {err}",
            path.display()
        ))
    })?;
    let value: Value = serde_json::from_str(&content).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed parsing witness JSON from '{}': {err}",
            path.display()
        ))
    })?;
    parse_witness_value_flexible(&value, &format!("witness '{}'", path.display()))
}

fn parse_witness_value_flexible(value: &Value, context: &str) -> ZkfResult<Witness> {
    if let Ok(witness) = serde_json::from_value::<Witness>(value.clone()) {
        return Ok(witness);
    }
    if let Some(array) = value.as_array() {
        return witness_from_snarkjs_array(array);
    }
    if let Some(obj) = value.as_object()
        && let Some(witness_array) = obj.get("witness").and_then(Value::as_array)
    {
        return witness_from_snarkjs_array(witness_array);
    }
    Err(ZkfError::InvalidArtifact(format!(
        "failed to deserialize {context}: expected Witness object or snarkjs witness array"
    )))
}

fn witness_from_snarkjs_array(array: &[Value]) -> ZkfResult<Witness> {
    let mut values = BTreeMap::new();
    for (index, raw) in array.iter().enumerate() {
        let rendered = match raw {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Object(obj) if obj.get("value").is_some() => obj
                .get("value")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    obj.get("value")
                        .and_then(Value::as_u64)
                        .map(|v| v.to_string())
                })
                .ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "snarkjs witness entry {index} object `value` must be string/number"
                    ))
                })?,
            other => {
                return Err(ZkfError::InvalidArtifact(format!(
                    "snarkjs witness entry {index} must be string/number/object-with-value, found {other}"
                )));
            }
        };
        values.insert(format!("w{index}"), FieldElement::new(rendered));
    }
    Ok(Witness { values })
}

fn apply_import_overrides(
    mut program: Program,
    options: &FrontendImportOptions,
) -> ZkfResult<Program> {
    if let Some(name) = options.program_name.as_ref() {
        program.name = name.clone();
    }
    if let Some(field) = options.field {
        program.field = field;
    }
    Ok(program)
}

fn run_shell_command(command: &str, context: &str) -> ZkfResult<()> {
    let status = Command::new("sh")
        .arg("-lc")
        .arg(command)
        .status()
        .map_err(|err| ZkfError::Io(format!("{context}: failed to spawn command: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ZkfError::Backend(format!(
            "{context}: command exited with status {status}"
        )))
    }
}

fn parse_u32_value(value: &Value, context: &str) -> ZkfResult<u32> {
    match value {
        Value::Number(num) => num
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!("{context} must be a non-negative u32 number"))
            }),
        Value::String(text) => text.parse::<u32>().map_err(|_| {
            ZkfError::InvalidArtifact(format!("{context} '{text}' is not a valid u32"))
        }),
        _ => Err(ZkfError::InvalidArtifact(format!(
            "{context} must be a string/number"
        ))),
    }
}

fn parse_bigint(value: &Value, context: &str) -> ZkfResult<BigInt> {
    match value {
        Value::Number(number) => BigInt::parse_bytes(number.to_string().as_bytes(), 10)
            .ok_or_else(|| ZkfError::InvalidArtifact(format!("{context} is not a valid integer"))),
        Value::String(text) => BigInt::parse_bytes(text.as_bytes(), 10).ok_or_else(|| {
            ZkfError::InvalidArtifact(format!("{context} '{text}' is not a valid integer"))
        }),
        _ => Err(ZkfError::InvalidArtifact(format!(
            "{context} must be string/number"
        ))),
    }
}

fn infer_field_from_prime(value: &Value) -> Option<FieldId> {
    let prime = value
        .get("prime")
        .or_else(|| value.get("field_prime"))
        .and_then(Value::as_str)?;
    match prime {
        "21888242871839275222246405745257275088548364400416034343698204186575808495617" => {
            Some(FieldId::Bn254)
        }
        "52435875175126190479447740508185965837690552500527637822603658699938581184512" => {
            Some(FieldId::Bls12_381)
        }
        _ => None,
    }
}

fn extract_u32(value: &Value, keys: &[&str]) -> Option<u32> {
    for key in keys {
        if let Some(found) = value.get(*key)
            && let Ok(parsed) = parse_u32_value(found, key)
        {
            return Some(parsed);
        }
    }
    None
}

fn r1cs_constraints_value(value: &Value) -> Option<&Value> {
    if let Some(constraints) = value.get("constraints") {
        return Some(constraints);
    }
    if let Some(r1cs) = value.get("r1cs").and_then(Value::as_object) {
        return r1cs.get("constraints");
    }
    if let Some(circuit) = value.get("circuit").and_then(Value::as_object) {
        return circuit.get("constraints");
    }
    if let Some(map) = value.as_object() {
        return map
            .get("constraints")
            .or_else(|| map.get("Constraints"))
            .or_else(|| map.get("CONSTRAINTS"));
    }
    None
}
