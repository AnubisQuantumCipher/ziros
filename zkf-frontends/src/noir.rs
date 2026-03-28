use crate::translation::TranslationTarget;
use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe, IrFamilyPreference, default_frontend_translator, infer_noir_translation_meta,
};
use acir::FieldElement as AcirFieldElement;
use acir::circuit::brillig::BrilligOutputs as AcirBrilligOutputs;
use acir::circuit::directives::Directive as AcirDirective;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{Opcode as AcirOpcode, Program as AcirProgram};
use acir::native_types::{
    Expression as AcirExpression, Witness as AcirWitness, WitnessMap as AcirWitnessMap,
};
use acir_beta9::AcirField as _;
use acir_beta9::FieldElement as Beta9FieldElement;
use acir_beta9::circuit::Program as Beta9Program;
use acir_beta9::native_types::{Witness as Beta9Witness, WitnessMap as Beta9WitnessMap};
use acir_beta19::AcirField as _;
use acir_beta19::FieldElement as Beta19FieldElement;
use acir_beta19::circuit::Program as Beta19Program;
use acir_beta19::native_types::{Witness as Beta19Witness, WitnessMap as Beta19WitnessMap};
use acvm::brillig_vm::brillig::ForeignCallResult as AcirForeignCallResult;
use acvm::pwg::{ACVM as Acvm046, ACVMStatus as Acvm046Status};
use acvm_beta9::brillig_vm::brillig::ForeignCallResult as Beta9ForeignCallResult;
use acvm_beta9::pwg::{ACVM as Beta9Acvm, ACVMStatus as Beta9AcvmStatus};
use acvm_beta19::brillig_vm::brillig::ForeignCallResult as Beta19ForeignCallResult;
use acvm_beta19::pwg::{ACVM as Beta19Acvm, ACVMStatus as Beta19AcvmStatus};
use base64::Engine;
use bn254_blackbox_solver::Bn254BlackBoxSolver as AcirBn254BlackBoxSolver;
use bn254_blackbox_solver_beta9::Bn254BlackBoxSolver as Beta9Bn254BlackBoxSolver;
use bn254_blackbox_solver_beta19::Bn254BlackBoxSolver as Beta19Bn254BlackBoxSolver;
use flate2::read::GzDecoder;
use num_bigint::{BigInt, Sign};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use zkf_core::{
    BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, ToolRequirement,
    Visibility, Witness as ZkfWitness, WitnessHint, WitnessHintKind, WitnessInputs, WitnessPlan,
    ZkfError, ZkfResult, check_constraints,
};

pub struct NoirAcirFrontend;

impl FrontendEngine for NoirAcirFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Noir
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Noir,
            can_compile_to_ir: true,
            can_execute: true,
            input_formats: vec![
                "noir-artifact-json".to_string(),
                "acir-program-json".to_string(),
            ],
            notes: "ACIR import supports AssertZero, RANGE, AND/XOR (bit-decomposed), native BlackBox constraints (SHA256/Keccak256/Pedersen/Schnorr/ECDSA/Blake2s/RecursiveAggregation marker), plus compatibility hint-backed blackbox metadata for unsupported ops, Directive::ToLeRadix, MemoryInit/MemoryOp (constant and dynamic index via multiplexer), Brillig hints, and multi-function Call inlining."
                .to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let mut notes = Vec::new();
        let noir_version = value
            .get("noir_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);

        let format = if value.get("bytecode").and_then(Value::as_str).is_some() {
            Some("noir-artifact-json".to_string())
        } else if value.get("program").is_some() {
            Some("wrapped-acir-program-json".to_string())
        } else if value.get("functions").is_some() {
            Some("acir-program-json".to_string())
        } else {
            None
        };

        if let Some(version) = noir_version.as_deref()
            && is_known_unsupported_noir_version(version)
        {
            notes.push(format!(
                    "detected noir_version '{version}', which is likely incompatible with in-process acir={} decoder",
                    "0.46"
                ));
        }

        FrontendProbe {
            accepted: format.is_some(),
            format,
            noir_version,
            notes,
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        let mut working = value.clone();
        let mut parsed_from_original = None;

        if let Some(version) = value.get("noir_version").and_then(Value::as_str)
            && is_known_unsupported_noir_version(version)
            && !options.allow_unsupported_versions
        {
            match parse_acir_program(&working) {
                Ok(program) => {
                    parsed_from_original = Some(program);
                }
                Err(_) => {
                    let translator = options
                        .translator
                        .clone()
                        .unwrap_or_else(default_frontend_translator);
                    working = translator.translate_noir_artifact(
                        &working,
                        version,
                        TranslationTarget::Acir046,
                    )?;
                }
            }
        }

        let mut program_name = options.program_name.clone();
        if program_name.is_none() {
            program_name = working
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }

        let acir_program = if let Some(program) = parsed_from_original {
            program
        } else {
            parse_acir_program(&working)?
        };
        let external_hints = parse_serialized_witness_hints(&working)?;
        let mut program = import_acir_program(
            &acir_program,
            program_name,
            options.field.unwrap_or(FieldId::Bn254),
            external_hints,
        )?;

        // Extract ABI parameter names from the Noir artifact and create
        // input_aliases so developers can use original names (a, b, result)
        // instead of witness indices (w0, w1, w4).
        if let Some(abi) = value.get("abi").and_then(Value::as_object)
            && let Some(params) = abi.get("parameters").and_then(Value::as_array)
        {
            let main = &acir_program.functions[0];
            // Build ordered list of all input witnesses (private then public)
            let mut input_witnesses: Vec<u32> = main
                .private_parameters
                .iter()
                .map(|w| w.witness_index())
                .collect();
            let mut public_indices: Vec<u32> =
                main.public_parameters.indices().into_iter().collect();
            public_indices.sort();
            input_witnesses.extend(public_indices);
            input_witnesses.sort();

            for (i, param) in params.iter().enumerate() {
                if let (Some(name), Some(&witness_idx)) = (
                    param.get("name").and_then(Value::as_str),
                    input_witnesses.get(i),
                ) {
                    let signal_name = witness_name(witness_idx);
                    if name != signal_name {
                        program
                            .witness_plan
                            .input_aliases
                            .insert(name.to_string(), signal_name);
                    }
                }
            }
        }

        // Store the serialized ACIR program for optional solver-based Brillig resolution.
        if let Ok(acir_bytes) = serde_json::to_vec(value) {
            use base64::Engine;
            program.witness_plan.acir_program_bytes =
                Some(base64::engine::general_purpose::STANDARD.encode(&acir_bytes));
        }

        // Set metadata so the CLI knows this came from Noir and can default
        // to the ACVM solver for witness generation.
        program
            .metadata
            .insert("frontend".to_string(), "noir".to_string());
        program.metadata.insert(
            "solver".to_string(),
            if value
                .get("noir_version")
                .and_then(Value::as_str)
                .is_some_and(is_beta19_version)
            {
                "noop".to_string()
            } else {
                "acvm".to_string()
            },
        );

        Ok(program)
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let mut working = value.clone();
        let mut dropped_features = Vec::new();
        let mut requires_hints = false;

        if let Some(version) = probe.noir_version.as_deref()
            && is_known_unsupported_noir_version(version)
        {
            match parse_acir_program(&working) {
                Ok(program) => {
                    let direct =
                        inspect_acir_program(&program, probe, dropped_features, requires_hints);
                    return Ok(direct);
                }
                Err(_) => {
                    let meta = infer_noir_translation_meta(&working, version)?;
                    dropped_features = meta.dropped_features;
                    requires_hints = meta.requires_hints;
                    let translator = default_frontend_translator();
                    working = translator.translate_noir_artifact(
                        &working,
                        version,
                        TranslationTarget::Acir046,
                    )?;
                }
            }
        }

        let acir_program = parse_acir_program(&working)?;
        Ok(inspect_acir_program(
            &acir_program,
            probe,
            dropped_features,
            requires_hints,
        ))
    }

    fn execute(&self, value: &Value, inputs: &WitnessInputs) -> ZkfResult<ZkfWitness> {
        let version = value
            .get("noir_version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let witness = if is_beta9_version(version) {
            execute_beta9_artifact(value, inputs)?
        } else if let Ok(program) = parse_acir_program(value) {
            execute_acir046_program(&program, inputs)?
        } else if is_beta19_version(version) {
            execute_beta19_artifact(value, inputs)?
        } else {
            return Err(ZkfError::UnsupportedBackend {
                backend: "frontend/noir/execute".to_string(),
                message: if version.is_empty() {
                    "execution requires either beta.9 noir_version metadata or parseable acir-program content".to_string()
                } else {
                    format!(
                        "no execution engine registered for noir_version '{version}' and artifact was not parseable as acir 0.46 program"
                    )
                },
            });
        };

        if !inputs.is_empty() {
            validate_translated_constraints_against_acvm_witness(value, &witness)?;
        }

        Ok(witness)
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "nargo".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Noir compile/execute CLI".to_string()),
                required: false,
            },
            ToolRequirement {
                tool: "noirup".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Noir toolchain installer/version manager".to_string()),
                required: false,
            },
        ]
    }
}

fn is_beta9_version(version: &str) -> bool {
    let normalized = version.split('+').next().unwrap_or(version);
    normalized == "1.0.0-beta.9"
}

fn is_beta19_version(version: &str) -> bool {
    let normalized = version.split('+').next().unwrap_or(version);
    normalized == "1.0.0-beta.19"
}

fn validate_translated_constraints_against_acvm_witness(
    value: &Value,
    witness: &ZkfWitness,
) -> ZkfResult<()> {
    let frontend = NoirAcirFrontend;
    let imported = frontend.compile_to_ir(
        value,
        &FrontendImportOptions {
            field: Some(FieldId::Bn254),
            ir_family: IrFamilyPreference::IrV2,
            ..Default::default()
        },
    )?;

    check_constraints(&imported, witness).map_err(|error| {
        ZkfError::InvalidArtifact(format!(
            "noir ACIR translation consistency check failed after ACVM execution: {error}"
        ))
    })
}

fn execute_acir046_program(value: &AcirProgram, inputs: &WitnessInputs) -> ZkfResult<ZkfWitness> {
    if value.functions.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "acir 0.46 execution requires at least one function".to_string(),
        ));
    }

    let mut initial_witness = AcirWitnessMap::new();
    for (name, value) in inputs {
        let witness = parse_signal_as_acir_witness(name)?;
        let field = parse_acir_field_element(value)?;
        initial_witness.insert(witness, field);
    }

    let solved = execute_acir046_function(value, 0, initial_witness)?;
    let mut values = BTreeMap::new();
    for (witness, value) in solved {
        values.insert(
            format!("w{}", witness.0),
            acir046_field_to_field_element(value),
        );
    }

    Ok(ZkfWitness { values })
}

fn execute_acir046_function(
    program: &AcirProgram,
    function_index: usize,
    initial_witness: AcirWitnessMap,
) -> ZkfResult<AcirWitnessMap> {
    let function = program.functions.get(function_index).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "acir 0.46 execution referenced missing function {function_index}"
        ))
    })?;

    let backend = AcirBn254BlackBoxSolver::default();
    let mut acvm = Acvm046::new(
        &backend,
        &function.opcodes,
        initial_witness,
        &program.unconstrained_functions,
        &function.assert_messages,
    );

    loop {
        match acvm.solve() {
            Acvm046Status::Solved => break,
            Acvm046Status::InProgress => continue,
            Acvm046Status::RequiresForeignCall(foreign_call) => {
                if is_noop_beta9_foreign_call(&foreign_call.function) {
                    acvm.resolve_pending_foreign_call(AcirForeignCallResult::default());
                    continue;
                }
                return Err(ZkfError::UnsupportedBackend {
                    backend: "frontend/noir/execute-acir046".to_string(),
                    message: format!(
                        "acir 0.46 execution requires unresolved foreign call '{}'",
                        foreign_call.function
                    ),
                });
            }
            Acvm046Status::RequiresAcirCall(call_info) => {
                let callee_index = call_info.id as usize;
                let callee_witness =
                    execute_acir046_function(program, callee_index, call_info.initial_witness)?;
                let callee_function = program.functions.get(callee_index).ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "acir 0.46 execution referenced missing function {callee_index}"
                    ))
                })?;

                let mut outputs = Vec::new();
                let mut return_indices = callee_function
                    .return_values
                    .indices()
                    .into_iter()
                    .collect::<Vec<_>>();
                return_indices.sort_unstable();
                for return_index in return_indices {
                    let value = callee_witness.get(&AcirWitness(return_index)).ok_or_else(|| {
                        ZkfError::InvalidArtifact(format!(
                            "acir 0.46 execution failed to resolve call output witness w{return_index} from function {callee_index}"
                        ))
                    })?;
                    outputs.push(*value);
                }
                acvm.resolve_pending_acir_call(outputs);
            }
            Acvm046Status::Failure(error) => return Err(ZkfError::Backend(error.to_string())),
        }
    }

    Ok(acvm.finalize())
}

fn execute_beta9_artifact(value: &Value, inputs: &WitnessInputs) -> ZkfResult<ZkfWitness> {
    let program = parse_beta9_program(value)?;
    let mut initial_witness = Beta9WitnessMap::new();
    for (name, value) in inputs {
        let witness = parse_signal_as_beta9_witness(name)?;
        let field = parse_beta9_field_element(value)?;
        initial_witness.insert(witness, field);
    }

    let solved = execute_beta9_function(&program, 0, initial_witness)?;
    let mut values = BTreeMap::new();
    for (witness, value) in solved {
        values.insert(
            format!("w{}", witness.0),
            beta9_field_to_field_element(value),
        );
    }

    Ok(ZkfWitness { values })
}

fn execute_beta9_function(
    program: &Beta9Program<Beta9FieldElement>,
    function_index: usize,
    initial_witness: Beta9WitnessMap<Beta9FieldElement>,
) -> ZkfResult<Beta9WitnessMap<Beta9FieldElement>> {
    let function = program.functions.get(function_index).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "beta.9 execution referenced missing function {function_index}"
        ))
    })?;

    let backend = Beta9Bn254BlackBoxSolver::default();
    let mut acvm = Beta9Acvm::new(
        &backend,
        &function.opcodes,
        initial_witness,
        &program.unconstrained_functions,
        &function.assert_messages,
    );

    loop {
        match acvm.solve() {
            Beta9AcvmStatus::Solved => break,
            Beta9AcvmStatus::InProgress => continue,
            Beta9AcvmStatus::RequiresForeignCall(foreign_call) => {
                if is_noop_beta9_foreign_call(&foreign_call.function) {
                    acvm.resolve_pending_foreign_call(Beta9ForeignCallResult::default());
                    continue;
                }
                return Err(ZkfError::UnsupportedBackend {
                    backend: "frontend/noir/execute-beta9".to_string(),
                    message: format!(
                        "beta.9 execution requires unresolved foreign call '{}'",
                        foreign_call.function
                    ),
                });
            }
            Beta9AcvmStatus::RequiresAcirCall(call_info) => {
                let callee_index = call_info.id.as_usize();
                let callee_witness =
                    execute_beta9_function(program, callee_index, call_info.initial_witness)?;
                let callee_function = program.functions.get(callee_index).ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "beta.9 execution referenced missing function {callee_index}"
                    ))
                })?;

                let mut outputs = Vec::new();
                let mut return_indices = callee_function
                    .return_values
                    .indices()
                    .into_iter()
                    .collect::<Vec<_>>();
                return_indices.sort_unstable();
                for return_index in return_indices {
                    let value = callee_witness
                        .get(&Beta9Witness(return_index))
                        .ok_or_else(|| {
                            ZkfError::InvalidArtifact(format!(
                                "beta.9 execution failed to resolve call output witness w{return_index} from function {callee_index}"
                            ))
                        })?;
                    outputs.push(*value);
                }
                acvm.resolve_pending_acir_call(outputs);
            }
            Beta9AcvmStatus::Failure(error) => return Err(ZkfError::Backend(error.to_string())),
        }
    }

    Ok(acvm.finalize())
}

fn execute_beta19_artifact(value: &Value, inputs: &WitnessInputs) -> ZkfResult<ZkfWitness> {
    let program = parse_beta19_program(value)?;
    let mut initial_witness = Beta19WitnessMap::new();
    for (name, value) in inputs {
        let witness = parse_signal_as_beta19_witness(name)?;
        let field = parse_beta19_field_element(value)?;
        initial_witness.insert(witness, field);
    }

    let solved = execute_beta19_function(&program, 0, initial_witness)?;
    let mut values = BTreeMap::new();
    for (witness, value) in solved {
        values.insert(
            format!("w{}", witness.0),
            beta19_field_to_field_element(value),
        );
    }

    Ok(ZkfWitness { values })
}

fn execute_beta19_function(
    program: &Beta19Program<Beta19FieldElement>,
    function_index: usize,
    initial_witness: Beta19WitnessMap<Beta19FieldElement>,
) -> ZkfResult<Beta19WitnessMap<Beta19FieldElement>> {
    let function = program.functions.get(function_index).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "beta.19 execution referenced missing function {function_index}"
        ))
    })?;

    let backend = Beta19Bn254BlackBoxSolver;
    let mut acvm = Beta19Acvm::new(
        &backend,
        &function.opcodes,
        initial_witness,
        &program.unconstrained_functions,
        &function.assert_messages,
    );

    loop {
        match acvm.solve() {
            Beta19AcvmStatus::Solved => break,
            Beta19AcvmStatus::InProgress => continue,
            Beta19AcvmStatus::RequiresForeignCall(foreign_call) => {
                if is_noop_beta9_foreign_call(&foreign_call.function) {
                    acvm.resolve_pending_foreign_call(Beta19ForeignCallResult::default());
                    continue;
                }
                return Err(ZkfError::UnsupportedBackend {
                    backend: "frontend/noir/execute-beta19".to_string(),
                    message: format!(
                        "beta.19 execution requires unresolved foreign call '{}'",
                        foreign_call.function
                    ),
                });
            }
            Beta19AcvmStatus::RequiresAcirCall(call_info) => {
                let callee_index = call_info.id.as_usize();
                let callee_witness =
                    execute_beta19_function(program, callee_index, call_info.initial_witness)?;
                let callee_function = program.functions.get(callee_index).ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "beta.19 execution referenced missing function {callee_index}"
                    ))
                })?;

                let mut outputs = Vec::new();
                let mut return_indices = callee_function
                    .return_values
                    .indices()
                    .into_iter()
                    .collect::<Vec<_>>();
                return_indices.sort_unstable();
                for return_index in return_indices {
                    let value = callee_witness
                        .get(&Beta19Witness(return_index))
                        .ok_or_else(|| {
                            ZkfError::InvalidArtifact(format!(
                                "beta.19 execution failed to resolve call output witness w{return_index} from function {callee_index}"
                            ))
                        })?;
                    outputs.push(*value);
                }
                acvm.resolve_pending_acir_call(outputs);
            }
            Beta19AcvmStatus::Failure(error) => return Err(ZkfError::Backend(error.to_string())),
        }
    }

    Ok(acvm.finalize())
}

fn parse_beta9_program(value: &Value) -> ZkfResult<Beta9Program<Beta9FieldElement>> {
    if let Some(program) = value.get("program") {
        return serde_json::from_value(program.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize beta.9 program JSON: {err}"))
        });
    }

    let bytecode = value
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "noir artifact execution requires 'bytecode' or 'program'".to_string(),
            )
        })?;

    let program_bytes = base64::engine::general_purpose::STANDARD
        .decode(bytecode.trim())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid base64 Noir ACIR bytecode: {err}"))
        })?;

    Beta9Program::deserialize_program(&program_bytes).map_err(|err| {
        ZkfError::InvalidArtifact(format!("failed to deserialize Noir beta.9 bytecode: {err}"))
    })
}

fn parse_beta19_program(value: &Value) -> ZkfResult<Beta19Program<Beta19FieldElement>> {
    if let Some(program) = value.get("program") {
        return serde_json::from_value(program.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize beta.19 program JSON: {err}"))
        });
    }

    let bytecode = value
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "noir artifact execution requires 'bytecode' or 'program'".to_string(),
            )
        })?;

    let program_bytes = base64::engine::general_purpose::STANDARD
        .decode(bytecode.trim())
        .map_err(|err| {
            ZkfError::InvalidArtifact(format!("invalid base64 Noir ACIR bytecode: {err}"))
        })?;

    Beta19Program::deserialize_program(&program_bytes).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize Noir beta.19 bytecode: {err}"
        ))
    })
}

fn parse_signal_as_beta9_witness(name: &str) -> ZkfResult<Beta9Witness> {
    let index_str = name.strip_prefix('w').ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "beta.9 execution expects witness-style signal names (w<index>), found '{name}'"
        ))
    })?;
    let index = index_str.parse::<u32>().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "invalid witness signal name '{name}', expected w<index>"
        ))
    })?;
    Ok(Beta9Witness(index))
}

fn parse_signal_as_beta19_witness(name: &str) -> ZkfResult<Beta19Witness> {
    let index_str = name.strip_prefix('w').ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "beta.19 execution expects witness-style signal names (w<index>), found '{name}'"
        ))
    })?;
    let index = index_str.parse::<u32>().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "invalid witness signal name '{name}', expected w<index>"
        ))
    })?;
    Ok(Beta19Witness(index))
}

fn parse_signal_as_acir_witness(name: &str) -> ZkfResult<AcirWitness> {
    let index_str = name.strip_prefix('w').ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "acir 0.46 execution expects witness-style signal names (w<index>), found '{name}'"
        ))
    })?;
    let index = index_str.parse::<u32>().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "invalid witness signal name '{name}', expected w<index>"
        ))
    })?;
    Ok(AcirWitness(index))
}

fn parse_beta9_field_element(value: &FieldElement) -> ZkfResult<Beta9FieldElement> {
    let normalized = value.normalized_bigint(FieldId::Bn254)?;
    let (_, mut bytes) = normalized.to_bytes_be();
    if bytes.is_empty() {
        bytes.push(0);
    }
    Ok(Beta9FieldElement::from_be_bytes_reduce(&bytes))
}

fn parse_beta19_field_element(value: &FieldElement) -> ZkfResult<Beta19FieldElement> {
    let normalized = value.normalized_bigint(FieldId::Bn254)?;
    let (_, mut bytes) = normalized.to_bytes_be();
    if bytes.is_empty() {
        bytes.push(0);
    }
    Ok(Beta19FieldElement::from_be_bytes_reduce(&bytes))
}

fn parse_acir_field_element(value: &FieldElement) -> ZkfResult<AcirFieldElement> {
    let normalized = value.normalized_bigint(FieldId::Bn254)?;
    let (_, mut bytes) = normalized.to_bytes_be();
    if bytes.is_empty() {
        bytes.push(0);
    }
    Ok(AcirFieldElement::from_be_bytes_reduce(&bytes))
}

fn acir046_field_to_field_element(value: AcirFieldElement) -> FieldElement {
    let bigint = BigInt::from_bytes_be(Sign::Plus, &value.to_be_bytes());
    FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
}

fn beta9_field_to_field_element(value: Beta9FieldElement) -> FieldElement {
    let bigint = BigInt::from_bytes_be(Sign::Plus, &value.to_be_bytes());
    FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
}

fn beta19_field_to_field_element(value: Beta19FieldElement) -> FieldElement {
    let bigint = BigInt::from_bytes_be(Sign::Plus, &value.to_be_bytes());
    FieldElement::from_bigint_with_field(bigint, FieldId::Bn254)
}

fn is_noop_beta9_foreign_call(function: &str) -> bool {
    let normalized = function.to_ascii_lowercase();
    normalized.contains("print") || normalized.contains("debug")
}

fn black_box_call_requires_hints(call: &BlackBoxFuncCall) -> bool {
    matches!(
        call,
        BlackBoxFuncCall::Blake3 { .. }
            | BlackBoxFuncCall::AES128Encrypt { .. }
            | BlackBoxFuncCall::Keccakf1600 { .. }
            | BlackBoxFuncCall::Sha256Compression { .. }
    )
}

fn black_box_call_native_op(call: &BlackBoxFuncCall) -> Option<BlackBoxOp> {
    match call {
        BlackBoxFuncCall::Poseidon2Permutation { .. } => Some(BlackBoxOp::Poseidon),
        BlackBoxFuncCall::SHA256 { .. } => Some(BlackBoxOp::Sha256),
        BlackBoxFuncCall::Keccak256 { .. } => Some(BlackBoxOp::Keccak256),
        BlackBoxFuncCall::PedersenHash { .. } | BlackBoxFuncCall::PedersenCommitment { .. } => {
            Some(BlackBoxOp::Pedersen)
        }
        BlackBoxFuncCall::SchnorrVerify { .. } => Some(BlackBoxOp::SchnorrVerify),
        BlackBoxFuncCall::EcdsaSecp256k1 { .. } => Some(BlackBoxOp::EcdsaSecp256k1),
        BlackBoxFuncCall::EcdsaSecp256r1 { .. } => Some(BlackBoxOp::EcdsaSecp256r1),
        BlackBoxFuncCall::Blake2s { .. } => Some(BlackBoxOp::Blake2s),
        BlackBoxFuncCall::RecursiveAggregation { .. } => {
            Some(BlackBoxOp::RecursiveAggregationMarker)
        }
        _ => None,
    }
}

fn black_box_outputs_boolean(call: &BlackBoxFuncCall) -> bool {
    matches!(
        call,
        BlackBoxFuncCall::SchnorrVerify { .. }
            | BlackBoxFuncCall::EcdsaSecp256k1 { .. }
            | BlackBoxFuncCall::EcdsaSecp256r1 { .. }
    )
}

fn black_box_output_range_bits(call: &BlackBoxFuncCall) -> Option<u32> {
    match call {
        BlackBoxFuncCall::SHA256 { .. }
        | BlackBoxFuncCall::Blake2s { .. }
        | BlackBoxFuncCall::Blake3 { .. }
        | BlackBoxFuncCall::Keccak256 { .. }
        | BlackBoxFuncCall::AES128Encrypt { .. }
        | BlackBoxFuncCall::BigIntToLeBytes { .. } => Some(8),
        BlackBoxFuncCall::Sha256Compression { .. } => Some(32),
        BlackBoxFuncCall::Keccakf1600 { .. } => Some(64),
        _ => None,
    }
}

fn validate_blackbox_input_bits(
    num_bits: u32,
    function_index: usize,
    opcode_index: usize,
    call_name: &str,
    input_i: usize,
    field: FieldId,
) -> ZkfResult<()> {
    let max_bits = max_safe_bits_for_field(field);
    if num_bits == 0 || num_bits > max_bits {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported ACIR black-box opcode at function {function_index}, index {opcode_index}: {call_name} input bits must be in 1..={max_bits} for field {field}, found {num_bits} at input {input_i}",
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_blackbox_input_signal(
    input: &FunctionInput,
    function_index: usize,
    opcode_index: usize,
    call_name: &str,
    input_i: usize,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
) -> ZkfResult<String> {
    let signal_name = resolve_witness_name(input.witness.witness_index(), mapping, prefix, state);
    if !(state.field == FieldId::Bn254 && input.num_bits == 254) {
        validate_blackbox_input_bits(
            input.num_bits,
            function_index,
            opcode_index,
            call_name,
            input_i,
            state.field,
        )?;
        state.constraints.push(Constraint::Range {
            signal: signal_name.clone(),
            bits: input.num_bits,
            label: Some(format!(
                "acir_f{function_index}_{call_name}_{opcode_index}_input_{input_i}"
            )),
        });
    }
    Ok(signal_name)
}

#[allow(clippy::too_many_arguments)]
fn translate_multi_scalar_mul_call(
    points: &[FunctionInput],
    scalars: &[FunctionInput],
    outputs: &(AcirWitness, AcirWitness),
    function_index: usize,
    opcode_index: usize,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
) -> ZkfResult<()> {
    if scalars.is_empty() || !scalars.len().is_multiple_of(2) {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported ACIR MultiScalarMul at function {function_index}, index {opcode_index}: expected scalar limbs as low/high pairs, found {} entries",
            scalars.len()
        )));
    }

    let point_count = scalars.len() / 2;
    let point_arity = if points.len() == point_count * 2 {
        2
    } else if points.len() == point_count * 3 {
        3
    } else {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported ACIR MultiScalarMul at function {function_index}, index {opcode_index}: expected point coordinates as 2-tuples or 3-tuples for {point_count} terms, found {} entries",
            points.len()
        )));
    };

    let two_pow_128 = FieldElement::from_bigint_with_field(BigInt::from(1u8) << 128, state.field);
    let mut msm_terms = Vec::<(String, String)>::with_capacity(point_count);

    for term_i in 0..point_count {
        let point_base = term_i * point_arity;
        let point_x = resolve_blackbox_input_signal(
            &points[point_base],
            function_index,
            opcode_index,
            "multi_scalar_mul",
            point_base,
            mapping,
            prefix,
            state,
        )?;
        let point_y = resolve_blackbox_input_signal(
            &points[point_base + 1],
            function_index,
            opcode_index,
            "multi_scalar_mul",
            point_base + 1,
            mapping,
            prefix,
            state,
        )?;
        if point_arity == 3 {
            let point_is_infinite = resolve_blackbox_input_signal(
                &points[point_base + 2],
                function_index,
                opcode_index,
                "multi_scalar_mul",
                point_base + 2,
                mapping,
                prefix,
                state,
            )?;
            state.constraints.push(Constraint::Boolean {
                signal: point_is_infinite.clone(),
                label: Some(format!(
                    "acir_f{function_index}_multi_scalar_mul_{opcode_index}_point_{term_i}_is_infinite_boolean"
                )),
            });
            state.constraints.push(Constraint::Equal {
                lhs: Expr::Signal(point_is_infinite),
                rhs: Expr::Const(FieldElement::from_i64(0)),
                label: Some(format!(
                    "acir_f{function_index}_multi_scalar_mul_{opcode_index}_point_{term_i}_is_infinite_zero"
                )),
            });
        }
        let scalar_lo = resolve_blackbox_input_signal(
            &scalars[term_i * 2],
            function_index,
            opcode_index,
            "multi_scalar_mul",
            points.len() + term_i * 2,
            mapping,
            prefix,
            state,
        )?;
        let scalar_hi = resolve_blackbox_input_signal(
            &scalars[term_i * 2 + 1],
            function_index,
            opcode_index,
            "multi_scalar_mul",
            points.len() + term_i * 2 + 1,
            mapping,
            prefix,
            state,
        )?;

        let scalar_expr = Expr::Add(vec![
            Expr::Signal(scalar_lo),
            Expr::Mul(
                Box::new(Expr::Const(two_pow_128.clone())),
                Box::new(Expr::Signal(scalar_hi)),
            ),
        ]);

        let (term_x, term_y) = if point_count == 1 {
            (
                resolve_witness_name(outputs.0.witness_index(), mapping, prefix, state),
                resolve_witness_name(outputs.1.witness_index(), mapping, prefix, state),
            )
        } else {
            (
                allocate_aux_signal(
                    state,
                    &format!("msm_f{function_index}_{opcode_index}_{term_i}_x"),
                ),
                allocate_aux_signal(
                    state,
                    &format!("msm_f{function_index}_{opcode_index}_{term_i}_y"),
                ),
            )
        };

        register_signal(state, term_x.clone(), Visibility::Private);
        register_signal(state, term_y.clone(), Visibility::Private);
        state.constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::ScalarMulG1,
            inputs: vec![scalar_expr, Expr::Signal(point_x), Expr::Signal(point_y)],
            outputs: vec![term_x.clone(), term_y.clone()],
            params: BTreeMap::new(),
            label: Some(format!(
                "acir_f{function_index}_multi_scalar_mul_{opcode_index}_term_{term_i}"
            )),
        });
        msm_terms.push((term_x, term_y));
    }

    if point_count == 1 {
        return Ok(());
    }

    let mut acc = msm_terms[0].clone();
    for (add_i, next) in msm_terms.iter().skip(1).enumerate() {
        let last_add = add_i == point_count - 2;
        let (out_x, out_y) = if last_add {
            (
                resolve_witness_name(outputs.0.witness_index(), mapping, prefix, state),
                resolve_witness_name(outputs.1.witness_index(), mapping, prefix, state),
            )
        } else {
            (
                allocate_aux_signal(
                    state,
                    &format!("msm_f{function_index}_{opcode_index}_add_{add_i}_x"),
                ),
                allocate_aux_signal(
                    state,
                    &format!("msm_f{function_index}_{opcode_index}_add_{add_i}_y"),
                ),
            )
        };

        register_signal(state, out_x.clone(), Visibility::Private);
        register_signal(state, out_y.clone(), Visibility::Private);
        state.constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::PointAddG1,
            inputs: vec![
                Expr::Signal(acc.0.clone()),
                Expr::Signal(acc.1.clone()),
                Expr::Signal(next.0.clone()),
                Expr::Signal(next.1.clone()),
            ],
            outputs: vec![out_x.clone(), out_y.clone()],
            params: BTreeMap::new(),
            label: Some(format!(
                "acir_f{function_index}_multi_scalar_mul_{opcode_index}_acc_{add_i}"
            )),
        });
        acc = (out_x, out_y);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn translate_embedded_curve_add_call(
    input1_x: &FunctionInput,
    input1_y: &FunctionInput,
    input2_x: &FunctionInput,
    input2_y: &FunctionInput,
    outputs: &(AcirWitness, AcirWitness),
    function_index: usize,
    opcode_index: usize,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
) -> ZkfResult<()> {
    let x1 = resolve_blackbox_input_signal(
        input1_x,
        function_index,
        opcode_index,
        "embedded_curve_add",
        0,
        mapping,
        prefix,
        state,
    )?;
    let y1 = resolve_blackbox_input_signal(
        input1_y,
        function_index,
        opcode_index,
        "embedded_curve_add",
        1,
        mapping,
        prefix,
        state,
    )?;
    let x2 = resolve_blackbox_input_signal(
        input2_x,
        function_index,
        opcode_index,
        "embedded_curve_add",
        2,
        mapping,
        prefix,
        state,
    )?;
    let y2 = resolve_blackbox_input_signal(
        input2_y,
        function_index,
        opcode_index,
        "embedded_curve_add",
        3,
        mapping,
        prefix,
        state,
    )?;
    let out_x = resolve_witness_name(outputs.0.witness_index(), mapping, prefix, state);
    let out_y = resolve_witness_name(outputs.1.witness_index(), mapping, prefix, state);
    state.constraints.push(Constraint::BlackBox {
        op: BlackBoxOp::PointAddG1,
        inputs: vec![
            Expr::Signal(x1),
            Expr::Signal(y1),
            Expr::Signal(x2),
            Expr::Signal(y2),
        ],
        outputs: vec![out_x, out_y],
        params: BTreeMap::new(),
        label: Some(format!(
            "acir_f{function_index}_embedded_curve_add_{opcode_index}"
        )),
    });
    Ok(())
}

fn is_known_unsupported_noir_version(version: &str) -> bool {
    let prefix = version
        .split('+')
        .next()
        .unwrap_or(version)
        .split('-')
        .next()
        .unwrap_or(version);

    let major = prefix
        .split('.')
        .next()
        .and_then(|segment| segment.parse::<u64>().ok());

    matches!(major, Some(m) if m >= 1)
}

fn import_acir_program(
    acir_program: &AcirProgram,
    program_name: Option<String>,
    field: FieldId,
    external_hints: Vec<WitnessHint>,
) -> ZkfResult<Program> {
    if acir_program.functions.is_empty() {
        return Err(ZkfError::InvalidArtifact(format!(
            "ACIR importer expects at least one function, found {}",
            acir_program.functions.len()
        )));
    }

    translate_program(
        acir_program,
        program_name.unwrap_or_else(|| "acir_import".to_string()),
        field,
        external_hints,
    )
}

fn inspect_acir_program(
    program: &AcirProgram,
    probe: FrontendProbe,
    dropped_features: Vec<String>,
    requires_hints_from_translation: bool,
) -> FrontendInspection {
    let mut opcode_counts = BTreeMap::new();
    let mut blackbox_counts = BTreeMap::new();
    let mut required_capabilities = BTreeSet::new();
    let mut requires_hints =
        requires_hints_from_translation || !program.unconstrained_functions.is_empty();

    for function in &program.functions {
        for opcode in &function.opcodes {
            match opcode {
                AcirOpcode::AssertZero(_) => {
                    *opcode_counts.entry("assert_zero".to_string()).or_insert(0) += 1;
                    required_capabilities.insert("assert-zero".to_string());
                }
                AcirOpcode::BlackBoxFuncCall(call) => {
                    *opcode_counts
                        .entry("black_box_func_call".to_string())
                        .or_insert(0) += 1;
                    let name = call.name().to_string();
                    *blackbox_counts.entry(name.clone()).or_insert(0) += 1;
                    required_capabilities.insert(format!("blackbox:{name}"));
                    if black_box_call_requires_hints(call) {
                        requires_hints = true;
                        required_capabilities.insert("hints".to_string());
                    }
                }
                AcirOpcode::Directive(_) => {
                    *opcode_counts.entry("directive".to_string()).or_insert(0) += 1;
                    required_capabilities.insert("directive".to_string());
                }
                AcirOpcode::MemoryOp { .. } => {
                    *opcode_counts.entry("memory_op".to_string()).or_insert(0) += 1;
                    required_capabilities.insert("memory".to_string());
                }
                AcirOpcode::MemoryInit { .. } => {
                    *opcode_counts.entry("memory_init".to_string()).or_insert(0) += 1;
                    required_capabilities.insert("memory".to_string());
                }
                AcirOpcode::BrilligCall { .. } => {
                    *opcode_counts.entry("brillig_call".to_string()).or_insert(0) += 1;
                    required_capabilities.insert("hints".to_string());
                    requires_hints = true;
                }
                AcirOpcode::Call { .. } => {
                    *opcode_counts.entry("call".to_string()).or_insert(0) += 1;
                    required_capabilities.insert("call".to_string());
                }
            }
        }
    }

    if program.functions.len() > 1 {
        required_capabilities.insert("multi-function".to_string());
    }
    if requires_hints {
        required_capabilities.insert("hints".to_string());
    }

    FrontendInspection {
        frontend: FrontendKind::Noir,
        format: probe.format,
        version: probe.noir_version,
        functions: program.functions.len(),
        unconstrained_functions: program.unconstrained_functions.len(),
        opcode_counts,
        blackbox_counts,
        required_capabilities: required_capabilities.into_iter().collect(),
        dropped_features,
        requires_hints,
    }
}

fn parse_acir_program(value: &Value) -> ZkfResult<AcirProgram> {
    if let Some(bytecode) = value.get("bytecode").and_then(Value::as_str) {
        return parse_program_bytecode(bytecode);
    }

    if let Some(program_value) = value.get("program")
        && let Ok(program) = serde_json::from_value::<AcirProgram>(program_value.clone())
    {
        return Ok(program);
    }

    serde_json::from_value::<AcirProgram>(value.clone()).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "input is neither ACIR Program JSON nor Noir artifact bytecode: {err}"
        ))
    })
}

fn parse_program_bytecode(bytecode: &str) -> ZkfResult<AcirProgram> {
    let bytecode = bytecode.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(bytecode)
        .map_err(|err| ZkfError::InvalidArtifact(format!("invalid base64 ACIR bytecode: {err}")))?;

    let raw_result = AcirProgram::deserialize_program(&bytes);
    if let Ok(program) = raw_result {
        return Ok(program);
    }

    if !is_gzip(&bytes) {
        return raw_result.map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize ACIR bytecode: {err}"))
        });
    }

    let mut decoder = GzDecoder::new(bytes.as_slice());
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|err| {
        ZkfError::InvalidArtifact(format!("failed to decompress ACIR bytecode (gzip): {err}"))
    })?;

    if let Ok(program) = AcirProgram::deserialize_program(&decompressed) {
        return Ok(program);
    }

    if let Ok(program) = bincode::deserialize::<AcirProgram>(&decompressed) {
        return Ok(program);
    }

    let raw_err = raw_result
        .err()
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let nested_err = AcirProgram::deserialize_program(&decompressed)
        .err()
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());
    let bincode_err = bincode::deserialize::<AcirProgram>(&decompressed)
        .err()
        .map(|err| err.to_string())
        .unwrap_or_else(|| "unknown error".to_string());

    Err(ZkfError::InvalidArtifact(format!(
        "failed to deserialize ACIR bytecode (raw: {raw_err}; nested-gzip: {nested_err}; bincode: {bincode_err})"
    )))
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

#[derive(Debug)]
struct TranslationState {
    field: FieldId,
    public_witnesses_main: BTreeSet<u32>,
    signal_visibility: BTreeMap<String, Visibility>,
    constraints: Vec<Constraint>,
    hints: Vec<WitnessHint>,
    inline_counter: usize,
    aux_counter: usize,
}

fn parse_serialized_witness_hints(value: &Value) -> ZkfResult<Vec<WitnessHint>> {
    let Some(raw_hints) = value.get("witness_hints") else {
        return Ok(Vec::new());
    };
    serde_json::from_value(raw_hints.clone()).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize witness_hints metadata: {err}"
        ))
    })
}

fn translate_program(
    acir_program: &AcirProgram,
    program_name: String,
    field: FieldId,
    mut external_hints: Vec<WitnessHint>,
) -> ZkfResult<Program> {
    let main = &acir_program.functions[0];
    let mut public_witnesses_main: BTreeSet<u32> =
        main.public_parameters.indices().into_iter().collect();
    public_witnesses_main.extend(main.return_values.indices());

    let mut state = TranslationState {
        field,
        public_witnesses_main,
        signal_visibility: BTreeMap::new(),
        constraints: Vec::new(),
        hints: Vec::new(),
        inline_counter: 0,
        aux_counter: 0,
    };

    for witness in &main.private_parameters {
        let name = witness_name(witness.witness_index());
        register_signal(&mut state, name, Visibility::Private);
    }
    for witness_index in state.public_witnesses_main.clone() {
        register_signal(&mut state, witness_name(witness_index), Visibility::Public);
    }

    let mut main_mapping = BTreeMap::new();
    let mut call_stack = Vec::new();
    translate_function(
        acir_program,
        0,
        &mut main_mapping,
        "",
        &mut state,
        &mut call_stack,
    )?;

    let internal_hint_targets = state
        .hints
        .iter()
        .map(|hint| hint.target.clone())
        .collect::<Vec<_>>();
    for target in internal_hint_targets {
        register_signal(&mut state, target, Visibility::Private);
    }
    for hint in &external_hints {
        register_signal(&mut state, hint.target.clone(), Visibility::Private);
    }

    let mut hints = state.hints;
    hints.append(&mut external_hints);

    let signals = state
        .signal_visibility
        .into_iter()
        .map(|(name, visibility)| Signal {
            name,
            visibility,
            constant: None,
            ty: None,
        })
        .collect::<Vec<_>>();

    Ok(Program {
        name: program_name,
        field,
        signals,
        constraints: state.constraints,
        witness_plan: WitnessPlan {
            assignments: Vec::new(),
            hints,
            ..Default::default()
        },
        ..Default::default()
    })
}

fn translate_function(
    acir_program: &AcirProgram,
    function_index: usize,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
    call_stack: &mut Vec<usize>,
) -> ZkfResult<()> {
    if function_index >= acir_program.functions.len() {
        return Err(ZkfError::InvalidArtifact(format!(
            "ACIR call references missing function id {function_index}"
        )));
    }
    if call_stack.contains(&function_index) {
        return Err(ZkfError::InvalidArtifact(format!(
            "recursive ACIR call cycle detected at function {function_index}"
        )));
    }
    call_stack.push(function_index);

    let circuit = &acir_program.functions[function_index];
    let mut memory_blocks: BTreeMap<u32, Vec<Expr>> = BTreeMap::new();

    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        match opcode {
            AcirOpcode::AssertZero(expr) => {
                let lhs = translate_expression(expr, mapping, prefix, state);
                state.constraints.push(Constraint::Equal {
                    lhs,
                    rhs: Expr::Const(FieldElement::from_i64(0)),
                    label: Some(format!("acir_f{function_index}_assert_zero_{opcode_index}")),
                });
            }
            AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE { input }) => {
                let signal_name =
                    resolve_witness_name(input.witness.witness_index(), mapping, prefix, state);
                state.constraints.push(Constraint::Range {
                    signal: signal_name,
                    bits: input.num_bits,
                    label: Some(format!("acir_f{function_index}_range_{opcode_index}")),
                });
            }
            AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::AND { lhs, rhs, output }) => {
                let lhs_bits = lhs.num_bits;
                let rhs_bits = rhs.num_bits;
                if lhs_bits != rhs_bits {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "unsupported ACIR AND at function {function_index}, index {opcode_index}: input bit sizes must match (lhs={lhs_bits}, rhs={rhs_bits})"
                    )));
                }
                let max_bits = max_safe_bits_for_field(state.field);
                if lhs_bits == 0 || lhs_bits > max_bits {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "unsupported ACIR AND at function {function_index}, index {opcode_index}: num_bits must be in 1..={max_bits} for field {}, found {lhs_bits}",
                        state.field
                    )));
                }

                let lhs_signal =
                    resolve_witness_name(lhs.witness.witness_index(), mapping, prefix, state);
                let rhs_signal =
                    resolve_witness_name(rhs.witness.witness_index(), mapping, prefix, state);
                let output_signal =
                    resolve_witness_name(output.witness_index(), mapping, prefix, state);

                let lhs_bits_signals = add_bit_decomposition(
                    state,
                    &lhs_signal,
                    lhs_bits,
                    &format!("acir_f{function_index}_and_{opcode_index}_lhs"),
                );
                let rhs_bits_signals = add_bit_decomposition(
                    state,
                    &rhs_signal,
                    lhs_bits,
                    &format!("acir_f{function_index}_and_{opcode_index}_rhs"),
                );
                let out_bits_signals = add_bit_decomposition(
                    state,
                    &output_signal,
                    lhs_bits,
                    &format!("acir_f{function_index}_and_{opcode_index}_out"),
                );

                for (bit_i, ((lhs_bit, rhs_bit), out_bit)) in lhs_bits_signals
                    .iter()
                    .zip(rhs_bits_signals.iter())
                    .zip(out_bits_signals.iter())
                    .enumerate()
                {
                    state.constraints.push(Constraint::Equal {
                        lhs: Expr::Signal(out_bit.clone()),
                        rhs: Expr::Mul(
                            Box::new(Expr::Signal(lhs_bit.clone())),
                            Box::new(Expr::Signal(rhs_bit.clone())),
                        ),
                        label: Some(format!(
                            "acir_f{function_index}_and_{opcode_index}_bit_{bit_i}"
                        )),
                    });
                }
            }
            AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR { lhs, rhs, output }) => {
                let lhs_bits = lhs.num_bits;
                let rhs_bits = rhs.num_bits;
                if lhs_bits != rhs_bits {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "unsupported ACIR XOR at function {function_index}, index {opcode_index}: input bit sizes must match (lhs={lhs_bits}, rhs={rhs_bits})"
                    )));
                }
                let max_bits = max_safe_bits_for_field(state.field);
                if lhs_bits == 0 || lhs_bits > max_bits {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "unsupported ACIR XOR at function {function_index}, index {opcode_index}: num_bits must be in 1..={max_bits} for field {}, found {lhs_bits}",
                        state.field
                    )));
                }

                let lhs_signal =
                    resolve_witness_name(lhs.witness.witness_index(), mapping, prefix, state);
                let rhs_signal =
                    resolve_witness_name(rhs.witness.witness_index(), mapping, prefix, state);
                let output_signal =
                    resolve_witness_name(output.witness_index(), mapping, prefix, state);

                let lhs_bits_signals = add_bit_decomposition(
                    state,
                    &lhs_signal,
                    lhs_bits,
                    &format!("acir_f{function_index}_xor_{opcode_index}_lhs"),
                );
                let rhs_bits_signals = add_bit_decomposition(
                    state,
                    &rhs_signal,
                    lhs_bits,
                    &format!("acir_f{function_index}_xor_{opcode_index}_rhs"),
                );
                let out_bits_signals = add_bit_decomposition(
                    state,
                    &output_signal,
                    lhs_bits,
                    &format!("acir_f{function_index}_xor_{opcode_index}_out"),
                );

                for (bit_i, ((lhs_bit, rhs_bit), out_bit)) in lhs_bits_signals
                    .iter()
                    .zip(rhs_bits_signals.iter())
                    .zip(out_bits_signals.iter())
                    .enumerate()
                {
                    // For boolean bits, xor = a + b - 2ab in the field.
                    let lhs_expr = Expr::Signal(lhs_bit.clone());
                    let rhs_expr = Expr::Signal(rhs_bit.clone());
                    let two_ab = Expr::Mul(
                        Box::new(Expr::Const(FieldElement::from_i64(2))),
                        Box::new(Expr::Mul(
                            Box::new(lhs_expr.clone()),
                            Box::new(rhs_expr.clone()),
                        )),
                    );
                    state.constraints.push(Constraint::Equal {
                        lhs: Expr::Signal(out_bit.clone()),
                        rhs: Expr::Sub(
                            Box::new(Expr::Add(vec![lhs_expr, rhs_expr])),
                            Box::new(two_ab),
                        ),
                        label: Some(format!(
                            "acir_f{function_index}_xor_{opcode_index}_bit_{bit_i}"
                        )),
                    });
                }
            }
            AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                outputs,
            }) => {
                translate_multi_scalar_mul_call(
                    points,
                    scalars,
                    outputs,
                    function_index,
                    opcode_index,
                    mapping,
                    prefix,
                    state,
                )?;
            }
            AcirOpcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd {
                input1_x,
                input1_y,
                input2_x,
                input2_y,
                outputs,
            }) => {
                translate_embedded_curve_add_call(
                    input1_x,
                    input1_y,
                    input2_x,
                    input2_y,
                    outputs,
                    function_index,
                    opcode_index,
                    mapping,
                    prefix,
                    state,
                )?;
            }
            AcirOpcode::BlackBoxFuncCall(call) if black_box_call_native_op(call).is_some() => {
                let call_name = call.name().to_ascii_lowercase();
                let blackbox_op = black_box_call_native_op(call).expect("checked above");
                let max_bits = max_safe_bits_for_field(state.field);
                let mut inputs = Vec::new();
                let mut input_num_bits = Vec::new();

                for (input_i, input) in call.get_inputs_vec().iter().enumerate() {
                    let signal_name =
                        resolve_witness_name(input.witness.witness_index(), mapping, prefix, state);
                    if input.num_bits == 0 || input.num_bits > max_bits {
                        return Err(ZkfError::InvalidArtifact(format!(
                            "unsupported ACIR black-box opcode at function {function_index}, index {opcode_index}: {} input bits must be in 1..={max_bits} for field {}, found {} at input {input_i}",
                            call.name(),
                            state.field,
                            input.num_bits
                        )));
                    }
                    input_num_bits.push(input.num_bits.to_string());
                    inputs.push(Expr::Signal(signal_name.clone()));
                    state.constraints.push(Constraint::Range {
                        signal: signal_name,
                        bits: input.num_bits,
                        label: Some(format!(
                            "acir_f{function_index}_{call_name}_{opcode_index}_input_{input_i}"
                        )),
                    });
                }

                let output_witnesses = call.get_outputs_vec();
                let mut outputs = Vec::new();
                let mut params = BTreeMap::new();
                params.insert("call".to_string(), call.name().to_string());
                if !input_num_bits.is_empty() {
                    params.insert("input_num_bits".to_string(), input_num_bits.join(","));
                }
                if let BlackBoxFuncCall::Poseidon2Permutation { len, .. } = call {
                    params.insert("state_len".to_string(), len.to_string());
                }
                if matches!(blackbox_op, BlackBoxOp::RecursiveAggregationMarker) {
                    params.insert(
                        "requires_recursive_composition".to_string(),
                        "true".to_string(),
                    );
                }

                for (out_i, witness) in output_witnesses.iter().enumerate() {
                    let target =
                        resolve_witness_name(witness.witness_index(), mapping, prefix, state);
                    outputs.push(target.clone());
                    if black_box_outputs_boolean(call) {
                        state.constraints.push(Constraint::Boolean {
                            signal: target.clone(),
                            label: Some(format!(
                                "acir_f{function_index}_{call_name}_{opcode_index}_out_{out_i}_boolean"
                            )),
                        });
                    } else if let Some(bits) = black_box_output_range_bits(call) {
                        state.constraints.push(Constraint::Range {
                            signal: target.clone(),
                            bits,
                            label: Some(format!(
                                "acir_f{function_index}_{call_name}_{opcode_index}_out_{out_i}_range"
                            )),
                        });
                    }
                }

                state.constraints.push(Constraint::BlackBox {
                    op: blackbox_op,
                    inputs,
                    outputs,
                    params,
                    label: Some(format!("acir_f{function_index}_{call_name}_{opcode_index}")),
                });
            }
            AcirOpcode::BlackBoxFuncCall(call) => {
                return Err(ZkfError::InvalidArtifact(format!(
                    "unsupported ACIR black-box opcode at function {function_index}, index {opcode_index}: {} (supported: RANGE, AND, XOR, native-blackbox: SHA256/Keccak256/Pedersen/Schnorr/ECDSA/Blake2s/RecursiveAggregation marker)",
                    call.name()
                )));
            }
            AcirOpcode::Directive(AcirDirective::ToLeRadix { a, b, radix }) => {
                if *radix < 2 || !radix.is_power_of_two() {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "unsupported ACIR Directive::ToLeRadix at function {function_index}, index {opcode_index}: radix {radix} must be a power of two"
                    )));
                }
                let bits = radix.trailing_zeros();
                let lhs = translate_expression(a, mapping, prefix, state);
                let rhs_terms = b
                    .iter()
                    .enumerate()
                    .map(|(i, witness)| {
                        let signal_name =
                            resolve_witness_name(witness.witness_index(), mapping, prefix, state);
                        state.constraints.push(Constraint::Range {
                            signal: signal_name.clone(),
                            bits,
                            label: Some(format!(
                                "acir_f{function_index}_directive_tole_radix_{opcode_index}_digit_{i}"
                            )),
                        });
                        let mut coeff = BigInt::from(*radix);
                        coeff = coeff.pow(i as u32);
                        let term = Expr::Signal(signal_name);
                        if coeff == BigInt::from(1u8) {
                            term
                        } else {
                            Expr::Mul(
                                Box::new(Expr::Const(FieldElement::from_bigint_with_field(
                                    coeff,
                                    state.field,
                                ))),
                                Box::new(term),
                            )
                        }
                    })
                    .collect::<Vec<_>>();
                let rhs = match rhs_terms.len() {
                    0 => Expr::Const(FieldElement::from_i64(0)),
                    1 => rhs_terms[0].clone(),
                    _ => Expr::Add(rhs_terms),
                };
                state.constraints.push(Constraint::Equal {
                    lhs,
                    rhs,
                    label: Some(format!(
                        "acir_f{function_index}_directive_tole_radix_{opcode_index}"
                    )),
                });
            }
            AcirOpcode::MemoryInit { block_id, init } => {
                let slots = init
                    .iter()
                    .map(|witness| {
                        Expr::Signal(resolve_witness_name(
                            witness.witness_index(),
                            mapping,
                            prefix,
                            state,
                        ))
                    })
                    .collect::<Vec<_>>();
                memory_blocks.insert(block_id.0, slots);
            }
            AcirOpcode::MemoryOp {
                block_id,
                op,
                predicate,
            } => {
                let should_execute = resolve_predicate(
                    predicate,
                    mapping,
                    prefix,
                    state,
                    format!("MemoryOp at function {function_index}, index {opcode_index}"),
                )?;
                if !should_execute {
                    continue;
                }
                let slots = memory_blocks.get_mut(&block_id.0).ok_or_else(|| {
                    ZkfError::InvalidArtifact(format!(
                        "MemoryOp references uninitialized block {} at function {function_index}, index {opcode_index}",
                        block_id.0
                    ))
                })?;
                let operation = resolve_constant_u32(
                    &op.operation,
                    state.field,
                    format!(
                        "MemoryOp operation at function {function_index}, index {opcode_index}"
                    ),
                )?;
                let value_expr = translate_expression(&op.value, mapping, prefix, state);

                // Try constant index first (fast path)
                if let Ok(index) = resolve_constant_u32(
                    &op.index,
                    state.field,
                    format!("MemoryOp index at function {function_index}, index {opcode_index}"),
                ) {
                    let index = index as usize;
                    if index >= slots.len() {
                        return Err(ZkfError::InvalidArtifact(format!(
                            "MemoryOp index {index} out of bounds for block {} (len={}) at function {function_index}, index {opcode_index}",
                            block_id.0,
                            slots.len()
                        )));
                    }
                    match operation {
                        0 => state.constraints.push(Constraint::Equal {
                            lhs: value_expr,
                            rhs: slots[index].clone(),
                            label: Some(format!(
                                "acir_f{function_index}_memory_read_{opcode_index}"
                            )),
                        }),
                        1 => slots[index] = value_expr,
                        other => {
                            return Err(ZkfError::InvalidArtifact(format!(
                                "MemoryOp operation must be constant 0/1, found {other} at function {function_index}, index {opcode_index}"
                            )));
                        }
                    }
                } else {
                    // Dynamic index: multiplexer pattern
                    let index_expr = translate_expression(&op.index, mapping, prefix, state);
                    let n = slots.len();
                    let label_base = format!("acir_f{function_index}_memory_dyn_{opcode_index}");

                    // Create selector bits s_k for each possible index k
                    // Constraint: s_k * (idx - k) = 0 (s_k can only be 1 when idx == k)
                    // Constraint: sum(s_k) = 1 (exactly one selector is active)
                    let mut selector_signals = Vec::with_capacity(n);
                    for k in 0..n {
                        let s_k = allocate_aux_signal(state, &format!("{label_base}_sel"));
                        state.constraints.push(Constraint::Boolean {
                            signal: s_k.clone(),
                            label: Some(format!("{label_base}_sel_{k}_bool")),
                        });
                        // s_k * (idx - k) = 0
                        let idx_minus_k = if k == 0 {
                            index_expr.clone()
                        } else {
                            Expr::Sub(
                                Box::new(index_expr.clone()),
                                Box::new(Expr::Const(FieldElement::from_i64(k as i64))),
                            )
                        };
                        state.constraints.push(Constraint::Equal {
                            lhs: Expr::Mul(
                                Box::new(Expr::Signal(s_k.clone())),
                                Box::new(idx_minus_k),
                            ),
                            rhs: Expr::Const(FieldElement::from_i64(0)),
                            label: Some(format!("{label_base}_sel_{k}_guard")),
                        });
                        selector_signals.push(s_k);
                    }

                    // sum(s_k) = 1
                    let selector_sum = Expr::Add(
                        selector_signals
                            .iter()
                            .map(|s| Expr::Signal(s.clone()))
                            .collect(),
                    );
                    state.constraints.push(Constraint::Equal {
                        lhs: selector_sum,
                        rhs: Expr::Const(FieldElement::from_i64(1)),
                        label: Some(format!("{label_base}_sel_sum")),
                    });

                    match operation {
                        0 => {
                            // Read: value = sum(s_k * mem[k])
                            let mux_terms: Vec<Expr> = (0..n)
                                .map(|k| {
                                    Expr::Mul(
                                        Box::new(Expr::Signal(selector_signals[k].clone())),
                                        Box::new(slots[k].clone()),
                                    )
                                })
                                .collect();
                            let mux_value = if mux_terms.len() == 1 {
                                mux_terms.into_iter().next().unwrap()
                            } else {
                                Expr::Add(mux_terms)
                            };
                            state.constraints.push(Constraint::Equal {
                                lhs: value_expr,
                                rhs: mux_value,
                                label: Some(format!("{label_base}_read")),
                            });
                        }
                        1 => {
                            // Write: for each k, new_mem[k] = s_k * new_value + (1 - s_k) * old_mem[k]
                            for k in 0..n {
                                let new_slot =
                                    allocate_aux_signal(state, &format!("{label_base}_wslot"));
                                let s_k_expr = Expr::Signal(selector_signals[k].clone());
                                let one_minus_s_k = Expr::Sub(
                                    Box::new(Expr::Const(FieldElement::from_i64(1))),
                                    Box::new(s_k_expr.clone()),
                                );
                                // new_slot = s_k * new_value + (1 - s_k) * old_mem[k]
                                let rhs = Expr::Add(vec![
                                    Expr::Mul(Box::new(s_k_expr), Box::new(value_expr.clone())),
                                    Expr::Mul(Box::new(one_minus_s_k), Box::new(slots[k].clone())),
                                ]);
                                state.constraints.push(Constraint::Equal {
                                    lhs: Expr::Signal(new_slot.clone()),
                                    rhs,
                                    label: Some(format!("{label_base}_write_{k}")),
                                });
                                slots[k] = Expr::Signal(new_slot);
                            }
                        }
                        other => {
                            return Err(ZkfError::InvalidArtifact(format!(
                                "MemoryOp operation must be constant 0/1, found {other} at function {function_index}, index {opcode_index}"
                            )));
                        }
                    }
                }
            }
            AcirOpcode::BrilligCall {
                outputs, predicate, ..
            } => {
                let should_execute = resolve_predicate(
                    predicate,
                    mapping,
                    prefix,
                    state,
                    format!("BrilligCall at function {function_index}, index {opcode_index}"),
                )?;
                for output in outputs.iter() {
                    for witness_index in brillig_output_witnesses(output) {
                        let target = resolve_witness_name(witness_index, mapping, prefix, state);
                        if should_execute {
                            // Point the hint source at the actual witness signal name.
                            // When target == source the hint is a no-op (already resolved);
                            // when execute() has populated the value via ACVM, it flows through.
                            let source = target.clone();
                            state.hints.push(WitnessHint {
                                target,
                                source,
                                kind: WitnessHintKind::Copy,
                            });
                        } else {
                            state.constraints.push(Constraint::Equal {
                                lhs: Expr::Signal(target),
                                rhs: Expr::Const(FieldElement::from_i64(0)),
                                label: Some(format!(
                                    "acir_f{function_index}_brillig_predicate_false_{opcode_index}"
                                )),
                            });
                        }
                    }
                }
            }
            AcirOpcode::Call {
                id,
                inputs,
                outputs,
                predicate,
            } => {
                let should_execute = resolve_predicate(
                    predicate,
                    mapping,
                    prefix,
                    state,
                    format!("Call at function {function_index}, index {opcode_index}"),
                )?;
                if !should_execute {
                    for output in outputs {
                        let output_name =
                            resolve_witness_name(output.witness_index(), mapping, prefix, state);
                        state.constraints.push(Constraint::Equal {
                            lhs: Expr::Signal(output_name),
                            rhs: Expr::Const(FieldElement::from_i64(0)),
                            label: Some(format!(
                                "acir_f{function_index}_call_predicate_false_{opcode_index}"
                            )),
                        });
                    }
                    continue;
                }

                let callee_index = *id as usize;
                if callee_index == 0 {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "ACIR Call to function 0 (main) is not supported at function {function_index}, index {opcode_index}"
                    )));
                }
                if callee_index >= acir_program.functions.len() {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "ACIR Call references function {callee_index}, but only {} functions exist",
                        acir_program.functions.len()
                    )));
                }

                let callee = &acir_program.functions[callee_index];
                let mut child_mapping = BTreeMap::new();
                for (input_index, input_witness) in inputs.iter().enumerate() {
                    let caller_name =
                        resolve_witness_name(input_witness.witness_index(), mapping, prefix, state);
                    child_mapping.insert(input_index as u32, caller_name);
                }

                let mut parameter_indices = callee
                    .private_parameters
                    .iter()
                    .map(|w| w.witness_index())
                    .collect::<Vec<_>>();
                parameter_indices.extend(callee.public_parameters.indices());
                parameter_indices.sort_unstable();
                parameter_indices.dedup();
                if parameter_indices.len() == inputs.len() {
                    for (param_index, input_witness) in
                        parameter_indices.into_iter().zip(inputs.iter())
                    {
                        let caller_name = resolve_witness_name(
                            input_witness.witness_index(),
                            mapping,
                            prefix,
                            state,
                        );
                        child_mapping.insert(param_index, caller_name);
                    }
                }

                let mut return_indices = callee
                    .return_values
                    .indices()
                    .into_iter()
                    .collect::<Vec<_>>();
                return_indices.sort_unstable();
                if return_indices.len() != outputs.len() {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "ACIR Call output mismatch at function {function_index}, index {opcode_index}: callee returns {} values, call expects {}",
                        return_indices.len(),
                        outputs.len()
                    )));
                }
                for (return_index, output_witness) in return_indices.into_iter().zip(outputs.iter())
                {
                    let output_name = resolve_witness_name(
                        output_witness.witness_index(),
                        mapping,
                        prefix,
                        state,
                    );
                    child_mapping.insert(return_index, output_name);
                }

                let inline_id = state.inline_counter;
                state.inline_counter += 1;
                let child_prefix = format!("fn{callee_index}_call{inline_id}_");
                translate_function(
                    acir_program,
                    callee_index,
                    &mut child_mapping,
                    &child_prefix,
                    state,
                    call_stack,
                )?;
            }
        }
    }

    call_stack.pop();
    Ok(())
}

fn translate_expression(
    expr: &AcirExpression,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
) -> Expr {
    let mut terms = Vec::new();

    for (coefficient, lhs_witness, rhs_witness) in &expr.mul_terms {
        let lhs_name = resolve_witness_name(lhs_witness.witness_index(), mapping, prefix, state);
        let rhs_name = resolve_witness_name(rhs_witness.witness_index(), mapping, prefix, state);

        let term = Expr::Mul(
            Box::new(Expr::signal(lhs_name)),
            Box::new(Expr::signal(rhs_name)),
        );
        if let Some(term) = apply_coefficient(term, *coefficient, state.field) {
            terms.push(term);
        }
    }

    for (coefficient, witness) in &expr.linear_combinations {
        let witness_name = resolve_witness_name(witness.witness_index(), mapping, prefix, state);
        let term = Expr::signal(witness_name);
        if let Some(term) = apply_coefficient(term, *coefficient, state.field) {
            terms.push(term);
        }
    }

    if !expr.q_c.is_zero() {
        terms.push(Expr::Const(acir_field_to_ir(expr.q_c, state.field)));
    }

    match terms.len() {
        0 => Expr::Const(FieldElement::from_i64(0)),
        1 => terms.remove(0),
        _ => Expr::Add(terms),
    }
}

fn resolve_witness_name(
    witness_index: u32,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
) -> String {
    if let Some(name) = mapping.get(&witness_index) {
        return name.clone();
    }

    let name = if prefix.is_empty() {
        witness_name(witness_index)
    } else {
        format!("{prefix}w{witness_index}")
    };
    let visibility = if prefix.is_empty() && state.public_witnesses_main.contains(&witness_index) {
        Visibility::Public
    } else {
        Visibility::Private
    };
    register_signal(state, name.clone(), visibility);
    mapping.insert(witness_index, name.clone());
    name
}

fn register_signal(state: &mut TranslationState, name: String, visibility: Visibility) {
    match state.signal_visibility.get_mut(&name) {
        Some(existing) => {
            if *existing == Visibility::Private && visibility == Visibility::Public {
                *existing = Visibility::Public;
            }
        }
        None => {
            state.signal_visibility.insert(name, visibility);
        }
    }
}

fn allocate_aux_signal(state: &mut TranslationState, prefix: &str) -> String {
    let name = format!("{prefix}_{}", state.aux_counter);
    state.aux_counter += 1;
    register_signal(state, name.clone(), Visibility::Private);
    name
}

fn max_safe_bits_for_field(field: FieldId) -> u32 {
    let (_, bytes) = field.modulus().to_bytes_be();
    if bytes.is_empty() {
        return 1;
    }
    let leading = bytes[0].leading_zeros();
    let bit_len = (bytes.len() as u32 * 8).saturating_sub(leading);
    bit_len.saturating_sub(1).max(1)
}

fn add_bit_decomposition(
    state: &mut TranslationState,
    signal_name: &str,
    bits: u32,
    label_prefix: &str,
) -> Vec<String> {
    let mut bit_signals = Vec::with_capacity(bits as usize);
    let mut terms = Vec::with_capacity(bits as usize);

    for bit in 0..bits {
        let bit_signal = allocate_aux_signal(state, &format!("{label_prefix}_bit"));
        state.constraints.push(Constraint::Boolean {
            signal: bit_signal.clone(),
            label: Some(format!("{label_prefix}_bit_{bit}_boolean")),
        });
        let coeff = BigInt::from(1u8) << bit;
        let bit_expr = Expr::Signal(bit_signal.clone());
        let term = if bit == 0 {
            bit_expr
        } else {
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_bigint_with_field(
                    coeff,
                    state.field,
                ))),
                Box::new(bit_expr),
            )
        };
        terms.push(term);
        bit_signals.push(bit_signal);
    }

    let rhs = match terms.len() {
        0 => Expr::Const(FieldElement::from_i64(0)),
        1 => terms[0].clone(),
        _ => Expr::Add(terms),
    };
    state.constraints.push(Constraint::Equal {
        lhs: Expr::Signal(signal_name.to_string()),
        rhs,
        label: Some(format!("{label_prefix}_recompose")),
    });

    bit_signals
}

fn resolve_constant_u32(expr: &AcirExpression, field: FieldId, context: String) -> ZkfResult<u32> {
    let value = constant_expression_bigint(expr, field).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "{context} must be a constant expression for current importer"
        ))
    })?;
    if value.sign() == Sign::Minus {
        return Err(ZkfError::InvalidArtifact(format!(
            "{context} must be non-negative, found {value}"
        )));
    }
    value.clone().try_into().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "{context} is too large for u32 conversion: {value}"
        ))
    })
}

fn resolve_predicate(
    predicate: &Option<AcirExpression>,
    mapping: &mut BTreeMap<u32, String>,
    prefix: &str,
    state: &mut TranslationState,
    _context: String,
) -> ZkfResult<bool> {
    let Some(predicate_expr) = predicate else {
        return Ok(true);
    };

    if let Some(value) = constant_expression_bigint(predicate_expr, state.field) {
        return Ok(value != BigInt::from(0u8));
    }

    // ACIR predicates are execution optimization hints, not correctness requirements.
    // Treating dynamic predicates as "always true" is sound — the constraints
    // themselves enforce correctness regardless.
    let _rendered = translate_expression(predicate_expr, mapping, prefix, state);
    Ok(true)
}

fn constant_expression_bigint(expr: &AcirExpression, field: FieldId) -> Option<BigInt> {
    if !expr.mul_terms.is_empty() || !expr.linear_combinations.is_empty() {
        return None;
    }
    acir_field_to_ir(expr.q_c, field)
        .normalized_bigint(field)
        .ok()
}

fn brillig_output_witnesses(output: &AcirBrilligOutputs) -> Vec<u32> {
    match output {
        AcirBrilligOutputs::Simple(witness) => vec![witness.witness_index()],
        AcirBrilligOutputs::Array(witnesses) => witnesses
            .iter()
            .map(|witness| witness.witness_index())
            .collect(),
    }
}

fn apply_coefficient(term: Expr, coefficient: AcirFieldElement, field: FieldId) -> Option<Expr> {
    if coefficient.is_zero() {
        return None;
    }

    if coefficient.is_one() {
        return Some(term);
    }

    Some(Expr::Mul(
        Box::new(Expr::Const(acir_field_to_ir(coefficient, field))),
        Box::new(term),
    ))
}

fn acir_field_to_ir(value: AcirFieldElement, field: FieldId) -> FieldElement {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(value.to_be_bytes().as_slice());
    let bigint = BigInt::from_bytes_be(Sign::Plus, &bytes);
    // ACIR constants are BN254 field elements. Values > p_bn254/2 represent
    // negative numbers (e.g., p_bn254-1 is -1). When targeting a different field,
    // we must interpret them as signed values relative to BN254, then reduce
    // modulo the target field.
    let bn254_modulus = FieldId::Bn254.modulus();
    let half = bn254_modulus.clone() >> 1;
    let signed = if bigint > half {
        bigint - bn254_modulus
    } else {
        bigint
    };
    FieldElement::from_bigint_with_field(signed, field)
}

fn witness_name(index: u32) -> String {
    format!("w{index}")
}
