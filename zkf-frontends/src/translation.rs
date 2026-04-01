use acir::FieldElement as AcirFieldElement;
use acir::circuit::opcodes::{
    BlackBoxFuncCall as AcirBlackBoxFuncCall, FunctionInput as AcirFunctionInput,
};
use acir::circuit::{
    Circuit as AcirCircuit, ExpressionWidth as AcirExpressionWidth, Opcode as AcirOpcode,
    Program as AcirProgram, PublicInputs as AcirPublicInputs,
};
use acir::native_types::{Expression as AcirExpression, Witness as AcirWitness};
use acir_beta9::AcirField as _;
use acir_beta9::FieldElement as Beta9FieldElement;
use acir_beta9::circuit::opcodes::{
    BlackBoxFuncCall as Beta9BlackBoxFuncCall, ConstantOrWitnessEnum as Beta9ConstantOrWitness,
    FunctionInput as Beta9FunctionInput,
};
use acir_beta9::circuit::{
    Circuit as Beta9Circuit, ExpressionWidth as Beta9ExpressionWidth, Opcode as Beta9Opcode,
    Program as Beta9Program,
};
use acir_beta9::native_types::{Expression as Beta9Expression, Witness as Beta9Witness};
use acir_beta19::AcirField as _;
use acir_beta19::FieldElement as Beta19FieldElement;
use acir_beta19::circuit::opcodes::{
    BlackBoxFuncCall as Beta19BlackBoxFuncCall, FunctionInput as Beta19FunctionInput,
};
use acir_beta19::circuit::{
    Circuit as Beta19Circuit, Opcode as Beta19Opcode, Program as Beta19Program,
};
use acir_beta19::native_types::{Expression as Beta19Expression, Witness as Beta19Witness};
use base64::Engine;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;
use zkf_core::{WitnessHint, WitnessHintKind, ZkfError, ZkfResult};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TranslationTarget {
    Acir046,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct TranslationMeta {
    pub lossy: bool,
    #[serde(default)]
    pub dropped_features: Vec<String>,
    pub requires_hints: bool,
}

pub trait FrontendTranslator: Send + Sync {
    fn translate_noir_artifact(
        &self,
        artifact: &Value,
        noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value>;
}

pub fn default_frontend_translator() -> Arc<dyn FrontendTranslator> {
    Arc::new(DefaultFrontendTranslator::new())
}

#[derive(Debug, Default)]
pub struct NoopFrontendTranslator;

impl FrontendTranslator for NoopFrontendTranslator {
    fn translate_noir_artifact(
        &self,
        _artifact: &Value,
        noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        Err(ZkfError::UnsupportedBackend {
            backend: "frontend-translator".to_string(),
            message: format!(
                "no translator configured for noir_version '{noir_version}' -> {:?}",
                target
            ),
        })
    }
}

pub fn infer_noir_translation_meta(
    artifact: &Value,
    noir_version: &str,
) -> ZkfResult<TranslationMeta> {
    let version = parse_noir_version(noir_version)?;
    if version.major == 1
        && version.minor == 0
        && version.patch == 0
        && version
            .pre
            .as_str()
            .strip_prefix("beta.")
            .is_some_and(|suffix| suffix == "9")
    {
        let program = parse_beta9_program(artifact)?;
        let mut dropped = BTreeSet::new();
        let mut requires_hints = !program.unconstrained_functions.is_empty();

        for function in &program.functions {
            for opcode in &function.opcodes {
                match opcode {
                    Beta9Opcode::BrilligCall { .. } => {
                        dropped.insert("BrilligCall".to_string());
                        requires_hints = true;
                    }
                    Beta9Opcode::BlackBoxFuncCall(call) => {
                        if beta9_black_box_call_requires_hints(call) {
                            requires_hints = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        let dropped_features = dropped.into_iter().collect::<Vec<_>>();
        return Ok(TranslationMeta {
            lossy: !dropped_features.is_empty(),
            dropped_features,
            requires_hints,
        });
    }

    if version.major == 1
        && version.minor == 0
        && version.patch == 0
        && version
            .pre
            .as_str()
            .strip_prefix("beta.")
            .is_some_and(|suffix| suffix == "19")
    {
        let program = parse_beta19_program(artifact)?;
        let mut dropped = BTreeSet::new();
        let mut requires_hints = !program.unconstrained_functions.is_empty();

        for function in &program.functions {
            for opcode in &function.opcodes {
                match opcode {
                    Beta19Opcode::BrilligCall { .. } => {
                        dropped.insert("BrilligCall".to_string());
                        requires_hints = true;
                    }
                    Beta19Opcode::BlackBoxFuncCall(call) => {
                        if beta19_black_box_call_requires_hints(call) {
                            requires_hints = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        let dropped_features = dropped.into_iter().collect::<Vec<_>>();
        return Ok(TranslationMeta {
            lossy: !dropped_features.is_empty(),
            dropped_features,
            requires_hints,
        });
    }

    if version.major >= 1
        && let Some(program) = artifact.get("program")
        && let Ok(program) = serde_json::from_value::<AcirProgram>(program.clone())
    {
        return Ok(acir046_program_hint_meta(&program));
    }

    Ok(TranslationMeta::default())
}

fn acir046_program_hint_meta(program: &AcirProgram) -> TranslationMeta {
    let mut requires_hints = !program.unconstrained_functions.is_empty();
    for function in &program.functions {
        for opcode in &function.opcodes {
            if let AcirOpcode::BrilligCall { .. } = opcode {
                requires_hints = true;
            }
            if let AcirOpcode::BlackBoxFuncCall(call) = opcode
                && matches!(
                    call,
                    AcirBlackBoxFuncCall::Blake3 { .. }
                        | AcirBlackBoxFuncCall::AES128Encrypt { .. }
                        | AcirBlackBoxFuncCall::Keccakf1600 { .. }
                        | AcirBlackBoxFuncCall::Sha256Compression { .. }
                )
            {
                requires_hints = true;
            }
        }
    }
    TranslationMeta {
        lossy: false,
        dropped_features: Vec::new(),
        requires_hints,
    }
}

fn beta9_black_box_call_requires_hints(call: &Beta9BlackBoxFuncCall<Beta9FieldElement>) -> bool {
    matches!(
        call,
        Beta9BlackBoxFuncCall::AES128Encrypt { .. }
            | Beta9BlackBoxFuncCall::Blake3 { .. }
            | Beta9BlackBoxFuncCall::Keccakf1600 { .. }
            | Beta9BlackBoxFuncCall::Sha256Compression { .. }
    )
}

fn beta19_black_box_call_requires_hints(call: &Beta19BlackBoxFuncCall<Beta19FieldElement>) -> bool {
    matches!(
        call,
        Beta19BlackBoxFuncCall::AES128Encrypt { .. }
            | Beta19BlackBoxFuncCall::Blake3 { .. }
            | Beta19BlackBoxFuncCall::Keccakf1600 { .. }
            | Beta19BlackBoxFuncCall::Sha256Compression { .. }
    )
}

pub struct DefaultFrontendTranslator {
    noir_translators: Vec<Box<dyn NoirArtifactTranslator>>,
}

impl DefaultFrontendTranslator {
    pub fn new() -> Self {
        Self {
            noir_translators: vec![
                Box::new(NoirV1Beta9Translator),
                Box::new(NoirV1Beta19Translator),
                Box::new(NoirV1Beta10Translator),
                Box::new(NoirV1StableTranslator),
                Box::new(NoirV1ProgramJsonTranslator),
            ],
        }
    }
}

impl Default for DefaultFrontendTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrontendTranslator for DefaultFrontendTranslator {
    fn translate_noir_artifact(
        &self,
        artifact: &Value,
        noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        let version = parse_noir_version(noir_version)?;
        for translator in &self.noir_translators {
            if translator.supports(&version, target) {
                return translator.translate(artifact, noir_version, target);
            }
        }

        Err(ZkfError::UnsupportedBackend {
            backend: "frontend-translator".to_string(),
            message: format!(
                "no translator supports noir_version '{noir_version}' -> {:?}",
                target
            ),
        })
    }
}

trait NoirArtifactTranslator: Send + Sync {
    fn supports(&self, version: &Version, target: TranslationTarget) -> bool;
    fn translate(
        &self,
        artifact: &Value,
        noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value>;
}

struct NoirV1Beta9Translator;

impl NoirArtifactTranslator for NoirV1Beta9Translator {
    fn supports(&self, version: &Version, target: TranslationTarget) -> bool {
        if target != TranslationTarget::Acir046 {
            return false;
        }
        version.major == 1
            && version.minor == 0
            && version.patch == 0
            && version
                .pre
                .as_str()
                .strip_prefix("beta.")
                .is_some_and(|suffix| suffix == "9")
    }

    fn translate(
        &self,
        artifact: &Value,
        _noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        if target != TranslationTarget::Acir046 {
            return Err(ZkfError::UnsupportedBackend {
                backend: "frontend-translator/noir-beta9".to_string(),
                message: format!("unsupported translation target {:?}", target),
            });
        }

        let beta_program = parse_beta9_program(artifact)?;
        let (acir_program, witness_hints) = convert_program_beta9_to_046(&beta_program)?;
        let mut out = serde_json::Map::new();

        if let Some(name) = artifact.get("name") {
            out.insert("name".to_string(), name.clone());
        }
        out.insert(
            "program".to_string(),
            serde_json::to_value(acir_program)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?,
        );
        if !witness_hints.is_empty() {
            out.insert(
                "witness_hints".to_string(),
                serde_json::to_value(witness_hints)
                    .map_err(|err| ZkfError::Serialization(err.to_string()))?,
            );
        }
        out.insert(
            "translated_by".to_string(),
            Value::String("noir-v1-beta9->acir0.46".to_string()),
        );

        Ok(Value::Object(out))
    }
}

struct NoirV1ProgramJsonTranslator;

struct NoirV1Beta19Translator;

impl NoirArtifactTranslator for NoirV1Beta19Translator {
    fn supports(&self, version: &Version, target: TranslationTarget) -> bool {
        if target != TranslationTarget::Acir046 {
            return false;
        }
        version.major == 1
            && version.minor == 0
            && version.patch == 0
            && version
                .pre
                .as_str()
                .strip_prefix("beta.")
                .is_some_and(|suffix| suffix == "19")
    }

    fn translate(
        &self,
        artifact: &Value,
        _noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        if target != TranslationTarget::Acir046 {
            return Err(ZkfError::UnsupportedBackend {
                backend: "frontend-translator/noir-beta19".to_string(),
                message: format!("unsupported translation target {:?}", target),
            });
        }

        let beta_program = parse_beta19_program(artifact)?;
        let (acir_program, witness_hints) = convert_program_beta19_to_046(&beta_program)?;
        let mut out = serde_json::Map::new();

        if let Some(name) = artifact.get("name") {
            out.insert("name".to_string(), name.clone());
        }
        out.insert(
            "program".to_string(),
            serde_json::to_value(acir_program)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?,
        );
        if !witness_hints.is_empty() {
            out.insert(
                "witness_hints".to_string(),
                serde_json::to_value(witness_hints)
                    .map_err(|err| ZkfError::Serialization(err.to_string()))?,
            );
        }
        out.insert(
            "translated_by".to_string(),
            Value::String("noir-v1-beta19->acir0.46".to_string()),
        );

        Ok(Value::Object(out))
    }
}

impl NoirArtifactTranslator for NoirV1ProgramJsonTranslator {
    fn supports(&self, version: &Version, target: TranslationTarget) -> bool {
        target == TranslationTarget::Acir046 && version.major >= 1
    }

    fn translate(
        &self,
        artifact: &Value,
        _noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        translate_program_json_artifact(
            artifact,
            target,
            "frontend-translator/noir-v1-program-json",
            "noir-v1-program-json->acir0.46",
        )
    }
}

struct NoirV1Beta10Translator;

impl NoirArtifactTranslator for NoirV1Beta10Translator {
    fn supports(&self, version: &Version, target: TranslationTarget) -> bool {
        if target != TranslationTarget::Acir046 {
            return false;
        }
        version.major == 1
            && version.minor == 0
            && version.patch == 0
            && version
                .pre
                .as_str()
                .strip_prefix("beta.")
                .is_some_and(|suffix| suffix == "10")
    }

    fn translate(
        &self,
        artifact: &Value,
        _noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        translate_program_json_artifact(
            artifact,
            target,
            "frontend-translator/noir-beta10",
            "noir-v1-beta10->acir0.46",
        )
    }
}

struct NoirV1StableTranslator;

impl NoirArtifactTranslator for NoirV1StableTranslator {
    fn supports(&self, version: &Version, target: TranslationTarget) -> bool {
        target == TranslationTarget::Acir046 && version.major == 1 && version.pre.is_empty()
    }

    fn translate(
        &self,
        artifact: &Value,
        _noir_version: &str,
        target: TranslationTarget,
    ) -> ZkfResult<Value> {
        translate_program_json_artifact(
            artifact,
            target,
            "frontend-translator/noir-v1-stable",
            "noir-v1-stable->acir0.46",
        )
    }
}

fn translate_program_json_artifact(
    artifact: &Value,
    target: TranslationTarget,
    backend_id: &str,
    translated_by: &str,
) -> ZkfResult<Value> {
    if target != TranslationTarget::Acir046 {
        return Err(ZkfError::UnsupportedBackend {
            backend: backend_id.to_string(),
            message: format!("unsupported translation target {:?}", target),
        });
    }

    let program_value = artifact
        .get("program")
        .ok_or_else(|| ZkfError::UnsupportedBackend {
            backend: backend_id.to_string(),
            message:
                "translator requires artifact `program` JSON payload for unsupported noir_version"
                    .to_string(),
        })?;
    let parsed_program: AcirProgram =
        serde_json::from_value(program_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize artifact `program` as acir 0.46: {err}"
            ))
        })?;

    let mut out = serde_json::Map::new();
    if let Some(name) = artifact.get("name") {
        out.insert("name".to_string(), name.clone());
    }
    out.insert(
        "program".to_string(),
        serde_json::to_value(parsed_program)
            .map_err(|err| ZkfError::Serialization(err.to_string()))?,
    );
    if let Some(witness_hints) = artifact.get("witness_hints") {
        out.insert("witness_hints".to_string(), witness_hints.clone());
    }
    out.insert(
        "translated_by".to_string(),
        Value::String(translated_by.to_string()),
    );

    Ok(Value::Object(out))
}

fn parse_noir_version(raw: &str) -> ZkfResult<Version> {
    Version::parse(raw).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "invalid noir_version '{raw}' for translation: {err}"
        ))
    })
}

fn parse_beta9_program(artifact: &Value) -> ZkfResult<Beta9Program<Beta9FieldElement>> {
    if let Some(program) = artifact.get("program") {
        return serde_json::from_value(program.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize beta.9 program JSON: {err}"))
        });
    }

    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "noir artifact translation requires 'bytecode' or 'program'".to_string(),
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

fn parse_beta19_program(artifact: &Value) -> ZkfResult<Beta19Program<Beta19FieldElement>> {
    if let Some(program) = artifact.get("program") {
        return serde_json::from_value(program.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to deserialize beta.19 program JSON: {err}"))
        });
    }

    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "noir artifact translation requires 'bytecode' or 'program'".to_string(),
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

fn convert_program_beta9_to_046(
    program: &Beta9Program<Beta9FieldElement>,
) -> ZkfResult<(AcirProgram, Vec<WitnessHint>)> {
    let mut witness_hints = Vec::new();
    let functions = program
        .functions
        .iter()
        .enumerate()
        .map(|(function_index, circuit)| {
            convert_circuit_beta9_to_046(circuit, function_index, &mut witness_hints)
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok((
        AcirProgram {
            functions,
            unconstrained_functions: Vec::new(),
        },
        witness_hints,
    ))
}

fn convert_program_beta19_to_046(
    program: &Beta19Program<Beta19FieldElement>,
) -> ZkfResult<(AcirProgram, Vec<WitnessHint>)> {
    let mut witness_hints = Vec::new();
    let functions = program
        .functions
        .iter()
        .enumerate()
        .map(|(function_index, circuit)| {
            convert_circuit_beta19_to_046(circuit, function_index, &mut witness_hints)
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok((
        AcirProgram {
            functions,
            unconstrained_functions: Vec::new(),
        },
        witness_hints,
    ))
}

fn convert_circuit_beta9_to_046(
    circuit: &Beta9Circuit<Beta9FieldElement>,
    function_index: usize,
    witness_hints: &mut Vec<WitnessHint>,
) -> ZkfResult<AcirCircuit> {
    let mut next_witness_index = circuit.current_witness_index.saturating_add(1);
    let mut opcodes = Vec::new();
    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        opcodes.extend(convert_opcode_beta9_to_046(
            opcode,
            function_index,
            opcode_index,
            witness_hints,
            &mut next_witness_index,
        )?);
    }

    let private_parameters = circuit
        .private_parameters
        .iter()
        .map(|witness| convert_witness_beta9_to_046(*witness))
        .collect();
    let public_parameters = AcirPublicInputs(
        circuit
            .public_parameters
            .indices()
            .into_iter()
            .map(AcirWitness)
            .collect(),
    );
    let return_values = AcirPublicInputs(
        circuit
            .return_values
            .indices()
            .into_iter()
            .map(AcirWitness)
            .collect(),
    );
    Ok(AcirCircuit {
        current_witness_index: next_witness_index.saturating_sub(1),
        opcodes,
        expression_width: convert_expression_width_beta9_to_046(circuit.expression_width),
        private_parameters,
        public_parameters,
        return_values,
        assert_messages: Vec::new(),
        recursive: false,
    })
}

fn convert_circuit_beta19_to_046(
    circuit: &Beta19Circuit<Beta19FieldElement>,
    function_index: usize,
    witness_hints: &mut Vec<WitnessHint>,
) -> ZkfResult<AcirCircuit> {
    let mut next_witness_index = circuit.current_witness_index.saturating_add(1);
    let mut opcodes = Vec::new();
    for (opcode_index, opcode) in circuit.opcodes.iter().enumerate() {
        opcodes.extend(convert_opcode_beta19_to_046(
            opcode,
            function_index,
            opcode_index,
            witness_hints,
            &mut next_witness_index,
        )?);
    }

    let private_parameters = circuit
        .private_parameters
        .iter()
        .map(|witness| convert_witness_beta19_to_046(*witness))
        .collect();
    let public_parameters = AcirPublicInputs(
        circuit
            .public_parameters
            .indices()
            .into_iter()
            .map(AcirWitness)
            .collect(),
    );
    let return_values = AcirPublicInputs(
        circuit
            .return_values
            .indices()
            .into_iter()
            .map(AcirWitness)
            .collect(),
    );
    Ok(AcirCircuit {
        current_witness_index: next_witness_index.saturating_sub(1),
        opcodes,
        expression_width: AcirExpressionWidth::Unbounded,
        private_parameters,
        public_parameters,
        return_values,
        assert_messages: Vec::new(),
        recursive: false,
    })
}

fn convert_expression_width_beta9_to_046(width: Beta9ExpressionWidth) -> AcirExpressionWidth {
    match width {
        Beta9ExpressionWidth::Unbounded => AcirExpressionWidth::Unbounded,
        Beta9ExpressionWidth::Bounded { width } => AcirExpressionWidth::Bounded { width },
    }
}

fn convert_opcode_beta9_to_046(
    opcode: &Beta9Opcode<Beta9FieldElement>,
    function_index: usize,
    opcode_index: usize,
    witness_hints: &mut Vec<WitnessHint>,
    next_witness_index: &mut u32,
) -> ZkfResult<Vec<AcirOpcode>> {
    match opcode {
        Beta9Opcode::AssertZero(expression) => Ok(vec![AcirOpcode::AssertZero(
            convert_expression_beta9_to_046(expression),
        )]),
        Beta9Opcode::BlackBoxFuncCall(call) => {
            let (mut prelude, translated) =
                convert_black_box_call_beta9_to_046(call, next_witness_index)?;
            prelude.push(AcirOpcode::BlackBoxFuncCall(translated));
            Ok(prelude)
        }
        Beta9Opcode::MemoryOp {
            block_id,
            op,
            predicate,
        } => Ok(vec![AcirOpcode::MemoryOp {
            block_id: acir::circuit::opcodes::BlockId(block_id.0),
            op: acir::circuit::opcodes::MemOp {
                operation: convert_expression_beta9_to_046(&op.operation),
                index: convert_expression_beta9_to_046(&op.index),
                value: convert_expression_beta9_to_046(&op.value),
            },
            predicate: predicate.as_ref().map(convert_expression_beta9_to_046),
        }]),
        Beta9Opcode::MemoryInit { block_id, init, .. } => Ok(vec![AcirOpcode::MemoryInit {
            block_id: acir::circuit::opcodes::BlockId(block_id.0),
            init: init.iter().map(|w| AcirWitness(w.0)).collect(),
        }]),
        Beta9Opcode::BrilligCall { outputs, .. } => {
            for (output_index, output) in outputs.iter().enumerate() {
                match output {
                    acir_beta9::circuit::brillig::BrilligOutputs::Simple(witness) => {
                        witness_hints.push(WitnessHint {
                            target: format!("w{}", witness.0),
                            source: format!(
                                "__brillig_f{function_index}_op{opcode_index}_out{output_index}"
                            ),
                            kind: WitnessHintKind::Copy,
                        });
                    }
                    acir_beta9::circuit::brillig::BrilligOutputs::Array(witnesses) => {
                        for (array_index, witness) in witnesses.iter().enumerate() {
                            witness_hints.push(WitnessHint {
                                target: format!("w{}", witness.0),
                                source: format!(
                                    "__brillig_f{function_index}_op{opcode_index}_out{output_index}_{array_index}"
                                ),
                                kind: WitnessHintKind::Copy,
                            });
                        }
                    }
                }
            }
            Ok(Vec::new())
        }
        Beta9Opcode::Call {
            id,
            inputs,
            outputs,
            predicate,
        } => Ok(vec![AcirOpcode::Call {
            id: id.0,
            inputs: inputs.iter().map(|w| AcirWitness(w.0)).collect(),
            outputs: outputs.iter().map(|w| AcirWitness(w.0)).collect(),
            predicate: predicate.as_ref().map(convert_expression_beta9_to_046),
        }]),
    }
}

fn convert_opcode_beta19_to_046(
    opcode: &Beta19Opcode<Beta19FieldElement>,
    function_index: usize,
    opcode_index: usize,
    witness_hints: &mut Vec<WitnessHint>,
    next_witness_index: &mut u32,
) -> ZkfResult<Vec<AcirOpcode>> {
    match opcode {
        Beta19Opcode::AssertZero(expression) => Ok(vec![AcirOpcode::AssertZero(
            convert_expression_beta19_to_046(expression),
        )]),
        Beta19Opcode::BlackBoxFuncCall(call) => {
            let (mut prelude, translated) =
                convert_black_box_call_beta19_to_046(call, next_witness_index)?;
            prelude.push(AcirOpcode::BlackBoxFuncCall(translated));
            Ok(prelude)
        }
        Beta19Opcode::MemoryOp { block_id, op } => Ok(vec![AcirOpcode::MemoryOp {
            block_id: acir::circuit::opcodes::BlockId(block_id.0),
            op: acir::circuit::opcodes::MemOp {
                operation: convert_expression_beta19_to_046(&op.operation),
                index: convert_expression_beta19_to_046(&op.index),
                value: convert_expression_beta19_to_046(&op.value),
            },
            predicate: None,
        }]),
        Beta19Opcode::MemoryInit { block_id, init, .. } => Ok(vec![AcirOpcode::MemoryInit {
            block_id: acir::circuit::opcodes::BlockId(block_id.0),
            init: init.iter().map(|w| AcirWitness(w.0)).collect(),
        }]),
        Beta19Opcode::BrilligCall { outputs, .. } => {
            for (output_index, output) in outputs.iter().enumerate() {
                match output {
                    acir_beta19::circuit::brillig::BrilligOutputs::Simple(witness) => {
                        witness_hints.push(WitnessHint {
                            target: format!("w{}", witness.0),
                            source: format!(
                                "__brillig_f{function_index}_op{opcode_index}_out{output_index}"
                            ),
                            kind: WitnessHintKind::Copy,
                        });
                    }
                    acir_beta19::circuit::brillig::BrilligOutputs::Array(witnesses) => {
                        for (array_index, witness) in witnesses.iter().enumerate() {
                            witness_hints.push(WitnessHint {
                                target: format!("w{}", witness.0),
                                source: format!(
                                    "__brillig_f{function_index}_op{opcode_index}_out{output_index}_{array_index}"
                                ),
                                kind: WitnessHintKind::Copy,
                            });
                        }
                    }
                }
            }
            Ok(Vec::new())
        }
        Beta19Opcode::Call {
            id,
            inputs,
            outputs,
            predicate,
        } => Ok(vec![AcirOpcode::Call {
            id: id.0,
            inputs: inputs.iter().map(|w| AcirWitness(w.0)).collect(),
            outputs: outputs.iter().map(|w| AcirWitness(w.0)).collect(),
            predicate: Some(convert_expression_beta19_to_046(predicate)),
        }]),
    }
}

fn convert_black_box_call_beta9_to_046(
    call: &Beta9BlackBoxFuncCall<Beta9FieldElement>,
    next_witness_index: &mut u32,
) -> ZkfResult<(Vec<AcirOpcode>, AcirBlackBoxFuncCall)> {
    let mut prelude = Vec::new();
    let translated = match call {
        Beta9BlackBoxFuncCall::AES128Encrypt {
            inputs,
            iv,
            key,
            outputs,
        } => AcirBlackBoxFuncCall::AES128Encrypt {
            inputs: convert_function_inputs_beta9_to_046(
                inputs,
                "AES128Encrypt inputs",
                &mut prelude,
                next_witness_index,
            )?,
            iv: convert_function_input_box_array_beta9_to_046::<16>(
                iv,
                "AES128Encrypt iv",
                &mut prelude,
                next_witness_index,
            )?,
            key: convert_function_input_box_array_beta9_to_046::<16>(
                key,
                "AES128Encrypt key",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: outputs
                .iter()
                .map(|w| convert_witness_beta9_to_046(*w))
                .collect(),
        },
        Beta9BlackBoxFuncCall::RANGE { input } => AcirBlackBoxFuncCall::RANGE {
            input: convert_function_input_beta9_to_046(
                input,
                "RANGE input",
                &mut prelude,
                next_witness_index,
            )?,
        },
        Beta9BlackBoxFuncCall::AND { lhs, rhs, output } => AcirBlackBoxFuncCall::AND {
            lhs: convert_function_input_beta9_to_046(
                lhs,
                "AND lhs",
                &mut prelude,
                next_witness_index,
            )?,
            rhs: convert_function_input_beta9_to_046(
                rhs,
                "AND rhs",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta9_to_046(*output),
        },
        Beta9BlackBoxFuncCall::XOR { lhs, rhs, output } => AcirBlackBoxFuncCall::XOR {
            lhs: convert_function_input_beta9_to_046(
                lhs,
                "XOR lhs",
                &mut prelude,
                next_witness_index,
            )?,
            rhs: convert_function_input_beta9_to_046(
                rhs,
                "XOR rhs",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta9_to_046(*output),
        },
        Beta9BlackBoxFuncCall::Blake2s { inputs, outputs } => AcirBlackBoxFuncCall::Blake2s {
            inputs: convert_function_inputs_beta9_to_046(
                inputs,
                "Blake2s inputs",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: Box::new(std::array::from_fn(|i| {
                convert_witness_beta9_to_046(outputs[i])
            })),
        },
        Beta9BlackBoxFuncCall::Blake3 { inputs, outputs } => AcirBlackBoxFuncCall::Blake3 {
            inputs: convert_function_inputs_beta9_to_046(
                inputs,
                "Blake3 inputs",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: Box::new(std::array::from_fn(|i| {
                convert_witness_beta9_to_046(outputs[i])
            })),
        },
        Beta9BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            output,
        } => AcirBlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x: convert_function_input_box_array_beta9_to_046::<32>(
                public_key_x,
                "EcdsaSecp256k1 public_key_x",
                &mut prelude,
                next_witness_index,
            )?,
            public_key_y: convert_function_input_box_array_beta9_to_046::<32>(
                public_key_y,
                "EcdsaSecp256k1 public_key_y",
                &mut prelude,
                next_witness_index,
            )?,
            signature: convert_function_input_box_array_beta9_to_046::<64>(
                signature,
                "EcdsaSecp256k1 signature",
                &mut prelude,
                next_witness_index,
            )?,
            hashed_message: convert_function_input_box_array_beta9_to_046::<32>(
                hashed_message,
                "EcdsaSecp256k1 hashed_message",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta9_to_046(*output),
        },
        Beta9BlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            output,
        } => AcirBlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x: convert_function_input_box_array_beta9_to_046::<32>(
                public_key_x,
                "EcdsaSecp256r1 public_key_x",
                &mut prelude,
                next_witness_index,
            )?,
            public_key_y: convert_function_input_box_array_beta9_to_046::<32>(
                public_key_y,
                "EcdsaSecp256r1 public_key_y",
                &mut prelude,
                next_witness_index,
            )?,
            signature: convert_function_input_box_array_beta9_to_046::<64>(
                signature,
                "EcdsaSecp256r1 signature",
                &mut prelude,
                next_witness_index,
            )?,
            hashed_message: convert_function_input_box_array_beta9_to_046::<32>(
                hashed_message,
                "EcdsaSecp256r1 hashed_message",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta9_to_046(*output),
        },
        Beta9BlackBoxFuncCall::Keccakf1600 { inputs, outputs } => {
            AcirBlackBoxFuncCall::Keccakf1600 {
                inputs: convert_function_input_box_array_beta9_to_046::<25>(
                    inputs,
                    "Keccakf1600 inputs",
                    &mut prelude,
                    next_witness_index,
                )?,
                outputs: Box::new(std::array::from_fn(|i| {
                    convert_witness_beta9_to_046(outputs[i])
                })),
            }
        }
        Beta9BlackBoxFuncCall::BigIntAdd { lhs, rhs, output } => AcirBlackBoxFuncCall::BigIntAdd {
            lhs: *lhs,
            rhs: *rhs,
            output: *output,
        },
        Beta9BlackBoxFuncCall::BigIntSub { lhs, rhs, output } => AcirBlackBoxFuncCall::BigIntSub {
            lhs: *lhs,
            rhs: *rhs,
            output: *output,
        },
        Beta9BlackBoxFuncCall::BigIntMul { lhs, rhs, output } => AcirBlackBoxFuncCall::BigIntMul {
            lhs: *lhs,
            rhs: *rhs,
            output: *output,
        },
        Beta9BlackBoxFuncCall::BigIntDiv { lhs, rhs, output } => AcirBlackBoxFuncCall::BigIntDiv {
            lhs: *lhs,
            rhs: *rhs,
            output: *output,
        },
        Beta9BlackBoxFuncCall::BigIntFromLeBytes {
            inputs,
            modulus,
            output,
        } => AcirBlackBoxFuncCall::BigIntFromLeBytes {
            inputs: convert_function_inputs_beta9_to_046(
                inputs,
                "BigIntFromLeBytes inputs",
                &mut prelude,
                next_witness_index,
            )?,
            modulus: modulus.clone(),
            output: *output,
        },
        Beta9BlackBoxFuncCall::BigIntToLeBytes { input, outputs } => {
            AcirBlackBoxFuncCall::BigIntToLeBytes {
                input: *input,
                outputs: outputs
                    .iter()
                    .map(|w| convert_witness_beta9_to_046(*w))
                    .collect(),
            }
        }
        Beta9BlackBoxFuncCall::Poseidon2Permutation {
            inputs,
            outputs,
            len,
        } => AcirBlackBoxFuncCall::Poseidon2Permutation {
            inputs: convert_function_inputs_beta9_to_046(
                inputs,
                "Poseidon2Permutation inputs",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: outputs
                .iter()
                .map(|w| convert_witness_beta9_to_046(*w))
                .collect(),
            len: *len,
        },
        Beta9BlackBoxFuncCall::Sha256Compression {
            inputs,
            hash_values,
            outputs,
        } => AcirBlackBoxFuncCall::Sha256Compression {
            inputs: convert_function_input_box_array_beta9_to_046::<16>(
                inputs,
                "Sha256Compression inputs",
                &mut prelude,
                next_witness_index,
            )?,
            hash_values: convert_function_input_box_array_beta9_to_046::<8>(
                hash_values,
                "Sha256Compression hash_values",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: Box::new(std::array::from_fn(|i| {
                convert_witness_beta9_to_046(outputs[i])
            })),
        },
        _ => {
            return Err(ZkfError::InvalidArtifact(format!(
                "translator does not support black-box opcode '{}'",
                call.name()
            )));
        }
    };
    Ok((prelude, translated))
}

fn convert_black_box_call_beta19_to_046(
    call: &Beta19BlackBoxFuncCall<Beta19FieldElement>,
    next_witness_index: &mut u32,
) -> ZkfResult<(Vec<AcirOpcode>, AcirBlackBoxFuncCall)> {
    let mut prelude = Vec::new();
    let translated = match call {
        Beta19BlackBoxFuncCall::AES128Encrypt {
            inputs,
            iv,
            key,
            outputs,
        } => AcirBlackBoxFuncCall::AES128Encrypt {
            inputs: convert_function_inputs_beta19_to_046(
                inputs,
                8,
                "AES128Encrypt inputs",
                &mut prelude,
                next_witness_index,
            )?,
            iv: convert_function_input_box_array_beta19_to_046::<16>(
                iv,
                8,
                "AES128Encrypt iv",
                &mut prelude,
                next_witness_index,
            )?,
            key: convert_function_input_box_array_beta19_to_046::<16>(
                key,
                8,
                "AES128Encrypt key",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: outputs
                .iter()
                .map(|w| convert_witness_beta19_to_046(*w))
                .collect(),
        },
        Beta19BlackBoxFuncCall::RANGE { input, num_bits } => AcirBlackBoxFuncCall::RANGE {
            input: convert_function_input_beta19_to_046(
                input,
                *num_bits,
                "RANGE input",
                &mut prelude,
                next_witness_index,
            )?,
        },
        Beta19BlackBoxFuncCall::AND {
            lhs,
            rhs,
            num_bits,
            output,
        } => AcirBlackBoxFuncCall::AND {
            lhs: convert_function_input_beta19_to_046(
                lhs,
                *num_bits,
                "AND lhs",
                &mut prelude,
                next_witness_index,
            )?,
            rhs: convert_function_input_beta19_to_046(
                rhs,
                *num_bits,
                "AND rhs",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta19_to_046(*output),
        },
        Beta19BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits,
            output,
        } => AcirBlackBoxFuncCall::XOR {
            lhs: convert_function_input_beta19_to_046(
                lhs,
                *num_bits,
                "XOR lhs",
                &mut prelude,
                next_witness_index,
            )?,
            rhs: convert_function_input_beta19_to_046(
                rhs,
                *num_bits,
                "XOR rhs",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta19_to_046(*output),
        },
        Beta19BlackBoxFuncCall::Blake2s { inputs, outputs } => AcirBlackBoxFuncCall::Blake2s {
            inputs: convert_function_inputs_beta19_to_046(
                inputs,
                8,
                "Blake2s inputs",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: Box::new(std::array::from_fn(|i| {
                convert_witness_beta19_to_046(outputs[i])
            })),
        },
        Beta19BlackBoxFuncCall::Blake3 { inputs, outputs } => AcirBlackBoxFuncCall::Blake3 {
            inputs: convert_function_inputs_beta19_to_046(
                inputs,
                8,
                "Blake3 inputs",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: Box::new(std::array::from_fn(|i| {
                convert_witness_beta19_to_046(outputs[i])
            })),
        },
        Beta19BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            output,
            ..
        } => AcirBlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x: convert_function_input_box_array_beta19_to_046::<32>(
                public_key_x,
                8,
                "EcdsaSecp256k1 public_key_x",
                &mut prelude,
                next_witness_index,
            )?,
            public_key_y: convert_function_input_box_array_beta19_to_046::<32>(
                public_key_y,
                8,
                "EcdsaSecp256k1 public_key_y",
                &mut prelude,
                next_witness_index,
            )?,
            signature: convert_function_input_box_array_beta19_to_046::<64>(
                signature,
                8,
                "EcdsaSecp256k1 signature",
                &mut prelude,
                next_witness_index,
            )?,
            hashed_message: convert_function_input_box_array_beta19_to_046::<32>(
                hashed_message,
                8,
                "EcdsaSecp256k1 hashed_message",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta19_to_046(*output),
        },
        Beta19BlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            output,
            ..
        } => AcirBlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x: convert_function_input_box_array_beta19_to_046::<32>(
                public_key_x,
                8,
                "EcdsaSecp256r1 public_key_x",
                &mut prelude,
                next_witness_index,
            )?,
            public_key_y: convert_function_input_box_array_beta19_to_046::<32>(
                public_key_y,
                8,
                "EcdsaSecp256r1 public_key_y",
                &mut prelude,
                next_witness_index,
            )?,
            signature: convert_function_input_box_array_beta19_to_046::<64>(
                signature,
                8,
                "EcdsaSecp256r1 signature",
                &mut prelude,
                next_witness_index,
            )?,
            hashed_message: convert_function_input_box_array_beta19_to_046::<32>(
                hashed_message,
                8,
                "EcdsaSecp256r1 hashed_message",
                &mut prelude,
                next_witness_index,
            )?,
            output: convert_witness_beta19_to_046(*output),
        },
        Beta19BlackBoxFuncCall::MultiScalarMul {
            points,
            scalars,
            outputs,
            ..
        } => {
            let infinity = convert_witness_beta19_to_046(outputs.2);
            prelude.push(AcirOpcode::AssertZero(AcirExpression {
                mul_terms: Vec::new(),
                linear_combinations: vec![(AcirFieldElement::from(1_i128), infinity)],
                q_c: AcirFieldElement::from(0_i128),
            }));
            AcirBlackBoxFuncCall::MultiScalarMul {
                points: convert_function_inputs_beta19_to_046(
                    points,
                    254,
                    "MultiScalarMul points",
                    &mut prelude,
                    next_witness_index,
                )?,
                scalars: convert_function_inputs_beta19_to_046(
                    scalars,
                    254,
                    "MultiScalarMul scalars",
                    &mut prelude,
                    next_witness_index,
                )?,
                outputs: (
                    convert_witness_beta19_to_046(outputs.0),
                    convert_witness_beta19_to_046(outputs.1),
                ),
            }
        }
        Beta19BlackBoxFuncCall::EmbeddedCurveAdd {
            input1,
            input2,
            outputs,
            ..
        } => {
            let infinity = convert_witness_beta19_to_046(outputs.2);
            prelude.push(AcirOpcode::AssertZero(AcirExpression {
                mul_terms: Vec::new(),
                linear_combinations: vec![(AcirFieldElement::from(1_i128), infinity)],
                q_c: AcirFieldElement::from(0_i128),
            }));
            AcirBlackBoxFuncCall::EmbeddedCurveAdd {
                input1_x: convert_function_input_beta19_to_046(
                    &input1[0],
                    254,
                    "EmbeddedCurveAdd input1_x",
                    &mut prelude,
                    next_witness_index,
                )?,
                input1_y: convert_function_input_beta19_to_046(
                    &input1[1],
                    254,
                    "EmbeddedCurveAdd input1_y",
                    &mut prelude,
                    next_witness_index,
                )?,
                input2_x: convert_function_input_beta19_to_046(
                    &input2[0],
                    254,
                    "EmbeddedCurveAdd input2_x",
                    &mut prelude,
                    next_witness_index,
                )?,
                input2_y: convert_function_input_beta19_to_046(
                    &input2[1],
                    254,
                    "EmbeddedCurveAdd input2_y",
                    &mut prelude,
                    next_witness_index,
                )?,
                outputs: (
                    convert_witness_beta19_to_046(outputs.0),
                    convert_witness_beta19_to_046(outputs.1),
                ),
            }
        }
        Beta19BlackBoxFuncCall::Keccakf1600 { inputs, outputs } => {
            AcirBlackBoxFuncCall::Keccakf1600 {
                inputs: convert_function_input_box_array_beta19_to_046::<25>(
                    inputs,
                    64,
                    "Keccakf1600 inputs",
                    &mut prelude,
                    next_witness_index,
                )?,
                outputs: Box::new(std::array::from_fn(|i| {
                    convert_witness_beta19_to_046(outputs[i])
                })),
            }
        }
        Beta19BlackBoxFuncCall::RecursiveAggregation {
            verification_key,
            proof,
            public_inputs,
            key_hash,
            ..
        } => AcirBlackBoxFuncCall::RecursiveAggregation {
            verification_key: convert_function_inputs_beta19_to_046(
                verification_key,
                254,
                "RecursiveAggregation verification_key",
                &mut prelude,
                next_witness_index,
            )?,
            proof: convert_function_inputs_beta19_to_046(
                proof,
                254,
                "RecursiveAggregation proof",
                &mut prelude,
                next_witness_index,
            )?,
            public_inputs: convert_function_inputs_beta19_to_046(
                public_inputs,
                254,
                "RecursiveAggregation public_inputs",
                &mut prelude,
                next_witness_index,
            )?,
            key_hash: convert_function_input_beta19_to_046(
                key_hash,
                254,
                "RecursiveAggregation key_hash",
                &mut prelude,
                next_witness_index,
            )?,
        },
        Beta19BlackBoxFuncCall::Poseidon2Permutation {
            inputs, outputs, ..
        } => AcirBlackBoxFuncCall::Poseidon2Permutation {
            inputs: convert_function_inputs_beta19_to_046(
                inputs,
                254,
                "Poseidon2Permutation inputs",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: outputs
                .iter()
                .map(|w| convert_witness_beta19_to_046(*w))
                .collect(),
            len: outputs.len() as u32,
        },
        Beta19BlackBoxFuncCall::Sha256Compression {
            inputs,
            hash_values,
            outputs,
        } => AcirBlackBoxFuncCall::Sha256Compression {
            inputs: convert_function_input_box_array_beta19_to_046::<16>(
                inputs,
                32,
                "Sha256Compression inputs",
                &mut prelude,
                next_witness_index,
            )?,
            hash_values: convert_function_input_box_array_beta19_to_046::<8>(
                hash_values,
                32,
                "Sha256Compression hash_values",
                &mut prelude,
                next_witness_index,
            )?,
            outputs: Box::new(std::array::from_fn(|i| {
                convert_witness_beta19_to_046(outputs[i])
            })),
        },
    };
    Ok((prelude, translated))
}

fn convert_function_input_beta9_to_046(
    input: &Beta9FunctionInput<Beta9FieldElement>,
    _context: &str,
    prelude: &mut Vec<AcirOpcode>,
    next_witness_index: &mut u32,
) -> ZkfResult<AcirFunctionInput> {
    let witness = match input.input() {
        Beta9ConstantOrWitness::Witness(witness) => convert_witness_beta9_to_046(witness),
        Beta9ConstantOrWitness::Constant(constant) => {
            let witness = AcirWitness(*next_witness_index);
            *next_witness_index = (*next_witness_index).saturating_add(1);
            let constant_046 = convert_field_element_beta9_to_046(constant);
            let assert_constant = AcirExpression {
                mul_terms: Vec::new(),
                linear_combinations: vec![(AcirFieldElement::from(1_i128), witness)],
                q_c: -constant_046,
            };
            prelude.push(AcirOpcode::AssertZero(assert_constant));
            witness
        }
    };
    Ok(AcirFunctionInput {
        witness,
        num_bits: input.num_bits(),
    })
}

fn convert_function_input_beta19_to_046(
    input: &Beta19FunctionInput<Beta19FieldElement>,
    num_bits: u32,
    _context: &str,
    prelude: &mut Vec<AcirOpcode>,
    next_witness_index: &mut u32,
) -> ZkfResult<AcirFunctionInput> {
    let witness = match input {
        Beta19FunctionInput::Witness(witness) => convert_witness_beta19_to_046(*witness),
        Beta19FunctionInput::Constant(constant) => {
            let witness = AcirWitness(*next_witness_index);
            *next_witness_index = (*next_witness_index).saturating_add(1);
            let constant_046 = convert_field_element_beta19_to_046(*constant);
            let assert_constant = AcirExpression {
                mul_terms: Vec::new(),
                linear_combinations: vec![(AcirFieldElement::from(1_i128), witness)],
                q_c: -constant_046,
            };
            prelude.push(AcirOpcode::AssertZero(assert_constant));
            witness
        }
    };
    Ok(AcirFunctionInput { witness, num_bits })
}

fn convert_function_inputs_beta9_to_046(
    inputs: &[Beta9FunctionInput<Beta9FieldElement>],
    context: &str,
    prelude: &mut Vec<AcirOpcode>,
    next_witness_index: &mut u32,
) -> ZkfResult<Vec<AcirFunctionInput>> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            convert_function_input_beta9_to_046(
                input,
                &format!("{context}[{index}]"),
                prelude,
                next_witness_index,
            )
        })
        .collect()
}

fn convert_function_inputs_beta19_to_046(
    inputs: &[Beta19FunctionInput<Beta19FieldElement>],
    num_bits: u32,
    context: &str,
    prelude: &mut Vec<AcirOpcode>,
    next_witness_index: &mut u32,
) -> ZkfResult<Vec<AcirFunctionInput>> {
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            convert_function_input_beta19_to_046(
                input,
                num_bits,
                &format!("{context}[{index}]"),
                prelude,
                next_witness_index,
            )
        })
        .collect()
}

fn convert_function_input_box_array_beta9_to_046<const N: usize>(
    inputs: &[Beta9FunctionInput<Beta9FieldElement>; N],
    context: &str,
    prelude: &mut Vec<AcirOpcode>,
    next_witness_index: &mut u32,
) -> ZkfResult<Box<[AcirFunctionInput; N]>> {
    let converted = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            convert_function_input_beta9_to_046(
                input,
                &format!("{context}[{index}]"),
                prelude,
                next_witness_index,
            )
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let boxed_slice = converted.into_boxed_slice();
    boxed_slice.try_into().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "translator failed to convert fixed-size input array for {context}"
        ))
    })
}

fn convert_function_input_box_array_beta19_to_046<const N: usize>(
    inputs: &[Beta19FunctionInput<Beta19FieldElement>; N],
    num_bits: u32,
    context: &str,
    prelude: &mut Vec<AcirOpcode>,
    next_witness_index: &mut u32,
) -> ZkfResult<Box<[AcirFunctionInput; N]>> {
    let converted = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            convert_function_input_beta19_to_046(
                input,
                num_bits,
                &format!("{context}[{index}]"),
                prelude,
                next_witness_index,
            )
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let boxed_slice = converted.into_boxed_slice();
    boxed_slice.try_into().map_err(|_| {
        ZkfError::InvalidArtifact(format!(
            "translator failed to convert fixed-size input array for {context}"
        ))
    })
}

fn convert_expression_beta9_to_046(
    expression: &Beta9Expression<Beta9FieldElement>,
) -> AcirExpression {
    AcirExpression {
        mul_terms: expression
            .mul_terms
            .iter()
            .map(|(coeff, lhs, rhs)| {
                (
                    convert_field_element_beta9_to_046(*coeff),
                    convert_witness_beta9_to_046(*lhs),
                    convert_witness_beta9_to_046(*rhs),
                )
            })
            .collect(),
        linear_combinations: expression
            .linear_combinations
            .iter()
            .map(|(coeff, witness)| {
                (
                    convert_field_element_beta9_to_046(*coeff),
                    convert_witness_beta9_to_046(*witness),
                )
            })
            .collect(),
        q_c: convert_field_element_beta9_to_046(expression.q_c),
    }
}

fn convert_expression_beta19_to_046(
    expression: &Beta19Expression<Beta19FieldElement>,
) -> AcirExpression {
    AcirExpression {
        mul_terms: expression
            .mul_terms
            .iter()
            .map(|(coeff, lhs, rhs)| {
                (
                    convert_field_element_beta19_to_046(*coeff),
                    convert_witness_beta19_to_046(*lhs),
                    convert_witness_beta19_to_046(*rhs),
                )
            })
            .collect(),
        linear_combinations: expression
            .linear_combinations
            .iter()
            .map(|(coeff, witness)| {
                (
                    convert_field_element_beta19_to_046(*coeff),
                    convert_witness_beta19_to_046(*witness),
                )
            })
            .collect(),
        q_c: convert_field_element_beta19_to_046(expression.q_c),
    }
}

fn convert_witness_beta9_to_046(witness: Beta9Witness) -> AcirWitness {
    AcirWitness(witness.0)
}

fn convert_witness_beta19_to_046(witness: Beta19Witness) -> AcirWitness {
    AcirWitness(witness.0)
}

fn convert_field_element_beta9_to_046(value: Beta9FieldElement) -> AcirFieldElement {
    AcirFieldElement::from_be_bytes_reduce(&value.to_be_bytes())
}

fn convert_field_element_beta19_to_046(value: Beta19FieldElement) -> AcirFieldElement {
    AcirFieldElement::from_be_bytes_reduce(&value.to_be_bytes())
}
