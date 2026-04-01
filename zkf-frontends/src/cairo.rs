// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe, FrontendProgram,
};
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use zkf_core::ir::LookupTable;
use zkf_core::{
    BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, ToolRequirement,
    Visibility, Witness, WitnessAssignment, WitnessHint, WitnessHintKind, WitnessInputs,
    WitnessPlan, ZkfError, ZkfResult, program_v2_to_zir, program_zir_to_v2, zir_v1,
};

/// Cairo/StarkNet frontend for importing Sierra IR into the ZKF pipeline.
///
/// Accepts:
/// - Sierra JSON (`sierra_json` or `sierra_json_path`)
/// - Pre-compiled ZKF program descriptor (`program` / `compiled_ir_path`)
/// - Build hook (`build_command`) for invoking `scarb build` or `cairo-compile`
///
/// Sierra IR is StarkNet's intermediate representation, sitting between Cairo
/// source and CASM (Cairo Assembly). This frontend translates Sierra's flat
/// typed instruction set into ZKF IR constraints.
pub struct CairoFrontend;

/// A minimal parsed Sierra program for translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SierraProgram {
    #[serde(default)]
    pub type_declarations: Vec<SierraTypeDecl>,
    #[serde(default)]
    pub libfunc_declarations: Vec<SierraLibfuncDecl>,
    #[serde(default)]
    pub statements: Vec<SierraStatement>,
    #[serde(default)]
    pub funcs: Vec<SierraFunc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SierraTypeDecl {
    pub id: Value,
    #[serde(default)]
    pub long_id: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SierraLibfuncDecl {
    pub id: Value,
    #[serde(default)]
    pub long_id: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SierraStatement {
    #[serde(flatten)]
    pub data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SierraFunc {
    pub id: Value,
    #[serde(default)]
    pub signature: Option<Value>,
    #[serde(default)]
    pub params: Vec<Value>,
}

// ---------------------------------------------------------------------------
// Stateful translation context
// ---------------------------------------------------------------------------

/// Tracks mutable state accumulated during a single Sierra → ZKF translation
/// pass. Keeps variable-to-signal mappings, array region tracking, and an
/// auto-incrementing auxiliary name counter.
struct SierraTranslationState {
    /// Maps Sierra variable IDs to canonical signal names.
    var_map: BTreeMap<u64, String>,
    /// Tracks live arrays by their canonical signal-name prefix.
    arrays: BTreeMap<String, ArrayState>,
    /// Maps enum type names to their number of variants.
    enum_types: BTreeMap<String, usize>,
    /// Maps struct type names to the ordered list of field signal-name
    /// suffixes.
    struct_types: BTreeMap<String, Vec<String>>,
    /// Counter used to give every auxiliary signal a unique suffix.
    aux_counter: usize,
    /// Accumulates coverage information: how many libfunc invocations were
    /// handled natively vs emitted as unsupported BlackBox markers.
    handled_count: usize,
    unhandled_count: usize,
}

/// Tracks a Sierra array that has been `array_new`-ed but not yet dropped.
#[derive(Clone)]
struct ArrayState {
    /// Base name used for all element signals of this array.
    region_name: String,
    /// Signal name carrying the current logical length of the array.
    length_signal: String,
}

impl SierraTranslationState {
    fn new() -> Self {
        Self {
            var_map: BTreeMap::new(),
            arrays: BTreeMap::new(),
            enum_types: BTreeMap::new(),
            struct_types: BTreeMap::new(),
            aux_counter: 0,
            handled_count: 0,
            unhandled_count: 0,
        }
    }

    /// Allocate a fresh auxiliary signal name with the given prefix.
    fn next_aux(&mut self, prefix: &str) -> String {
        let name = format!("__{prefix}_{}", self.aux_counter);
        self.aux_counter += 1;
        name
    }

    /// Return the canonical signal name for a Sierra variable ID.
    /// Falls back to `__sierra_aux_{id}` if not explicitly mapped.
    #[allow(dead_code)]
    fn signal_for_var(&self, id: u64) -> String {
        self.var_map
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("__sierra_aux_{id}"))
    }

    /// Register a Sierra variable ID → signal name binding.
    fn bind_var(&mut self, id: u64, name: String) {
        self.var_map.insert(id, name);
    }
}

// ---------------------------------------------------------------------------
// FrontendEngine implementation
// ---------------------------------------------------------------------------

impl FrontendEngine for CairoFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Cairo
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Cairo,
            can_compile_to_ir: true,
            can_execute: true,
            input_formats: vec![
                "sierra-json".to_string(),
                "cairo-descriptor-json".to_string(),
                "zkf-program-json".to_string(),
                "zkf-zir-program-json".to_string(),
            ],
            notes: "Cairo frontend imports Sierra IR (JSON) into ZKF. \
                    Supports descriptor-based import with optional build hooks \
                    (e.g., `scarb build`), direct ZIR loading for stateful Cairo/StarkNet flows, \
                    and descriptor-driven execution via `execute_command`. Native Sierra → \
                    constraint translation handles the supported felt252/integer/enum/struct/\
                    memory/control-flow subset. Unsupported Sierra libfuncs fail closed during \
                    import instead of being silently lowered to fallback BlackBox constraints."
                .to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let is_sierra =
            value.get("type_declarations").is_some() && value.get("libfunc_declarations").is_some();
        let is_descriptor = value.get("sierra_json").is_some()
            || value.get("sierra_json_path").is_some()
            || value.get("build_command").is_some()
            || value.get("program").is_some()
            || value.get("zir_program").is_some()
            || value.get("compiled_zir_path").is_some()
            || value.get("execute_command").is_some();

        let accepted = is_sierra || is_descriptor;
        FrontendProbe {
            accepted,
            format: if is_sierra {
                Some("sierra-json".to_string())
            } else if is_descriptor {
                Some("cairo-descriptor-json".to_string())
            } else {
                None
            },
            noir_version: None,
            notes: if accepted {
                vec![]
            } else {
                vec![
                    "expected Sierra JSON or Cairo descriptor with \
                     `sierra_json`/`sierra_json_path`/`program`/`build_command`"
                        .to_string(),
                ]
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        // Run optional build hook first (e.g., `scarb build`).
        if let Some(command) = value.get("build_command").and_then(Value::as_str) {
            run_build_command(command)?;
        }

        validate_cairo_descriptor(value)?;

        // Try loading a pre-compiled ZKF program.
        if let Some(program_value) = value.get("program").or(value.get("ir_program")) {
            let mut program: Program =
                serde_json::from_value(program_value.clone()).map_err(|err| {
                    ZkfError::InvalidArtifact(format!(
                        "failed to deserialize embedded program for Cairo frontend: {err}"
                    ))
                })?;
            if let Some(name) = options.program_name.as_ref() {
                program.name = name.clone();
            }
            if let Some(field) = options.field {
                program.field = field;
            }
            return Ok(program);
        }

        if let Some(path) = value.get("compiled_ir_path").and_then(Value::as_str) {
            let content = fs::read_to_string(path).map_err(|err| {
                ZkfError::Io(format!("failed reading compiled_ir_path '{path}': {err}"))
            })?;
            let mut program: Program = serde_json::from_str(&content).map_err(|err| {
                ZkfError::InvalidArtifact(format!(
                    "failed to deserialize program from '{path}': {err}"
                ))
            })?;
            if let Some(name) = options.program_name.as_ref() {
                program.name = name.clone();
            }
            if let Some(field) = options.field {
                program.field = field;
            }
            return Ok(program);
        }

        if descriptor_has_zir_program(value) {
            let zir_program = load_cairo_zir_program(value, options)?;
            if zir_requires_program_family(&zir_program)
                || descriptor_requests_stateful_family(value)
            {
                return Err(ZkfError::UnsupportedBackend {
                    backend: "frontend/cairo/compile-to-ir".to_string(),
                    message: "Cairo descriptor requires ZIR v1 because it carries stateful or \
                              toolchain-backed semantics that ir-v2 cannot represent losslessly; \
                              use compile_to_program_family()/`--ir-family zir-v1` instead."
                        .to_string(),
                });
            }
            return program_zir_to_v2(&zir_program);
        }

        // Try parsing Sierra JSON directly.
        let sierra = load_sierra(value)?;
        let program = translate_sierra_to_program(&sierra, options)?;
        let unsupported = unsupported_sierra_libfunc_counts(&program);
        if unsupported_requires_toolchain_zir(&unsupported)
            && matches!(
                options.ir_family,
                crate::IrFamilyPreference::Auto | crate::IrFamilyPreference::ZirV1
            )
        {
            return Err(ZkfError::UnsupportedBackend {
                backend: "frontend/cairo/compile-to-ir".to_string(),
                message: format!(
                    "Cairo import hit placeholder-only libfunc surface(s) {:?}; provide \
                     `zir_program` or `compiled_zir_path` after running your Cairo/StarkNet \
                     build step so those semantics stay in ZIR instead of falling back to \
                     placeholder BlackBox constraints.",
                    unsupported.keys().collect::<Vec<_>>()
                ),
            });
        }
        ensure_supported_sierra_translation(&program)?;
        Ok(program)
    }

    fn compile_to_program_family(
        &self,
        value: &Value,
        options: &FrontendImportOptions,
    ) -> ZkfResult<FrontendProgram> {
        if let Some(command) = value.get("build_command").and_then(Value::as_str) {
            run_build_command(command)?;
        }

        validate_cairo_descriptor(value)?;

        if descriptor_has_zir_program(value) {
            let zir_program = load_cairo_zir_program(value, options)?;
            if options.ir_family == crate::IrFamilyPreference::IrV2 {
                if zir_requires_program_family(&zir_program)
                    || descriptor_requests_stateful_family(value)
                {
                    return Err(ZkfError::UnsupportedBackend {
                        backend: "frontend/cairo/compile-to-ir".to_string(),
                        message: "Cairo descriptor requires ZIR v1 because it carries stateful or \
                                  toolchain-backed semantics that ir-v2 cannot represent \
                                  losslessly."
                            .to_string(),
                    });
                }
                return program_zir_to_v2(&zir_program).map(FrontendProgram::IrV2);
            }
            return Ok(FrontendProgram::ZirV1(zir_program));
        }

        if value.get("program").is_some()
            || value.get("ir_program").is_some()
            || value.get("compiled_ir_path").is_some()
        {
            let program = self.compile_to_ir(value, options)?;
            return Ok(match options.ir_family {
                crate::IrFamilyPreference::ZirV1 => {
                    FrontendProgram::ZirV1(program_v2_to_zir(&program))
                }
                _ => FrontendProgram::IrV2(program),
            });
        }

        let sierra = load_sierra(value)?;
        let program = translate_sierra_to_program(&sierra, options)?;
        let unsupported = unsupported_sierra_libfunc_counts(&program);
        if unsupported_requires_toolchain_zir(&unsupported) {
            return Err(ZkfError::UnsupportedBackend {
                backend: "frontend/cairo/compile-to-program-family".to_string(),
                message: format!(
                    "Cairo import hit placeholder-only libfunc surface(s) {:?}; provide \
                     `zir_program` or `compiled_zir_path` so arrays, generic calls, StarkNet \
                     storage/syscalls, and EC/state flows stay in ZIR instead of falling back \
                     to placeholder BlackBox constraints.",
                    unsupported.keys().collect::<Vec<_>>()
                ),
            });
        }
        ensure_supported_sierra_translation(&program)?;

        Ok(match options.ir_family {
            crate::IrFamilyPreference::ZirV1 => FrontendProgram::ZirV1(program_v2_to_zir(&program)),
            _ => FrontendProgram::IrV2(program),
        })
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let (funcs, types, stmts, blackbox_counts, dropped_features, requires_hints) =
            if let Ok(sierra) = load_sierra(value) {
                let translated =
                    translate_sierra_to_program(&sierra, &FrontendImportOptions::default()).ok();
                let (blackbox_counts, dropped_features, requires_hints) = translated
                    .as_ref()
                    .map(|program| {
                        let blackbox_counts = unsupported_sierra_libfunc_counts(program);
                        let dropped_features = blackbox_counts.keys().cloned().collect::<Vec<_>>();
                        let requires_hints = !program.witness_plan.hints.is_empty();
                        (blackbox_counts, dropped_features, requires_hints)
                    })
                    .unwrap_or_else(|| (BTreeMap::new(), Vec::new(), false));
                (
                    sierra.funcs.len(),
                    sierra.type_declarations.len(),
                    sierra.statements.len(),
                    blackbox_counts,
                    dropped_features,
                    requires_hints,
                )
            } else {
                (0, 0, 0, BTreeMap::new(), Vec::new(), false)
            };

        let mut opcode_counts = BTreeMap::new();
        opcode_counts.insert("sierra_types".to_string(), types);
        opcode_counts.insert("sierra_statements".to_string(), stmts);

        Ok(FrontendInspection {
            frontend: FrontendKind::Cairo,
            format: probe.format,
            version: None,
            functions: funcs,
            unconstrained_functions: 0,
            opcode_counts,
            blackbox_counts,
            required_capabilities: Vec::new(),
            dropped_features,
            requires_hints,
        })
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "scarb".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Cairo package manager and build tool".to_string()),
                required: false,
            },
            ToolRequirement {
                tool: "cairo-compile".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Cairo to Sierra compiler".to_string()),
                required: false,
            },
        ]
    }

    fn execute(&self, value: &Value, _inputs: &WitnessInputs) -> ZkfResult<Witness> {
        validate_cairo_descriptor(value)?;
        if let Some(command) = value.get("execute_command").and_then(Value::as_str) {
            run_cairo_command(command, "Cairo execute command")?;
        }
        load_cairo_witness(value)
    }
}

// ---------------------------------------------------------------------------
// Sierra loading helpers
// ---------------------------------------------------------------------------

fn load_sierra(value: &Value) -> ZkfResult<SierraProgram> {
    // Direct Sierra JSON.
    if value.get("type_declarations").is_some() {
        return serde_json::from_value(value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to parse Sierra JSON: {err}"))
        });
    }

    // Embedded Sierra.
    if let Some(sierra_value) = value.get("sierra_json") {
        return serde_json::from_value(sierra_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!("failed to parse sierra_json: {err}"))
        });
    }

    // Sierra from path.
    if let Some(path) = value.get("sierra_json_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        let content = fs::read_to_string(&path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading sierra_json_path '{}': {err}",
                path.display()
            ))
        })?;
        return serde_json::from_str(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to parse Sierra from '{}': {err}",
                path.display()
            ))
        });
    }

    Err(ZkfError::InvalidArtifact(
        "Cairo descriptor must include Sierra JSON, `sierra_json`, `sierra_json_path`, \
         or a pre-compiled `program`"
            .to_string(),
    ))
}

fn descriptor_has_zir_program(value: &Value) -> bool {
    value.get("zir_program").is_some() || value.get("compiled_zir_path").is_some()
}

fn descriptor_requests_stateful_family(value: &Value) -> bool {
    [
        "state_source",
        "rpc_url",
        "snapshot_path",
        "contract_address",
        "entrypoint",
        "calldata",
        "block_id",
        "execute_command",
    ]
    .into_iter()
    .any(|key| value.get(key).is_some())
}

fn unsupported_requires_toolchain_zir(unsupported: &BTreeMap<String, usize>) -> bool {
    !unsupported.is_empty()
        && unsupported.keys().all(|name| {
            matches!(
                name.as_str(),
                "array_get"
                    | "array_pop_front"
                    | "function_call"
                    | "storage_read"
                    | "storage_write"
            ) || name.starts_with("ec_point_from_x_nz")
                || name.starts_with("ec_state_")
        })
}

fn validate_cairo_descriptor(value: &Value) -> ZkfResult<()> {
    let state_source = value.get("state_source").and_then(Value::as_str);
    let has_rpc = value.get("rpc_url").is_some();
    let has_snapshot = value.get("snapshot_path").is_some();

    if let Some(source) = state_source {
        match source {
            "rpc" => {
                if !has_rpc {
                    return Err(ZkfError::InvalidArtifact(
                        "Cairo descriptor with `state_source=rpc` must include `rpc_url`"
                            .to_string(),
                    ));
                }
            }
            "snapshot" => {
                if !has_snapshot {
                    return Err(ZkfError::InvalidArtifact(
                        "Cairo descriptor with `state_source=snapshot` must include `snapshot_path`"
                            .to_string(),
                    ));
                }
            }
            other => {
                return Err(ZkfError::InvalidArtifact(format!(
                    "unsupported Cairo `state_source` '{other}' (expected `rpc` or `snapshot`)"
                )));
            }
        }
    }

    if has_rpc && has_snapshot {
        return Err(ZkfError::InvalidArtifact(
            "Cairo descriptor must choose either `rpc_url` or `snapshot_path` as the primary \
             state source, not both"
                .to_string(),
        ));
    }

    if descriptor_requests_stateful_family(value) {
        if value.get("entrypoint").is_some() && value.get("contract_address").is_none() {
            return Err(ZkfError::InvalidArtifact(
                "Cairo descriptor with `entrypoint` must also provide `contract_address`"
                    .to_string(),
            ));
        }
        if value.get("calldata").is_some() && value.get("entrypoint").is_none() {
            return Err(ZkfError::InvalidArtifact(
                "Cairo descriptor with `calldata` must also provide `entrypoint`".to_string(),
            ));
        }
    }

    Ok(())
}

fn load_cairo_zir_program(
    value: &Value,
    options: &FrontendImportOptions,
) -> ZkfResult<zir_v1::Program> {
    let mut program = if let Some(program_value) = value.get("zir_program") {
        serde_json::from_value(program_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize embedded ZIR program for Cairo frontend: {err}"
            ))
        })?
    } else if let Some(path) = value.get("compiled_zir_path").and_then(Value::as_str) {
        let content = fs::read_to_string(path).map_err(|err| {
            ZkfError::Io(format!("failed reading compiled_zir_path '{path}': {err}"))
        })?;
        serde_json::from_str::<zir_v1::Program>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize ZIR program from '{path}': {err}"
            ))
        })?
    } else {
        return Err(ZkfError::InvalidArtifact(
            "Cairo descriptor missing `zir_program` or `compiled_zir_path`".to_string(),
        ));
    };

    if let Some(name) = options.program_name.as_ref() {
        program.name = name.clone();
    }
    if let Some(field) = options.field {
        program.field = field;
    }

    program.metadata.insert(
        "frontend".to_string(),
        FrontendKind::Cairo.as_str().to_string(),
    );
    program.metadata.insert(
        "source_format".to_string(),
        "cairo-descriptor-json".to_string(),
    );
    copy_descriptor_metadata(value, &mut program.metadata);

    Ok(program)
}

fn zir_requires_program_family(program: &zir_v1::Program) -> bool {
    program.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            zir_v1::Constraint::CustomGate { .. }
                | zir_v1::Constraint::MemoryRead { .. }
                | zir_v1::Constraint::MemoryWrite { .. }
        )
    }) || program.metadata.contains_key("cairo_state_source")
}

fn copy_descriptor_metadata(value: &Value, metadata: &mut BTreeMap<String, String>) {
    copy_string_metadata(value, metadata, "state_source", "cairo_state_source");
    copy_string_metadata(value, metadata, "rpc_url", "cairo_rpc_url");
    copy_string_metadata(value, metadata, "snapshot_path", "cairo_snapshot_path");
    copy_string_metadata(
        value,
        metadata,
        "contract_address",
        "cairo_contract_address",
    );
    copy_string_metadata(value, metadata, "entrypoint", "cairo_entrypoint");
    copy_string_metadata(value, metadata, "block_id", "cairo_block_id");
    copy_string_metadata(value, metadata, "execute_command", "cairo_execute_command");
    if let Some(calldata) = value.get("calldata") {
        metadata.insert("cairo_calldata".to_string(), calldata.to_string());
    }
}

fn copy_string_metadata(
    value: &Value,
    metadata: &mut BTreeMap<String, String>,
    key: &str,
    metadata_key: &str,
) {
    if let Some(raw) = value.get(key) {
        if let Some(as_str) = raw.as_str() {
            metadata.insert(metadata_key.to_string(), as_str.to_string());
        } else {
            metadata.insert(metadata_key.to_string(), raw.to_string());
        }
    }
}

fn load_cairo_witness(value: &Value) -> ZkfResult<Witness> {
    if let Some(witness_value) = value.get("witness") {
        return serde_json::from_value(witness_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize embedded witness for Cairo frontend: {err}"
            ))
        });
    }

    if let Some(path) = value.get("witness_path").and_then(Value::as_str) {
        let content = fs::read_to_string(path)
            .map_err(|err| ZkfError::Io(format!("failed reading witness_path '{path}': {err}")))?;
        return serde_json::from_str::<Witness>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize witness from '{path}': {err}"
            ))
        });
    }

    if let Some(witness_values) = value.get("witness_values").and_then(Value::as_object) {
        let mut values = BTreeMap::new();
        for (key, raw) in witness_values {
            let rendered = match raw {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                other => {
                    return Err(ZkfError::InvalidArtifact(format!(
                        "witness_values['{}'] must be string/number, found {}",
                        key, other
                    )));
                }
            };
            values.insert(key.clone(), FieldElement::new(rendered));
        }
        return Ok(Witness { values });
    }

    Err(ZkfError::UnsupportedBackend {
        backend: "frontend/cairo/execute".to_string(),
        message: "descriptor missing `witness`, `witness_path`, or `witness_values`".to_string(),
    })
}

fn run_cairo_command(command: &str, context: &str) -> ZkfResult<()> {
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

// ---------------------------------------------------------------------------
// Top-level Sierra → Program translation
// ---------------------------------------------------------------------------

/// Translate a parsed Sierra program into ZKF IR.
///
/// This performs a structural translation: Sierra's felt252 operations
/// map to field arithmetic constraints, and range check builtins map
/// to Range constraints. More complex Sierra operations (dictionaries,
/// arrays with dynamic size) are represented as unsupported BlackBox markers.
fn translate_sierra_to_program(
    sierra: &SierraProgram,
    options: &FrontendImportOptions,
) -> ZkfResult<Program> {
    let name = options
        .program_name
        .clone()
        .unwrap_or_else(|| "cairo_program".to_string());
    let field = options.field.unwrap_or(FieldId::Goldilocks);

    let mut signals: Vec<Signal> = Vec::new();
    let mut constraints: Vec<Constraint> = Vec::new();
    let mut witness_assignments: Vec<WitnessAssignment> = Vec::new();
    let mut witness_hints: Vec<WitnessHint> = Vec::new();
    let mut state = SierraTranslationState::new();

    // Pre-populate type information from type declarations.
    populate_type_info(sierra, &mut state);

    // Create signals from function parameters.
    for (func_idx, func) in sierra.funcs.iter().enumerate() {
        for (param_idx, param) in func.params.iter().enumerate() {
            let sig_name = format!("func{func_idx}_param{param_idx}");
            signals.push(Signal {
                name: sig_name.clone(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            });
            // If the param has an explicit variable ID, register it.
            if let Some(var_id) = param.get("id").and_then(Value::as_u64) {
                state.bind_var(var_id, sig_name);
            }
        }
    }

    // Translate Sierra statements to constraints.
    for (stmt_idx, stmt) in sierra.statements.iter().enumerate() {
        let data = &stmt.data;

        // Sierra invocations map to constraints.
        if let Some(invocation) = data.get("Invocation") {
            let libfunc_id = invocation
                .get("libfunc_id")
                .and_then(|v| v.get("id"))
                .and_then(Value::as_u64)
                .unwrap_or_default();

            let libfunc_name = resolve_libfunc_name(sierra, libfunc_id);

            // Collect output variable IDs so we can bind them after dispatch.
            let output_var_ids = extract_output_var_ids(invocation);

            // Primary output signal: either the first declared output var, or a
            // fresh aux signal that we guarantee uniqueness for.
            let aux_name = if let Some(&first_out) = output_var_ids.first() {
                let n = format!("__sierra_aux_{first_out}");
                state.bind_var(first_out, n.clone());
                n
            } else {
                format!("__sierra_aux_{stmt_idx}")
            };

            // Bind any additional output variable IDs.
            for (i, &oid) in output_var_ids.iter().enumerate().skip(1) {
                let n = format!("__sierra_aux_{oid}");
                state.bind_var(oid, n);
                let _ = i; // silence unused warning
            }

            // Always emit a private signal for the primary output.
            signals.push(Signal {
                name: aux_name.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });

            dispatch_libfunc(
                &libfunc_name,
                invocation,
                stmt_idx,
                &aux_name,
                &output_var_ids,
                &mut state,
                &mut signals,
                &mut constraints,
                &mut witness_assignments,
                &mut witness_hints,
            );
        }
    }

    Ok(Program {
        name,
        field,
        signals,
        constraints,
        lookup_tables: cairo_lookup_tables(),
        witness_plan: WitnessPlan {
            assignments: witness_assignments,
            hints: witness_hints,
            ..Default::default()
        },
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Type-declaration pre-pass
// ---------------------------------------------------------------------------

/// Walk Sierra type declarations to populate enum / struct metadata in `state`.
fn populate_type_info(sierra: &SierraProgram, state: &mut SierraTranslationState) {
    for decl in &sierra.type_declarations {
        if let Some(long_id) = &decl.long_id {
            let generic_id = long_id
                .get("generic_id")
                .or(long_id.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default();

            // Enum: generic_id = "Enum", generic_args list the variants.
            if generic_id.eq_ignore_ascii_case("Enum") {
                let type_name = decl
                    .id
                    .get("debug_name")
                    .or(decl.id.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let type_name = if type_name.is_empty() {
                    "unknown_enum".to_string()
                } else {
                    type_name
                };
                let variant_count = long_id
                    .get("generic_args")
                    .and_then(Value::as_array)
                    .map_or(2, |a| a.len());
                state.enum_types.insert(type_name, variant_count);
            }

            // Struct: generic_id = "Struct", generic_args list field types.
            if generic_id.eq_ignore_ascii_case("Struct") {
                let type_name = decl
                    .id
                    .get("debug_name")
                    .or(decl.id.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let type_name = if type_name.is_empty() {
                    "unknown_struct".to_string()
                } else {
                    type_name
                };
                let fields: Vec<String> = long_id
                    .get("generic_args")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .enumerate()
                            .map(|(i, _)| format!("field{i}"))
                            .collect()
                    })
                    .unwrap_or_default();
                state.struct_types.insert(type_name, fields);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Central dispatch
// ---------------------------------------------------------------------------

/// Route a single Sierra libfunc invocation to the appropriate constraint
/// generator. Increments `state.handled_count` / `state.unhandled_count`
/// accordingly.
#[allow(clippy::too_many_arguments)]
fn dispatch_libfunc(
    name: &str,
    invocation: &Value,
    stmt_idx: usize,
    aux_name: &str,
    output_var_ids: &[u64],
    state: &mut SierraTranslationState,
    signals: &mut Vec<Signal>,
    constraints: &mut Vec<Constraint>,
    _witness_assignments: &mut Vec<WitnessAssignment>,
    witness_hints: &mut Vec<WitnessHint>,
) {
    // -----------------------------------------------------------------------
    // felt252 arithmetic
    // -----------------------------------------------------------------------
    if name.contains("felt252_add") || name.contains("felt_add") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Add(args.iter().map(|a| Expr::Signal(a.clone())).collect()),
                label: Some(format!("sierra_add_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("felt252_mul") || name.contains("felt_mul") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_mul_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("felt252_sub") || name.contains("felt_sub") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Sub(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_sub_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // felt252_div: witness b_inv, constrain b * b_inv = 1, result = a * b_inv
    if name.contains("felt252_div") || name.contains("felt_div") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            let b_inv = state.next_aux("b_inv");
            signals.push(Signal {
                name: b_inv.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            // b * b_inv = 1
            constraints.push(Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal(args[1].clone())),
                    Box::new(Expr::Signal(b_inv.clone())),
                ),
                rhs: Expr::Const(FieldElement::from_i64(1)),
                label: Some(format!("sierra_div_inv_{stmt_idx}")),
            });
            // result = a * b_inv
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(b_inv.clone())),
                ),
                label: Some(format!("sierra_div_{stmt_idx}")),
            });
            // Witness hint: b_inv = 1 / b  (solver-side)
            witness_hints.push(WitnessHint {
                target: b_inv,
                source: args[1].clone(),
                kind: WitnessHintKind::InverseOrZero,
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // felt252_is_zero: is_zero ∈ {0,1};  signal * is_zero = 0;
    //                  (1 - is_zero) * inv = 1
    if name.contains("felt252_is_zero") || name.contains("felt_is_zero") {
        let args = extract_invocation_args(invocation);
        let signal_name = args
            .first()
            .cloned()
            .unwrap_or_else(|| "__felt_unknown".to_string());
        let inv_name = state.next_aux("is_zero_inv");
        signals.push(Signal {
            name: inv_name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        // aux_name IS the is_zero boolean result
        constraints.push(Constraint::Boolean {
            signal: aux_name.to_string(),
            label: Some(format!("sierra_is_zero_bool_{stmt_idx}")),
        });
        // signal * is_zero = 0
        constraints.push(Constraint::Equal {
            lhs: Expr::Mul(
                Box::new(Expr::Signal(signal_name.clone())),
                Box::new(Expr::Signal(aux_name.to_string())),
            ),
            rhs: Expr::Const(FieldElement::from_i64(0)),
            label: Some(format!("sierra_is_zero_prod_{stmt_idx}")),
        });
        // (1 - is_zero) * inv = 1
        constraints.push(Constraint::Equal {
            lhs: Expr::Mul(
                Box::new(Expr::Sub(
                    Box::new(Expr::Const(FieldElement::from_i64(1))),
                    Box::new(Expr::Signal(aux_name.to_string())),
                )),
                Box::new(Expr::Signal(inv_name.clone())),
            ),
            rhs: Expr::Const(FieldElement::from_i64(1)),
            label: Some(format!("sierra_is_zero_inv_{stmt_idx}")),
        });
        witness_hints.push(WitnessHint {
            target: inv_name,
            source: signal_name,
            kind: WitnessHintKind::InverseOrZero,
        });
        state.handled_count += 1;
        return;
    }

    // felt252_const / felt_const
    if name.contains("felt252_const") || name.contains("felt_const") {
        let const_val = invocation
            .get("libfunc_id")
            .and_then(|v| v.get("generic_args"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("Value"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let val: i64 = const_val.parse().unwrap_or_default();
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal(aux_name.to_string()),
            rhs: Expr::Const(FieldElement::from_i64(val)),
            label: Some(format!("sierra_const_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    // felt252_neg: result = 0 - a
    if name.contains("felt252_neg") || name.contains("felt_neg") {
        let args = extract_invocation_args(invocation);
        if let Some(a) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Sub(
                    Box::new(Expr::Const(FieldElement::from_i64(0))),
                    Box::new(Expr::Signal(a.clone())),
                ),
                label: Some(format!("sierra_neg_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Range check builtin
    // -----------------------------------------------------------------------
    if name.contains("range_check") {
        let args = extract_invocation_args(invocation);
        if let Some(arg) = args.first() {
            constraints.push(Constraint::Range {
                signal: arg.clone(),
                bits: 128,
                label: Some(format!("sierra_range_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Unsigned integer comparisons: u128_lt / u64_lt / u32_lt
    // diff = b - a - 1;  range(diff);  a + diff + 1 = b
    // -----------------------------------------------------------------------
    if name.contains("u128_lt")
        || name.contains("u64_lt")
        || name.contains("u32_lt")
        || name.contains("u8_lt")
        || name.contains("u16_lt")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            emit_ordering_boolean_result(
                "lt",
                bits,
                true,
                &args,
                stmt_idx,
                aux_name,
                state,
                signals,
                constraints,
            );
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // u128_le / u64_le / u32_le: same as lt but diff = b - a (no -1)
    if name.contains("u128_le")
        || name.contains("u64_le")
        || name.contains("u32_le")
        || name.contains("u8_le")
        || name.contains("u16_le")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            emit_ordering_boolean_result(
                "le",
                bits,
                false,
                &args,
                stmt_idx,
                aux_name,
                state,
                signals,
                constraints,
            );
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Overflowing addition: sum = result + overflow * 2^N
    // -----------------------------------------------------------------------
    if name.contains("u128_overflowing_add")
        || name.contains("u64_overflowing_add")
        || name.contains("u32_overflowing_add")
        || name.contains("u8_overflowing_add")
        || name.contains("u16_overflowing_add")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // aux_name = result (low part)
            // overflow flag is a second output
            let overflow = if output_var_ids.len() >= 2 {
                let n = format!("__sierra_aux_{}", output_var_ids[1]);
                state.bind_var(output_var_ids[1], n.clone());
                n
            } else {
                state.next_aux("overflow")
            };
            signals.push(Signal {
                name: overflow.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Boolean {
                signal: overflow.clone(),
                label: Some(format!("sierra_overflow_bool_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_add_result_range_{stmt_idx}")),
            });
            // a + b = result + overflow * 2^bits
            let two_pow = FieldElement::from_i64(1i64 << bits.min(62));
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[0].clone()),
                    Expr::Signal(args[1].clone()),
                ]),
                rhs: Expr::Add(vec![
                    Expr::Signal(aux_name.to_string()),
                    Expr::Mul(
                        Box::new(Expr::Signal(overflow)),
                        Box::new(Expr::Const(two_pow)),
                    ),
                ]),
                label: Some(format!("sierra_overflowing_add_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Overflowing subtraction: a = result + borrow * 2^N + b  (or similar)
    // -----------------------------------------------------------------------
    if name.contains("u128_overflowing_sub")
        || name.contains("u64_overflowing_sub")
        || name.contains("u32_overflowing_sub")
        || name.contains("u8_overflowing_sub")
        || name.contains("u16_overflowing_sub")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            let borrow = if output_var_ids.len() >= 2 {
                let n = format!("__sierra_aux_{}", output_var_ids[1]);
                state.bind_var(output_var_ids[1], n.clone());
                n
            } else {
                state.next_aux("borrow")
            };
            signals.push(Signal {
                name: borrow.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Boolean {
                signal: borrow.clone(),
                label: Some(format!("sierra_borrow_bool_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_sub_result_range_{stmt_idx}")),
            });
            // a + borrow * 2^bits = result + b  =>  a - b = result - borrow * 2^bits
            let two_pow = FieldElement::from_i64(1i64 << bits.min(62));
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[0].clone()),
                    Expr::Mul(
                        Box::new(Expr::Signal(borrow)),
                        Box::new(Expr::Const(two_pow)),
                    ),
                ]),
                rhs: Expr::Add(vec![
                    Expr::Signal(aux_name.to_string()),
                    Expr::Signal(args[1].clone()),
                ]),
                label: Some(format!("sierra_overflowing_sub_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Widening multiplication: u128_wide_mul → two 128-bit limbs
    // -----------------------------------------------------------------------
    if name.contains("u128_wide_mul")
        || name.contains("u64_wide_mul")
        || name.contains("u32_wide_mul")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // hi limb gets the second output var, or a fresh aux.
            let hi = if output_var_ids.len() >= 2 {
                let n = format!("__sierra_aux_{}", output_var_ids[1]);
                state.bind_var(output_var_ids[1], n.clone());
                n
            } else {
                state.next_aux("wide_hi")
            };
            signals.push(Signal {
                name: hi.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_wide_mul_lo_range_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: hi.clone(),
                bits,
                label: Some(format!("sierra_wide_mul_hi_range_{stmt_idx}")),
            });
            let two_pow = FieldElement::from_i64(1i64 << bits.min(62));
            // a * b = lo + hi * 2^bits
            constraints.push(Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                rhs: Expr::Add(vec![
                    Expr::Signal(aux_name.to_string()),
                    Expr::Mul(Box::new(Expr::Signal(hi)), Box::new(Expr::Const(two_pow))),
                ]),
                label: Some(format!("sierra_wide_mul_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Type conversions
    // -----------------------------------------------------------------------

    // felt252_to_u128 / into<felt252, u128>: range-constrain to 128 bits
    if name.contains("felt252_to_u128")
        || (name.contains("into") && name.contains("felt252") && name.contains("u128"))
    {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_felt_to_u128_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits: 128,
                label: Some(format!("sierra_felt_to_u128_range_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // u128_to_felt252 / into<u128, felt252>: identity (felt252 is wider)
    if name.contains("u128_to_felt252")
        || (name.contains("into") && name.contains("u128") && name.contains("felt252"))
    {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_u128_to_felt_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // Generic integer widening/narrowing (u8/u16/u32/u64 <-> u128 / felt252)
    if name.contains("_to_felt252")
        || name.contains("_to_u128")
        || name.contains("_to_u64")
        || name.contains("_to_u32")
        || name.contains("_to_u16")
        || name.contains("_to_u8")
    {
        let target_bits = if name.contains("felt252") {
            252
        } else {
            uint_bits_from_name(name)
        };
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_cast_{stmt_idx}")),
            });
            if target_bits < 252 {
                constraints.push(Constraint::Range {
                    signal: aux_name.to_string(),
                    bits: target_bits,
                    label: Some(format!("sierra_cast_range_{stmt_idx}")),
                });
            }
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // Generic `into` conversion by name matching
    if name.starts_with("into") || name.contains("::into") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_into_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Arrays
    // -----------------------------------------------------------------------
    if name.contains("array_new") {
        let array_key = aux_name.to_string();
        let len_signal = state.next_aux("arr_len");
        signals.push(Signal {
            name: len_signal.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal(len_signal.clone()),
            rhs: Expr::Const(FieldElement::from_i64(0)),
            label: Some(format!("sierra_array_new_len_{stmt_idx}")),
        });
        state.arrays.insert(
            array_key.clone(),
            ArrayState {
                region_name: array_key,
                length_signal: len_signal,
            },
        );
        state.handled_count += 1;
        return;
    }

    if name.contains("array_append") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            let arr_name = &args[0];
            let val_name = &args[1];
            // Copy the value into the array slot (conceptual)
            let slot = state.next_aux("arr_slot");
            signals.push(Signal {
                name: slot.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(slot),
                rhs: Expr::Signal(val_name.clone()),
                label: Some(format!("sierra_array_append_{stmt_idx}")),
            });
            // Increment conceptual length (we can only do this symbolically)
            if let Some(arr_state) = state.arrays.get(arr_name).cloned() {
                let new_len = state.next_aux("arr_len_inc");
                signals.push(Signal {
                    name: new_len.clone(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                });
                constraints.push(Constraint::Equal {
                    lhs: Expr::Signal(new_len.clone()),
                    rhs: Expr::Add(vec![
                        Expr::Signal(arr_state.length_signal.clone()),
                        Expr::Const(FieldElement::from_i64(1)),
                    ]),
                    label: Some(format!("sierra_array_append_len_{stmt_idx}")),
                });
                // Update state
                state.arrays.insert(
                    arr_name.clone(),
                    ArrayState {
                        region_name: arr_state.region_name,
                        length_signal: new_len,
                    },
                );
            }
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("array_get") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            let arr_name = &args[0];
            let idx_name = &args[1];
            // Dynamic array indexing emitted as BlackBox (resolved by backend at proving time)
            let mut params = BTreeMap::new();
            params.insert("sierra_op".to_string(), "array_get".to_string());
            params.insert("array".to_string(), arr_name.clone());
            params.insert("index".to_string(), idx_name.clone());
            constraints.push(Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                inputs: vec![
                    Expr::Signal(arr_name.clone()),
                    Expr::Signal(idx_name.clone()),
                ],
                outputs: vec![aux_name.to_string()],
                params,
                label: Some(format!("sierra_array_get_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("array_pop_front") {
        let args = extract_invocation_args(invocation);
        if let Some(arr_name) = args.first() {
            let mut params = BTreeMap::new();
            params.insert("sierra_op".to_string(), "array_pop_front".to_string());
            params.insert("array".to_string(), arr_name.clone());
            constraints.push(Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                inputs: vec![Expr::Signal(arr_name.clone())],
                outputs: vec![aux_name.to_string()],
                params,
                label: Some(format!("sierra_array_pop_front_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("array_len") || name.contains("array::len") {
        let args = extract_invocation_args(invocation);
        if let Some(arr_name) = args.first() {
            if let Some(arr_state) = state.arrays.get(arr_name).cloned() {
                constraints.push(Constraint::Equal {
                    lhs: Expr::Signal(aux_name.to_string()),
                    rhs: Expr::Signal(arr_state.length_signal),
                    label: Some(format!("sierra_array_len_{stmt_idx}")),
                });
            } else {
                // Array not tracked: emit a copy constraint as best effort
                constraints.push(Constraint::Equal {
                    lhs: Expr::Signal(aux_name.to_string()),
                    rhs: Expr::Signal(arr_name.clone()),
                    label: Some(format!("sierra_array_len_unknown_{stmt_idx}")),
                });
            }
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Enums
    // -----------------------------------------------------------------------
    if name.contains("enum_init") {
        // aux_name is the enum tag value
        let tag = extract_enum_tag_from_name(name);
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal(aux_name.to_string()),
            rhs: Expr::Const(FieldElement::from_i64(tag)),
            label: Some(format!("sierra_enum_init_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    if name.contains("enum_match") || name.contains("match_enum") {
        let args = extract_invocation_args(invocation);
        if let Some(enum_signal) = args.first() {
            // For each output (variant arm), emit a boolean selector:
            // selector_k = (enum_val == k) as a BlackBox (equality test)
            for (k, out_id) in output_var_ids.iter().enumerate() {
                let sel_name = format!("__sierra_aux_{out_id}");
                state.bind_var(*out_id, sel_name.clone());
                signals.push(Signal {
                    name: sel_name.clone(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                });
                // sel_k * (enum_val - k) = 0
                constraints.push(Constraint::Equal {
                    lhs: Expr::Mul(
                        Box::new(Expr::Signal(sel_name.clone())),
                        Box::new(Expr::Sub(
                            Box::new(Expr::Signal(enum_signal.clone())),
                            Box::new(Expr::Const(FieldElement::from_i64(k as i64))),
                        )),
                    ),
                    rhs: Expr::Const(FieldElement::from_i64(0)),
                    label: Some(format!("sierra_enum_match_{stmt_idx}_arm{k}")),
                });
                constraints.push(Constraint::Boolean {
                    signal: sel_name,
                    label: Some(format!("sierra_enum_match_bool_{stmt_idx}_arm{k}")),
                });
            }
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------
    if name.contains("struct_construct") {
        let args = extract_invocation_args(invocation);
        // Combine all fields into the struct signal by equality
        for (i, field_sig) in args.iter().enumerate() {
            let field_out = format!("{aux_name}_f{i}");
            signals.push(Signal {
                name: field_out.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(field_out),
                rhs: Expr::Signal(field_sig.clone()),
                label: Some(format!("sierra_struct_construct_{stmt_idx}_f{i}")),
            });
        }
        state.handled_count += 1;
        return;
    }

    if name.contains("struct_deconstruct") || name.contains("struct_destructure") {
        let args = extract_invocation_args(invocation);
        if let Some(struct_sig) = args.first() {
            for (i, out_id) in output_var_ids.iter().enumerate() {
                let field_name = format!("__sierra_aux_{out_id}");
                state.bind_var(*out_id, field_name.clone());
                signals.push(Signal {
                    name: field_name.clone(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                });
                constraints.push(Constraint::Equal {
                    lhs: Expr::Signal(field_name),
                    rhs: Expr::Signal(format!("{struct_sig}_f{i}")),
                    label: Some(format!("sierra_struct_deconstruct_{stmt_idx}_f{i}")),
                });
            }
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Memory / register operations
    // -----------------------------------------------------------------------

    // store_temp / rename: signal aliasing
    if name.contains("store_temp") || name.contains("rename") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_alias_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // drop: no constraint needed
    if name == "drop" || name.starts_with("drop<") || name.contains("::drop") {
        state.handled_count += 1;
        return;
    }

    // dup: copy constraint
    if name == "dup" || name.starts_with("dup<") || name.contains("::dup") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_dup_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // alloc_local / store_local / finalize_locals: track in state, no constraint
    if name.contains("alloc_local")
        || name.contains("store_local")
        || name.contains("finalize_locals")
    {
        let args = extract_invocation_args(invocation);
        if name.contains("store_local")
            && let Some(src) = args.first()
        {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_store_local_{stmt_idx}")),
            });
        }
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------

    // branch_align: no constraint
    if name.contains("branch_align") {
        state.handled_count += 1;
        return;
    }

    // jump: no constraint
    if name == "jump" || name.starts_with("jump<") {
        state.handled_count += 1;
        return;
    }

    // function_call: emitted as BlackBox (cross-function constraint translation
    // requires the callee to be inlined; the backend resolves the BlackBox at proving time)
    if name.contains("function_call") || name.contains("call") {
        let args = extract_invocation_args(invocation);
        let mut params = BTreeMap::new();
        params.insert("sierra_op".to_string(), "function_call".to_string());
        params.insert("callee".to_string(), name.to_string());
        constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: args.iter().map(|a| Expr::Signal(a.clone())).collect(),
            outputs: vec![aux_name.to_string()],
            params,
            label: Some(format!("sierra_function_call_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    // return: copy constraints for outputs
    if name == "return" || name.starts_with("return<") {
        let args = extract_invocation_args(invocation);
        for (i, arg) in args.iter().enumerate() {
            let ret_sig = format!("__return_{i}");
            signals.push(Signal {
                name: ret_sig.clone(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(ret_sig),
                rhs: Expr::Signal(arg.clone()),
                label: Some(format!("sierra_return_{stmt_idx}_{i}")),
            });
        }
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // StarkNet storage
    // -----------------------------------------------------------------------
    if name.contains("storage_read") {
        let args = extract_invocation_args(invocation);
        let mut params = BTreeMap::new();
        params.insert("sierra_op".to_string(), "storage_read".to_string());
        constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: args.iter().map(|a| Expr::Signal(a.clone())).collect(),
            outputs: vec![aux_name.to_string()],
            params,
            label: Some(format!("sierra_storage_read_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    if name.contains("storage_write") {
        let args = extract_invocation_args(invocation);
        let mut params = BTreeMap::new();
        params.insert("sierra_op".to_string(), "storage_write".to_string());
        constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: args.iter().map(|a| Expr::Signal(a.clone())).collect(),
            outputs: vec![aux_name.to_string()],
            params,
            label: Some(format!("sierra_storage_write_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // Poseidon / hash builtins
    // -----------------------------------------------------------------------
    if name.contains("poseidon") {
        let args = extract_invocation_args(invocation);
        constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: args.iter().map(|a| Expr::Signal(a.clone())).collect(),
            outputs: vec![aux_name.to_string()],
            params: BTreeMap::new(),
            label: Some(format!("sierra_poseidon_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    if name.contains("pedersen") {
        let args = extract_invocation_args(invocation);
        constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::Pedersen,
            inputs: args.iter().map(|a| Expr::Signal(a.clone())).collect(),
            outputs: vec![aux_name.to_string()],
            params: BTreeMap::new(),
            label: Some(format!("sierra_pedersen_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // Boolean operations (felt252 / u*  booleans)
    // -----------------------------------------------------------------------
    if name.contains("bool_and") || (name.contains("and") && name.contains("bool")) {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // AND = product of two booleans
            constraints.push(Constraint::Boolean {
                signal: aux_name.to_string(),
                label: Some(format!("sierra_bool_and_result_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_bool_and_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("bool_or") || (name.contains("or") && name.contains("bool")) {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // OR = a + b - a*b
            let prod = state.next_aux("bool_or_prod");
            signals.push(Signal {
                name: prod.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(prod.clone()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_bool_or_prod_{stmt_idx}")),
            });
            constraints.push(Constraint::Boolean {
                signal: aux_name.to_string(),
                label: Some(format!("sierra_bool_or_result_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Sub(
                    Box::new(Expr::Add(vec![
                        Expr::Signal(args[0].clone()),
                        Expr::Signal(args[1].clone()),
                    ])),
                    Box::new(Expr::Signal(prod)),
                ),
                label: Some(format!("sierra_bool_or_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("bool_not") || (name.contains("not") && name.contains("bool")) {
        let args = extract_invocation_args(invocation);
        if let Some(a) = args.first() {
            constraints.push(Constraint::Boolean {
                signal: aux_name.to_string(),
                label: Some(format!("sierra_bool_not_result_{stmt_idx}")),
            });
            // NOT a = 1 - a
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Sub(
                    Box::new(Expr::Const(FieldElement::from_i64(1))),
                    Box::new(Expr::Signal(a.clone())),
                ),
                label: Some(format!("sierra_bool_not_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Bitwise operations (u128 / u64 / u32)
    // -----------------------------------------------------------------------
    if name.contains("bitwise_and")
        || name.contains("u128_and")
        || name.contains("u64_and")
        || name.contains("u32_and")
        || name.contains("u8_and")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        let mut emitter = SierraEmitter {
            state,
            signals,
            constraints,
        };
        if emit_bitwise_lookup("and", bits, &args, stmt_idx, aux_name, &mut emitter) {
            emitter.state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, emitter.constraints, emitter.state);
        }
        return;
    }

    if name.contains("bitwise_or")
        || name.contains("u128_or")
        || name.contains("u64_or")
        || name.contains("u32_or")
        || name.contains("u8_or")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        let mut emitter = SierraEmitter {
            state,
            signals,
            constraints,
        };
        if emit_bitwise_lookup("or", bits, &args, stmt_idx, aux_name, &mut emitter) {
            emitter.state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, emitter.constraints, emitter.state);
        }
        return;
    }

    if name.contains("bitwise_xor")
        || name.contains("u128_xor")
        || name.contains("u64_xor")
        || name.contains("u32_xor")
        || name.contains("u8_xor")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        let mut emitter = SierraEmitter {
            state,
            signals,
            constraints,
        };
        if emit_bitwise_lookup("xor", bits, &args, stmt_idx, aux_name, &mut emitter) {
            emitter.state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, emitter.constraints, emitter.state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Equality checks (felt252_eq / u128_eq etc.)
    // -----------------------------------------------------------------------
    if name.contains("felt252_eq")
        || name.contains("u128_eq")
        || name.contains("u64_eq")
        || name.contains("u32_eq")
        || name.contains("u8_eq")
        || name.contains("bool_eq")
    {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // diff = a - b;  is_eq = is_zero(diff)
            let diff = state.next_aux("eq_diff");
            let inv = state.next_aux("eq_inv");
            signals.push(Signal {
                name: diff.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            signals.push(Signal {
                name: inv.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(diff.clone()),
                rhs: Expr::Sub(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_eq_diff_{stmt_idx}")),
            });
            constraints.push(Constraint::Boolean {
                signal: aux_name.to_string(),
                label: Some(format!("sierra_eq_bool_{stmt_idx}")),
            });
            // diff * is_eq = 0
            constraints.push(Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal(diff.clone())),
                    Box::new(Expr::Signal(aux_name.to_string())),
                ),
                rhs: Expr::Const(FieldElement::from_i64(0)),
                label: Some(format!("sierra_eq_prod_{stmt_idx}")),
            });
            // (1 - is_eq) * inv = 1  (so inv = 1/diff when diff != 0)
            constraints.push(Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Sub(
                        Box::new(Expr::Const(FieldElement::from_i64(1))),
                        Box::new(Expr::Signal(aux_name.to_string())),
                    )),
                    Box::new(Expr::Signal(inv.clone())),
                ),
                rhs: Expr::Const(FieldElement::from_i64(1)),
                label: Some(format!("sierra_eq_inv_{stmt_idx}")),
            });
            witness_hints.push(WitnessHint {
                target: inv,
                source: diff,
                kind: WitnessHintKind::InverseOrZero,
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Snapshot / desnap (Cairo's immutable reference pattern)
    // desnap must be checked before snapshot_take because "desnap" contains "snap".
    // -----------------------------------------------------------------------
    if name.contains("desnap") || name.contains("unsnap") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_desnap_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("snapshot_take") || name.contains("snap") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_snapshot_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Unwrap / panic variants (assert non-error path)
    // -----------------------------------------------------------------------
    if name.contains("unwrap_nz") || name.contains("non_zero") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            // Witness that it is nonzero: src * inv = 1
            let inv = state.next_aux("nz_inv");
            signals.push(Signal {
                name: inv.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal(src.clone())),
                    Box::new(Expr::Signal(inv.clone())),
                ),
                rhs: Expr::Const(FieldElement::from_i64(1)),
                label: Some(format!("sierra_nz_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_nz_copy_{stmt_idx}")),
            });
            witness_hints.push(WitnessHint {
                target: inv,
                source: src.clone(),
                kind: WitnessHintKind::InverseOrZero,
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Simple integer arithmetic: u{N}_add / u{N}_sub (non-overflowing)
    // -----------------------------------------------------------------------
    if (name.contains("u8_add")
        || name.contains("u16_add")
        || name.contains("u32_add")
        || name.contains("u64_add")
        || name.contains("u128_add"))
        && !name.contains("overflowing")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_uint_add_range_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Add(vec![
                    Expr::Signal(args[0].clone()),
                    Expr::Signal(args[1].clone()),
                ]),
                label: Some(format!("sierra_uint_add_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if (name.contains("u8_sub")
        || name.contains("u16_sub")
        || name.contains("u32_sub")
        || name.contains("u64_sub")
        || name.contains("u128_sub"))
        && !name.contains("overflowing")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_uint_sub_range_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Sub(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_uint_sub_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Simple integer multiplication: u{N}_mul (non-wide)
    // -----------------------------------------------------------------------
    if (name.contains("u8_mul")
        || name.contains("u16_mul")
        || name.contains("u32_mul")
        || name.contains("u64_mul")
        || name.contains("u128_mul"))
        && !name.contains("wide_mul")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_uint_mul_range_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_uint_mul_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Integer div_mod / divmod: q * divisor + r = dividend
    // -----------------------------------------------------------------------
    if name.contains("u8_div_mod")
        || name.contains("u16_div_mod")
        || name.contains("u32_div_mod")
        || name.contains("u64_div_mod")
        || name.contains("u128_div_mod")
        || name.contains("u8_divmod")
        || name.contains("u16_divmod")
        || name.contains("u32_divmod")
        || name.contains("u64_divmod")
        || name.contains("u128_divmod")
    {
        let bits = uint_bits_from_name(name);
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // aux_name = quotient; remainder is a second output
            let remainder = if output_var_ids.len() >= 2 {
                let n = format!("__sierra_aux_{}", output_var_ids[1]);
                state.bind_var(output_var_ids[1], n.clone());
                n
            } else {
                state.next_aux("remainder")
            };
            signals.push(Signal {
                name: remainder.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            // range(quotient, bits)
            constraints.push(Constraint::Range {
                signal: aux_name.to_string(),
                bits,
                label: Some(format!("sierra_divmod_q_range_{stmt_idx}")),
            });
            // range(remainder, bits)
            constraints.push(Constraint::Range {
                signal: remainder.clone(),
                bits,
                label: Some(format!("sierra_divmod_r_range_{stmt_idx}")),
            });
            // q * divisor + r = dividend
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Mul(
                        Box::new(Expr::Signal(aux_name.to_string())),
                        Box::new(Expr::Signal(args[1].clone())),
                    ),
                    Expr::Signal(remainder.clone()),
                ]),
                rhs: Expr::Signal(args[0].clone()),
                label: Some(format!("sierra_divmod_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Boolean: bool_xor_impl
    // -----------------------------------------------------------------------
    if name.contains("bool_xor") || (name.contains("xor") && name.contains("bool")) {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            // XOR = a + b - 2*a*b
            let prod = state.next_aux("bool_xor_prod");
            signals.push(Signal {
                name: prod.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(prod.clone()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[1].clone())),
                ),
                label: Some(format!("sierra_bool_xor_prod_{stmt_idx}")),
            });
            constraints.push(Constraint::Boolean {
                signal: aux_name.to_string(),
                label: Some(format!("sierra_bool_xor_result_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Sub(
                    Box::new(Expr::Add(vec![
                        Expr::Signal(args[0].clone()),
                        Expr::Signal(args[1].clone()),
                    ])),
                    Box::new(Expr::Mul(
                        Box::new(Expr::Const(FieldElement::from_i64(2))),
                        Box::new(Expr::Signal(prod)),
                    )),
                ),
                label: Some(format!("sierra_bool_xor_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Boolean: bool_to_felt252 (identity — bools are already field elements)
    // -----------------------------------------------------------------------
    if name.contains("bool_to_felt252") {
        let args = extract_invocation_args(invocation);
        if let Some(a) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(a.clone()),
                label: Some(format!("sierra_bool_to_felt252_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Control flow no-ops: disable_ap_tracking, enable_ap_tracking
    // -----------------------------------------------------------------------
    if name.contains("disable_ap_tracking") || name.contains("enable_ap_tracking") {
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // EC operations: ec_point_from_x_nz, ec_state_add, ec_state_finalize,
    //                ec_state_init
    // -----------------------------------------------------------------------
    if name.contains("ec_point_from_x_nz")
        || name.contains("ec_state_add")
        || name.contains("ec_state_finalize")
        || name.contains("ec_state_init")
    {
        let args = extract_invocation_args(invocation);
        let mut params = BTreeMap::new();
        params.insert("sierra_op".to_string(), name.to_string());
        constraints.push(Constraint::BlackBox {
            op: BlackBoxOp::EcdsaSecp256k1,
            inputs: args.iter().map(|a| Expr::Signal(a.clone())).collect(),
            outputs: vec![aux_name.to_string()],
            params,
            label: Some(format!("sierra_ec_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // Box / Snapshot: unbox, into_box, snapshot_take — identity / copy
    // -----------------------------------------------------------------------
    if name.contains("unbox") || name.contains("into_box") {
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_box_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // felt252 comparisons: felt252_lt, felt252_le
    // -----------------------------------------------------------------------
    if name.contains("felt252_lt") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            emit_ordering_boolean_result(
                "felt_lt",
                252,
                true,
                &args,
                stmt_idx,
                aux_name,
                state,
                signals,
                constraints,
            );
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("felt252_le") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            emit_ordering_boolean_result(
                "felt_le",
                252,
                false,
                &args,
                stmt_idx,
                aux_name,
                state,
                signals,
                constraints,
            );
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // felt252_gt: reverse of lt — b + diff + 1 = a
    // -----------------------------------------------------------------------
    if name.contains("felt252_gt") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            let diff = state.next_aux("felt_gt_diff");
            signals.push(Signal {
                name: diff.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Range {
                signal: diff.clone(),
                bits: 252,
                label: Some(format!("sierra_felt_gt_diff_range_{stmt_idx}")),
            });
            // b + diff + 1 = a  (i.e. a > b)
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[1].clone()),
                    Expr::Signal(diff.clone()),
                    Expr::Const(FieldElement::from_i64(1)),
                ]),
                rhs: Expr::Signal(args[0].clone()),
                label: Some(format!("sierra_felt_gt_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Const(FieldElement::from_i64(1)),
                label: Some(format!("sierra_felt_gt_result_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // felt252_ge: reverse of le — b + diff = a
    if name.contains("felt252_ge") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 2 {
            let diff = state.next_aux("felt_ge_diff");
            signals.push(Signal {
                name: diff.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Range {
                signal: diff.clone(),
                bits: 252,
                label: Some(format!("sierra_felt_ge_diff_range_{stmt_idx}")),
            });
            // b + diff = a  (i.e. a >= b)
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[1].clone()),
                    Expr::Signal(diff.clone()),
                ]),
                rhs: Expr::Signal(args[0].clone()),
                label: Some(format!("sierra_felt_ge_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Const(FieldElement::from_i64(1)),
                label: Some(format!("sierra_felt_ge_result_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    // -----------------------------------------------------------------------
    // Gas builtins (no-op pass-through — gas is runtime-only)
    // -----------------------------------------------------------------------
    if name.contains("withdraw_gas")
        || name.contains("get_builtin_costs")
        || name.contains("gas_builtin")
        || name.contains("redeposit_gas")
    {
        // Gas operations are runtime-only; emit identity constraint (copy input to output)
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_gas_noop_{stmt_idx}")),
            });
        }
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // Nullable operations
    // -----------------------------------------------------------------------
    if name.contains("match_nullable") {
        // Treat like enum_match: branch on zero/non-zero
        let args = extract_invocation_args(invocation);
        if let Some(nullable_signal) = args.first() {
            for (k, out_id) in output_var_ids.iter().enumerate() {
                let sel_name = format!("__sierra_aux_{out_id}");
                state.bind_var(*out_id, sel_name.clone());
                signals.push(Signal {
                    name: sel_name.clone(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                });
                constraints.push(Constraint::Equal {
                    lhs: Expr::Mul(
                        Box::new(Expr::Signal(sel_name.clone())),
                        Box::new(Expr::Sub(
                            Box::new(Expr::Signal(nullable_signal.clone())),
                            Box::new(Expr::Const(FieldElement::from_i64(k as i64))),
                        )),
                    ),
                    rhs: Expr::Const(FieldElement::from_i64(0)),
                    label: Some(format!("sierra_match_nullable_{stmt_idx}_arm{k}")),
                });
                constraints.push(Constraint::Boolean {
                    signal: sel_name,
                    label: Some(format!("sierra_match_nullable_bool_{stmt_idx}_arm{k}")),
                });
            }
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("nullable_from_box") || name.contains("from_nullable") {
        // Identity constraint — unwrap nullable to its inner value
        let args = extract_invocation_args(invocation);
        if let Some(src) = args.first() {
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Signal(src.clone()),
                label: Some(format!("sierra_from_nullable_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name == "null" || name.starts_with("null<") || name.contains("::null") {
        // Null constant: zero
        constraints.push(Constraint::Equal {
            lhs: Expr::Signal(aux_name.to_string()),
            rhs: Expr::Const(FieldElement::from_i64(0)),
            label: Some(format!("sierra_null_{stmt_idx}")),
        });
        state.handled_count += 1;
        return;
    }

    // -----------------------------------------------------------------------
    // u256 operations (u256 = {low: u128, high: u128})
    // -----------------------------------------------------------------------
    if name.contains("u256_add") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 4 {
            // args: [a_low, a_high, b_low, b_high]
            // outputs: [result_low, result_high]
            let result_low = aux_name.to_string();
            let result_high = if output_var_ids.len() >= 2 {
                let n = format!("__sierra_aux_{}", output_var_ids[1]);
                state.bind_var(output_var_ids[1], n.clone());
                n
            } else {
                state.next_aux("u256_add_hi")
            };
            let carry = state.next_aux("u256_carry");
            signals.push(Signal {
                name: result_high.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            signals.push(Signal {
                name: carry.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Boolean {
                signal: carry.clone(),
                label: Some(format!("sierra_u256_add_carry_bool_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: result_low.clone(),
                bits: 128,
                label: Some(format!("sierra_u256_add_lo_range_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: result_high.clone(),
                bits: 128,
                label: Some(format!("sierra_u256_add_hi_range_{stmt_idx}")),
            });
            let two_pow_128 = FieldElement::from_i64(1i64 << 62);
            // a_low + b_low = result_low + carry * 2^128
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[0].clone()),
                    Expr::Signal(args[2].clone()),
                ]),
                rhs: Expr::Add(vec![
                    Expr::Signal(result_low),
                    Expr::Mul(
                        Box::new(Expr::Signal(carry.clone())),
                        Box::new(Expr::Const(two_pow_128.clone())),
                    ),
                ]),
                label: Some(format!("sierra_u256_add_lo_{stmt_idx}")),
            });
            // a_high + b_high + carry = result_high
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[1].clone()),
                    Expr::Signal(args[3].clone()),
                    Expr::Signal(carry),
                ]),
                rhs: Expr::Signal(result_high),
                label: Some(format!("sierra_u256_add_hi_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("u256_sub") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 4 {
            let result_low = aux_name.to_string();
            let result_high = if output_var_ids.len() >= 2 {
                let n = format!("__sierra_aux_{}", output_var_ids[1]);
                state.bind_var(output_var_ids[1], n.clone());
                n
            } else {
                state.next_aux("u256_sub_hi")
            };
            let borrow = state.next_aux("u256_borrow");
            signals.push(Signal {
                name: result_high.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            signals.push(Signal {
                name: borrow.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            constraints.push(Constraint::Boolean {
                signal: borrow.clone(),
                label: Some(format!("sierra_u256_sub_borrow_bool_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: result_low.clone(),
                bits: 128,
                label: Some(format!("sierra_u256_sub_lo_range_{stmt_idx}")),
            });
            constraints.push(Constraint::Range {
                signal: result_high.clone(),
                bits: 128,
                label: Some(format!("sierra_u256_sub_hi_range_{stmt_idx}")),
            });
            let two_pow_128 = FieldElement::from_i64(1i64 << 62);
            // a_low + borrow * 2^128 = result_low + b_low
            constraints.push(Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal(args[0].clone()),
                    Expr::Mul(
                        Box::new(Expr::Signal(borrow.clone())),
                        Box::new(Expr::Const(two_pow_128)),
                    ),
                ]),
                rhs: Expr::Add(vec![
                    Expr::Signal(result_low),
                    Expr::Signal(args[2].clone()),
                ]),
                label: Some(format!("sierra_u256_sub_lo_{stmt_idx}")),
            });
            // a_high = result_high + b_high + borrow
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(args[1].clone()),
                rhs: Expr::Add(vec![
                    Expr::Signal(result_high),
                    Expr::Signal(args[3].clone()),
                    Expr::Signal(borrow),
                ]),
                label: Some(format!("sierra_u256_sub_hi_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("u256_eq") {
        let args = extract_invocation_args(invocation);
        if args.len() >= 4 {
            // eq iff both limbs equal: diff_lo = a_lo - b_lo, diff_hi = a_hi - b_hi
            let diff_lo = state.next_aux("u256_eq_diff_lo");
            let diff_hi = state.next_aux("u256_eq_diff_hi");
            let eq_lo = state.next_aux("u256_eq_lo");
            let eq_hi = state.next_aux("u256_eq_hi");
            let inv_lo = state.next_aux("u256_eq_inv_lo");
            let inv_hi = state.next_aux("u256_eq_inv_hi");
            for s in [&diff_lo, &diff_hi, &eq_lo, &eq_hi, &inv_lo, &inv_hi] {
                signals.push(Signal {
                    name: s.clone(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                });
            }
            // diff_lo = a_lo - b_lo
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(diff_lo.clone()),
                rhs: Expr::Sub(
                    Box::new(Expr::Signal(args[0].clone())),
                    Box::new(Expr::Signal(args[2].clone())),
                ),
                label: Some(format!("sierra_u256_eq_diff_lo_{stmt_idx}")),
            });
            // diff_hi = a_hi - b_hi
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(diff_hi.clone()),
                rhs: Expr::Sub(
                    Box::new(Expr::Signal(args[1].clone())),
                    Box::new(Expr::Signal(args[3].clone())),
                ),
                label: Some(format!("sierra_u256_eq_diff_hi_{stmt_idx}")),
            });
            // is_zero pattern for each limb
            for (diff, eq, inv, suffix) in [
                (&diff_lo, &eq_lo, &inv_lo, "lo"),
                (&diff_hi, &eq_hi, &inv_hi, "hi"),
            ] {
                constraints.push(Constraint::Boolean {
                    signal: eq.clone(),
                    label: Some(format!("sierra_u256_eq_{suffix}_bool_{stmt_idx}")),
                });
                constraints.push(Constraint::Equal {
                    lhs: Expr::Mul(
                        Box::new(Expr::Signal(diff.clone())),
                        Box::new(Expr::Signal(eq.clone())),
                    ),
                    rhs: Expr::Const(FieldElement::from_i64(0)),
                    label: Some(format!("sierra_u256_eq_{suffix}_prod_{stmt_idx}")),
                });
                constraints.push(Constraint::Equal {
                    lhs: Expr::Mul(
                        Box::new(Expr::Sub(
                            Box::new(Expr::Const(FieldElement::from_i64(1))),
                            Box::new(Expr::Signal(eq.clone())),
                        )),
                        Box::new(Expr::Signal(inv.clone())),
                    ),
                    rhs: Expr::Const(FieldElement::from_i64(1)),
                    label: Some(format!("sierra_u256_eq_{suffix}_inv_{stmt_idx}")),
                });
                witness_hints.push(WitnessHint {
                    target: inv.clone(),
                    source: diff.clone(),
                    kind: WitnessHintKind::InverseOrZero,
                });
            }
            // result = eq_lo AND eq_hi
            constraints.push(Constraint::Boolean {
                signal: aux_name.to_string(),
                label: Some(format!("sierra_u256_eq_result_bool_{stmt_idx}")),
            });
            constraints.push(Constraint::Equal {
                lhs: Expr::Signal(aux_name.to_string()),
                rhs: Expr::Mul(Box::new(Expr::Signal(eq_lo)), Box::new(Expr::Signal(eq_hi))),
                label: Some(format!("sierra_u256_eq_{stmt_idx}")),
            });
            state.handled_count += 1;
        } else {
            emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        }
        return;
    }

    if name.contains("u256_lt") || name.contains("u256_le") {
        emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        return;
    }

    if name.contains("u256_mul") {
        emit_unhandled(name, stmt_idx, aux_name, constraints, state);
        return;
    }

    // -----------------------------------------------------------------------
    // Unrecognized libfunc: emit as BlackBox for backend resolution
    // -----------------------------------------------------------------------
    emit_unhandled(name, stmt_idx, aux_name, constraints, state);
}

// ---------------------------------------------------------------------------
// Helper: emit an unrecognized libfunc as a BlackBox constraint
// ---------------------------------------------------------------------------

fn emit_unhandled(
    name: &str,
    stmt_idx: usize,
    aux_name: &str,
    constraints: &mut Vec<Constraint>,
    state: &mut SierraTranslationState,
) {
    let mut params = BTreeMap::new();
    params.insert("sierra_op".to_string(), "sierra_unhandled".to_string());
    params.insert("libfunc".to_string(), name.to_string());
    constraints.push(Constraint::BlackBox {
        op: BlackBoxOp::Poseidon,
        inputs: Vec::new(),
        outputs: vec![aux_name.to_string()],
        params,
        label: Some(format!("sierra_unhandled_{stmt_idx}_{name}")),
    });
    state.unhandled_count += 1;
}

#[allow(clippy::too_many_arguments)]
fn emit_ordering_boolean_result(
    label_prefix: &str,
    bits: u32,
    strict: bool,
    args: &[String],
    stmt_idx: usize,
    aux_name: &str,
    state: &mut SierraTranslationState,
    signals: &mut Vec<Signal>,
    constraints: &mut Vec<Constraint>,
) {
    let true_diff = state.next_aux(&format!("{label_prefix}_true_diff"));
    let false_diff = state.next_aux(&format!("{label_prefix}_false_diff"));
    for diff in [&true_diff, &false_diff] {
        signals.push(Signal {
            name: diff.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
    }

    constraints.push(Constraint::Boolean {
        signal: aux_name.to_string(),
        label: Some(format!("sierra_{label_prefix}_result_bool_{stmt_idx}")),
    });
    constraints.push(Constraint::Range {
        signal: true_diff.clone(),
        bits,
        label: Some(format!("sierra_{label_prefix}_true_diff_range_{stmt_idx}")),
    });
    constraints.push(Constraint::Range {
        signal: false_diff.clone(),
        bits,
        label: Some(format!("sierra_{label_prefix}_false_diff_range_{stmt_idx}")),
    });

    let true_terms = if strict {
        vec![
            Expr::Signal(args[0].clone()),
            Expr::Signal(true_diff.clone()),
            Expr::Const(FieldElement::from_i64(1)),
        ]
    } else {
        vec![
            Expr::Signal(args[0].clone()),
            Expr::Signal(true_diff.clone()),
        ]
    };
    constraints.push(Constraint::Equal {
        lhs: Expr::Mul(
            Box::new(Expr::Signal(aux_name.to_string())),
            Box::new(Expr::Sub(
                Box::new(Expr::Add(true_terms)),
                Box::new(Expr::Signal(args[1].clone())),
            )),
        ),
        rhs: Expr::Const(FieldElement::from_i64(0)),
        label: Some(format!("sierra_{label_prefix}_true_{stmt_idx}")),
    });

    let false_terms = if strict {
        vec![
            Expr::Signal(args[1].clone()),
            Expr::Signal(false_diff.clone()),
        ]
    } else {
        vec![
            Expr::Signal(args[1].clone()),
            Expr::Signal(false_diff.clone()),
            Expr::Const(FieldElement::from_i64(1)),
        ]
    };
    constraints.push(Constraint::Equal {
        lhs: Expr::Mul(
            Box::new(Expr::Sub(
                Box::new(Expr::Const(FieldElement::from_i64(1))),
                Box::new(Expr::Signal(aux_name.to_string())),
            )),
            Box::new(Expr::Sub(
                Box::new(Expr::Add(false_terms)),
                Box::new(Expr::Signal(args[0].clone())),
            )),
        ),
        rhs: Expr::Const(FieldElement::from_i64(0)),
        label: Some(format!("sierra_{label_prefix}_false_{stmt_idx}")),
    });
}

fn cairo_lookup_tables() -> Vec<LookupTable> {
    vec![
        build_bitwise_nibble_table("and", |lhs, rhs| lhs & rhs),
        build_bitwise_nibble_table("or", |lhs, rhs| lhs | rhs),
        build_bitwise_nibble_table("xor", |lhs, rhs| lhs ^ rhs),
    ]
}

fn build_bitwise_nibble_table(op: &str, f: impl Fn(u8, u8) -> u8) -> LookupTable {
    let mut values = Vec::with_capacity(16 * 16);
    for lhs in 0u8..16 {
        for rhs in 0u8..16 {
            values.push(vec![
                FieldElement::from_i64(lhs as i64),
                FieldElement::from_i64(rhs as i64),
                FieldElement::from_i64(f(lhs, rhs) as i64),
            ]);
        }
    }
    LookupTable {
        name: format!("cairo_bitwise_{op}_nibble"),
        columns: vec!["lhs".to_string(), "rhs".to_string(), "out".to_string()],
        values,
    }
}

struct SierraEmitter<'a> {
    state: &'a mut SierraTranslationState,
    signals: &'a mut Vec<Signal>,
    constraints: &'a mut Vec<Constraint>,
}

fn emit_bitwise_lookup(
    op: &str,
    bits: u32,
    args: &[String],
    stmt_idx: usize,
    aux_name: &str,
    emitter: &mut SierraEmitter<'_>,
) -> bool {
    if args.len() < 2 || bits == 0 || !bits.is_multiple_of(4) {
        return false;
    }

    let lhs_nibbles = emit_radix_decomposition(
        &args[0],
        bits,
        4,
        &format!("sierra_bitwise_{op}_{stmt_idx}_lhs"),
        emitter,
    );
    let rhs_nibbles = emit_radix_decomposition(
        &args[1],
        bits,
        4,
        &format!("sierra_bitwise_{op}_{stmt_idx}_rhs"),
        emitter,
    );

    let mut out_nibbles = Vec::with_capacity(lhs_nibbles.len());
    for chunk_idx in 0..lhs_nibbles.len() {
        let out_nibble = emitter
            .state
            .next_aux(&format!("bitwise_{op}_{stmt_idx}_out_nib"));
        emitter.signals.push(Signal {
            name: out_nibble.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        emitter.constraints.push(Constraint::Range {
            signal: out_nibble.clone(),
            bits: 4,
            label: Some(format!(
                "sierra_bitwise_{op}_{stmt_idx}_out_range_{chunk_idx}"
            )),
        });
        emitter.constraints.push(Constraint::Lookup {
            inputs: vec![
                Expr::Signal(lhs_nibbles[chunk_idx].clone()),
                Expr::Signal(rhs_nibbles[chunk_idx].clone()),
            ],
            table: format!("cairo_bitwise_{op}_nibble"),
            outputs: Some(vec![out_nibble.clone()]),
            label: Some(format!("sierra_bitwise_{op}_{stmt_idx}_lookup_{chunk_idx}")),
        });
        out_nibbles.push(out_nibble);
    }

    emitter.constraints.push(Constraint::Range {
        signal: aux_name.to_string(),
        bits,
        label: Some(format!("sierra_bitwise_{op}_{stmt_idx}_result_range")),
    });
    emitter.constraints.push(Constraint::Equal {
        lhs: Expr::Signal(aux_name.to_string()),
        rhs: recompose_radix_expr(&out_nibbles, 4),
        label: Some(format!("sierra_bitwise_{op}_{stmt_idx}_recompose")),
    });

    true
}

fn emit_radix_decomposition(
    source: &str,
    total_bits: u32,
    chunk_bits: u32,
    prefix: &str,
    emitter: &mut SierraEmitter<'_>,
) -> Vec<String> {
    let chunk_count = (total_bits as usize).div_ceil(chunk_bits as usize);
    let mut chunks = Vec::with_capacity(chunk_count);

    for chunk_idx in 0..chunk_count {
        let chunk_name = emitter.state.next_aux(&format!("{prefix}_chunk"));
        emitter.signals.push(Signal {
            name: chunk_name.clone(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        });
        emitter.constraints.push(Constraint::Range {
            signal: chunk_name.clone(),
            bits: chunk_bits,
            label: Some(format!("{prefix}_range_{chunk_idx}")),
        });
        chunks.push(chunk_name);
    }

    emitter.constraints.push(Constraint::Equal {
        lhs: Expr::Signal(source.to_string()),
        rhs: recompose_radix_expr(&chunks, chunk_bits),
        label: Some(format!("{prefix}_recompose")),
    });

    chunks
}

fn recompose_radix_expr(chunks: &[String], chunk_bits: u32) -> Expr {
    let mut terms = Vec::with_capacity(chunks.len());
    for (idx, chunk) in chunks.iter().enumerate() {
        let shift = chunk_bits as usize * idx;
        let coeff = BigInt::from(1u8) << shift;
        let term = if idx == 0 {
            Expr::Signal(chunk.clone())
        } else {
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_bigint(coeff))),
                Box::new(Expr::Signal(chunk.clone())),
            )
        };
        terms.push(term);
    }

    if terms.len() == 1 {
        terms.into_iter().next().expect("single chunk exists")
    } else {
        Expr::Add(terms)
    }
}

fn unsupported_sierra_libfunc_counts(program: &Program) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for constraint in &program.constraints {
        if let Constraint::BlackBox { params, .. } = constraint
            && let Some(sierra_op) = params.get("sierra_op").map(String::as_str)
        {
            let libfunc = match sierra_op {
                "sierra_unhandled" => params
                    .get("libfunc")
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
                "array_get" | "array_pop_front" | "function_call" | "storage_read"
                | "storage_write" => sierra_op.to_string(),
                other
                    if other.starts_with("ec_point_from_x_nz")
                        || other.starts_with("ec_state_") =>
                {
                    other.to_string()
                }
                _ => continue,
            };
            *counts.entry(libfunc).or_insert(0) += 1;
        }
    }
    counts
}

fn ensure_supported_sierra_translation(program: &Program) -> ZkfResult<()> {
    let unsupported = unsupported_sierra_libfunc_counts(program);
    if unsupported.is_empty() {
        return Ok(());
    }

    let summary = unsupported
        .iter()
        .map(|(name, count)| format!("{name} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");
    let unique = unsupported.keys().cloned().collect::<BTreeSet<_>>().len();
    Err(ZkfError::UnsupportedBackend {
        backend: "frontend/cairo".to_string(),
        message: format!(
            "Cairo Sierra import hit {unique} unsupported or placeholder-only libfunc(s) and failed closed instead of admitting fallback BlackBox constraints: {summary}"
        ),
    })
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/// Infer the integer bit-width from a libfunc name containing "u8", "u16",
/// "u32", "u64", or "u128".
fn uint_bits_from_name(name: &str) -> u32 {
    if name.contains("u128") {
        128
    } else if name.contains("u64") {
        64
    } else if name.contains("u32") {
        32
    } else if name.contains("u16") {
        16
    } else if name.contains("u8") {
        8
    } else {
        128 // default to widest for unknown uint names
    }
}

/// Extract an enum variant tag index from a libfunc name such as
/// `"enum_init<MyType, 2>"`.  Falls back to 0.
fn extract_enum_tag_from_name(name: &str) -> i64 {
    // Try to find the last integer token in the name.
    name.rsplit(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default()
}

fn resolve_libfunc_name(sierra: &SierraProgram, id: u64) -> String {
    for decl in &sierra.libfunc_declarations {
        if decl.id.get("id").and_then(Value::as_u64) == Some(id)
            && let Some(long_id) = &decl.long_id
            && let Some(name) = long_id
                .get("generic_id")
                .or(long_id.get("id"))
                .and_then(Value::as_str)
        {
            return name.to_string();
        }
    }
    format!("libfunc_{id}")
}

fn extract_invocation_args(invocation: &Value) -> Vec<String> {
    invocation
        .get("args")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .enumerate()
                .map(|(i, v)| {
                    v.get("id")
                        .and_then(Value::as_u64)
                        .map(|id| format!("__sierra_aux_{id}"))
                        .unwrap_or_else(|| format!("__arg_{i}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the list of output variable IDs declared in a Sierra invocation's
/// `branches` field.  Sierra branches each carry a list of results.
fn extract_output_var_ids(invocation: &Value) -> Vec<u64> {
    let mut ids = Vec::new();
    if let Some(branches) = invocation.get("branches").and_then(Value::as_array) {
        for branch in branches {
            if let Some(results) = branch.get("results").and_then(Value::as_array) {
                for res in results {
                    if let Some(id) = res.get("id").and_then(Value::as_u64) {
                        ids.push(id);
                    }
                }
            }
        }
    }
    ids
}

fn run_build_command(command: &str) -> ZkfResult<()> {
    let status = Command::new("sh")
        .arg("-lc")
        .arg(command)
        .status()
        .map_err(|err| ZkfError::Io(format!("Cairo build command failed to spawn: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ZkfError::Backend(format!(
            "Cairo build command exited with status {status}"
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_sierra(libfunc_name: &str, libfunc_id: u64, args: &[u64]) -> SierraProgram {
        let args_json: Vec<Value> = args
            .iter()
            .map(|id| serde_json::json!({ "id": id }))
            .collect();
        let stmt = serde_json::json!({
            "Invocation": {
                "libfunc_id": { "id": libfunc_id },
                "args": args_json,
                "branches": [{ "results": [{ "id": 999u64 }] }]
            }
        });
        SierraProgram {
            type_declarations: vec![],
            libfunc_declarations: vec![SierraLibfuncDecl {
                id: serde_json::json!({ "id": libfunc_id }),
                long_id: Some(serde_json::json!({ "generic_id": libfunc_name })),
            }],
            statements: vec![SierraStatement { data: stmt }],
            funcs: vec![],
        }
    }

    fn sample_zir_program() -> zir_v1::Program {
        zir_v1::Program {
            name: "cairo_zir".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                zir_v1::Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    ty: zir_v1::SignalType::Field,
                    constant: None,
                },
                zir_v1::Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Private,
                    ty: zir_v1::SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![zir_v1::Constraint::Equal {
                lhs: zir_v1::Expr::Signal("y".to_string()),
                rhs: zir_v1::Expr::Signal("x".to_string()),
                label: Some("copy".to_string()),
            }],
            witness_plan: Default::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        }
    }

    fn stateful_zir_program() -> zir_v1::Program {
        zir_v1::Program {
            constraints: vec![zir_v1::Constraint::MemoryRead {
                memory: "storage".to_string(),
                index: zir_v1::Expr::Signal("slot".to_string()),
                value: zir_v1::Expr::Signal("value".to_string()),
                label: Some("storage_read".to_string()),
            }],
            signals: vec![
                zir_v1::Signal {
                    name: "slot".to_string(),
                    visibility: Visibility::Private,
                    ty: zir_v1::SignalType::Field,
                    constant: None,
                },
                zir_v1::Signal {
                    name: "value".to_string(),
                    visibility: Visibility::Private,
                    ty: zir_v1::SignalType::Field,
                    constant: None,
                },
            ],
            memory_regions: vec![zir_v1::MemoryRegion {
                name: "storage".to_string(),
                size: 16,
                read_only: false,
            }],
            ..sample_zir_program()
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("zkf_{name}_{nanos}.json"))
    }

    fn default_options() -> FrontendImportOptions {
        FrontendImportOptions {
            program_name: Some("test".to_string()),
            field: Some(FieldId::Goldilocks),
            allow_unsupported_versions: false,
            translator: None,
            ir_family: Default::default(),
            source_path: None,
        }
    }

    fn compile_sierra_with_frontend(sierra: &SierraProgram) -> ZkfResult<Program> {
        let frontend = CairoFrontend;
        let value = serde_json::to_value(sierra).expect("sierra serialization");
        frontend.compile_to_ir(&value, &default_options())
    }

    fn find_constraint_with_label(prog: &Program, label_fragment: &str) -> bool {
        prog.constraints.iter().any(|c| {
            c.label()
                .map(|l| l.contains(label_fragment))
                .unwrap_or(false)
        })
    }

    fn constraint_with_label<'a>(prog: &'a Program, label_fragment: &str) -> &'a Constraint {
        prog.constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains(label_fragment))
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| {
                panic!("missing constraint containing label fragment `{label_fragment}`")
            })
    }

    // -----------------------------------------------------------------------
    // felt252 arithmetic tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_felt252_add() {
        let sierra = make_sierra("felt252_add", 1, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_add_0"));
        // Verify it is an Equal constraint summing both args
        let c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_add_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match c {
            Constraint::Equal {
                rhs: Expr::Add(terms),
                ..
            } => {
                assert_eq!(terms.len(), 2);
            }
            other => panic!("unexpected constraint: {other:?}"),
        }
    }

    #[test]
    fn test_felt252_sub() {
        let sierra = make_sierra("felt252_sub", 2, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_sub_0"));
    }

    #[test]
    fn test_felt252_mul() {
        let sierra = make_sierra("felt252_mul", 3, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_mul_0"));
    }

    #[test]
    fn test_felt252_div_emits_inverse_witness() {
        let sierra = make_sierra("felt252_div", 4, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        // Must have b * b_inv = 1 constraint and the div result constraint
        assert!(find_constraint_with_label(&prog, "sierra_div_inv_0"));
        assert!(find_constraint_with_label(&prog, "sierra_div_0"));
        // Must have a witness hint for b_inv
        assert!(!prog.witness_plan.hints.is_empty());
    }

    #[test]
    fn test_felt252_is_zero_emits_boolean_and_nonlinearity() {
        let sierra = make_sierra("felt252_is_zero", 5, &[20]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_is_zero_bool_0"));
        assert!(find_constraint_with_label(&prog, "sierra_is_zero_prod_0"));
        assert!(find_constraint_with_label(&prog, "sierra_is_zero_inv_0"));
        // Boolean constraint exists
        assert!(
            prog.constraints
                .iter()
                .any(|c| matches!(c, Constraint::Boolean { .. }))
        );
    }

    #[test]
    fn test_felt252_neg() {
        let sierra = make_sierra("felt252_neg", 6, &[10]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_neg_0"));
    }

    // -----------------------------------------------------------------------
    // Range check
    // -----------------------------------------------------------------------

    #[test]
    fn test_range_check_builtin() {
        let sierra = make_sierra("range_check_builtin", 10, &[50]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_range_0"));
        let c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_range_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match c {
            Constraint::Range { bits: 128, .. } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Unsigned integer comparisons
    // -----------------------------------------------------------------------

    #[test]
    fn test_u128_lt() {
        let sierra = make_sierra("u128_lt", 20, &[30, 31]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_lt_result_bool_0"));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_lt_true_diff_range_0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_lt_false_diff_range_0"
        ));
        assert!(find_constraint_with_label(&prog, "sierra_lt_true_0"));
        assert!(find_constraint_with_label(&prog, "sierra_lt_false_0"));
    }

    #[test]
    fn test_u64_lt() {
        let sierra = make_sierra("u64_lt", 21, &[30, 31]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        // Bit width must be 64
        let range_c = constraint_with_label(&prog, "sierra_lt_true_diff_range_0");
        match range_c {
            Constraint::Range { bits: 64, .. } => {}
            other => panic!("expected 64-bit range, got {other:?}"),
        }
    }

    #[test]
    fn test_u128_le() {
        let sierra = make_sierra("u128_le", 22, &[30, 31]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_le_result_bool_0"));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_le_true_diff_range_0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_le_false_diff_range_0"
        ));
        assert!(find_constraint_with_label(&prog, "sierra_le_true_0"));
        assert!(find_constraint_with_label(&prog, "sierra_le_false_0"));
    }

    #[test]
    fn test_felt252_lt_emits_boolean_result_semantics() {
        let sierra = make_sierra("felt252_lt", 220, &[30, 31]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(
            &prog,
            "sierra_felt_lt_result_bool_0"
        ));
        assert!(find_constraint_with_label(&prog, "sierra_felt_lt_true_0"));
        assert!(find_constraint_with_label(&prog, "sierra_felt_lt_false_0"));
    }

    #[test]
    fn test_compile_to_ir_rejects_u256_placeholder_comparison_surface() {
        let sierra = make_sierra("u256_lt", 221, &[30, 31, 32, 33]);
        let err = compile_sierra_with_frontend(&sierra).expect_err("u256_lt should fail closed");
        assert!(format!("{err}").contains("u256_lt"));
    }

    // -----------------------------------------------------------------------
    // Overflowing add/sub
    // -----------------------------------------------------------------------

    #[test]
    fn test_u128_overflowing_add() {
        let sierra = make_sierra("u128_overflowing_add", 30, &[40, 41]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_overflow_bool_0"));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_add_result_range_0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_overflowing_add_0"
        ));
    }

    #[test]
    fn test_u64_overflowing_add() {
        let sierra = make_sierra("u64_overflowing_add", 31, &[40, 41]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(
            &prog,
            "sierra_overflowing_add_0"
        ));
        // Bit width should be 64
        let range_c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_add_result_range_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match range_c {
            Constraint::Range { bits: 64, .. } => {}
            other => panic!("expected 64-bit range, got {other:?}"),
        }
    }

    #[test]
    fn test_u128_overflowing_sub() {
        let sierra = make_sierra("u128_overflowing_sub", 32, &[40, 41]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_borrow_bool_0"));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_overflowing_sub_0"
        ));
    }

    // -----------------------------------------------------------------------
    // Wide multiply
    // -----------------------------------------------------------------------

    #[test]
    fn test_u128_wide_mul() {
        let sierra = make_sierra("u128_wide_mul", 33, &[40, 41]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(
            &prog,
            "sierra_wide_mul_lo_range_0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_wide_mul_hi_range_0"
        ));
        assert!(find_constraint_with_label(&prog, "sierra_wide_mul_0"));
    }

    // -----------------------------------------------------------------------
    // Type conversions
    // -----------------------------------------------------------------------

    #[test]
    fn test_felt252_to_u128_range_constrained() {
        let sierra = make_sierra("felt252_to_u128", 40, &[50]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_felt_to_u128_0"));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_felt_to_u128_range_0"
        ));
        let range_c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_felt_to_u128_range_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match range_c {
            Constraint::Range { bits: 128, .. } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_u128_to_felt252_identity() {
        let sierra = make_sierra("u128_to_felt252", 41, &[50]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_u128_to_felt_0"));
        // No range constraint for widening conversion
        assert!(!find_constraint_with_label(
            &prog,
            "sierra_u128_to_felt_0_range"
        ));
    }

    // -----------------------------------------------------------------------
    // Arrays
    // -----------------------------------------------------------------------

    #[test]
    fn test_array_new_creates_zero_length() {
        let sierra = make_sierra("array_new", 50, &[]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_array_new_len_0"));
        let len_c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_array_new_len_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match len_c {
            Constraint::Equal {
                rhs: Expr::Const(fe),
                ..
            } => {
                assert!(fe.is_zero());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_array_append_copies_value() {
        let sierra = make_sierra("array_append", 51, &[100, 101]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_array_append_0"));
    }

    #[test]
    fn test_array_get_blackbox() {
        let sierra = make_sierra("array_get", 52, &[100, 102]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_array_get_0"));
        let bb_c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_array_get_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        assert!(matches!(bb_c, Constraint::BlackBox { .. }));
    }

    #[test]
    fn test_compile_to_ir_rejects_array_get_placeholder_surface() {
        let sierra = make_sierra("array_get", 52, &[100, 102]);
        let err = compile_sierra_with_frontend(&sierra)
            .expect_err("array_get placeholder path must fail closed during frontend import");
        let rendered = err.to_string();
        assert!(rendered.contains("placeholder-only"), "{rendered}");
        assert!(rendered.contains("array_get"), "{rendered}");
    }

    // -----------------------------------------------------------------------
    // Enums
    // -----------------------------------------------------------------------

    #[test]
    fn test_enum_init_assigns_tag() {
        let sierra = make_sierra("enum_init<MyEnum, 2>", 60, &[]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_enum_init_0"));
        let tag_c = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_enum_init_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match tag_c {
            Constraint::Equal {
                rhs: Expr::Const(fe),
                ..
            } => {
                assert_eq!(fe.as_bigint(), num_bigint::BigInt::from(2i64));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_enum_match_emits_selector_constraints() {
        // enum_match with 2 output variant slots
        let args_json: Vec<Value> = vec![serde_json::json!({ "id": 10u64 })];
        let stmt = serde_json::json!({
            "Invocation": {
                "libfunc_id": { "id": 61u64 },
                "args": args_json,
                "branches": [
                    { "results": [{ "id": 200u64 }] },
                    { "results": [{ "id": 201u64 }] }
                ]
            }
        });
        let sierra = SierraProgram {
            type_declarations: vec![],
            libfunc_declarations: vec![SierraLibfuncDecl {
                id: serde_json::json!({ "id": 61u64 }),
                long_id: Some(serde_json::json!({ "generic_id": "enum_match" })),
            }],
            statements: vec![SierraStatement { data: stmt }],
            funcs: vec![],
        };
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(
            &prog,
            "sierra_enum_match_0_arm0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_enum_match_0_arm1"
        ));
    }

    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    #[test]
    fn test_struct_construct_copies_fields() {
        let sierra = make_sierra("struct_construct", 70, &[80, 81, 82]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(
            &prog,
            "sierra_struct_construct_0_f0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_struct_construct_0_f1"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_struct_construct_0_f2"
        ));
    }

    #[test]
    fn test_struct_deconstruct_extracts_fields() {
        let stmt = serde_json::json!({
            "Invocation": {
                "libfunc_id": { "id": 71u64 },
                "args": [{ "id": 90u64 }],
                "branches": [
                    {
                        "results": [
                            { "id": 300u64 },
                            { "id": 301u64 }
                        ]
                    }
                ]
            }
        });
        let sierra = SierraProgram {
            type_declarations: vec![],
            libfunc_declarations: vec![SierraLibfuncDecl {
                id: serde_json::json!({ "id": 71u64 }),
                long_id: Some(serde_json::json!({ "generic_id": "struct_deconstruct" })),
            }],
            statements: vec![SierraStatement { data: stmt }],
            funcs: vec![],
        };
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(
            &prog,
            "sierra_struct_deconstruct_0_f0"
        ));
        assert!(find_constraint_with_label(
            &prog,
            "sierra_struct_deconstruct_0_f1"
        ));
    }

    // -----------------------------------------------------------------------
    // Memory / register ops
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_temp_alias() {
        let sierra = make_sierra("store_temp", 80, &[100]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_alias_0"));
    }

    #[test]
    fn test_rename_alias() {
        let sierra = make_sierra("rename", 81, &[100]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_alias_0"));
    }

    #[test]
    fn test_drop_no_constraint() {
        let sierra = make_sierra("drop", 82, &[100]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        // drop should produce 0 constraints (beyond the always-added signal)
        assert!(prog.constraints.is_empty());
    }

    #[test]
    fn test_dup_copy_constraint() {
        let sierra = make_sierra("dup", 83, &[100]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_dup_0"));
    }

    #[test]
    fn test_alloc_local_no_constraint() {
        let sierra = make_sierra("alloc_local", 84, &[]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(prog.constraints.is_empty());
    }

    #[test]
    fn test_store_local_copies_value() {
        let sierra = make_sierra("store_local", 85, &[100]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_store_local_0"));
    }

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------

    #[test]
    fn test_branch_align_no_constraint() {
        let sierra = make_sierra("branch_align", 90, &[]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(prog.constraints.is_empty());
    }

    #[test]
    fn test_jump_no_constraint() {
        let sierra = make_sierra("jump", 91, &[]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(prog.constraints.is_empty());
    }

    #[test]
    fn test_function_call_blackbox_stub() {
        let sierra = make_sierra("function_call<foo>", 92, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_function_call_0"));
        assert!(
            prog.constraints
                .iter()
                .any(|c| matches!(c, Constraint::BlackBox { .. }))
        );
    }

    #[test]
    fn test_compile_to_ir_rejects_function_call_placeholder_surface() {
        let sierra = make_sierra("function_call<foo>", 92, &[10, 11]);
        let err = compile_sierra_with_frontend(&sierra)
            .expect_err("function_call placeholder path must fail closed during frontend import");
        let rendered = err.to_string();
        assert!(rendered.contains("function_call"), "{rendered}");
    }

    #[test]
    fn test_return_produces_public_signals() {
        let sierra = make_sierra("return", 93, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_return_0_0"));
        assert!(find_constraint_with_label(&prog, "sierra_return_0_1"));
        assert!(
            prog.signals
                .iter()
                .any(|s| s.name == "__return_0" && s.visibility == Visibility::Public)
        );
    }

    // -----------------------------------------------------------------------
    // StarkNet storage
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_read_blackbox() {
        let sierra = make_sierra("storage_read", 100, &[10]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_storage_read_0"));
        assert!(
            prog.constraints
                .iter()
                .any(|c| matches!(c, Constraint::BlackBox { .. }))
        );
    }

    #[test]
    fn test_storage_write_blackbox() {
        let sierra = make_sierra("storage_write", 101, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_storage_write_0"));
    }

    #[test]
    fn test_compile_to_ir_rejects_storage_placeholder_surface() {
        let sierra = make_sierra("storage_read", 100, &[10]);
        let err = compile_sierra_with_frontend(&sierra)
            .expect_err("storage placeholder path must fail closed during frontend import");
        let rendered = err.to_string();
        assert!(rendered.contains("storage_read"), "{rendered}");
    }

    #[test]
    fn test_compile_to_ir_rejects_ec_state_placeholder_surface() {
        let sierra = make_sierra("ec_state_add", 102, &[10, 11]);
        let err = compile_sierra_with_frontend(&sierra)
            .expect_err("ec_state placeholder path must fail closed during frontend import");
        let rendered = err.to_string();
        assert!(rendered.contains("ec_state_add"), "{rendered}");
    }

    // -----------------------------------------------------------------------
    // Hashes
    // -----------------------------------------------------------------------

    #[test]
    fn test_poseidon_blackbox() {
        let sierra = make_sierra("poseidon", 110, &[10, 11, 12]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_poseidon_0"));
        let bb = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_poseidon_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match bb {
            Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                ..
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn test_pedersen_blackbox() {
        let sierra = make_sierra("pedersen", 111, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_pedersen_0"));
        let bb = prog
            .constraints
            .iter()
            .find(|c| {
                c.label()
                    .map(|l| l.contains("sierra_pedersen_0"))
                    .unwrap_or(false)
            })
            .unwrap();
        match bb {
            Constraint::BlackBox {
                op: BlackBoxOp::Pedersen,
                ..
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Boolean operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_bool_and() {
        let sierra = make_sierra("bool_and", 120, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_bool_and_0"));
        assert!(
            prog.constraints
                .iter()
                .any(|c| matches!(c, Constraint::Boolean { .. }))
        );
    }

    #[test]
    fn test_bool_or() {
        let sierra = make_sierra("bool_or", 121, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_bool_or_0"));
    }

    #[test]
    fn test_bool_not() {
        let sierra = make_sierra("bool_not", 122, &[10]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_bool_not_0"));
    }

    #[test]
    fn test_u8_bitwise_xor_uses_lookup_tables() {
        let sierra = make_sierra("u8_xor", 123, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(
            prog.constraints
                .iter()
                .any(|c| matches!(c, Constraint::Lookup { label: Some(label), .. } if label.contains("sierra_bitwise_xor_0_lookup_")))
        );
        assert!(find_constraint_with_label(
            &prog,
            "sierra_bitwise_xor_0_recompose"
        ));
        assert!(
            !prog.constraints.iter().any(|c| matches!(
                c,
                Constraint::BlackBox {
                    op: BlackBoxOp::Poseidon,
                    label: Some(label),
                    ..
                } if label.contains("sierra_bitwise_xor_0")
            )),
            "bitwise xor should no longer route through a placeholder Poseidon BlackBox"
        );
        assert!(
            prog.lookup_tables
                .iter()
                .any(|table| table.name == "cairo_bitwise_xor_nibble")
        );
    }

    #[test]
    fn test_u128_bitwise_and_emits_chunked_recomposition() {
        let sierra = make_sierra("u128_and", 124, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        let lookup_count = prog
            .constraints
            .iter()
            .filter(|c| {
                matches!(
                    c,
                    Constraint::Lookup {
                        label: Some(label),
                        ..
                    } if label.contains("sierra_bitwise_and_0_lookup_")
                )
            })
            .count();
        assert_eq!(
            lookup_count, 32,
            "u128 should use one nibble lookup per 4-bit chunk"
        );
        assert!(find_constraint_with_label(
            &prog,
            "sierra_bitwise_and_0_result_range"
        ));
    }

    // -----------------------------------------------------------------------
    // Equality checks
    // -----------------------------------------------------------------------

    #[test]
    fn test_felt252_eq() {
        let sierra = make_sierra("felt252_eq", 130, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_eq_diff_0"));
        assert!(find_constraint_with_label(&prog, "sierra_eq_bool_0"));
        assert!(find_constraint_with_label(&prog, "sierra_eq_prod_0"));
        assert!(find_constraint_with_label(&prog, "sierra_eq_inv_0"));
        assert!(!prog.witness_plan.hints.is_empty());
    }

    #[test]
    fn test_u128_eq() {
        let sierra = make_sierra("u128_eq", 131, &[10, 11]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_eq_diff_0"));
    }

    // -----------------------------------------------------------------------
    // Snapshot / desnap
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_take_identity() {
        let sierra = make_sierra("snapshot_take", 140, &[10]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_snapshot_0"));
    }

    #[test]
    fn test_desnap_identity() {
        let sierra = make_sierra("desnap", 141, &[10]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_desnap_0"));
    }

    // -----------------------------------------------------------------------
    // Non-zero assertion
    // -----------------------------------------------------------------------

    #[test]
    fn test_unwrap_nz_asserts_nonzero() {
        let sierra = make_sierra("unwrap_nz", 150, &[10]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        assert!(find_constraint_with_label(&prog, "sierra_nz_0"));
        assert!(find_constraint_with_label(&prog, "sierra_nz_copy_0"));
        assert!(!prog.witness_plan.hints.is_empty());
    }

    // -----------------------------------------------------------------------
    // Unhandled libfunc → BlackBox stub
    // -----------------------------------------------------------------------

    #[test]
    fn test_unhandled_libfunc_emits_blackbox_stub() {
        let sierra = make_sierra("totally_unknown_op", 200, &[]);
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();
        let bb = prog
            .constraints
            .iter()
            .find(|c| matches!(c, Constraint::BlackBox { .. }));
        assert!(bb.is_some(), "expected BlackBox stub for unhandled libfunc");
        if let Some(Constraint::BlackBox { params, .. }) = bb {
            assert_eq!(
                params.get("sierra_op").map(String::as_str),
                Some("sierra_unhandled")
            );
        }
    }

    // -----------------------------------------------------------------------
    // Coverage counter
    // -----------------------------------------------------------------------

    #[test]
    fn test_coverage_counter() {
        // Build a program with a mix of handled and unhandled ops.
        let make_stmt = |libfunc_id: u64, _libfunc_name: &str, args: &[u64]| -> Value {
            let args_json: Vec<Value> = args
                .iter()
                .map(|id| serde_json::json!({ "id": id }))
                .collect();
            serde_json::json!({
                "Invocation": {
                    "libfunc_id": { "id": libfunc_id },
                    "args": args_json,
                    "branches": [{ "results": [{ "id": libfunc_id + 900u64 }] }]
                }
            })
        };
        let sierra = SierraProgram {
            type_declarations: vec![],
            libfunc_declarations: vec![
                SierraLibfuncDecl {
                    id: serde_json::json!({ "id": 1u64 }),
                    long_id: Some(serde_json::json!({ "generic_id": "felt252_add" })),
                },
                SierraLibfuncDecl {
                    id: serde_json::json!({ "id": 2u64 }),
                    long_id: Some(serde_json::json!({ "generic_id": "truly_unknown_xyz" })),
                },
                SierraLibfuncDecl {
                    id: serde_json::json!({ "id": 3u64 }),
                    long_id: Some(serde_json::json!({ "generic_id": "felt252_mul" })),
                },
            ],
            statements: vec![
                SierraStatement {
                    data: make_stmt(1, "felt252_add", &[10, 11]),
                },
                SierraStatement {
                    data: make_stmt(2, "truly_unknown_xyz", &[]),
                },
                SierraStatement {
                    data: make_stmt(3, "felt252_mul", &[10, 11]),
                },
            ],
            funcs: vec![],
        };

        // We track handled/unhandled via the state, but since translate_sierra_to_program
        // doesn't expose coverage stats directly, verify via constraint kinds:
        let prog = translate_sierra_to_program(&sierra, &default_options()).unwrap();

        let handled: usize = prog
            .constraints
            .iter()
            .filter(|c| {
                c.label()
                    .map(|l| l.contains("sierra_add") || l.contains("sierra_mul"))
                    .unwrap_or(false)
            })
            .count();
        let unhandled: usize = prog
            .constraints
            .iter()
            .filter(|c| {
                if let Constraint::BlackBox { params, .. } = c {
                    params.get("sierra_op").map(String::as_str) == Some("sierra_unhandled")
                } else {
                    false
                }
            })
            .count();

        assert_eq!(handled, 2, "expected 2 handled constraints");
        assert_eq!(unhandled, 1, "expected 1 unhandled BlackBox stub");
    }

    // -----------------------------------------------------------------------
    // Integration: FrontendEngine compile_to_ir via sierra_json field
    // -----------------------------------------------------------------------

    #[test]
    fn test_cairo_frontend_compile_to_ir_sierra_json() {
        let sierra_json = serde_json::json!({
            "type_declarations": [],
            "libfunc_declarations": [
                {
                    "id": { "id": 1u64 },
                    "long_id": { "generic_id": "felt252_add" }
                }
            ],
            "statements": [
                {
                    "Invocation": {
                        "libfunc_id": { "id": 1u64 },
                        "args": [{ "id": 10u64 }, { "id": 11u64 }],
                        "branches": [{ "results": [{ "id": 99u64 }] }]
                    }
                }
            ],
            "funcs": []
        });
        let descriptor = serde_json::json!({ "sierra_json": sierra_json });
        let options = default_options();
        let prog = CairoFrontend.compile_to_ir(&descriptor, &options).unwrap();
        assert!(!prog.constraints.is_empty());
        assert!(find_constraint_with_label(&prog, "sierra_add_0"));
    }

    #[test]
    fn test_cairo_frontend_probe_sierra_json() {
        let sierra = serde_json::json!({
            "type_declarations": [],
            "libfunc_declarations": [],
            "statements": [],
            "funcs": []
        });
        let probe = CairoFrontend.probe(&sierra);
        assert!(probe.accepted);
        assert_eq!(probe.format.as_deref(), Some("sierra-json"));
    }

    #[test]
    fn test_cairo_frontend_probe_descriptor() {
        let desc = serde_json::json!({ "sierra_json_path": "/some/path.json" });
        let probe = CairoFrontend.probe(&desc);
        assert!(probe.accepted);
        assert_eq!(probe.format.as_deref(), Some("cairo-descriptor-json"));
    }

    #[test]
    fn test_cairo_frontend_probe_rejects_unknown() {
        let unknown = serde_json::json!({ "something_else": 42 });
        let probe = CairoFrontend.probe(&unknown);
        assert!(!probe.accepted);
        assert!(!probe.notes.is_empty());
    }

    #[test]
    fn test_cairo_frontend_compile_to_ir_rejects_unhandled_libfuncs() {
        let sierra = make_sierra("totally_unknown_op", 200, &[]);
        let descriptor = serde_json::to_value(&sierra).expect("serialize sierra");
        let err = CairoFrontend
            .compile_to_ir(&descriptor, &default_options())
            .expect_err("unsupported Sierra op should fail closed");
        assert!(err.to_string().contains("failed closed"));
        assert!(err.to_string().contains("totally_unknown_op"));
    }

    #[test]
    fn test_cairo_frontend_compile_to_program_family_loads_embedded_zir() {
        let descriptor = serde_json::json!({
            "zir_program": sample_zir_program(),
            "state_source": "snapshot",
            "snapshot_path": "/tmp/state.json",
        });
        let program = CairoFrontend
            .compile_to_program_family(&descriptor, &default_options())
            .expect("embedded zir should load");
        let FrontendProgram::ZirV1(program) = program else {
            panic!("expected zir-v1 program");
        };
        assert_eq!(
            program
                .metadata
                .get("cairo_state_source")
                .map(String::as_str),
            Some("snapshot")
        );
        assert_eq!(
            program
                .metadata
                .get("cairo_snapshot_path")
                .map(String::as_str),
            Some("/tmp/state.json")
        );
    }

    #[test]
    fn test_cairo_frontend_compile_to_program_family_loads_zir_path() {
        let path = unique_temp_path("cairo_zir");
        let zir_program = sample_zir_program();
        fs::write(&path, serde_json::to_vec(&zir_program).unwrap()).unwrap();
        let descriptor = serde_json::json!({
            "compiled_zir_path": path,
        });
        let program = CairoFrontend
            .compile_to_program_family(&descriptor, &default_options())
            .expect("zir path should load");
        let FrontendProgram::ZirV1(program) = program else {
            panic!("expected zir-v1 program");
        };
        assert_eq!(program.name, "test");
    }

    #[test]
    fn test_cairo_frontend_compile_to_ir_rejects_stateful_zir_descriptor() {
        let descriptor = serde_json::json!({
            "zir_program": stateful_zir_program(),
            "state_source": "rpc",
            "rpc_url": "https://rpc.example.invalid",
            "contract_address": "0x1234",
            "entrypoint": "read",
        });
        let err = CairoFrontend
            .compile_to_ir(&descriptor, &default_options())
            .expect_err("stateful zir must stay in zir-v1");
        assert!(err.to_string().contains("requires ZIR v1"));
    }

    #[test]
    fn test_cairo_frontend_compile_to_program_family_rejects_placeholder_sierra_without_zir() {
        let sierra = make_sierra("storage_read", 100, &[10]);
        let descriptor = serde_json::json!({ "sierra_json": sierra });
        let err = CairoFrontend
            .compile_to_program_family(&descriptor, &default_options())
            .expect_err("placeholder sierra surface must require toolchain zir");
        let rendered = err.to_string();
        assert!(rendered.contains("placeholder-only"), "{rendered}");
        assert!(rendered.contains("zir_program"), "{rendered}");
    }

    #[test]
    fn test_cairo_frontend_execute_supports_descriptor_witness_loading() {
        let descriptor = serde_json::json!({
            "execute_command": "true",
            "witness_values": {
                "a": "7",
                "b": 9
            }
        });
        let witness = CairoFrontend
            .execute(&descriptor, &WitnessInputs::default())
            .expect("descriptor execute should load witness");
        assert_eq!(witness.values.get("a"), Some(&FieldElement::new("7")));
        assert_eq!(witness.values.get("b"), Some(&FieldElement::new("9")));
    }

    #[test]
    fn test_cairo_frontend_validate_state_source_requires_backing_field() {
        let descriptor = serde_json::json!({
            "state_source": "rpc",
            "contract_address": "0x1234",
            "entrypoint": "read"
        });
        let err = CairoFrontend
            .compile_to_program_family(&descriptor, &default_options())
            .expect_err("rpc state source without rpc_url must fail");
        assert!(err.to_string().contains("rpc_url"));
    }
}
