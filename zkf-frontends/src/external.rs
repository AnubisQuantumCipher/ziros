//! External-tool-driven frontends for descriptor-based workflows.
//!
//! These frontends support import and execution via external toolchains
//! (shell commands, CLI tools, Docker containers). They accept JSON
//! descriptors containing embedded programs, file paths, or command hooks,
//! and delegate compilation/execution to external processes.

mod compact_zkir;

use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use zkf_core::{
    FieldElement, Program, ToolRequirement, Witness, WitnessInputs, ZkfError, ZkfResult,
};

pub struct CompactFrontend;
pub struct ZkvmFrontend;

impl FrontendEngine for CompactFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Compact
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Compact,
            can_compile_to_ir: true,
            can_execute: true,
            input_formats: vec![
                "compact-zkir-json".to_string(),
                "compact-descriptor-json".to_string(),
                "zkf-program-json".to_string(),
                "compact-source".to_string(),
            ],
            notes: "Midnight Compact frontend: imports local compactc 0.30.0 zkir v2.0 circuits directly, auto-discovers contract sidecars when available, and still supports descriptor-based fallback flows.".to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let zkir_match = compact_zkir::is_probable_zkir_value(value);

        // Check descriptor keys
        let descriptor_match = value.get("program").is_some()
            || value.get("ir_program").is_some()
            || value.get("compiled_ir_path").is_some()
            || value.get("compile_command").is_some()
            || value.get("zkir").is_some()
            || value.get("zkir_path").is_some();

        // Check for .compact file extension in path fields
        let compact_extension = value
            .get("source_path")
            .and_then(Value::as_str)
            .is_some_and(|p| p.ends_with(".compact"));

        // Check for Compact-specific keywords in source content
        let compact_keyword = value
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("contract ") || s.contains("export circuit"));

        let accepted = zkir_match || descriptor_match || compact_extension || compact_keyword;
        FrontendProbe {
            accepted,
            format: accepted.then_some(if zkir_match {
                "compact-zkir-json".to_string()
            } else {
                "compact-descriptor-json".to_string()
            }),
            noir_version: None,
            notes: if accepted {
                vec![]
            } else {
                vec![
                    "expected Compact zkir v2 JSON or a Compact descriptor with `program`/`ir_program`/`compiled_ir_path`/`zkir_path`, `compile_command`, `.compact` source, or `contract` keyword".to_string(),
                ]
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        if let Some(command) = value.get("compile_command").and_then(Value::as_str) {
            run_shell_command(command, "frontend/compact/compile")?;
        }
        if let Some(program) = compact_zkir::compile_from_value(value, options)? {
            return Ok(program);
        }
        load_program_from_descriptor(value, options, self.kind())
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let program = if let Some(program) =
            compact_zkir::compile_from_value(value, &FrontendImportOptions::default())?
        {
            program
        } else {
            load_program_from_descriptor(value, &FrontendImportOptions::default(), self.kind())?
        };
        Ok(basic_inspection(self.kind(), probe, &program))
    }

    fn execute(&self, value: &Value, _inputs: &WitnessInputs) -> ZkfResult<Witness> {
        if let Some(command) = value.get("execute_command").and_then(Value::as_str) {
            run_shell_command(command, "frontend/compact/execute")?;
        }
        load_witness_from_descriptor(value, self.kind())
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "compact".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Midnight Compact compiler CLI".to_string()),
                required: false,
            },
            ToolRequirement {
                tool: "docker".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Typical local Midnight proof-server runtime".to_string()),
                required: false,
            },
            ToolRequirement {
                tool: "node".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Compact.js runtime".to_string()),
                required: false,
            },
        ]
    }
}

impl FrontendEngine for ZkvmFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Zkvm
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Zkvm,
            can_compile_to_ir: true,
            can_execute: true,
            input_formats: vec![
                "zkvm-descriptor-json".to_string(),
                "zkf-program-json".to_string(),
            ],
            notes: "External-tool frontend for zkVM (SP1, RISC Zero): supports descriptor-based import/execute with toolchain hooks, ELF binary detection, and witness loading."
                .to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        let descriptor_match = value.get("program").is_some()
            || value.get("ir_program").is_some()
            || value.get("compiled_ir_path").is_some()
            || value.get("build_command").is_some();

        // Detect ELF binaries by magic bytes in base64-encoded content
        let elf_magic = value
            .get("elf_bytes")
            .and_then(Value::as_str)
            .is_some_and(|s| {
                // ELF magic: 0x7f 'E' 'L' 'F' → base64 starts with "f0VM"
                s.starts_with("f0VM")
            });

        // Detect ELF file path
        let elf_path = value
            .get("elf_path")
            .and_then(Value::as_str)
            .is_some_and(|p| {
                // Check for ELF magic bytes in file
                std::fs::read(p)
                    .ok()
                    .is_some_and(|bytes| bytes.starts_with(b"\x7fELF"))
            });

        let accepted = descriptor_match || elf_magic || elf_path;
        FrontendProbe {
            accepted,
            format: accepted.then_some("zkvm-descriptor-json".to_string()),
            noir_version: None,
            notes: if accepted {
                vec![]
            } else {
                vec![
                    "expected zkVM descriptor with `program`/`ir_program`/`compiled_ir_path`, `build_command`, or ELF binary".to_string(),
                ]
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        if let Some(command) = value.get("build_command").and_then(Value::as_str) {
            run_shell_command(command, "frontend/zkvm/build")?;
        }
        load_program_from_descriptor(value, options, self.kind())
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let probe = self.probe(value);
        let program =
            load_program_from_descriptor(value, &FrontendImportOptions::default(), self.kind())?;
        Ok(basic_inspection(self.kind(), probe, &program))
    }

    fn execute(&self, value: &Value, _inputs: &WitnessInputs) -> ZkfResult<Witness> {
        if let Some(command) = value.get("execute_command").and_then(Value::as_str) {
            run_shell_command(command, "frontend/zkvm/execute")?;
        }
        load_witness_from_descriptor(value, self.kind())
    }

    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        vec![
            ToolRequirement {
                tool: "cargo".to_string(),
                args: vec!["--version".to_string()],
                note: Some("Rust build toolchain for zkVM guest programs".to_string()),
                required: true,
            },
            ToolRequirement {
                tool: "sp1up".to_string(),
                args: vec!["--version".to_string()],
                note: Some("SP1 toolchain manager (optional)".to_string()),
                required: false,
            },
        ]
    }
}

fn load_program_from_descriptor(
    value: &Value,
    options: &FrontendImportOptions,
    kind: FrontendKind,
) -> ZkfResult<Program> {
    let mut program = if let Some(program_value) = value.get("program").or(value.get("ir_program"))
    {
        serde_json::from_value(program_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize embedded program for frontend '{}': {err}",
                kind
            ))
        })?
    } else if let Some(path) = value.get("compiled_ir_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        let content = fs::read_to_string(&path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading compiled_ir_path '{}': {err}",
                path.display()
            ))
        })?;
        serde_json::from_str::<Program>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize program from '{}': {err}",
                path.display()
            ))
        })?
    } else {
        serde_json::from_value::<Program>(value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "frontend '{}' expects `program`/`ir_program`/`compiled_ir_path` or direct Program JSON: {err}",
                kind
            ))
        })?
    };

    if let Some(name) = options.program_name.as_ref() {
        program.name = name.clone();
    }
    if let Some(field) = options.field {
        program.field = field;
    }
    Ok(program)
}

fn load_witness_from_descriptor(value: &Value, kind: FrontendKind) -> ZkfResult<Witness> {
    if let Some(witness_value) = value.get("witness") {
        return serde_json::from_value(witness_value.clone()).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize embedded witness for frontend '{}': {err}",
                kind
            ))
        });
    }

    if let Some(path) = value.get("witness_path").and_then(Value::as_str) {
        let path = PathBuf::from(path);
        let content = fs::read_to_string(&path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading witness_path '{}': {err}",
                path.display()
            ))
        })?;
        return serde_json::from_str::<Witness>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize witness from '{}': {err}",
                path.display()
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
        backend: format!("frontend/{kind}/execute"),
        message: "descriptor missing `witness`, `witness_path`, or `witness_values`".to_string(),
    })
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

fn basic_inspection(
    kind: FrontendKind,
    probe: FrontendProbe,
    program: &Program,
) -> FrontendInspection {
    let mut opcode_counts = BTreeMap::new();
    opcode_counts.insert("constraints".to_string(), program.constraints.len());
    opcode_counts.insert("signals".to_string(), program.signals.len());

    let mut blackbox_counts = BTreeMap::new();
    for constraint in &program.constraints {
        if let zkf_core::Constraint::BlackBox { op, .. } = constraint {
            *blackbox_counts.entry(op.as_str().to_string()).or_insert(0) += 1;
        }
    }

    FrontendInspection {
        frontend: kind,
        format: probe.format,
        version: probe.noir_version,
        functions: 1,
        unconstrained_functions: 0,
        opcode_counts,
        blackbox_counts,
        required_capabilities: Vec::new(),
        dropped_features: Vec::new(),
        requires_hints: !program.witness_plan.hints.is_empty(),
    }
}
