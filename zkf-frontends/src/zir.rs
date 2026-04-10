use serde_json::Value;
use std::path::{Path, PathBuf};
use zkf_core::{Program, ZkfError, ZkfResult};
use zkf_lang::{ZirCompileOptions, ZirTier};

use crate::{
    FrontendCapabilities, FrontendEngine, FrontendImportOptions, FrontendInspection, FrontendKind,
    FrontendProbe, FrontendProgram, IrFamilyPreference,
};

#[derive(Clone, Default)]
pub struct ZirFrontend;

#[derive(Debug)]
struct ZirSourceInput {
    source: String,
    entry: Option<String>,
    tier: Option<ZirTier>,
}

impl FrontendEngine for ZirFrontend {
    fn kind(&self) -> FrontendKind {
        FrontendKind::Zir
    }

    fn capabilities(&self) -> FrontendCapabilities {
        FrontendCapabilities {
            frontend: FrontendKind::Zir,
            can_compile_to_ir: true,
            can_execute: false,
            input_formats: vec![
                "zir-source".to_string(),
                "zkf-zir-source-descriptor-json".to_string(),
            ],
            notes: "Native Zir source frontend. Tier 1 is total and bounded; Tier 2 preserves advanced ZIR features and fails closed when forced through unsupported lowerings.".to_string(),
        }
    }

    fn probe(&self, value: &Value) -> FrontendProbe {
        match source_from_value(value, &FrontendImportOptions::default()) {
            Ok(input) => FrontendProbe {
                accepted: zkf_lang::parse_source(&input.source).is_ok(),
                format: Some("zir-source".to_string()),
                noir_version: None,
                notes: vec!["native Zir source".to_string()],
            },
            Err(error) => FrontendProbe {
                accepted: false,
                format: None,
                noir_version: None,
                notes: vec![error.to_string()],
            },
        }
    }

    fn compile_to_ir(&self, value: &Value, options: &FrontendImportOptions) -> ZkfResult<Program> {
        let input = source_from_value(value, options)?;
        let (mut program, _) = zkf_lang::lower_source_to_ir_v2_with_options(
            &input.source,
            &compile_options(&input, options),
        )
        .map_err(map_zir_error)?;
        let report =
            zkf_lang::check_source_with_options(&input.source, &compile_options(&input, options));
        program.metadata.insert(
            "frontend".to_string(),
            FrontendKind::Zir.as_str().to_string(),
        );
        program
            .metadata
            .insert("source_language".to_string(), "zir".to_string());
        program.metadata.insert(
            "source_language_version".to_string(),
            report.language_version,
        );
        program
            .metadata
            .insert("language_tier".to_string(), report.language_tier);
        program
            .metadata
            .insert("zir_source_sha256".to_string(), report.source_digest.hex);
        Ok(program)
    }

    fn compile_to_program_family(
        &self,
        value: &Value,
        options: &FrontendImportOptions,
    ) -> ZkfResult<FrontendProgram> {
        let input = source_from_value(value, options)?;
        let compile_options = compile_options(&input, options);
        match options.ir_family {
            IrFamilyPreference::IrV2 => self
                .compile_to_ir(value, options)
                .map(FrontendProgram::IrV2),
            IrFamilyPreference::ZirV1 | IrFamilyPreference::Auto => {
                let output = zkf_lang::compile_source_with_options(&input.source, &compile_options)
                    .map_err(map_zir_error)?;
                Ok(FrontendProgram::ZirV1(output.zir))
            }
        }
    }

    fn inspect(&self, value: &Value) -> ZkfResult<FrontendInspection> {
        let input = source_from_value(value, &FrontendImportOptions::default())?;
        let inspection = zkf_lang::inspect_source(&input.source).map_err(map_zir_error)?;
        Ok(FrontendInspection {
            frontend: FrontendKind::Zir,
            format: Some("zir-source".to_string()),
            version: Some(inspection.language_version),
            functions: inspection.circuits.len(),
            unconstrained_functions: 0,
            opcode_counts: Default::default(),
            blackbox_counts: Default::default(),
            required_capabilities: Vec::new(),
            dropped_features: Vec::new(),
            requires_hints: false,
        })
    }
}

fn compile_options(input: &ZirSourceInput, options: &FrontendImportOptions) -> ZirCompileOptions {
    ZirCompileOptions {
        entry: input.entry.clone().or_else(|| options.program_name.clone()),
        tier: input.tier,
        allow_tier2: true,
    }
}

fn source_from_value(value: &Value, options: &FrontendImportOptions) -> ZkfResult<ZirSourceInput> {
    if let Value::String(source) = value {
        return Ok(ZirSourceInput {
            source: source.clone(),
            entry: None,
            tier: None,
        });
    }
    let Some(object) = value.as_object() else {
        return Err(ZkfError::InvalidArtifact(
            "Zir frontend expected raw source string or descriptor object".to_string(),
        ));
    };
    if object
        .get("schema")
        .and_then(Value::as_str)
        .is_some_and(|schema| schema != "zkf-zir-source-v1")
    {
        return Err(ZkfError::InvalidArtifact(
            "Zir descriptor schema must be zkf-zir-source-v1".to_string(),
        ));
    }
    let source = if let Some(text) = object.get("source_text").and_then(Value::as_str) {
        text.to_string()
    } else if let Some(path) = object.get("source_path").and_then(Value::as_str) {
        let path = resolve_descriptor_path(path, options.source_path.as_deref());
        std::fs::read_to_string(&path).map_err(|error| {
            ZkfError::InvalidArtifact(format!(
                "failed to read Zir source {}: {error}",
                path.display()
            ))
        })?
    } else {
        return Err(ZkfError::InvalidArtifact(
            "Zir descriptor requires source_text or source_path".to_string(),
        ));
    };
    let tier = object
        .get("tier")
        .and_then(Value::as_str)
        .map(str::parse::<ZirTier>)
        .transpose()
        .map_err(ZkfError::InvalidArtifact)?;
    Ok(ZirSourceInput {
        source,
        entry: object
            .get("entry")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        tier,
    })
}

fn resolve_descriptor_path(path: &str, descriptor_path: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }
    descriptor_path
        .and_then(Path::parent)
        .map(|parent| parent.join(&candidate))
        .unwrap_or(candidate)
}

fn map_zir_error(error: zkf_lang::ZirLangError) -> ZkfError {
    ZkfError::InvalidArtifact(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"
        circuit native(field: bn254) {
          private x: field;
          public y: field;
          y = x + 1;
          expose y;
        }
    "#;

    #[test]
    fn raw_zir_source_import_preserves_zir_family_by_default() {
        let frontend = ZirFrontend;
        let program = frontend
            .compile_to_program_family(&Value::String(SOURCE.to_string()), &Default::default())
            .expect("zir import");
        assert!(matches!(program, FrontendProgram::ZirV1(_)));
    }

    #[test]
    fn forced_ir_v2_import_lowers_raw_source() {
        let frontend = ZirFrontend;
        let program = frontend
            .compile_to_program_family(
                &Value::String(SOURCE.to_string()),
                &FrontendImportOptions {
                    ir_family: IrFamilyPreference::IrV2,
                    ..FrontendImportOptions::default()
                },
            )
            .expect("zir ir-v2 import");
        assert!(matches!(program, FrontendProgram::IrV2(_)));
    }
}
