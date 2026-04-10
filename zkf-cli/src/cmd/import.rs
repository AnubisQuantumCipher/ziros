use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use zkf_core::{
    FrontendProvenance, PackageFileRef, PackageManifest, Program, lowering::LoweringReport,
};
use zkf_frontends::{
    FrontendImportOptions, FrontendInspection, FrontendKind, FrontendProgram, IrFamilyPreference,
    default_frontend_translator, frontend_for,
};

use crate::util::{
    ProgramArtifact, WitnessRequirement, infer_translator_family, infer_witness_requirement,
    parse_field, parse_frontend, read_json, render_zkf_error, warn_if_r1cs_lookup_limit_exceeded,
    write_json, write_json_and_hash,
};

struct ImportedProgram {
    output: ProgramArtifact,
    lowered_v2: Program,
    source_ir_family: String,
    source_program_digest: String,
    lowered_program_digest: Option<String>,
    lowering_report: Option<LoweringReport>,
}

pub(crate) fn run_inspect(
    frontend: FrontendKind,
    input: &Path,
) -> Result<FrontendInspection, String> {
    let value: Value = read_frontend_value(frontend, input)?;
    let engine = frontend_for(frontend);
    engine.inspect(&value).map_err(render_zkf_error)
}

pub(crate) struct ImportOptions<'a> {
    pub frontend: FrontendKind,
    pub input: &'a Path,
    pub out: &'a Path,
    pub name: Option<String>,
    pub field: Option<String>,
    pub ir_family: IrFamilyPreference,
    pub allow_unsupported_version: bool,
    pub package_out: Option<&'a Path>,
    pub json: bool,
}

pub(crate) fn run_import(opts: &ImportOptions<'_>) -> Result<(), String> {
    let ImportOptions {
        frontend,
        input,
        out,
        ref name,
        ref field,
        ir_family,
        allow_unsupported_version,
        package_out,
        json,
    } = *opts;
    let value: Value = read_frontend_value(frontend, input)?;
    let field = field.as_deref().map(parse_field).transpose()?;
    let engine = frontend_for(frontend);
    let probe = engine.probe(&value);
    let compiled = engine
        .compile_to_program_family(
            &value,
            &FrontendImportOptions {
                program_name: name.clone(),
                field,
                allow_unsupported_versions: allow_unsupported_version,
                translator: Some(default_frontend_translator()),
                ir_family,
                source_path: Some(input.to_path_buf()),
            },
        )
        .map_err(render_zkf_error)?;
    let imported = select_import_program(compiled, ir_family)?;
    warn_if_r1cs_lookup_limit_exceeded(
        zkf_core::BackendKind::ArkworksGroth16,
        &imported.lowered_v2,
        "zkf import",
    );
    write_program_artifact(out, &imported.output)?;

    let package_path = if let Some(package_out) = package_out {
        Some(write_package(
            package_out,
            &imported,
            frontend,
            &probe,
            input,
            &value,
            allow_unsupported_version,
        )?)
    } else {
        None
    };

    if json {
        let summary = serde_json::json!({
            "frontend": frontend.as_str(),
            "out": out.display().to_string(),
            "package_out": package_path.as_ref().map(|path| path.display().to_string()),
            "program": {
                "name": imported.output.name(),
                "field": imported.output.field(),
                "signals": imported.output.signal_count(),
                "constraints": imported.output.constraint_count(),
                "ir_family": imported.output.ir_family(),
                "source_ir_family": imported.source_ir_family,
                "source_program_digest": imported.source_program_digest,
                "lowered_program_digest": imported.lowered_program_digest,
            },
            "lowering_report": imported.lowering_report,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
        );
    } else {
        println!("imported {} artifact -> {}", frontend, out.display());
        println!(
            "  family={}, {} signals ({} private, {} public), {} constraints, field={}",
            imported.output.ir_family(),
            imported.lowered_v2.signals.len(),
            imported
                .lowered_v2
                .signals
                .iter()
                .filter(|s| s.visibility == zkf_core::Visibility::Private)
                .count(),
            imported
                .lowered_v2
                .signals
                .iter()
                .filter(|s| s.visibility == zkf_core::Visibility::Public)
                .count(),
            imported.lowered_v2.constraints.len(),
            imported.lowered_v2.field,
        );
        if !imported.lowered_v2.witness_plan.input_aliases.is_empty() {
            println!("  input mapping (use either name in your inputs JSON):");
            for (alias, signal) in &imported.lowered_v2.witness_plan.input_aliases {
                let vis = imported
                    .lowered_v2
                    .signal(signal)
                    .map(|s| format!("{:?}", s.visibility).to_lowercase())
                    .unwrap_or_default();
                println!("    {alias} -> {signal} ({vis})");
            }
        }
        if let Some(solver) = imported.lowered_v2.metadata.get("solver") {
            println!(
                "  auto-solver: {solver} (intermediate witness values computed automatically)"
            );
        }
        println!(
            "  source_ir_family={}, source_program_digest={}",
            imported.source_ir_family, imported.source_program_digest
        );
        if let Some(lowered_program_digest) = &imported.lowered_program_digest {
            println!("  lowered_program_digest={lowered_program_digest}");
        }
        if let Some(path) = package_path {
            println!("wrote package manifest: {}", path.display());
        }
    }
    Ok(())
}

fn write_package(
    package_out: &Path,
    imported: &ImportedProgram,
    frontend: FrontendKind,
    probe: &zkf_frontends::FrontendProbe,
    source_path: &Path,
    original_artifact: &Value,
    allow_unsupported_version: bool,
) -> Result<PathBuf, String> {
    let program_dir_name = match imported.output.ir_family() {
        "zir-v1" => "zir",
        _ => "ir",
    };
    let program_dir = package_out.join(program_dir_name);
    fs::create_dir_all(&program_dir).map_err(|e| format!("{}: {e}", program_dir.display()))?;

    let package_program_rel = PathBuf::from(format!("{program_dir_name}/program.json"));
    let package_program = package_out.join(&package_program_rel);
    let program_sha = write_program_artifact_and_hash(&package_program, &imported.output)?;

    let frontend_dir = package_out.join("frontends").join(frontend.as_str());
    fs::create_dir_all(&frontend_dir).map_err(|e| format!("{}: {e}", frontend_dir.display()))?;
    let original_artifact_rel = PathBuf::from(format!("frontends/{}/original.json", frontend));
    let original_artifact_path = package_out.join(&original_artifact_rel);
    let original_artifact_sha = write_json_and_hash(&original_artifact_path, original_artifact)?;

    let mut frontend_provenance = FrontendProvenance::new(frontend.as_str());
    frontend_provenance.format = probe.format.clone();
    frontend_provenance.version = probe.noir_version.clone();
    frontend_provenance.source = Some(source_path.display().to_string());
    let translator_used =
        probe.notes.iter().any(|note| note.contains("incompatible")) && !allow_unsupported_version;
    let translator_family = infer_translator_family(frontend, probe);
    if translator_used {
        frontend_provenance.translator = Some(translator_family.clone());
    }

    let inspection = frontend_for(frontend).inspect(original_artifact).ok();
    let witness_requirement = infer_witness_requirement(&imported.lowered_v2, inspection.as_ref());
    let requires_hints = inspection.as_ref().is_some_and(|s| s.requires_hints);
    let dropped_features = inspection
        .as_ref()
        .map(|s| s.dropped_features.clone())
        .unwrap_or_default();
    let lossy = !dropped_features.is_empty();

    let mut manifest = PackageManifest::from_program(
        &imported.lowered_v2,
        frontend_provenance,
        package_program_rel.display().to_string(),
        original_artifact_rel.display().to_string(),
    );
    manifest.package_name = imported.output.name().to_string();
    manifest.field = imported.output.field();
    manifest.program_digest = imported.output.digest_hex();
    manifest.files.cache_dir = Some("cache".to_string());
    manifest.files.program.sha256 = program_sha;
    manifest.files.original_artifact.sha256 = original_artifact_sha;

    if translator_used {
        let translation_report = serde_json::json!({
            "status": "translated",
            "translator_id": translator_family,
            "target": "acir-0.46",
            "frontend": frontend.as_str(),
            "lossy": lossy,
            "dropped_features": dropped_features,
            "requires_hints": requires_hints,
            "source_noir_version": probe.noir_version,
            "source_path": source_path.display().to_string(),
            "source_sha256": manifest.files.original_artifact.sha256,
            "notes": probe.notes,
        });
        let translation_rel = PathBuf::from("translation/report.json");
        let translation_path = package_out.join(&translation_rel);
        let translation_sha = write_json_and_hash(&translation_path, &translation_report)?;
        manifest.files.translation_report = Some(PackageFileRef {
            path: translation_rel.display().to_string(),
            sha256: translation_sha,
        });
    }

    manifest.metadata.insert(
        "signals".to_string(),
        imported.output.signal_count().to_string(),
    );
    manifest.metadata.insert(
        "ir_family".to_string(),
        imported.output.ir_family().to_string(),
    );
    manifest.metadata.insert(
        "ir_version".to_string(),
        match imported.output.ir_family() {
            "zir-v1" => "1",
            _ => "2",
        }
        .to_string(),
    );
    manifest.metadata.insert(
        "source_ir_family".to_string(),
        imported.source_ir_family.clone(),
    );
    manifest.metadata.insert(
        "source_program_digest".to_string(),
        imported.source_program_digest.clone(),
    );
    if let Some(lowered_program_digest) = &imported.lowered_program_digest {
        manifest.metadata.insert(
            "lowered_program_digest".to_string(),
            lowered_program_digest.clone(),
        );
    }
    manifest
        .metadata
        .entry("strict_mode".to_string())
        .or_insert_with(|| "true".to_string());
    manifest.metadata.insert(
        "constraints".to_string(),
        imported.output.constraint_count().to_string(),
    );
    manifest
        .metadata
        .insert("requires_hints".to_string(), requires_hints.to_string());
    manifest.metadata.insert(
        "requires_execution".to_string(),
        (witness_requirement == WitnessRequirement::Execution).to_string(),
    );
    manifest.metadata.insert(
        "requires_solver".to_string(),
        (witness_requirement == WitnessRequirement::Solver).to_string(),
    );
    manifest
        .metadata
        .insert("allow_builtin_fallback".to_string(), "false".to_string());
    manifest.metadata.insert(
        "witness_requirement".to_string(),
        witness_requirement.as_str().to_string(),
    );
    if !inspection
        .as_ref()
        .map(|s| s.required_capabilities.is_empty())
        .unwrap_or(true)
    {
        let required_capabilities = inspection
            .as_ref()
            .map(|s| s.required_capabilities.join(","))
            .unwrap_or_default();
        manifest
            .metadata
            .insert("required_capabilities".to_string(), required_capabilities);
    }
    if let Some(lowering_report) = &imported.lowering_report {
        let lowering_rel = PathBuf::from("lowering/report.json");
        let lowering_path = package_out.join(&lowering_rel);
        let lowering_sha = write_json_and_hash(&lowering_path, lowering_report)?;
        manifest.metadata.insert(
            "lowering_report_path".to_string(),
            lowering_rel.display().to_string(),
        );
        manifest
            .metadata
            .insert("lowering_report_sha256".to_string(), lowering_sha);
    }

    let manifest_path = package_out.join("manifest.json");
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    write_json(&manifest_path, &manifest)?;
    Ok(manifest_path)
}

pub(crate) struct HandleImportArgs {
    pub frontend: String,
    pub input: PathBuf,
    pub out: PathBuf,
    pub name: Option<String>,
    pub field: Option<String>,
    pub ir_family: String,
    pub allow_unsupported_version: bool,
    pub package_out: Option<PathBuf>,
    pub json: bool,
}

pub(crate) fn handle_import(args: HandleImportArgs) -> Result<(), String> {
    let frontend = parse_frontend(&args.frontend)?;
    let ir_family = args.ir_family.parse::<IrFamilyPreference>()?;
    run_import(&ImportOptions {
        frontend,
        input: &args.input,
        out: &args.out,
        name: args.name,
        field: args.field,
        ir_family,
        allow_unsupported_version: args.allow_unsupported_version,
        package_out: args.package_out.as_deref(),
        json: args.json,
    })
}

pub(crate) fn handle_inspect(frontend: String, input: PathBuf, json: bool) -> Result<(), String> {
    if frontend.eq_ignore_ascii_case("auto") {
        return handle_auto_inspect(input, json);
    }

    let frontend = parse_frontend(&frontend)?;
    let inspection = run_inspect(frontend, &input)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "inspect {}: functions={}, opcodes={}, capabilities={}",
            frontend,
            inspection.functions,
            inspection.opcode_counts.values().sum::<usize>(),
            inspection.required_capabilities.join(",")
        );
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct NativeProgramInspection {
    frontend: &'static str,
    ir_family: &'static str,
    name: String,
    field: String,
    signals: usize,
    constraints: usize,
    digest: String,
}

fn inspect_native_program(input: &Path) -> Result<NativeProgramInspection, String> {
    let artifact = crate::util::read_program_artifact(input)?;
    Ok(NativeProgramInspection {
        frontend: "native-zkf",
        ir_family: artifact.ir_family(),
        name: artifact.name().to_string(),
        field: artifact.field().to_string(),
        signals: artifact.signal_count(),
        constraints: artifact.constraint_count(),
        digest: artifact.digest_hex(),
    })
}

fn handle_auto_inspect(input: PathBuf, json: bool) -> Result<(), String> {
    if let Ok(native) = inspect_native_program(&input) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&native).map_err(|e| e.to_string())?
            );
        } else {
            println!(
                "inspect {}: family={}, signals={}, constraints={}, field={}",
                native.frontend, native.ir_family, native.signals, native.constraints, native.field
            );
        }
        return Ok(());
    }

    let candidates = [
        FrontendKind::Zir,
        FrontendKind::Noir,
        FrontendKind::Circom,
        FrontendKind::Cairo,
        FrontendKind::Compact,
        FrontendKind::Halo2Rust,
        FrontendKind::Plonky3Air,
        FrontendKind::Zkvm,
    ];
    let mut last_err = None;
    for frontend in candidates {
        match run_inspect(frontend, &input) {
            Ok(inspection) => {
                if json {
                    let payload = serde_json::json!({
                        "frontend": frontend.as_str(),
                        "inspection": inspection,
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?
                    );
                } else {
                    println!(
                        "inspect {}: functions={}, opcodes={}, capabilities={}",
                        frontend,
                        inspection.functions,
                        inspection.opcode_counts.values().sum::<usize>(),
                        inspection.required_capabilities.join(",")
                    );
                }
                return Ok(());
            }
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        format!(
            "{}: failed to inspect as native ZKF IR or any supported frontend artifact",
            input.display()
        )
    }))
}

fn read_frontend_value(frontend: FrontendKind, input: &Path) -> Result<Value, String> {
    if frontend != FrontendKind::Zir {
        return read_json(input);
    }
    let text =
        fs::read_to_string(input).map_err(|error| format!("{}: {error}", input.display()))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(value)
            if value
                .get("schema")
                .and_then(Value::as_str)
                .is_some_and(|schema| schema == "zkf-zir-source-v1") =>
        {
            Ok(value)
        }
        _ => Ok(Value::String(text)),
    }
}

pub(crate) fn handle_import_acir(
    input: PathBuf,
    out: PathBuf,
    name: Option<String>,
    field: Option<String>,
    ir_family: String,
    package_out: Option<PathBuf>,
) -> Result<(), String> {
    let ir_family = ir_family.parse::<IrFamilyPreference>()?;
    run_import(&ImportOptions {
        frontend: FrontendKind::Noir,
        input: &input,
        out: &out,
        name,
        field,
        ir_family,
        allow_unsupported_version: false,
        package_out: package_out.as_deref(),
        json: false,
    })
}

pub(crate) fn handle_emit_example(out: PathBuf, field: Option<String>) -> Result<(), String> {
    let field = field
        .as_deref()
        .map(parse_field)
        .transpose()?
        .unwrap_or(zkf_core::FieldId::Bn254);
    write_json(&out, &zkf_examples::mul_add_program_with_field(field))?;
    println!("wrote example program: {} (field={field})", out.display());
    Ok(())
}

fn select_import_program(
    compiled: FrontendProgram,
    preference: IrFamilyPreference,
) -> Result<ImportedProgram, String> {
    let source_ir_family = compiled.ir_family().to_string();
    let source_program_digest = compiled.digest_hex();
    let source_zir = match &compiled {
        FrontendProgram::ZirV1(program) => Some(program.clone()),
        FrontendProgram::IrV2(_) => None,
    };
    let output = match preference {
        IrFamilyPreference::Auto => match compiled {
            FrontendProgram::IrV2(program) => ProgramArtifact::IrV2(program),
            FrontendProgram::ZirV1(program) => ProgramArtifact::ZirV1(program),
        },
        IrFamilyPreference::ZirV1 => ProgramArtifact::ZirV1(compiled.promote_to_zir_v1()),
        IrFamilyPreference::IrV2 => {
            ProgramArtifact::IrV2(compiled.lower_to_ir_v2().map_err(render_zkf_error)?)
        }
    };

    let lowered_v2 = output.lower_to_ir_v2()?;
    let lowered_program_digest = (source_ir_family == "zir-v1").then(|| lowered_v2.digest_hex());
    let lowering_report = match (&output, source_ir_family.as_str(), preference) {
        (ProgramArtifact::IrV2(_), "zir-v1", IrFamilyPreference::IrV2) => source_zir
            .as_ref()
            .map(|program| build_zir_lowering_report(program, &lowered_v2)),
        _ => None,
    };

    Ok(ImportedProgram {
        output,
        lowered_v2,
        source_ir_family,
        source_program_digest,
        lowered_program_digest,
        lowering_report,
    })
}

fn build_zir_lowering_report(
    program: &zkf_core::zir_v1::Program,
    lowered: &Program,
) -> LoweringReport {
    let mut native_features = Vec::new();
    let mut adapted_features = Vec::new();
    let mut incompatibilities = Vec::new();

    let has_typed_signals = program
        .signals
        .iter()
        .any(|signal| !matches!(signal.ty, zkf_core::zir_v1::SignalType::Field));
    if has_typed_signals {
        adapted_features.push("typed-signals".to_string());
    }
    if program
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, zkf_core::zir_v1::Constraint::Copy { .. }))
    {
        adapted_features.push("copy-constraints".to_string());
    }
    if program
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, zkf_core::zir_v1::Constraint::Permutation { .. }))
    {
        adapted_features.push("permutation-constraints".to_string());
    }

    for feature in ["equal", "boolean", "range", "lookup", "blackbox"] {
        let present =
            match feature {
                "equal" => program.constraints.iter().any(|constraint| {
                    matches!(constraint, zkf_core::zir_v1::Constraint::Equal { .. })
                }),
                "boolean" => program.constraints.iter().any(|constraint| {
                    matches!(constraint, zkf_core::zir_v1::Constraint::Boolean { .. })
                }),
                "range" => program.constraints.iter().any(|constraint| {
                    matches!(constraint, zkf_core::zir_v1::Constraint::Range { .. })
                }),
                "lookup" => program.constraints.iter().any(|constraint| {
                    matches!(constraint, zkf_core::zir_v1::Constraint::Lookup { .. })
                }),
                "blackbox" => program.constraints.iter().any(|constraint| {
                    matches!(constraint, zkf_core::zir_v1::Constraint::BlackBox { .. })
                }),
                _ => false,
            };
        if present {
            native_features.push(feature.to_string());
        }
    }

    if has_typed_signals {
        incompatibilities.push(
            "IR v2 does not preserve ZIR signal type annotations; types were lowered to field signals."
                .to_string(),
        );
    }

    LoweringReport {
        native_features,
        adapted_features,
        delegated_features: Vec::new(),
        dropped_features: Vec::new(),
        aux_variable_count: 0,
        original_constraint_count: program.constraints.len(),
        final_constraint_count: lowered.constraints.len(),
        incompatibilities,
    }
}

fn write_program_artifact(path: &Path, program: &ProgramArtifact) -> Result<(), String> {
    match program {
        ProgramArtifact::IrV2(program) => write_json(path, program),
        ProgramArtifact::ZirV1(program) => write_json(path, program),
    }
}

fn write_program_artifact_and_hash(
    path: &Path,
    program: &ProgramArtifact,
) -> Result<String, String> {
    match program {
        ProgramArtifact::IrV2(program) => write_json_and_hash(path, program),
        ProgramArtifact::ZirV1(program) => write_json_and_hash(path, program),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_example_honors_requested_field() {
        let root = std::env::temp_dir().join(format!("zkf-emit-example-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let out = root.join("example.json");

        handle_emit_example(out.clone(), Some("goldilocks".to_string())).unwrap();

        let program: Program = read_json(&out).unwrap();
        assert_eq!(program.field, zkf_core::FieldId::Goldilocks);
    }

    #[test]
    fn inspect_auto_detects_native_programs() {
        let root = std::env::temp_dir().join(format!("zkf-inspect-auto-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("program.json");
        write_json(&input, &zkf_examples::mul_add_program()).unwrap();

        let inspection = inspect_native_program(&input).unwrap();
        assert_eq!(inspection.frontend, "native-zkf");
        assert_eq!(inspection.ir_family, "ir-v2");
        assert_eq!(inspection.signals, 4);
    }
}
