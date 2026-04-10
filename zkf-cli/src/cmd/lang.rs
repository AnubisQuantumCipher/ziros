use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zkf_core::{FrontendProvenance, PackageFileRef, PackageManifest};

use crate::util::{read_json, sha256_hex, write_json, write_json_and_hash};

use super::prove;

pub(crate) struct LangProveArgs {
    pub(crate) source: PathBuf,
    pub(crate) inputs: PathBuf,
    pub(crate) json: bool,
    pub(crate) backend: Option<String>,
    pub(crate) objective: String,
    pub(crate) mode: Option<String>,
    pub(crate) export: Option<String>,
    pub(crate) allow_attestation: bool,
    pub(crate) out: PathBuf,
    pub(crate) compiled_out: Option<PathBuf>,
    pub(crate) solver: Option<String>,
    pub(crate) seed: Option<String>,
    pub(crate) groth16_setup_blob: Option<PathBuf>,
    pub(crate) allow_dev_deterministic_groth16: bool,
    pub(crate) hybrid: bool,
}

pub(crate) struct LangVerifyArgs {
    pub(crate) source: PathBuf,
    pub(crate) artifact: PathBuf,
    pub(crate) backend: String,
    pub(crate) compiled: Option<PathBuf>,
    pub(crate) seed: Option<String>,
    pub(crate) groth16_setup_blob: Option<PathBuf>,
    pub(crate) allow_dev_deterministic_groth16: bool,
    pub(crate) hybrid: bool,
}

pub(crate) fn handle_lang_check(source: PathBuf, json: bool) -> Result<(), String> {
    let text = read_source(&source)?;
    let report = zkf_lang::check_source(&text);

    if json {
        print_json(&report)?;
    } else if report.ok {
        println!("Zir source check passed: {}", source.display());
        if let Some(entry) = &report.entry {
            println!("  entry: {entry}");
        }
        if let Some(field) = report.field {
            println!("  field: {field}");
        }
        println!(
            "  signals: {} public, {} private",
            report.public_signals.len(),
            report.private_signals.len()
        );
        println!("  constraints: {}", report.constraint_count);
        println!("  obligations: {}", report.proof_obligations.len());
    } else {
        print_diagnostics(&report.diagnostics);
    }

    if report.ok {
        Ok(())
    } else {
        Err(format!(
            "zir source check failed for {} with {} diagnostic(s)",
            source.display(),
            report.diagnostics.len()
        ))
    }
}

pub(crate) fn handle_lang_lower(
    source: PathBuf,
    out: PathBuf,
    to: String,
    json: bool,
) -> Result<(), String> {
    let text = read_source(&source)?;
    match to.as_str() {
        "zir" | "zir-v1" => {
            let output = zkf_lang::compile_source_to_zir(&text).map_err(render_lang_error)?;
            write_json(&out, &output.zir)?;
            if json {
                let report = serde_json::json!({
                    "ok": true,
                    "source": source.display().to_string(),
                    "out": out.display().to_string(),
                    "target": "zir-v1",
                    "program": output.report,
                    "digest": output.zir.digest_hex(),
                });
                print_json(&report)?;
            } else {
                println!(
                    "lowered Zir source to ZIR v1: {} -> {}",
                    source.display(),
                    out.display()
                );
                println!("  digest: {}", output.zir.digest_hex());
            }
        }
        "ir" | "ir-v2" => {
            let (program, report) =
                zkf_lang::lower_source_to_ir_v2(&text).map_err(render_lang_error)?;
            write_json(&out, &program)?;
            if json {
                let summary = serde_json::json!({
                    "ok": true,
                    "source": source.display().to_string(),
                    "out": out.display().to_string(),
                    "target": "ir-v2",
                    "program": report,
                    "digest": program.digest_hex(),
                });
                print_json(&summary)?;
            } else {
                println!(
                    "lowered Zir source to IR v2: {} -> {}",
                    source.display(),
                    out.display()
                );
                println!("  digest: {}", program.digest_hex());
            }
        }
        other => {
            return Err(format!(
                "unsupported lang lower target '{other}' (expected zir-v1 or ir-v2)"
            ));
        }
    }
    Ok(())
}

pub(crate) fn handle_lang_inspect(source: PathBuf, json: bool) -> Result<(), String> {
    let text = read_source(&source)?;
    let inspection = zkf_lang::inspect_source(&text).map_err(render_lang_error)?;
    if json {
        print_json(&inspection)?;
    } else {
        println!(
            "Zir source inspect: {} (circuits={})",
            source.display(),
            inspection.circuits.len()
        );
        for circuit in &inspection.circuits {
            println!(
                "  - {} field={} tier={} items={}",
                circuit.name, circuit.field, circuit.tier, circuit.item_count
            );
        }
    }
    Ok(())
}

pub(crate) fn handle_lang_package(
    source: PathBuf,
    out: PathBuf,
    to: String,
    json: bool,
) -> Result<(), String> {
    let text = read_source(&source)?;
    let output = zkf_lang::compile_source_to_zir(&text).map_err(render_lang_error)?;
    let (program_rel, program_sha, ir_family, program_digest) = match to.as_str() {
        "zir" | "zir-v1" => {
            let rel = PathBuf::from("zir/program.json");
            let path = out.join(&rel);
            let sha = write_json_and_hash(&path, &output.zir)?;
            (rel, sha, "zir-v1".to_string(), output.zir.digest_hex())
        }
        "ir" | "ir-v2" => {
            let (program, _) = zkf_lang::lower_source_to_ir_v2(&text).map_err(render_lang_error)?;
            let rel = PathBuf::from("ir/program.json");
            let path = out.join(&rel);
            let sha = write_json_and_hash(&path, &program)?;
            (rel, sha, "ir-v2".to_string(), program.digest_hex())
        }
        other => {
            return Err(format!(
                "unsupported lang package target '{other}' (expected zir-v1 or ir-v2)"
            ));
        }
    };

    let frontend_dir = out.join("frontends/zir");
    fs::create_dir_all(&frontend_dir)
        .map_err(|error| format!("{}: {error}", frontend_dir.display()))?;
    let source_rel = PathBuf::from("frontends/zir/source.zir");
    let source_path = out.join(&source_rel);
    if let Some(parent) = source_path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(&source_path, &text)
        .map_err(|error| format!("{}: {error}", source_path.display()))?;
    let source_sha = sha256_hex(text.as_bytes());

    let descriptor = serde_json::json!({
        "schema": "zkf-zir-source-v1",
        "source_path": "source.zir",
        "entry": output.report.program_name,
        "tier": output.report.language_tier,
        "source_sha256": output.report.source_digest.hex,
    });
    let descriptor_rel = PathBuf::from("frontends/zir/descriptor.json");
    let descriptor_sha = write_json_and_hash(&out.join(&descriptor_rel), &descriptor)?;

    let check_report = zkf_lang::check_source(&text);
    let check_rel = PathBuf::from("frontends/zir/check-report.json");
    let check_sha = write_json_and_hash(&out.join(&check_rel), &check_report)?;
    let obligations = serde_json::json!({
        "source": source.display().to_string(),
        "source_digest": output.report.source_digest,
        "proof_obligations": output.report.proof_obligations,
    });
    let obligations_rel = PathBuf::from("frontends/zir/obligations.json");
    let obligations_sha = write_json_and_hash(&out.join(&obligations_rel), &obligations)?;
    let source_map = serde_json::json!({
        "source_digest": check_report.source_digest,
        "entries": [],
        "note": "source map is constraint-level ready; individual span mapping is emitted by future parser span expansion"
    });
    let source_map_rel = PathBuf::from("frontends/zir/source-map.json");
    let source_map_sha = write_json_and_hash(&out.join(&source_map_rel), &source_map)?;

    let mut provenance = FrontendProvenance::new("zir");
    provenance.version = Some(zkf_lang::ZIR_LANGUAGE_VERSION.to_string());
    provenance.format = Some("zir-source".to_string());
    provenance.source = Some(source.display().to_string());
    let manifest_program = zkf_core::program_zir_to_v2(&output.zir).unwrap_or_else(|_| {
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("ir_family".to_string(), "zir-v1".to_string());
        metadata.insert("zir_only_package_manifest".to_string(), "true".to_string());
        zkf_core::Program {
            name: output.zir.name.clone(),
            field: output.zir.field,
            signals: Vec::new(),
            constraints: Vec::new(),
            witness_plan: Default::default(),
            lookup_tables: Vec::new(),
            metadata,
        }
    });
    let mut manifest = PackageManifest::from_program(
        &manifest_program,
        provenance,
        program_rel.display().to_string(),
        descriptor_rel.display().to_string(),
    );
    manifest.package_name = output.zir.name.clone();
    manifest.program_digest = program_digest.clone();
    manifest.files.program.sha256 = program_sha;
    manifest.files.original_artifact.sha256 = descriptor_sha;
    manifest.files.source = Some(PackageFileRef {
        path: source_rel.display().to_string(),
        sha256: source_sha.clone(),
    });
    manifest.files.source_map = Some(PackageFileRef {
        path: source_map_rel.display().to_string(),
        sha256: source_map_sha,
    });
    manifest.files.check_report = Some(PackageFileRef {
        path: check_rel.display().to_string(),
        sha256: check_sha,
    });
    manifest.files.obligations = Some(PackageFileRef {
        path: obligations_rel.display().to_string(),
        sha256: obligations_sha,
    });
    manifest
        .metadata
        .insert("frontend".to_string(), "zir".to_string());
    manifest.metadata.insert(
        "source_language".to_string(),
        zkf_lang::ZIR_LANGUAGE_NAME.to_string(),
    );
    manifest.metadata.insert(
        "source_language_version".to_string(),
        zkf_lang::ZIR_LANGUAGE_VERSION.to_string(),
    );
    manifest.metadata.insert(
        "language_tier".to_string(),
        output.report.language_tier.clone(),
    );
    manifest
        .metadata
        .insert("source_sha256".to_string(), source_sha.clone());
    manifest
        .metadata
        .insert("zir_digest".to_string(), output.zir.digest_hex());
    manifest
        .metadata
        .insert("ir_family".to_string(), ir_family.clone());
    manifest
        .metadata
        .insert("lowering_mode".to_string(), "lossless".to_string());
    manifest
        .metadata
        .insert("proof_claims".to_string(), "none".to_string());

    let manifest_path = out.join("manifest.json");
    write_json(&manifest_path, &manifest)?;
    let report = zkf_lang::ZirPackageReport {
        ok: true,
        source: source.display().to_string(),
        package_dir: out.display().to_string(),
        manifest: manifest_path.display().to_string(),
        source_digest: output.report.source_digest,
        program_digest,
        ir_family,
    };
    if json {
        print_json(&report)?;
    } else {
        println!(
            "packaged Zir source: {} -> {}",
            source.display(),
            manifest_path.display()
        );
    }
    Ok(())
}

pub(crate) fn handle_lang_obligations(source: PathBuf, json: bool) -> Result<(), String> {
    let text = read_source(&source)?;
    let report = zkf_lang::check_source(&text);
    if json {
        let payload = serde_json::json!({
            "ok": report.ok,
            "source": source.display().to_string(),
            "language": report.language,
            "language_version": report.language_version,
            "language_tier": report.language_tier,
            "proof_obligations": report.proof_obligations,
            "diagnostics": report.diagnostics,
        });
        print_json(&payload)?;
    } else {
        println!("Zir proof obligations: {}", source.display());
        for obligation in &report.proof_obligations {
            println!(
                "  - {} [{} / {}]: {}",
                obligation.id,
                obligation.category,
                obligation.required_assurance,
                obligation.statement
            );
        }
        if !report.ok {
            print_diagnostics(&report.diagnostics);
        }
    }
    if report.ok {
        Ok(())
    } else {
        Err(format!(
            "cannot emit complete obligations for invalid Zir source {}",
            source.display()
        ))
    }
}

pub(crate) fn handle_lang_fmt(
    source: PathBuf,
    out: Option<PathBuf>,
    check: bool,
) -> Result<(), String> {
    let text = read_source(&source)?;
    let formatted = zkf_lang::format_source(&text).map_err(render_lang_error)?;
    if check {
        if normalize_line_endings(&text) == normalize_line_endings(&formatted) {
            println!("Zir source is formatted: {}", source.display());
            return Ok(());
        }
        return Err(format!("Zir source is not formatted: {}", source.display()));
    }

    if let Some(out) = out {
        fs::write(&out, formatted).map_err(|error| format!("{}: {error}", out.display()))?;
        println!(
            "formatted Zir source: {} -> {}",
            source.display(),
            out.display()
        );
    } else {
        print!("{formatted}");
    }
    Ok(())
}

pub(crate) fn handle_lang_prove(args: LangProveArgs, allow_compat: bool) -> Result<(), String> {
    let source_text = read_source(&args.source)?;
    let check = zkf_lang::check_source(&source_text);
    let artifact_out = args.out.clone();
    let program = lower_source_to_temp_ir_v2(&args.source)?;
    let result = prove::handle_prove(
        prove::ProveArgs {
            program: program.clone(),
            inputs: args.inputs,
            json: args.json,
            backend: args.backend,
            objective: args.objective,
            mode: args.mode,
            export: args.export,
            allow_attestation: args.allow_attestation,
            out: args.out,
            compiled_out: args.compiled_out,
            solver: args.solver,
            seed: args.seed,
            groth16_setup_blob: args.groth16_setup_blob,
            allow_dev_deterministic_groth16: args.allow_dev_deterministic_groth16,
            hybrid: args.hybrid,
        },
        allow_compat,
    );
    let _ = fs::remove_file(program);
    if result.is_ok() {
        annotate_lang_artifact(&artifact_out, &check)?;
    }
    result
}

pub(crate) fn handle_lang_verify(args: LangVerifyArgs, allow_compat: bool) -> Result<(), String> {
    let program = lower_source_to_temp_ir_v2(&args.source)?;
    let result = prove::handle_verify(
        program.clone(),
        args.artifact,
        args.backend,
        args.compiled,
        args.seed,
        args.groth16_setup_blob,
        args.allow_dev_deterministic_groth16,
        args.hybrid,
        allow_compat,
    );
    let _ = fs::remove_file(program);
    result
}

pub(crate) fn handle_lang_flow_check(flow: PathBuf, json: bool) -> Result<(), String> {
    let text = read_source(&flow)?;
    let plan = zkf_lang::plan_flow_source(&text).map_err(render_lang_error)?;
    if json {
        print_json(&plan)?;
    } else {
        println!(
            "ZirFlow check passed: {} (steps={}, approval_required={})",
            flow.display(),
            plan.steps.len(),
            plan.approved_required
        );
    }
    Ok(())
}

pub(crate) fn handle_lang_flow_plan(
    flow: PathBuf,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), String> {
    let text = read_source(&flow)?;
    let plan = zkf_lang::plan_flow_source(&text).map_err(render_lang_error)?;
    if let Some(out) = out {
        write_json(&out, &plan)?;
    }
    if json {
        print_json(&plan)?;
    } else {
        println!(
            "ZirFlow plan: {} steps for {}",
            plan.steps.len(),
            plan.workflow
        );
    }
    Ok(())
}

pub(crate) fn handle_lang_flow_run(
    flow: PathBuf,
    approve: bool,
    json: bool,
    allow_compat: bool,
) -> Result<(), String> {
    let text = read_source(&flow)?;
    let plan = zkf_lang::plan_flow_source(&text).map_err(render_lang_error)?;
    if plan.approved_required && !approve {
        return Err("ZirFlow run requires --approve for write/prove/verify steps".to_string());
    }
    let base = flow.parent().unwrap_or_else(|| Path::new("."));
    let mut sources = std::collections::BTreeMap::<String, PathBuf>::new();
    for step in &plan.steps {
        match step {
            zkf_lang::ZirFlowStep::Source { alias, path } => {
                sources.insert(alias.clone(), resolve_flow_path(base, path));
            }
            zkf_lang::ZirFlowStep::Check { alias, tier } => {
                let source = flow_source(&sources, alias)?;
                handle_lang_check_with_tier(source, json, *tier)?;
            }
            zkf_lang::ZirFlowStep::Lower { alias, target, out } => {
                let source = flow_source(&sources, alias)?;
                handle_lang_lower(source, resolve_flow_path(base, out), target.clone(), json)?;
            }
            zkf_lang::ZirFlowStep::Package { alias, out } => {
                let source = flow_source(&sources, alias)?;
                handle_lang_package(
                    source,
                    resolve_flow_path(base, out),
                    "zir-v1".to_string(),
                    json,
                )?;
            }
            zkf_lang::ZirFlowStep::Prove {
                alias,
                backend,
                inputs,
                out,
                allow_dev_deterministic_groth16,
            } => {
                let source = flow_source(&sources, alias)?;
                handle_lang_prove(
                    LangProveArgs {
                        source,
                        inputs: resolve_flow_path(base, inputs),
                        json,
                        backend: Some(backend.clone()),
                        objective: "fastest-prove".to_string(),
                        mode: None,
                        export: None,
                        allow_attestation: false,
                        out: resolve_flow_path(base, out),
                        compiled_out: None,
                        solver: None,
                        seed: None,
                        groth16_setup_blob: None,
                        allow_dev_deterministic_groth16: *allow_dev_deterministic_groth16,
                        hybrid: false,
                    },
                    allow_compat,
                )?;
            }
            zkf_lang::ZirFlowStep::Verify {
                alias,
                backend,
                artifact,
                allow_dev_deterministic_groth16,
            } => {
                let source = flow_source(&sources, alias)?;
                handle_lang_verify(
                    LangVerifyArgs {
                        source,
                        artifact: resolve_flow_path(base, artifact),
                        backend: backend.clone(),
                        compiled: None,
                        seed: None,
                        groth16_setup_blob: None,
                        allow_dev_deterministic_groth16: *allow_dev_deterministic_groth16,
                        hybrid: false,
                    },
                    allow_compat,
                )?;
            }
        }
    }
    if json {
        print_json(&serde_json::json!({
            "ok": true,
            "workflow": plan.workflow,
            "steps": plan.steps.len(),
        }))?;
    }
    Ok(())
}

pub(crate) fn handle_lang_lsp_serve() -> Result<(), String> {
    zkf_lsp::serve_stdio_blocking().map_err(|error| error.to_string())
}

fn annotate_lang_artifact(
    artifact_out: &Path,
    check: &zkf_lang::ZirCheckReport,
) -> Result<(), String> {
    let mut artifact: zkf_core::ProofArtifact = read_json(artifact_out)?;
    artifact
        .metadata
        .insert("source_language".to_string(), check.language.clone());
    artifact.metadata.insert(
        "source_language_version".to_string(),
        check.language_version.clone(),
    );
    artifact
        .metadata
        .insert("language_tier".to_string(), check.language_tier.clone());
    artifact
        .metadata
        .insert("source_sha256".to_string(), check.source_digest.hex.clone());
    artifact.metadata.insert(
        "proof_claims".to_string(),
        "none beyond selected backend proof semantics".to_string(),
    );
    write_json(artifact_out, &artifact)
}

fn resolve_flow_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn flow_source(
    sources: &std::collections::BTreeMap<String, PathBuf>,
    alias: &str,
) -> Result<PathBuf, String> {
    sources
        .get(alias)
        .cloned()
        .ok_or_else(|| format!("unknown ZirFlow source alias '{alias}'"))
}

fn handle_lang_check_with_tier(
    source: PathBuf,
    json: bool,
    tier: Option<zkf_lang::ZirTier>,
) -> Result<(), String> {
    let text = read_source(&source)?;
    let report = zkf_lang::check_source_with_options(
        &text,
        &zkf_lang::ZirCompileOptions {
            tier,
            allow_tier2: tier == Some(zkf_lang::ZirTier::Tier2),
            ..zkf_lang::ZirCompileOptions::default()
        },
    );
    if json {
        print_json(&report)?;
    } else if report.ok {
        println!("Zir source check passed: {}", source.display());
        if let Some(entry) = &report.entry {
            println!("  entry: {entry}");
        }
        if let Some(field) = report.field {
            println!("  field: {field}");
        }
        println!(
            "  signals: {} public, {} private",
            report.public_signals.len(),
            report.private_signals.len()
        );
        println!("  constraints: {}", report.constraint_count);
        println!("  obligations: {}", report.proof_obligations.len());
    } else {
        print_diagnostics(&report.diagnostics);
    }
    if report.ok {
        Ok(())
    } else {
        Err(format!(
            "zir source check failed for {} with {} diagnostic(s)",
            source.display(),
            report.diagnostics.len()
        ))
    }
}

fn read_source(source: &Path) -> Result<String, String> {
    fs::read_to_string(source).map_err(|error| format!("{}: {error}", source.display()))
}

fn lower_source_to_temp_ir_v2(source: &Path) -> Result<PathBuf, String> {
    let text = read_source(source)?;
    let (program, _) = zkf_lang::lower_source_to_ir_v2(&text).map_err(render_lang_error)?;
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.push(format!(
        "ziros-lang-{}-{nanos}.ir-v2.json",
        std::process::id()
    ));
    write_json(&path, &program)?;
    Ok(path)
}

fn render_lang_error(error: zkf_lang::ZirLangError) -> String {
    let diagnostics = error.diagnostics();
    if diagnostics.is_empty() {
        return error.to_string();
    }
    diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "{}:{}: {}: {}",
                diagnostic.line, diagnostic.column, diagnostic.code, diagnostic.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn print_diagnostics(diagnostics: &[zkf_lang::ZirDiagnostic]) {
    for diagnostic in diagnostics {
        eprintln!(
            "{}:{}: {}: {}",
            diagnostic.line, diagnostic.column, diagnostic.code, diagnostic.message
        );
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn normalize_line_endings(value: &str) -> String {
    value.replace("\r\n", "\n")
}
