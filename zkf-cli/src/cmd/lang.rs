use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::write_json;

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
