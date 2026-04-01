use std::fmt::Write as _;
use std::path::PathBuf;

use crate::util::{load_program_zir, parse_backend};

/// Handle `zkf audit`: generate a machine-verifiable audit report for a ZKF program.
pub(crate) fn handle_audit(
    program: PathBuf,
    backend: Option<String>,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), String> {
    let prog: zkf_core::zir_v1::Program = load_program_zir(&program)?;

    let backend_kind = backend.as_deref().map(parse_backend).transpose()?;

    let capability_matrix = zkf_backends::backend_capability_matrix();
    let report =
        zkf_core::audit_program_with_capability_matrix(&prog, backend_kind, &capability_matrix);

    // Optionally write the full report to a file
    if let Some(ref out_path) = out {
        let content = report.to_json()?;
        std::fs::write(out_path, &content).map_err(|e| format!("{}: {e}", out_path.display()))?;
        if !json {
            println!("audit report written to {}", out_path.display());
        }
    }

    if json {
        println!("{}", report.to_json()?);
    } else {
        print!("{}", render_audit_report(&report)?);

        if report.summary.failed > 0 {
            return Err(format!(
                "audit failed: {} check(s) failed",
                report.summary.failed
            ));
        }
    }
    Ok(())
}

pub(crate) fn render_audit_report(report: &zkf_core::AuditReport) -> Result<String, String> {
    let mut out = String::new();
    writeln!(&mut out, "Audit Report").map_err(|error| error.to_string())?;
    writeln!(&mut out, "============").map_err(|error| error.to_string())?;
    if let Some(ref digest) = report.program_digest {
        writeln!(
            &mut out,
            "Program digest: {}...",
            &digest[..16.min(digest.len())]
        )
        .map_err(|error| error.to_string())?;
    }
    if let Some(ref field) = report.field {
        writeln!(&mut out, "Field:          {:?}", field).map_err(|error| error.to_string())?;
    }
    if let Some(ref bk) = report.backend {
        writeln!(&mut out, "Backend:        {}", bk).map_err(|error| error.to_string())?;
    }
    if let Some(ref sc) = report.support_class {
        writeln!(&mut out, "Support class:  {}", sc).map_err(|error| error.to_string())?;
    }
    if let Some(ref implementation_type) = report.implementation_type {
        writeln!(&mut out, "Implementation: {}", implementation_type)
            .map_err(|error| error.to_string())?;
    }
    if let Some(readiness) = report.readiness.as_deref() {
        writeln!(&mut out, "Readiness:      {}", readiness).map_err(|error| error.to_string())?;
    }
    if let Some(production_ready) = report.production_ready {
        writeln!(&mut out, "Production:     {}", production_ready)
            .map_err(|error| error.to_string())?;
    }
    if let Some(reason) = report.readiness_reason.as_deref() {
        writeln!(&mut out, "Reason:         {}", reason).map_err(|error| error.to_string())?;
    }
    if let Some(action) = report.operator_action.as_deref() {
        writeln!(&mut out, "Operator action: {}", action).map_err(|error| error.to_string())?;
    }
    if let Some(alias) = report.explicit_compat_alias.as_deref() {
        writeln!(&mut out, "Compat alias:   {}", alias).map_err(|error| error.to_string())?;
    }
    writeln!(&mut out).map_err(|error| error.to_string())?;

    writeln!(
        &mut out,
        "  {:<32} {:<16} {:<8} evidence",
        "check", "category", "status"
    )
    .map_err(|error| error.to_string())?;
    writeln!(&mut out, "  {}", "-".repeat(90)).map_err(|error| error.to_string())?;
    for check in &report.checks {
        let status_str = match check.status {
            zkf_core::AuditStatus::Pass => "PASS",
            zkf_core::AuditStatus::Warn => "WARN",
            zkf_core::AuditStatus::Fail => "FAIL",
            zkf_core::AuditStatus::Skip => "SKIP",
        };
        writeln!(
            &mut out,
            "  {:<32} {:<16} {:<8} {}",
            check.name,
            serde_json::to_string(&check.category).unwrap_or_default(),
            status_str,
            check.evidence.as_deref().unwrap_or("-"),
        )
        .map_err(|error| error.to_string())?;
    }

    if !report.findings.is_empty() {
        writeln!(&mut out).map_err(|error| error.to_string())?;
        writeln!(&mut out, "Findings:").map_err(|error| error.to_string())?;
        for finding in &report.findings {
            let sev = match finding.severity {
                zkf_core::AuditSeverity::Info => "INFO",
                zkf_core::AuditSeverity::Warning => "WARN",
                zkf_core::AuditSeverity::Error => "ERROR",
                zkf_core::AuditSeverity::Critical => "CRIT",
            };
            let loc = finding
                .location
                .as_deref()
                .map(|location| format!(" ({location})"))
                .unwrap_or_default();
            writeln!(&mut out, "  [{}]{} {}", sev, loc, finding.message)
                .map_err(|error| error.to_string())?;
            if let Some(suggestion) = finding.suggestion.as_deref() {
                writeln!(&mut out, "      suggestion: {}", suggestion)
                    .map_err(|error| error.to_string())?;
            }
        }
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Summary: {} checks — {} passed, {} warned, {} failed, {} skipped",
        report.summary.total_checks,
        report.summary.passed,
        report.summary.warned,
        report.summary.failed,
        report.summary.skipped,
    )
    .map_err(|error| error.to_string())?;

    let overall = match report.summary.overall_status {
        zkf_core::AuditStatus::Pass => "PASS",
        zkf_core::AuditStatus::Warn => "WARN",
        zkf_core::AuditStatus::Fail => "FAIL",
        zkf_core::AuditStatus::Skip => "SKIP",
    };
    writeln!(&mut out, "Overall:  {}", overall).map_err(|error| error.to_string())?;
    Ok(out)
}
