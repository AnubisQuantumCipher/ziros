use std::fmt::Write as _;
use std::path::PathBuf;

use crate::util::read_program_artifact;

pub(crate) fn handle_disclosure(program: PathBuf, json: bool) -> Result<(), String> {
    let program_ir = read_program_artifact(&program)?.lower_to_ir_v2()?;
    let report =
        zkf_core::analyze_midnight_disclosure(&program_ir).map_err(|err| err.to_string())?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        print!("{}", render_disclosure_report(&report)?);
        if report.summary.overall_status == zkf_core::DisclosureStatus::Fail {
            return Err(
                "midnight disclosure failed: untracked or unsafe public exposure detected"
                    .to_string(),
            );
        }
    }

    Ok(())
}

pub(crate) fn render_disclosure_report(
    report: &zkf_core::DisclosureReport,
) -> Result<String, String> {
    let mut out = String::new();
    writeln!(&mut out, "Midnight Disclosure Report").map_err(|error| error.to_string())?;
    writeln!(&mut out, "===========================").map_err(|error| error.to_string())?;
    writeln!(&mut out, "Program:        {}", report.program_name)
        .map_err(|error| error.to_string())?;
    writeln!(&mut out, "Circuit:        {}", report.circuit_name)
        .map_err(|error| error.to_string())?;
    writeln!(&mut out, "Digest:         {}", report.program_digest)
        .map_err(|error| error.to_string())?;
    writeln!(&mut out, "Frontend:       {}", report.frontend).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Transcript:     {}",
        if report.public_transcript_order.is_empty() {
            "none".to_string()
        } else {
            report.public_transcript_order.join(", ")
        }
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Contract info:  {}",
        if report.sidecars.contract_info_present {
            report
                .sidecars
                .contract_info_path
                .as_deref()
                .unwrap_or("present")
        } else {
            "missing"
        }
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Contract types: {}",
        if report.sidecars.contract_types_present {
            report
                .sidecars
                .contract_types_path
                .as_deref()
                .unwrap_or("present")
        } else {
            "missing"
        }
    )
    .map_err(|error| error.to_string())?;

    writeln!(&mut out).map_err(|error| error.to_string())?;
    writeln!(&mut out, "Public surfaces:").map_err(|error| error.to_string())?;
    if report.public_signals.is_empty() {
        writeln!(&mut out, "  - none").map_err(|error| error.to_string())?;
    } else {
        for signal in &report.public_signals {
            writeln!(
                &mut out,
                "  - {} [{}] tracked={} private_deps={} commitment_ops={}",
                signal.name,
                disclosure_classification_label(&signal.classification),
                signal.tracked_in_transcript,
                if signal.private_dependencies.is_empty() {
                    "none".to_string()
                } else {
                    signal.private_dependencies.join(", ")
                },
                if signal.commitment_ops.is_empty() {
                    "none".to_string()
                } else {
                    signal.commitment_ops.join(", ")
                }
            )
            .map_err(|error| error.to_string())?;
            if !signal.conditional_guards.is_empty() {
                writeln!(
                    &mut out,
                    "      conditional guards: {}",
                    signal.conditional_guards.join(", ")
                )
                .map_err(|error| error.to_string())?;
            }
            if let Some(note) = signal.note.as_deref() {
                writeln!(&mut out, "      note: {}", note).map_err(|error| error.to_string())?;
            }
        }
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    writeln!(&mut out, "Private surfaces:").map_err(|error| error.to_string())?;
    if report.private_signals.is_empty() {
        writeln!(&mut out, "  - none").map_err(|error| error.to_string())?;
    } else {
        for signal in &report.private_signals {
            writeln!(
                &mut out,
                "  - {} public_consumers={}",
                signal.name,
                if signal.public_consumers.is_empty() {
                    "none".to_string()
                } else {
                    signal.public_consumers.join(", ")
                }
            )
            .map_err(|error| error.to_string())?;
        }
    }

    if !report.findings.is_empty() {
        writeln!(&mut out).map_err(|error| error.to_string())?;
        writeln!(&mut out, "Findings:").map_err(|error| error.to_string())?;
        for finding in &report.findings {
            writeln!(
                &mut out,
                "  [{}] {}{}",
                disclosure_severity_label(&finding.severity),
                finding
                    .signal
                    .as_deref()
                    .map(|signal| format!("{signal}: "))
                    .unwrap_or_default(),
                finding.message
            )
            .map_err(|error| error.to_string())?;
            writeln!(&mut out, "      remediation: {}", finding.remediation)
                .map_err(|error| error.to_string())?;
        }
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Summary: {} public, {} disclosed, {} commitment-backed, {} private-only, {} uncertain, {} warning(s), {} error(s)",
        report.summary.total_public_signals,
        report.summary.disclosed_public,
        report.summary.commitment_public_hash,
        report.summary.private_only,
        report.summary.uncertain,
        report.summary.warnings,
        report.summary.errors,
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Overall: {}",
        disclosure_status_label(&report.summary.overall_status)
    )
    .map_err(|error| error.to_string())?;

    Ok(out)
}

fn disclosure_status_label(status: &zkf_core::DisclosureStatus) -> &'static str {
    match status {
        zkf_core::DisclosureStatus::Pass => "PASS",
        zkf_core::DisclosureStatus::Warn => "WARN",
        zkf_core::DisclosureStatus::Fail => "FAIL",
    }
}

fn disclosure_severity_label(severity: &zkf_core::DisclosureSeverity) -> &'static str {
    match severity {
        zkf_core::DisclosureSeverity::Warning => "WARN",
        zkf_core::DisclosureSeverity::Error => "ERROR",
    }
}

fn disclosure_classification_label(
    classification: &zkf_core::DisclosureClassification,
) -> &'static str {
    match classification {
        zkf_core::DisclosureClassification::DisclosedPublic => "disclosed_public",
        zkf_core::DisclosureClassification::CommitmentPublicHash => "commitment_public_hash",
        zkf_core::DisclosureClassification::PrivateOnly => "private_only",
        zkf_core::DisclosureClassification::Uncertain => "uncertain",
    }
}
