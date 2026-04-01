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

use owo_colors::OwoColorize;
use zkf_lib::{AuditReport, EmbeddedCheck, EmbeddedProof, FieldElement};

use crate::theme::ZkTheme;

#[derive(Debug, Clone, Copy)]
enum Tone {
    Success,
    Failure,
    Warning,
    Info,
    Muted,
}

fn paint(theme: &ZkTheme, text: impl AsRef<str>, tone: Tone) -> String {
    let text = text.as_ref();
    if !theme.colors_enabled {
        return text.to_string();
    }
    match tone {
        Tone::Success => text.green().bold().to_string(),
        Tone::Failure => text.red().bold().to_string(),
        Tone::Warning => text.yellow().bold().to_string(),
        Tone::Info => text.cyan().bold().to_string(),
        Tone::Muted => text.dimmed().to_string(),
    }
}

fn box_chars(
    theme: &ZkTheme,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if theme.unicode_enabled {
        ("┌", "┐", "└", "┘", "│")
    } else {
        ("+", "+", "+", "+", "|")
    }
}

fn horizontal(theme: &ZkTheme, width: usize) -> String {
    if theme.unicode_enabled {
        "─".repeat(width)
    } else {
        "-".repeat(width)
    }
}

fn boxed(title: &str, lines: &[String], theme: &ZkTheme) -> String {
    let (tl, tr, bl, br, v) = box_chars(theme);
    let mut width = title.len();
    for line in lines {
        width = width.max(line.len());
    }
    let border = horizontal(theme, width + 2);
    let mut rendered = Vec::with_capacity(lines.len() + 2);
    rendered.push(format!("{tl}{border}{tr}"));
    rendered.push(format!("{v} {:width$} {v}", title, width = width));
    for line in lines {
        rendered.push(format!("{v} {:width$} {v}", line, width = width));
    }
    rendered.push(format!("{bl}{border}{br}"));
    rendered.join("\n")
}

fn format_public_inputs(values: &[FieldElement]) -> String {
    values
        .iter()
        .map(FieldElement::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_proof_banner(
    circuit_name: &str,
    signals: usize,
    constraints: usize,
    theme: &ZkTheme,
) -> String {
    let title = paint(theme, "ZirOS Proof Run", Tone::Info);
    boxed(
        &title,
        &[
            format!("Circuit: {circuit_name}"),
            format!("Signals: {signals}"),
            format!("Constraints: {constraints}"),
        ],
        theme,
    )
}

pub fn render_audit_report(report: &AuditReport, theme: &ZkTheme) -> String {
    let status = if report.summary.failed > 0 {
        paint(
            theme,
            format!("{} FAIL", theme.failure_symbol),
            Tone::Failure,
        )
    } else if report.summary.warned > 0 {
        paint(
            theme,
            format!("{} WARN", theme.warning_symbol),
            Tone::Warning,
        )
    } else {
        paint(
            theme,
            format!("{} PASS", theme.success_symbol),
            Tone::Success,
        )
    };
    let mut lines = vec![format!(
        "Checks: {} pass / {} warn / {} fail",
        report.summary.passed, report.summary.warned, report.summary.failed
    )];
    for finding in report.findings.iter().take(3) {
        let severity = match finding.severity {
            zkf_lib::AuditSeverity::Info => paint(theme, "INFO", Tone::Info),
            zkf_lib::AuditSeverity::Warning => paint(theme, "WARN", Tone::Warning),
            zkf_lib::AuditSeverity::Error | zkf_lib::AuditSeverity::Critical => {
                paint(theme, "FAIL", Tone::Failure)
            }
        };
        lines.push(format!("{severity}: {}", finding.message));
        if let Some(suggestion) = &finding.suggestion {
            lines.push(format!(
                "{} {}",
                paint(theme, "Suggestion:", Tone::Success),
                suggestion
            ));
        }
    }
    format!("{status}\n{}", lines.join("\n"))
}

pub fn render_check_result(check: &EmbeddedCheck, theme: &ZkTheme) -> String {
    let title = if check.audit.summary.failed > 0 {
        paint(
            theme,
            format!("{} Check Failed", theme.failure_symbol),
            Tone::Failure,
        )
    } else if check.audit.summary.warned > 0 {
        paint(
            theme,
            format!("{} Check Complete", theme.warning_symbol),
            Tone::Warning,
        )
    } else {
        paint(
            theme,
            format!("{} Check Complete", theme.success_symbol),
            Tone::Success,
        )
    };
    let mut lines = vec![
        format!("Backend: {}", check.compiled.backend),
        format!("Witness values: {}", check.witness.values.len()),
        format!(
            "Public inputs: {}",
            format_public_inputs(&check.public_inputs)
        ),
    ];
    lines.push(format!(
        "Diagnostics: {} signals / {} constraints",
        check.diagnostics.signal_count, check.diagnostics.constraint_count
    ));
    format!(
        "{}\n{}",
        boxed(&title, &lines, theme),
        render_audit_report(&check.audit, theme)
    )
}

pub fn render_proof_result(proof: &EmbeddedProof, theme: &ZkTheme) -> String {
    let title = paint(
        theme,
        format!("{} Proof Ready", theme.success_symbol),
        Tone::Success,
    );
    let proof_size = proof.artifact.proof.len();
    let size_line = if proof_size == 128 {
        format!(
            "Proof bytes: {}",
            paint(theme, proof_size.to_string(), Tone::Success)
        )
    } else {
        format!("Proof bytes: {proof_size}")
    };
    boxed(
        &title,
        &[
            format!("Backend: {}", proof.compiled.backend),
            size_line,
            format!("VK bytes: {}", proof.artifact.verification_key.len()),
            format!("Program digest: {}", proof.compiled.program_digest),
        ],
        theme,
    )
}

pub fn render_credential(
    public_inputs: &[FieldElement],
    labels: &[&str],
    theme: &ZkTheme,
) -> String {
    let mut lines = Vec::with_capacity(public_inputs.len() + 2);
    for (index, value) in public_inputs.iter().enumerate() {
        let label = labels.get(index).copied().unwrap_or("public-input");
        lines.push(format!("{label}: {}", value));
    }
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        paint(theme, theme.sealed_label, Tone::Muted),
        paint(
            theme,
            "private witness values remain local to the app",
            Tone::Muted
        )
    ));
    boxed(&paint(theme, "Credential", Tone::Info), &lines, theme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zkf_lib::{
        AuditCategory, AuditCheck, AuditFinding, AuditSeverity, AuditStatus, AuditSummary,
        BackendKind, CompiledProgram, Constraint, DiagnosticsReport, EmbeddedCheck, EmbeddedProof,
        Expr, FieldElement, FieldId, Program, ProofArtifact, Signal, Visibility, Witness,
    };

    fn fixture_program() -> Program {
        Program {
            name: "render_fixture".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "out".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::signal("out"),
                rhs: Expr::constant_i64(1),
                label: None,
            }],
            ..Program::default()
        }
    }

    fn fixture_audit() -> AuditReport {
        AuditReport {
            version: zkf_lib::AUDIT_REPORT_VERSION,
            timestamp: "0Z".to_string(),
            program_digest: None,
            backend: None,
            field: None,
            support_class: None,
            implementation_type: None,
            compiled_in: None,
            toolchain_ready: None,
            runtime_ready: None,
            production_ready: None,
            readiness: None,
            readiness_reason: None,
            operator_action: None,
            explicit_compat_alias: None,
            native_lookup_support: None,
            lookup_lowering_support: None,
            lookup_semantics: None,
            aggregation_semantics: None,
            checks: vec![AuditCheck {
                name: "constraint_soundness".to_string(),
                category: AuditCategory::ConstraintSoundness,
                status: AuditStatus::Warn,
                evidence: Some("fixture evidence".to_string()),
                duration_ms: Some(1),
            }],
            findings: vec![AuditFinding {
                severity: AuditSeverity::Warning,
                category: AuditCategory::ConstraintSoundness,
                message: "underconstrained fixture".to_string(),
                location: None,
                suggestion: Some("add a binding constraint".to_string()),
            }],
            summary: AuditSummary {
                total_checks: 4,
                passed: 3,
                warned: 1,
                failed: 0,
                skipped: 0,
                overall_status: AuditStatus::Warn,
            },
        }
    }

    fn fixture_check() -> EmbeddedCheck {
        EmbeddedCheck {
            compiled: CompiledProgram::new(BackendKind::ArkworksGroth16, fixture_program()),
            witness: Witness {
                values: BTreeMap::from([("out".to_string(), FieldElement::from_i64(1))]),
            },
            public_inputs: vec![FieldElement::from_i64(1)],
            audit: fixture_audit(),
            diagnostics: DiagnosticsReport {
                signal_count: 1,
                constraint_count: 1,
                unconstrained_private_signals: Vec::new(),
                referenced_signals: vec!["out".to_string()],
            },
        }
    }

    fn fixture_proof() -> EmbeddedProof {
        let compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, fixture_program());
        EmbeddedProof {
            compiled: compiled.clone(),
            artifact: ProofArtifact::new(
                BackendKind::ArkworksGroth16,
                compiled.program_digest.clone(),
                vec![0u8; 128],
                vec![1u8; 64],
                vec![FieldElement::from_i64(1)],
            ),
        }
    }

    #[test]
    fn plain_theme_render_has_no_ansi_sequences() {
        let theme = ZkTheme::plain();
        let rendered = render_credential(&[FieldElement::from_i64(9)], &["score"], &theme);
        assert!(!rendered.contains('\u{1b}'));
        assert!(rendered.contains("Credential"));
        assert!(rendered.contains("score: 9"));
        assert!(rendered.contains("SEALED"));
    }

    #[test]
    fn colored_render_contains_expected_sections() {
        let theme = ZkTheme::default();
        let rendered = render_check_result(&fixture_check(), &theme);
        let plain = render_check_result(&fixture_check(), &ZkTheme::plain());
        assert!(rendered.contains("Backend: arkworks-groth16"));
        assert!(rendered.contains("Suggestion:"));
        assert_ne!(rendered, plain);
    }

    #[test]
    fn proof_result_highlights_128_byte_proofs() {
        let rendered = render_proof_result(&fixture_proof(), &ZkTheme::default());
        assert!(rendered.contains("Proof bytes:"));
        assert!(rendered.contains("128"));
    }

    #[test]
    fn proof_banner_mentions_counts() {
        let rendered = render_proof_banner("demo", 4, 9, &ZkTheme::plain());
        assert!(rendered.contains("Circuit: demo"));
        assert!(rendered.contains("Signals: 4"));
        assert!(rendered.contains("Constraints: 9"));
    }
}
