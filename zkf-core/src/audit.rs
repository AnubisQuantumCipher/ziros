//! Machine-verifiable audit reports for ZKF programs and proofs.
//!
//! Provides structured, JSON-serializable audit reports that check type safety,
//! normalization idempotency, backend capability honesty, and underconstrained
//! signal analysis. Each check is individually recorded with status, category,
//! evidence, and timing.

use crate::FieldId;
use crate::artifact::BackendKind;
use crate::debugger::UnderconstrainedAnalysis;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Instant;

/// Audit report schema version.
pub const AUDIT_REPORT_VERSION: u32 = 3;
const UNDERCONSTRAINED_DENSE_CELL_CAP_ENV: &str = "ZKF_AUDIT_UNDERCONSTRAINED_MAX_DENSE_CELLS";
const DEFAULT_UNDERCONSTRAINED_DENSE_CELL_CAP: usize = 20_000_000;

// ─── Status & category enums ─────────────────────────────────────────────────

/// Outcome status of an individual audit check.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

/// Category of an audit check or finding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    ConstraintSoundness,
    UnderconstrainedSignals,
    TypeSafety,
    BackendHonesty,
    GpuAccuracy,
    Reproducibility,
    SetupIntegrity,
    Normalization,
}

/// Severity level of an audit finding.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

// ─── Check & finding structs ─────────────────────────────────────────────────

/// A single audit check with its category, status, and optional evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheck {
    pub name: String,
    pub category: AuditCategory,
    pub status: AuditStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// An audit finding -- a specific issue discovered during an audit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub severity: AuditSeverity,
    pub category: AuditCategory,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

// ─── Summary ─────────────────────────────────────────────────────────────────

/// Aggregate summary of all audit checks in a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_checks: usize,
    pub passed: usize,
    pub warned: usize,
    pub failed: usize,
    pub skipped: usize,
    pub overall_status: AuditStatus,
}

impl Default for AuditSummary {
    fn default() -> Self {
        Self {
            total_checks: 0,
            passed: 0,
            warned: 0,
            failed: 0,
            skipped: 0,
            overall_status: AuditStatus::Pass,
        }
    }
}

// ─── Report ──────────────────────────────────────────────────────────────────

/// Complete audit report for a ZIR program with checks, findings, and summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub version: u32,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<FieldId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiled_in: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit_compat_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_lookup_support: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_lowering_support: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregation_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub underconstrained_analysis: Option<UnderconstrainedAnalysis>,
    pub checks: Vec<AuditCheck>,
    pub findings: Vec<AuditFinding>,
    pub summary: AuditSummary,
}

impl AuditReport {
    /// Create an empty report with the current UTC timestamp.
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // ISO-8601 UTC timestamp without external crate
        let timestamp = format!("{}Z", secs);

        Self {
            version: AUDIT_REPORT_VERSION,
            timestamp,
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
            underconstrained_analysis: None,
            checks: Vec::new(),
            findings: Vec::new(),
            summary: AuditSummary::default(),
        }
    }

    /// Append a check to the report.
    pub fn add_check(&mut self, check: AuditCheck) {
        self.checks.push(check);
    }

    /// Append a finding to the report.
    pub fn add_finding(&mut self, mut finding: AuditFinding) {
        if finding.suggestion.is_none() {
            finding.suggestion = default_suggestion_for_finding(&finding);
        }
        self.findings.push(finding);
    }

    /// Recompute the summary from the current checks list.
    pub fn finalize(&mut self) {
        let mut passed = 0usize;
        let mut warned = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;

        for check in &self.checks {
            match check.status {
                AuditStatus::Pass => passed += 1,
                AuditStatus::Warn => warned += 1,
                AuditStatus::Fail => failed += 1,
                AuditStatus::Skip => skipped += 1,
            }
        }

        let overall_status = if failed > 0 {
            AuditStatus::Fail
        } else if warned > 0 {
            AuditStatus::Warn
        } else {
            AuditStatus::Pass
        };

        self.summary = AuditSummary {
            total_checks: self.checks.len(),
            passed,
            warned,
            failed,
            skipped,
            overall_status,
        };
    }

    /// Serialize the report to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("audit report serialization failed: {e}"))
    }
}

fn default_suggestion_for_finding(finding: &AuditFinding) -> Option<String> {
    let message = finding.message.to_ascii_lowercase();
    match finding.category {
        AuditCategory::UnderconstrainedSignals => {
            if message.contains("is not referenced by any constraint") {
                return Some(
                    "Constrain the signal in at least one equation, expose it as a public output if it is intentional state, or remove it if it is unused.".into(),
                );
            }
            if message.contains("linearly underdetermined without nonlinear anchoring") {
                return Some(
                    "This signal is only constrained by linear relations such as addition, subtraction, or equality, so a malicious prover may be able to change it without changing the rest of the circuit. Fix it by routing the signal through a nonlinear relation such as a Poseidon hash, a boolean constraint (`x * (1 - x) = 0`), or another multiplication gate. See docs/NONLINEAR_ANCHORING.md.".into(),
                );
            }
            None
        }
        _ => None,
    }
}

impl Default for AuditReport {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Program audit ───────────────────────────────────────────────────────────

/// Run a full audit of a ZIR program and return a structured report.
///
/// Checks performed:
/// 1. **Type safety** — runs `type_check()` on the program.
/// 2. **Normalization idempotency** — normalizes the program twice and verifies
///    the digests match (i.e., normalization is stable).
/// 3. **Backend capability** — if a backend is specified, looks it up in the
///    capability matrix and records its support class and any broken/delegated
///    status.
/// 4. **Underconstrained signals** — runs `analyze_underconstrained_zir` and
///    records any unconstrained or linearly underdetermined private signals.
pub fn audit_program(program: &crate::zir::Program, backend: Option<BackendKind>) -> AuditReport {
    audit_program_with_capability_matrix(
        program,
        backend,
        &crate::capability::BackendCapabilityMatrix::current(),
    )
}

/// Run a full audit of a ZIR program using a caller-supplied capability matrix.
pub fn audit_program_with_capability_matrix(
    program: &crate::zir::Program,
    backend: Option<BackendKind>,
    matrix: &crate::capability::BackendCapabilityMatrix,
) -> AuditReport {
    let mut report = AuditReport::new();
    report.program_digest = Some(program.digest_hex());
    report.field = Some(program.field);
    report.backend = backend;

    // ── Check 1: Type safety ─────────────────────────────────────────────
    {
        let start = Instant::now();
        let result = crate::type_check::type_check(program);
        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(()) => {
                report.add_check(AuditCheck {
                    name: "type_check".into(),
                    category: AuditCategory::TypeSafety,
                    status: AuditStatus::Pass,
                    evidence: Some("all signals and constraints well-typed".into()),
                    duration_ms: Some(elapsed),
                });
            }
            Err(errors) => {
                let msg = errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                report.add_check(AuditCheck {
                    name: "type_check".into(),
                    category: AuditCategory::TypeSafety,
                    status: AuditStatus::Fail,
                    evidence: Some(format!("{} error(s): {}", errors.len(), msg)),
                    duration_ms: Some(elapsed),
                });
                for err in &errors {
                    report.add_finding(AuditFinding {
                        severity: AuditSeverity::Error,
                        category: AuditCategory::TypeSafety,
                        message: err.to_string(),
                        location: err.location.map(|l| format!("constraint/signal index {l}")),
                        suggestion: None,
                    });
                }
            }
        }
    }

    // ── Check 2: Normalization idempotency ───────────────────────────────
    {
        let start = Instant::now();
        let (d1, d2) = if let Some(idempotency) =
            crate::proof_transform_spec::normalize_supported_program_idempotency_runtime(program)
        {
            (
                idempotency.report.output_digest,
                idempotency.second_output_digest,
            )
        } else {
            let (norm1, _report1) = crate::normalize::normalize(program);
            let d1 = norm1.digest_hex();
            let (norm2, _report2) = crate::normalize::normalize(&norm1);
            let d2 = norm2.digest_hex();
            (d1, d2)
        };
        let elapsed = start.elapsed().as_millis() as u64;

        if d1 == d2 {
            report.add_check(AuditCheck {
                name: "normalization_idempotency".into(),
                category: AuditCategory::Normalization,
                status: AuditStatus::Pass,
                evidence: Some(format!("digest stable: {}", &d1[..16])),
                duration_ms: Some(elapsed),
            });
        } else {
            report.add_check(AuditCheck {
                name: "normalization_idempotency".into(),
                category: AuditCategory::Normalization,
                status: AuditStatus::Fail,
                evidence: Some(format!("digest drift: {} vs {}", &d1[..16], &d2[..16])),
                duration_ms: Some(elapsed),
            });
            report.add_finding(AuditFinding {
                severity: AuditSeverity::Critical,
                category: AuditCategory::Normalization,
                message:
                    "normalization is not idempotent — double-normalize produces a different digest"
                        .into(),
                location: None,
                suggestion: None,
            });
        }
    }

    // ── Check 3: Backend capability ──────────────────────────────────────
    if let Some(bk) = backend {
        if let Some(entry) = matrix.entry_for(bk) {
            report.support_class = Some(entry.support_class.as_str().to_string());
            report.implementation_type = Some(
                entry
                    .implementation_type
                    .unwrap_or(entry.support_class)
                    .as_str()
                    .to_string(),
            );
            report.compiled_in = entry.compiled_in;
            report.toolchain_ready = entry.toolchain_ready;
            report.runtime_ready = entry.runtime_ready;
            report.production_ready = entry.production_ready;
            report.readiness = entry.readiness.clone();
            report.readiness_reason = entry.readiness_reason.clone();
            report.operator_action = entry.operator_action.clone();
            report.explicit_compat_alias = entry.explicit_compat_alias.clone();
            report.native_lookup_support = entry.native_lookup_support;
            report.lookup_lowering_support = entry.lookup_lowering_support;
            report.lookup_semantics = entry.lookup_semantics.clone();
            report.aggregation_semantics = entry.aggregation_semantics.clone();

            // Support class check
            match entry.support_class {
                crate::capability::SupportClass::Native => {
                    report.add_check(AuditCheck {
                        name: "backend_support_class".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Pass,
                        evidence: Some(format!("{} is native", bk)),
                        duration_ms: None,
                    });
                }
                crate::capability::SupportClass::Delegated => {
                    let delegate_info = entry
                        .delegates_to
                        .map(|d| format!(", delegates to {d}"))
                        .unwrap_or_default();
                    report.add_check(AuditCheck {
                        name: "backend_support_class".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Warn,
                        evidence: Some(format!("{} is delegated{}", bk, delegate_info)),
                        duration_ms: None,
                    });
                    report.add_finding(AuditFinding {
                        severity: AuditSeverity::Warning,
                        category: AuditCategory::BackendHonesty,
                        message: format!(
                            "backend {} is delegated — proofs may be produced by another prover{}",
                            bk, delegate_info
                        ),
                        location: None,
                        suggestion: None,
                    });
                }
                crate::capability::SupportClass::Adapted => {
                    report.add_check(AuditCheck {
                        name: "backend_support_class".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Warn,
                        evidence: Some(format!(
                            "{} is adapted (max_range_bits={:?})",
                            bk, entry.max_range_bits
                        )),
                        duration_ms: None,
                    });
                    report.add_finding(AuditFinding {
                        severity: AuditSeverity::Warning,
                        category: AuditCategory::BackendHonesty,
                        message: format!(
                            "backend {} requires IR adaptation — constraints may be rewritten",
                            bk
                        ),
                        location: None,
                        suggestion: None,
                    });
                }
                crate::capability::SupportClass::Broken => {
                    report.add_check(AuditCheck {
                        name: "backend_support_class".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Fail,
                        evidence: Some(format!("{} is broken", bk)),
                        duration_ms: None,
                    });
                    report.add_finding(AuditFinding {
                        severity: AuditSeverity::Critical,
                        category: AuditCategory::BackendHonesty,
                        message: format!(
                            "backend {} is classified as broken — will fail at prove time",
                            bk
                        ),
                        location: None,
                        suggestion: None,
                    });
                }
                crate::capability::SupportClass::Unsupported => {
                    report.add_check(AuditCheck {
                        name: "backend_support_class".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Fail,
                        evidence: Some(format!("{} is explicitly unsupported", bk)),
                        duration_ms: None,
                    });
                }
                crate::capability::SupportClass::Experimental => {
                    report.add_check(AuditCheck {
                        name: "backend_support_class".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Warn,
                        evidence: Some(format!("{} is experimental", bk)),
                        duration_ms: None,
                    });
                }
            }

            if let Some(production_ready) = entry.production_ready {
                let readiness = entry.readiness.as_deref().unwrap_or("unknown");
                let reason = entry.readiness_reason.as_deref().unwrap_or("not-ready");
                if production_ready {
                    report.add_check(AuditCheck {
                        name: "backend_readiness".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Pass,
                        evidence: Some(format!("readiness={readiness}")),
                        duration_ms: None,
                    });
                } else {
                    report.add_check(AuditCheck {
                        name: "backend_readiness".into(),
                        category: AuditCategory::BackendHonesty,
                        status: AuditStatus::Fail,
                        evidence: Some(format!("readiness={readiness}, reason={reason}")),
                        duration_ms: None,
                    });
                    report.add_finding(AuditFinding {
                        severity: AuditSeverity::Error,
                        category: AuditCategory::BackendHonesty,
                        message: format!(
                            "backend {} is not production-ready on this host (readiness={}, reason={})",
                            bk, readiness, reason
                        ),
                        location: entry.operator_action.clone(),
                        suggestion: None,
                    });
                }
            }

            // GPU accuracy check
            if entry.gpu_acceleration.claimed != entry.gpu_acceleration.actual {
                report.add_check(AuditCheck {
                    name: "gpu_accuracy".into(),
                    category: AuditCategory::GpuAccuracy,
                    status: AuditStatus::Warn,
                    evidence: Some(format!(
                        "claimed={}, actual={}",
                        entry.gpu_acceleration.claimed, entry.gpu_acceleration.actual
                    )),
                    duration_ms: None,
                });
                report.add_finding(AuditFinding {
                    severity: AuditSeverity::Warning,
                    category: AuditCategory::GpuAccuracy,
                    message: format!(
                        "backend {} GPU claim mismatch: claims Metal={} but measured={}",
                        bk, entry.gpu_acceleration.claimed, entry.gpu_acceleration.actual
                    ),
                    location: None,
                    suggestion: None,
                });
            } else {
                report.add_check(AuditCheck {
                    name: "gpu_accuracy".into(),
                    category: AuditCategory::GpuAccuracy,
                    status: AuditStatus::Pass,
                    evidence: Some(format!(
                        "claimed={}, actual={}",
                        entry.gpu_acceleration.claimed, entry.gpu_acceleration.actual
                    )),
                    duration_ms: None,
                });
            }

            // Field compatibility
            if !entry.supported_fields.is_empty()
                && !entry.supported_fields.contains(&program.field)
            {
                report.add_check(AuditCheck {
                    name: "field_compatibility".into(),
                    category: AuditCategory::BackendHonesty,
                    status: AuditStatus::Fail,
                    evidence: Some(format!(
                        "program field {:?} not in {:?}",
                        program.field, entry.supported_fields
                    )),
                    duration_ms: None,
                });
                report.add_finding(AuditFinding {
                    severity: AuditSeverity::Error,
                    category: AuditCategory::BackendHonesty,
                    message: format!(
                        "program uses field {:?} but backend {} only supports {:?}",
                        program.field, bk, entry.supported_fields
                    ),
                    location: None,
                    suggestion: None,
                });
            } else {
                report.add_check(AuditCheck {
                    name: "field_compatibility".into(),
                    category: AuditCategory::BackendHonesty,
                    status: AuditStatus::Pass,
                    evidence: Some(format!("field {:?} supported", program.field)),
                    duration_ms: None,
                });
            }

            // Setup integrity check
            if entry.trusted_setup_required {
                report.add_check(AuditCheck {
                    name: "setup_integrity".into(),
                    category: AuditCategory::SetupIntegrity,
                    status: AuditStatus::Warn,
                    evidence: Some(format!(
                        "{} requires trusted setup — ceremony verification recommended",
                        bk
                    )),
                    duration_ms: None,
                });
                report.add_finding(AuditFinding {
                    severity: AuditSeverity::Info,
                    category: AuditCategory::SetupIntegrity,
                    message: format!(
                        "backend {} requires trusted setup; verify ceremony transcript before production use",
                        bk
                    ),
                    location: None,
                    suggestion: None,
                });
            } else {
                report.add_check(AuditCheck {
                    name: "setup_integrity".into(),
                    category: AuditCategory::SetupIntegrity,
                    status: AuditStatus::Pass,
                    evidence: Some(format!("{} uses transparent setup", bk)),
                    duration_ms: None,
                });
            }
        } else {
            report.add_check(AuditCheck {
                name: "backend_lookup".into(),
                category: AuditCategory::BackendHonesty,
                status: AuditStatus::Fail,
                evidence: Some(format!("{} not found in capability matrix", bk)),
                duration_ms: None,
            });
            report.add_finding(AuditFinding {
                severity: AuditSeverity::Error,
                category: AuditCategory::BackendHonesty,
                message: format!("backend {} not found in capability matrix", bk),
                location: None,
                suggestion: None,
            });
        }
    }

    // ── Check 4: Underconstrained signals ────────────────────────────────
    {
        let start = Instant::now();
        let (cap, cap_source) = underconstrained_dense_cell_cap();
        if let Some(cap) = cap {
            let estimate = underconstrained_dense_cell_estimate(program);
            if estimate > cap {
                let elapsed = start.elapsed().as_millis() as u64;
                report.add_check(AuditCheck {
                    name: "underconstrained_signals".into(),
                    category: AuditCategory::UnderconstrainedSignals,
                    status: AuditStatus::Skip,
                    evidence: Some(format!(
                        "analysis skipped: dense linear rank estimate {estimate} exceeds {cap_source} cap {cap}; override with {UNDERCONSTRAINED_DENSE_CELL_CAP_ENV}=<positive integer> or disable with 0/off"
                    )),
                    duration_ms: Some(elapsed),
                });
            } else {
                match crate::debugger::analyze_underconstrained_zir(program) {
                    Ok(analysis) => {
                        report.underconstrained_analysis = Some(analysis.clone());
                        let elapsed = start.elapsed().as_millis() as u64;

                        let nonlinear_private_signal_set = analysis
                            .nonlinear_private_signals
                            .iter()
                            .cloned()
                            .collect::<std::collections::BTreeSet<_>>();
                        let blocking_underdetermined_signals = analysis
                            .linearly_underdetermined_private_signals
                            .iter()
                            .filter(|signal| !nonlinear_private_signal_set.contains(*signal))
                            .cloned()
                            .collect::<Vec<_>>();
                        let conservative_nonlinear_signals = analysis
                            .linearly_underdetermined_private_signals
                            .iter()
                            .filter(|signal| nonlinear_private_signal_set.contains(*signal))
                            .cloned()
                            .collect::<Vec<_>>();

                        if analysis.unconstrained_private_signals.is_empty()
                            && blocking_underdetermined_signals.is_empty()
                        {
                            report.add_check(AuditCheck {
                                name: "underconstrained_signals".into(),
                                category: AuditCategory::UnderconstrainedSignals,
                                status: AuditStatus::Pass,
                                evidence: Some(format!(
                                    "0 unconstrained, 0 linear-only underdetermined, {} nonlinear-participating conservative underdetermined (rank={}, nullity={})",
                                    conservative_nonlinear_signals.len(),
                                    analysis.linear_rank,
                                    analysis.linear_nullity
                                )),
                                duration_ms: Some(elapsed),
                            });
                        } else {
                            let unconstrained_count = analysis.unconstrained_private_signals.len();
                            let underdetermined_count = blocking_underdetermined_signals.len();

                            let status = AuditStatus::Fail;

                            report.add_check(AuditCheck {
                                name: "underconstrained_signals".into(),
                                category: AuditCategory::UnderconstrainedSignals,
                                status,
                                evidence: Some(format!(
                                    "{} unconstrained, {} linear-only underdetermined, {} nonlinear-participating conservative underdetermined",
                                    unconstrained_count,
                                    underdetermined_count,
                                    conservative_nonlinear_signals.len()
                                )),
                                duration_ms: Some(elapsed),
                            });

                            for sig in &analysis.unconstrained_private_signals {
                                report.add_finding(AuditFinding {
                                    severity: AuditSeverity::Error,
                                    category: AuditCategory::UnderconstrainedSignals,
                                    message: format!(
                                        "private signal '{}' is not referenced by any constraint",
                                        sig
                                    ),
                                    location: Some(format!("signal '{}'", sig)),
                                    suggestion: None,
                                });
                            }
                            for sig in &blocking_underdetermined_signals {
                                report.add_finding(AuditFinding {
                                    severity: AuditSeverity::Error,
                                    category: AuditCategory::UnderconstrainedSignals,
                                    message: format!(
                                        "private signal '{}' is only used in linear constraints and is linearly underdetermined without nonlinear anchoring (nullity>0). A malicious prover could manipulate this value without detection until it participates in a nonlinear relation.",
                                        sig
                                    ),
                                    location: Some(format!("signal '{}'", sig)),
                                    suggestion: None,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        let elapsed = start.elapsed().as_millis() as u64;
                        report.add_check(AuditCheck {
                            name: "underconstrained_signals".into(),
                            category: AuditCategory::UnderconstrainedSignals,
                            status: AuditStatus::Skip,
                            evidence: Some(format!("analysis failed: {}", e)),
                            duration_ms: Some(elapsed),
                        });
                    }
                }
            }
        } else {
            match crate::debugger::analyze_underconstrained_zir(program) {
                Ok(analysis) => {
                    report.underconstrained_analysis = Some(analysis.clone());
                    let elapsed = start.elapsed().as_millis() as u64;

                    let nonlinear_private_signal_set = analysis
                        .nonlinear_private_signals
                        .iter()
                        .cloned()
                        .collect::<std::collections::BTreeSet<_>>();
                    let blocking_underdetermined_signals = analysis
                        .linearly_underdetermined_private_signals
                        .iter()
                        .filter(|signal| !nonlinear_private_signal_set.contains(*signal))
                        .cloned()
                        .collect::<Vec<_>>();
                    let conservative_nonlinear_signals = analysis
                        .linearly_underdetermined_private_signals
                        .iter()
                        .filter(|signal| nonlinear_private_signal_set.contains(*signal))
                        .cloned()
                        .collect::<Vec<_>>();

                    if analysis.unconstrained_private_signals.is_empty()
                        && blocking_underdetermined_signals.is_empty()
                    {
                        report.add_check(AuditCheck {
                            name: "underconstrained_signals".into(),
                            category: AuditCategory::UnderconstrainedSignals,
                            status: AuditStatus::Pass,
                            evidence: Some(format!(
                                "0 unconstrained, 0 linear-only underdetermined, {} nonlinear-participating conservative underdetermined (rank={}, nullity={})",
                                conservative_nonlinear_signals.len(),
                                analysis.linear_rank,
                                analysis.linear_nullity
                            )),
                            duration_ms: Some(elapsed),
                        });
                    } else {
                        let unconstrained_count = analysis.unconstrained_private_signals.len();
                        let underdetermined_count = blocking_underdetermined_signals.len();

                        let status = AuditStatus::Fail;

                        report.add_check(AuditCheck {
                            name: "underconstrained_signals".into(),
                            category: AuditCategory::UnderconstrainedSignals,
                            status,
                            evidence: Some(format!(
                                "{} unconstrained, {} linear-only underdetermined, {} nonlinear-participating conservative underdetermined",
                                unconstrained_count,
                                underdetermined_count,
                                conservative_nonlinear_signals.len()
                            )),
                            duration_ms: Some(elapsed),
                        });

                        for sig in &analysis.unconstrained_private_signals {
                            report.add_finding(AuditFinding {
                                severity: AuditSeverity::Error,
                                category: AuditCategory::UnderconstrainedSignals,
                                message: format!(
                                    "private signal '{}' is not referenced by any constraint",
                                    sig
                                ),
                                location: Some(format!("signal '{}'", sig)),
                                suggestion: None,
                            });
                        }
                        for sig in &blocking_underdetermined_signals {
                            report.add_finding(AuditFinding {
                                severity: AuditSeverity::Error,
                                category: AuditCategory::UnderconstrainedSignals,
                                message: format!(
                                    "private signal '{}' is only used in linear constraints and is linearly underdetermined without nonlinear anchoring (nullity>0). A malicious prover could manipulate this value without detection until it participates in a nonlinear relation.",
                                    sig
                                ),
                                location: Some(format!("signal '{}'", sig)),
                                suggestion: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    report.add_check(AuditCheck {
                        name: "underconstrained_signals".into(),
                        category: AuditCategory::UnderconstrainedSignals,
                        status: AuditStatus::Skip,
                        evidence: Some(format!("analysis failed: {}", e)),
                        duration_ms: Some(elapsed),
                    });
                }
            }
        }
    }

    // ── Check 5: Constraint soundness (basic) ────────────────────────────
    {
        let n_constraints = program.constraints.len();
        let n_signals = program.signals.len();
        if n_constraints == 0 && n_signals > 0 {
            report.add_check(AuditCheck {
                name: "constraint_soundness".into(),
                category: AuditCategory::ConstraintSoundness,
                status: AuditStatus::Warn,
                evidence: Some(format!(
                    "{} signals but 0 constraints — circuit is trivially satisfiable",
                    n_signals
                )),
                duration_ms: None,
            });
            report.add_finding(AuditFinding {
                severity: AuditSeverity::Warning,
                category: AuditCategory::ConstraintSoundness,
                message: "program has signals but no constraints".into(),
                location: None,
                suggestion: None,
            });
        } else {
            report.add_check(AuditCheck {
                name: "constraint_soundness".into(),
                category: AuditCategory::ConstraintSoundness,
                status: AuditStatus::Pass,
                evidence: Some(format!(
                    "{} constraint(s) over {} signal(s)",
                    n_constraints, n_signals
                )),
                duration_ms: None,
            });
        }
    }

    // ── Check 6: BlackBox constraint lowering status ─────────────────────
    {
        use crate::zir::{BlackBoxOp, Constraint};

        // Classify each BlackBox op by how it's handled during lowering
        let blackbox_ops: Vec<BlackBoxOp> = program
            .constraints
            .iter()
            .filter_map(|c| {
                if let Constraint::BlackBox { op, .. } = c {
                    Some(*op)
                } else {
                    None
                }
            })
            .collect();

        if blackbox_ops.is_empty() {
            report.add_check(AuditCheck {
                name: "blackbox_lowering".into(),
                category: AuditCategory::ConstraintSoundness,
                status: AuditStatus::Pass,
                evidence: Some("no BlackBox constraints present".into()),
                duration_ms: None,
            });
        } else {
            let mut constrained: Vec<&str> = Vec::new();
            let mut limited: Vec<&str> = Vec::new();
            let mut metadata_only: Vec<&str> = Vec::new();
            let mut host_only: Vec<&str> = Vec::new();

            for op in &blackbox_ops {
                match op {
                    // Fully lowered to algebraic constraints
                    BlackBoxOp::Sha256
                    | BlackBoxOp::Keccak256
                    | BlackBoxOp::Poseidon
                    | BlackBoxOp::Blake2s
                    | BlackBoxOp::EcdsaSecp256r1 => constrained.push(op.as_str()),
                    // Present in the codebase but still explicitly limited elsewhere
                    // in the production support matrix / gadget registry.
                    BlackBoxOp::EcdsaSecp256k1
                    | BlackBoxOp::SchnorrVerify
                    | BlackBoxOp::ScalarMulG1
                    | BlackBoxOp::PointAddG1 => limited.push(op.as_str()),
                    // Metadata-only: no in-circuit constraints generated
                    BlackBoxOp::RecursiveAggregationMarker => metadata_only.push(op.as_str()),
                    // Will return explicit error at synthesis — not supported in-circuit
                    BlackBoxOp::PairingCheck | BlackBoxOp::Pedersen => host_only.push(op.as_str()),
                }
            }

            let has_unsupported = !host_only.is_empty();
            let has_limited = !limited.is_empty();
            let has_metadata_only = !metadata_only.is_empty();
            let status = if has_unsupported {
                AuditStatus::Fail
            } else if has_limited || has_metadata_only {
                AuditStatus::Warn
            } else {
                AuditStatus::Pass
            };

            let evidence = format!(
                "constrained: [{}]; limited: [{}]; metadata-only: [{}]; unsupported (will error): [{}]",
                constrained.join(", "),
                limited.join(", "),
                metadata_only.join(", "),
                host_only.join(", ")
            );
            report.add_check(AuditCheck {
                name: "blackbox_lowering".into(),
                category: AuditCategory::ConstraintSoundness,
                status,
                evidence: Some(evidence),
                duration_ms: None,
            });

            for op_name in &host_only {
                report.add_finding(AuditFinding {
                    severity: AuditSeverity::Critical,
                    category: AuditCategory::ConstraintSoundness,
                    message: format!(
                        "BlackBox op '{}' is not supported in-circuit and will cause \
                         a synthesis error. Use a pairing-friendly backend or \
                         the recursive aggregation path instead.",
                        op_name
                    ),
                    location: None,
                    suggestion: None,
                });
            }
            for op_name in &limited {
                report.add_finding(AuditFinding {
                    severity: AuditSeverity::Warning,
                    category: AuditCategory::ConstraintSoundness,
                    message: format!(
                        "BlackBox op '{}' is implemented but still classified as limited rather than production-safe. Treat proofs using it as feature-complete only for explicitly limited lanes until the underlying soundness/completeness work is closed.",
                        op_name
                    ),
                    location: None,
                    suggestion: None,
                });
            }
            for op_name in &metadata_only {
                report.add_finding(AuditFinding {
                    severity: AuditSeverity::Warning,
                    category: AuditCategory::ConstraintSoundness,
                    message: format!(
                        "BlackBox op '{}' generates no in-circuit constraints. \
                         It is a metadata marker only — the aggregation claim is \
                         NOT cryptographically proven in this circuit.",
                        op_name
                    ),
                    location: None,
                    suggestion: None,
                });
            }
        }
    }

    // ── Check 7: Lookup constraint handling ──────────────────────────────
    {
        use crate::zir::Constraint;

        let lookup_count = program
            .constraints
            .iter()
            .filter(|c| matches!(c, Constraint::Lookup { .. }))
            .count();

        if lookup_count == 0 {
            report.add_check(AuditCheck {
                name: "lookup_constraints".into(),
                category: AuditCategory::ConstraintSoundness,
                status: AuditStatus::Pass,
                evidence: Some("no Lookup constraints present".into()),
                duration_ms: None,
            });
        } else {
            // Check table sizes to predict lowering outcome
            let large_tables: Vec<&str> = program
                .lookup_tables
                .iter()
                .filter(|t| t.values.len() > 256)
                .map(|t| t.name.as_str())
                .collect();
            let entry = backend.and_then(|bk| matrix.entry_for(bk));
            let native_lookup = entry
                .and_then(|item| item.native_lookup_support)
                .unwrap_or(false);
            let lowering_lookup = entry
                .and_then(|item| item.lookup_lowering_support)
                .unwrap_or(false);
            let lookup_semantics = entry
                .and_then(|item| item.lookup_semantics.as_deref())
                .unwrap_or("unknown");

            let (status, evidence) = if entry.is_none() && large_tables.is_empty() {
                (
                    AuditStatus::Pass,
                    format!(
                        "{} Lookup constraint(s); backend-specific lookup semantics unavailable, \
                         but tables are within the current arithmetic lowering limit of 256 rows",
                        lookup_count
                    ),
                )
            } else if entry.is_none() {
                (
                    AuditStatus::Warn,
                    format!(
                        "{} Lookup constraint(s); backend-specific lookup semantics unavailable and \
                         {} table(s) exceed the current arithmetic lowering limit of 256 rows: [{}]",
                        lookup_count,
                        large_tables.len(),
                        large_tables.join(", ")
                    ),
                )
            } else if native_lookup {
                (
                    AuditStatus::Pass,
                    format!(
                        "{} Lookup constraint(s); backend accepts raw lookup constraints natively \
                         (lookup_semantics={lookup_semantics})",
                        lookup_count
                    ),
                )
            } else if lowering_lookup && large_tables.is_empty() {
                (
                    AuditStatus::Pass,
                    format!(
                        "{} Lookup constraint(s); backend requires arithmetic lowering before synthesis \
                         (lookup_semantics={lookup_semantics})",
                        lookup_count
                    ),
                )
            } else if lowering_lookup {
                (
                    AuditStatus::Fail,
                    format!(
                        "{} Lookup constraint(s); {} table(s) exceed the current arithmetic lowering limit \
                         of 256 rows: [{}] (lookup_semantics={lookup_semantics})",
                        lookup_count,
                        large_tables.len(),
                        large_tables.join(", ")
                    ),
                )
            } else {
                (
                    AuditStatus::Fail,
                    format!(
                        "{} Lookup constraint(s); backend does not support them on this proving path \
                         (lookup_semantics={lookup_semantics})",
                        lookup_count
                    ),
                )
            };

            report.add_check(AuditCheck {
                name: "lookup_constraints".into(),
                category: AuditCategory::ConstraintSoundness,
                status,
                evidence: Some(evidence),
                duration_ms: None,
            });

            if !native_lookup && lowering_lookup {
                report.add_finding(AuditFinding {
                    severity: if large_tables.is_empty() {
                        AuditSeverity::Warning
                    } else {
                        AuditSeverity::Error
                    },
                    category: AuditCategory::ConstraintSoundness,
                    message: if large_tables.is_empty() {
                        "Lookup constraints are accepted only after arithmetic lowering on this backend."
                            .into()
                    } else {
                        format!(
                            "Lookup tables [{}] exceed the current arithmetic lowering limit of 256 rows.",
                            large_tables.join(", ")
                        )
                    },
                    location: Some(format!("lookup_semantics={lookup_semantics}")),
                    suggestion: None,
                });
            }
        }
    }

    // ── Check 8: Signature semantics must use cryptographic relations ────
    audit_signature_semantics(program, &mut report);

    report.finalize();
    report
}

fn underconstrained_dense_cell_cap() -> (Option<usize>, &'static str) {
    match env::var(UNDERCONSTRAINED_DENSE_CELL_CAP_ENV) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.eq_ignore_ascii_case("off")
                || trimmed.eq_ignore_ascii_case("none")
                || trimmed == "0"
            {
                (None, "env")
            } else {
                (
                    trimmed
                        .parse::<usize>()
                        .ok()
                        .filter(|parsed| *parsed > 0)
                        .or(Some(DEFAULT_UNDERCONSTRAINED_DENSE_CELL_CAP)),
                    "env",
                )
            }
        }
        Err(_) => (Some(DEFAULT_UNDERCONSTRAINED_DENSE_CELL_CAP), "default"),
    }
}

fn underconstrained_dense_cell_estimate(program: &crate::zir::Program) -> usize {
    let private_signals = program
        .signals
        .iter()
        .filter(|signal| signal.visibility == crate::Visibility::Private)
        .count();
    let linear_constraints = program
        .constraints
        .iter()
        .filter(|constraint| matches!(constraint, crate::zir::Constraint::Equal { .. }))
        .count();
    private_signals.saturating_mul(linear_constraints)
}

fn is_cryptographic_signature_blackbox(op: crate::zir::BlackBoxOp) -> bool {
    matches!(
        op,
        crate::zir::BlackBoxOp::EcdsaSecp256k1
            | crate::zir::BlackBoxOp::EcdsaSecp256r1
            | crate::zir::BlackBoxOp::SchnorrVerify
    )
}

fn signature_blackbox_ops(program: &crate::zir::Program) -> Vec<&'static str> {
    let mut ops = std::collections::BTreeSet::new();
    for constraint in &program.constraints {
        if let crate::zir::Constraint::BlackBox { op, .. } = constraint
            && is_cryptographic_signature_blackbox(*op)
        {
            ops.insert(op.as_str());
        }
    }
    ops.into_iter().collect()
}

fn lower_ascii(text: &str) -> String {
    text.to_ascii_lowercase()
}

fn is_signatureish_identifier(text: &str) -> bool {
    let lower = lower_ascii(text);
    lower.contains("signature")
        || lower.contains("issuer_public_key")
        || lower.contains("public_key")
        || lower.contains("ecdsa")
        || lower.contains("schnorr")
        || lower.contains("issuer_valid")
        || lower.contains("signature_valid")
        || lower.contains("pkx")
        || lower.contains("pky")
}

fn is_signature_validity_claim(text: &str) -> bool {
    let lower = lower_ascii(text);
    (lower.contains("issuer") || lower.contains("signature") || lower.contains("auth"))
        && (lower.contains("valid") || lower.contains("authentic"))
}

fn expr_contains_arithmetic(expr: &crate::zir::Expr) -> bool {
    match expr {
        crate::zir::Expr::Const(_) | crate::zir::Expr::Signal(_) => false,
        crate::zir::Expr::Add(items) => !items.is_empty(),
        crate::zir::Expr::Sub(_, _) | crate::zir::Expr::Mul(_, _) | crate::zir::Expr::Div(_, _) => {
            true
        }
    }
}

fn collect_signal_names(expr: &crate::zir::Expr, out: &mut Vec<String>) {
    match expr {
        crate::zir::Expr::Const(_) => {}
        crate::zir::Expr::Signal(name) => out.push(name.clone()),
        crate::zir::Expr::Add(items) => {
            for item in items {
                collect_signal_names(item, out);
            }
        }
        crate::zir::Expr::Sub(lhs, rhs)
        | crate::zir::Expr::Mul(lhs, rhs)
        | crate::zir::Expr::Div(lhs, rhs) => {
            collect_signal_names(lhs, out);
            collect_signal_names(rhs, out);
        }
    }
}

fn arithmetic_signature_relations(program: &crate::zir::Program) -> Vec<String> {
    let mut relations = Vec::new();
    for constraint in &program.constraints {
        let crate::zir::Constraint::Equal { lhs, rhs, label } = constraint else {
            continue;
        };

        if !expr_contains_arithmetic(lhs) && !expr_contains_arithmetic(rhs) {
            continue;
        }

        let mut names = Vec::new();
        collect_signal_names(lhs, &mut names);
        collect_signal_names(rhs, &mut names);
        names.sort();
        names.dedup();

        let signatureish_names = names
            .iter()
            .filter(|name| is_signatureish_identifier(name))
            .cloned()
            .collect::<Vec<_>>();
        if signatureish_names.is_empty() {
            continue;
        }

        relations.push(match label {
            Some(label) => format!("{label} => [{}]", signatureish_names.join(", ")),
            None => format!("[{}]", signatureish_names.join(", ")),
        });
    }
    relations
}

fn signature_claim_markers(program: &crate::zir::Program) -> Vec<String> {
    let mut markers = std::collections::BTreeSet::new();

    if is_signatureish_identifier(&program.name) {
        markers.insert(format!("program {}", program.name));
    }

    for signal in &program.signals {
        if signal.visibility == crate::Visibility::Public
            && is_signature_validity_claim(&signal.name)
        {
            markers.insert(format!("public signal {}", signal.name));
        }
    }

    for constraint in &program.constraints {
        if let Some(label) = constraint_label(constraint)
            && is_signature_validity_claim(label)
        {
            markers.insert(format!("constraint label {}", label));
        }
    }

    for (key, value) in &program.metadata {
        if is_signatureish_identifier(key) || is_signatureish_identifier(value) {
            markers.insert(format!("metadata {}", key));
        }
    }

    markers.into_iter().collect()
}

fn constraint_label(constraint: &crate::zir::Constraint) -> Option<&String> {
    match constraint {
        crate::zir::Constraint::Equal { label, .. }
        | crate::zir::Constraint::Boolean { label, .. }
        | crate::zir::Constraint::Range { label, .. }
        | crate::zir::Constraint::Lookup { label, .. }
        | crate::zir::Constraint::CustomGate { label, .. }
        | crate::zir::Constraint::MemoryRead { label, .. }
        | crate::zir::Constraint::MemoryWrite { label, .. }
        | crate::zir::Constraint::BlackBox { label, .. }
        | crate::zir::Constraint::Permutation { label, .. }
        | crate::zir::Constraint::Copy { label, .. } => label.as_ref(),
    }
}

fn audit_signature_semantics(program: &crate::zir::Program, report: &mut AuditReport) {
    let signature_ops = signature_blackbox_ops(program);
    let claim_markers = signature_claim_markers(program);
    let arithmetic_relations = arithmetic_signature_relations(program);

    if !signature_ops.is_empty() {
        let mut evidence = format!(
            "cryptographic signature verification present via [{}]",
            signature_ops.join(", ")
        );
        if !claim_markers.is_empty() {
            evidence.push_str(&format!("; claims: [{}]", claim_markers.join(", ")));
        }
        report.add_check(AuditCheck {
            name: "signature_semantics".into(),
            category: AuditCategory::ConstraintSoundness,
            status: AuditStatus::Pass,
            evidence: Some(evidence),
            duration_ms: None,
        });
        return;
    }

    if !claim_markers.is_empty() || !arithmetic_relations.is_empty() {
        let mut evidence_parts = Vec::new();
        if !claim_markers.is_empty() {
            evidence_parts.push(format!("claims: [{}]", claim_markers.join(", ")));
        }
        if !arithmetic_relations.is_empty() {
            evidence_parts.push(format!(
                "arithmetic relations: [{}]",
                arithmetic_relations.join(", ")
            ));
        }
        report.add_check(AuditCheck {
            name: "signature_semantics".into(),
            category: AuditCategory::ConstraintSoundness,
            status: AuditStatus::Fail,
            evidence: Some(format!(
                "signature/issuer semantics detected without cryptographic signature blackbox; {}",
                evidence_parts.join("; ")
            )),
            duration_ms: None,
        });
        report.add_finding(AuditFinding {
            severity: AuditSeverity::Critical,
            category: AuditCategory::ConstraintSoundness,
            message:
                "circuit claims issuer/signature authenticity without using a cryptographic signature verifier; use ecdsa_* or schnorr_verify rather than arithmetic placeholders"
                    .into(),
            location: None,
            suggestion: None,
        });
        if !arithmetic_relations.is_empty() {
            report.add_finding(AuditFinding {
                severity: AuditSeverity::Error,
                category: AuditCategory::ConstraintSoundness,
                message: format!(
                    "signature-shaped arithmetic relations are not accepted as issuer authentication: {}",
                    arithmetic_relations.join(" | ")
                ),
                location: None,
                suggestion: None,
            });
        }
        return;
    }

    report.add_check(AuditCheck {
        name: "signature_semantics".into(),
        category: AuditCategory::ConstraintSoundness,
        status: AuditStatus::Pass,
        evidence: Some("no signature/issuer authenticity semantics detected".into()),
        duration_ms: None,
    });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zir::{self, Constraint, Expr, Signal, SignalType};
    use crate::{FieldElement, Visibility};
    use std::collections::BTreeMap;

    fn make_test_program() -> crate::zir::Program {
        crate::zir::Program {
            name: "audit_test".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".into()),
                rhs: Expr::Signal("y".into()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn report_new_has_version() {
        let report = AuditReport::new();
        assert_eq!(report.version, AUDIT_REPORT_VERSION);
        assert!(report.checks.is_empty());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn report_add_check_and_finalize() {
        let mut report = AuditReport::new();
        report.add_check(AuditCheck {
            name: "test_pass".into(),
            category: AuditCategory::TypeSafety,
            status: AuditStatus::Pass,
            evidence: None,
            duration_ms: None,
        });
        report.add_check(AuditCheck {
            name: "test_warn".into(),
            category: AuditCategory::Normalization,
            status: AuditStatus::Warn,
            evidence: Some("something fishy".into()),
            duration_ms: Some(42),
        });
        report.add_check(AuditCheck {
            name: "test_skip".into(),
            category: AuditCategory::BackendHonesty,
            status: AuditStatus::Skip,
            evidence: None,
            duration_ms: None,
        });
        report.finalize();

        assert_eq!(report.summary.total_checks, 3);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.warned, 1);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.overall_status, AuditStatus::Warn);
    }

    #[test]
    fn report_fail_overrides_warn() {
        let mut report = AuditReport::new();
        report.add_check(AuditCheck {
            name: "w".into(),
            category: AuditCategory::TypeSafety,
            status: AuditStatus::Warn,
            evidence: None,
            duration_ms: None,
        });
        report.add_check(AuditCheck {
            name: "f".into(),
            category: AuditCategory::TypeSafety,
            status: AuditStatus::Fail,
            evidence: None,
            duration_ms: None,
        });
        report.finalize();
        assert_eq!(report.summary.overall_status, AuditStatus::Fail);
    }

    #[test]
    fn report_serializes_to_json() {
        let mut report = AuditReport::new();
        report.program_digest = Some("abc123".into());
        report.add_check(AuditCheck {
            name: "dummy".into(),
            category: AuditCategory::TypeSafety,
            status: AuditStatus::Pass,
            evidence: None,
            duration_ms: None,
        });
        report.finalize();

        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], AUDIT_REPORT_VERSION);
        assert_eq!(parsed["program_digest"], "abc123");
        assert_eq!(parsed["checks"][0]["status"], "pass");
        assert_eq!(parsed["summary"]["total_checks"], 1);
        assert_eq!(parsed["summary"]["overall_status"], "pass");
    }

    #[test]
    fn report_deserializes_from_json() {
        let mut report = AuditReport::new();
        report.add_check(AuditCheck {
            name: "round_trip".into(),
            category: AuditCategory::Normalization,
            status: AuditStatus::Warn,
            evidence: Some("test evidence".into()),
            duration_ms: Some(10),
        });
        report.add_finding(AuditFinding {
            severity: AuditSeverity::Warning,
            category: AuditCategory::Normalization,
            message: "test finding".into(),
            location: Some("line 42".into()),
            suggestion: None,
        });
        report.finalize();

        let json = report.to_json().unwrap();
        let restored: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.checks.len(), 1);
        assert_eq!(restored.findings.len(), 1);
        assert_eq!(restored.findings[0].severity, AuditSeverity::Warning);
        assert_eq!(restored.summary.warned, 1);
    }

    #[test]
    fn underconstrained_findings_receive_default_suggestions() {
        let mut report = AuditReport::new();
        report.add_finding(AuditFinding {
            severity: AuditSeverity::Error,
            category: AuditCategory::UnderconstrainedSignals,
            message: "private signal 'x' is not referenced by any constraint".into(),
            location: Some("signal 'x'".into()),
            suggestion: None,
        });
        report.add_finding(AuditFinding {
            severity: AuditSeverity::Error,
            category: AuditCategory::UnderconstrainedSignals,
            message:
                "private signal 'y' is linearly underdetermined without nonlinear anchoring (nullity>0)"
                    .into(),
            location: Some("signal 'y'".into()),
            suggestion: None,
        });

        assert!(
            report.findings[0]
                .suggestion
                .as_deref()
                .unwrap_or_default()
                .contains("Constrain the signal")
        );
        assert!(
            report.findings[1]
                .suggestion
                .as_deref()
                .unwrap_or_default()
                .contains("nonlinear relation")
        );
    }

    #[test]
    fn audit_program_basic() {
        let program = make_test_program();
        let report = audit_program(&program, None);

        // Should have at least type_check, normalization, underconstrained, and constraint_soundness
        assert!(report.checks.len() >= 3);
        assert_eq!(report.version, AUDIT_REPORT_VERSION);
        assert!(report.program_digest.is_some());
        assert_eq!(report.field, Some(FieldId::Bn254));

        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["summary"]["total_checks"].as_u64().unwrap() >= 3);
    }

    #[test]
    fn audit_program_skips_dense_underconstrained_rank_by_default() {
        let private_signal_count = 4_500usize;
        let mut signals = Vec::with_capacity(private_signal_count + 1);
        signals.push(Signal {
            name: "out".into(),
            visibility: Visibility::Public,
            ty: SignalType::Field,
            constant: None,
        });
        for idx in 0..private_signal_count {
            signals.push(Signal {
                name: format!("x_{idx}"),
                visibility: Visibility::Private,
                ty: SignalType::Field,
                constant: None,
            });
        }

        let constraints = (0..private_signal_count)
            .map(|idx| Constraint::Equal {
                lhs: Expr::Signal("out".into()),
                rhs: Expr::Signal(format!("x_{idx}")),
                label: Some(format!("eq_{idx}")),
            })
            .collect::<Vec<_>>();

        let program = crate::zir::Program {
            name: "dense_rank_skip".into(),
            field: FieldId::Goldilocks,
            signals,
            constraints,
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let report = audit_program(&program, None);
        let check = report
            .checks
            .iter()
            .find(|candidate| candidate.name == "underconstrained_signals")
            .expect("underconstrained_signals check");

        assert_eq!(check.status, AuditStatus::Skip);
        assert!(
            check
                .evidence
                .as_deref()
                .unwrap_or_default()
                .contains("default cap"),
            "{check:?}"
        );
    }

    #[test]
    fn supported_normalization_idempotency_fast_path_matches_normalize_api() {
        let program = make_test_program();
        let idempotency =
            crate::proof_transform_spec::normalize_supported_program_idempotency_runtime(&program)
                .expect("supported normalization idempotency");
        let (norm1, _) = crate::normalize::normalize(&program);
        let d1 = norm1.digest_hex();
        let (norm2, _) = crate::normalize::normalize(&norm1);
        let d2 = norm2.digest_hex();

        assert_eq!(idempotency.report.output_digest, d1);
        assert_eq!(idempotency.second_output_digest, d2);
    }

    #[test]
    fn audit_program_marks_linearly_underdetermined_private_signals_as_fail() {
        let program = crate::zir::Program {
            name: "underdetermined".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("out".into()),
                rhs: Expr::Add(vec![Expr::Signal("x".into()), Expr::Signal("y".into())]),
                label: Some("sum".into()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let report = audit_program(&program, None);
        let check = report
            .checks
            .iter()
            .find(|candidate| candidate.name == "underconstrained_signals")
            .expect("underconstrained_signals check");

        assert_eq!(check.status, AuditStatus::Fail);
        let finding = report
            .findings
            .iter()
            .find(|finding| {
                finding.severity == AuditSeverity::Error
                    && finding.message.contains("linearly underdetermined")
            })
            .expect("underdetermined finding");
        assert!(
            finding
                .message
                .contains("A malicious prover could manipulate this value"),
            "finding should explain the exploit in plain English"
        );
        assert!(
            finding
                .suggestion
                .as_deref()
                .unwrap_or_default()
                .contains("docs/NONLINEAR_ANCHORING.md"),
            "finding should point to the nonlinear anchoring guide"
        );
    }

    #[test]
    fn audit_program_allows_nonlinear_private_relations_without_linear_only_failures() {
        let program = crate::zir::Program {
            name: "nonlinear_private_relation".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("out".into()),
                rhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("y".into())),
                ),
                label: Some("product".into()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let report = audit_program(&program, None);
        let check = report
            .checks
            .iter()
            .find(|candidate| candidate.name == "underconstrained_signals")
            .expect("underconstrained_signals check");

        assert_eq!(check.status, AuditStatus::Pass);
        assert!(
            check
                .evidence
                .as_deref()
                .unwrap_or_default()
                .contains("nonlinear-participating conservative underdetermined"),
            "{check:?}"
        );
    }

    #[test]
    fn audit_program_with_backend() {
        let program = make_test_program();
        let report = audit_program(&program, Some(BackendKind::ArkworksGroth16));

        // Should include backend checks
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == "backend_support_class")
        );
        assert!(report.checks.iter().any(|c| c.name == "gpu_accuracy"));
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == "field_compatibility")
        );
        assert!(report.checks.iter().any(|c| c.name == "setup_integrity"));
        assert_eq!(report.support_class, Some("native".into()));
    }

    #[test]
    fn audit_program_marks_limited_blackbox_ops_as_warning() {
        let program = crate::zir::Program {
            name: "limited_blackbox".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "sig_in".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "sig_out".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![Constraint::BlackBox {
                op: crate::zir::BlackBoxOp::SchnorrVerify,
                inputs: vec![Expr::Signal("sig_in".into())],
                outputs: vec!["sig_out".into()],
                params: BTreeMap::new(),
                label: Some("limited_schnorr".into()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let report = audit_program(&program, None);
        let check = report
            .checks
            .iter()
            .find(|candidate| candidate.name == "blackbox_lowering")
            .expect("blackbox_lowering check");

        assert_eq!(check.status, AuditStatus::Warn);
        assert!(
            check
                .evidence
                .as_deref()
                .unwrap_or_default()
                .contains("limited: [schnorr_verify]"),
            "{check:?}"
        );
        assert!(report.findings.iter().any(|finding| {
            finding.severity == AuditSeverity::Warning
                && finding
                    .message
                    .contains("limited rather than production-safe")
        }));
    }

    #[test]
    fn audit_program_rejects_signature_sham_arithmetic() {
        let program = crate::zir::Program {
            name: "fake_signature_check".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "issuer_public_key".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "issuer_signature_r".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "issuer_signature_s".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "is_issuer_valid".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("issuer_signature_s".into()),
                    rhs: Expr::Mul(
                        Box::new(Expr::Signal("issuer_public_key".into())),
                        Box::new(Expr::Signal("issuer_signature_r".into())),
                    ),
                    label: Some("issuer_signature_relation".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("is_issuer_valid".into()),
                    rhs: Expr::Const(FieldElement::from_i64(1)),
                    label: Some("issuer_auth_claim".into()),
                },
            ],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::from([("issuer_public_key_hint".into(), "demo-only".into())]),
        };

        let report = audit_program(&program, None);
        let check = report
            .checks
            .iter()
            .find(|candidate| candidate.name == "signature_semantics")
            .expect("signature_semantics check");

        assert_eq!(check.status, AuditStatus::Fail);
        assert!(
            check
                .evidence
                .as_deref()
                .unwrap_or_default()
                .contains("without cryptographic signature blackbox"),
            "{check:?}"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| { finding.message.contains("use ecdsa_* or schnorr_verify") })
        );
    }

    #[test]
    fn audit_program_accepts_real_signature_blackbox_semantics() {
        let program = crate::zir::Program {
            name: "real_signature_check".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "issuer_signature_00".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "is_issuer_valid".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Field,
                    constant: None,
                },
            ],
            constraints: vec![Constraint::BlackBox {
                op: crate::zir::BlackBoxOp::EcdsaSecp256r1,
                inputs: vec![Expr::Signal("issuer_signature_00".into())],
                outputs: vec!["is_issuer_valid".into()],
                params: BTreeMap::new(),
                label: Some("issuer_signature_verify".into()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::from([(
                "issuer_public_key_uncompressed_hex".into(),
                "04deadbeef".into(),
            )]),
        };

        let report = audit_program(&program, None);
        let check = report
            .checks
            .iter()
            .find(|candidate| candidate.name == "signature_semantics")
            .expect("signature_semantics check");

        assert_eq!(check.status, AuditStatus::Pass);
        assert!(
            check
                .evidence
                .as_deref()
                .unwrap_or_default()
                .contains("ecdsa_secp256r1"),
            "{check:?}"
        );
    }

    #[test]
    fn audit_program_uses_supplied_readiness_metadata() {
        let program = make_test_program();
        let matrix = crate::BackendCapabilityMatrix {
            schema_version: 2,
            audit_date: "dynamic-test".into(),
            entries: vec![crate::BackendCapabilityEntry {
                backend: BackendKind::ArkworksGroth16,
                support_class: crate::SupportClass::Native,
                delegates_to: None,
                supported_fields: vec![FieldId::Bn254],
                max_range_bits: None,
                gpu_acceleration: crate::GpuAcceleration {
                    claimed: true,
                    actual: true,
                    stages: vec!["msm".into()],
                },
                accepts_canonical_ir: true,
                trusted_setup_required: true,
                recursion_ready: false,
                solidity_export: true,
                proof_size_estimate: "~128 bytes".into(),
                supported_constraint_kinds: vec!["equal".into()],
                supported_blackbox_ops: vec![],
                implementation_type: Some(crate::SupportClass::Native),
                compiled_in: Some(true),
                toolchain_ready: Some(false),
                runtime_ready: Some(false),
                production_ready: Some(false),
                readiness: Some("blocked".into()),
                readiness_reason: Some("test-readiness-blocker".into()),
                operator_action: Some("install the missing test dependency".into()),
                explicit_compat_alias: Some("arkworks-groth16-compat".into()),
                native_lookup_support: Some(false),
                lookup_lowering_support: Some(true),
                lookup_semantics: Some("arithmetic-lowering-required".into()),
                aggregation_semantics: Some("single-proof-only".into()),
                notes: "test entry".into(),
            }],
        };

        let report = audit_program_with_capability_matrix(
            &program,
            Some(BackendKind::ArkworksGroth16),
            &matrix,
        );

        assert_eq!(report.production_ready, Some(false));
        assert_eq!(report.readiness.as_deref(), Some("blocked"));
        assert_eq!(
            report.readiness_reason.as_deref(),
            Some("test-readiness-blocker")
        );
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "backend_readiness" && check.status == AuditStatus::Fail));
    }

    #[test]
    fn audit_program_native_halo2_backend_passes() {
        let program = crate::zir::Program {
            name: "broken_test".into(),
            field: FieldId::Bls12_381,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Public,
                ty: SignalType::Field,
                constant: None,
            }],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };
        let report = audit_program(&program, Some(BackendKind::Halo2Bls12381));

        let backend_check = report
            .checks
            .iter()
            .find(|c| c.name == "backend_support_class")
            .unwrap();
        assert_eq!(backend_check.status, AuditStatus::Pass);
        assert_eq!(report.support_class, Some("native".into()));
    }

    #[test]
    fn audit_program_type_error() {
        let program = crate::zir::Program {
            name: "bad_types".into(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Public,
                ty: SignalType::Field,
                constant: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".into()),
                rhs: Expr::Signal("nonexistent".into()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };
        let report = audit_program(&program, None);

        let tc = report
            .checks
            .iter()
            .find(|c| c.name == "type_check")
            .unwrap();
        assert_eq!(tc.status, AuditStatus::Fail);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.category == AuditCategory::TypeSafety)
        );
    }
}
