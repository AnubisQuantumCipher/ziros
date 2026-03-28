use crate::FieldElement;
#[cfg(feature = "full")]
use crate::{AuditReport, UnderconstrainedAnalysis};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZkfError {
    #[error("failed to parse field element '{value}'")]
    ParseField { value: String },

    #[error("unknown signal '{signal}'")]
    UnknownSignal { signal: String },

    #[error("missing required witness value for signal '{signal}'")]
    MissingWitnessValue { signal: String },

    #[error("division by zero while evaluating expression")]
    DivisionByZero,

    #[error("constraint violation at index {index} ({label:?}): lhs={lhs}, rhs={rhs}")]
    ConstraintViolation {
        index: usize,
        label: Option<String>,
        lhs: FieldElement,
        rhs: FieldElement,
    },

    #[error(
        "boolean constraint violation at index {index} ({label:?}) for signal '{signal}': value={value}"
    )]
    BooleanConstraintViolation {
        index: usize,
        label: Option<String>,
        signal: String,
        value: FieldElement,
    },

    #[error(
        "range constraint violation at index {index} ({label:?}) for signal '{signal}': bits={bits}, value={value}"
    )]
    RangeConstraintViolation {
        index: usize,
        label: Option<String>,
        signal: String,
        bits: u32,
        value: FieldElement,
    },

    #[error(
        "lookup constraint violation at index {index} ({label:?}) for table '{table}': {message}"
    )]
    LookupConstraintViolation {
        index: usize,
        label: Option<String>,
        table: String,
        message: String,
    },

    #[error("lookup constraint references unknown table '{table}'")]
    UnknownLookupTable { table: String },

    #[error("ccs conversion cannot encode constraint at index {index} ({label:?}): {reason}")]
    UnsupportedCcsEncoding {
        index: usize,
        label: Option<String>,
        reason: String,
    },

    #[error(
        "witness generation could not resolve derived signals {unresolved_signals:?}: {reason}"
    )]
    UnsupportedWitnessSolve {
        unresolved_signals: Vec<String>,
        reason: String,
    },

    #[error("unsupported backend '{backend}': {message}")]
    UnsupportedBackend { backend: String, message: String },

    #[error("backend failure: {0}")]
    Backend(String),

    #[cfg(feature = "full")]
    #[error("{message}")]
    AuditFailure {
        message: String,
        failed_checks: usize,
        report: Box<AuditReport>,
        analysis: Option<Box<UnderconstrainedAnalysis>>,
    },

    #[error("feature disabled for backend '{backend}'")]
    FeatureDisabled { backend: String },

    #[error("invalid artifact: {0}")]
    InvalidArtifact(String),

    #[error("program digest mismatch, expected {expected}, found {found}")]
    ProgramMismatch { expected: String, found: String },

    #[error("compiled artifact is missing backend setup data")]
    MissingCompiledData,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("io error: {0}")]
    Io(String),
}

pub type ZkfResult<T> = Result<T, ZkfError>;

#[cfg(feature = "full")]
impl ZkfError {
    pub fn audit_report(&self) -> Option<&AuditReport> {
        match self {
            ZkfError::AuditFailure { report, .. } => Some(report.as_ref()),
            _ => None,
        }
    }

    pub fn audit_analysis(&self) -> Option<&UnderconstrainedAnalysis> {
        match self {
            ZkfError::AuditFailure { analysis, .. } => analysis.as_deref(),
            _ => None,
        }
    }
}
