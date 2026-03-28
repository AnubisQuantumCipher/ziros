//! ZKF Frontend SDK — build plugins that compile external circuit formats to ZKF IR.
//!
//! This crate provides the [`ZkfFrontendPlugin`] trait that external frontends implement
//! to integrate with the ZKF framework. It provides a simpler, more stable API surface
//! than the internal `FrontendEngine` trait.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use zkf_frontend_sdk::{ZkfFrontendPlugin, PluginInfo, ProbeResult, CompileOptions, PluginError};
//! use zkf_core::{FieldId, Program};
//!
//! struct MyFrontend;
//!
//! impl ZkfFrontendPlugin for MyFrontend {
//!     fn info(&self) -> PluginInfo {
//!         PluginInfo {
//!             name: "my-dsl".into(),
//!             version: "0.1.0".into(),
//!             description: "My custom DSL frontend".into(),
//!             supported_fields: vec![FieldId::Bn254],
//!             file_extensions: vec![".mydsl".into()],
//!         }
//!     }
//!
//!     fn probe(&self, _artifact: &serde_json::Value) -> ProbeResult {
//!         ProbeResult { compatible: false, confidence: 0.0, message: None }
//!     }
//!
//!     fn compile_to_zir(
//!         &self,
//!         _artifact: &serde_json::Value,
//!         _options: &CompileOptions,
//!     ) -> Result<Program, PluginError> {
//!         Err(PluginError::unsupported_feature("not yet implemented"))
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use zkf_core::{FieldId, Program};

/// Metadata about a frontend plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique name of the frontend (e.g., "my-dsl").
    pub name: String,
    /// Semantic version of the plugin.
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Supported output fields.
    pub supported_fields: Vec<FieldId>,
    /// File extensions this frontend can handle (e.g., `[".noir", ".json"]`).
    pub file_extensions: Vec<String>,
}

/// Result of probing a file/artifact to check if this frontend can handle it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Whether this frontend can handle the artifact.
    pub compatible: bool,
    /// Confidence level (0.0 = guess, 1.0 = certain).
    pub confidence: f64,
    /// Optional message about the probe result.
    pub message: Option<String>,
}

/// Options for compilation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompileOptions {
    /// Target field (if `None`, use the frontend's default).
    pub target_field: Option<FieldId>,
    /// Circuit/program name override.
    pub program_name: Option<String>,
    /// Whether to allow experimental/unstable features.
    pub allow_experimental: bool,
}

/// Trait for external frontend plugins.
///
/// Implement this trait to create a ZKF frontend that compiles your
/// circuit format into ZKF IR.
pub trait ZkfFrontendPlugin: Send + Sync {
    /// Return metadata about this plugin.
    fn info(&self) -> PluginInfo;

    /// Probe an artifact to determine if this frontend can handle it.
    fn probe(&self, artifact: &serde_json::Value) -> ProbeResult;

    /// Compile an artifact into a ZKF IR [`Program`].
    fn compile_to_zir(
        &self,
        artifact: &serde_json::Value,
        options: &CompileOptions,
    ) -> Result<Program, PluginError>;

    /// Optional: return the IR version this plugin targets.
    fn target_ir_version(&self) -> zkf_ir_spec::version::IrVersion {
        zkf_ir_spec::version::IrVersion {
            major: zkf_ir_spec::IR_SPEC_MAJOR,
            minor: zkf_ir_spec::IR_SPEC_MINOR,
        }
    }
}

/// Error type for frontend plugin operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginError {
    /// Machine-readable error code (e.g., `"PARSE_ERROR"`).
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional source location string (e.g., `"file.noir:12:5"`).
    pub source_location: Option<String>,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for PluginError {}

impl PluginError {
    /// Create a new error with a code and message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            source_location: None,
        }
    }

    /// Attach a source location to this error.
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.source_location = Some(location.into());
        self
    }

    /// Create a parse error.
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new("PARSE_ERROR", message)
    }

    /// Create an unsupported-feature error.
    pub fn unsupported_feature(message: impl Into<String>) -> Self {
        Self::new("UNSUPPORTED_FEATURE", message)
    }

    /// Create a field-mismatch error.
    pub fn field_mismatch(message: impl Into<String>) -> Self {
        Self::new("FIELD_MISMATCH", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_info_roundtrips_through_json() {
        let info = PluginInfo {
            name: "test-frontend".into(),
            version: "1.2.3".into(),
            description: "A test frontend".into(),
            supported_fields: vec![FieldId::Bn254, FieldId::Goldilocks],
            file_extensions: vec![".test".into(), ".json".into()],
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: PluginInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test-frontend");
        assert_eq!(back.version, "1.2.3");
        assert_eq!(back.supported_fields.len(), 2);
        assert_eq!(back.file_extensions, vec![".test", ".json"]);
    }

    #[test]
    fn probe_result_roundtrips_through_json() {
        let probe = ProbeResult {
            compatible: true,
            confidence: 0.95,
            message: Some("Detected Noir ACIR format".into()),
        };
        let json = serde_json::to_string(&probe).unwrap();
        let back: ProbeResult = serde_json::from_str(&json).unwrap();
        assert!(back.compatible);
        assert!((back.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(back.message.as_deref(), Some("Detected Noir ACIR format"));
    }

    #[test]
    fn probe_result_none_message() {
        let probe = ProbeResult {
            compatible: false,
            confidence: 0.0,
            message: None,
        };
        let json = serde_json::to_string(&probe).unwrap();
        let back: ProbeResult = serde_json::from_str(&json).unwrap();
        assert!(!back.compatible);
        assert!(back.message.is_none());
    }

    #[test]
    fn compile_options_default_is_empty() {
        let opts = CompileOptions::default();
        assert!(opts.target_field.is_none());
        assert!(opts.program_name.is_none());
        assert!(!opts.allow_experimental);
    }

    #[test]
    fn compile_options_roundtrips_through_json() {
        let opts = CompileOptions {
            target_field: Some(FieldId::BabyBear),
            program_name: Some("my_circuit".into()),
            allow_experimental: true,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let back: CompileOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target_field, Some(FieldId::BabyBear));
        assert_eq!(back.program_name.as_deref(), Some("my_circuit"));
        assert!(back.allow_experimental);
    }

    #[test]
    fn plugin_error_display() {
        let err = PluginError::new("TEST_ERR", "something went wrong");
        assert_eq!(err.to_string(), "[TEST_ERR] something went wrong");
    }

    #[test]
    fn plugin_error_with_location() {
        let err = PluginError::parse_error("unexpected token").with_location("circuit.noir:42:10");
        assert_eq!(err.code, "PARSE_ERROR");
        assert_eq!(err.source_location.as_deref(), Some("circuit.noir:42:10"));
    }

    #[test]
    fn plugin_error_convenience_constructors() {
        let e1 = PluginError::parse_error("bad syntax");
        assert_eq!(e1.code, "PARSE_ERROR");

        let e2 = PluginError::unsupported_feature("recursion");
        assert_eq!(e2.code, "UNSUPPORTED_FEATURE");

        let e3 = PluginError::field_mismatch("expected BN254, got BabyBear");
        assert_eq!(e3.code, "FIELD_MISMATCH");
    }

    #[test]
    fn plugin_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(PluginError::new("CODE", "msg"));
        assert!(err.to_string().contains("CODE"));
    }

    #[test]
    fn plugin_error_roundtrips_through_json() {
        let err = PluginError::parse_error("unexpected EOF").with_location("file.zk:1:0");
        let json = serde_json::to_string(&err).unwrap();
        let back: PluginError = serde_json::from_str(&json).unwrap();
        assert_eq!(back.code, "PARSE_ERROR");
        assert_eq!(back.message, "unexpected EOF");
        assert_eq!(back.source_location.as_deref(), Some("file.zk:1:0"));
    }
}
