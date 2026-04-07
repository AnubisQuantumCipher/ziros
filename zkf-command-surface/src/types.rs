use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResultV1<T> {
    pub schema: String,
    pub operation_id: String,
    pub status: String,
    pub generated_at: String,
    pub data: T,
}

impl<T> CommandResultV1<T> {
    pub fn success(operation_id: impl Into<String>, data: T) -> Self {
        Self {
            schema: "zkf-command-result-v1".to_string(),
            operation_id: operation_id.into(),
            status: "ok".to_string(),
            generated_at: now_rfc3339(),
            data,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClassV1 {
    ReadOnly,
    LocalBuildTest,
    WorkspaceMutation,
    ToolchainInstall,
    NetworkPublish,
    WalletSignOrSubmit,
    PublicEdgeChange,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CommandErrorClassV1 {
    CapabilityBlocked,
    ApprovalRequired,
    DependencyBlocked,
    InvalidInput,
    MissingArtifact,
    ToolchainFailure,
    RuntimeFailure,
    VerificationFailure,
    ExternalServiceFailure,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRefV1 {
    pub label: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRecordV1 {
    pub name: String,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDescriptorV1 {
    pub name: String,
    pub family: String,
    pub risk_class: RiskClassV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResultEnvelopeV1 {
    pub schema: String,
    pub operation_id: String,
    pub action: ActionDescriptorV1,
    pub status: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_summary: Option<TrustSummaryV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRefV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<MetricRecordV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<CommandErrorClassV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

impl ActionResultEnvelopeV1 {
    pub fn success(
        operation_id: impl Into<String>,
        action: ActionDescriptorV1,
        payload: Option<Value>,
    ) -> Self {
        Self {
            schema: "zkf-action-result-v1".to_string(),
            operation_id: operation_id.into(),
            action,
            status: "ok".to_string(),
            generated_at: now_rfc3339(),
            trust_summary: None,
            artifacts: Vec::new(),
            metrics: Vec::new(),
            error_class: None,
            payload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandEventKindV1 {
    Started,
    Progress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustSummaryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEventV1 {
    pub schema: String,
    pub timestamp: String,
    pub event_kind: CommandEventKindV1,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workgraph_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    pub action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_summary: Option<TrustSummaryV1>,
}

impl CommandEventV1 {
    pub fn new(
        action_id: impl Into<String>,
        event_kind: CommandEventKindV1,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema: "zkf-command-event-v1".to_string(),
            timestamp: now_rfc3339(),
            event_kind,
            message: message.into(),
            session_id: None,
            workgraph_id: None,
            node_id: None,
            action_id: action_id.into(),
            stage: None,
            metrics: None,
            artifacts: None,
            trust_summary: None,
        }
    }
}

enum JsonlTarget {
    Stdout,
    File(File),
}

pub struct JsonlEventSink {
    target: JsonlTarget,
}

impl JsonlEventSink {
    pub fn open(path: Option<PathBuf>) -> Result<Option<Self>, String> {
        let Some(path) = path else {
            return Ok(None);
        };
        if path.as_os_str() == "-" {
            return Ok(Some(Self {
                target: JsonlTarget::Stdout,
            }));
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
        Ok(Some(Self {
            target: JsonlTarget::File(file),
        }))
    }

    pub fn emit(&mut self, event: &CommandEventV1) -> Result<(), String> {
        let line = serde_json::to_string(event).map_err(|error| error.to_string())?;
        match &mut self.target {
            JsonlTarget::Stdout => {
                println!("{line}");
                Ok(())
            }
            JsonlTarget::File(file) => {
                writeln!(file, "{line}").map_err(|error| error.to_string())?;
                file.flush().map_err(|error| error.to_string())
            }
        }
    }
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub fn new_operation_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{prefix}-{}", bytes_to_hex(&bytes))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
