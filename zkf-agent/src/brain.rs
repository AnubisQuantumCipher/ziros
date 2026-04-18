use crate::state::{brain_path, ensure_ziros_layout};
use crate::types::{
    ActionReceiptV1, AgentSessionViewV1, ApprovalRequestRecordV1, ApprovalTokenRecordV1,
    ArtifactRecordV1, BridgeHandoffRecordV1, CheckpointRecordV1, DeploymentRecordV1,
    EnvironmentSnapshotV1, IncidentRecordV1, ProcedureRecordV1, ProjectRecordV1,
    ProviderRouteRecordV1, SessionStatusV1, SubmissionGrantRecordV1, TrustGateReportV1,
    WorkgraphNodeV1, WorkgraphV1, WorktreeRecordV1,
};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use zkf_cloudfs::CloudFS;
use zkf_command_surface::{ArtifactRefV1, new_operation_id, now_rfc3339};
use zkf_keymanager::KeyManager;

const BRAIN_KEY_ID: &str = "ziros-agent-brain";
const BRAIN_KEY_SERVICE: &str = "com.ziros.agent.brain";

pub struct BrainStore {
    conn: Connection,
    key: [u8; 32],
    cache_root: PathBuf,
}

impl BrainStore {
    pub fn open_default() -> Result<Self, String> {
        let cloudfs = CloudFS::new().map_err(|error| error.to_string())?;
        let _ = ensure_ziros_layout()?;
        Self::open_at_path(cloudfs, brain_path())
    }

    #[cfg(test)]
    pub(crate) fn open_with_cloudfs(cloudfs: CloudFS) -> Result<Self, String> {
        let db_path = isolated_brain_path_for_cloudfs(&cloudfs);
        Self::open_at_path(cloudfs, db_path)
    }

    fn open_at_path(cloudfs: CloudFS, db_path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
        }
        let conn = Connection::open(&db_path)
            .map_err(|error| format!("failed to open {}: {error}", db_path.display()))?;
        let manager = KeyManager::with_cloudfs(cloudfs);
        let key = load_or_create_key(&manager)?;
        let store = Self {
            conn,
            key,
            cache_root: db_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    pub fn create_session(
        &self,
        goal: &str,
        workflow_kind: &str,
        status: SessionStatusV1,
        project_root: Option<PathBuf>,
    ) -> Result<AgentSessionViewV1, String> {
        let session_id = new_operation_id("session");
        let now = now_rfc3339();
        let goal_summary = summarize_goal(goal);
        let goal_ciphertext = self.encrypt_json(&json!({ "goal": goal }))?;
        self.conn
            .execute(
                "INSERT INTO sessions (
                    session_id, status, workflow_kind, goal_summary, created_at, updated_at, project_root
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    session_id,
                    status.as_str(),
                    workflow_kind,
                    goal_summary,
                    now,
                    now,
                    project_root.as_ref().map(|path| path.display().to_string()),
                ],
            )
            .map_err(|error| error.to_string())?;
        self.conn
            .execute(
                "INSERT INTO goals (goal_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    new_operation_id("goal"),
                    session_id,
                    now_rfc3339(),
                    goal_ciphertext
                ],
            )
            .map_err(|error| error.to_string())?;
        self.get_session(&session_id)?
            .ok_or_else(|| format!("failed to create session '{session_id}'"))
    }

    pub fn attach_workgraph(
        &self,
        session_id: &str,
        workgraph_id: &str,
        capability_snapshot_id: String,
    ) -> Result<AgentSessionViewV1, String> {
        self.conn
            .execute(
                "UPDATE sessions SET workgraph_id = ?2, capability_snapshot_id = ?3, updated_at = ?4 WHERE session_id = ?1",
                params![session_id, workgraph_id, capability_snapshot_id, now_rfc3339()],
            )
            .map_err(|error| error.to_string())?;
        self.get_session(session_id)?
            .ok_or_else(|| format!("unknown session '{session_id}'"))
    }

    pub fn store_capability_snapshot(
        &self,
        session_id: &str,
        trust_gate: &TrustGateReportV1,
    ) -> Result<String, String> {
        let snapshot_id = new_operation_id("capability-snapshot");
        self.conn
            .execute(
                "INSERT INTO capability_snapshots (snapshot_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    snapshot_id,
                    session_id,
                    now_rfc3339(),
                    self.encrypt_json(trust_gate)?
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(snapshot_id)
    }

    pub fn get_capability_snapshot(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<TrustGateReportV1>, String> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_ciphertext FROM capability_snapshots WHERE snapshot_id = ?1",
                params![snapshot_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        payload
            .map(|payload| self.decrypt_json::<TrustGateReportV1>(&payload))
            .transpose()
    }

    pub fn store_workgraph(
        &self,
        session_id: &str,
        _capability_snapshot_id: String,
        workgraph: &WorkgraphV1,
    ) -> Result<WorkgraphV1, String> {
        let mut stored = workgraph.clone();
        stored.session_id = Some(session_id.to_string());
        self.conn
            .execute(
                "INSERT INTO workgraphs (workgraph_id, session_id, status, workflow_kind, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    stored.workgraph_id,
                    session_id,
                    stored.status,
                    stored.workflow_kind,
                    now_rfc3339(),
                    self.encrypt_json(&stored)?
                ],
            )
            .map_err(|error| error.to_string())?;
        for node in &stored.nodes {
            self.store_node(&stored.workgraph_id, node)?;
        }
        Ok(stored)
    }

    pub fn get_workgraph(&self, workgraph_id: &str) -> Result<Option<WorkgraphV1>, String> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_ciphertext FROM workgraphs WHERE workgraph_id = ?1",
                params![workgraph_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        payload
            .map(|payload| self.decrypt_json::<WorkgraphV1>(&payload))
            .transpose()
    }

    pub fn update_workgraph(&self, workgraph: &WorkgraphV1) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE workgraphs
                 SET status = ?2, payload_ciphertext = ?3
                 WHERE workgraph_id = ?1",
                params![
                    workgraph.workgraph_id,
                    workgraph.status,
                    self.encrypt_json(workgraph)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        for node in &workgraph.nodes {
            self.store_node(&workgraph.workgraph_id, node)?;
        }
        Ok(())
    }

    pub fn append_receipt(&self, receipt: &ActionReceiptV1) -> Result<ActionReceiptV1, String> {
        self.conn
            .execute(
                "INSERT INTO action_receipts (receipt_id, session_id, created_at, action_name, status, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    receipt.receipt_id,
                    receipt.session_id,
                    receipt.created_at,
                    receipt.action_name,
                    receipt.status,
                    self.encrypt_json(receipt)?
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(receipt.clone())
    }

    pub fn new_receipt(
        &self,
        session_id: &str,
        action_name: &str,
        status: &str,
        payload: &impl Serialize,
    ) -> Result<ActionReceiptV1, String> {
        Ok(ActionReceiptV1 {
            schema: "ziros-action-receipt-v1".to_string(),
            receipt_id: new_operation_id("receipt"),
            session_id: session_id.to_string(),
            action_name: action_name.to_string(),
            status: status.to_string(),
            created_at: now_rfc3339(),
            action: None,
            artifacts: Vec::new(),
            metrics: Vec::new(),
            error_class: None,
            payload: serde_json::to_value(payload).map_err(|error| error.to_string())?,
        })
    }

    pub fn list_receipts(&self, session_id: &str) -> Result<Vec<ActionReceiptV1>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT receipt_id, created_at, action_name, status, payload_ciphertext
                 FROM action_receipts
                 WHERE session_id = ?1
                 ORDER BY created_at ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![session_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        let mut receipts = Vec::new();
        for row in rows {
            let (receipt_id, created_at, action_name, status, payload_ciphertext) =
                row.map_err(|error| error.to_string())?;
            let mut receipt = match self.decrypt_json::<ActionReceiptV1>(&payload_ciphertext) {
                Ok(receipt) => receipt,
                Err(_) => ActionReceiptV1 {
                    schema: "ziros-action-receipt-v1".to_string(),
                    receipt_id: receipt_id.clone(),
                    session_id: session_id.to_string(),
                    action_name: action_name.clone(),
                    status: status.clone(),
                    created_at: created_at.clone(),
                    action: None,
                    artifacts: Vec::new(),
                    metrics: Vec::new(),
                    error_class: None,
                    payload: self.decrypt_json(&payload_ciphertext)?,
                },
            };
            receipt.receipt_id = receipt_id;
            receipt.session_id = session_id.to_string();
            receipt.action_name = action_name;
            receipt.status = status;
            receipt.created_at = created_at;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<AgentSessionViewV1>, String> {
        self.conn
            .query_row(
                "SELECT session_id, status, workflow_kind, goal_summary, created_at, updated_at, project_root, workgraph_id, capability_snapshot_id
                 FROM sessions
                 WHERE session_id = ?1",
                params![session_id],
                |row| {
                    Ok(AgentSessionViewV1 {
                        session_id: row.get(0)?,
                        status: parse_status(row.get::<_, String>(1)?.as_str()),
                        workflow_kind: row.get(2)?,
                        goal_summary: row.get(3)?,
                        created_at: row.get(4)?,
                        updated_at: row.get(5)?,
                        project_root: row.get(6)?,
                        workgraph_id: row.get(7)?,
                        capability_snapshot_id: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn list_sessions(&self, limit: usize) -> Result<Vec<AgentSessionViewV1>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT session_id, status, workflow_kind, goal_summary, created_at, updated_at, project_root, workgraph_id, capability_snapshot_id
                 FROM sessions
                 ORDER BY updated_at DESC
                 LIMIT ?1",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(AgentSessionViewV1 {
                    session_id: row.get(0)?,
                    status: parse_status(row.get::<_, String>(1)?.as_str()),
                    workflow_kind: row.get(2)?,
                    goal_summary: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    project_root: row.get(6)?,
                    workgraph_id: row.get(7)?,
                    capability_snapshot_id: row.get(8)?,
                })
            })
            .map_err(|error| error.to_string())?;
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row.map_err(|error| error.to_string())?);
        }
        Ok(sessions)
    }

    pub fn update_session_status(
        &self,
        session_id: &str,
        status: SessionStatusV1,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE sessions SET status = ?2, updated_at = ?3 WHERE session_id = ?1",
                params![session_id, status.as_str(), now_rfc3339()],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn update_session_project_root(
        &self,
        session_id: &str,
        project_root: Option<&Path>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "UPDATE sessions SET project_root = ?2, updated_at = ?3 WHERE session_id = ?1",
                params![
                    session_id,
                    project_root.map(|path| path.display().to_string()),
                    now_rfc3339()
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn register_project(&self, name: &str, root_path: &str) -> Result<ProjectRecordV1, String> {
        let record = ProjectRecordV1 {
            name: name.to_string(),
            root_path: root_path.to_string(),
            created_at: now_rfc3339(),
        };
        self.conn
            .execute(
                "INSERT OR REPLACE INTO project_registry (name, root_path, created_at, metadata_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.name,
                    record.root_path,
                    record.created_at,
                    self.encrypt_json(&record)?
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record)
    }

    pub fn list_projects(&self) -> Result<Vec<ProjectRecordV1>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT metadata_ciphertext FROM project_registry ORDER BY created_at DESC")
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|error| error.to_string())?;
        let mut projects = Vec::new();
        for row in rows {
            projects.push(self.decrypt_json(&row.map_err(|error| error.to_string())?)?);
        }
        Ok(projects)
    }

    pub fn store_bridge_handoff(
        &self,
        record: &BridgeHandoffRecordV1,
    ) -> Result<BridgeHandoffRecordV1, String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO bridge_handoffs (handoff_id, session_id, created_at, updated_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.handoff_id,
                    record.session_id,
                    record.created_at,
                    record.updated_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn get_bridge_handoff(
        &self,
        handoff_id: &str,
    ) -> Result<Option<BridgeHandoffRecordV1>, String> {
        let payload = self
            .conn
            .query_row(
                "SELECT payload_ciphertext FROM bridge_handoffs WHERE handoff_id = ?1",
                params![handoff_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        payload
            .map(|payload| self.decrypt_json::<BridgeHandoffRecordV1>(&payload))
            .transpose()
    }

    pub fn list_bridge_handoffs(&self) -> Result<Vec<BridgeHandoffRecordV1>, String> {
        self.list_payloads("bridge_handoffs", "handoff_id", None, "session_id")
    }

    pub fn list_environment_snapshots(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<EnvironmentSnapshotV1>, String> {
        self.list_payloads(
            "environment_snapshots",
            "snapshot_id",
            session_id,
            "session_id",
        )
    }

    pub fn store_environment_snapshot(
        &self,
        snapshot: &EnvironmentSnapshotV1,
    ) -> Result<EnvironmentSnapshotV1, String> {
        self.conn
            .execute(
                "INSERT INTO environment_snapshots (snapshot_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    snapshot.snapshot_id,
                    snapshot.session_id,
                    snapshot.generated_at,
                    self.encrypt_json(snapshot)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(snapshot.clone())
    }

    pub fn register_artifact(
        &self,
        session_id: Option<&str>,
        artifact: ArtifactRefV1,
    ) -> Result<ArtifactRecordV1, String> {
        let record = ArtifactRecordV1 {
            schema: "ziros-agent-artifact-v1".to_string(),
            artifact_id: new_operation_id("artifact"),
            session_id: session_id.map(str::to_string),
            created_at: now_rfc3339(),
            artifact,
        };
        self.conn
            .execute(
                "INSERT INTO artifacts (artifact_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.artifact_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(&record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record)
    }

    pub fn list_artifacts(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<ArtifactRecordV1>, String> {
        self.list_payloads("artifacts", "artifact_id", session_id, "session_id")
    }

    pub fn store_procedure(&self, record: &ProcedureRecordV1) -> Result<ProcedureRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO procedures (procedure_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3)",
                params![
                    record.procedure_id,
                    record.created_at,
                    self.encrypt_json(record)?
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_procedures(&self) -> Result<Vec<ProcedureRecordV1>, String> {
        self.list_payloads("procedures", "procedure_id", None, "session_id")
    }

    pub fn store_incident(&self, record: &IncidentRecordV1) -> Result<IncidentRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO incidents (incident_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3)",
                params![
                    record.incident_id,
                    record.created_at,
                    self.encrypt_json(record)?
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_incidents(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<IncidentRecordV1>, String> {
        self.list_payloads("incidents", "incident_id", session_id, "session_id")
    }

    pub fn store_approval_request(
        &self,
        record: &ApprovalRequestRecordV1,
    ) -> Result<ApprovalRequestRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO approval_requests (approval_request_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.approval_request_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn store_approval_token(
        &self,
        record: &ApprovalTokenRecordV1,
    ) -> Result<ApprovalTokenRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO approval_tokens (token_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.token_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_approval_requests(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<ApprovalRequestRecordV1>, String> {
        self.list_payloads(
            "approval_requests",
            "approval_request_id",
            session_id,
            "session_id",
        )
    }

    pub fn list_approval_tokens(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<ApprovalTokenRecordV1>, String> {
        self.list_payloads("approval_tokens", "token_id", session_id, "session_id")
    }

    #[allow(dead_code)]
    pub fn store_submission_grant(
        &self,
        record: &SubmissionGrantRecordV1,
    ) -> Result<SubmissionGrantRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO submission_grants (grant_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.grant_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_submission_grants(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<SubmissionGrantRecordV1>, String> {
        self.list_payloads("submission_grants", "grant_id", session_id, "session_id")
    }

    pub fn store_deployment(
        &self,
        record: &DeploymentRecordV1,
    ) -> Result<DeploymentRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO deployments (deployment_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.deployment_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_deployments(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<DeploymentRecordV1>, String> {
        self.list_payloads("deployments", "deployment_id", session_id, "session_id")
    }

    pub fn register_worktree(&self, record: &WorktreeRecordV1) -> Result<WorktreeRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO worktrees (worktree_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.worktree_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_worktrees(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<WorktreeRecordV1>, String> {
        self.list_payloads("worktrees", "worktree_id", session_id, "session_id")
    }

    pub fn get_worktree(&self, worktree_id: &str) -> Result<Option<WorktreeRecordV1>, String> {
        self.get_payload("worktrees", "worktree_id", worktree_id)
    }

    pub fn store_checkpoint(
        &self,
        record: &CheckpointRecordV1,
    ) -> Result<CheckpointRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO checkpoints (checkpoint_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.checkpoint_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_checkpoints(&self, session_id: &str) -> Result<Vec<CheckpointRecordV1>, String> {
        self.list_payloads(
            "checkpoints",
            "checkpoint_id",
            Some(session_id),
            "session_id",
        )
    }

    pub fn get_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<CheckpointRecordV1>, String> {
        self.get_payload("checkpoints", "checkpoint_id", checkpoint_id)
    }

    pub fn store_provider_route(
        &self,
        record: &ProviderRouteRecordV1,
    ) -> Result<ProviderRouteRecordV1, String> {
        self.conn
            .execute(
                "INSERT INTO provider_routes (route_id, session_id, created_at, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.route_id,
                    record.session_id,
                    record.created_at,
                    self.encrypt_json(record)?,
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(record.clone())
    }

    pub fn list_provider_routes(
        &self,
        session_id: Option<&str>,
    ) -> Result<Vec<ProviderRouteRecordV1>, String> {
        self.list_payloads("provider_routes", "route_id", session_id, "session_id")
    }

    fn migrate(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    workflow_kind TEXT NOT NULL,
                    goal_summary TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    project_root TEXT,
                    workgraph_id TEXT,
                    capability_snapshot_id TEXT
                );
                CREATE TABLE IF NOT EXISTS goals (
                    goal_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workgraphs (
                    workgraph_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    workflow_kind TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY,
                    workgraph_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    label TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    approval_required INTEGER NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS action_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS procedures (
                    procedure_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_request_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_tokens (
                    token_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS submission_grants (
                    grant_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deployments (
                    deployment_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS capability_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS environment_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS project_registry (
                    name TEXT PRIMARY KEY,
                    root_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS bridge_handoffs (
                    handoff_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS worktrees (
                    worktree_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_routes (
                    route_id TEXT PRIMARY KEY,
                    session_id TEXT,
                    created_at TEXT NOT NULL,
                    payload_ciphertext BLOB NOT NULL
                );
                ",
            )
            .map_err(|error| error.to_string())?;
        self.ensure_column("bridge_handoffs", "session_id", "TEXT")?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> Result<(), String> {
        let mut statement = self
            .conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|error| error.to_string())?;
        let present = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
            .into_iter()
            .any(|name| name == column);
        if present {
            return Ok(());
        }
        self.conn
            .execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn store_node(&self, workgraph_id: &str, node: &WorkgraphNodeV1) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO nodes (node_id, workgraph_id, status, label, action_name, approval_required, payload_ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node.node_id,
                    workgraph_id,
                    node.status,
                    node.label,
                    node.action_name,
                    i64::from(node.approval_required),
                    self.encrypt_json(node)?
                ],
            )
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn get_payload<T: DeserializeOwned>(
        &self,
        table: &str,
        key_column: &str,
        key: &str,
    ) -> Result<Option<T>, String> {
        let query = format!("SELECT payload_ciphertext FROM {table} WHERE {key_column} = ?1");
        let payload = self
            .conn
            .query_row(&query, params![key], |row| row.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(|error| error.to_string())?;
        payload
            .map(|payload| self.decrypt_json::<T>(&payload))
            .transpose()
    }

    fn list_payloads<T: DeserializeOwned>(
        &self,
        table: &str,
        order_column: &str,
        session_id: Option<&str>,
        session_column: &str,
    ) -> Result<Vec<T>, String> {
        let query = if session_id.is_some() {
            format!(
                "SELECT payload_ciphertext FROM {table} WHERE {session_column} = ?1 ORDER BY created_at ASC, {order_column} ASC"
            )
        } else {
            format!(
                "SELECT payload_ciphertext FROM {table} ORDER BY created_at ASC, {order_column} ASC"
            )
        };
        let mut stmt = self
            .conn
            .prepare(&query)
            .map_err(|error| error.to_string())?;
        let mut records = Vec::new();
        if let Some(session_id) = session_id {
            let rows = stmt
                .query_map(params![session_id], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| error.to_string())?;
            for row in rows {
                records.push(self.decrypt_json(&row.map_err(|error| error.to_string())?)?);
            }
        } else {
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| error.to_string())?;
            for row in rows {
                records.push(self.decrypt_json(&row.map_err(|error| error.to_string())?)?);
            }
        }
        Ok(records)
    }

    fn encrypt_json(&self, value: &impl Serialize) -> Result<Vec<u8>, String> {
        let plaintext = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|error| error.to_string())?;
        let mut payload = nonce_bytes.to_vec();
        payload.extend(ciphertext);
        Ok(payload)
    }

    fn decrypt_json<T: DeserializeOwned>(&self, payload: &[u8]) -> Result<T, String> {
        if payload.len() < 12 {
            return Err("encrypted brain payload is truncated".to_string());
        }
        let (nonce_bytes, ciphertext) = payload.split_at(12);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|error| error.to_string())?;
        serde_json::from_slice(&plaintext).map_err(|error| error.to_string())
    }
}

#[cfg(test)]
fn isolated_brain_path_for_cloudfs(cloudfs: &CloudFS) -> PathBuf {
    cloudfs
        .cache_root()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cloudfs.cache_root().to_path_buf())
        .join("agent")
        .join("brain.sqlite3")
}

fn load_or_create_key(manager: &KeyManager) -> Result<[u8; 32], String> {
    let bytes = match manager.retrieve_key(BRAIN_KEY_ID, BRAIN_KEY_SERVICE) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            manager
                .store_key(BRAIN_KEY_ID, BRAIN_KEY_SERVICE, &bytes)
                .map_err(|store_error| store_error.to_string())?;
            bytes.to_vec()
        }
        Err(error) => return Err(error.to_string()),
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "agent brain key must be exactly 32 bytes".to_string())
}

fn summarize_goal(goal: &str) -> String {
    const LIMIT: usize = 120;
    if goal.chars().count() <= LIMIT {
        return goal.to_string();
    }
    goal.chars().take(LIMIT - 1).collect::<String>() + "…"
}

fn parse_status(raw: &str) -> SessionStatusV1 {
    match raw {
        "blocked" => SessionStatusV1::Blocked,
        "cancelled" => SessionStatusV1::Cancelled,
        "completed" => SessionStatusV1::Completed,
        _ => SessionStatusV1::Planned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::tempdir;
    use zkf_command_surface::RiskClassV1;
    use zkf_wallet::{ApprovalMethod, ApprovalToken, SubmissionGrant, WalletNetwork};

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe {
                    std::env::set_var(self.key, value);
                },
                None => unsafe {
                    std::env::remove_var(self.key);
                },
            }
        }
    }

    #[test]
    fn open_with_cloudfs_does_not_touch_live_brain_path() {
        let temp = tempdir().expect("tempdir");
        let _ziros_home = EnvVarGuard::set_path("ZIROS_HOME", &temp.path().join("ziros-home"));
        let live_brain = brain_path();
        assert!(
            !live_brain.exists(),
            "fresh test should not have a live brain db"
        );

        let persistent_root = temp.path().join("persistent");
        let cache_root = temp.path().join("cache");
        let isolated_brain = temp.path().join("agent").join("brain.sqlite3");
        let cloudfs = CloudFS::from_roots(persistent_root.clone(), cache_root.clone(), false);
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        brain
            .register_project("demo", "/tmp/demo")
            .expect("register");

        assert!(
            !live_brain.exists(),
            "open_with_cloudfs must not write to the live brain path: {}",
            live_brain.display()
        );
        assert!(
            isolated_brain.exists(),
            "open_with_cloudfs should keep its sqlite db under the supplied temp roots: {}",
            isolated_brain.display()
        );

        let reopened =
            BrainStore::open_with_cloudfs(CloudFS::from_roots(persistent_root, cache_root, false))
                .expect("reopen brain");
        assert_eq!(reopened.list_projects().expect("list projects").len(), 1);
    }

    #[test]
    fn brain_store_roundtrips_projects_and_receipts() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        let project = brain
            .register_project("demo", "/tmp/demo")
            .expect("register");
        assert_eq!(project.name, "demo");
        let session = brain
            .create_session(
                "prove something",
                "proof-app-build",
                SessionStatusV1::Planned,
                None,
            )
            .expect("session");
        let receipt = brain
            .append_receipt(
                &brain
                    .new_receipt(
                        &session.session_id,
                        "planner",
                        "planned",
                        &json!({ "ok": true }),
                    )
                    .expect("new receipt"),
            )
            .expect("receipt");
        assert_eq!(receipt.status, "planned");
        let artifact = brain
            .register_artifact(
                Some(&session.session_id),
                ArtifactRefV1 {
                    label: "proof".to_string(),
                    path: "/tmp/proof.json".to_string(),
                    kind: Some("proof".to_string()),
                },
            )
            .expect("artifact");
        assert_eq!(artifact.artifact.label, "proof");
        let procedure = brain
            .store_procedure(&ProcedureRecordV1 {
                schema: "ziros-agent-procedure-v1".to_string(),
                procedure_id: new_operation_id("procedure"),
                created_at: now_rfc3339(),
                workflow_kind: "proof-app-build".to_string(),
                summary: "prove something".to_string(),
                action_names: vec!["planner".to_string()],
            })
            .expect("procedure");
        assert_eq!(procedure.workflow_kind, "proof-app-build");
        let incident = brain
            .store_incident(&IncidentRecordV1 {
                schema: "ziros-agent-incident-v1".to_string(),
                incident_id: new_operation_id("incident"),
                created_at: now_rfc3339(),
                session_id: Some(session.session_id.clone()),
                action_name: "planner".to_string(),
                error_class: zkf_command_surface::CommandErrorClassV1::Unknown,
                summary: "test incident".to_string(),
                details: json!({ "ok": false }),
            })
            .expect("incident");
        assert_eq!(incident.action_name, "planner");
        let approval_request = brain
            .store_approval_request(&ApprovalRequestRecordV1 {
                schema: "ziros-agent-approval-request-v1".to_string(),
                approval_request_id: new_operation_id("approval-request"),
                session_id: Some(session.session_id.clone()),
                created_at: now_rfc3339(),
                pending_id: "node-wallet-approval".to_string(),
                risk_class: RiskClassV1::WalletSignOrSubmit,
                action_name: "wallet.pending.approve".to_string(),
                node_id: Some("node-wallet-approval".to_string()),
                wallet_pending_id: Some("wallet-pending-1".to_string()),
            })
            .expect("approval request");
        let token = brain
            .store_approval_token(&ApprovalTokenRecordV1 {
                schema: "ziros-agent-approval-token-v1".to_string(),
                token_id: new_operation_id("approval-token"),
                session_id: Some(session.session_id.clone()),
                created_at: now_rfc3339(),
                pending_id: "wallet-pending-1".to_string(),
                token: ApprovalToken {
                    token_id: "token-1".to_string(),
                    pending_id: "wallet-pending-1".to_string(),
                    origin: "native://wallet".to_string(),
                    network: WalletNetwork::Preprod,
                    method: ApprovalMethod::Submit,
                    tx_digest: "0xabc123".to_string(),
                    issued_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now(),
                },
                approval_request_id: Some(approval_request.approval_request_id.clone()),
                node_id: approval_request.node_id.clone(),
                bridge_session_id: None,
            })
            .expect("approval token");
        let submission_grant = brain
            .store_submission_grant(&SubmissionGrantRecordV1 {
                schema: "ziros-agent-submission-grant-v1".to_string(),
                grant_id: new_operation_id("submission-grant"),
                session_id: Some(session.session_id.clone()),
                created_at: now_rfc3339(),
                approval_request_id: Some(approval_request.approval_request_id.clone()),
                token_id: Some(token.token.token_id.clone()),
                summary: serde_json::to_value(SubmissionGrant {
                    grant_id: "grant-1".to_string(),
                    token_id: "token-1".to_string(),
                    origin: "native://wallet".to_string(),
                    network: WalletNetwork::Preprod,
                    method: ApprovalMethod::Submit,
                    tx_digest: "0xabc123".to_string(),
                    issued_at: chrono::Utc::now(),
                    expires_at: chrono::Utc::now(),
                })
                .expect("grant value"),
            })
            .expect("submission grant");
        assert_eq!(submission_grant.token_id.as_deref(), Some("token-1"));
        assert_eq!(
            brain
                .list_artifacts(Some(&session.session_id))
                .expect("list artifacts")
                .len(),
            1
        );
        let worktree = brain
            .register_worktree(&WorktreeRecordV1 {
                schema: "ziros-agent-worktree-v1".to_string(),
                worktree_id: new_operation_id("worktree"),
                session_id: Some(session.session_id.clone()),
                created_at: now_rfc3339(),
                repo_root: temp.path().display().to_string(),
                worktree_root: temp.path().join("wt").display().to_string(),
                project_root: Some(temp.path().join("wt/project").display().to_string()),
                branch_name: "detached@test".to_string(),
                head_commit: "abc123".to_string(),
                managed: true,
                note: None,
            })
            .expect("worktree");
        assert_eq!(worktree.branch_name, "detached@test");
        let checkpoint = brain
            .store_checkpoint(&CheckpointRecordV1 {
                schema: "ziros-agent-checkpoint-v1".to_string(),
                checkpoint_id: new_operation_id("checkpoint"),
                session_id: session.session_id.clone(),
                created_at: now_rfc3339(),
                label: "planned".to_string(),
                session_status: SessionStatusV1::Planned,
                worktree_id: Some(worktree.worktree_id.clone()),
                worktree_root: Some(worktree.worktree_root.clone()),
                head_commit: Some("abc123".to_string()),
                latest_receipt_id: Some(receipt.receipt_id.clone()),
                workgraph: WorkgraphV1 {
                    schema: "ziros-workgraph-v1".to_string(),
                    workgraph_id: new_operation_id("workgraph"),
                    session_id: Some(session.session_id.clone()),
                    workflow_kind: "proof-app-build".to_string(),
                    status: "planned".to_string(),
                    goal: "prove something".to_string(),
                    intent: crate::types::GoalIntentV1 {
                        summary: "prove something".to_string(),
                        workflow_kind: "proof-app-build".to_string(),
                        scope: crate::types::IntentScopeV1::Project,
                        requested_outputs: vec!["proof.json".to_string()],
                        hints: None,
                    },
                    execution_policy: crate::types::ExecutionPolicyV1 {
                        strict: true,
                        compat_allowed: false,
                        stop_on_first_failure: true,
                        require_explicit_approval_for_high_risk: true,
                        operator_profile: crate::types::OperatorProfileV1::HermesRigorous,
                        structured_command_first: true,
                        postflight_required: true,
                    },
                    capability_requirements: Vec::new(),
                    blocked_prerequisites: Vec::new(),
                    nodes: Vec::new(),
                },
            })
            .expect("checkpoint");
        assert_eq!(checkpoint.label, "planned");
        let route = brain
            .store_provider_route(&ProviderRouteRecordV1 {
                schema: "ziros-agent-provider-route-v1".to_string(),
                route_id: new_operation_id("provider-route"),
                session_id: Some(session.session_id.clone()),
                created_at: now_rfc3339(),
                role: "planner".to_string(),
                provider: "embedded-zkf-planner".to_string(),
                locality: "in-process".to_string(),
                ready: true,
                summary: json!({"mode": "local-first"}),
            })
            .expect("provider route");
        assert_eq!(route.provider, "embedded-zkf-planner");
        assert_eq!(
            brain
                .list_worktrees(Some(&session.session_id))
                .expect("list worktrees")
                .len(),
            1
        );
        assert_eq!(
            brain
                .list_checkpoints(&session.session_id)
                .expect("list checkpoints")
                .len(),
            1
        );
        assert_eq!(
            brain
                .list_provider_routes(Some(&session.session_id))
                .expect("list provider routes")
                .len(),
            1
        );
        assert_eq!(
            brain
                .list_approval_requests(Some(&session.session_id))
                .expect("list approval requests")
                .len(),
            1
        );
        assert_eq!(
            brain
                .list_approval_tokens(Some(&session.session_id))
                .expect("list approval tokens")
                .len(),
            1
        );
        assert_eq!(
            brain
                .list_submission_grants(Some(&session.session_id))
                .expect("list submission grants")
                .len(),
            1
        );
    }
}
