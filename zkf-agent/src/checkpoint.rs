use crate::brain::BrainStore;
use crate::types::{AgentSessionViewV1, CheckpointRecordV1, WorkgraphV1};
use std::path::Path;
use std::process::Command;
use zkf_command_surface::{new_operation_id, now_rfc3339};

pub fn create_checkpoint_record(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
    workgraph: &WorkgraphV1,
    label: &str,
    latest_receipt_id: Option<String>,
) -> Result<CheckpointRecordV1, String> {
    let worktree = brain.list_worktrees(Some(&session.session_id))?.into_iter().last();
    let (worktree_id, worktree_root, head_commit) = if let Some(record) = worktree {
        let head_commit = git_capture(Path::new(&record.worktree_root), &["rev-parse", "HEAD"]).ok();
        (
            Some(record.worktree_id),
            Some(record.worktree_root),
            head_commit,
        )
    } else {
        (None, None, None)
    };
    Ok(CheckpointRecordV1 {
        schema: "ziros-agent-checkpoint-v1".to_string(),
        checkpoint_id: new_operation_id("checkpoint"),
        session_id: session.session_id.clone(),
        created_at: now_rfc3339(),
        label: label.to_string(),
        session_status: session.status,
        worktree_id,
        worktree_root,
        head_commit,
        latest_receipt_id,
        workgraph: workgraph.clone(),
    })
}

pub fn rollback_to_checkpoint_record(
    brain: &BrainStore,
    checkpoint: &CheckpointRecordV1,
) -> Result<(), String> {
    if let (Some(worktree_root), Some(head_commit)) =
        (checkpoint.worktree_root.as_deref(), checkpoint.head_commit.as_deref())
    {
        git(Path::new(worktree_root), &["reset", "--hard", head_commit])?;
    }
    brain.update_session_status(&checkpoint.session_id, checkpoint.session_status)?;
    brain.update_workgraph(&checkpoint.workgraph)?;
    brain.append_receipt(&brain.new_receipt(
        &checkpoint.session_id,
        "checkpoint.rollback",
        "completed",
        checkpoint,
    )?)?;
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run git {}: {error}", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "git {} failed in {}: {}",
        args.join(" "),
        root.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn git_capture(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
