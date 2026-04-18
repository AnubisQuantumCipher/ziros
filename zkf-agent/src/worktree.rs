use crate::brain::BrainStore;
use crate::types::WorktreeRecordV1;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkf_command_surface::shell::workspace_root;
use zkf_command_surface::{new_operation_id, now_rfc3339};

pub fn create_session_worktree(
    brain: &BrainStore,
    session_id: &str,
    workflow_kind: &str,
    goal: &str,
    project_root: Option<&Path>,
) -> Result<Option<(WorktreeRecordV1, Option<PathBuf>)>, String> {
    if !workflow_prefers_worktree(workflow_kind) {
        return Ok(None);
    }

    let repo_root = workspace_root().to_path_buf();
    if let Some(project_root) = project_root
        && project_root.is_absolute()
        && !project_root.starts_with(&repo_root)
    {
        return Ok(None);
    }

    let worktree_root = brain.cache_root().join("worktrees").join(session_id);
    if !worktree_root.exists() {
        if let Some(parent) = worktree_root.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
        }
        git(
            &repo_root,
            &[
                "worktree",
                "add",
                "--detach",
                worktree_root.to_str().unwrap(),
                "HEAD",
            ],
        )?;
    }

    let project_root = project_root
        .map(|root| remap_project_root(root, &repo_root, &worktree_root))
        .transpose()?
        .or_else(|| Some(default_project_root(&worktree_root, workflow_kind, goal)));
    let head_commit = git_capture(&worktree_root, &["rev-parse", "HEAD"])?;
    let record = WorktreeRecordV1 {
        schema: "ziros-agent-worktree-v1".to_string(),
        worktree_id: new_operation_id("worktree"),
        session_id: Some(session_id.to_string()),
        created_at: now_rfc3339(),
        repo_root: repo_root.display().to_string(),
        worktree_root: worktree_root.display().to_string(),
        project_root: project_root.as_ref().map(|path| path.display().to_string()),
        branch_name: format!("detached@{session_id}"),
        head_commit,
        managed: true,
        note: Some("daemon-managed worktree".to_string()),
    };
    Ok(Some((record, project_root)))
}

pub fn cleanup_worktree_record(
    record: &WorktreeRecordV1,
    remove_files: bool,
) -> Result<(), String> {
    let repo_root = PathBuf::from(&record.repo_root);
    let worktree_root = PathBuf::from(&record.worktree_root);
    if worktree_root.exists() {
        let _ = git(
            &repo_root,
            &[
                "worktree",
                "remove",
                "--force",
                worktree_root.to_str().unwrap(),
            ],
        );
        if remove_files && worktree_root.exists() {
            fs::remove_dir_all(&worktree_root).map_err(|error| {
                format!("failed to remove {}: {error}", worktree_root.display())
            })?;
        }
    }
    Ok(())
}

fn workflow_prefers_worktree(workflow_kind: &str) -> bool {
    matches!(
        workflow_kind,
        "proof-app-build"
            | "midnight-contract-ops"
            | "subsystem-scaffold"
            | "subsystem-modify"
            | "subsystem-proof"
            | "subsystem-midnight-ops"
            | "subsystem-benchmark"
            | "subsystem-evidence-release"
            | "evidence-bundle"
    )
}

fn remap_project_root(
    project_root: &Path,
    repo_root: &Path,
    worktree_root: &Path,
) -> Result<PathBuf, String> {
    if project_root.is_absolute() {
        let relative = project_root.strip_prefix(repo_root).map_err(|_| {
            format!(
                "cannot map project root '{}' into managed worktree '{}'",
                project_root.display(),
                repo_root.display()
            )
        })?;
        Ok(worktree_root.join(relative))
    } else {
        Ok(worktree_root.join(project_root))
    }
}

fn default_project_root(worktree_root: &Path, workflow_kind: &str, goal: &str) -> PathBuf {
    let prefix = match workflow_kind {
        "proof-app-build" => "proof-app",
        "midnight-contract-ops" | "subsystem-midnight-ops" => "midnight",
        "subsystem-scaffold" | "subsystem-modify" | "subsystem-proof" => "subsystem",
        "subsystem-benchmark" => "subsystem-benchmark",
        "subsystem-evidence-release" => "subsystem-release",
        _ => "project",
    };
    worktree_root.join(format!("{prefix}-{}", slugify(goal)))
}

fn slugify(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .split('-')
        .filter(|segment| !segment.is_empty())
        .take(6)
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        "session".to_string()
    } else {
        slug
    }
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
