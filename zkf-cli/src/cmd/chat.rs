use serde_json::Value;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use zkf_agent::{
    AgentRunOptionsV1, agent_status, approval_lineage, list_projects, list_procedures,
    load_provider_profile_store, provider_status, run_goal, session_deployments, workflow_list,
};

#[derive(Debug, Clone)]
pub(crate) struct ChatCommand {
    pub(crate) project_root: Option<PathBuf>,
    pub(crate) provider: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) strict: bool,
    pub(crate) compat_allowed: bool,
}

impl Default for ChatCommand {
    fn default() -> Self {
        Self {
            project_root: None,
            provider: None,
            model: None,
            strict: true,
            compat_allowed: false,
        }
    }
}

pub(crate) fn handle_chat(command: ChatCommand) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("ziros chat requires an interactive terminal".to_string());
    }

    let provider_override = command
        .provider
        .clone()
        .or_else(|| load_provider_profile_store().ok().and_then(|store| store.default_profile));
    print_banner(&command, provider_override.as_deref())?;

    loop {
        print!("ziros> ");
        io::stdout().flush().map_err(|error| error.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|error| error.to_string())?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "/exit" | "/quit") {
            break;
        }
        if trimmed.starts_with('/') {
            handle_slash_command(trimmed, &command)?;
            continue;
        }

        let report = run_goal(
            trimmed,
            AgentRunOptionsV1 {
                strict: command.strict,
                compat_allowed: command.compat_allowed,
                project_root: command.project_root.clone(),
                provider_override: provider_override.clone(),
                model_override: command.model.clone(),
                ..AgentRunOptionsV1::default()
            },
        )?;
        println!(
            "session {} [{}] workflow={}",
            report.session.session_id, report.session.status.as_str(), report.session.workflow_kind
        );
        println!("goal: {}", report.session.goal_summary);
        if report.trust_gate.blocked {
            println!("trust gate: blocked");
        } else {
            println!("trust gate: ready");
        }
        println!("receipts: {}", report.receipts.len());
        if let Some(project_root) = report.session.project_root.as_deref() {
            println!("project: {project_root}");
        }
        println!(
            "artifacts/approvals: use `/projects`, `/approvals`, or `ziros agent memory ...` for details"
        );
    }

    Ok(())
}

fn print_banner(command: &ChatCommand, provider_override: Option<&str>) -> Result<(), String> {
    println!("ZirOS {}  midnight-first operator shell", env!("CARGO_PKG_VERSION"));
    println!("Toolsets: subsystem  midnight  evm  wallet  release  memory  worktree  checkpoint");
    println!("Slash: /help  /doctor  /models  /recipes  /projects  /memory  /approvals  /deployments  /update  /exit");

    let routes = provider_status(None)?;
    if let Some(route) = routes.routes.iter().find(|route| {
        route.role == "assistant"
            && provider_override.is_none_or(|selected| {
                selected == route.provider
                    || route
                        .summary
                        .get("profile_id")
                        .and_then(Value::as_str)
                        .is_some_and(|profile| profile == selected)
            })
    }) {
        let model = route.summary.get("model").and_then(Value::as_str).unwrap_or("embedded");
        let profile = route
            .summary
            .get("profile_id")
            .and_then(Value::as_str)
            .unwrap_or(route.provider.as_str());
        println!("Provider: {profile} [{}] model={model}", route.provider);
    } else {
        println!("Provider: embedded/local-only");
    }

    let repo_root = command
        .project_root
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Some(midnight) = read_midnight_readiness(&repo_root) {
        let status = midnight
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let live_submit = midnight
            .get("ready_for_live_submit")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        println!(
            "Midnight: {status} ({})",
            if live_submit {
                "live-submit-ready"
            } else {
                "local-only"
            }
        );
    }

    println!("Workspace: {}", repo_root.display());
    Ok(())
}

fn handle_slash_command(input: &str, command: &ChatCommand) -> Result<(), String> {
    match input {
        "/help" => {
            println!("Enter a normal goal to run the agent.");
            println!("Slash commands: /doctor /models /recipes /projects /memory /approvals /deployments /update /exit");
        }
        "/doctor" => {
            print_jsonish(&serde_json::json!({
                "agent": agent_status(5)?,
                "providers": provider_status(None)?,
            }))?;
        }
        "/models" => {
            print_jsonish(&load_provider_profile_store()?)?;
        }
        "/recipes" => {
            print_jsonish(&workflow_list()?)?;
        }
        "/projects" => {
            print_jsonish(&list_projects()?)?;
        }
        "/memory" => {
            print_jsonish(&list_procedures()?)?;
        }
        "/approvals" => {
            print_jsonish(&approval_lineage(None)?)?;
        }
        "/deployments" => {
            print_jsonish(&session_deployments(None)?)?;
        }
        "/update" => {
            crate::cmd::update::handle_update(Some(crate::cli::UpdateCommands::Status {
                json: false,
                manifest_url: None,
            }))?;
        }
        "/toolsets" => {
            println!("subsystem  midnight  evm  wallet  release  memory  worktree  checkpoint");
        }
        other => {
            println!("unknown shell command: {other}");
        }
    }
    if let Some(root) = command.project_root.as_deref() {
        println!("project binding: {}", root.display());
    }
    Ok(())
}

fn read_midnight_readiness(repo_root: &PathBuf) -> Option<Value> {
    let path = repo_root.join("release").join("midnight_operator_readiness.json");
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn print_jsonish(value: &impl serde::Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}
