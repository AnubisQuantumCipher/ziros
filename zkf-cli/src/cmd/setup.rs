use serde::Serialize;
use std::fs;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use zkf_agent::{
    AgentStateLayoutReportV1, ProviderKindV1, ProviderProfileV1, ProviderRoleBindingV1,
    ensure_ziros_layout, load_provider_profile_store, openai_credential_ref,
    store_openai_api_key, upsert_provider_profile, ziros_config_path,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct SetupCommand {
    pub(crate) json: bool,
    pub(crate) non_interactive: bool,
    pub(crate) provider: Option<String>,
    pub(crate) profile: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) project: Option<String>,
    pub(crate) organization: Option<String>,
    pub(crate) api_key_stdin: bool,
    pub(crate) set_default: bool,
    pub(crate) start_daemon: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SetupConfigV1 {
    schema: String,
    version: String,
    persona: String,
    install_channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_project: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SetupCheckV1 {
    name: String,
    ok: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct SetupReportV1 {
    schema: String,
    version: String,
    layout: AgentStateLayoutReportV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    configured_profile: Option<String>,
    checks: Vec<SetupCheckV1>,
    daemon_started: bool,
    next_steps: Vec<String>,
}

pub(crate) fn setup_is_complete() -> bool {
    ziros_config_path().exists()
}

pub(crate) fn handle_setup(command: SetupCommand) -> Result<(), String> {
    let layout = ensure_ziros_layout()?;
    let mut configured_profile = None;

    if !ziros_config_path().exists() {
        save_setup_config(&SetupConfigV1 {
            schema: "ziros-setup-config-v1".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            persona: "midnight-developer".to_string(),
            install_channel: "stable".to_string(),
            default_project: command.project.clone(),
        })?;
    }

    let provider_kind = if command.non_interactive {
        command.provider.clone()
    } else {
        command
            .provider
            .clone()
            .or_else(prompt_provider_choice)
    };

    if let Some(provider) = provider_kind {
        let profile_id = configure_provider_profile(&command, &provider)?;
        configured_profile = Some(profile_id);
    }

    let checks = run_setup_checks()?;
    let daemon_started = if command.start_daemon {
        start_daemon()?
    } else {
        false
    };
    let report = SetupReportV1 {
        schema: "ziros-setup-report-v1".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        layout,
        configured_profile,
        checks,
        daemon_started,
        next_steps: vec![
            "ziros".to_string(),
            "ziros chat".to_string(),
            "ziros model list".to_string(),
            "ziros gateway serve".to_string(),
        ],
    };

    if command.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!("ZirOS setup complete");
        println!("home: {}", report.layout.ziros_home);
        println!("agent: {}", report.layout.agent_root);
        if let Some(profile) = report.configured_profile.as_deref() {
            println!("provider profile: {profile}");
        }
        for check in &report.checks {
            println!(
                "[{}] {}: {}",
                if check.ok { "ok" } else { "warn" },
                check.name,
                check.detail
            );
        }
        if report.daemon_started {
            println!("daemon: started");
        }
        println!("next:");
        for step in &report.next_steps {
            println!("  - {step}");
        }
    }

    Ok(())
}

fn save_setup_config(config: &SetupConfigV1) -> Result<(), String> {
    let body = toml::to_string_pretty(config).map_err(|error| error.to_string())?;
    fs::write(ziros_config_path(), body).map_err(|error| {
        format!(
            "failed to write {}: {error}",
            ziros_config_path().display()
        )
    })
}

fn configure_provider_profile(command: &SetupCommand, provider: &str) -> Result<String, String> {
    let provider_kind = parse_provider_kind(provider)?;
    let profile_id = command
        .profile
        .clone()
        .unwrap_or_else(|| default_profile_id(&provider_kind));

    let role_models = ProviderRoleBindingV1::filled(
        command
            .model
            .clone()
            .or(if command.non_interactive {
                None
            } else {
                interactive_optional_value("Default model", None)?
            }),
    );

    let base_url = if let Some(base_url) = command.base_url.clone() {
        Some(base_url)
    } else if command.non_interactive {
        provider_kind.default_base_url().map(str::to_string)
    } else {
        interactive_optional_value(
            "Base URL",
            provider_kind.default_base_url().map(str::to_string),
        )?
        .or_else(|| provider_kind.default_base_url().map(str::to_string))
    };

    let mut profile = ProviderProfileV1 {
        profile_id: profile_id.clone(),
        provider_kind: provider_kind.clone(),
        base_url,
        role_models,
        organization: command.organization.clone(),
        project: command.project.clone(),
        credential: None,
    };

    if matches!(provider_kind, ProviderKindV1::OpenaiApi) {
        profile.credential = Some(openai_credential_ref(&profile_id));
        if let Some(api_key) = resolve_openai_api_key(command)? {
            store_openai_api_key(&profile_id, &api_key)?;
        }
    }

    let _ = upsert_provider_profile(profile, command.set_default || !has_default_profile()?)?;
    Ok(profile_id)
}

fn resolve_openai_api_key(command: &SetupCommand) -> Result<Option<String>, String> {
    if command.api_key_stdin {
        return read_stdin_secret("OpenAI API key");
    }

    if command.non_interactive {
        return Ok(None);
    }

    interactive_optional_value("OpenAI API key (optional; stored in Keychain)", None)
}

fn run_setup_checks() -> Result<Vec<SetupCheckV1>, String> {
    let mut checks = Vec::new();
    for command in [
        vec!["doctor", "--json"],
        vec!["metal-doctor", "--json", "--strict"],
        vec!["agent", "--json", "doctor"],
        vec!["midnight", "doctor", "--json", "--network", "preprod"],
        vec!["evm", "diagnose", "--json"],
    ] {
        checks.push(run_single_check(&command)?);
    }
    Ok(checks)
}

fn run_single_check(args: &[&str]) -> Result<SetupCheckV1, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let output = Command::new(exe)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("failed to run '{}': {error}", args.join(" ")))?;
    let ok = output.status.success();
    let detail = if ok {
        "ok".to_string()
    } else {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    };
    Ok(SetupCheckV1 {
        name: args.join(" "),
        ok,
        detail,
    })
}

fn start_daemon() -> Result<bool, String> {
    let status = Command::new("ziros-agentd")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match status {
        Ok(_) => Ok(true),
        Err(error) => Err(format!("failed to start ziros-agentd: {error}")),
    }
}

fn parse_provider_kind(value: &str) -> Result<ProviderKindV1, String> {
    match value {
        "openai" | "openai-api" => Ok(ProviderKindV1::OpenaiApi),
        "mlx" | "mlx-local" => Ok(ProviderKindV1::MlxLocal),
        "openai-compatible" | "openai-compatible-local" => {
            Ok(ProviderKindV1::OpenaiCompatibleLocal)
        }
        "ollama" | "ollama-local" => Ok(ProviderKindV1::OllamaLocal),
        other => Err(format!(
            "unsupported provider '{other}' (expected openai, mlx, openai-compatible, or ollama)"
        )),
    }
}

fn default_profile_id(provider_kind: &ProviderKindV1) -> String {
    match provider_kind {
        ProviderKindV1::OpenaiApi => "openai-default".to_string(),
        ProviderKindV1::MlxLocal => "mlx-default".to_string(),
        ProviderKindV1::OpenaiCompatibleLocal => "openai-compatible-default".to_string(),
        ProviderKindV1::OllamaLocal => "ollama-default".to_string(),
    }
}

fn has_default_profile() -> Result<bool, String> {
    Ok(load_provider_profile_store()?.default_profile.is_some())
}

fn prompt_provider_choice() -> Option<String> {
    println!("Select a provider profile to configure:");
    println!("  1. openai");
    println!("  2. mlx");
    println!("  3. openai-compatible");
    println!("  4. ollama");
    println!("  5. skip");
    let choice = prompt("Provider", Some("openai")).ok()??;
    match choice.as_str() {
        "1" | "openai" => Some("openai".to_string()),
        "2" | "mlx" => Some("mlx".to_string()),
        "3" | "openai-compatible" => Some("openai-compatible".to_string()),
        "4" | "ollama" => Some("ollama".to_string()),
        _ => None,
    }
}

fn interactive_optional_value(
    label: &str,
    default: Option<String>,
) -> Result<Option<String>, String> {
    Ok(prompt(label, default.as_deref())?.filter(|value| !value.trim().is_empty()))
}

fn prompt(label: &str, default: Option<&str>) -> Result<Option<String>, String> {
    print!("{label}");
    if let Some(default) = default {
        print!(" [{default}]");
    }
    print!(": ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| error.to_string())?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        return Ok(default.map(str::to_string));
    }
    Ok(Some(trimmed))
}

fn read_stdin_secret(label: &str) -> Result<Option<String>, String> {
    eprint!("{label}: ");
    io::stderr().flush().map_err(|error| error.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| error.to_string())?;
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}
