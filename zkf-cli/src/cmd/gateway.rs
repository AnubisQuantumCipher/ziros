use actix_web::http::header::CONTENT_TYPE;
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use futures::stream;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_agent::{
    AgentRunOptionsV1, McpExposureV1, handle_mcp_jsonrpc_bytes, load_provider_profile_store,
    mcp_server_manifest, run_goal, ziros_home_root, ziros_logs_root, ziros_managed_bin_root,
    ensure_ziros_layout,
};

use crate::cli::GatewayCommands;

#[derive(Debug, Clone)]
struct GatewayState {
    project_root: Option<PathBuf>,
    provider: Option<String>,
    model: Option<String>,
    remote_mcp_exposure: McpExposureV1,
}

#[derive(Debug, Deserialize)]
struct GatewayChatRequest {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    messages: Vec<GatewayMessage>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct GatewayMessage {
    role: String,
    content: Value,
}

#[derive(Debug, Serialize)]
struct GatewayModelsResponse {
    object: &'static str,
    data: Vec<GatewayModel>,
}

#[derive(Debug, Serialize)]
struct GatewayModel {
    id: String,
    object: &'static str,
    created: u64,
    owned_by: &'static str,
}

#[derive(Debug, Serialize)]
struct GatewaySetupReportV1 {
    schema: String,
    bind: String,
    local_health_ok: bool,
    remote_health_ok: bool,
    gateway_launchd_label: String,
    tunnel_launchd_label: String,
    mcp_url: String,
    copied_to_clipboard: bool,
    opened_chatgpt: bool,
}

#[derive(Debug, Serialize)]
struct GatewayStatusReportV1 {
    schema: String,
    bind: String,
    configured: bool,
    local_health_ok: bool,
    remote_health_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<String>,
    gateway_running: bool,
    tunnel_running: bool,
}

#[derive(Debug, Serialize)]
struct GatewayLifecycleReportV1 {
    schema: String,
    action: String,
    bind: String,
    configured: bool,
    local_health_ok: bool,
    remote_health_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_url: Option<String>,
    gateway_running: bool,
    tunnel_running: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct GatewayConfigV1 {
    schema: String,
    bind: String,
}

const GATEWAY_LABEL: &str = "com.ziros.gateway";
const LOCALHOSTRUN_LABEL: &str = "com.ziros.chatgpt-localhostrun";
const DEFAULT_GATEWAY_BIND: &str = "127.0.0.1:8788";

pub(crate) fn handle_gateway(command: GatewayCommands) -> Result<(), String> {
    match command {
        GatewayCommands::Setup {
            bind,
            json,
            copy_url,
            open_chatgpt,
        } => setup_gateway(bind, json, copy_url, open_chatgpt),
        GatewayCommands::Install { bind, json } => install_gateway(bind, json),
        GatewayCommands::Start { json } => start_gateway(json),
        GatewayCommands::Stop { json } => stop_gateway(json),
        GatewayCommands::Restart { json } => restart_gateway(json),
        GatewayCommands::Status { json } => status_gateway(json),
        GatewayCommands::Serve {
            bind,
            project,
            provider,
            model,
            allow_remote_writes,
        } => serve_gateway(bind, project, provider, model, allow_remote_writes),
    }
}

fn setup_gateway(
    bind: String,
    json_output: bool,
    copy_url: bool,
    open_chatgpt: bool,
) -> Result<(), String> {
    install_or_restart_gateway(&bind)?;
    let mcp_url = wait_for_mcp_url()?;
    let remote_health_ok = remote_health(&mcp_url);
    let copied = if copy_url {
        Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(mcp_url.as_bytes())?;
                }
                child.wait()
            })
            .map(|status| status.success())
            .unwrap_or(false)
    } else {
        false
    };
    let opened = if open_chatgpt {
        Command::new("open")
            .arg("https://chatgpt.com/")
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    } else {
        false
    };
    let report = GatewaySetupReportV1 {
        schema: "ziros-gateway-setup-v1".to_string(),
        bind,
        local_health_ok: true,
        remote_health_ok,
        gateway_launchd_label: GATEWAY_LABEL.to_string(),
        tunnel_launchd_label: LOCALHOSTRUN_LABEL.to_string(),
        mcp_url,
        copied_to_clipboard: copied,
        opened_chatgpt: opened,
    };
    print_gateway_output(json_output, &report)
}

fn install_gateway(bind: String, json_output: bool) -> Result<(), String> {
    install_or_restart_gateway(&bind)?;
    let report = lifecycle_report("install", &bind)?;
    print_gateway_output(json_output, &report)
}

fn start_gateway(json_output: bool) -> Result<(), String> {
    let bind = configured_bind();
    ensure_gateway_installed()?;
    truncate_if_exists(&mcp_url_path())?;
    kickstart_launch_agent(&gateway_plist_path(), GATEWAY_LABEL)?;
    kickstart_launch_agent(&localhostrun_plist_path(), LOCALHOSTRUN_LABEL)?;
    wait_for_local_health(&bind)?;
    let _ = wait_for_mcp_url()?;
    let report = lifecycle_report("start", &bind)?;
    print_gateway_output(json_output, &report)
}

fn stop_gateway(json_output: bool) -> Result<(), String> {
    let bind = configured_bind();
    let _ = bootout_launch_agent(&localhostrun_plist_path());
    let _ = bootout_launch_agent(&gateway_plist_path());
    let report = lifecycle_report("stop", &bind)?;
    print_gateway_output(json_output, &report)
}

fn restart_gateway(json_output: bool) -> Result<(), String> {
    let bind = configured_bind();
    ensure_gateway_installed()?;
    truncate_if_exists(&mcp_url_path())?;
    restart_launch_agent(&gateway_plist_path(), GATEWAY_LABEL)?;
    restart_launch_agent(&localhostrun_plist_path(), LOCALHOSTRUN_LABEL)?;
    wait_for_local_health(&bind)?;
    let _ = wait_for_mcp_url()?;
    let report = lifecycle_report("restart", &bind)?;
    print_gateway_output(json_output, &report)
}

fn status_gateway(json_output: bool) -> Result<(), String> {
    let _ = ensure_ziros_layout()?;
    let bind = configured_bind();
    let mcp_url = read_mcp_url();
    let report = GatewayStatusReportV1 {
        schema: "ziros-gateway-status-v1".to_string(),
        bind: bind.clone(),
        configured: gateway_config_path().exists(),
        local_health_ok: local_health(&bind),
        remote_health_ok: mcp_url
            .as_deref()
            .map(remote_health)
            .unwrap_or(false),
        mcp_url,
        gateway_running: launch_agent_running(GATEWAY_LABEL),
        tunnel_running: launch_agent_running(LOCALHOSTRUN_LABEL),
    };
    print_gateway_output(json_output, &report)
}

fn serve_gateway(
    bind: String,
    project_root: Option<PathBuf>,
    provider: Option<String>,
    model: Option<String>,
    allow_remote_writes: bool,
) -> Result<(), String> {
    let state = web::Data::new(GatewayState {
        project_root,
        provider,
        model,
        remote_mcp_exposure: if allow_remote_writes {
            McpExposureV1::RemoteBridgeWrite
        } else {
            McpExposureV1::RemoteBridgeReadOnly
        },
    });
    println!("ZirOS gateway listening on http://{bind}");
    actix_web::rt::System::new().block_on(async move {
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .route("/health", web::get().to(gateway_health))
                .route("/mcp/health", web::get().to(gateway_health))
                .route("/mcp/manifest.json", web::get().to(gateway_mcp_manifest))
                .route("/mcp", web::post().to(gateway_mcp_jsonrpc))
                .route("/v1/models", web::get().to(gateway_models))
                .route("/v1/chat/completions", web::post().to(gateway_chat_completions))
                .route("/v1/responses", web::post().to(gateway_responses))
        })
        .bind(&bind)
        .map_err(|error| error.to_string())?
        .run()
        .await
        .map_err(|error| error.to_string())
    })
}

async fn gateway_health() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "ziros-gateway",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn gateway_mcp_manifest(state: web::Data<GatewayState>) -> impl Responder {
    HttpResponse::Ok().json(mcp_server_manifest(state.remote_mcp_exposure))
}

async fn gateway_mcp_jsonrpc(
    state: web::Data<GatewayState>,
    body: web::Bytes,
) -> impl Responder {
    match handle_mcp_jsonrpc_bytes(body.as_ref(), state.remote_mcp_exposure) {
        Ok(response) => HttpResponse::Ok()
            .insert_header((CONTENT_TYPE, "application/json"))
            .body(response),
        Err(error) => HttpResponse::BadRequest().json(json!({
            "error": {
                "type": "ziros_mcp_bridge_error",
                "message": error,
            }
        })),
    }
}

async fn gateway_models() -> impl Responder {
    let now = now_unix();
    let mut models = Vec::new();
    if let Ok(store) = load_provider_profile_store() {
        for profile in store.profiles {
            for model in [
                profile.role_models.planner,
                profile.role_models.chat,
                profile.role_models.summarizer,
                profile.role_models.retrieval,
            ]
            .into_iter()
            .flatten()
            {
                models.push(GatewayModel {
                    id: model,
                    object: "model",
                    created: now,
                    owned_by: "ziros",
                });
            }
        }
    }
    models.sort_by(|left, right| left.id.cmp(&right.id));
    models.dedup_by(|left, right| left.id == right.id);
    HttpResponse::Ok().json(GatewayModelsResponse {
        object: "list",
        data: models,
    })
}

async fn gateway_chat_completions(
    state: web::Data<GatewayState>,
    request: web::Json<GatewayChatRequest>,
) -> impl Responder {
    let goal = extract_goal(&request.messages).unwrap_or_else(|| "inspect current operator state".to_string());
    match run_gateway_goal(&state, request.model.clone(), project_root_from_metadata(&state, request.metadata.as_ref()), &goal) {
        Ok((content, model)) => {
            if request.stream {
                let stream_payload = format!(
                    "data: {}\n\ndata: [DONE]\n\n",
                    json!({
                        "id": format!("chatcmpl-{}", now_unix()),
                        "object": "chat.completion.chunk",
                        "created": now_unix(),
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": { "role": "assistant", "content": content },
                                "finish_reason": "stop"
                            }
                        ]
                    })
                );
                return HttpResponse::Ok()
                    .insert_header((CONTENT_TYPE, "text/event-stream"))
                    .streaming(stream::once(async move {
                        Ok::<_, actix_web::Error>(web::Bytes::from(stream_payload))
                    }));
            }
            HttpResponse::Ok().json(json!({
                "id": format!("chatcmpl-{}", now_unix()),
                "object": "chat.completion",
                "created": now_unix(),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": content,
                        },
                        "finish_reason": "stop"
                    }
                ]
            }))
        }
        Err(error) => HttpResponse::InternalServerError().json(json!({
            "error": {
                "type": "ziros_gateway_error",
                "message": error,
            }
        })),
    }
}

async fn gateway_responses(
    state: web::Data<GatewayState>,
    request: web::Json<GatewayChatRequest>,
) -> impl Responder {
    let goal = extract_goal(&request.messages).unwrap_or_else(|| "inspect current operator state".to_string());
    match run_gateway_goal(&state, request.model.clone(), project_root_from_metadata(&state, request.metadata.as_ref()), &goal) {
        Ok((content, model)) => HttpResponse::Ok().json(json!({
            "id": format!("resp-{}", now_unix()),
            "object": "response",
            "created_at": now_unix(),
            "model": model,
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": content,
                        }
                    ]
                }
            ]
        })),
        Err(error) => HttpResponse::InternalServerError().json(json!({
            "error": {
                "type": "ziros_gateway_error",
                "message": error,
            }
        })),
    }
}

fn run_gateway_goal(
    state: &GatewayState,
    requested_model: Option<String>,
    project_root: Option<PathBuf>,
    goal: &str,
) -> Result<(String, String), String> {
    let provider = state
        .provider
        .clone()
        .or_else(|| load_provider_profile_store().ok().and_then(|store| store.default_profile));
    let model = requested_model.or_else(|| state.model.clone());
    let report = run_goal(
        goal,
        AgentRunOptionsV1 {
            project_root,
            provider_override: provider,
            model_override: model.clone(),
            ..AgentRunOptionsV1::default()
        },
    )?;
    let summary = format!(
        "ZirOS completed goal '{}' as workflow '{}' in session {} with status {} and {} receipt(s).",
        report.session.goal_summary,
        report.session.workflow_kind,
        report.session.session_id,
        report.session.status.as_str(),
        report.receipts.len(),
    );
    Ok((summary, model.unwrap_or_else(|| "ziros-agent".to_string())))
}

fn extract_goal(messages: &[GatewayMessage]) -> Option<String> {
    messages
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .and_then(|message| text_from_content(&message.content))
}

fn text_from_content(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }
    content.as_array().map(|parts| {
        parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        part.get("content")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
            })
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn project_root_from_metadata(state: &GatewayState, metadata: Option<&Value>) -> Option<PathBuf> {
    metadata
        .and_then(|value| value.get("project_root"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| state.project_root.clone())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn print_gateway_output(json_output: bool, value: &impl Serialize) -> Result<(), String> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
        );
    }
    Ok(())
}

fn install_or_restart_gateway(bind: &str) -> Result<(), String> {
    let _ = ensure_ziros_layout()?;
    let current_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let wrapper_path = write_localhostrun_wrapper(bind)?;
    write_gateway_config(bind)?;
    write_gateway_plist(&current_exe, bind)?;
    write_localhostrun_plist(&wrapper_path)?;
    truncate_if_exists(&gateway_stdout_path())?;
    truncate_if_exists(&gateway_stderr_path())?;
    truncate_if_exists(&localhostrun_stdout_path())?;
    truncate_if_exists(&localhostrun_stderr_path())?;
    truncate_if_exists(&mcp_url_path())?;
    restart_launch_agent(&gateway_plist_path(), GATEWAY_LABEL)?;
    restart_launch_agent(&localhostrun_plist_path(), LOCALHOSTRUN_LABEL)?;
    wait_for_local_health(bind)?;
    Ok(())
}

fn lifecycle_report(action: &str, bind: &str) -> Result<GatewayLifecycleReportV1, String> {
    let mcp_url = read_mcp_url();
    Ok(GatewayLifecycleReportV1 {
        schema: "ziros-gateway-lifecycle-v1".to_string(),
        action: action.to_string(),
        bind: bind.to_string(),
        configured: gateway_config_path().exists(),
        local_health_ok: local_health(bind),
        remote_health_ok: mcp_url.as_deref().map(remote_health).unwrap_or(false),
        mcp_url,
        gateway_running: launch_agent_running(GATEWAY_LABEL),
        tunnel_running: launch_agent_running(LOCALHOSTRUN_LABEL),
    })
}

fn ensure_gateway_installed() -> Result<(), String> {
    if gateway_plist_path().exists() && localhostrun_plist_path().exists() {
        return Ok(());
    }
    Err("gateway is not installed; run `ziros gateway setup` first".to_string())
}

fn gateway_plist_path() -> PathBuf {
    home_dir()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{GATEWAY_LABEL}.plist"))
}

fn localhostrun_plist_path() -> PathBuf {
    home_dir()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LOCALHOSTRUN_LABEL}.plist"))
}

fn chatgpt_bridge_root() -> PathBuf {
    ziros_home_root().join("chatgpt-bridge")
}

fn gateway_config_path() -> PathBuf {
    chatgpt_bridge_root().join("gateway-config.json")
}

fn mcp_url_path() -> PathBuf {
    chatgpt_bridge_root().join("mcp-url.txt")
}

fn localhostrun_wrapper_path() -> PathBuf {
    ziros_managed_bin_root().join("ziros-chatgpt-localhostrun")
}

fn gateway_stdout_path() -> PathBuf {
    ziros_logs_root().join("launchd-gateway.stdout.log")
}

fn gateway_stderr_path() -> PathBuf {
    ziros_logs_root().join("launchd-gateway.stderr.log")
}

fn localhostrun_stdout_path() -> PathBuf {
    ziros_logs_root().join("chatgpt-localhostrun.stdout.log")
}

fn localhostrun_stderr_path() -> PathBuf {
    ziros_logs_root().join("chatgpt-localhostrun.stderr.log")
}

fn write_gateway_plist(current_exe: &std::path::Path, bind: &str) -> Result<(), String> {
    if let Some(parent) = gateway_plist_path().parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>gateway</string>
    <string>serve</string>
    <string>--bind</string>
    <string>{bind}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>{home}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>{home}</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:{bin_root}:{local_bin}:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
        label = GATEWAY_LABEL,
        exe = xml_escape(&current_exe.display().to_string()),
        bind = xml_escape(bind),
        home = xml_escape(&home_dir().display().to_string()),
        bin_root = xml_escape(&ziros_managed_bin_root().display().to_string()),
        local_bin = xml_escape(&home_dir().join(".local/bin").display().to_string()),
        stdout = xml_escape(&gateway_stdout_path().display().to_string()),
        stderr = xml_escape(&gateway_stderr_path().display().to_string()),
    );
    fs::write(gateway_plist_path(), body).map_err(|error| error.to_string())
}

fn write_localhostrun_plist(wrapper_path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = localhostrun_plist_path().parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/zsh</string>
    <string>{wrapper}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>{home}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>{home}</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:{bin_root}:{local_bin}:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{stdout}</string>
  <key>StandardErrorPath</key>
  <string>{stderr}</string>
</dict>
</plist>
"#,
        label = LOCALHOSTRUN_LABEL,
        wrapper = xml_escape(&wrapper_path.display().to_string()),
        home = xml_escape(&home_dir().display().to_string()),
        bin_root = xml_escape(&ziros_managed_bin_root().display().to_string()),
        local_bin = xml_escape(&home_dir().join(".local/bin").display().to_string()),
        stdout = xml_escape(&localhostrun_stdout_path().display().to_string()),
        stderr = xml_escape(&localhostrun_stderr_path().display().to_string()),
    );
    fs::write(localhostrun_plist_path(), body).map_err(|error| error.to_string())
}

fn write_localhostrun_wrapper(bind: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(ziros_managed_bin_root()).map_err(|error| error.to_string())?;
    fs::create_dir_all(chatgpt_bridge_root()).map_err(|error| error.to_string())?;
    let body = format!(
        r#"#!/bin/zsh
set -euo pipefail

bridge_dir="{bridge_dir}"
mkdir -p "$bridge_dir"
url_file="{url_file}"

/usr/bin/ssh \
  -o StrictHostKeyChecking=no \
  -o ServerAliveInterval=30 \
  -R 80:{bind} \
  nokey@localhost.run 2>&1 | while IFS= read -r line; do
  printf '%s\n' "$line"
  if [[ "$line" =~ https://[^[:space:]]+\\.lhr\\.life ]]; then
    match="$MATCH"
    printf '%s/mcp\n' "${{match%/}}" > "$url_file"
  fi
done
"#,
        bridge_dir = chatgpt_bridge_root().display(),
        url_file = mcp_url_path().display(),
        bind = bind,
    );
    fs::write(localhostrun_wrapper_path(), body).map_err(|error| error.to_string())?;
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(localhostrun_wrapper_path())
            .map_err(|error| error.to_string())?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(localhostrun_wrapper_path(), permissions)
            .map_err(|error| error.to_string())?;
    }
    Ok(localhostrun_wrapper_path())
}

fn write_gateway_config(bind: &str) -> Result<(), String> {
    fs::create_dir_all(chatgpt_bridge_root()).map_err(|error| error.to_string())?;
    let config = GatewayConfigV1 {
        schema: "ziros-gateway-config-v1".to_string(),
        bind: bind.to_string(),
    };
    let data = serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?;
    fs::write(gateway_config_path(), data).map_err(|error| error.to_string())
}

fn read_gateway_config() -> Option<GatewayConfigV1> {
    fs::read(gateway_config_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<GatewayConfigV1>(&bytes).ok())
}

fn configured_bind() -> String {
    read_gateway_config()
        .map(|config| config.bind)
        .filter(|bind| !bind.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GATEWAY_BIND.to_string())
}

fn restart_launch_agent(plist_path: &std::path::Path, label: &str) -> Result<(), String> {
    let domain = format!("gui/{}", current_uid()?);
    let _ = bootout_launch_agent(plist_path);
    let bootstrap = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(plist_path)
        .status()
        .map_err(|error| error.to_string())?;
    if !bootstrap.success() {
        return Err(format!(
            "launchctl bootstrap failed for {}",
            plist_path.display()
        ));
    }
    let kickstart = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("{domain}/{label}")])
        .status()
        .map_err(|error| error.to_string())?;
    if !kickstart.success() {
        return Err(format!("launchctl kickstart failed for {label}"));
    }
    Ok(())
}

fn kickstart_launch_agent(plist_path: &std::path::Path, label: &str) -> Result<(), String> {
    let domain = format!("gui/{}", current_uid()?);
    if !plist_path.exists() {
        return Err(format!(
            "launch agent plist is missing: {}",
            plist_path.display()
        ));
    }
    let kickstart = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("{domain}/{label}")])
        .status()
        .map_err(|error| error.to_string())?;
    if kickstart.success() {
        return Ok(());
    }
    let bootstrap = Command::new("launchctl")
        .args(["bootstrap", &domain])
        .arg(plist_path)
        .status()
        .map_err(|error| error.to_string())?;
    if !bootstrap.success() {
        return Err(format!("launchctl bootstrap failed for {}", plist_path.display()));
    }
    let kickstart = Command::new("launchctl")
        .args(["kickstart", "-k", &format!("{domain}/{label}")])
        .status()
        .map_err(|error| error.to_string())?;
    if !kickstart.success() {
        return Err(format!("launchctl kickstart failed for {label}"));
    }
    Ok(())
}

fn bootout_launch_agent(plist_path: &std::path::Path) -> Result<(), String> {
    let domain = format!("gui/{}", current_uid()?);
    Command::new("launchctl")
        .args(["bootout", &domain])
        .arg(plist_path)
        .status()
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn wait_for_local_health(bind: &str) -> Result<(), String> {
    let url = format!("http://{bind}/health");
    for _ in 0..30 {
        if local_health(bind) {
            return Ok(());
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(format!("gateway did not become healthy at {url}"))
}

fn wait_for_mcp_url() -> Result<String, String> {
    for _ in 0..45 {
        if let Some(url) = read_mcp_url() {
            if remote_health(&url) {
                return Ok(url);
            }
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
    Err("failed to discover a live public MCP URL".to_string())
}

fn read_mcp_url() -> Option<String> {
    fs::read_to_string(mcp_url_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn local_health(bind: &str) -> bool {
    let url = format!("http://{bind}/health");
    Command::new("curl")
        .args(["-sf", "-o", "/dev/null", &url])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn remote_health(mcp_url: &str) -> bool {
    let health = if let Some(prefix) = mcp_url.strip_suffix("/mcp") {
        format!("{prefix}/health")
    } else {
        format!("{}/health", mcp_url.trim_end_matches('/'))
    };
    Command::new("curl")
        .args(["-sf", "-o", "/dev/null", &health])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn launch_agent_running(label: &str) -> bool {
    let domain = match current_uid() {
        Ok(uid) => format!("gui/{uid}/{label}"),
        Err(_) => return false,
    };
    Command::new("launchctl")
        .args(["print", &domain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn truncate_if_exists(path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, "").map_err(|error| error.to_string())
}

fn current_uid() -> Result<String, String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("failed to resolve current uid".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
