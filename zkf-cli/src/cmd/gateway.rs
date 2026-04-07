use actix_web::http::header::CONTENT_TYPE;
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use futures::stream;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zkf_agent::{AgentRunOptionsV1, load_provider_profile_store, run_goal};

use crate::cli::GatewayCommands;

#[derive(Debug, Clone)]
struct GatewayState {
    project_root: Option<PathBuf>,
    provider: Option<String>,
    model: Option<String>,
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

pub(crate) fn handle_gateway(command: GatewayCommands) -> Result<(), String> {
    match command {
        GatewayCommands::Serve {
            bind,
            project,
            provider,
            model,
        } => serve_gateway(bind, project, provider, model),
    }
}

fn serve_gateway(
    bind: String,
    project_root: Option<PathBuf>,
    provider: Option<String>,
    model: Option<String>,
) -> Result<(), String> {
    let state = web::Data::new(GatewayState {
        project_root,
        provider,
        model,
    });
    println!("ZirOS gateway listening on http://{bind}");
    actix_web::rt::System::new().block_on(async move {
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .route("/health", web::get().to(gateway_health))
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
