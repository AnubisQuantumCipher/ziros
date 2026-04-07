use crate::planner::{workflow_catalog, workflow_from_kind};
use crate::provider::select_provider_routes;
use crate::types::{AgentRunOptionsV1, GoalIntentV1};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

pub fn try_compile_goal_intent(goal: &str, options: &AgentRunOptionsV1) -> Option<GoalIntentV1> {
    if options.workflow_override.is_some() {
        return None;
    }
    let routes = select_provider_routes(
        None,
        "intent-compilation",
        options.provider_override.as_deref(),
        options.model_override.as_deref(),
    );
    let route = routes
        .iter()
        .find(|candidate| {
            candidate.role == "assistant"
                && matches!(
                    candidate.provider.as_str(),
                    "openai-api" | "openai-compatible-local" | "mlx-local"
                )
                && candidate
                    .summary
                    .get("base_url")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
                && candidate
                    .summary
                    .get("model")
                    .and_then(serde_json::Value::as_str)
                    .is_some()
        })?;
    let model = route.summary.get("model")?.as_str()?;
    let base_url = route.summary.get("base_url")?.as_str()?;

    compile_goal_intent_via_chat_completions(base_url, route, goal, model)
}

fn compile_goal_intent_via_chat_completions(
    base_url: &str,
    route: &crate::types::ProviderRouteRecordV1,
    goal: &str,
    model: &str,
) -> Option<GoalIntentV1> {
    let endpoint = format!(
        "{}/v1/chat/completions",
        normalize_base_url(base_url).trim_end_matches('/')
    );
    let body = json!({
        "model": model,
        "temperature": 0,
        "response_format": { "type": "json_object" },
        "messages": [
            {
                "role": "system",
                "content": system_prompt(),
            },
            {
                "role": "user",
                "content": user_prompt(goal),
            }
        ]
    });
    let payload = serde_json::to_string(&body).ok()?;

    let mut request = ureq::post(&endpoint)
        .timeout(Duration::from_secs(8))
        .set("Content-Type", "application/json");
    if let Some(api_key) = auth_bearer_for_route(route) {
        request = request.set("Authorization", &format!("Bearer {api_key}"));
    }
    if let Some(project) = route
        .summary
        .get("project")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        request = request.set("OpenAI-Project", project);
    }
    if let Some(organization) = route
        .summary
        .get("organization")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        request = request.set("OpenAI-Organization", organization);
    }

    let response = request.send_string(&payload);
    let body = match response {
        Ok(response) => response.into_string().ok()?,
        Err(_) => return None,
    };
    let payload = serde_json::from_str::<ChatCompletionResponse>(&body).ok()?;
    let content = payload
        .choices
        .into_iter()
        .next()?
        .message
        .content
        .trim()
        .to_string();
    let parsed = serde_json::from_str::<ModelIntentEnvelope>(&content)
        .ok()
        .or_else(|| extract_json_object(&content).and_then(|value| serde_json::from_str(&value).ok()))?;
    if workflow_catalog()
        .into_iter()
        .all(|candidate| candidate.workflow_kind != parsed.workflow_kind)
    {
        return None;
    }

    let mut intent = workflow_from_kind(&parsed.workflow_kind, goal);
    if let Some(summary) = parsed.summary.filter(|value| !value.trim().is_empty()) {
        intent.summary = summary;
    }
    if !parsed.requested_outputs.is_empty() {
        intent.requested_outputs = parsed.requested_outputs;
    }
    if let Some(hints) = parsed.hints {
        intent.hints = Some(hints);
    }
    Some(intent)
}

fn normalize_base_url(base_url: &str) -> String {
    if base_url.starts_with("http://") || base_url.starts_with("https://") {
        base_url.to_string()
    } else {
        format!("http://{base_url}")
    }
}

fn auth_bearer_for_route(route: &crate::types::ProviderRouteRecordV1) -> Option<String> {
    match route.provider.as_str() {
        "openai-api" => std::env::var("OPENAI_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        _ => None,
    }
}

fn system_prompt() -> &'static str {
    "You are the ZirOS intent compiler. Classify the operator goal into one existing workflow and return JSON only. Never invent new workflow names. Prefer subsystem-first workflows. Prefer Midnight over EVM when the request is ambiguous. Use EVM only when the request clearly mentions Solidity, verifier export, Foundry, Anvil, or EVM deployment/testing. Return a JSON object with workflow_kind, optional summary, optional requested_outputs, and optional hints."
}

fn user_prompt(goal: &str) -> String {
    format!(
        "Goal:\n{goal}\n\nAllowed workflow_kind values:\n- subsystem-scaffold\n- subsystem-proof\n- subsystem-midnight-ops\n- subsystem-evm-ops\n- subsystem-benchmark\n- subsystem-evidence-release\n- proof-app-build\n- midnight-contract-ops\n- midnight-proof-server-ops\n- benchmark-report\n- evidence-bundle\n- host-readiness\n- generic-investigation\n\nAllowed hint keys:\n- require_wallet\n- require_metal\n- subsystem_style\n- midnight_template\n- app_template\n- benchmark_parallel\n- benchmark_distributed\n- target_chain\n\nAllowed target_chain values:\n- midnight\n- evm\n- hybrid\n\nReturn JSON only."
    )
}

fn extract_json_object(value: &str) -> Option<String> {
    let start = value.find('{')?;
    let end = value.rfind('}')?;
    (end > start).then(|| value[start..=end].to_string())
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionChoice {
    message: ChatCompletionMessage,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
struct ModelIntentEnvelope {
    workflow_kind: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    requested_outputs: Vec<String>,
    #[serde(default)]
    hints: Option<crate::types::IntentHintsV1>,
}

#[cfg(test)]
mod tests {
    use super::extract_json_object;

    #[test]
    fn extracts_embedded_json_object() {
        let value = "```json\n{\"workflow_kind\":\"host-readiness\"}\n```";
        assert_eq!(
            extract_json_object(value).as_deref(),
            Some("{\"workflow_kind\":\"host-readiness\"}")
        );
    }
}
