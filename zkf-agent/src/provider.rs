use crate::types::{ProviderProbeResultV1, ProviderRouteRecordV1};
use serde_json::json;
use std::env;
use std::time::Instant;
use zkf_command_surface::{new_operation_id, now_rfc3339};

pub fn select_provider_routes(
    session_id: Option<&str>,
    workflow_kind: &str,
    provider_override: Option<&str>,
) -> Vec<ProviderRouteRecordV1> {
    let mut routes = Vec::new();
    routes.push(route(
        session_id,
        "planner",
        provider_override.unwrap_or("embedded-zkf-planner"),
        "in-process",
        provider_override.is_none_or(|value| value == "embedded-zkf-planner"),
        json!({
            "workflow_kind": workflow_kind,
            "mode": "local-first",
            "capabilities": ["intent-compilation", "workgraph-planning", "command-routing"],
        }),
    ));

    for (provider, locality, vars) in [
        (
            "mlx-local",
            "apple-silicon-local",
            &["ZIROS_AGENT_MLX_BASE_URL", "MLX_SERVER_URL"][..],
        ),
        (
            "openai-compatible-local",
            "local-endpoint",
            &["ZIROS_AGENT_MODEL_BASE_URL", "OPENAI_BASE_URL"][..],
        ),
        ("ollama-local", "local-endpoint", &["OLLAMA_HOST"][..]),
    ] {
        let detected = vars
            .iter()
            .find_map(|name| env::var(name).ok().map(|value| ((*name).to_string(), value)));
        let ready = detected.is_some() || provider_override == Some(provider);
        if ready {
            routes.push(route(
                session_id,
                "assistant",
                provider,
                locality,
                detected.is_some(),
                json!({
                    "workflow_kind": workflow_kind,
                    "configured_from": detected.as_ref().map(|(name, _)| name.clone()),
                    "base_url": detected.as_ref().map(|(_, value)| value.clone()),
                    "mode": "detected-not-probed",
                }),
            ));
        }
    }

    let openai_api_key = env::var("OPENAI_API_KEY").ok().filter(|value| !value.trim().is_empty());
    let openai_base = env::var("ZIROS_AGENT_OPENAI_BASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| env::var("OPENAI_API_BASE").ok().filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "https://api.openai.com".to_string());
    let openai_model = env::var("ZIROS_AGENT_OPENAI_MODEL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| env::var("OPENAI_MODEL").ok().filter(|value| !value.trim().is_empty()));
    let openai_project = env::var("OPENAI_PROJECT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let openai_org = env::var("OPENAI_ORG_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let openai_ready = openai_api_key.is_some() || provider_override == Some("openai-api");
    if openai_ready {
        routes.push(route(
            session_id,
            "assistant",
            "openai-api",
            "remote-api",
            openai_api_key.is_some(),
            json!({
                "workflow_kind": workflow_kind,
                "configured_from": openai_api_key.as_ref().map(|_| "OPENAI_API_KEY"),
                "base_url": openai_base,
                "model": openai_model,
                "project": openai_project,
                "organization": openai_org,
                "auth_mode": if openai_api_key.is_some() { "bearer-api-key" } else { "missing-api-key" },
                "mode": "detected-not-probed",
            }),
        ));
    }

    if let Some(provider_override) = provider_override
        && routes.iter().all(|route| route.provider != provider_override)
    {
        routes.insert(
            0,
            route(
                session_id,
                "planner",
                provider_override,
                "explicit-override",
                false,
                json!({
                    "workflow_kind": workflow_kind,
                    "mode": "override-not-detected",
                }),
            ),
        );
    }

    routes
}

pub fn probe_provider_routes(routes: &[ProviderRouteRecordV1]) -> Vec<ProviderProbeResultV1> {
    routes.iter().map(probe_route).collect()
}

fn probe_route(route: &ProviderRouteRecordV1) -> ProviderProbeResultV1 {
    if route.locality == "in-process" {
        return ProviderProbeResultV1 {
            schema: "ziros-agent-provider-probe-v1".to_string(),
            probe_id: new_operation_id("provider-probe"),
            generated_at: now_rfc3339(),
            provider: route.provider.clone(),
            role: route.role.clone(),
            locality: route.locality.clone(),
            ready: route.ready,
            endpoint: None,
            probe_path: None,
            status_code: None,
            model_count: None,
            latency_ms: Some(0),
            error: None,
        };
    }

    let Some(base_url) = route.summary.get("base_url").and_then(serde_json::Value::as_str) else {
        return ProviderProbeResultV1 {
            schema: "ziros-agent-provider-probe-v1".to_string(),
            probe_id: new_operation_id("provider-probe"),
            generated_at: now_rfc3339(),
            provider: route.provider.clone(),
            role: route.role.clone(),
            locality: route.locality.clone(),
            ready: false,
            endpoint: None,
            probe_path: Some(probe_path_for_provider(&route.provider).to_string()),
            status_code: None,
            model_count: None,
            latency_ms: None,
            error: Some("provider route has no base_url to probe".to_string()),
        };
    };

    let normalized_base = normalize_base_url(base_url);
    let probe_path = probe_path_for_provider(&route.provider);
    let endpoint = format!(
        "{}/{}",
        normalized_base.trim_end_matches('/'),
        probe_path.trim_start_matches('/')
    );
    let started = Instant::now();
    let response = {
        let mut request = ureq::get(&endpoint).timeout(std::time::Duration::from_secs(2));
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
        request.call()
    };
    let latency_ms = started.elapsed().as_millis();

    match response {
        Ok(response) => {
            let status_code = response.status();
            let body = response.into_string().unwrap_or_default();
            let parsed = serde_json::from_str::<serde_json::Value>(&body).ok();
            let model_count = model_count_for_provider(&route.provider, parsed.as_ref());
            ProviderProbeResultV1 {
                schema: "ziros-agent-provider-probe-v1".to_string(),
                probe_id: new_operation_id("provider-probe"),
                generated_at: now_rfc3339(),
                provider: route.provider.clone(),
                role: route.role.clone(),
                locality: route.locality.clone(),
                ready: (200..300).contains(&status_code),
                endpoint: Some(normalized_base),
                probe_path: Some(probe_path.to_string()),
                status_code: Some(status_code),
                model_count,
                latency_ms: Some(latency_ms),
                error: None,
            }
        }
        Err(error) => {
            let status_code = match &error {
                ureq::Error::Status(code, _) => Some(*code),
                _ => None,
            };
            ProviderProbeResultV1 {
                schema: "ziros-agent-provider-probe-v1".to_string(),
                probe_id: new_operation_id("provider-probe"),
                generated_at: now_rfc3339(),
                provider: route.provider.clone(),
                role: route.role.clone(),
                locality: route.locality.clone(),
                ready: false,
                endpoint: Some(normalized_base),
                probe_path: Some(probe_path.to_string()),
                status_code,
                model_count: None,
                latency_ms: Some(latency_ms),
                error: Some(error.to_string()),
            }
        }
    }
}

fn normalize_base_url(base_url: &str) -> String {
    if base_url.starts_with("http://") || base_url.starts_with("https://") {
        base_url.to_string()
    } else {
        format!("http://{base_url}")
    }
}

fn probe_path_for_provider(provider: &str) -> &'static str {
    match provider {
        "ollama-local" => "/api/tags",
        _ => "/v1/models",
    }
}

fn auth_bearer_for_route(route: &ProviderRouteRecordV1) -> Option<String> {
    match route.provider.as_str() {
        "openai-api" => env::var("OPENAI_API_KEY").ok().filter(|value| !value.trim().is_empty()),
        _ => None,
    }
}

fn model_count_for_provider(provider: &str, payload: Option<&serde_json::Value>) -> Option<usize> {
    let payload = payload?;
    match provider {
        "ollama-local" => payload
            .get("models")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        _ => payload
            .get("data")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
    }
}

fn route(
    session_id: Option<&str>,
    role: &str,
    provider: &str,
    locality: &str,
    ready: bool,
    summary: serde_json::Value,
) -> ProviderRouteRecordV1 {
    ProviderRouteRecordV1 {
        schema: "ziros-agent-provider-route-v1".to_string(),
        route_id: new_operation_id("provider-route"),
        session_id: session_id.map(str::to_string),
        created_at: now_rfc3339(),
        role: role.to_string(),
        provider: provider.to_string(),
        locality: locality.to_string(),
        ready,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        auth_bearer_for_route, model_count_for_provider, normalize_base_url,
        probe_path_for_provider, probe_provider_routes, route,
    };
    use serde_json::json;

    #[test]
    fn normalize_base_url_adds_http_scheme_when_missing() {
        assert_eq!(normalize_base_url("127.0.0.1:1234"), "http://127.0.0.1:1234");
        assert_eq!(
            normalize_base_url("https://127.0.0.1:1234"),
            "https://127.0.0.1:1234"
        );
    }

    #[test]
    fn probe_path_depends_on_provider_family() {
        assert_eq!(probe_path_for_provider("ollama-local"), "/api/tags");
        assert_eq!(probe_path_for_provider("mlx-local"), "/v1/models");
    }

    #[test]
    fn model_count_reads_openai_and_ollama_shapes() {
        assert_eq!(
            model_count_for_provider("mlx-local", Some(&json!({ "data": [{}, {}] }))),
            Some(2)
        );
        assert_eq!(
            model_count_for_provider("ollama-local", Some(&json!({ "models": [{}, {}, {}] }))),
            Some(3)
        );
    }

    #[test]
    fn probe_provider_routes_short_circuits_in_process_provider() {
        let routes = vec![route(
            None,
            "planner",
            "embedded-zkf-planner",
            "in-process",
            true,
            json!({ "mode": "local-first" }),
        )];
        let probes = probe_provider_routes(&routes);

        assert_eq!(probes.len(), 1);
        let probe = &probes[0];
        assert!(probe.ready);
        assert_eq!(probe.status_code, None);
        assert_eq!(probe.model_count, None);
        assert_eq!(probe.latency_ms, Some(0));
        assert_eq!(probe.probe_path, None);
        assert_eq!(probe.endpoint, None);
    }

    #[test]
    fn probe_provider_routes_reports_missing_base_url() {
        let routes = vec![route(
            None,
            "assistant",
            "mlx-local",
            "apple-silicon-local",
            true,
            json!({ "configured_from": "ZIROS_AGENT_MLX_BASE_URL" }),
        )];
        let probes = probe_provider_routes(&routes);

        assert_eq!(probes.len(), 1);
        let probe = &probes[0];
        assert!(!probe.ready);
        assert_eq!(probe.status_code, None);
        assert_eq!(probe.model_count, None);
        assert_eq!(probe.probe_path.as_deref(), Some("/v1/models"));
        assert_eq!(
            probe.error.as_deref(),
            Some("provider route has no base_url to probe")
        );
    }

    #[allow(unsafe_code)]
    #[test]
    fn openai_api_route_uses_bearer_auth_from_environment() {
        unsafe {
            std::env::set_var("OPENAI_API_KEY", "test-openai-key");
        }
        let route = route(
            None,
            "assistant",
            "openai-api",
            "remote-api",
            true,
            json!({
                "base_url": "https://api.openai.com",
                "auth_mode": "bearer-api-key",
            }),
        );
        assert_eq!(auth_bearer_for_route(&route).as_deref(), Some("test-openai-key"));
        unsafe {
            std::env::remove_var("OPENAI_API_KEY");
        }
    }
}
