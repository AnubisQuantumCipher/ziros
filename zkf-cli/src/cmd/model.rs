use crate::cli::{ModelAddCommands, ModelCommands};
use serde::Serialize;
use std::io::{self, Write};
use zkf_agent::{
    AgentProviderTestRequestV1, ProviderKindV1, ProviderProfileV1, ProviderRoleBindingV1,
    load_provider_profile_store, provider_test, remove_provider_profile,
    set_default_provider_profile, store_openai_api_key, upsert_provider_profile,
};

pub(crate) fn handle_model(json_output: bool, command: ModelCommands) -> Result<(), String> {
    match command {
        ModelCommands::List => print_output(json_output, &load_provider_profile_store()?),
        ModelCommands::Add { command } => match command {
            ModelAddCommands::Openai {
                profile,
                model,
                planner_model,
                chat_model,
                summarizer_model,
                retrieval_model,
                base_url,
                project,
                organization,
                api_key_stdin,
                set_default,
            } => {
                let profile_id = profile.unwrap_or_else(|| "openai-default".to_string());
                let role_models = ProviderRoleBindingV1 {
                    planner: planner_model.clone().or_else(|| model.clone()),
                    chat: chat_model.clone().or_else(|| model.clone()),
                    summarizer: summarizer_model.clone().or_else(|| model.clone()),
                    retrieval: retrieval_model.clone().or(model),
                };
                let profile = ProviderProfileV1 {
                    profile_id: profile_id.clone(),
                    provider_kind: ProviderKindV1::OpenaiApi,
                    base_url: Some(
                        base_url.unwrap_or_else(|| "https://api.openai.com".to_string()),
                    ),
                    role_models,
                    organization,
                    project,
                    credential: Some(zkf_agent::openai_credential_ref(&profile_id)),
                };
                if api_key_stdin && let Some(api_key) = read_stdin_secret("OpenAI API key")? {
                    store_openai_api_key(&profile_id, &api_key)?;
                }
                let store = upsert_provider_profile(profile, set_default)?;
                print_output(json_output, &store)
            }
            ModelAddCommands::Mlx {
                profile,
                model,
                base_url,
                set_default,
            } => print_output(
                json_output,
                &upsert_provider_profile(
                    ProviderProfileV1 {
                        profile_id: profile.unwrap_or_else(|| "mlx-default".to_string()),
                        provider_kind: ProviderKindV1::MlxLocal,
                        base_url: Some(
                            base_url.unwrap_or_else(|| "http://127.0.0.1:8080".to_string()),
                        ),
                        role_models: ProviderRoleBindingV1::filled(model),
                        organization: None,
                        project: None,
                        credential: None,
                    },
                    set_default,
                )?,
            ),
            ModelAddCommands::OpenaiCompatible {
                profile,
                model,
                base_url,
                set_default,
            } => print_output(
                json_output,
                &upsert_provider_profile(
                    ProviderProfileV1 {
                        profile_id: profile
                            .unwrap_or_else(|| "openai-compatible-default".to_string()),
                        provider_kind: ProviderKindV1::OpenaiCompatibleLocal,
                        base_url: Some(
                            base_url.unwrap_or_else(|| "http://127.0.0.1:11434".to_string()),
                        ),
                        role_models: ProviderRoleBindingV1::filled(model),
                        organization: None,
                        project: None,
                        credential: None,
                    },
                    set_default,
                )?,
            ),
            ModelAddCommands::Ollama {
                profile,
                model,
                base_url,
                set_default,
            } => print_output(
                json_output,
                &upsert_provider_profile(
                    ProviderProfileV1 {
                        profile_id: profile.unwrap_or_else(|| "ollama-default".to_string()),
                        provider_kind: ProviderKindV1::OllamaLocal,
                        base_url: Some(
                            base_url.unwrap_or_else(|| "http://127.0.0.1:11434".to_string()),
                        ),
                        role_models: ProviderRoleBindingV1::filled(model),
                        organization: None,
                        project: None,
                        credential: None,
                    },
                    set_default,
                )?,
            ),
        },
        ModelCommands::Use { profile_id } => {
            print_output(json_output, &set_default_provider_profile(&profile_id)?)
        }
        ModelCommands::Test { profile_id } => {
            let selected_profile = profile_id.or_else(|| {
                load_provider_profile_store()
                    .ok()
                    .and_then(|store| store.default_profile)
            });
            let report = provider_test(AgentProviderTestRequestV1 {
                session_id: None,
                provider_override: selected_profile,
                model_override: None,
            })?;
            print_output(json_output, &report)
        }
        ModelCommands::Remove { profile_id } => {
            print_output(json_output, &remove_provider_profile(&profile_id)?)
        }
    }
}

fn print_output(json_output: bool, value: &impl Serialize) -> Result<(), String> {
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
