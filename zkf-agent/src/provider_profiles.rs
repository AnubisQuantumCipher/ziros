use crate::state::{ensure_ziros_layout, provider_profiles_path};
use serde::{Deserialize, Serialize};
use std::fs;
use zkf_keymanager::KeyManager;

const STORE_SCHEMA: &str = "ziros-provider-profiles-v1";
const OPENAI_KEY_SERVICE: &str = "com.ziros.agent.api.openai";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderKindV1 {
    OpenaiApi,
    MlxLocal,
    OpenaiCompatibleLocal,
    OllamaLocal,
}

impl ProviderKindV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenaiApi => "openai-api",
            Self::MlxLocal => "mlx-local",
            Self::OpenaiCompatibleLocal => "openai-compatible-local",
            Self::OllamaLocal => "ollama-local",
        }
    }

    pub fn default_base_url(&self) -> Option<&'static str> {
        match self {
            Self::OpenaiApi => Some("https://api.openai.com"),
            Self::MlxLocal => Some("http://127.0.0.1:8080"),
            Self::OpenaiCompatibleLocal => Some("http://127.0.0.1:11434"),
            Self::OllamaLocal => Some("http://127.0.0.1:11434"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRoleBindingV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summarizer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval: Option<String>,
}

impl ProviderRoleBindingV1 {
    pub fn filled(model: Option<String>) -> Self {
        Self {
            planner: model.clone(),
            chat: model.clone(),
            summarizer: model.clone(),
            retrieval: model,
        }
    }

    pub fn model_for_role(&self, role: &str) -> Option<&str> {
        match role {
            "planner" => self
                .planner
                .as_deref()
                .or(self.chat.as_deref())
                .or(self.summarizer.as_deref()),
            "summarizer" => self
                .summarizer
                .as_deref()
                .or(self.chat.as_deref())
                .or(self.planner.as_deref()),
            "retrieval" => self
                .retrieval
                .as_deref()
                .or(self.chat.as_deref())
                .or(self.planner.as_deref()),
            _ => self
                .chat
                .as_deref()
                .or(self.planner.as_deref())
                .or(self.summarizer.as_deref()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderCredentialRefV1 {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderProfileV1 {
    pub profile_id: String,
    pub provider_kind: ProviderKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default)]
    pub role_models: ProviderRoleBindingV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<ProviderCredentialRefV1>,
}

impl ProviderProfileV1 {
    pub fn selected_model(
        &self,
        requested_role: &str,
        model_override: Option<&str>,
    ) -> Option<String> {
        model_override.map(str::to_string).or_else(|| {
            self.role_models
                .model_for_role(requested_role)
                .map(str::to_string)
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderProfileStoreV1 {
    pub schema: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: Vec<ProviderProfileV1>,
}

impl Default for ProviderProfileStoreV1 {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            default_profile: None,
            profiles: Vec::new(),
        }
    }
}

pub fn load_provider_profile_store() -> Result<ProviderProfileStoreV1, String> {
    let path = provider_profiles_path();
    if !path.exists() {
        return Ok(ProviderProfileStoreV1::default());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    toml::from_str(&content).map_err(|error| format!("failed to parse {}: {error}", path.display()))
}

pub fn save_provider_profile_store(store: &ProviderProfileStoreV1) -> Result<(), String> {
    let _ = ensure_ziros_layout()?;
    let path = provider_profiles_path();
    let body = toml::to_string_pretty(store).map_err(|error| error.to_string())?;
    fs::write(&path, body).map_err(|error| format!("failed to write {}: {error}", path.display()))
}

pub fn upsert_provider_profile(
    profile: ProviderProfileV1,
    set_default: bool,
) -> Result<ProviderProfileStoreV1, String> {
    let mut store = load_provider_profile_store()?;
    store
        .profiles
        .retain(|candidate| candidate.profile_id != profile.profile_id);
    store.profiles.push(profile.clone());
    store
        .profiles
        .sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
    if set_default || store.default_profile.is_none() {
        store.default_profile = Some(profile.profile_id);
    }
    save_provider_profile_store(&store)?;
    Ok(store)
}

pub fn remove_provider_profile(profile_id: &str) -> Result<ProviderProfileStoreV1, String> {
    let mut store = load_provider_profile_store()?;
    store
        .profiles
        .retain(|profile| profile.profile_id != profile_id);
    if store.default_profile.as_deref() == Some(profile_id) {
        store.default_profile = store
            .profiles
            .first()
            .map(|profile| profile.profile_id.clone());
    }
    save_provider_profile_store(&store)?;
    Ok(store)
}

pub fn set_default_provider_profile(profile_id: &str) -> Result<ProviderProfileStoreV1, String> {
    let mut store = load_provider_profile_store()?;
    if store
        .profiles
        .iter()
        .all(|profile| profile.profile_id != profile_id)
    {
        return Err(format!("unknown provider profile '{profile_id}'"));
    }
    store.default_profile = Some(profile_id.to_string());
    save_provider_profile_store(&store)?;
    Ok(store)
}

pub fn ordered_profiles_for_selection(
    store: &ProviderProfileStoreV1,
    provider_override: Option<&str>,
) -> Vec<ProviderProfileV1> {
    let mut profiles = store.profiles.clone();
    profiles.sort_by(|left, right| {
        let left_rank = profile_rank(left, store.default_profile.as_deref(), provider_override);
        let right_rank = profile_rank(right, store.default_profile.as_deref(), provider_override);
        left_rank
            .cmp(&right_rank)
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    profiles
        .into_iter()
        .filter(|profile| {
            provider_override.is_none_or(|requested| {
                requested == profile.profile_id || requested == profile.provider_kind.as_str()
            })
        })
        .collect()
}

pub fn openai_credential_ref(profile_id: &str) -> ProviderCredentialRefV1 {
    ProviderCredentialRefV1 {
        source: "keychain".to_string(),
        env_var: Some("OPENAI_API_KEY".to_string()),
        keychain_service: Some(OPENAI_KEY_SERVICE.to_string()),
        keychain_account: Some(format!("openai/{profile_id}")),
    }
}

pub fn store_openai_api_key(profile_id: &str, api_key: &str) -> Result<(), String> {
    let manager = KeyManager::new().map_err(|error| error.to_string())?;
    let credential = openai_credential_ref(profile_id);
    manager
        .store_key(
            credential
                .keychain_account
                .as_deref()
                .ok_or_else(|| "missing keychain account".to_string())?,
            credential
                .keychain_service
                .as_deref()
                .ok_or_else(|| "missing keychain service".to_string())?,
            api_key.as_bytes(),
        )
        .map_err(|error| error.to_string())
}

pub fn load_api_key(credential: Option<&ProviderCredentialRefV1>) -> Option<String> {
    let credential = credential?;
    if let Some(env_var) = credential.env_var.as_deref()
        && let Ok(value) = std::env::var(env_var)
        && !value.trim().is_empty()
    {
        return Some(value);
    }

    if credential.source == "keychain" {
        let manager = KeyManager::new().ok()?;
        let account = credential.keychain_account.as_deref()?;
        let service = credential.keychain_service.as_deref()?;
        let bytes = manager.retrieve_key(account, service).ok()?;
        return String::from_utf8(bytes)
            .ok()
            .filter(|value| !value.trim().is_empty());
    }

    None
}

fn profile_rank(
    profile: &ProviderProfileV1,
    default_profile: Option<&str>,
    provider_override: Option<&str>,
) -> u8 {
    if provider_override.is_some_and(|requested| requested == profile.profile_id) {
        0
    } else if default_profile.is_some_and(|default| default == profile.profile_id) {
        1
    } else {
        2
    }
}
