use super::config::SwarmConfig;
use crate::security::{RuntimeSecurityContext, SecurityEvaluation, SecuritySupervisor};
use crate::swarm_entrypoint_core;
use crate::telemetry::GraphExecutionReport;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntrypointSurface {
    Cli,
    Api,
}

impl EntrypointSurface {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Api => "api",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntrypointObservation {
    pub surface: EntrypointSurface,
    pub name: String,
    pub started_unix_ms: u128,
    pub completed_unix_ms: u128,
    pub duration_ms: u128,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<String>,
}

pub struct EntrypointGuard {
    config: SwarmConfig,
    surface: EntrypointSurface,
    name: String,
    started_unix_ms: u128,
    started_at: Instant,
}

impl EntrypointGuard {
    pub fn begin(surface: EntrypointSurface, name: impl Into<String>) -> Self {
        Self {
            config: SwarmConfig::from_env(),
            surface,
            name: name.into(),
            started_unix_ms: unix_time_now_ms(),
            started_at: Instant::now(),
        }
    }

    pub fn finish(
        self,
        context: RuntimeSecurityContext,
        success: bool,
        status_code: Option<u16>,
        detail: Option<String>,
    ) -> io::Result<Option<SecurityEvaluation>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let completed_unix_ms = unix_time_now_ms();
        let observation = EntrypointObservation {
            surface: self.surface,
            name: self.name,
            started_unix_ms: self.started_unix_ms,
            completed_unix_ms,
            duration_ms: self.started_at.elapsed().as_millis(),
            success,
            status_code,
            detail: detail.clone(),
            caller_class: context.caller_class.clone(),
            identity_hash: context.api_identity_hash.clone(),
        };
        write_observation(&self.config, &observation)?;

        if !context_has_security_signal(&context) {
            return Ok(None);
        }

        Ok(Some(SecuritySupervisor::evaluate(
            &GraphExecutionReport::new(),
            None,
            Some(&context),
            None,
        )))
    }
}

fn context_has_security_signal(context: &RuntimeSecurityContext) -> bool {
    swarm_entrypoint_core::context_has_security_signal(context)
}

fn write_observation(config: &SwarmConfig, observation: &EntrypointObservation) -> io::Result<()> {
    let dir = config.swarm_root().join("entrypoints");
    fs::create_dir_all(&dir)?;
    let file_name = format!(
        "{}-{}-{}.json",
        observation.started_unix_ms,
        observation.surface.as_str(),
        sanitize_file_component(&observation.name)
    );
    let payload = serde_json::to_vec_pretty(observation)
        .map_err(|err| io::Error::other(format!("serialize entrypoint observation: {err}")))?;
    fs::write(dir.join(file_name), payload)
}

fn sanitize_file_component(value: &str) -> String {
    swarm_entrypoint_core::sanitize_file_component(value)
}

fn unix_time_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{EntrypointGuard, EntrypointSurface};
    use crate::SwarmConfig;
    use crate::security::{RuntimeSecurityContext, ThreatSignalKind};
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_temp_home<T>(swarm_enabled: bool, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let old_home = std::env::var_os("HOME");
        let old_swarm = std::env::var_os("ZKF_SWARM");
        let old_backend = std::env::var_os("ZKF_SWARM_KEY_BACKEND");
        unsafe {
            std::env::set_var("HOME", temp.path());
            std::env::set_var("ZKF_SWARM", if swarm_enabled { "1" } else { "0" });
            std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
        }
        let result = f();
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
            if let Some(old_swarm) = old_swarm {
                std::env::set_var("ZKF_SWARM", old_swarm);
            } else {
                std::env::remove_var("ZKF_SWARM");
            }
            if let Some(old_backend) = old_backend {
                std::env::set_var("ZKF_SWARM_KEY_BACKEND", old_backend);
            } else {
                std::env::remove_var("ZKF_SWARM_KEY_BACKEND");
            }
        }
        result
    }

    #[test]
    fn entrypoint_guard_writes_observation_when_swarm_enabled() {
        with_temp_home(true, || {
            let config = SwarmConfig::from_env();
            let guard = EntrypointGuard::begin(EntrypointSurface::Cli, "capabilities");
            guard
                .finish(
                    RuntimeSecurityContext {
                        caller_class: Some("cli".to_string()),
                        ..RuntimeSecurityContext::default()
                    },
                    true,
                    None,
                    None,
                )
                .expect("finish");

            let entrypoints_dir = config.swarm_root().join("entrypoints");
            let mut entries = fs::read_dir(&entrypoints_dir)
                .expect("entrypoints dir")
                .collect::<Result<Vec<_>, _>>()
                .expect("read dir");
            entries.sort_by_key(|entry| entry.file_name());
            assert_eq!(entries.len(), 1);

            let payload = fs::read_to_string(entries[0].path()).expect("payload");
            assert!(payload.contains("\"surface\": \"cli\""));
            assert!(payload.contains("\"name\": \"capabilities\""));
        });
    }

    #[test]
    fn entrypoint_guard_respects_kill_switch() {
        with_temp_home(false, || {
            let config = SwarmConfig::from_env();
            let guard = EntrypointGuard::begin(EntrypointSurface::Cli, "capabilities");
            guard
                .finish(RuntimeSecurityContext::default(), true, None, None)
                .expect("finish");
            assert!(!config.swarm_root().exists());
        });
    }

    #[test]
    fn entrypoint_guard_routes_security_signals_through_supervisor() {
        with_temp_home(true, || {
            let guard = EntrypointGuard::begin(EntrypointSurface::Api, "GET /health");
            let evaluation = guard
                .finish(
                    RuntimeSecurityContext {
                        caller_class: Some("api".to_string()),
                        malformed_request_count: 1,
                        ..RuntimeSecurityContext::default()
                    },
                    false,
                    Some(422),
                    Some("unprocessable".to_string()),
                )
                .expect("finish")
                .expect("security evaluation");
            assert!(
                evaluation
                    .verdict
                    .signals
                    .iter()
                    .any(|signal| signal.kind == ThreatSignalKind::MalformedRequestBurst)
            );
        });
    }
}
