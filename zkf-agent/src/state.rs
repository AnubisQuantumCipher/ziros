use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
#[cfg(target_family = "unix")]
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

const ZIROS_HOME_ENV: &str = "ZIROS_HOME";
const LEGACY_ZKF_ROOT: &str = ".zkf";
const ZIROS_ROOT: &str = ".ziros";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStateMigrationRecordV1 {
    pub source: String,
    pub destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStateLayoutReportV1 {
    pub ziros_home: String,
    pub config_path: String,
    pub providers_path: String,
    pub bin_root: String,
    pub logs_root: String,
    pub state_root: String,
    pub agent_root: String,
    pub brain_path: String,
    pub socket_path: String,
    pub legacy_agent_root: String,
    pub migrated: Vec<AgentStateMigrationRecordV1>,
}

pub fn ziros_home_root() -> PathBuf {
    std::env::var_os(ZIROS_HOME_ENV)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| home_dir().join(ZIROS_ROOT))
}

pub fn legacy_zkf_root() -> PathBuf {
    home_dir().join(LEGACY_ZKF_ROOT)
}

pub fn legacy_agent_root() -> PathBuf {
    legacy_zkf_root().join("cache").join("agent")
}

pub fn config_path() -> PathBuf {
    ziros_home_root().join("config.toml")
}

pub fn provider_profiles_path() -> PathBuf {
    ziros_home_root().join("providers.toml")
}

pub fn managed_bin_root() -> PathBuf {
    ziros_home_root().join("bin")
}

pub fn logs_root() -> PathBuf {
    ziros_home_root().join("logs")
}

pub fn state_root() -> PathBuf {
    ziros_home_root().join("state")
}

pub fn install_root() -> PathBuf {
    ziros_home_root().join("install")
}

pub fn agent_root() -> PathBuf {
    ziros_home_root().join("agent")
}

pub fn brain_path() -> PathBuf {
    agent_root().join("brain.sqlite3")
}

pub fn socket_path() -> PathBuf {
    agent_root().join("ziros-agentd.sock")
}

pub fn first_run_marker_path() -> PathBuf {
    state_root().join("ziros-first-run-v1")
}

pub fn ensure_ziros_layout() -> Result<AgentStateLayoutReportV1, String> {
    fs::create_dir_all(ziros_home_root())
        .map_err(|error| format!("failed to create {}: {error}", ziros_home_root().display()))?;
    fs::create_dir_all(agent_root())
        .map_err(|error| format!("failed to create {}: {error}", agent_root().display()))?;
    fs::create_dir_all(managed_bin_root()).map_err(|error| {
        format!(
            "failed to create {}: {error}",
            managed_bin_root().display()
        )
    })?;
    fs::create_dir_all(logs_root())
        .map_err(|error| format!("failed to create {}: {error}", logs_root().display()))?;
    fs::create_dir_all(state_root())
        .map_err(|error| format!("failed to create {}: {error}", state_root().display()))?;
    fs::create_dir_all(install_root())
        .map_err(|error| format!("failed to create {}: {error}", install_root().display()))?;

    let migrated = migrate_legacy_agent_state()?;
    let _ = ensure_legacy_agent_bridge();

    Ok(AgentStateLayoutReportV1 {
        ziros_home: ziros_home_root().display().to_string(),
        config_path: config_path().display().to_string(),
        providers_path: provider_profiles_path().display().to_string(),
        bin_root: managed_bin_root().display().to_string(),
        logs_root: logs_root().display().to_string(),
        state_root: state_root().display().to_string(),
        agent_root: agent_root().display().to_string(),
        brain_path: brain_path().display().to_string(),
        socket_path: socket_path().display().to_string(),
        legacy_agent_root: legacy_agent_root().display().to_string(),
        migrated,
    })
}

pub fn migrate_legacy_agent_state() -> Result<Vec<AgentStateMigrationRecordV1>, String> {
    let legacy = legacy_agent_root();
    let destination = agent_root();
    if !legacy.exists() || legacy == destination {
        return Ok(Vec::new());
    }
    let mut migrated = Vec::new();
    copy_missing_tree(&legacy, &destination, &mut migrated)
        .map_err(|error| format!("failed to migrate agent state: {error}"))?;
    Ok(migrated)
}

fn ensure_legacy_agent_bridge() -> io::Result<()> {
    let legacy = legacy_agent_root();
    if legacy.exists() {
        return Ok(());
    }
    if let Some(parent) = legacy.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(target_family = "unix")]
    {
        unix_fs::symlink(agent_root(), legacy)?;
    }
    Ok(())
}

fn copy_missing_tree(
    source: &Path,
    destination: &Path,
    migrated: &mut Vec<AgentStateMigrationRecordV1>,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source)?;
        let resolved = if target.is_absolute() {
            target
        } else {
            source
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(target)
        };
        return copy_missing_tree(&resolved, destination, migrated);
    }
    if source.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        if !destination.exists() {
            fs::copy(source, destination)?;
            migrated.push(AgentStateMigrationRecordV1 {
                source: source.display().to_string(),
                destination: destination.display().to_string(),
            });
        }
        return Ok(());
    }
    if !source.is_dir() {
        return Ok(());
    }

    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        copy_missing_tree(&source_path, &destination_path, migrated)?;
    }
    Ok(())
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::{brain_path, ensure_ziros_layout, first_run_marker_path, ziros_home_root};

    #[test]
    fn layout_uses_ziros_home_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("HOME", temp.path());
        }
        let report = ensure_ziros_layout().expect("layout");
        assert!(report.ziros_home.ends_with("/.ziros"));
        assert!(brain_path().starts_with(ziros_home_root()));
        assert!(first_run_marker_path().starts_with(ziros_home_root()));
    }
}
