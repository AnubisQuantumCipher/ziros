use crate::cli::StorageCommands;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use zkf_storage::{
    FileClass, StorageGuardianConfig, SweepReport, archive_file, classify_path,
    collect_archivable_paths, collect_ephemeral_paths, collect_showcase_roots,
    current_icloud_archive_bytes, current_utc_timestamp, directory_size_bytes, get_ssd_health,
    icloud_archive_root, purge_ephemeral,
};

const LAUNCHD_TEMPLATE: &str =
    include_str!("../../../scripts/launchd/com.ziros.storage-guardian.plist");

#[derive(Debug, Serialize)]
struct StorageStatusReport {
    health_status: String,
    health_reason: Option<String>,
    capacity_gb: f64,
    available_gb: f64,
    used_percent: f64,
    build_cache: BuildCacheReport,
    runtime_state: RuntimeStateReport,
    showcase: ShowcaseUsage,
    icloud_archive: ICloudArchiveReport,
    recoverable_bytes: u64,
    recoverable_gb: f64,
}

#[derive(Debug, Serialize)]
struct BuildCacheReport {
    target_local_debug_bytes: u64,
    target_local_kani_bytes: u64,
    target_debug_bytes: u64,
    target_local_release_bytes: u64,
}

#[derive(Debug, Serialize)]
struct RuntimeStateReport {
    telemetry_bytes: u64,
    models_bytes: u64,
    swarm_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ShowcaseUsage {
    root_count: usize,
    total_bytes: u64,
    roots: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ICloudArchiveReport {
    enabled: bool,
    available: bool,
    path: String,
    archived_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct StorageDoctorReport {
    device_name: String,
    model: String,
    serial: String,
    firmware: String,
    capacity_gb: f64,
    used_gb: f64,
    available_gb: f64,
    used_percent: f64,
    wear_level_percent: Option<f64>,
    temperature_celsius: Option<f64>,
    power_on_hours: Option<u64>,
    smart_available: bool,
    health_status: String,
    health_reason: Option<String>,
    profile: String,
    warn_free_space_gb: u64,
    critical_free_space_gb: u64,
    icloud_archived_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct StoragePolicyReport {
    enabled: bool,
    icloud_archive_enabled: bool,
    profile: String,
    warn_free_space_gb: u64,
    critical_free_space_gb: u64,
    monitor_interval_secs: u64,
    auto_archive_proofs: bool,
    auto_archive_telemetry: bool,
    auto_purge_debug_cache: bool,
    purge_witness_after_prove: bool,
    dry_run: bool,
    storage_root: String,
    log_path: String,
}

#[derive(Debug, Serialize)]
struct ArchiveCommandReport {
    files_archived: usize,
    bytes_archived: u64,
    archive_root: String,
    archived_paths: Vec<String>,
    dry_run: bool,
}

pub(crate) fn handle_storage(command: StorageCommands) -> Result<(), String> {
    match command {
        StorageCommands::Status { json } => handle_status(json),
        StorageCommands::Archive { dry_run } => handle_archive(dry_run),
        StorageCommands::Purge {
            dry_run,
            include_release,
        } => handle_purge(dry_run, include_release),
        StorageCommands::Sweep { dry_run } => handle_sweep(dry_run),
        StorageCommands::Watch { interval } => handle_watch(interval),
        StorageCommands::Restore { path } => handle_restore(&path),
        StorageCommands::Doctor { json } => handle_doctor(json),
        StorageCommands::Policy { json } => handle_policy(json),
        StorageCommands::Install { uninstall } => handle_install(uninstall),
    }
}

fn handle_status(json: bool) -> Result<(), String> {
    let report = status_report()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "storage status: health={} free={:.1} GB used={:.1}% recoverable={}",
            report.health_status,
            report.available_gb,
            report.used_percent,
            human_size(report.recoverable_bytes)
        );
    }
    Ok(())
}

fn handle_archive(dry_run: bool) -> Result<(), String> {
    let report = archive_report(dry_run)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
    );
    Ok(())
}

fn handle_purge(dry_run: bool, include_release: bool) -> Result<(), String> {
    let repo_root = repo_root();
    let home = home_dir();
    let paths = collect_ephemeral_paths(&repo_root, &home, include_release)
        .map_err(|err| err.to_string())?;
    let report = purge_ephemeral(&paths, dry_run).map_err(|err| err.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
    );
    Ok(())
}

fn handle_sweep(dry_run: bool) -> Result<(), String> {
    let archive = archive_report(dry_run)?;
    let repo_root = repo_root();
    let home = home_dir();
    let paths =
        collect_ephemeral_paths(&repo_root, &home, false).map_err(|err| err.to_string())?;
    let purge = purge_ephemeral(&paths, dry_run).map_err(|err| err.to_string())?;
    let report = SweepReport {
        files_archived: archive.files_archived,
        bytes_archived: archive.bytes_archived,
        files_purged: purge.files_purged,
        bytes_freed: purge.bytes_freed,
        icloud_archive_path: Some(PathBuf::from(&archive.archive_root)),
        errors: Vec::new(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
    );
    Ok(())
}

fn handle_watch(interval: u64) -> Result<(), String> {
    let config = StorageGuardianConfig::from_env();
    let sleep_secs = interval.max(1);
    loop {
        let doctor = doctor_report()?;
        match doctor.health_status.as_str() {
            "critical" => {
                eprintln!(
                    "storage guardian: critical free space detected ({:.1} GB); running sweep",
                    doctor.available_gb
                );
                handle_sweep(config.dry_run)?;
            }
            "warning" => {
                eprintln!(
                    "storage guardian: warning free space detected ({:.1} GB); running archive",
                    doctor.available_gb
                );
                handle_archive(config.dry_run)?;
            }
            _ => {
                println!(
                    "storage guardian: healthy free space {:.1} GB used {:.1}%",
                    doctor.available_gb, doctor.used_percent
                );
            }
        }
        thread::sleep(Duration::from_secs(sleep_secs));
    }
}

fn handle_restore(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("brctl")
            .arg("download")
            .arg(path)
            .status()
            .map_err(|err| format!("failed to launch brctl: {err}"))?;
        if !status.success() {
            return Err(format!("brctl download failed for {}", path.display()));
        }
        println!("requested iCloud restore: {}", path.display());
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("storage restore is only supported on macOS".to_string())
    }
}

fn handle_doctor(json: bool) -> Result<(), String> {
    let report = doctor_report()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "storage doctor: health={} free={:.1} GB used={:.1}% profile={}",
            report.health_status, report.available_gb, report.used_percent, report.profile
        );
        if let Some(reason) = report.health_reason.as_deref() {
            println!("reason: {reason}");
        }
    }
    Ok(())
}

fn handle_policy(json: bool) -> Result<(), String> {
    let report = policy_report();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "storage policy: profile={} warn={} GB critical={} GB interval={}s",
            report.profile,
            report.warn_free_space_gb,
            report.critical_free_space_gb,
            report.monitor_interval_secs
        );
    }
    Ok(())
}

fn handle_install(uninstall: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let home = home_dir();
        let launch_agents_dir = home.join("Library").join("LaunchAgents");
        let plist_path = launch_agents_dir.join("com.ziros.storage-guardian.plist");
        fs::create_dir_all(&launch_agents_dir)
            .map_err(|err| format!("failed to create {}: {err}", launch_agents_dir.display()))?;
        fs::create_dir_all(home.join(".zkf").join("storage"))
            .map_err(|err| format!("failed to create ~/.zkf/storage: {err}"))?;
        fs::create_dir_all(home.join(".zkf").join("logs"))
            .map_err(|err| format!("failed to create ~/.zkf/logs: {err}"))?;

        let _ = Command::new("launchctl")
            .arg("unload")
            .arg(&plist_path)
            .status();

        if uninstall {
            if plist_path.exists() {
                fs::remove_file(&plist_path)
                    .map_err(|err| format!("failed to remove {}: {err}", plist_path.display()))?;
            }
            println!("removed launchd storage guardian: {}", plist_path.display());
            return Ok(());
        }

        let plist = render_launchd_plist(LAUNCHD_TEMPLATE, &which_zkf_cli()?, &home);
        fs::write(&plist_path, plist)
            .map_err(|err| format!("failed to write {}: {err}", plist_path.display()))?;

        let status = Command::new("launchctl")
            .arg("load")
            .arg(&plist_path)
            .status()
            .map_err(|err| format!("failed to launch launchctl: {err}"))?;
        if !status.success() {
            return Err(format!("launchctl load failed for {}", plist_path.display()));
        }
        println!("installed launchd storage guardian: {}", plist_path.display());
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = uninstall;
        Err("storage install is only supported on macOS".to_string())
    }
}

fn status_report() -> Result<StorageStatusReport, String> {
    let repo_root = repo_root();
    let home = home_dir();
    let health = get_ssd_health().map_err(|err| err.to_string())?;
    let build_cache = BuildCacheReport {
        target_local_debug_bytes: path_size(&repo_root.join("target-local").join("debug")),
        target_local_kani_bytes: path_size(&repo_root.join("target-local").join("kani")),
        target_debug_bytes: path_size(&repo_root.join("target").join("debug")),
        target_local_release_bytes: path_size(&repo_root.join("target-local").join("release")),
    };
    let runtime_state = RuntimeStateReport {
        telemetry_bytes: path_size(&home.join(".zkf").join("telemetry")),
        models_bytes: path_size(&home.join(".zkf").join("models")),
        swarm_bytes: path_size(&home.join(".zkf").join("swarm")),
    };
    let showcase_roots = collect_showcase_roots(&home);
    let showcase = ShowcaseUsage {
        root_count: showcase_roots.len(),
        total_bytes: showcase_roots.iter().map(|path| path_size(path)).sum(),
        roots: showcase_roots
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    };
    let expected_archive_root = expected_icloud_archive_root(&home);
    let icloud_root = icloud_archive_root().unwrap_or_else(|| expected_archive_root.clone());
    let archivable_paths =
        collect_archivable_paths(&repo_root, &home).map_err(|err| err.to_string())?;
    let ephemeral_paths =
        collect_ephemeral_paths(&repo_root, &home, false).map_err(|err| err.to_string())?;
    let recoverable_bytes = archivable_paths
        .iter()
        .chain(ephemeral_paths.iter())
        .map(|path| path_size(path))
        .sum();

    Ok(StorageStatusReport {
        health_status: health.health_status.as_str().to_string(),
        health_reason: health.health_status.reason().map(|value| value.to_string()),
        capacity_gb: bytes_to_gb(health.capacity_bytes),
        available_gb: bytes_to_gb(health.available_bytes),
        used_percent: health.used_percent,
        build_cache,
        runtime_state,
        showcase,
        icloud_archive: ICloudArchiveReport {
            enabled: StorageGuardianConfig::from_env().icloud_archive_enabled,
            available: icloud_root.exists(),
            path: icloud_root.display().to_string(),
            archived_bytes: current_icloud_archive_bytes(),
        },
        recoverable_bytes,
        recoverable_gb: bytes_to_gb(recoverable_bytes),
    })
}

fn archive_report(dry_run: bool) -> Result<ArchiveCommandReport, String> {
    let config = StorageGuardianConfig::from_env();
    if !config.icloud_archive_enabled {
        return Err("iCloud archive is disabled by configuration".to_string());
    }

    let repo_root = repo_root();
    let home = home_dir();
    let archive_root = archive_root_for_mode(dry_run, &home)?;
    let mut files = collect_archivable_paths(&repo_root, &home).map_err(|err| err.to_string())?;
    files.sort();

    let mut report = ArchiveCommandReport {
        files_archived: 0,
        bytes_archived: 0,
        archive_root: archive_root.display().to_string(),
        archived_paths: Vec::new(),
        dry_run,
    };

    for path in files {
        if classify_path(&path) != FileClass::Archivable {
            continue;
        }
        let run_name = archive_run_name(&path, &home);
        let archived = archive_file(&path, FileClass::Archivable, &run_name, &archive_root, dry_run)
            .map_err(|err| err.to_string())?;
        report.files_archived += 1;
        report.bytes_archived += path_size(&path);
        report.archived_paths.push(archived.display().to_string());
    }

    Ok(report)
}

fn doctor_report() -> Result<StorageDoctorReport, String> {
    let config = StorageGuardianConfig::from_env();
    let health = get_ssd_health().map_err(|err| err.to_string())?;
    Ok(StorageDoctorReport {
        device_name: health.device_name,
        model: health.model,
        serial: health.serial,
        firmware: health.firmware,
        capacity_gb: bytes_to_gb(health.capacity_bytes),
        used_gb: bytes_to_gb(health.used_bytes),
        available_gb: bytes_to_gb(health.available_bytes),
        used_percent: health.used_percent,
        wear_level_percent: health.wear_level_percent,
        temperature_celsius: health.temperature_celsius,
        power_on_hours: health.power_on_hours,
        smart_available: health.smart_available,
        health_status: health.health_status.as_str().to_string(),
        health_reason: health.health_status.reason().map(|value| value.to_string()),
        profile: config.profile.as_str().to_string(),
        warn_free_space_gb: config.warn_free_space_gb,
        critical_free_space_gb: config.critical_free_space_gb,
        icloud_archived_bytes: current_icloud_archive_bytes(),
    })
}

fn policy_report() -> StoragePolicyReport {
    let config = StorageGuardianConfig::from_env();
    StoragePolicyReport {
        enabled: config.enabled,
        icloud_archive_enabled: config.icloud_archive_enabled,
        profile: config.profile.as_str().to_string(),
        warn_free_space_gb: config.warn_free_space_gb,
        critical_free_space_gb: config.critical_free_space_gb,
        monitor_interval_secs: config.monitor_interval_secs,
        auto_archive_proofs: config.auto_archive_proofs,
        auto_archive_telemetry: config.auto_archive_telemetry,
        auto_purge_debug_cache: config.auto_purge_debug_cache,
        purge_witness_after_prove: config.purge_witness_after_prove,
        dry_run: config.dry_run,
        storage_root: config.storage_root.display().to_string(),
        log_path: config.log_path.display().to_string(),
    }
}

fn archive_root_for_mode(dry_run: bool, home: &Path) -> Result<PathBuf, String> {
    if let Some(path) = icloud_archive_root() {
        return Ok(path);
    }
    if dry_run {
        return Ok(expected_icloud_archive_root(home));
    }
    Err("iCloud Drive is not available at ~/Library/Mobile Documents/com~apple~CloudDocs/ZirOS_Archive".to_string())
}

fn archive_run_name(path: &Path, home: &Path) -> String {
    let timestamp = current_utc_timestamp();
    let normalized = path.to_string_lossy().replace('\\', "/");
    let telemetry_root = home.join(".zkf").join("telemetry");
    if normalized.starts_with(&telemetry_root.to_string_lossy().replace('\\', "/")) {
        return timestamp[..8].to_string();
    }

    let app_name = path
        .ancestors()
        .filter_map(|ancestor| ancestor.file_name().and_then(|value| value.to_str()))
        .find(|name| {
            name.starts_with("ZirOS_")
                || name.starts_with("ziros-")
                || name.starts_with("swarm_")
                || name.starts_with("reentry_")
        })
        .unwrap_or("run");
    format!("{}_{}", sanitize_run_name(app_name), timestamp)
}

fn sanitize_run_name(value: &str) -> String {
    value.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => ch,
            _ => '_',
        })
        .collect()
}

fn render_launchd_plist(template: &str, zkf_cli_path: &Path, home: &Path) -> String {
    template
        .replace("__ZKF_CLI_PATH__", &zkf_cli_path.display().to_string())
        .replace("__HOME__", &home.display().to_string())
}

fn which_zkf_cli() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|err| format!("failed to resolve current executable: {err}"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn expected_icloud_archive_root(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Mobile Documents")
        .join("com~apple~CloudDocs")
        .join("ZirOS_Archive")
}

fn bytes_to_gb(bytes: u64) -> f64 {
    bytes as f64 / 1_000_000_000.0
}

fn path_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    directory_size_bytes(path)
        .unwrap_or_else(|_| path.metadata().map(|metadata| metadata.len()).unwrap_or_default())
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes_to_gb(bytes))
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::{archive_run_name, render_launchd_plist};
    use std::path::Path;

    #[test]
    fn archive_run_name_uses_showcase_directory_name() {
        let home = Path::new("/Users/test");
        let value = archive_run_name(
            Path::new("/Users/test/Desktop/ZirOS_PoweredDescent/output/demo.proof.json"),
            home,
        );
        assert!(value.starts_with("ZirOS_PoweredDescent_"));
    }

    #[test]
    fn launchd_template_substitutes_placeholders() {
        let rendered = render_launchd_plist(
            "Program=__ZKF_CLI_PATH__\nHome=__HOME__\n",
            Path::new("/tmp/zkf-cli"),
            Path::new("/Users/test"),
        );
        assert!(rendered.contains("/tmp/zkf-cli"));
        assert!(rendered.contains("/Users/test"));
    }
}
