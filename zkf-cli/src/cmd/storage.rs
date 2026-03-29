use std::fs;
use std::path::PathBuf;
use std::process::Command;

use zkf_storage::{self, StorageStatusReport};

pub(crate) fn handle_storage(command: crate::cli::StorageCommands) -> Result<(), String> {
    match command {
        crate::cli::StorageCommands::Status { json } => handle_status(json),
        crate::cli::StorageCommands::MigrateToIcloud => handle_migrate_to_icloud(),
        crate::cli::StorageCommands::Warm => handle_warm(),
        crate::cli::StorageCommands::Evict => handle_evict(),
        crate::cli::StorageCommands::Install => handle_install(),
    }
}

fn handle_status(json: bool) -> Result<(), String> {
    let report = zkf_storage::status().map_err(|err| err.to_string())?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
        return Ok(());
    }

    render_status(&report);
    Ok(())
}

fn render_status(report: &StorageStatusReport) {
    println!(
        "storage status: mode={} sync={} cache={} bytes keys={}",
        report.mode,
        report.sync_state,
        report.local_cache_usage_bytes,
        report.key_count
    );
    println!("persistent root: {}", report.persistent_root);
    println!("cache root: {}", report.cache_root);
    println!("swarm sqlite live: {}", report.swarm_sqlite_live_path);
    println!("swarm sqlite snapshot: {}", report.swarm_sqlite_snapshot_path);
}

fn handle_migrate_to_icloud() -> Result<(), String> {
    let report = zkf_storage::migrate().map_err(|err| err.to_string())?;
    if !report.conflicts.is_empty() {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
        return Err("migration halted due to destination conflicts".to_string());
    }

    println!(
        "migrated to iCloud-native mode: moved={} deduplicated={} pointer={}",
        report.moved.len(),
        report.deduplicated.len(),
        report.pointer_file
    );
    Ok(())
}

fn handle_warm() -> Result<(), String> {
    let report = zkf_storage::warm().map_err(|err| err.to_string())?;
    println!("prefetched {} path(s)", report.prefetched.len());
    for path in report.prefetched {
        println!("{path}");
    }
    Ok(())
}

fn handle_evict() -> Result<(), String> {
    let report = zkf_storage::evict().map_err(|err| err.to_string())?;
    println!("evicted {} cached path(s)", report.evicted.len());
    for path in report.evicted {
        println!("{path}");
    }
    Ok(())
}

fn handle_install() -> Result<(), String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    fs::create_dir_all(home.join(".zkf").join("cache")).map_err(|err| err.to_string())?;
    fs::create_dir_all(home.join(".zkf").join("logs")).map_err(|err| err.to_string())?;

    let cli_path = std::env::current_exe().map_err(|err| err.to_string())?;
    let report = zkf_storage::install(&cli_path).map_err(|err| err.to_string())?;

    #[cfg(target_os = "macos")]
    {
        let plist_path = PathBuf::from(&report.plist_path);
        let _ = Command::new("launchctl")
            .arg("unload")
            .arg(&plist_path)
            .status();
        let status = Command::new("launchctl")
            .arg("load")
            .arg(&plist_path)
            .status()
            .map_err(|err| err.to_string())?;
        if !status.success() {
            return Err(format!(
                "launchctl load failed for {} with status {status}",
                plist_path.display()
            ));
        }
    }

    println!(
        "installed storage guardian: plist={} cli={}",
        report.plist_path, report.cli_path
    );
    Ok(())
}
