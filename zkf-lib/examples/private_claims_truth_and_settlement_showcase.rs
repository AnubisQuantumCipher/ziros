use std::env;
use std::fs;
use std::path::PathBuf;
use zkf_lib::{
    BackendKind, PrivateClaimsTruthExportConfig, PrivateClaimsTruthExportProfile, ZkfError,
    ZkfResult, parse_backend_selection, run_private_claims_truth_export,
    run_private_claims_truth_hypernova_diagnostics,
};

fn output_dir() -> PathBuf {
    env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string()))
            .join("Desktop/ZirOS_Private_Claims_Truth_And_Settlement")
    })
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn export_profile() -> ZkfResult<PrivateClaimsTruthExportProfile> {
    let raw =
        env::var("ZKF_PRIVATE_CLAIMS_TRUTH_PROFILE").unwrap_or_else(|_| "flagship".to_string());
    PrivateClaimsTruthExportProfile::parse(&raw)
}

fn primary_backend_selection() -> ZkfResult<zkf_backends::BackendSelection> {
    let requested = env::var("ZKF_PRIVATE_CLAIMS_TRUTH_PRIMARY_BACKEND")
        .unwrap_or_else(|_| "hypernova".to_string());
    let selection = parse_backend_selection(&requested)
        .map_err(|error| ZkfError::Backend(error.to_string()))?;
    if !matches!(selection.backend, BackendKind::HyperNova) {
        return Err(ZkfError::Backend(format!(
            "claims truth showcase requires hypernova primary backend, got {}",
            selection.requested_name
        )));
    }
    Ok(selection)
}

fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ZkfResult<T> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(128 * 1024 * 1024)
        .spawn(f)
        .map_err(|error| ZkfError::Backend(format!("spawn {name} worker: {error}")))?;
    handle.join().map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else if let Some(message) = panic.downcast_ref::<String>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else {
            ZkfError::Backend(format!("{name} worker panicked"))
        }
    })?
}

fn run_export() -> ZkfResult<PathBuf> {
    let out_dir = output_dir();
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;
    run_private_claims_truth_export(PrivateClaimsTruthExportConfig {
        out_dir,
        profile: export_profile()?,
        primary_backend: primary_backend_selection()?,
        distributed_mode_requested: env_flag("ZKF_PRIVATE_CLAIMS_TRUTH_DISTRIBUTED"),
    })
}

fn main() -> ZkfResult<()> {
    if env_flag("ZKF_PRIVATE_CLAIMS_TRUTH_DIAGNOSTICS") {
        let diagnostics = run_with_large_stack_result(
            "private-claims-truth-diagnostics",
            run_private_claims_truth_hypernova_diagnostics,
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&diagnostics)
                .map_err(|error| ZkfError::Serialization(error.to_string()))?
        );
        return Ok(());
    }
    let report_path = run_with_large_stack_result("private-claims-truth-showcase", run_export)?;
    println!("{}", report_path.display());
    Ok(())
}
