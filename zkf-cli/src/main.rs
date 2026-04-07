mod benchmark;
mod cli;
mod cmd;
mod compose;
mod package_io;
#[cfg(all(feature = "metal-gpu", target_os = "macos"))]
mod runtime_metal;
mod solidity;
mod types;
mod util;

use clap::Parser;
use cli::Cli;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use types::*;
use zkf_runtime::{EntrypointGuard, EntrypointSurface, RuntimeSecurityContext};

const ZIROS_FIRST_RUN_BANNER: &str = "Welcome to ZirOS. Prove thou wilt.";
const ZIROS_FIRST_RUN_MARKER_FILE: &str = "ziros-first-run-v1";
const ZIROS_INVOKED_AS_ENV: &str = "ZIROS_INVOKED_AS";
const DEFAULT_CLI_STACK_BYTES: usize = 1024 * 1024 * 1024;

fn main() -> ExitCode {
    #[cfg(not(target_arch = "wasm32"))]
    {
        zkf_backends::init_accelerators();
        zkf_backends::harden_accelerators_for_current_pressure();
    }

    maybe_emit_ziros_first_run_banner();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            observe_cli_parse_failure(&err.to_string());
            let _ = err.print();
            return ExitCode::from(err.exit_code() as u8);
        }
    };

    match run_on_cli_stack(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if let Some(raw) = util::raw_cli_error_payload(&err) {
                eprintln!("{raw}");
            } else {
                eprintln!("error: {err}");
            }
            ExitCode::from(1)
        }
    }
}

fn observe_cli_parse_failure(detail: &str) {
    let guard = EntrypointGuard::begin(
        EntrypointSurface::Cli,
        format!("parse:{}", raw_cli_invocation_label()),
    );
    let _ = guard.finish(
        RuntimeSecurityContext {
            caller_class: Some("cli".to_string()),
            ..RuntimeSecurityContext::default()
        },
        false,
        Some(2),
        Some(detail.to_string()),
    );
}

fn raw_cli_invocation_label() -> String {
    let mut args = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with('-'))
        .take(2)
        .collect::<Vec<_>>();
    if args.is_empty() {
        return "root".to_string();
    }
    if args.len() == 2 {
        format!("{}-{}", args.remove(0), args.remove(0))
    } else {
        args.remove(0)
    }
}

fn run(cli: Cli) -> Result<(), String> {
    cmd::handle(cli.command, cli.allow_compat)
}

fn cli_stack_bytes() -> usize {
    std::env::var("ZKF_CLI_STACK_BYTES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|bytes| *bytes >= 8 * 1024 * 1024)
        .unwrap_or(DEFAULT_CLI_STACK_BYTES)
}

fn run_on_cli_stack(cli: Cli) -> Result<(), String> {
    let stack_bytes = cli_stack_bytes();
    let handle = thread::Builder::new()
        .name("ziros-cli".to_string())
        .stack_size(stack_bytes)
        .spawn(move || run(cli))
        .map_err(|err| format!("failed to spawn CLI worker thread: {err}"))?;

    match handle.join() {
        Ok(result) => result,
        Err(payload) => {
            let reason = if let Some(message) = payload.downcast_ref::<&'static str>() {
                (*message).to_string()
            } else if let Some(message) = payload.downcast_ref::<String>() {
                message.clone()
            } else {
                "unknown panic payload".to_string()
            };
            Err(format!(
                "CLI worker thread panicked on a {stack_bytes}-byte stack: {reason}"
            ))
        }
    }
}

pub(crate) fn maybe_emit_ziros_first_run_banner() {
    let argv0 = std::env::args_os().next();
    let env_flag = std::env::var_os(ZIROS_INVOKED_AS_ENV);
    let marker_path = ziros_first_run_marker_path();
    if !should_emit_ziros_first_run_banner(
        argv0.as_deref(),
        env_flag.as_deref(),
        marker_path.as_deref(),
    ) {
        return;
    }
    println!("{ZIROS_FIRST_RUN_BANNER}");
    persist_ziros_first_run_marker(marker_path.as_deref());
}

pub(crate) fn should_emit_ziros_first_run_banner(
    argv0: Option<&OsStr>,
    env_flag: Option<&OsStr>,
    marker_path: Option<&Path>,
) -> bool {
    if !ziros_invocation_requested(argv0, env_flag) {
        return false;
    }
    match marker_path {
        Some(path) => !path.exists(),
        None => true,
    }
}

pub(crate) fn invoked_as_ziros(argv0: Option<&OsStr>) -> bool {
    argv0
        .and_then(|value| Path::new(value).file_name())
        .is_some_and(|value| value == "ziros")
}

pub(crate) fn ziros_invocation_requested(argv0: Option<&OsStr>, env_flag: Option<&OsStr>) -> bool {
    invoked_as_ziros(argv0)
        || env_flag
            .and_then(OsStr::to_str)
            .is_some_and(|value| value == "1")
}

pub(crate) fn ziros_first_run_marker_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".zkf")
            .join("state")
            .join(ZIROS_FIRST_RUN_MARKER_FILE)
    })
}

pub(crate) fn persist_ziros_first_run_marker(path: Option<&Path>) {
    let Some(path) = path else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, b"seen\n");
}

#[cfg(test)]
mod tests;
