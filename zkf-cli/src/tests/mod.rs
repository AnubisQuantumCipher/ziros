use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use zkf_backends::backend_for;
use zkf_core::{
    BackendKind, Constraint, FieldElement, FieldId, PackageManifest, Program, ProofArtifact,
    StepMode, Witness, WitnessInputs, program_zir_to_v2,
};
use zkf_frontends::{FrontendInspection, FrontendKind};

use crate::cmd;
use crate::compose::*;
use crate::solidity::{render_groth16_solidity_verifier, render_sp1_solidity_verifier};
use crate::types::*;
use crate::util::*;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn with_temp_home_and_env<T>(extra_vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let mut entries = vec![
        ("HOME".to_string(), temp.path().as_os_str().to_os_string()),
        ("HOSTNAME".to_string(), OsString::from("swarm-cli-test")),
        ("ZKF_SWARM_KEY_BACKEND".to_string(), OsString::from("file")),
        (
            "ZKF_SECURITY_POLICY_MODE".to_string(),
            OsString::from("observe"),
        ),
    ];
    entries.extend(
        extra_vars
            .iter()
            .map(|(key, value)| (key.to_string(), OsString::from(value))),
    );
    let previous = entries
        .iter()
        .map(|(key, _)| (key.clone(), std::env::var_os(key)))
        .collect::<Vec<_>>();
    for (key, value) in &entries {
        unsafe {
            std::env::set_var(key, value);
        }
    }
    let result = f();
    for (key, value) in previous {
        unsafe {
            if let Some(value) = value {
                std::env::set_var(&key, value);
            } else {
                std::env::remove_var(&key);
            }
        }
    }
    result
}

fn run_package(
    manifest_path: &Path,
    inputs_path: &Path,
    run_id: &str,
    solver: Option<&str>,
) -> Result<RunResult, String> {
    cmd::witness::run_package(manifest_path, inputs_path, run_id, solver)
}

fn chain_step_inputs(
    base_inputs: &WitnessInputs,
    public_signal_names: &[String],
    public_inputs: &[FieldElement],
) -> Result<WitnessInputs, String> {
    cmd::package::fold::chain_step_inputs(base_inputs, public_signal_names, public_inputs)
}

fn chain_nova_ivc_input(
    base_inputs: &WitnessInputs,
    input_signal: &str,
    output_value: &FieldElement,
) -> WitnessInputs {
    cmd::package::fold::chain_nova_ivc_input(base_inputs, input_signal, output_value)
}

fn migrate_package_manifest(
    manifest_path: &Path,
    from: &str,
    to: &str,
) -> Result<PackageMigrateReport, String> {
    cmd::package::verify::migrate_package_manifest(manifest_path, from, to)
}

fn verify_package_manifest(manifest_path: &Path) -> Result<PackageVerifyReport, String> {
    cmd::package::verify::verify_package_manifest(manifest_path)
}

mod app;
mod audit;
mod circuit;
mod compact_integration;
mod composition;
mod core_util;
mod debug;
mod equivalence;
mod negative_paths;
mod midnight_platform;
mod package_bundle;
mod package_migrate;
mod package_prove;
mod package_run;
mod package_verify_metadata;
mod package_verify_run_execution;
mod package_verify_run_solver;
mod package_verify_zir;
mod package_zir;
mod startup;
mod swarm;
mod verify;
