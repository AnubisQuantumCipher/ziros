use std::env;
use std::fs;
use std::path::PathBuf;
use zkf_lib::{
    BackendKind, PRIVATE_TURBINE_BLADE_DEFAULT_STEPS, PrivateTurbineBladeExportConfig,
    PrivateTurbineBladeExportProfile, ZkfError, ZkfResult, parse_backend_selection,
    run_private_turbine_blade_export,
};

fn output_dir() -> PathBuf {
    env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string()))
            .join("Desktop/ZirOS_Private_Turbine_Blade_Life")
    })
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn integration_steps() -> ZkfResult<usize> {
    match env::var("ZKF_PRIVATE_TURBINE_BLADE_STEPS_OVERRIDE") {
        Ok(raw) => {
            let steps = raw.parse::<usize>().map_err(|error| {
                ZkfError::Backend(format!(
                    "parse ZKF_PRIVATE_TURBINE_BLADE_STEPS_OVERRIDE={raw:?}: {error}"
                ))
            })?;
            if steps == 0 {
                return Err(ZkfError::Backend(
                    "ZKF_PRIVATE_TURBINE_BLADE_STEPS_OVERRIDE must be greater than zero"
                        .to_string(),
                ));
            }
            Ok(steps)
        }
        Err(env::VarError::NotPresent) => Ok(PRIVATE_TURBINE_BLADE_DEFAULT_STEPS),
        Err(error) => Err(ZkfError::Backend(format!(
            "read ZKF_PRIVATE_TURBINE_BLADE_STEPS_OVERRIDE: {error}"
        ))),
    }
}

fn export_profile() -> ZkfResult<PrivateTurbineBladeExportProfile> {
    let raw =
        env::var("ZKF_PRIVATE_TURBINE_BLADE_PROFILE").unwrap_or_else(|_| "flagship".to_string());
    PrivateTurbineBladeExportProfile::parse(&raw)
}

fn primary_backend_selection() -> ZkfResult<zkf_backends::BackendSelection> {
    let requested = env::var("ZKF_PRIVATE_TURBINE_BLADE_PRIMARY_BACKEND")
        .unwrap_or_else(|_| "arkworks-groth16".to_string());
    let selection = parse_backend_selection(&requested)
        .map_err(|error| ZkfError::Backend(error.to_string()))?;
    if !matches!(
        selection.backend,
        BackendKind::HyperNova | BackendKind::ArkworksGroth16
    ) {
        return Err(ZkfError::Backend(format!(
            "primary turbine showcase backend must resolve to hypernova or arkworks-groth16, got {}",
            selection.requested_name
        )));
    }
    Ok(selection)
}

fn main() -> ZkfResult<()> {
    let out_dir = output_dir();
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;
    let report_path = run_private_turbine_blade_export(PrivateTurbineBladeExportConfig {
        out_dir,
        steps: integration_steps()?,
        profile: export_profile()?,
        primary_backend: primary_backend_selection()?,
        full_audit_requested: env_flag("ZKF_PRIVATE_TURBINE_BLADE_FULL_AUDIT"),
        optional_cloudfs_requested: env_flag("ZKF_PRIVATE_TURBINE_BLADE_CLOUDFS"),
        distributed_plan_requested: env_flag("ZKF_PRIVATE_TURBINE_BLADE_DISTRIBUTED"),
    })?;
    println!("{}", report_path.display());
    Ok(())
}
