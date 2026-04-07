use super::*;
use std::ffi::OsStr;

#[test]
fn invoked_as_ziros_matches_basename_only() {
    assert!(crate::invoked_as_ziros(Some(OsStr::new("ziros"))));
    assert!(crate::invoked_as_ziros(Some(OsStr::new("/tmp/bin/ziros"))));
    assert!(!crate::invoked_as_ziros(Some(OsStr::new("zkf"))));
    assert!(!crate::invoked_as_ziros(None));
}

#[test]
fn ziros_invocation_requested_accepts_wrapper_env_flag() {
    assert!(crate::ziros_invocation_requested(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
    ));
    assert!(crate::ziros_invocation_requested(
        Some(OsStr::new("ziros")),
        Some(OsStr::new("0")),
    ));
    assert!(!crate::ziros_invocation_requested(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("0")),
    ));
}

#[test]
fn should_emit_ziros_banner_only_for_first_ziros_run() {
    let temp_root = std::env::temp_dir().join(format!("zkf-startup-banner-{}", std::process::id()));
    let marker_path = temp_root.join("seen");
    let _ = fs::remove_dir_all(&temp_root);

    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        Some(marker_path.as_path()),
        &[],
        true,
    ));
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf")),
        None,
        Some(marker_path.as_path()),
        &[],
        true,
    ));
    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
        Some(marker_path.as_path()),
        &[],
        true,
    ));

    crate::persist_ziros_first_run_marker(Some(marker_path.as_path()));
    assert!(marker_path.exists());
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        Some(marker_path.as_path()),
        &[],
        true,
    ));
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
        Some(marker_path.as_path()),
        &[],
        true,
    ));

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn should_emit_ziros_banner_without_marker_path() {
    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        None,
        &[],
        true,
    ));
    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
        None,
        &[],
        true,
    ));
}

#[test]
fn should_suppress_ziros_banner_for_machine_surfaces() {
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        None,
        &[],
        false,
    ));
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        None,
        &[std::ffi::OsString::from("--json")],
        true,
    ));
}
