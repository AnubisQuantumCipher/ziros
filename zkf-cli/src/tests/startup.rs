// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

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
    ));
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf")),
        None,
        Some(marker_path.as_path()),
    ));
    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
        Some(marker_path.as_path()),
    ));

    crate::persist_ziros_first_run_marker(Some(marker_path.as_path()));
    assert!(marker_path.exists());
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        Some(marker_path.as_path()),
    ));
    assert!(!crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
        Some(marker_path.as_path()),
    ));

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn should_emit_ziros_banner_without_marker_path() {
    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("ziros")),
        None,
        None,
    ));
    assert!(crate::should_emit_ziros_first_run_banner(
        Some(OsStr::new("zkf-cli")),
        Some(OsStr::new("1")),
        None,
    ));
}
