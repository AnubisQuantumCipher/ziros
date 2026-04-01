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

use crate::util::parse_backend;
use std::path::{Path, PathBuf};

/// Handle `zkf conformance`: run the conformance test suite against a backend.
pub(crate) fn handle_conformance(
    backend: String,
    json: bool,
    export_json: Option<PathBuf>,
    export_cbor: Option<PathBuf>,
) -> Result<(), String> {
    let backend_kind = parse_backend(&backend)?;
    let report = zkf_conformance::run_conformance(backend_kind);
    maybe_export_conformance_artifacts(&report, export_json.as_deref(), export_cbor.as_deref())?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("Conformance Report");
        println!("==================");
        println!("Backend:      {}", report.backend);
        println!("Field:        {}", report.field);
        println!("Tests run:    {}", report.tests_run);
        println!("Passed:       {}", report.tests_passed);
        println!("Failed:       {}", report.tests_failed);
        println!("Pass rate:    {:.1}%", report.pass_rate * 100.0);
        println!();

        println!(
            "  {:<24} {:<10} {:<10} {:<10} {:<10} error",
            "test", "compile", "prove", "verify", "time_ms"
        );
        println!("  {}", "-".repeat(80));
        for r in &report.results {
            let status = |ok: bool| if ok { "ok" } else { "FAIL" };
            println!(
                "  {:<24} {:<10} {:<10} {:<10} {:<10} {}",
                r.test_name,
                status(r.compile_ok),
                status(r.prove_ok),
                status(r.verify_ok),
                r.total_time_ms,
                r.error.as_deref().unwrap_or("-"),
            );
        }

        if let Some(path) = export_json.as_deref() {
            println!("exported conformance JSON: {}", path.display());
        }
        if let Some(path) = export_cbor.as_deref() {
            println!("exported conformance CBOR: {}", path.display());
        }

        if report.tests_failed > 0 {
            return Err(format!(
                "conformance: {} of {} tests failed for {}",
                report.tests_failed, report.tests_run, backend
            ));
        } else {
            println!("\nAll conformance tests passed.");
        }
    }
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct VersionedConformanceArtifact<'a> {
    schema_version: &'static str,
    backend: &'a str,
    exported_at_unix_s: u64,
    report: &'a zkf_conformance::ConformanceReport,
}

fn maybe_export_conformance_artifacts(
    report: &zkf_conformance::ConformanceReport,
    export_json: Option<&Path>,
    export_cbor: Option<&Path>,
) -> Result<(), String> {
    if export_json.is_none() && export_cbor.is_none() {
        return Ok(());
    }

    let exported_at_unix_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("failed to derive export timestamp: {e}"))?
        .as_secs();
    let artifact = VersionedConformanceArtifact {
        schema_version: "zkf-conformance-report/v1",
        backend: &report.backend,
        exported_at_unix_s,
        report,
    };

    if let Some(path) = export_json {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create '{}': {e}", parent.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(&artifact)
            .map_err(|e| format!("failed to serialize conformance JSON: {e}"))?;
        std::fs::write(path, bytes)
            .map_err(|e| format!("failed to write '{}': {e}", path.display()))?;
    }

    if let Some(path) = export_cbor {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create '{}': {e}", parent.display()))?;
        }
        let bytes = serde_cbor::to_vec(&artifact)
            .map_err(|e| format!("failed to serialize conformance CBOR: {e}"))?;
        std::fs::write(path, bytes)
            .map_err(|e| format!("failed to write '{}': {e}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> zkf_conformance::ConformanceReport {
        zkf_conformance::ConformanceReport {
            backend: "arkworks-groth16".to_string(),
            field: "Bn254".to_string(),
            tests_run: 1,
            tests_passed: 1,
            tests_failed: 0,
            pass_rate: 1.0,
            results: vec![zkf_conformance::ConformanceTestResult {
                test_name: "smoke".to_string(),
                backend: "arkworks-groth16".to_string(),
                compile_ok: true,
                prove_ok: true,
                verify_ok: true,
                total_time_ms: 1,
                error: None,
                compile_error: None,
                prove_error: None,
                verify_error: None,
                public_outputs: None,
            }],
        }
    }

    #[test]
    fn conformance_export_writes_json_and_cbor() {
        let root =
            std::env::temp_dir().join(format!("zkf-conformance-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let json_path = root.join("report.json");
        let cbor_path = root.join("report.cbor");

        maybe_export_conformance_artifacts(&sample_report(), Some(&json_path), Some(&cbor_path))
            .unwrap();

        assert!(json_path.exists());
        assert!(cbor_path.exists());
        let json = std::fs::read_to_string(&json_path).unwrap();
        assert!(json.contains("zkf-conformance-report/v1"));
        let cbor = std::fs::read(&cbor_path).unwrap();
        assert!(!cbor.is_empty());
    }
}
