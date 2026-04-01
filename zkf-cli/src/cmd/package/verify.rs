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

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use zkf_core::{PACKAGE_SCHEMA_VERSION, PackageFileRef, PackageManifest};

use crate::util::{
    WitnessRequirement, parse_witness_requirement, program_digest_matches_manifest, read_json,
    sha256_hex, validate_compose_proof_file, validate_compose_report_file,
    validate_v2_manifest_metadata, validate_v2_run_report, write_json, write_json_and_hash,
};

pub(crate) fn migrate_package_manifest(
    manifest_path: &Path,
    from: &str,
    to: &str,
) -> Result<crate::PackageMigrateReport, String> {
    let from_version = from
        .trim_start_matches('v')
        .parse::<u32>()
        .map_err(|_| format!("invalid --from version '{from}'"))?;
    let to_version = to
        .trim_start_matches('v')
        .parse::<u32>()
        .map_err(|_| format!("invalid --to version '{to}'"))?;
    if from_version < 1 || to_version > PACKAGE_SCHEMA_VERSION || from_version >= to_version {
        return Err(format!(
            "only forward migrations within v1..=v{} are supported (requested v{} -> v{})",
            PACKAGE_SCHEMA_VERSION, from_version, to_version
        ));
    }

    let mut manifest_value: Value = read_json(manifest_path)?;
    let detected_version = manifest_value
        .get("schema_version")
        .and_then(Value::as_u64)
        .unwrap_or(1) as u32;
    if detected_version != from_version {
        return Err(format!(
            "manifest schema version mismatch: expected v{}, found v{}",
            from_version, detected_version
        ));
    }
    manifest_value["schema_version"] = Value::from(to_version as u64);

    let mut manifest: PackageManifest = serde_json::from_value(manifest_value)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    let mut warnings = Vec::new();
    let mut updated_files = 1usize;

    let legacy_requirement = manifest
        .metadata
        .get("witness_requirement")
        .and_then(|value| parse_witness_requirement(value));
    let requires_hints = manifest
        .metadata
        .get("requires_hints")
        .is_some_and(|value| value == "true");
    let requires_execution = legacy_requirement == Some(WitnessRequirement::Execution)
        || manifest
            .metadata
            .get("requires_execution")
            .is_some_and(|value| value == "true")
        || requires_hints;
    let requires_solver = legacy_requirement == Some(WitnessRequirement::Solver)
        || manifest
            .metadata
            .get("requires_solver")
            .is_some_and(|value| value == "true");
    manifest.metadata.insert(
        "requires_execution".to_string(),
        requires_execution.to_string(),
    );
    manifest
        .metadata
        .insert("requires_solver".to_string(), requires_solver.to_string());
    manifest
        .metadata
        .entry("ir_family".to_string())
        .or_insert_with(|| "ir-v2".to_string());
    manifest
        .metadata
        .entry("ir_version".to_string())
        .or_insert_with(|| "2".to_string());
    manifest
        .metadata
        .entry("strict_mode".to_string())
        .or_insert_with(|| "true".to_string());
    manifest
        .metadata
        .insert("allow_builtin_fallback".to_string(), "false".to_string());

    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let mut migrate_run_report = |file_ref: &PackageFileRef| -> Result<(), String> {
        let path = root.join(&file_ref.path);
        if !path.exists() {
            warnings.push(format!(
                "run report path '{}' does not exist during migration",
                file_ref.path
            ));
            return Ok(());
        }
        let mut report: Value = read_json(&path)?;
        if let Some(obj) = report.as_object_mut() {
            obj.insert(
                "requires_execution".to_string(),
                Value::from(requires_execution),
            );
            obj.insert("requires_solver".to_string(), Value::from(requires_solver));
            if obj.get("solver_path").is_none()
                && let Some(solver) = obj.get("solver").and_then(Value::as_str)
            {
                obj.insert("solver_path".to_string(), Value::from(solver));
            }
            if obj.get("solver_path").is_none() {
                obj.insert("solver_path".to_string(), Value::from("unknown"));
            }
            if obj.get("execution_path").is_none() {
                let execution_path = obj
                    .get("solver_path")
                    .and_then(Value::as_str)
                    .map(|solver_path| {
                        if solver_path.starts_with("frontend/") {
                            "frontend-execute"
                        } else if solver_path == "builtin" {
                            "builtin-fallback"
                        } else if solver_path == "acvm" || solver_path == "acvm-beta9" {
                            "solver-fallback"
                        } else {
                            "explicit-solver"
                        }
                    })
                    .unwrap_or("explicit-solver");
                obj.insert("execution_path".to_string(), Value::from(execution_path));
            }
            obj.remove("witness_requirement");
            let sha = write_json_and_hash(&path, &report)?;
            if file_ref.sha256 != sha {
                updated_files += 1;
            }
        } else {
            warnings.push(format!(
                "run report '{}' was not a JSON object; skipped field migration",
                file_ref.path
            ));
        }
        Ok(())
    };

    if let Some(run_report) = manifest.files.run_report.as_mut() {
        migrate_run_report(run_report)?;
        let path = root.join(&run_report.path);
        if path.exists() {
            run_report.sha256 = sha256_hex(
                fs::read(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?
                    .as_slice(),
            );
        }
    }
    for run in manifest.runs.values_mut() {
        migrate_run_report(&run.run_report)?;
        let path = root.join(&run.run_report.path);
        if path.exists() {
            run.run_report.sha256 = sha256_hex(
                fs::read(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?
                    .as_slice(),
            );
        }
    }

    write_json(manifest_path, &manifest)?;
    Ok(crate::PackageMigrateReport {
        manifest: manifest_path.display().to_string(),
        from_version,
        to_version,
        updated_files,
        warnings,
    })
}

pub(crate) fn verify_package_manifest(
    manifest_path: &Path,
) -> Result<crate::PackageVerifyReport, String> {
    let manifest: PackageManifest = read_json(manifest_path)?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;

    let mut checks = Vec::new();
    let mut all_hashes_match = true;
    let mut warnings = Vec::new();
    if manifest.schema_version != PACKAGE_SCHEMA_VERSION {
        warnings.push(format!(
            "manifest schema version is v{}, expected v{}; run `zkf package migrate --manifest {} --from {} --to {}`",
            manifest.schema_version,
            PACKAGE_SCHEMA_VERSION,
            manifest_path.display(),
            manifest.schema_version,
            PACKAGE_SCHEMA_VERSION
        ));
    }
    let metadata_issues = validate_v2_manifest_metadata(&manifest);
    let metadata_valid = metadata_issues.is_empty();
    warnings.extend(metadata_issues);

    let mut verify_ref = |file: &PackageFileRef| -> Result<(), String> {
        let abs = root.join(&file.path);
        if !abs.exists() {
            all_hashes_match = false;
            checks.push(crate::PackageFileCheck {
                path: file.path.clone(),
                exists: false,
                hash_matches: false,
            });
            return Ok(());
        }

        let content = fs::read(&abs).map_err(|e| format!("{}: {e}", abs.display()))?;
        let actual = sha256_hex(&content);
        let hash_matches = actual == file.sha256;
        if !hash_matches {
            all_hashes_match = false;
        }
        checks.push(crate::PackageFileCheck {
            path: file.path.clone(),
            exists: true,
            hash_matches,
        });
        Ok(())
    };

    verify_ref(&manifest.files.program)?;
    verify_ref(&manifest.files.original_artifact)?;
    if let Some(file) = &manifest.files.translation_report {
        verify_ref(file)?;
    }
    if let Some(file) = &manifest.files.witness {
        verify_ref(file)?;
    }
    if let Some(file) = &manifest.files.public_inputs {
        verify_ref(file)?;
    }
    if let Some(file) = &manifest.files.run_report {
        verify_ref(file)?;
    }
    if let Some(file) = &manifest.files.abi {
        verify_ref(file)?;
    }
    if let Some(file) = &manifest.files.debug {
        verify_ref(file)?;
    }
    for file in manifest.files.replay_manifests.values() {
        verify_ref(file)?;
    }
    for run in manifest.runs.values() {
        verify_ref(&run.witness)?;
        verify_ref(&run.public_inputs)?;
        verify_ref(&run.run_report)?;
    }
    for file in manifest.files.compiled.values() {
        verify_ref(file)?;
    }
    let mut compose_artifacts_valid = true;
    for (key, file) in &manifest.files.proofs {
        verify_ref(file)?;
        if key.starts_with("compose-report/") {
            let issues = validate_compose_report_file(&root.join(&file.path), key)?;
            if !issues.is_empty() {
                compose_artifacts_valid = false;
                warnings.extend(issues);
            }
        } else if key.starts_with("compose-proof/") {
            let issues = validate_compose_proof_file(&root.join(&file.path), key)?;
            if !issues.is_empty() {
                compose_artifacts_valid = false;
                warnings.extend(issues);
            }
        }
    }

    let mut run_reports_valid = true;
    let mut checked_run_report_paths = BTreeSet::<String>::new();
    let mut verify_run_report = |file: &PackageFileRef| -> Result<(), String> {
        if !checked_run_report_paths.insert(file.path.clone()) {
            return Ok(());
        }
        let run_report_path = root.join(&file.path);
        let issues = validate_v2_run_report(&run_report_path)?;
        if !issues.is_empty() {
            run_reports_valid = false;
            warnings.extend(issues);
        }
        Ok(())
    };
    if let Some(file) = &manifest.files.run_report {
        verify_run_report(file)?;
    }
    for run in manifest.runs.values() {
        verify_run_report(&run.run_report)?;
    }

    let program_digest_match = match program_digest_matches_manifest(root, &manifest) {
        Ok(matches) => matches,
        Err(err) => {
            warnings.push(err);
            false
        }
    };

    let translator_provenance_valid = if manifest.frontend.translator.is_some() {
        if let Some(report_ref) = manifest.files.translation_report.as_ref() {
            let report_path = root.join(&report_ref.path);
            let report: Value = read_json(&report_path)?;
            report
                .get("translator_id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.trim().is_empty())
                && report
                    .get("source_noir_version")
                    .and_then(Value::as_str)
                    .is_some_and(|version| !version.trim().is_empty())
        } else {
            false
        }
    } else {
        true
    };

    if let Some(report_ref) = manifest.files.translation_report.as_ref() {
        let report_path = root.join(&report_ref.path);
        if report_path.exists() {
            let report: Value = read_json(&report_path)?;
            let lossy = report
                .get("lossy")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if lossy {
                warnings.push("translation report marked as lossy".to_string());
            }
            let requires_hints = report
                .get("requires_hints")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let has_witness_artifacts =
                manifest.files.witness.is_some() || !manifest.runs.is_empty();
            if requires_hints && !has_witness_artifacts {
                warnings.push(
                    "package requires hints but no witness artifact is present; run `zkf run`"
                        .to_string(),
                );
            }
        }
    }

    let ok = all_hashes_match
        && program_digest_match
        && translator_provenance_valid
        && metadata_valid
        && run_reports_valid
        && compose_artifacts_valid;
    Ok(crate::PackageVerifyReport {
        manifest: manifest_path.display().to_string(),
        ok,
        program_digest_match,
        translator_provenance_valid,
        checked_files: checks,
        warnings,
    })
}

pub(crate) fn handle_migrate(
    manifest: std::path::PathBuf,
    from: String,
    to: String,
    json: bool,
) -> Result<(), String> {
    let report = migrate_package_manifest(&manifest, &from, &to)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package migrate: {} v{} -> v{} (updated_files={})",
            report.manifest, report.from_version, report.to_version, report.updated_files
        );
    }
    Ok(())
}

pub(crate) fn handle_verify(manifest: std::path::PathBuf, json: bool) -> Result<(), String> {
    let report = verify_package_manifest(&manifest)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else if report.ok {
        println!(
            "package verification: OK (files_checked={}, digest_match={})",
            report.checked_files.len(),
            report.program_digest_match
        );
    } else {
        return Err("package verification: FAILED".to_string());
    }
    Ok(())
}
