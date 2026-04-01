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

use std::path::PathBuf;
use std::process::Command;

pub(crate) fn handle_stats(dir: Option<PathBuf>, json: bool) -> Result<(), String> {
    let stats = match dir.as_deref() {
        Some(path) => zkf_runtime::telemetry_collector::telemetry_corpus_stats_for_dir(path),
        None => zkf_runtime::telemetry_collector::telemetry_corpus_stats(),
    }
    .map_err(|err| format!("failed to summarize telemetry corpus: {err}"))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&stats).map_err(|err| err.to_string())?
        );
    } else {
        println!("schema: {}", stats.schema);
        println!("directory: {}", stats.directory);
        println!("records: {}", stats.record_count);
        println!("corpus_hash: {}", stats.corpus_hash);
    }
    Ok(())
}

pub(crate) fn handle_export(
    input: Vec<String>,
    out: Option<PathBuf>,
    json: bool,
) -> Result<(), String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let script = root.join("scripts/export_anonymized_telemetry.py");
    if !script.exists() {
        return Err(format!("export script not found at {}", script.display()));
    }

    let default_out = default_model_dir().join("telemetry_anonymized.jsonl");
    let dest = out.unwrap_or(default_out);

    let mut args = vec!["--out".to_string(), dest.display().to_string()];
    for path in &input {
        args.push("--input".to_string());
        args.push(path.clone());
    }

    let output = Command::new("python3")
        .arg(&script)
        .args(&args)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to launch {}: {err}", script.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() {
        return Err(format!(
            "{} exited with status {}{}{}",
            script.display(),
            output.status,
            if stdout.is_empty() { "" } else { "\nstdout:\n" },
            if stdout.is_empty() {
                stderr
            } else if stderr.is_empty() {
                stdout
            } else {
                format!("{stdout}\n\nstderr:\n{stderr}")
            }
        ));
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": dest,
                "stdout": stdout,
            }))
            .map_err(|err| err.to_string())?
        );
    } else if !stdout.is_empty() {
        println!("{stdout}");
    } else {
        println!("exported anonymized telemetry -> {}", dest.display());
    }
    Ok(())
}

fn default_model_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("models")
}
