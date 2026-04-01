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

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub(crate) struct RetrainArgs {
    pub(crate) input: Vec<String>,
    pub(crate) profile: String,
    pub(crate) model_dir: Option<PathBuf>,
    pub(crate) corpus_out: Option<PathBuf>,
    pub(crate) summary_out: Option<PathBuf>,
    pub(crate) manifest_out: Option<PathBuf>,
    pub(crate) threshold_out: Option<PathBuf>,
    pub(crate) skip_threshold_optimizer: bool,
    pub(crate) json: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn default_model_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("models")
}

fn run_python_script(
    root: &Path,
    script: &Path,
    args: &[String],
) -> Result<serde_json::Value, String> {
    let output = Command::new("python3")
        .arg(script)
        .args(args)
        .current_dir(root)
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
    Ok(serde_json::json!({
        "script": script.display().to_string(),
        "stdout": stdout,
        "stderr": stderr,
    }))
}

pub(crate) fn handle_retrain(args: RetrainArgs) -> Result<(), String> {
    if !matches!(args.profile.as_str(), "fixture" | "production") {
        return Err(format!(
            "unknown retrain profile '{}' (expected fixture or production)",
            args.profile
        ));
    }

    let root = repo_root();
    let scripts_dir = root.join("scripts");
    let model_dir = args.model_dir.unwrap_or_else(default_model_dir);
    let corpus_out = args
        .corpus_out
        .unwrap_or_else(|| model_dir.join("control_plane_corpus.jsonl"));
    let summary_out = args
        .summary_out
        .unwrap_or_else(|| model_dir.join("control_plane_corpus.summary.json"));
    let manifest_out = args
        .manifest_out
        .unwrap_or_else(|| model_dir.join("control_plane_models_manifest.json"));
    let threshold_out = args
        .threshold_out
        .unwrap_or_else(|| model_dir.join("threshold_optimizer_v1.mlpackage"));

    let mut train_args = vec![
        "--profile".to_string(),
        args.profile.clone(),
        "--model-dir".to_string(),
        model_dir.display().to_string(),
        "--corpus-out".to_string(),
        corpus_out.display().to_string(),
        "--summary-out".to_string(),
        summary_out.display().to_string(),
        "--manifest-out".to_string(),
        manifest_out.display().to_string(),
    ];
    for input in &args.input {
        train_args.push("--input".to_string());
        train_args.push(input.clone());
    }

    let mut results = vec![run_python_script(
        &root,
        &scripts_dir.join("train_control_plane_models.py"),
        &train_args,
    )?];

    if !args.skip_threshold_optimizer {
        let mut threshold_args = vec![
            "--quality-profile".to_string(),
            args.profile.clone(),
            "--out".to_string(),
            threshold_out.display().to_string(),
        ];
        for input in &args.input {
            threshold_args.push("--input".to_string());
            threshold_args.push(input.clone());
        }
        results.push(run_python_script(
            &root,
            &scripts_dir.join("train_threshold_optimizer.py"),
            &threshold_args,
        )?);
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "profile": args.profile,
                "model_dir": model_dir,
                "corpus_out": corpus_out,
                "summary_out": summary_out,
                "manifest_out": manifest_out,
                "threshold_out": if args.skip_threshold_optimizer {
                    serde_json::Value::Null
                } else {
                    serde_json::json!(threshold_out)
                },
                "steps": results,
            }))
            .map_err(|err| err.to_string())?
        );
    } else {
        println!("retrained control-plane models -> {}", model_dir.display());
        println!("corpus -> {}", corpus_out.display());
        println!("summary -> {}", summary_out.display());
        println!("manifest -> {}", manifest_out.display());
        if !args.skip_threshold_optimizer {
            println!("threshold optimizer -> {}", threshold_out.display());
        }
        for result in results {
            if let Some(stdout) = result.get("stdout").and_then(|value| value.as_str())
                && !stdout.is_empty()
            {
                println!("{stdout}");
            }
        }
    }

    Ok(())
}
