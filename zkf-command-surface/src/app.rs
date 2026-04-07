use crate::shell::run_zkf_cli;
use crate::types::now_rfc3339;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppScaffoldReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub template: String,
    pub name: String,
    pub out_dir: String,
    pub spec_path: String,
    pub stdout: String,
    pub stderr: String,
}

pub fn scaffold(template: &str, name: &str, out_dir: &Path, cwd: &Path) -> Result<AppScaffoldReportV1, String> {
    let args = vec![
        "app".to_string(),
        "init".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--template".to_string(),
        template.to_string(),
        "--out".to_string(),
        out_dir.display().to_string(),
    ];
    let result = run_zkf_cli(&args, cwd)?;
    Ok(AppScaffoldReportV1 {
        schema: "zkf-app-scaffold-v1".to_string(),
        generated_at: now_rfc3339(),
        template: template.to_string(),
        name: name.to_string(),
        out_dir: out_dir.display().to_string(),
        spec_path: out_dir.join("zirapp.json").display().to_string(),
        stdout: result.stdout,
        stderr: result.stderr,
    })
}

pub fn scaffold_summary(report: &AppScaffoldReportV1) -> serde_json::Value {
    json!({
        "schema": report.schema,
        "template": report.template,
        "name": report.name,
        "out_dir": report.out_dir,
        "spec_path": report.spec_path,
    })
}
