use crate::cli::NeuralCommands;
use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zkf_core::ir::{Constraint, Expr, Program, Signal, Visibility};
use zkf_core::{BackendKind, FieldId};
use zkf_runtime::{
    ControlPlaneRequest, JobKind, ModelCatalog, ModelDescriptor, ModelLane, OptimizationObjective,
    RequiredTrustLane, evaluate_control_plane, feature_vector_labels_v1, feature_vector_labels_v2,
    feature_vector_labels_v3, schema_fingerprint_for_lane_shape, security_feature_labels_v1,
    security_feature_labels_v2, security_feature_labels_v3, threshold_optimizer_feature_labels,
};

pub(crate) fn handle_neural(command: NeuralCommands) -> Result<(), String> {
    match command {
        NeuralCommands::Schema { json } => handle_schema(json),
        NeuralCommands::Pin {
            model_dir,
            manifest_out,
            json,
        } => handle_pin(model_dir, manifest_out, json),
        NeuralCommands::Doctor {
            require_all,
            require_ane,
            json,
        } => handle_doctor(require_all, require_ane, json),
    }
}

fn handle_schema(json_output: bool) -> Result<(), String> {
    let report = json!({
        "schema": "zkf-neural-schema-report-v1",
        "control_plane": {
            "v1": schema_row(ModelLane::Scheduler, 47, feature_vector_labels_v1()),
            "v2": schema_row(ModelLane::Scheduler, 57, feature_vector_labels_v2()),
            "v3": schema_row(ModelLane::Scheduler, 128, feature_vector_labels_v3()),
        },
        "security": {
            "v1": schema_row(ModelLane::Security, 64, security_feature_labels_v1()),
            "v2": schema_row(ModelLane::Security, 74, security_feature_labels_v2()),
            "v3": schema_row(ModelLane::Security, 145, security_feature_labels_v3()),
        },
        "threshold_optimizer": schema_row(
            ModelLane::ThresholdOptimizer,
            12,
            threshold_optimizer_feature_labels()
        ),
    });
    print_output(json_output, &report)
}

fn handle_pin(
    model_dir: Option<PathBuf>,
    manifest_out: Option<PathBuf>,
    json_output: bool,
) -> Result<(), String> {
    let model_dir = model_dir.unwrap_or_else(default_model_dir);
    let manifest_out =
        manifest_out.unwrap_or_else(|| model_dir.join("control_plane_models_manifest.json"));
    let lanes = [
        ModelLane::Scheduler,
        ModelLane::Backend,
        ModelLane::Duration,
        ModelLane::Anomaly,
        ModelLane::Security,
        ModelLane::ThresholdOptimizer,
    ];
    let mut model_entries = Vec::new();
    let mut lane_entries = Map::new();
    for lane in lanes {
        let entry = pin_lane(lane, &model_dir)?;
        lane_entries.insert(lane.as_str().to_string(), entry.clone());
        model_entries.push(entry);
    }
    let manifest = json!({
        "schema": "zkf-control-plane-model-bundle-manifest-v3",
        "generated_at": Utc::now().to_rfc3339(),
        "generator": "zkf-cli neural pin",
        "model_dir": model_dir.display().to_string(),
        "lanes": lane_entries,
        "models": model_entries,
    });
    if let Some(parent) = manifest_out.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
    fs::write(&manifest_out, bytes)
        .map_err(|error| format!("write {}: {error}", manifest_out.display()))?;
    let report = json!({
        "schema": "zkf-neural-pin-report-v1",
        "model_dir": model_dir.display().to_string(),
        "manifest_out": manifest_out.display().to_string(),
        "lane_count": lanes.len(),
        "manifest_sha256": hash_path(&manifest_out)?,
        "models": manifest["models"],
    });
    print_output(json_output, &report)
}

fn pin_lane(lane: ModelLane, model_dir: &Path) -> Result<Value, String> {
    let package_path = lane
        .default_file_names()
        .iter()
        .map(|file_name| model_dir.join(file_name))
        .find(|candidate| candidate.exists())
        .ok_or_else(|| {
            format!(
                "missing {} model in {} (expected one of {:?})",
                lane.as_str(),
                model_dir.display(),
                lane.default_file_names()
            )
        })?;
    let (sidecar_path, sidecar) = load_sidecar(&package_path)?;
    let input_shape = sidecar
        .get("input_shape")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .ok_or_else(|| {
            format!(
                "{} sidecar {} is missing numeric input_shape",
                lane.as_str(),
                sidecar_path.display()
            )
        })?;
    if !lane.supported_input_shapes().contains(&input_shape) {
        return Err(format!(
            "{} sidecar {} has unsupported input_shape {} (expected one of {:?})",
            lane.as_str(),
            sidecar_path.display(),
            input_shape,
            lane.supported_input_shapes()
        ));
    }
    let output_name = sidecar
        .get("output_name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "{} sidecar {} is missing output_name",
                lane.as_str(),
                sidecar_path.display()
            )
        })?;
    if output_name != lane.expected_output_name() {
        return Err(format!(
            "{} sidecar {} output mismatch: expected {}, found {}",
            lane.as_str(),
            sidecar_path.display(),
            lane.expected_output_name(),
            output_name
        ));
    }
    let expected_schema =
        schema_fingerprint_for_lane_shape(lane, input_shape).ok_or_else(|| {
            format!(
                "{} input_shape {} has no runtime schema fingerprint",
                lane.as_str(),
                input_shape
            )
        })?;
    if let Some(actual_schema) = sidecar.get("schema_fingerprint").and_then(Value::as_str)
        && actual_schema != expected_schema
    {
        return Err(format!(
            "{} sidecar {} schema mismatch: expected {}, found {}",
            lane.as_str(),
            sidecar_path.display(),
            expected_schema,
            actual_schema
        ));
    }
    if !sidecar
        .get("quality_gate")
        .and_then(|value| value.get("passed"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(format!(
            "{} sidecar {} does not have a passing quality_gate",
            lane.as_str(),
            sidecar_path.display()
        ));
    }
    let package_tree_sha256 = hash_model_package(&package_path)?;
    let sidecar_sha256 = hash_path(&sidecar_path)?;
    let model_fingerprint = model_fingerprint(&package_tree_sha256, &sidecar_sha256);
    Ok(json!({
        "lane": lane.as_str(),
        "package": package_path.display().to_string(),
        "path": package_path.display().to_string(),
        "sidecar": sidecar_path.display().to_string(),
        "source": "pinned-local-coreml",
        "version": sidecar.get("version").cloned().unwrap_or(Value::Null),
        "schema": sidecar.get("schema").cloned().unwrap_or(Value::Null),
        "schema_fingerprint": expected_schema,
        "input_shape": input_shape,
        "output_name": output_name,
        "quality_gate": sidecar.get("quality_gate").cloned().unwrap_or(Value::Null),
        "corpus_hash": sidecar.get("corpus_hash").cloned().unwrap_or(Value::Null),
        "record_count": sidecar.get("record_count").cloned().unwrap_or(Value::Null),
        "trained_at": sidecar.get("trained_at").cloned().unwrap_or(Value::Null),
        "package_tree_sha256": package_tree_sha256,
        "sidecar_sha256": sidecar_sha256,
        "model_fingerprint": model_fingerprint,
    }))
}

fn default_model_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".zkf")
        .join("models")
}

fn load_sidecar(package_path: &Path) -> Result<(PathBuf, Value), String> {
    let mut candidates = Vec::new();
    candidates.push(PathBuf::from(format!("{}.json", package_path.display())));
    if package_path.is_dir() {
        candidates.push(package_path.join("zkf-model.json"));
    }
    for candidate in candidates {
        let Ok(bytes) = fs::read(&candidate) else {
            continue;
        };
        let payload = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse {}: {error}", candidate.display()))?;
        return Ok((candidate, payload));
    }
    Err(format!(
        "missing sidecar for {} (expected <package>.json or package/zkf-model.json)",
        package_path.display()
    ))
}

fn hash_model_package(path: &Path) -> Result<String, String> {
    if path.is_file() {
        return hash_path(path);
    }
    let mut hasher = Sha256::new();
    for entry in collect_file_entries(path)? {
        hasher.update(
            entry
                .strip_prefix(path)
                .unwrap_or(entry.as_path())
                .to_string_lossy()
                .as_bytes(),
        );
        hasher.update([0u8]);
        hasher.update(
            fs::read(&entry).map_err(|error| format!("hash {}: {error}", entry.display()))?,
        );
        hasher.update([0u8]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect_file_entries(root: &Path) -> Result<Vec<PathBuf>, String> {
    fn walk(current: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut entries = fs::read_dir(current)
            .map_err(|error| format!("read_dir {}: {error}", current.display()))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("file_type {}: {error}", path.display()))?;
            if file_type.is_dir() {
                walk(&path, out)?;
            } else if file_type.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }

    let mut out = Vec::new();
    walk(root, &mut out)?;
    Ok(out)
}

fn hash_path(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("hash {}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn model_fingerprint(package_tree_sha256: &str, sidecar_sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(package_tree_sha256.as_bytes());
    hasher.update([0u8]);
    hasher.update(sidecar_sha256.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn schema_row(lane: ModelLane, shape: usize, labels: Vec<String>) -> serde_json::Value {
    json!({
        "lane": lane,
        "input_shape": shape,
        "label_count": labels.len(),
        "schema_fingerprint": schema_fingerprint_for_lane_shape(lane, shape),
        "feature_labels": labels,
    })
}

fn handle_doctor(require_all: bool, require_ane: bool, json_output: bool) -> Result<(), String> {
    let catalog = ModelCatalog::discover();
    let decision = evaluate_control_plane(&sample_request());
    let lanes = [
        lane_report(ModelLane::Scheduler, catalog.scheduler.as_ref(), &decision),
        lane_report(ModelLane::Backend, catalog.backend.as_ref(), &decision),
        lane_report(ModelLane::Duration, catalog.duration.as_ref(), &decision),
        lane_report(ModelLane::Anomaly, catalog.anomaly.as_ref(), &decision),
        lane_report(ModelLane::Security, catalog.security.as_ref(), &decision),
        lane_report(
            ModelLane::ThresholdOptimizer,
            catalog.threshold_optimizer.as_ref(),
            &decision,
        ),
    ];
    let all_available = lanes.iter().all(|lane| lane.available);
    let all_pinned = lanes.iter().all(|lane| lane.pinned);
    let all_quality_passed = lanes.iter().all(|lane| lane.quality_passed);
    let all_executed = lanes.iter().all(|lane| lane.executed);
    let ane_compiled = cfg!(all(target_vendor = "apple", feature = "neural-engine"));
    let ready = (!require_all || (all_available && all_pinned && all_quality_passed))
        && (!require_ane || (ane_compiled && all_executed));
    let report = NeuralDoctorReport {
        schema: "zkf-neural-doctor-report-v1",
        require_all,
        require_ane,
        ready,
        ane_compiled,
        all_available,
        all_pinned,
        all_quality_passed,
        all_executed,
        lanes,
        failures: catalog.failures,
    };

    print_output(json_output, &report)?;
    if ready {
        Ok(())
    } else {
        Err("neural doctor strict requirements failed".to_string())
    }
}

#[derive(Debug, Serialize)]
struct NeuralDoctorReport {
    schema: &'static str,
    require_all: bool,
    require_ane: bool,
    ready: bool,
    ane_compiled: bool,
    all_available: bool,
    all_pinned: bool,
    all_quality_passed: bool,
    all_executed: bool,
    lanes: [NeuralLaneReport; 6],
    failures: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct NeuralLaneReport {
    lane: ModelLane,
    available: bool,
    pinned: bool,
    trusted: bool,
    quality_passed: bool,
    executed: bool,
    source: String,
    input_shape: Option<usize>,
    model_path: Option<String>,
    error: Option<String>,
}

fn lane_report(
    lane: ModelLane,
    descriptor: Option<&ModelDescriptor>,
    decision: &zkf_runtime::ControlPlaneDecision,
) -> NeuralLaneReport {
    let execution = decision
        .model_executions
        .iter()
        .find(|execution| execution.lane == lane);
    NeuralLaneReport {
        lane,
        available: descriptor.is_some(),
        pinned: descriptor.is_some_and(|value| value.pinned),
        trusted: descriptor.is_some_and(|value| value.trusted),
        quality_passed: descriptor
            .and_then(|value| value.quality_gate.as_ref())
            .is_some_and(|value| value.passed),
        executed: execution.is_some_and(|value| value.executed),
        source: execution
            .map(|value| value.source.clone())
            .unwrap_or_else(|| "missing".to_string()),
        input_shape: execution
            .and_then(|value| value.input_shape)
            .or_else(|| descriptor.and_then(|value| value.input_shape)),
        model_path: descriptor.map(|value| value.path.clone()),
        error: execution
            .and_then(|value| value.error.clone())
            .or_else(|| decision.model_catalog.failures.get(lane.as_str()).cloned()),
    }
}

fn sample_request() -> ControlPlaneRequest<'static> {
    let program = Box::leak(Box::new(sample_program()));
    let mut request = ControlPlaneRequest::for_program(JobKind::Prove, None, Some(program), None);
    request.objective = OptimizationObjective::FastestProve;
    request.requested_backend = Some(BackendKind::ArkworksGroth16);
    request.trust_lane = RequiredTrustLane::StrictCryptographic;
    request.requested_jobs = Some(2);
    request.total_jobs = Some(4);
    request.backend_candidates = vec![BackendKind::ArkworksGroth16, BackendKind::Plonky3];
    request
}

fn sample_program() -> Program {
    Program {
        name: "neural-doctor-sample".to_string(),
        field: FieldId::Bn254,
        signals: vec![
            Signal {
                name: "private_value".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            },
            Signal {
                name: "public_square".to_string(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            },
        ],
        constraints: vec![Constraint::Equal {
            lhs: Expr::signal("public_square"),
            rhs: Expr::Mul(
                Box::new(Expr::signal("private_value")),
                Box::new(Expr::signal("private_value")),
            ),
            label: Some("square".to_string()),
        }],
        ..Program::default()
    }
}

fn print_output(json_output: bool, value: &impl Serialize) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    if json_output {
        println!("{rendered}");
    } else {
        println!("{rendered}");
    }
    Ok(())
}
