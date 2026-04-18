use crate::state::{
    hermes_config_path, hermes_home_root, hermes_pack_lock_path, hermes_pack_root,
    hermes_skills_root,
};
use crate::types::{
    GuardrailViolationV1, HermesBootstrapAssetV1, HermesConfigStatusV1, HermesDoctorReportV1,
    HermesExportBootstrapReportV1, HermesInstallReportV1, HermesManagedAssetStatusV1,
    HermesPackDiffV1, HermesPackStatusV1, OperatorProfileV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yaml::{Mapping as YamlMapping, Value as YamlValue};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
struct HermesPackManifest {
    schema: String,
    operator_profile: String,
    repo_root: String,
    pack_root: String,
    lock_file: String,
    assets: Vec<HermesPackAsset>,
    skills: Vec<HermesPackSkill>,
    managed_config: HermesManagedConfig,
}

#[derive(Debug, Clone, Deserialize)]
struct HermesPackAsset {
    id: String,
    kind: String,
    source: String,
    target: String,
}

#[derive(Debug, Clone, Deserialize)]
struct HermesPackSkill {
    name: String,
    source: String,
    target: String,
}

#[derive(Debug, Clone, Deserialize)]
struct HermesManagedConfig {
    operator_profile: String,
    cwd_prefix: String,
    autoload_skills: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HermesPackLockV1 {
    schema: String,
    generated_at: String,
    operator_profile: String,
    repo_root: String,
    manifest_sha256: String,
    pack_root: String,
    config_path: String,
    assets: Vec<HermesPackLockEntryV1>,
    skills: Vec<HermesPackLockEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HermesPackLockEntryV1 {
    id: String,
    target_path: String,
    sha256: String,
}

#[derive(Debug)]
struct ConfigInspection {
    status: HermesConfigStatusV1,
    issues: Vec<GuardrailViolationV1>,
}

pub fn hermes_status() -> Result<HermesPackStatusV1, String> {
    let manifest = load_manifest()?;
    let assets = collect_asset_statuses(&manifest)?;
    let config = inspect_config(&manifest)?;
    let lock_present = hermes_pack_lock_path().exists();
    let lock_issues = inspect_lock(&manifest, &assets)?;
    let mut violations = config.issues;
    violations.extend(lock_issues);
    for asset in &assets {
        if !asset.installed {
            violations.push(violation(
                "missing-managed-asset",
                format!("managed Hermes asset '{}' is missing", asset.id),
                Some(asset.target_path.clone()),
            ));
        } else if !asset.sha256_match {
            violations.push(violation(
                "asset-sha-mismatch",
                format!(
                    "managed Hermes asset '{}' drifted from the repo copy",
                    asset.id
                ),
                Some(asset.target_path.clone()),
            ));
        }
    }
    let install_complete = assets
        .iter()
        .all(|asset| asset.installed && asset.sha256_match)
        && config.status.exists
        && config.status.auto_load_rule_present
        && config.status.missing_skills.is_empty()
        && lock_present;
    Ok(HermesPackStatusV1 {
        schema: "ziros-hermes-pack-status-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        operator_profile: OperatorProfileV1::HermesRigorous,
        repo_root: repo_root().display().to_string(),
        hermes_home: hermes_home_root().display().to_string(),
        pack_root: hermes_pack_root().display().to_string(),
        lock_path: hermes_pack_lock_path().display().to_string(),
        contract_path: contract_path().display().to_string(),
        manifest_path: manifest_path().display().to_string(),
        install_complete,
        doctor_ok: violations.is_empty(),
        lock_present,
        config: config.status,
        assets,
        non_canonical_state: non_canonical_state()?,
        violations,
    })
}

pub fn hermes_diff() -> Result<HermesPackDiffV1, String> {
    let status = hermes_status()?;
    let missing_assets = status
        .assets
        .iter()
        .filter(|asset| !asset.installed)
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    let changed_assets = status
        .assets
        .iter()
        .filter(|asset| asset.installed && !asset.sha256_match)
        .map(|asset| asset.id.clone())
        .collect::<Vec<_>>();
    let config_issues = status
        .violations
        .iter()
        .filter(|issue| issue.code.starts_with("config-"))
        .cloned()
        .collect::<Vec<_>>();
    let lock_issues = status
        .violations
        .iter()
        .filter(|issue| issue.code.starts_with("lock-"))
        .cloned()
        .collect::<Vec<_>>();
    Ok(HermesPackDiffV1 {
        schema: "ziros-hermes-pack-diff-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        healthy: status.doctor_ok,
        missing_assets,
        changed_assets,
        config_issues,
        lock_issues,
    })
}

pub fn hermes_install() -> Result<HermesInstallReportV1, String> {
    sync_pack()
}

pub fn hermes_sync() -> Result<HermesInstallReportV1, String> {
    sync_pack()
}

pub fn hermes_doctor() -> Result<HermesDoctorReportV1, String> {
    let status = hermes_status()?;
    Ok(HermesDoctorReportV1 {
        schema: "ziros-hermes-doctor-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        healthy: status.doctor_ok,
        repair_command: "ziros agent hermes sync --json".to_string(),
        status,
    })
}

pub fn hermes_export_bootstrap() -> Result<HermesExportBootstrapReportV1, String> {
    let manifest = load_manifest()?;
    let prompt_path = bootstrap_prompt_path();
    let prompt_text = fs::read_to_string(&prompt_path)
        .map_err(|error| format!("failed to read {}: {error}", prompt_path.display()))?;
    let assets = manifest
        .assets
        .iter()
        .map(|asset| {
            let source = repo_root().join(&asset.source);
            let installed = hermes_pack_root().join(&asset.target);
            Ok(HermesBootstrapAssetV1 {
                id: asset.id.clone(),
                source_path: source.display().to_string(),
                installed_path: installed.display().to_string(),
                sha256: sha256_hex(&source)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(HermesExportBootstrapReportV1 {
        schema: "ziros-hermes-bootstrap-export-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        prompt_path: prompt_path.display().to_string(),
        prompt_text,
        contract_path: contract_path().display().to_string(),
        manifest_path: manifest_path().display().to_string(),
        assets,
    })
}

fn sync_pack() -> Result<HermesInstallReportV1, String> {
    let manifest = load_manifest()?;
    fs::create_dir_all(hermes_pack_root())
        .map_err(|error| format!("failed to create {}: {error}", hermes_pack_root().display()))?;
    fs::create_dir_all(hermes_skills_root()).map_err(|error| {
        format!(
            "failed to create {}: {error}",
            hermes_skills_root().display()
        )
    })?;

    let mut assets_written = Vec::new();
    for asset in &manifest.assets {
        let source = repo_root().join(&asset.source);
        let target = hermes_pack_root().join(&asset.target);
        copy_if_changed(&source, &target)?;
        assets_written.push(asset.id.clone());
    }

    let mut skills_written = Vec::new();
    for skill in &manifest.skills {
        let source = repo_root().join(&skill.source);
        let target = hermes_skills_root().join(&skill.target);
        copy_if_changed(&source, &target)?;
        skills_written.push(skill.name.clone());
    }

    let config_updated = merge_overlay_config(&manifest)?;
    let lock = build_lock(&manifest)?;
    fs::write(
        hermes_pack_lock_path(),
        serde_json::to_string_pretty(&lock).map_err(|error| error.to_string())? + "\n",
    )
    .map_err(|error| {
        format!(
            "failed to write {}: {error}",
            hermes_pack_lock_path().display()
        )
    })?;

    Ok(HermesInstallReportV1 {
        schema: "ziros-hermes-install-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        pack_root: hermes_pack_root().display().to_string(),
        lock_path: hermes_pack_lock_path().display().to_string(),
        config_path: hermes_config_path().display().to_string(),
        assets_written,
        skills_written,
        config_updated,
        lock_written: true,
    })
}

fn load_manifest() -> Result<HermesPackManifest, String> {
    let path = manifest_path();
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let manifest: HermesPackManifest =
        serde_json::from_str(&contents).map_err(|error| format!("invalid manifest: {error}"))?;
    if manifest.schema != "ziros-hermes-pack-manifest-v1" {
        return Err(format!(
            "unsupported Hermes manifest schema '{}'",
            manifest.schema
        ));
    }
    if manifest.repo_root != "." {
        return Err(format!(
            "unsupported Hermes manifest repo_root '{}'",
            manifest.repo_root
        ));
    }
    if manifest.pack_root != "ziros-pack" {
        return Err(format!(
            "unsupported Hermes manifest pack_root '{}'",
            manifest.pack_root
        ));
    }
    if manifest.lock_file != "ziros-pack.lock.json" {
        return Err(format!(
            "unsupported Hermes manifest lock_file '{}'",
            manifest.lock_file
        ));
    }
    Ok(manifest)
}

fn collect_asset_statuses(
    manifest: &HermesPackManifest,
) -> Result<Vec<HermesManagedAssetStatusV1>, String> {
    manifest
        .assets
        .iter()
        .map(|asset| {
            let source = repo_root().join(&asset.source);
            let target = hermes_pack_root().join(&asset.target);
            let expected_sha256 = sha256_hex(&source)?;
            let (installed, actual_sha256, sha256_match) = if target.exists() {
                let actual = sha256_hex(&target)?;
                let matches = actual == expected_sha256;
                (true, Some(actual), matches)
            } else {
                (false, None, false)
            };
            Ok(HermesManagedAssetStatusV1 {
                id: asset.id.clone(),
                kind: asset.kind.clone(),
                source_path: source.display().to_string(),
                target_path: target.display().to_string(),
                expected_sha256,
                installed,
                actual_sha256,
                sha256_match,
            })
        })
        .collect::<Result<Vec<_>, String>>()
}

fn inspect_config(manifest: &HermesPackManifest) -> Result<ConfigInspection, String> {
    let config_path = hermes_config_path();
    if !config_path.exists() {
        return Ok(ConfigInspection {
            status: HermesConfigStatusV1 {
                path: config_path.display().to_string(),
                exists: false,
                operator_profile: None,
                repo_root: None,
                pack_root: None,
                auto_load_rule_present: false,
                missing_skills: manifest.managed_config.autoload_skills.clone(),
            },
            issues: vec![violation(
                "config-missing",
                "Hermes config.yaml is missing".to_string(),
                Some(config_path.display().to_string()),
            )],
        });
    }

    let contents = fs::read_to_string(&config_path)
        .map_err(|error| format!("failed to read {}: {error}", config_path.display()))?;
    let parsed: YamlValue =
        serde_yaml::from_str(&contents).map_err(|error| format!("invalid Hermes YAML: {error}"))?;
    let root = parsed
        .as_mapping()
        .ok_or_else(|| "Hermes config root must be a YAML mapping".to_string())?;

    let managed = root
        .get(yaml_key("ziros_repo_managed"))
        .and_then(YamlValue::as_mapping);
    let operator_profile = managed
        .and_then(|map| mapping_string(map, "operator_profile"))
        .map(str::to_string);
    let repo_root_value = managed
        .and_then(|map| mapping_string(map, "repo_root"))
        .map(str::to_string);
    let pack_root_value = managed
        .and_then(|map| mapping_string(map, "pack_root"))
        .map(str::to_string);

    let auto_load_rule_skills = root
        .get(yaml_key("skills"))
        .and_then(YamlValue::as_mapping)
        .and_then(|skills| skills.get(yaml_key("auto_load_rules")))
        .and_then(YamlValue::as_sequence)
        .and_then(|rules| {
            rules.iter().find_map(|rule| {
                let rule_map = rule.as_mapping()?;
                let cwd_prefix = mapping_string(rule_map, "cwd_prefix")?;
                if cwd_prefix == manifest.managed_config.cwd_prefix {
                    Some(
                        rule_map
                            .get(yaml_key("skills"))
                            .and_then(YamlValue::as_sequence)
                            .map(|skills| {
                                skills
                                    .iter()
                                    .filter_map(YamlValue::as_str)
                                    .map(str::to_string)
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                    )
                } else {
                    None
                }
            })
        })
        .unwrap_or_default();
    let missing_skills = manifest
        .managed_config
        .autoload_skills
        .iter()
        .filter(|skill| {
            !auto_load_rule_skills
                .iter()
                .any(|present| present == *skill)
        })
        .cloned()
        .collect::<Vec<_>>();
    let auto_load_rule_present = !auto_load_rule_skills.is_empty();

    let mut issues = Vec::new();
    if operator_profile.as_deref() != Some(manifest.managed_config.operator_profile.as_str()) {
        issues.push(violation(
            "config-profile-mismatch",
            "Hermes config does not advertise the rigorous ZirOS operator profile".to_string(),
            Some(config_path.display().to_string()),
        ));
    }
    if repo_root_value.as_deref() != Some(repo_root().display().to_string().as_str()) {
        issues.push(violation(
            "config-repo-root-mismatch",
            "Hermes config repo_root does not match the current ZirOS checkout".to_string(),
            Some(config_path.display().to_string()),
        ));
    }
    if pack_root_value.as_deref() != Some(hermes_pack_root().display().to_string().as_str()) {
        issues.push(violation(
            "config-pack-root-mismatch",
            "Hermes config pack_root does not match the managed install root".to_string(),
            Some(config_path.display().to_string()),
        ));
    }
    if !auto_load_rule_present {
        issues.push(violation(
            "config-autoload-rule-missing",
            "Hermes config is missing the ZirOS auto-load skill rule".to_string(),
            Some(config_path.display().to_string()),
        ));
    }
    if !missing_skills.is_empty() {
        issues.push(violation(
            "config-autoload-skills-missing",
            format!(
                "Hermes config is missing required ZirOS auto-load skills: {}",
                missing_skills.join(", ")
            ),
            Some(config_path.display().to_string()),
        ));
    }

    Ok(ConfigInspection {
        status: HermesConfigStatusV1 {
            path: config_path.display().to_string(),
            exists: true,
            operator_profile,
            repo_root: repo_root_value,
            pack_root: pack_root_value,
            auto_load_rule_present,
            missing_skills,
        },
        issues,
    })
}

fn inspect_lock(
    manifest: &HermesPackManifest,
    assets: &[HermesManagedAssetStatusV1],
) -> Result<Vec<GuardrailViolationV1>, String> {
    let lock_path = hermes_pack_lock_path();
    if !lock_path.exists() {
        return Ok(vec![violation(
            "lock-missing",
            "Hermes pack lock file is missing".to_string(),
            Some(lock_path.display().to_string()),
        )]);
    }
    let contents = fs::read_to_string(&lock_path)
        .map_err(|error| format!("failed to read {}: {error}", lock_path.display()))?;
    let lock: HermesPackLockV1 =
        serde_json::from_str(&contents).map_err(|error| format!("invalid lock JSON: {error}"))?;
    let mut issues = Vec::new();
    if lock.schema != "ziros-hermes-pack-lock-v1" {
        issues.push(violation(
            "lock-schema-mismatch",
            format!("unexpected Hermes pack lock schema '{}'", lock.schema),
            Some(lock_path.display().to_string()),
        ));
    }
    let expected_manifest_sha = sha256_hex(&manifest_path())?;
    if lock.manifest_sha256 != expected_manifest_sha {
        issues.push(violation(
            "lock-manifest-mismatch",
            "Hermes pack lock was generated from a different manifest".to_string(),
            Some(lock_path.display().to_string()),
        ));
    }
    if lock.operator_profile != manifest.operator_profile {
        issues.push(violation(
            "lock-profile-mismatch",
            "Hermes pack lock operator profile drifted".to_string(),
            Some(lock_path.display().to_string()),
        ));
    }
    for asset in assets {
        let found = lock.assets.iter().find(|entry| entry.id == asset.id);
        match found {
            Some(entry) if entry.sha256 == asset.expected_sha256 => {}
            Some(_) => issues.push(violation(
                "lock-asset-mismatch",
                format!("Hermes pack lock hash for '{}' drifted", asset.id),
                Some(lock_path.display().to_string()),
            )),
            None => issues.push(violation(
                "lock-asset-missing",
                format!("Hermes pack lock is missing '{}'", asset.id),
                Some(lock_path.display().to_string()),
            )),
        }
    }
    Ok(issues)
}

fn build_lock(manifest: &HermesPackManifest) -> Result<HermesPackLockV1, String> {
    let assets = manifest
        .assets
        .iter()
        .map(|asset| {
            let source = repo_root().join(&asset.source);
            Ok(HermesPackLockEntryV1 {
                id: asset.id.clone(),
                target_path: hermes_pack_root().join(&asset.target).display().to_string(),
                sha256: sha256_hex(&source)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let skills = manifest
        .skills
        .iter()
        .map(|skill| {
            let source = repo_root().join(&skill.source);
            Ok(HermesPackLockEntryV1 {
                id: skill.name.clone(),
                target_path: hermes_skills_root()
                    .join(&skill.target)
                    .display()
                    .to_string(),
                sha256: sha256_hex(&source)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(HermesPackLockV1 {
        schema: "ziros-hermes-pack-lock-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        operator_profile: manifest.operator_profile.clone(),
        repo_root: repo_root().display().to_string(),
        manifest_sha256: sha256_hex(&manifest_path())?,
        pack_root: hermes_pack_root().display().to_string(),
        config_path: hermes_config_path().display().to_string(),
        assets,
        skills,
    })
}

fn merge_overlay_config(manifest: &HermesPackManifest) -> Result<bool, String> {
    let config_path = hermes_config_path();
    let mut root = if config_path.exists() {
        let contents = fs::read_to_string(&config_path)
            .map_err(|error| format!("failed to read {}: {error}", config_path.display()))?;
        serde_yaml::from_str::<YamlValue>(&contents)
            .map_err(|error| format!("invalid Hermes YAML: {error}"))?
    } else {
        YamlValue::Mapping(YamlMapping::new())
    };
    let root_map = ensure_yaml_mapping(&mut root)?;

    let mut managed = YamlMapping::new();
    managed.insert(
        yaml_key("operator_profile"),
        YamlValue::String(manifest.managed_config.operator_profile.clone()),
    );
    managed.insert(
        yaml_key("repo_root"),
        YamlValue::String(repo_root().display().to_string()),
    );
    managed.insert(
        yaml_key("operator_core"),
        YamlValue::String(
            repo_root()
                .join("docs/agent/OPERATOR_CORE.md")
                .display()
                .to_string(),
        ),
    );
    managed.insert(
        yaml_key("operator_contract"),
        YamlValue::String(contract_path().display().to_string()),
    );
    managed.insert(
        yaml_key("bootstrap_prompt"),
        YamlValue::String(bootstrap_prompt_path().display().to_string()),
    );
    managed.insert(
        yaml_key("pack_manifest"),
        YamlValue::String(manifest_path().display().to_string()),
    );
    managed.insert(
        yaml_key("pack_root"),
        YamlValue::String(hermes_pack_root().display().to_string()),
    );
    managed.insert(
        yaml_key("non_canonical_state"),
        YamlValue::Sequence(
            non_canonical_state()?
                .into_iter()
                .map(YamlValue::String)
                .collect::<Vec<_>>(),
        ),
    );
    root_map.insert(yaml_key("ziros_repo_managed"), YamlValue::Mapping(managed));

    let skills_value = root_map
        .entry(yaml_key("skills"))
        .or_insert_with(|| YamlValue::Mapping(YamlMapping::new()));
    let skills_map = ensure_yaml_mapping(skills_value)?;
    let rules_value = skills_map
        .entry(yaml_key("auto_load_rules"))
        .or_insert_with(|| YamlValue::Sequence(Vec::new()));
    let rules = ensure_yaml_sequence(rules_value)?;
    let mut rule_index = None;
    for (index, rule) in rules.iter().enumerate() {
        if let Some(rule_map) = rule.as_mapping()
            && mapping_string(rule_map, "cwd_prefix")
                == Some(manifest.managed_config.cwd_prefix.as_str())
        {
            rule_index = Some(index);
            break;
        }
    }
    let mut rule_map = rule_index
        .and_then(|index| rules.get(index).cloned())
        .unwrap_or_else(|| YamlValue::Mapping(YamlMapping::new()));
    let rule_mapping = ensure_yaml_mapping(&mut rule_map)?;
    rule_mapping.insert(
        yaml_key("cwd_prefix"),
        YamlValue::String(manifest.managed_config.cwd_prefix.clone()),
    );
    let mut merged_skills = rule_mapping
        .get(yaml_key("skills"))
        .and_then(YamlValue::as_sequence)
        .map(|seq| {
            seq.iter()
                .filter_map(YamlValue::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for skill in &manifest.managed_config.autoload_skills {
        if !merged_skills.iter().any(|present| present == skill) {
            merged_skills.push(skill.clone());
        }
    }
    rule_mapping.insert(
        yaml_key("skills"),
        YamlValue::Sequence(
            merged_skills
                .into_iter()
                .map(YamlValue::String)
                .collect::<Vec<_>>(),
        ),
    );
    match rule_index {
        Some(index) => rules[index] = rule_map,
        None => rules.push(rule_map),
    }

    let rendered = serde_yaml::to_string(&root).map_err(|error| error.to_string())?;
    let changed = fs::read_to_string(&config_path).unwrap_or_default() != rendered;
    if changed {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
        }
        fs::write(&config_path, rendered)
            .map_err(|error| format!("failed to write {}: {error}", config_path.display()))?;
    }
    Ok(changed)
}

fn copy_if_changed(source: &Path, target: &Path) -> Result<(), String> {
    let source_bytes = fs::read(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?;
    let target_bytes = fs::read(target).ok();
    if target_bytes.as_deref() == Some(source_bytes.as_slice()) {
        return Ok(());
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::write(target, source_bytes)
        .map_err(|error| format!("failed to write {}: {error}", target.display()))
}

fn non_canonical_state() -> Result<Vec<String>, String> {
    let contract = fs::read_to_string(contract_path())
        .map_err(|error| format!("failed to read {}: {error}", contract_path().display()))?;
    let value: JsonValue = serde_json::from_str(&contract)
        .map_err(|error| format!("invalid operator contract: {error}"))?;
    Ok(value
        .get("non_canonical_operator_state")
        .and_then(JsonValue::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default())
}

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn manifest_path() -> PathBuf {
    repo_root().join("setup/hermes/manifest.json")
}

fn contract_path() -> PathBuf {
    repo_root().join("docs/agent/HERMES_OPERATOR_CONTRACT.json")
}

fn bootstrap_prompt_path() -> PathBuf {
    repo_root().join("docs/agent/HERMES_BOOTSTRAP_PROMPT.md")
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

fn violation(code: &str, message: String, path: Option<String>) -> GuardrailViolationV1 {
    GuardrailViolationV1 {
        code: code.to_string(),
        severity: "error".to_string(),
        message,
        path,
    }
}

fn ensure_yaml_mapping(value: &mut YamlValue) -> Result<&mut YamlMapping, String> {
    if matches!(value, YamlValue::Null) {
        *value = YamlValue::Mapping(YamlMapping::new());
    }
    match value {
        YamlValue::Mapping(map) => Ok(map),
        _ => Err("expected YAML mapping".to_string()),
    }
}

fn ensure_yaml_sequence(value: &mut YamlValue) -> Result<&mut Vec<YamlValue>, String> {
    if matches!(value, YamlValue::Null) {
        *value = YamlValue::Sequence(Vec::new());
    }
    match value {
        YamlValue::Sequence(seq) => Ok(seq),
        _ => Err("expected YAML sequence".to_string()),
    }
}

fn yaml_key(key: &str) -> YamlValue {
    YamlValue::String(key.to_string())
}

fn mapping_string<'a>(mapping: &'a YamlMapping, key: &str) -> Option<&'a str> {
    mapping.get(yaml_key(key)).and_then(YamlValue::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn sync_installs_pack_and_skills() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("HERMES_HOME", temp.path());
        }
        let report = hermes_sync().expect("sync");
        assert!(
            report
                .assets_written
                .iter()
                .any(|item| item == "operator-contract")
        );
        assert!(
            hermes_pack_root()
                .join("docs/HERMES_OPERATOR_CONTRACT.json")
                .exists()
        );
        assert!(
            hermes_skills_root()
                .join("ziros-operator-core/SKILL.md")
                .exists()
        );
        let status = hermes_status().expect("status");
        assert!(status.install_complete);
        assert!(status.doctor_ok);
        unsafe {
            std::env::remove_var("HERMES_HOME");
        }
    }

    #[test]
    fn doctor_reports_missing_pack_before_install() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("HERMES_HOME", temp.path());
        }
        let report = hermes_doctor().expect("doctor");
        assert!(!report.healthy);
        assert!(
            report
                .status
                .violations
                .iter()
                .any(|issue| issue.code == "config-missing")
        );
        unsafe {
            std::env::remove_var("HERMES_HOME");
        }
    }
}
