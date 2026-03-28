use std::path::{Path, PathBuf};

use zkf_core::{BackendKind, ProofArtifact};

use crate::solidity::{
    EvmTarget, parse_evm_target, render_groth16_solidity_verifier_for_target,
    render_sp1_solidity_verifier_for_target,
};
use crate::util::{ensure_release_safe_proof_artifact, read_json, write_text};

pub(crate) fn handle_deploy(
    artifact_path: PathBuf,
    backend: String,
    out: PathBuf,
    contract_name: Option<String>,
    evm_target: String,
    json: bool,
) -> Result<(), String> {
    let backend_kind = crate::util::parse_backend(&backend)?;
    let evm_target = parse_evm_target(Some(&evm_target))?;

    let artifact: ProofArtifact = read_json(&artifact_path)?;
    ensure_release_safe_proof_artifact(&artifact, "zkf deploy")?;

    let name = contract_name.unwrap_or_else(|| default_contract_name(backend_kind));

    let source = render_solidity_verifier(backend_kind, &artifact, &name, evm_target)?;

    write_solidity_output(&out, &source)?;

    if json {
        let report = DeployReport {
            backend: backend_kind.as_str().to_string(),
            evm_target: evm_target.as_str().to_string(),
            artifact_path: artifact_path.display().to_string(),
            solidity_path: out.display().to_string(),
            contract_name: name,
            solidity_bytes: source.len(),
            algebraic_binding: artifact.metadata.get("algebraic_binding").cloned(),
            trust_boundary_note: trust_boundary_note(&artifact),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "deploy: backend={} evm_target={} contract={} -> {}",
            backend_kind,
            evm_target.as_str(),
            name,
            out.display()
        );
    }

    Ok(())
}

fn render_solidity_verifier(
    backend: BackendKind,
    artifact: &ProofArtifact,
    contract_name: &str,
    evm_target: EvmTarget,
) -> Result<String, String> {
    match backend {
        BackendKind::Sp1 => render_sp1_solidity_verifier_for_target(artifact, evm_target),
        BackendKind::ArkworksGroth16 => Ok(render_groth16_solidity_verifier_for_target(
            artifact,
            contract_name,
            evm_target,
        )),
        other => Err(format!(
            "solidity verifier generation is not supported for backend '{}'; supported backends: sp1, arkworks-groth16",
            other
        )),
    }
}

fn default_contract_name(backend: BackendKind) -> String {
    match backend {
        BackendKind::Sp1 => "ZkfSp1BoundVerifier".to_string(),
        BackendKind::ArkworksGroth16 => "ZkfGroth16Verifier".to_string(),
        _ => "ZkfVerifier".to_string(),
    }
}

fn write_solidity_output(path: &Path, source: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create output directory '{}': {e}",
                parent.display()
            )
        })?;
    }
    write_text(path, source).map_err(|e| {
        format!(
            "failed to write solidity verifier to '{}': {e}",
            path.display()
        )
    })
}

#[derive(Debug, serde::Serialize)]
struct DeployReport {
    backend: String,
    evm_target: String,
    artifact_path: String,
    solidity_path: String,
    contract_name: String,
    solidity_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    algebraic_binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust_boundary_note: Option<String>,
}

fn trust_boundary_note(artifact: &ProofArtifact) -> Option<String> {
    artifact
        .metadata
        .get("algebraic_binding")
        .filter(|value| value.as_str() == "false")
        .map(|_| {
            "algebraic_binding=false: exported verifier is metadata-bound and does not claim a fully algebraically bound in-circuit accumulator check"
                .to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::write_json;
    use std::collections::BTreeMap;
    use zkf_core::{BackendKind, ProofArtifact};

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("zkf-deploy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn proof_artifact(trust_model: &str) -> ProofArtifact {
        let mut metadata = BTreeMap::new();
        metadata.insert("trust_model".to_string(), trust_model.to_string());
        ProofArtifact {
            backend: BackendKind::ArkworksGroth16,
            program_digest: "digest".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        }
    }

    #[test]
    fn deploy_rejects_attested_artifacts() {
        let root = temp_root("rejects-attested");
        let artifact_path = root.join("proof.json");
        let out_path = root.join("verifier.sol");
        write_json(&artifact_path, &proof_artifact("attestation")).unwrap();

        let err = handle_deploy(
            artifact_path,
            "arkworks-groth16".to_string(),
            out_path.clone(),
            None,
            "ethereum".to_string(),
            false,
        )
        .unwrap_err();

        assert!(err.contains("trust_model=attestation"));
        assert!(!out_path.exists());
    }

    #[test]
    fn deploy_accepts_cryptographic_artifacts() {
        let root = temp_root("accepts-cryptographic");
        let artifact_path = root.join("proof.json");
        let out_path = root.join("verifier.sol");
        write_json(&artifact_path, &proof_artifact("cryptographic")).unwrap();

        handle_deploy(
            artifact_path,
            "arkworks-groth16".to_string(),
            out_path.clone(),
            Some("ProdVerifier".to_string()),
            "ethereum".to_string(),
            false,
        )
        .unwrap();

        let source = std::fs::read_to_string(&out_path).unwrap();
        assert!(source.contains("contract ProdVerifier"));
        assert!(source.contains("ZKF EVM target: ethereum"));
    }
}
