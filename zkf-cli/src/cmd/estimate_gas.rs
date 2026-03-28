use std::path::PathBuf;

use zkf_core::{BackendKind, ProofArtifact};

use crate::solidity::{EvmTarget, parse_evm_target};
use crate::util::{parse_backend, read_json};

fn gas_model_note(backend: BackendKind, target: EvmTarget) -> String {
    let target_note = match target {
        EvmTarget::Ethereum => "Targeted to Ethereum mainnet calldata and precompile costs.",
        EvmTarget::OptimismArbitrumL2 => {
            "Targeted to Optimism/Arbitrum-style L2 execution and calldata heuristics."
        }
        EvmTarget::GenericEvm => "Targeted to generic EVM deployment heuristics.",
    };
    match backend {
        BackendKind::ArkworksGroth16 => {
            format!(
                "Groth16 estimate assumes a BN254 precompile verifier path with target-specific calldata overheads. {target_note}"
            )
        }
        BackendKind::Halo2 => {
            format!(
                "Halo2 estimate uses a size-weighted heuristic pending chain-specific verifier calibration. {target_note}"
            )
        }
        BackendKind::Halo2Bls12381 => {
            format!(
                "Halo2-BLS12-381 estimate uses a size-weighted heuristic based on a KZG verifier gas profile. {target_note}"
            )
        }
        BackendKind::Plonky3 => {
            format!(
                "Plonky3 estimate uses a size-weighted heuristic pending chain-specific verifier calibration. {target_note}"
            )
        }
        BackendKind::Sp1 => {
            format!(
                "SP1 estimate uses a size-weighted heuristic for on-chain verifier wrappers. {target_note}"
            )
        }
        BackendKind::RiscZero => {
            format!(
                "RISC Zero estimate uses a size-weighted heuristic for on-chain verifier wrappers. {target_note}"
            )
        }
        BackendKind::Nova => {
            format!(
                "Nova estimate uses a size-weighted heuristic; recursive verifier circuits vary by implementation. {target_note}"
            )
        }
        BackendKind::HyperNova => {
            format!(
                "HyperNova estimate uses a size-weighted heuristic based on a CCS multifolding verifier gas profile. {target_note}"
            )
        }
        BackendKind::MidnightCompact => {
            format!(
                "Midnight verification is network/runtime-specific and not modeled as EVM gas. {target_note}"
            )
        }
    }
}

fn estimate_verification_gas(
    backend: BackendKind,
    proof_size_bytes: usize,
    target: EvmTarget,
) -> Result<u64, String> {
    let size = proof_size_bytes as u64;
    let base = match backend {
        BackendKind::ArkworksGroth16 => 210_000,
        BackendKind::Halo2 => 280_000 + (size.saturating_mul(16)),
        BackendKind::Halo2Bls12381 => 300_000 + (size.saturating_mul(18)),
        BackendKind::Plonky3 => 350_000 + (size.saturating_mul(12)),
        BackendKind::Sp1 => 450_000 + (size.saturating_mul(20)),
        BackendKind::RiscZero => 420_000 + (size.saturating_mul(18)),
        BackendKind::Nova => 300_000 + (size.saturating_mul(15)),
        BackendKind::HyperNova => 320_000 + (size.saturating_mul(16)),
        BackendKind::MidnightCompact => {
            return Err(
                "gas estimation for midnight-compact is not applicable in EVM gas units"
                    .to_string(),
            );
        }
    };
    let gas = match target {
        EvmTarget::Ethereum => base,
        EvmTarget::OptimismArbitrumL2 => base.saturating_mul(86) / 100,
        EvmTarget::GenericEvm => base.saturating_mul(95) / 100,
    };
    Ok(gas)
}

pub(crate) fn handle_estimate_gas(
    backend: String,
    artifact: Option<PathBuf>,
    proof_size: Option<usize>,
    evm_target: String,
    json: bool,
) -> Result<(), String> {
    let backend = parse_backend(&backend)?;
    let evm_target = parse_evm_target(Some(&evm_target))?;
    let (proof_size_bytes, source) = if let Some(path) = artifact.as_ref() {
        let artifact: ProofArtifact = read_json(path)?;
        (artifact.proof.len(), format!("artifact:{}", path.display()))
    } else if let Some(size) = proof_size {
        (size, "cli".to_string())
    } else {
        return Err(
            "estimate-gas requires either --artifact <proof.json> or --proof-size <bytes>"
                .to_string(),
        );
    };

    let estimate = estimate_verification_gas(backend, proof_size_bytes, evm_target)?;
    let report = crate::GasEstimateReport {
        backend: backend.as_str().to_string(),
        evm_target: evm_target.as_str().to_string(),
        proof_size_bytes,
        estimated_verify_gas: estimate,
        model_source: source,
        model_note: gas_model_note(backend, evm_target),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "gas estimate: backend={} evm_target={} proof_size={} estimated_verify_gas={}",
            report.backend, report.evm_target, report.proof_size_bytes, report.estimated_verify_gas
        );
    }

    Ok(())
}
