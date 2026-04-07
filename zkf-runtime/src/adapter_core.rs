use crate::trust::TrustModel;
use zkf_core::artifact::BackendKind;
use zkf_core::wrapping::WrapperPreview;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackendProveGraphSpec {
    pub(crate) signal_count: usize,
    pub(crate) constraints: usize,
    pub(crate) witness_bytes: usize,
    pub(crate) transcript_bytes: usize,
    pub(crate) prove_bytes: usize,
    pub(crate) artifact_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackendFoldGraphSpec {
    pub(crate) constraints: usize,
    pub(crate) transcript_seed_bytes: usize,
    pub(crate) transcript_bytes: usize,
    pub(crate) fold_bytes: usize,
    pub(crate) artifact_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WrapperGraphSpec {
    pub(crate) trust: TrustModel,
    pub(crate) estimated_constraints: usize,
    pub(crate) working_bytes: usize,
    pub(crate) source_bytes: usize,
    pub(crate) transcript_bytes: usize,
    pub(crate) verifier_bytes: usize,
    pub(crate) proof_bytes: usize,
}

pub(crate) fn preview_trust_model(preview: &WrapperPreview) -> TrustModel {
    match preview.trust_model.as_str() {
        "cryptographic" => TrustModel::Cryptographic,
        "attestation" => TrustModel::Attestation,
        _ => TrustModel::MetadataOnly,
    }
}

pub(crate) fn backend_kind_name(kind: zkf_core::BackendKind) -> &'static str {
    kind.as_str()
}

pub(crate) fn delegated_backend_artifact_bytes(backend: BackendKind, constraints: usize) -> usize {
    let base = match backend {
        BackendKind::ArkworksGroth16 | BackendKind::Halo2 | BackendKind::Halo2Bls12381 => {
            512 * 1024
        }
        BackendKind::Plonky3 => 16 * 1024 * 1024,
        BackendKind::Nova | BackendKind::HyperNova => 4 * 1024 * 1024,
        _ => 2 * 1024 * 1024,
    };
    // Plonky3 STARK proofs scale with constraint count — large circuits
    // (e.g. 96-step Euler integration) produce proofs exceeding 8 MB.
    let max_bytes = match backend {
        BackendKind::Plonky3 => 64 * 1024 * 1024,
        _ => 16 * 1024 * 1024,
    };
    base.max(constraints.saturating_mul(64))
        .clamp(256 * 1024, max_bytes)
}

pub(crate) fn backend_prove_graph_spec(
    signal_count: usize,
    constraints: usize,
    backend: BackendKind,
) -> BackendProveGraphSpec {
    BackendProveGraphSpec {
        signal_count,
        constraints,
        witness_bytes: signal_count * 32,
        transcript_bytes: 32,
        prove_bytes: 32,
        artifact_bytes: delegated_backend_artifact_bytes(backend, constraints),
    }
}

pub(crate) fn backend_fold_graph_spec(
    constraints: usize,
    backend: BackendKind,
) -> BackendFoldGraphSpec {
    BackendFoldGraphSpec {
        constraints,
        transcript_seed_bytes: 256,
        transcript_bytes: 32,
        fold_bytes: 32,
        artifact_bytes: delegated_backend_artifact_bytes(backend, constraints),
    }
}

pub(crate) fn wrapper_graph_spec(preview: &WrapperPreview) -> WrapperGraphSpec {
    let estimated_constraints = preview.estimated_constraints.unwrap_or(1024).max(1) as usize;
    let working_bytes = preview
        .estimated_memory_bytes
        .unwrap_or(64 * 1024 * 1024)
        .max(4 * 1024 * 1024) as usize;
    WrapperGraphSpec {
        trust: preview_trust_model(preview),
        estimated_constraints,
        working_bytes,
        source_bytes: (working_bytes / 4).max(64 * 1024),
        transcript_bytes: 32,
        verifier_bytes: 2048,
        proof_bytes: 4096,
    }
}
