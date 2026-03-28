use crate::control_plane::JobKind;
use crate::error::RuntimeError;
use crate::execution::ExecutionContext;
use std::collections::HashMap;
use zkf_core::artifact::ProofArtifact;
use zkf_core::ir::Program;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactState {
    Empty,
    PrimaryOnly,
    WrappedOnly,
    Dual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitialBufferMaterialization {
    pub(crate) slot: u32,
    pub(crate) size_bytes: usize,
}

pub(crate) fn classify_job(ctx: &ExecutionContext) -> JobKind {
    if ctx.wrapper_preview.is_some() || ctx.source_proof.is_some() {
        JobKind::Wrap
    } else if ctx.fold_witnesses.is_some() {
        JobKind::Fold
    } else {
        JobKind::Prove
    }
}

pub(crate) fn effective_program(ctx: &ExecutionContext) -> Option<&Program> {
    ctx.program.as_deref().or_else(|| {
        ctx.compiled.as_ref().map(|compiled| {
            compiled
                .original_program
                .as_ref()
                .unwrap_or(&compiled.program)
        })
    })
}

pub(crate) fn artifact_state(ctx: &ExecutionContext) -> ArtifactState {
    match (ctx.proof_artifact.is_some(), ctx.wrapped_artifact.is_some()) {
        (false, false) => ArtifactState::Empty,
        (true, false) => ArtifactState::PrimaryOnly,
        (false, true) => ArtifactState::WrappedOnly,
        (true, true) => ArtifactState::Dual,
    }
}

pub(crate) fn preferred_output_artifact(ctx: &ExecutionContext) -> Option<&ProofArtifact> {
    ctx.proof_artifact
        .as_ref()
        .or(ctx.wrapped_artifact.as_ref())
}

pub(crate) fn initial_buffer_plan(ctx: &ExecutionContext) -> Vec<InitialBufferMaterialization> {
    let mut plan = ctx
        .initial_buffers
        .iter()
        .map(|(&slot, data)| InitialBufferMaterialization {
            slot,
            size_bytes: data.len(),
        })
        .collect::<Vec<_>>();
    plan.sort_by_key(|entry| entry.slot);
    plan
}

pub(crate) fn verify_wrapper_source_artifacts(ctx: &ExecutionContext) -> Result<(), RuntimeError> {
    if classify_job(ctx) == JobKind::Wrap && (ctx.source_proof.is_none() || ctx.compiled.is_none())
    {
        return Err(RuntimeError::UnsupportedFeature {
            backend: "runtime-wrapper".to_string(),
            feature:
                "wrapper execution requires both the source proof artifact and compiled source program"
                    .to_string(),
        });
    }
    Ok(())
}

pub(crate) fn output_presence_map(
    outputs: &HashMap<String, Vec<u8>>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    for (key, value) in outputs {
        map.insert(
            key.clone(),
            serde_json::json!({
                "bytes": value.len(),
                "present": true,
            }),
        );
    }
    map
}
