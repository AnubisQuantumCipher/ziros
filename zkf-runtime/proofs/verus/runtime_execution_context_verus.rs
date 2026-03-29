use vstd::prelude::*;

verus! {

pub enum JobKindModel {
    Prove,
    Fold,
    Wrap,
}

pub enum ArtifactStateModel {
    Empty,
    PrimaryOnly,
    WrappedOnly,
    Dual,
}

pub open spec fn classify_job(
    has_wrapper_preview: bool,
    has_source_proof: bool,
    has_fold_witnesses: bool,
) -> JobKindModel {
    if has_wrapper_preview || has_source_proof {
        JobKindModel::Wrap
    } else if has_fold_witnesses {
        JobKindModel::Fold
    } else {
        JobKindModel::Prove
    }
}

pub open spec fn wrapper_sources_valid(
    job_kind: JobKindModel,
    has_source_artifact: bool,
    has_compiled: bool,
) -> bool {
    job_kind != JobKindModel::Wrap || (has_source_artifact && has_compiled)
}

pub open spec fn sorted_non_decreasing(slots: Seq<int>) -> bool {
    forall |i: int, j: int|
        0 <= i < j < slots.len() as int ==> slots[i] <= slots[j]
}

pub open spec fn artifact_state(has_primary: bool, has_wrapped: bool) -> ArtifactStateModel {
    match (has_primary, has_wrapped) {
        (false, false) => ArtifactStateModel::Empty,
        (true, false) => ArtifactStateModel::PrimaryOnly,
        (false, true) => ArtifactStateModel::WrappedOnly,
        (true, true) => ArtifactStateModel::Dual,
    }
}

pub open spec fn preferred_output_present(has_primary: bool, has_wrapped: bool) -> bool {
    has_primary || has_wrapped
}

pub open spec fn artifact_state_after_dispatch(
    has_primary: bool,
    has_wrapped: bool,
    dispatch_ok: bool,
    wrote_primary: bool,
    wrote_wrapped: bool,
) -> ArtifactStateModel {
    if dispatch_ok {
        artifact_state(has_primary || wrote_primary, has_wrapped || wrote_wrapped)
    } else {
        artifact_state(has_primary, has_wrapped)
    }
}

pub proof fn runtime_execution_context_artifact_state_machine(
    has_wrapper_preview: bool,
    has_source_proof: bool,
    has_fold_witnesses: bool,
    has_source_artifact: bool,
    has_compiled: bool,
    has_primary: bool,
    has_wrapped: bool,
    dispatch_ok: bool,
    wrote_primary: bool,
    wrote_wrapped: bool,
    initial_slots: Seq<int>,
)
    requires
        sorted_non_decreasing(initial_slots),
    ensures
        classify_job(has_wrapper_preview, has_source_proof, has_fold_witnesses) == JobKindModel::Wrap
            <==> (has_wrapper_preview || has_source_proof),
        classify_job(has_wrapper_preview, has_source_proof, has_fold_witnesses) == JobKindModel::Fold
            <==> !(has_wrapper_preview || has_source_proof) && has_fold_witnesses,
        classify_job(has_wrapper_preview, has_source_proof, has_fold_witnesses) == JobKindModel::Prove
            <==> !(has_wrapper_preview || has_source_proof) && !has_fold_witnesses,
        wrapper_sources_valid(
            classify_job(has_wrapper_preview, has_source_proof, has_fold_witnesses),
            has_source_artifact,
            has_compiled,
        ) == (
            classify_job(has_wrapper_preview, has_source_proof, has_fold_witnesses) != JobKindModel::Wrap
                || (has_source_artifact && has_compiled)
        ),
        sorted_non_decreasing(initial_slots),
        has_primary && has_wrapped ==> artifact_state(has_primary, has_wrapped) == ArtifactStateModel::Dual,
        has_primary && !has_wrapped ==> artifact_state(has_primary, has_wrapped) == ArtifactStateModel::PrimaryOnly,
        !has_primary && has_wrapped ==> artifact_state(has_primary, has_wrapped) == ArtifactStateModel::WrappedOnly,
        !has_primary && !has_wrapped ==> artifact_state(has_primary, has_wrapped) == ArtifactStateModel::Empty,
        preferred_output_present(has_primary, has_wrapped) == (has_primary || has_wrapped),
        artifact_state_after_dispatch(
            has_primary,
            has_wrapped,
            dispatch_ok,
            wrote_primary,
            wrote_wrapped,
        ) == if dispatch_ok {
            artifact_state(has_primary || wrote_primary, has_wrapped || wrote_wrapped)
        } else {
            artifact_state(has_primary, has_wrapped)
        },
{
}

} // verus!
