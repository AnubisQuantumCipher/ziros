use vstd::prelude::*;

verus! {

pub open spec fn controller_artifact_path(enabled: bool, reject: bool) -> Option<bool> {
    if enabled && reject {
        None
    } else {
        Some(true)
    }
}

pub proof fn swarm_artifact_non_mutation_surface(enabled: bool)
    ensures
        controller_artifact_path(enabled, false) == Some(true),
        controller_artifact_path(false, true) == Some(true),
        controller_artifact_path(true, true).is_None(),
{
}

} // verus!
