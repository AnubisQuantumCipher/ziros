#![allow(dead_code)]

/// Shipped proof-core summary of the exact classic-Nova recursive wrapper
/// boundary used by the protocol hypothesis lane.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NovaExactSurfaceModel {
    pub metadata_complete: bool,
    pub verifier_guards_match: bool,
    pub fold_profile_matches: bool,
    pub verifier_accepts: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn complete_classic_nova_ivc_metadata(model: NovaExactSurfaceModel) -> bool {
    model.metadata_complete
}

#[cfg_attr(hax, hax_lib::include)]
pub fn nova_exact_verifier_guard(model: NovaExactSurfaceModel) -> bool {
    model.verifier_guards_match && model.fold_profile_matches
}

#[cfg_attr(hax, hax_lib::include)]
pub fn nova_exact_completeness_reduction(model: NovaExactSurfaceModel) -> bool {
    !complete_classic_nova_ivc_metadata(model)
        || !nova_exact_verifier_guard(model)
        || model.verifier_accepts
}

#[cfg_attr(hax, hax_lib::include)]
pub fn nova_exact_folding_soundness_reduction(model: NovaExactSurfaceModel) -> bool {
    !model.verifier_accepts || model.fold_profile_matches
}

#[cfg(test)]
mod tests {
    use super::{
        NovaExactSurfaceModel, complete_classic_nova_ivc_metadata,
        nova_exact_completeness_reduction, nova_exact_folding_soundness_reduction,
        nova_exact_verifier_guard,
    };

    #[test]
    fn metadata_and_guard_shape_drive_the_exact_surface() {
        let good = NovaExactSurfaceModel {
            metadata_complete: true,
            verifier_guards_match: true,
            fold_profile_matches: true,
            verifier_accepts: true,
        };
        assert!(complete_classic_nova_ivc_metadata(good));
        assert!(nova_exact_verifier_guard(good));
        assert!(nova_exact_completeness_reduction(good));
        assert!(nova_exact_folding_soundness_reduction(good));
    }
}
