#![allow(dead_code)]

/// Shipped proof-core summary of the exact HyperNova CCS wrapper boundary used
/// by the protocol hypothesis lane.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HyperNovaExactSurfaceModel {
    pub ccs_metadata_complete: bool,
    pub verifier_guards_match: bool,
    pub fold_profile_matches: bool,
    pub verifier_accepts: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn hypernova_exact_verifier_guard(model: HyperNovaExactSurfaceModel) -> bool {
    model.ccs_metadata_complete && model.verifier_guards_match && model.fold_profile_matches
}

#[cfg_attr(hax, hax_lib::include)]
pub fn hypernova_exact_completeness_reduction(model: HyperNovaExactSurfaceModel) -> bool {
    !hypernova_exact_verifier_guard(model) || model.verifier_accepts
}

#[cfg_attr(hax, hax_lib::include)]
pub fn hypernova_exact_folding_soundness_reduction(model: HyperNovaExactSurfaceModel) -> bool {
    !model.verifier_accepts || model.fold_profile_matches
}

#[cfg(test)]
mod tests {
    use super::{
        HyperNovaExactSurfaceModel, hypernova_exact_completeness_reduction,
        hypernova_exact_folding_soundness_reduction, hypernova_exact_verifier_guard,
    };

    #[test]
    fn ccs_metadata_and_guard_shape_drive_the_exact_surface() {
        let good = HyperNovaExactSurfaceModel {
            ccs_metadata_complete: true,
            verifier_guards_match: true,
            fold_profile_matches: true,
            verifier_accepts: true,
        };
        assert!(hypernova_exact_verifier_guard(good));
        assert!(hypernova_exact_completeness_reduction(good));
        assert!(hypernova_exact_folding_soundness_reduction(good));
    }
}
