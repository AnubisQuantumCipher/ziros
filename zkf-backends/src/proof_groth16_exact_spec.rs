#![allow(dead_code)]

/// Shipped proof-core summary of the exact Groth16 wrapper boundary used by the
/// protocol hypothesis lane.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Groth16ExactSurfaceModel {
    pub imported_crs_valid: bool,
    pub public_input_arity_matches: bool,
    pub encoding_matches: bool,
    pub verifier_accepts: bool,
    pub simulator_view_matches: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn groth16_verifier_guard(model: Groth16ExactSurfaceModel) -> bool {
    model.public_input_arity_matches && model.encoding_matches
}

#[cfg_attr(hax, hax_lib::include)]
pub fn groth16_exact_completeness_reduction(model: Groth16ExactSurfaceModel) -> bool {
    !model.imported_crs_valid || !groth16_verifier_guard(model) || model.verifier_accepts
}

#[cfg_attr(hax, hax_lib::include)]
pub fn groth16_exact_knowledge_soundness_reduction(model: Groth16ExactSurfaceModel) -> bool {
    !model.imported_crs_valid || !model.verifier_accepts || model.public_input_arity_matches
}

#[cfg_attr(hax, hax_lib::include)]
pub fn groth16_exact_zero_knowledge_reduction(model: Groth16ExactSurfaceModel) -> bool {
    !model.imported_crs_valid || model.simulator_view_matches
}

#[cfg(test)]
mod tests {
    use super::{
        Groth16ExactSurfaceModel, groth16_exact_completeness_reduction,
        groth16_exact_knowledge_soundness_reduction, groth16_exact_zero_knowledge_reduction,
        groth16_verifier_guard,
    };

    #[test]
    fn verifier_guard_requires_shape_and_encoding_match() {
        assert!(!groth16_verifier_guard(Groth16ExactSurfaceModel {
            imported_crs_valid: true,
            public_input_arity_matches: false,
            encoding_matches: true,
            verifier_accepts: true,
            simulator_view_matches: true,
        }));
        assert!(groth16_verifier_guard(Groth16ExactSurfaceModel {
            imported_crs_valid: true,
            public_input_arity_matches: true,
            encoding_matches: true,
            verifier_accepts: true,
            simulator_view_matches: true,
        }));
    }

    #[test]
    fn exact_reductions_fail_closed_when_assumptions_are_missing() {
        let accepted = Groth16ExactSurfaceModel {
            imported_crs_valid: true,
            public_input_arity_matches: true,
            encoding_matches: true,
            verifier_accepts: true,
            simulator_view_matches: true,
        };
        assert!(groth16_exact_completeness_reduction(accepted));
        assert!(groth16_exact_knowledge_soundness_reduction(accepted));
        assert!(groth16_exact_zero_knowledge_reduction(accepted));

        let malformed = Groth16ExactSurfaceModel {
            imported_crs_valid: false,
            ..accepted
        };
        assert!(groth16_exact_completeness_reduction(malformed));
        assert!(groth16_exact_knowledge_soundness_reduction(malformed));
        assert!(groth16_exact_zero_knowledge_reduction(malformed));
    }
}
