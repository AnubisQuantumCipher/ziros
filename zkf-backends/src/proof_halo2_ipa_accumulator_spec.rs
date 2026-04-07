#![allow(dead_code)]

/// Shipped proof-core summary of the metadata binding shape required before the
/// deferred IPA/Groth16 recomputation can proceed.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Halo2IpaBindingModel {
    pub proof_count: usize,
    pub proof_hash_count: usize,
    pub bound_g_point_count: usize,
    pub malformed_g_point_count: usize,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn halo2_ipa_binding_accepts(model: Halo2IpaBindingModel) -> bool {
    model.proof_count > 0
        && model.proof_hash_count == model.proof_count
        && model.bound_g_point_count == model.proof_count
        && model.malformed_g_point_count == 0
}

#[cfg(test)]
mod tests {
    use super::{Halo2IpaBindingModel, halo2_ipa_binding_accepts};

    #[test]
    fn accepts_only_complete_nonempty_binding_batches() {
        assert!(halo2_ipa_binding_accepts(Halo2IpaBindingModel {
            proof_count: 2,
            proof_hash_count: 2,
            bound_g_point_count: 2,
            malformed_g_point_count: 0,
        }));
        assert!(!halo2_ipa_binding_accepts(Halo2IpaBindingModel {
            proof_count: 0,
            proof_hash_count: 0,
            bound_g_point_count: 0,
            malformed_g_point_count: 0,
        }));
        assert!(!halo2_ipa_binding_accepts(Halo2IpaBindingModel {
            proof_count: 2,
            proof_hash_count: 1,
            bound_g_point_count: 2,
            malformed_g_point_count: 0,
        }));
    }
}
