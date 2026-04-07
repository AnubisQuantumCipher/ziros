#![allow(dead_code)]

/// Shipped proof-core summary of the exact FRI transcript and verifier-guard
/// boundary used by the protocol hypothesis lane.
#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriExactSurfaceModel {
    pub transcript_matches: bool,
    pub seed_replay_matches: bool,
    pub merkle_queries_match: bool,
    pub verifier_accepts: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub fn fri_exact_verifier_guard(model: FriExactSurfaceModel) -> bool {
    model.transcript_matches && model.seed_replay_matches && model.merkle_queries_match
}

#[cfg_attr(hax, hax_lib::include)]
pub fn fri_exact_completeness_reduction(model: FriExactSurfaceModel) -> bool {
    !fri_exact_verifier_guard(model) || model.verifier_accepts
}

#[cfg_attr(hax, hax_lib::include)]
pub fn fri_exact_proximity_soundness_reduction(model: FriExactSurfaceModel) -> bool {
    !model.verifier_accepts || model.merkle_queries_match
}

#[cfg(test)]
mod tests {
    use super::{
        FriExactSurfaceModel, fri_exact_completeness_reduction,
        fri_exact_proximity_soundness_reduction, fri_exact_verifier_guard,
    };

    #[test]
    fn verifier_guard_tracks_transcript_seed_and_query_shape() {
        let good = FriExactSurfaceModel {
            transcript_matches: true,
            seed_replay_matches: true,
            merkle_queries_match: true,
            verifier_accepts: true,
        };
        assert!(fri_exact_verifier_guard(good));
        assert!(fri_exact_completeness_reduction(good));
        assert!(fri_exact_proximity_soundness_reduction(good));

        let bad = FriExactSurfaceModel {
            seed_replay_matches: false,
            ..good
        };
        assert!(!fri_exact_verifier_guard(bad));
        assert!(fri_exact_completeness_reduction(bad));
    }
}
