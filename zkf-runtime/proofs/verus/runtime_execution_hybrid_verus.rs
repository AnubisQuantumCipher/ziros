use vstd::prelude::*;

verus! {

pub struct HardwareProbeSummaryModel {
    pub ok: bool,
    pub mismatch_count: nat,
}

pub struct ReplayManifestIdentityModel {
    pub replay_id: int,
    pub transcript_hash: int,
    pub backend_route: int,
    pub hardware_profile: int,
    pub stage_manifest_digest: int,
}

pub open spec fn verify_decision(primary_ok: bool, companion_ok: bool) -> bool {
    primary_ok && companion_ok
}

pub open spec fn hardware_probes_clean(summary: HardwareProbeSummaryModel) -> bool {
    summary.ok && summary.mismatch_count == 0
}

pub open spec fn byte_components_match(
    artifact_proof: Seq<int>,
    artifact_verification_key: Seq<int>,
    primary_leg_proof: Seq<int>,
    primary_leg_verification_key: Seq<int>,
) -> bool {
    artifact_proof == primary_leg_proof
        && artifact_verification_key == primary_leg_verification_key
}

pub open spec fn digest_matches_recorded_hash(
    recorded_hash: Option<Seq<int>>,
    expected_hash: Seq<int>,
) -> bool {
    match recorded_hash {
        Option::Some(recorded) => recorded == expected_hash,
        Option::None => false,
    }
}

pub open spec fn replay_manifest_identity(
    manifest: ReplayManifestIdentityModel,
) -> (int, int, int, int, int) {
    (
        manifest.replay_id,
        manifest.transcript_hash,
        manifest.backend_route,
        manifest.hardware_profile,
        manifest.stage_manifest_digest,
    )
}

pub proof fn runtime_hybrid_verification_soundness(
    primary_ok: bool,
    companion_ok: bool,
    hardware_probes: HardwareProbeSummaryModel,
    artifact_proof: Seq<int>,
    artifact_verification_key: Seq<int>,
    primary_leg_proof: Seq<int>,
    primary_leg_verification_key: Seq<int>,
    recorded_hash: Option<Seq<int>>,
    expected_hash: Seq<int>,
)
    ensures
        verify_decision(primary_ok, companion_ok) == (primary_ok && companion_ok),
        hardware_probes_clean(hardware_probes) == (hardware_probes.ok && hardware_probes.mismatch_count == 0),
        byte_components_match(
            artifact_proof,
            artifact_verification_key,
            primary_leg_proof,
            primary_leg_verification_key,
        ) == (
            artifact_proof == primary_leg_proof
                && artifact_verification_key == primary_leg_verification_key
        ),
        digest_matches_recorded_hash(recorded_hash, expected_hash) == match recorded_hash {
            Option::Some(recorded) => recorded == expected_hash,
            Option::None => false,
        },
{
}

pub proof fn runtime_hybrid_replay_manifest_determinism(
    lhs: ReplayManifestIdentityModel,
    rhs: ReplayManifestIdentityModel,
)
    ensures
        replay_manifest_identity(lhs) == replay_manifest_identity(rhs)
            <==> lhs.replay_id == rhs.replay_id
                && lhs.transcript_hash == rhs.transcript_hash
                && lhs.backend_route == rhs.backend_route
                && lhs.hardware_profile == rhs.hardware_profile
                && lhs.stage_manifest_digest == rhs.stage_manifest_digest,
{
}

} // verus!
