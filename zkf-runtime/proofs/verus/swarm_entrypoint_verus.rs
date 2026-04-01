use vstd::prelude::*;

verus! {

pub struct SecurityContextModel {
    pub rate_limit_violation_count: nat,
    pub auth_failure_count: nat,
    pub malformed_request_count: nat,
    pub backend_incompatibility_attempt_count: nat,
    pub anonymous_burst: bool,
    pub telemetry_replay_detected: bool,
    pub integrity_mismatch_detected: bool,
}

pub open spec fn context_has_security_signal(ctx: SecurityContextModel) -> bool {
    ctx.rate_limit_violation_count > 0
        || ctx.auth_failure_count > 0
        || ctx.malformed_request_count > 0
        || ctx.backend_incompatibility_attempt_count > 0
        || ctx.anonymous_burst
        || ctx.telemetry_replay_detected
        || ctx.integrity_mismatch_detected
}

pub proof fn swarm_entrypoint_signal_routing(ctx: SecurityContextModel)
    ensures
        ctx.malformed_request_count > 0 ==> context_has_security_signal(ctx),
        ctx.auth_failure_count > 0 ==> context_has_security_signal(ctx),
        !ctx.anonymous_burst
            && !ctx.telemetry_replay_detected
            && !ctx.integrity_mismatch_detected
            && ctx.rate_limit_violation_count == 0
            && ctx.auth_failure_count == 0
            && ctx.malformed_request_count == 0
            && ctx.backend_incompatibility_attempt_count == 0
            ==> !context_has_security_signal(ctx),
{
}

} // verus!
