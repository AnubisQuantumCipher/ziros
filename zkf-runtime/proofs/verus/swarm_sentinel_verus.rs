use vstd::prelude::*;

verus! {

pub open spec fn canary_due(now_ms: int, next_due_ms: int) -> bool {
    next_due_ms == 0 || now_ms >= next_due_ms
}

pub open spec fn allow_digest(
    current_window_unix_ms: int,
    digests_emitted_in_window: nat,
    now_ms: int,
    rate_limit_per_sec: nat,
) -> Option<(int, nat)> {
    if rate_limit_per_sec == 0 {
        None
    } else {
        let window_start = now_ms - (now_ms % 1000);
        let emitted = if current_window_unix_ms == window_start {
            digests_emitted_in_window
        } else {
            0nat
        };
        if emitted >= rate_limit_per_sec {
            None
        } else {
            Some((window_start, emitted + 1))
        }
    }
}

pub open spec fn should_seal_baseline(
    observation_count: nat,
    seal_every_observations: nat,
    last_observation_count: Option<nat>,
    last_commitment_matches: bool,
) -> bool {
    seal_every_observations != 0
        && observation_count != 0
        && observation_count % seal_every_observations == 0
        && !(last_observation_count == Some(observation_count) && last_commitment_matches)
}

pub struct WelfordStateModel {
    pub count: nat,
    pub m2_scaled: nat,
}

pub struct JitterStateModel {
    pub variance_of_variance: WelfordStateModel,
    pub probe_baseline: WelfordStateModel,
    pub last_variance_scaled: nat,
    pub observation_count: nat,
}

pub open spec fn welford_variance_scaled(state: WelfordStateModel) -> nat {
    if state.count < 2 {
        0nat
    } else {
        state.m2_scaled / ((state.count - 1nat) as nat)
    }
}

pub open spec fn welford_z_score_scaled(state: WelfordStateModel, observed_delta_scaled: nat) -> nat {
    let variance = welford_variance_scaled(state);
    if variance == 0 {
        observed_delta_scaled
    } else {
        observed_delta_scaled / variance
    }
}

pub open spec fn jitter_variance_delta_scaled(
    current_variance_scaled: nat,
    last_variance_scaled: nat,
    observation_count: nat,
) -> nat {
    if observation_count == 0 {
        0nat
    } else if current_variance_scaled >= last_variance_scaled {
        (current_variance_scaled - last_variance_scaled) as nat
    } else {
        (last_variance_scaled - current_variance_scaled) as nat
    }
}

pub open spec fn jitter_variance_delta_score_scaled(
    state: JitterStateModel,
    current_variance_scaled: nat,
) -> nat {
    let delta = jitter_variance_delta_scaled(
        current_variance_scaled,
        state.last_variance_scaled,
        state.observation_count,
    );
    if state.variance_of_variance.count < 2 {
        delta
    } else {
        welford_z_score_scaled(state.variance_of_variance, delta)
    }
}

pub open spec fn jitter_probe_duration_score_scaled(
    state: JitterStateModel,
    duration_ns_scaled: nat,
) -> nat {
    if state.probe_baseline.count < 2 {
        duration_ns_scaled
    } else {
        welford_z_score_scaled(state.probe_baseline, duration_ns_scaled)
    }
}

pub proof fn swarm_sentinel_rate_limit_and_baseline_soundness(
    current_window_unix_ms: int,
    digests_emitted_in_window: nat,
    now_ms: int,
    rate_limit_per_sec: nat,
    observation_count: nat,
    seal_every_observations: nat,
)
    ensures
        canary_due(now_ms, 0),
        rate_limit_per_sec == 0 ==> allow_digest(
            current_window_unix_ms,
            digests_emitted_in_window,
            now_ms,
            rate_limit_per_sec,
        ).is_None(),
        rate_limit_per_sec > 0
            && digests_emitted_in_window < rate_limit_per_sec
            ==> allow_digest(
                now_ms - (now_ms % 1000),
                digests_emitted_in_window,
                now_ms,
                rate_limit_per_sec,
            ).is_Some(),
        should_seal_baseline(observation_count, seal_every_observations, Some(observation_count), true)
            == false,
{
}

pub proof fn jitter_detection_timing_model_finite_ok(
    state: JitterStateModel,
    current_variance_scaled: nat,
    duration_ns_scaled: nat,
)
    ensures
        welford_variance_scaled(state.variance_of_variance) >= 0,
        welford_variance_scaled(state.probe_baseline) >= 0,
        welford_z_score_scaled(
            state.variance_of_variance,
            jitter_variance_delta_scaled(
                current_variance_scaled,
                state.last_variance_scaled,
                state.observation_count,
            ),
        ) >= 0,
        jitter_variance_delta_score_scaled(state, current_variance_scaled) >= 0,
        jitter_probe_duration_score_scaled(state, duration_ns_scaled) >= 0,
{
}

} // verus!
