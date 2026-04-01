// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

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

} // verus!
