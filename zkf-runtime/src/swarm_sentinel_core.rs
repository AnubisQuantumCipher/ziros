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

pub(crate) fn canary_due(now_ms: u128, next_due_unix_ms: u128) -> bool {
    next_due_unix_ms == 0 || now_ms >= next_due_unix_ms
}

pub(crate) fn allow_digest(
    current_window_unix_ms: u128,
    digests_emitted_in_window: u32,
    now_ms: u128,
    rate_limit_per_sec: u32,
) -> Option<(u128, u32)> {
    if rate_limit_per_sec == 0 {
        return None;
    }
    let window_start = now_ms - (now_ms % 1_000);
    let emitted = if current_window_unix_ms == window_start {
        digests_emitted_in_window
    } else {
        0
    };
    if emitted >= rate_limit_per_sec {
        None
    } else {
        Some((window_start, emitted + 1))
    }
}

pub(crate) fn should_seal_baseline(
    observation_count: u64,
    seal_every_observations: u64,
    last_observation_count: Option<u64>,
    last_commitment_matches: bool,
) -> bool {
    seal_every_observations != 0
        && observation_count != 0
        && observation_count.is_multiple_of(seal_every_observations)
        && !(last_observation_count == Some(observation_count) && last_commitment_matches)
}

pub(crate) fn should_emit_drift_digest(
    current_count: u64,
    reference_count: u64,
    drift_score_millis: u32,
    baseline_drift_threshold_millis: u32,
) -> bool {
    current_count > reference_count && drift_score_millis > baseline_drift_threshold_millis
}

#[cfg(test)]
mod tests {
    use super::{allow_digest, canary_due, should_emit_drift_digest, should_seal_baseline};

    #[test]
    fn digest_rate_limit_is_fail_closed() {
        assert_eq!(allow_digest(0, 0, 1_000, 0), None);
        assert_eq!(allow_digest(1_000, 1, 1_200, 1), None);
        assert_eq!(allow_digest(1_000, 0, 1_200, 1), Some((1_000, 1)));
    }

    #[test]
    fn canary_deadlines_are_monotone() {
        assert!(canary_due(10, 0));
        assert!(canary_due(10, 10));
        assert!(!canary_due(9, 10));
    }

    #[test]
    fn baseline_seals_and_drift_require_new_observations() {
        assert!(should_seal_baseline(6, 3, Some(3), false));
        assert!(!should_seal_baseline(6, 3, Some(6), true));
        assert!(should_emit_drift_digest(7, 6, 4000, 3500));
        assert!(!should_emit_drift_digest(6, 6, 4000, 3500));
    }
}
