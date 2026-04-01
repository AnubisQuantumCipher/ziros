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

use crate::security::ThreatSeverity;
use crate::swarm::queen::ActivationLevel;

const PRESSURE_BASIS_POINTS_SCALE: u32 = 100;

pub(crate) fn level_rank(level: ActivationLevel) -> u8 {
    match level {
        ActivationLevel::Dormant => 0,
        ActivationLevel::Alert => 1,
        ActivationLevel::Active => 2,
        ActivationLevel::Emergency => 3,
    }
}

pub(crate) fn median_activation_rank(levels: &[u8]) -> u8 {
    if levels.is_empty() {
        return 0;
    }
    let mut normalized = levels.to_vec();
    normalized.sort_unstable();
    normalized[normalized.len() / 2].min(level_rank(ActivationLevel::Emergency))
}

pub(crate) fn severity_weight_basis_points(severity: ThreatSeverity) -> u32 {
    match severity {
        ThreatSeverity::Low => 75,
        ThreatSeverity::Moderate => 100,
        ThreatSeverity::High => 150,
        ThreatSeverity::Critical => 250,
        ThreatSeverity::ModelIntegrityCritical => 400,
    }
}

pub(crate) fn bias_basis_points(level: ActivationLevel) -> u32 {
    match level {
        ActivationLevel::Dormant => 1000,
        ActivationLevel::Alert => 1150,
        ActivationLevel::Active => 1350,
        ActivationLevel::Emergency => 1750,
    }
}

pub(crate) fn weighted_median_pressure_basis_points(values: &[(u32, u32)]) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let mut weighted = values.to_vec();
    weighted.sort_by_key(|(value, _)| *value);
    let total_weight = weighted
        .iter()
        .map(|(_, weight)| *weight as u64)
        .sum::<u64>()
        .max(1);
    let cutoff = total_weight / 2;
    let mut seen = 0u64;
    for (value, weight) in weighted {
        seen = seen.saturating_add(weight as u64);
        if seen >= cutoff {
            return value;
        }
    }
    0
}

#[allow(dead_code)]
pub(crate) fn cooldown_tick_level(
    level: ActivationLevel,
    cooldown_active: bool,
) -> ActivationLevel {
    if cooldown_active {
        return level;
    }
    match level {
        ActivationLevel::Dormant => ActivationLevel::Dormant,
        ActivationLevel::Alert => ActivationLevel::Dormant,
        ActivationLevel::Active => ActivationLevel::Alert,
        ActivationLevel::Emergency => ActivationLevel::Active,
    }
}

pub(crate) fn pressure_to_basis_points(value: f64) -> u32 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        (value * PRESSURE_BASIS_POINTS_SCALE as f64).round() as u32
    }
}

pub(crate) fn basis_points_to_pressure(value: u32) -> f64 {
    value as f64 / PRESSURE_BASIS_POINTS_SCALE as f64
}

#[cfg(test)]
mod tests {
    use super::{
        bias_basis_points, cooldown_tick_level, median_activation_rank,
        weighted_median_pressure_basis_points,
    };
    use crate::swarm::queen::ActivationLevel;

    #[test]
    fn cooldown_drops_at_most_one_level() {
        assert_eq!(
            cooldown_tick_level(ActivationLevel::Emergency, false),
            ActivationLevel::Active
        );
        assert_eq!(
            cooldown_tick_level(ActivationLevel::Active, true),
            ActivationLevel::Active
        );
    }

    #[test]
    fn activation_rank_and_bias_are_monotone() {
        assert_eq!(median_activation_rank(&[0, 3, 2]), 2);
        assert!(
            bias_basis_points(ActivationLevel::Emergency)
                > bias_basis_points(ActivationLevel::Alert)
        );
    }

    #[test]
    fn weighted_median_prefers_cumulative_weight_cutoff() {
        assert_eq!(
            weighted_median_pressure_basis_points(&[(100, 20), (800, 90), (200, 30)]),
            800
        );
    }
}
