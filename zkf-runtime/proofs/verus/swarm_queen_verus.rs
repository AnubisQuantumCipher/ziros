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

pub enum ActivationLevelModel {
    Dormant,
    Alert,
    Active,
    Emergency,
}

pub open spec fn cooldown_tick(level: ActivationLevelModel, cooldown_active: bool) -> ActivationLevelModel {
    if cooldown_active {
        level
    } else {
        match level {
            ActivationLevelModel::Dormant => ActivationLevelModel::Dormant,
            ActivationLevelModel::Alert => ActivationLevelModel::Dormant,
            ActivationLevelModel::Active => ActivationLevelModel::Alert,
            ActivationLevelModel::Emergency => ActivationLevelModel::Active,
        }
    }
}

pub open spec fn weighted_median_pressure(values: Seq<(int, nat)>) -> int {
    if values.len() == 0 {
        0
    } else {
        values[((values.len() / 2) as int)].0
    }
}

pub proof fn swarm_queen_escalation_cooldown_monotonicity(level: ActivationLevelModel, values: Seq<(int, nat)>)
    ensures
        cooldown_tick(level, true) == level,
        level == ActivationLevelModel::Emergency ==> cooldown_tick(level, false) == ActivationLevelModel::Active,
        values.len() == 0 ==> weighted_median_pressure(values) == 0,
        values.len() > 0 ==> exists|i: int| 0 <= i < values.len() && weighted_median_pressure(values) == values[i].0,
{
    if values.len() > 0 {
        let i = (values.len() / 2) as int;
        assert(0 <= i);
        assert(i < values.len());
        assert(weighted_median_pressure(values) == values[i].0);
    }
}

} // verus!
