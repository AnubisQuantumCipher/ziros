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
