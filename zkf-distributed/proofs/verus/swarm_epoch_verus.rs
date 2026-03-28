use vstd::prelude::*;

verus! {

pub open spec fn has_plaintext_threat_surface(
    digest_count: nat,
    activation_level_present: bool,
    intelligence_root_present: bool,
    local_pressure_present: bool,
    network_pressure_present: bool,
) -> bool {
    digest_count > 0
        || activation_level_present
        || intelligence_root_present
        || local_pressure_present
        || network_pressure_present
}

pub open spec fn encrypted_gossip_negotiated(
    local_support: bool,
    remote_support: bool,
    remote_epoch_keys_present: bool,
) -> bool {
    local_support && remote_support && remote_epoch_keys_present
}

pub proof fn swarm_epoch_negotiation_fail_closed(
    digest_count: nat,
    activation_level_present: bool,
    intelligence_root_present: bool,
    local_pressure_present: bool,
    network_pressure_present: bool,
)
    ensures
        encrypted_gossip_negotiated(true, true, true),
        !encrypted_gossip_negotiated(true, true, false),
        !has_plaintext_threat_surface(0, false, false, false, false),
        digest_count > 0
            || activation_level_present
            || intelligence_root_present
            || local_pressure_present
            || network_pressure_present
            ==> has_plaintext_threat_surface(
                digest_count,
                activation_level_present,
                intelligence_root_present,
                local_pressure_present,
                network_pressure_present,
            ),
{
}

} // verus!
