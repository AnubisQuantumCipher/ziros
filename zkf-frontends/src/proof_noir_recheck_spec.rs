#![allow(dead_code)]

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SpecNoirRecheckStatus {
    Accepted,
    Rejected,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SpecNoirRecheckBoundary {
    pub(crate) translated_constraints_valid: bool,
    pub(crate) acvm_witness_present: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn noir_acir_recheck_wrapper_surface(
    boundary: SpecNoirRecheckBoundary,
) -> SpecNoirRecheckStatus {
    if boundary.translated_constraints_valid && boundary.acvm_witness_present {
        SpecNoirRecheckStatus::Accepted
    } else {
        SpecNoirRecheckStatus::Rejected
    }
}
