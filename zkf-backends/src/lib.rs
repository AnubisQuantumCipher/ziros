#![allow(unexpected_cfgs)]

#[cfg(hax)]
pub(crate) mod proof_blackbox_ecdsa_spec;
#[cfg(hax)]
pub(crate) mod proof_blackbox_hash_spec;
#[cfg(hax)]
pub(crate) mod proof_lookup_lowering_spec;
#[cfg(hax)]
pub(crate) mod proof_plonky3_surface;

#[cfg(not(hax))]
pub(crate) mod proof_lookup_lowering_spec;

#[cfg(not(hax))]
include!("lib_non_hax.rs");
