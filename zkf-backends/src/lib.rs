#![allow(unexpected_cfgs)]

#[cfg(hax)]
pub(crate) mod proof_blackbox_ecdsa_spec;
#[cfg(hax)]
pub(crate) mod proof_blackbox_hash_spec;
#[cfg(hax)]
pub(crate) mod proof_fri_exact_spec;
#[cfg(hax)]
pub(crate) mod proof_groth16_boundary_spec;
#[cfg(hax)]
pub(crate) mod proof_groth16_exact_spec;
#[cfg(hax)]
pub(crate) mod proof_halo2_ipa_accumulator_spec;
#[cfg(hax)]
pub(crate) mod proof_hypernova_exact_spec;
#[cfg(hax)]
pub(crate) mod proof_lookup_lowering_spec;
#[cfg(hax)]
pub(crate) mod proof_nova_exact_spec;
#[cfg(hax)]
pub(crate) mod proof_plonky3_surface;

#[cfg(not(hax))]
pub(crate) mod proof_lookup_lowering_spec;

#[cfg(not(hax))]
include!("lib_non_hax.rs");
