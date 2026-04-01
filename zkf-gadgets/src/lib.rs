pub mod blake3;
pub mod boolean;
pub mod comparison;
pub mod ecdsa;
pub mod gadget;
pub mod kzg;
pub mod merkle;
pub mod nonnative;
pub mod plonk_gate;
pub mod poseidon;
pub mod range;
pub mod registry;
pub mod schnorr;
pub mod secp256k1;
pub mod sha256;

pub use gadget::{
    BUILTIN_GADGET_NAMES, Gadget, GadgetEmission, GadgetRegistry, builtin_supported_field_names,
    builtin_supported_fields, validate_builtin_field_support,
};
pub use registry::{AuditStatus as GadgetAuditStatus, GadgetSpec, all_gadget_specs, gadget_spec};
