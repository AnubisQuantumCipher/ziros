//! ZKF Pro Backends
//!
//! This crate provides proprietary ZKF components under the Business Source
//! License 1.1 (BSL-1.1), converting to Apache-2.0 after 36 months.
//!
//! # Components
//!
//! - **STARK-to-SNARK wrapping**: Compress Plonky3 STARK proofs into constant-size
//!   Groth16 proofs for cheap on-chain verification (~280K gas).
//!
//! - **Halo2-to-Groth16 wrapping**: Convert Halo2 IPA proofs into Groth16 via
//!   commitment-bound re-prove.
//!
//! - **Metal GPU acceleration** (macOS, feature `metal-gpu`): MSM Pippenger,
//!   NTT butterfly, Poseidon2, SHA256, Keccak256, FRI fold on Apple Silicon.
//!
//! - **Midnight integration**: Compact DSL codegen, proof server client,
//!   transaction builder.
//!
//! # Usage
//!
//! ```rust,ignore
//! use zkf_backends_pro::pro_wrapper_registry;
//!
//! let registry = pro_wrapper_registry();
//! let wrapper = registry.find(BackendKind::Plonky3, BackendKind::ArkworksGroth16)
//!     .expect("STARK-to-Groth16 wrapper");
//! let wrapped = wrapper.wrap(&stark_proof, &compiled)?;
//! ```

// Re-export the wrapping pipeline from zkf-backends.
// In the full split, these modules will move here directly.
// For now, this crate acts as the licensing boundary.
pub use zkf_backends::wrapping;

// Re-export Midnight modules
pub use zkf_backends::midnight;
pub use zkf_backends::midnight_client;
pub use zkf_backends::midnight_codegen;
pub use zkf_backends::midnight_tx;

// Re-export Metal GPU when available
#[cfg(feature = "metal-gpu")]
pub use zkf_metal;

use zkf_core::wrapping::WrapperRegistry;

/// Create a wrapper registry with all Pro wrapping paths.
///
/// This is the Pro equivalent of `zkf_backends::wrapping::default_wrapper_registry()`.
/// Currently delegates to the same implementation; after the crate split,
/// the wrapping implementations will live here exclusively.
pub fn pro_wrapper_registry() -> WrapperRegistry {
    wrapping::default_wrapper_registry()
}

/// Check whether Pro features are available at runtime.
pub fn pro_available() -> bool {
    true
}

/// Report Pro component versions.
pub fn pro_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::BackendKind;

    #[test]
    fn pro_registry_has_wrappers() {
        let registry = pro_wrapper_registry();
        let paths = registry.available_paths();
        assert!(!paths.is_empty(), "Pro registry should have wrapping paths");
        assert!(
            registry
                .find(BackendKind::Plonky3, BackendKind::ArkworksGroth16)
                .is_some(),
            "STARK-to-Groth16 wrapper should be registered"
        );
    }

    #[test]
    fn pro_metadata() {
        assert!(pro_available());
        assert!(!pro_version().is_empty());
    }
}
