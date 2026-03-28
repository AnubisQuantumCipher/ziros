//! Hardware acceleration for cryptographic primitives on Apple Silicon.
//!
//! This crate provides thin wrappers around ARM CPU crypto extensions
//! (FEAT_SHA256, FEAT_SHA3, FEAT_AES, FEAT_PMULL) and Apple-specific
//! accelerators (SME/AMX, Accelerate.framework) with pure-Rust fallbacks
//! for cross-compilation.
//!
//! All accelerated paths produce bit-identical results to software fallbacks.
//! Set `ZKF_CRYPTO_ACCEL=0` to disable all hardware paths.

pub mod accelerate_ffi;
pub mod aes;
pub mod detect;
pub mod keccak;
pub mod montgomery;
pub mod pmull;
pub mod sha256;
pub mod sme;

pub use detect::CryptoExtensions;

/// Check if hardware crypto acceleration is enabled via environment.
/// Returns `false` if `ZKF_CRYPTO_ACCEL=0`.
pub fn is_enabled() -> bool {
    !matches!(
        std::env::var("ZKF_CRYPTO_ACCEL").as_deref(),
        Ok("0") | Ok("false") | Ok("FALSE") | Ok("no") | Ok("NO")
    )
}
