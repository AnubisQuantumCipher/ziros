//! Runtime ISA feature detection for ARM CPU crypto extensions.
//!
//! On macOS/iOS, detects features via `sysctl hw.optional.arm.FEAT_*`.
//! On other platforms, returns false for all features.

use std::sync::OnceLock;

/// Available ARM CPU cryptographic extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CryptoExtensions {
    /// FEAT_SHA256: hardware SHA-256 (SHA256H, SHA256H2, SHA256SU0, SHA256SU1)
    pub sha256: bool,
    /// FEAT_SHA3: hardware SHA-3/Keccak (EOR3, RAX1, XAR, BCAX)
    pub sha3: bool,
    /// FEAT_AES: hardware AES (AESE, AESD, AESMC, AESIMC)
    pub aes: bool,
    /// FEAT_PMULL: polynomial multiply (PMULL, PMULL2) for GF(2^128)
    pub pmull: bool,
    /// FEAT_SME: Scalable Matrix Extension
    pub sme: bool,
}

impl CryptoExtensions {
    /// Detect available crypto extensions at runtime.
    pub fn detect() -> Self {
        *DETECTED.get_or_init(detect_extensions)
    }

    /// Return true if any hardware crypto extension is available.
    pub fn any_available(&self) -> bool {
        self.sha256 || self.sha3 || self.aes || self.pmull || self.sme
    }

    /// Summary string for diagnostics.
    pub fn summary(&self) -> String {
        let mut features = Vec::new();
        if self.sha256 {
            features.push("SHA256");
        }
        if self.sha3 {
            features.push("SHA3");
        }
        if self.aes {
            features.push("AES");
        }
        if self.pmull {
            features.push("PMULL");
        }
        if self.sme {
            features.push("SME");
        }
        if features.is_empty() {
            "none".to_string()
        } else {
            features.join(", ")
        }
    }
}

static DETECTED: OnceLock<CryptoExtensions> = OnceLock::new();

#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
fn detect_extensions() -> CryptoExtensions {
    CryptoExtensions {
        sha256: sysctl_bool("hw.optional.arm.FEAT_SHA256"),
        sha3: sysctl_bool("hw.optional.arm.FEAT_SHA3"),
        aes: sysctl_bool("hw.optional.arm.FEAT_AES"),
        pmull: sysctl_bool("hw.optional.arm.FEAT_PMULL"),
        sme: sysctl_bool("hw.optional.arm.FEAT_SME"),
    }
}

#[cfg(not(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios"))))]
fn detect_extensions() -> CryptoExtensions {
    CryptoExtensions::default()
}

#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "ios")))]
fn sysctl_bool(name: &str) -> bool {
    use std::ffi::CString;

    let Ok(c_name) = CString::new(name) else {
        return false;
    };
    let mut value: i32 = 0;
    let mut size: libc::size_t = std::mem::size_of::<i32>();
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            &raw mut value as *mut libc::c_void,
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    ret == 0 && value != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_does_not_panic() {
        let ext = CryptoExtensions::detect();
        let _ = ext.summary();
    }

    #[test]
    fn default_is_all_false() {
        let ext = CryptoExtensions::default();
        assert!(!ext.any_available());
        assert_eq!(ext.summary(), "none");
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    fn macos_aarch64_has_sha256() {
        // All Apple Silicon (M1+) has FEAT_SHA256
        let ext = CryptoExtensions::detect();
        assert!(ext.sha256, "Expected SHA256 on Apple Silicon");
        assert!(ext.aes, "Expected AES on Apple Silicon");
    }
}
