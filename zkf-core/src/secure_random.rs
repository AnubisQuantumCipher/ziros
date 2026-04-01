//! Hardware entropy source for cryptographic randomness.
//!
//! On macOS/iOS, uses `SecRandomCopyBytes` from Security.framework which
//! reads from the Secure Enclave's hardware TRNG. On other platforms,
//! falls back to `getrandom`.
//!
//! Groth16 and PLONK require random blinding factors that must be
//! cryptographically unpredictable. Hardware entropy is strictly superior
//! to software PRNG for this purpose.

/// Fill `buf` with cryptographically secure random bytes.
/// Uses Secure Enclave hardware TRNG on macOS, `getrandom` elsewhere.
pub fn secure_random_bytes(buf: &mut [u8]) -> Result<(), String> {
    platform_random_bytes(buf)
}

/// Generate `n` cryptographically secure random bytes.
pub fn secure_random_vec(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    secure_random_bytes(&mut buf)?;
    Ok(buf)
}

/// Generate a 32-byte cryptographic seed.
pub fn secure_random_seed() -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    secure_random_bytes(&mut seed)?;
    Ok(seed)
}

/// Source description for diagnostics.
pub fn entropy_source_name() -> &'static str {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        "SecRandomCopyBytes (Secure Enclave TRNG)"
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        "getrandom (OS entropy)"
    }
}

// ─── Platform implementations ───────────────────────────────────────────

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecRandomCopyBytes(rng: *const u8, count: libc::size_t, bytes: *mut u8) -> i32;
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn platform_random_bytes(buf: &mut [u8]) -> Result<(), String> {
    let ret = unsafe { SecRandomCopyBytes(std::ptr::null(), buf.len(), buf.as_mut_ptr()) };

    if ret == 0 {
        Ok(())
    } else {
        Err(format!("SecRandomCopyBytes failed with error code {ret}"))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn platform_random_bytes(buf: &mut [u8]) -> Result<(), String> {
    // Use libc getrandom on Linux, or /dev/urandom fallback
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if ret < 0 || (ret as usize) != buf.len() {
            return Err("getrandom failed".to_string());
        }
        return Ok(());
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: read from /dev/urandom
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")
            .map_err(|e| format!("failed to open /dev/urandom: {e}"))?;
        file.read_exact(buf)
            .map_err(|e| format!("failed to read /dev/urandom: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_random_bytes() {
        let mut buf = [0u8; 32];
        secure_random_bytes(&mut buf).expect("should generate random bytes");
        // Extremely unlikely all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn random_vec_correct_length() {
        let vec = secure_random_vec(64).expect("should generate random vec");
        assert_eq!(vec.len(), 64);
    }

    #[test]
    fn random_seed_not_zero() {
        let seed = secure_random_seed().expect("should generate seed");
        assert!(seed.iter().any(|&b| b != 0));
    }

    #[test]
    fn two_seeds_differ() {
        let s1 = secure_random_seed().expect("seed 1");
        let s2 = secure_random_seed().expect("seed 2");
        assert_ne!(
            s1, s2,
            "Two seeds should differ with overwhelming probability"
        );
    }

    #[test]
    fn entropy_source_name_nonempty() {
        assert!(!entropy_source_name().is_empty());
    }
}
