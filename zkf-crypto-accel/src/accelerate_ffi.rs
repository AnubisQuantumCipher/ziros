//! FFI bindings to Apple's Accelerate.framework for vectorized math.
//!
//! Accelerate provides hardware-optimized FFT (vDSP) and sparse matrix ops
//! running on AMX/SME internally. vDSP routines hit ~1.49 TFLOPS on M4.
//!
//! Used for polynomial evaluation and sparse constraint evaluation.

/// Evaluate polynomial using vectorized Horner's method.
/// Evaluates `coeffs` at each point in `points`, returning results.
///
/// This uses Accelerate's vDSP when on macOS, otherwise scalar Horner.
pub fn batch_eval_polynomial_f64(coeffs: &[f64], points: &[f64]) -> Vec<f64> {
    if crate::is_enabled() {
        #[cfg(target_os = "macos")]
        {
            return batch_eval_polynomial_accelerate(coeffs, points);
        }
    }
    #[allow(unreachable_code)]
    batch_eval_polynomial_scalar(coeffs, points)
}

/// Scalar Horner evaluation (fallback).
pub fn batch_eval_polynomial_scalar(coeffs: &[f64], points: &[f64]) -> Vec<f64> {
    points
        .iter()
        .map(|&x| {
            let mut result = 0.0f64;
            for coeff in coeffs.iter().rev() {
                result = result * x + coeff;
            }
            result
        })
        .collect()
}

// ─── Accelerate.framework FFI ───────────────────────────────────────────

#[cfg(target_os = "macos")]
#[link(name = "Accelerate", kind = "framework")]
unsafe extern "C" {
    // vDSP polynomial evaluation: evaluates polynomial at single point
    fn vDSP_vpolyD(
        coefficients: *const f64,
        stride_coefficients: i64,
        x: *const f64,
        stride_x: i64,
        result: *mut f64,
        stride_result: i64,
        n: u64,      // number of points
        degree: u64, // polynomial degree (len(coeffs) - 1)
    );

    // vDSP vector multiply
    fn vDSP_vmulD(
        a: *const f64,
        stride_a: i64,
        b: *const f64,
        stride_b: i64,
        c: *mut f64,
        stride_c: i64,
        n: u64,
    );

    // vDSP vector add
    fn vDSP_vaddD(
        a: *const f64,
        stride_a: i64,
        b: *const f64,
        stride_b: i64,
        c: *mut f64,
        stride_c: i64,
        n: u64,
    );
}

#[cfg(target_os = "macos")]
fn batch_eval_polynomial_accelerate(coeffs: &[f64], points: &[f64]) -> Vec<f64> {
    if coeffs.is_empty() || points.is_empty() {
        return vec![0.0; points.len()];
    }

    // vDSP_vpolyD evaluates a polynomial at multiple points using vectorized Horner
    // coefficients must be in descending order (highest degree first)
    let reversed_coeffs: Vec<f64> = coeffs.iter().rev().copied().collect();
    let degree = coeffs.len() - 1;
    let n = points.len();
    let mut result = vec![0.0f64; n];

    unsafe {
        vDSP_vpolyD(
            reversed_coeffs.as_ptr(),
            1,
            points.as_ptr(),
            1,
            result.as_mut_ptr(),
            1,
            n as u64,
            degree as u64,
        );
    }

    result
}

/// Vectorized f64 multiply using Accelerate (used for field-like operations).
pub fn vec_mul_f64(a: &[f64], b: &[f64]) -> Vec<f64> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut result = vec![0.0f64; n];

    #[cfg(target_os = "macos")]
    if crate::is_enabled() {
        unsafe {
            vDSP_vmulD(
                a.as_ptr(),
                1,
                b.as_ptr(),
                1,
                result.as_mut_ptr(),
                1,
                n as u64,
            );
        }
        return result;
    }

    for i in 0..n {
        result[i] = a[i] * b[i];
    }
    result
}

/// Vectorized f64 add using Accelerate.
pub fn vec_add_f64(a: &[f64], b: &[f64]) -> Vec<f64> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut result = vec![0.0f64; n];

    #[cfg(target_os = "macos")]
    if crate::is_enabled() {
        unsafe {
            vDSP_vaddD(
                a.as_ptr(),
                1,
                b.as_ptr(),
                1,
                result.as_mut_ptr(),
                1,
                n as u64,
            );
        }
        return result;
    }

    for i in 0..n {
        result[i] = a[i] + b[i];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_eval_constant() {
        let coeffs = [42.0];
        let points = [0.0, 1.0, 2.0, 3.0];
        let result = batch_eval_polynomial_scalar(&coeffs, &points);
        for &r in &result {
            assert!((r - 42.0).abs() < 1e-10);
        }
    }

    #[test]
    fn scalar_eval_linear() {
        // p(x) = 3 + 2x → p(0)=3, p(1)=5, p(2)=7
        let coeffs = [3.0, 2.0];
        let points = [0.0, 1.0, 2.0];
        let result = batch_eval_polynomial_scalar(&coeffs, &points);
        assert!((result[0] - 3.0).abs() < 1e-10);
        assert!((result[1] - 5.0).abs() < 1e-10);
        assert!((result[2] - 7.0).abs() < 1e-10);
    }

    #[test]
    fn vec_mul_basic() {
        let a = [1.0, 2.0, 3.0, 4.0];
        let b = [5.0, 6.0, 7.0, 8.0];
        let result = vec_mul_f64(&a, &b);
        assert!((result[0] - 5.0).abs() < 1e-10);
        assert!((result[1] - 12.0).abs() < 1e-10);
        assert!((result[2] - 21.0).abs() < 1e-10);
        assert!((result[3] - 32.0).abs() < 1e-10);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn accelerate_matches_scalar() {
        let coeffs = [1.0, 2.0, 3.0]; // 1 + 2x + 3x^2
        let points: Vec<f64> = (0..100).map(|i| i as f64 * 0.1).collect();
        let scalar = batch_eval_polynomial_scalar(&coeffs, &points);
        let accel = batch_eval_polynomial_accelerate(&coeffs, &points);
        for (s, a) in scalar.iter().zip(accel.iter()) {
            assert!((s - a).abs() < 1e-6, "Mismatch: scalar={s}, accelerate={a}");
        }
    }
}
