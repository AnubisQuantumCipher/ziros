//! Stable GPU acceleration abstraction layer for ZKF.
//!
//! This crate defines portable device/buffer/operation interfaces for GPU
//! accelerators. It does not claim a finished cross-platform proving backend;
//! the production accelerator implementation in this tree is the Metal path in
//! `zkf-metal`.

pub mod buffer;
pub mod device;
pub mod ops;

pub use buffer::{GpuBuffer, GpuBufferUsage};
pub use device::{GpuBackend, GpuDevice, GpuDeviceInfo};
pub use ops::{GpuHash, GpuMsm, GpuNtt, GpuOpResult, GpuOperation};

#[cfg(test)]
mod tests {
    use super::*;

    // ── GpuBackend ──────────────────────────────────────────────────

    #[test]
    fn backend_display() {
        assert_eq!(GpuBackend::Metal.to_string(), "Metal");
        assert_eq!(GpuBackend::WebGpu.to_string(), "WebGPU");
        assert_eq!(GpuBackend::Vulkan.to_string(), "Vulkan");
        assert_eq!(GpuBackend::None.to_string(), "None (CPU)");
    }

    #[test]
    fn backend_serde_roundtrip() {
        for backend in [
            GpuBackend::Metal,
            GpuBackend::WebGpu,
            GpuBackend::Vulkan,
            GpuBackend::None,
        ] {
            let json = serde_json::to_string(&backend).unwrap();
            let back: GpuBackend = serde_json::from_str(&json).unwrap();
            assert_eq!(backend, back);
        }
    }

    #[test]
    fn backend_serde_snake_case() {
        let json = serde_json::to_string(&GpuBackend::WebGpu).unwrap();
        assert_eq!(json, "\"web_gpu\"");
        let json = serde_json::to_string(&GpuBackend::None).unwrap();
        assert_eq!(json, "\"none\"");
    }

    #[test]
    fn backend_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(GpuBackend::Metal);
        set.insert(GpuBackend::Metal);
        assert_eq!(set.len(), 1);
        set.insert(GpuBackend::WebGpu);
        assert_eq!(set.len(), 2);
    }

    // ── GpuDeviceInfo ───────────────────────────────────────────────

    #[test]
    fn device_info_serde_roundtrip() {
        let info = GpuDeviceInfo {
            name: "Apple M4 Max GPU".into(),
            backend: GpuBackend::Metal,
            compute_units: Some(40),
            max_buffer_size: Some(8 * 1024 * 1024 * 1024),
            unified_memory: true,
            memory_bytes: Some(128 * 1024 * 1024 * 1024),
            max_workgroup_size: Some(1024),
            max_workgroups: Some(65535),
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        let back: GpuDeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Apple M4 Max GPU");
        assert_eq!(back.backend, GpuBackend::Metal);
        assert_eq!(back.compute_units, Some(40));
        assert!(back.unified_memory);
    }

    #[test]
    fn device_info_optional_fields() {
        let info = GpuDeviceInfo {
            name: "Generic GPU".into(),
            backend: GpuBackend::WebGpu,
            compute_units: None,
            max_buffer_size: None,
            unified_memory: false,
            memory_bytes: None,
            max_workgroup_size: None,
            max_workgroups: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: GpuDeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.compute_units, None);
        assert!(!back.unified_memory);
    }

    // ── GpuOperation ────────────────────────────────────────────────

    #[test]
    fn operation_display_all() {
        let expected = [
            (GpuOperation::Msm, "MSM"),
            (GpuOperation::Ntt, "NTT"),
            (GpuOperation::InverseNtt, "iNTT"),
            (GpuOperation::Poseidon2Hash, "Poseidon2"),
            (GpuOperation::MerkleTree, "Merkle"),
            (GpuOperation::FriFold, "FRI fold"),
            (GpuOperation::FieldArithmetic, "Field ops"),
            (GpuOperation::ConstraintEval, "Constraints"),
            (GpuOperation::PolynomialEval, "Polynomial"),
            (GpuOperation::BitonicSort, "Bitonic sort"),
        ];
        for (op, label) in expected {
            assert_eq!(op.to_string(), label);
        }
    }

    #[test]
    fn operation_serde_roundtrip() {
        let ops = [
            GpuOperation::Msm,
            GpuOperation::Ntt,
            GpuOperation::InverseNtt,
            GpuOperation::Poseidon2Hash,
            GpuOperation::MerkleTree,
            GpuOperation::FriFold,
            GpuOperation::FieldArithmetic,
            GpuOperation::ConstraintEval,
            GpuOperation::PolynomialEval,
            GpuOperation::BitonicSort,
        ];
        for op in ops {
            let json = serde_json::to_string(&op).unwrap();
            let back: GpuOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn operation_serde_snake_case() {
        let json = serde_json::to_string(&GpuOperation::InverseNtt).unwrap();
        assert_eq!(json, "\"inverse_ntt\"");
        let json = serde_json::to_string(&GpuOperation::Poseidon2Hash).unwrap();
        assert_eq!(json, "\"poseidon2_hash\"");
    }

    // ── GpuOpResult ─────────────────────────────────────────────────

    #[test]
    fn op_result_success() {
        let r = GpuOpResult {
            success: true,
            gpu_time_ms: 12.5,
            cpu_overhead_ms: 0.3,
            elements_processed: 1 << 20,
            error: None,
        };
        assert!(r.success);
        assert!(r.error.is_none());
        let json = serde_json::to_string(&r).unwrap();
        let back: GpuOpResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.elements_processed, 1 << 20);
    }

    #[test]
    fn op_result_failure() {
        let r = GpuOpResult {
            success: false,
            gpu_time_ms: 0.0,
            cpu_overhead_ms: 0.1,
            elements_processed: 0,
            error: Some("device lost".into()),
        };
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("device lost"));
    }

    // ── GpuCapabilities ─────────────────────────────────────────────

    #[test]
    fn capabilities_serde_roundtrip() {
        let caps = ops::GpuCapabilities {
            backend: GpuBackend::Metal,
            supported_ops: vec![
                GpuOperation::Msm,
                GpuOperation::Ntt,
                GpuOperation::Poseidon2Hash,
            ],
            max_field_bits: 256,
            supports_u64: true,
        };
        let json = serde_json::to_string_pretty(&caps).unwrap();
        let back: ops::GpuCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back.supported_ops.len(), 3);
        assert!(back.supports_u64);
        assert_eq!(back.max_field_bits, 256);
    }

    // ── GpuBuffer ───────────────────────────────────────────────────

    #[test]
    fn buffer_new_defaults() {
        let buf = GpuBuffer::new(4096, GpuBufferUsage::ReadOnly);
        assert_eq!(buf.size_bytes, 4096);
        assert_eq!(buf.usage, GpuBufferUsage::ReadOnly);
        assert!(!buf.unified);
        assert!(buf.label.is_none());
    }

    #[test]
    fn buffer_builder_pattern() {
        let buf = GpuBuffer::new(1024 * 1024, GpuBufferUsage::ReadWrite)
            .with_unified(true)
            .with_label("scalars");
        assert!(buf.unified);
        assert_eq!(buf.label.as_deref(), Some("scalars"));
    }

    #[test]
    fn buffer_size_helpers() {
        let buf = GpuBuffer::new(2 * 1024 * 1024, GpuBufferUsage::WriteOnly);
        assert!((buf.size_kb() - 2048.0).abs() < f64::EPSILON);
        assert!((buf.size_mb() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn buffer_size_zero() {
        let buf = GpuBuffer::new(0, GpuBufferUsage::Uniform);
        assert_eq!(buf.size_bytes, 0);
        assert!((buf.size_kb()).abs() < f64::EPSILON);
        assert!((buf.size_mb()).abs() < f64::EPSILON);
    }

    #[test]
    fn buffer_usage_serde_roundtrip() {
        for usage in [
            GpuBufferUsage::ReadOnly,
            GpuBufferUsage::WriteOnly,
            GpuBufferUsage::ReadWrite,
            GpuBufferUsage::Uniform,
        ] {
            let json = serde_json::to_string(&usage).unwrap();
            let back: GpuBufferUsage = serde_json::from_str(&json).unwrap();
            assert_eq!(usage, back);
        }
    }

    #[test]
    fn buffer_usage_serde_snake_case() {
        let json = serde_json::to_string(&GpuBufferUsage::ReadOnly).unwrap();
        assert_eq!(json, "\"read_only\"");
        let json = serde_json::to_string(&GpuBufferUsage::ReadWrite).unwrap();
        assert_eq!(json, "\"read_write\"");
    }

    #[test]
    fn buffer_serde_roundtrip() {
        let buf = GpuBuffer::new(8192, GpuBufferUsage::ReadWrite)
            .with_unified(true)
            .with_label("points");
        let json = serde_json::to_string(&buf).unwrap();
        let back: GpuBuffer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size_bytes, 8192);
        assert_eq!(back.usage, GpuBufferUsage::ReadWrite);
        assert!(back.unified);
        assert_eq!(back.label.as_deref(), Some("points"));
    }

    // ── GpuOperation Hash / Eq ──────────────────────────────────────

    #[test]
    fn operation_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(GpuOperation::Msm);
        set.insert(GpuOperation::Msm);
        set.insert(GpuOperation::Ntt);
        assert_eq!(set.len(), 2);
    }

    // ── GpuBufferUsage Hash / Eq ────────────────────────────────────

    #[test]
    fn buffer_usage_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(GpuBufferUsage::ReadOnly);
        set.insert(GpuBufferUsage::ReadOnly);
        set.insert(GpuBufferUsage::WriteOnly);
        assert_eq!(set.len(), 2);
    }
}
