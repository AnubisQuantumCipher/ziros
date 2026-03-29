//! Metal 4 host-gated MSM dispatch policy for large workloads.

use crate::device;
use crate::metal4::detect_capabilities;
use crate::msm::pippenger;
use ark_bn254::{Fr, G1Affine, G1Projective};

/// Configuration for large-batch MSM dispatch.
#[derive(Debug, Clone, Copy)]
pub struct TensorMsmConfig {
    /// Minimum batch size to consider the Metal path.
    pub min_gpu_batch: usize,
    /// Fraction of work budgeted toward the GPU-heavy path.
    pub gpu_fraction: f64,
}

impl Default for TensorMsmConfig {
    fn default() -> Self {
        Self {
            min_gpu_batch: 1 << 16,
            gpu_fraction: 0.8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TensorMsmRoute {
    Cpu,
    MetalClassic,
    MetalHybrid,
    MetalLargeBatch,
}

#[derive(Debug, Clone)]
pub struct TensorMsmDecision {
    pub route: TensorMsmRoute,
    pub point_count: usize,
    pub tensor_capable: bool,
    pub reason: String,
}

impl TensorMsmDecision {
    pub fn uses_gpu(&self) -> bool {
        !matches!(self.route, TensorMsmRoute::Cpu)
    }
}

pub fn plan_bn254(point_count: usize, config: TensorMsmConfig) -> TensorMsmDecision {
    let caps = detect_capabilities();
    if point_count < config.min_gpu_batch {
        return TensorMsmDecision {
            route: TensorMsmRoute::Cpu,
            point_count,
            tensor_capable: caps.supports_tensors,
            reason: format!(
                "batch size {point_count} is below the Metal threshold {}",
                config.min_gpu_batch
            ),
        };
    }

    if device::global_context().is_none() {
        return TensorMsmDecision {
            route: TensorMsmRoute::Cpu,
            point_count,
            tensor_capable: caps.supports_tensors,
            reason: "Metal GPU unavailable on this host".to_string(),
        };
    }

    let route = if caps.supports_tensors && config.gpu_fraction >= 0.75 {
        TensorMsmRoute::MetalLargeBatch
    } else if config.gpu_fraction >= 0.5 {
        TensorMsmRoute::MetalHybrid
    } else {
        TensorMsmRoute::MetalClassic
    };
    let reason = match route {
        TensorMsmRoute::MetalLargeBatch => {
            "Metal 4 tensor-capable host detected; using the large-batch GPU path".to_string()
        }
        TensorMsmRoute::MetalHybrid => {
            "Metal available; using the hybrid GPU/CPU MSM path".to_string()
        }
        TensorMsmRoute::MetalClassic => {
            "Metal available; using the classic GPU bucket accumulation path".to_string()
        }
        TensorMsmRoute::Cpu => "CPU fallback".to_string(),
    };

    TensorMsmDecision {
        route,
        point_count,
        tensor_capable: caps.supports_tensors,
        reason,
    }
}

pub fn msm_bn254(
    scalars: &[Fr],
    bases: &[G1Affine],
    config: TensorMsmConfig,
) -> Option<(G1Projective, TensorMsmDecision)> {
    if scalars.len() != bases.len() {
        return None;
    }

    let decision = plan_bn254(scalars.len(), config);
    let ctx = device::global_context();
    let result = match (decision.route, ctx) {
        (TensorMsmRoute::MetalLargeBatch, Some(ctx)) => {
            pippenger::metal_msm_full_gpu(ctx, scalars, bases)
                .or_else(|| pippenger::metal_msm_hybrid(ctx, scalars, bases))
                .or_else(|| pippenger::metal_msm(ctx, scalars, bases))
                .unwrap_or_else(|| pippenger::cpu_pippenger(scalars, bases))
        }
        (TensorMsmRoute::MetalHybrid, Some(ctx)) => {
            pippenger::metal_msm_hybrid(ctx, scalars, bases)
                .or_else(|| pippenger::metal_msm(ctx, scalars, bases))
                .or_else(|| pippenger::metal_msm_full_gpu(ctx, scalars, bases))
                .unwrap_or_else(|| pippenger::cpu_pippenger(scalars, bases))
        }
        (TensorMsmRoute::MetalClassic, Some(ctx)) => pippenger::metal_msm(ctx, scalars, bases)
            .or_else(|| pippenger::metal_msm_hybrid(ctx, scalars, bases))
            .or_else(|| pippenger::metal_msm_full_gpu(ctx, scalars, bases))
            .unwrap_or_else(|| pippenger::cpu_pippenger(scalars, bases)),
        _ => pippenger::cpu_pippenger(scalars, bases),
    };

    Some((result, decision))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planner_prefers_cpu_below_threshold() {
        let decision = plan_bn254(1024, TensorMsmConfig::default());
        assert_eq!(decision.route, TensorMsmRoute::Cpu);
    }
}
