//! Metal-accelerated Multi-Scalar Multiplication (MSM).

pub mod bn254;
pub mod pallas;
pub mod pallas_pippenger;
pub mod pippenger;
pub mod vesta;
pub mod vesta_pippenger;

use crate::device::{self, MetalContext};
use zkf_core::acceleration::MsmAccelerator;
use zkf_core::{FieldElement, ZkfError, ZkfResult};

pub use pallas_pippenger::try_metal_pallas_msm;
pub use vesta_pippenger::try_metal_vesta_msm;

/// Metal GPU MSM accelerator for BN254 G1.
pub struct MetalMsmAccelerator {
    ctx: &'static MetalContext,
}

impl MetalMsmAccelerator {
    /// Create a new Metal MSM accelerator if Metal GPU is available.
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }
}

impl MsmAccelerator for MetalMsmAccelerator {
    fn name(&self) -> &str {
        "metal-msm-bn254"
    }

    fn is_available(&self) -> bool {
        device::dispatch_allowed()
    }

    fn msm_g1(&self, scalars: &[FieldElement], bases: &[Vec<u8>]) -> ZkfResult<Vec<u8>> {
        use ark_bn254::{Fr, G1Affine};
        use ark_ec::CurveGroup;
        use ark_ff::PrimeField;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        if scalars.len() != bases.len() {
            return Err(ZkfError::Backend(format!(
                "MSM size mismatch: {} scalars vs {} bases",
                scalars.len(),
                bases.len()
            )));
        }

        if scalars.is_empty() {
            let mut buf = Vec::new();
            let identity = ark_bn254::G1Affine::identity();
            identity
                .serialize_compressed(&mut buf)
                .map_err(|e| ZkfError::Backend(e.to_string()))?;
            return Ok(buf);
        }

        // Convert FieldElements to arkworks Fr scalars
        let ark_scalars: Vec<Fr> = scalars
            .iter()
            .map(|fe| {
                let bytes = fe.to_le_bytes();
                Fr::from_le_bytes_mod_order(bytes)
            })
            .collect();

        // Deserialize bases from compressed affine bytes
        let ark_bases: Vec<G1Affine> = bases
            .iter()
            .map(|b| {
                G1Affine::deserialize_compressed(b.as_slice())
                    .map_err(|e| ZkfError::Backend(format!("bad base point: {e}")))
            })
            .collect::<ZkfResult<Vec<_>>>()?;

        // The certified BN254 lane is classic-only: hybrid, full-GPU, and
        // tensor-routed variants remain available only through explicit
        // experimental call sites and are not part of the promoted claim.
        let result = match pippenger::metal_msm_dispatch(self.ctx, &ark_scalars, &ark_bases) {
            pippenger::Bn254MsmDispatch::Metal(projective) => projective,
            pippenger::Bn254MsmDispatch::BelowThreshold
            | pippenger::Bn254MsmDispatch::Unavailable => {
                pippenger::cpu_pippenger(&ark_scalars, &ark_bases)
            }
            pippenger::Bn254MsmDispatch::DispatchFailed(reason) => {
                return Err(ZkfError::Backend(reason));
            }
        };
        let affine = result.into_affine();
        if !affine.is_on_curve() || !affine.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ZkfError::Backend(
                "Metal MSM produced an invalid BN254 point".to_string(),
            ));
        }

        let mut buf = Vec::new();
        affine
            .serialize_compressed(&mut buf)
            .map_err(|e| ZkfError::Backend(e.to_string()))?;
        Ok(buf)
    }

    fn max_batch_size(&self) -> usize {
        1 << 24
    }

    fn min_batch_size(&self) -> usize {
        pippenger::gpu_threshold()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metal_msm_accelerator_available() {
        if let Some(acc) = MetalMsmAccelerator::new() {
            assert_eq!(acc.name(), "metal-msm-bn254");
            assert!(acc.is_available());
        }
    }
}
