// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! Metal-accelerated Number Theoretic Transform (NTT).

pub mod bn254;
pub mod fields;
pub mod p3_adapter;
pub mod radix2;

use crate::device::{self, MetalContext};
use zkf_core::acceleration::NttAccelerator;
use zkf_core::{FieldElement, ZkfError, ZkfResult};

/// Metal GPU NTT accelerator.
pub struct MetalNttAccelerator {
    _ctx: &'static MetalContext,
}

impl MetalNttAccelerator {
    /// Create a new Metal NTT accelerator if Metal GPU is available.
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { _ctx: ctx })
    }
}

impl NttAccelerator for MetalNttAccelerator {
    fn name(&self) -> &str {
        "metal-ntt"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn forward_ntt(&self, values: &mut [FieldElement]) -> ZkfResult<()> {
        let n = values.len();
        if n == 0 || !n.is_power_of_two() {
            return Err(ZkfError::Backend(
                "NTT size must be a power of 2".to_string(),
            ));
        }

        // Convert to u64, dispatch GPU NTT, convert back
        use p3_dft::TwoAdicSubgroupDft;
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::Goldilocks;
        use p3_matrix::dense::RowMajorMatrix;

        let gl_values: Vec<Goldilocks> = values
            .iter()
            .map(|fe| {
                let bytes = fe.to_le_bytes();
                let mut arr = [0u8; 8];
                let len = bytes.len().min(8);
                arr[..len].copy_from_slice(&bytes[..len]);
                Goldilocks::from_u64(u64::from_le_bytes(arr))
            })
            .collect();

        let mat = RowMajorMatrix::new(gl_values, 1);
        let dft = p3_adapter::MetalDft::<Goldilocks>::new()
            .ok_or_else(|| ZkfError::Backend("Metal GPU unavailable".to_string()))?;
        let result = dft.dft_batch(mat);

        for (i, val) in result.values.iter().enumerate() {
            values[i] = FieldElement::from_u64(val.as_canonical_u64());
        }

        Ok(())
    }

    fn inverse_ntt(&self, values: &mut [FieldElement]) -> ZkfResult<()> {
        let n = values.len();
        if n == 0 || !n.is_power_of_two() {
            return Err(ZkfError::Backend(
                "NTT size must be a power of 2".to_string(),
            ));
        }

        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::Goldilocks;
        use p3_matrix::dense::RowMajorMatrix;

        let gl_values: Vec<Goldilocks> = values
            .iter()
            .map(|fe| {
                let bytes = fe.to_le_bytes();
                let mut arr = [0u8; 8];
                let len = bytes.len().min(8);
                arr[..len].copy_from_slice(&bytes[..len]);
                Goldilocks::from_u64(u64::from_le_bytes(arr))
            })
            .collect();

        let mat = RowMajorMatrix::new(gl_values, 1);
        let dft = p3_adapter::MetalDft::<Goldilocks>::new()
            .ok_or_else(|| ZkfError::Backend("Metal GPU unavailable".to_string()))?;
        let result = dft.idft_batch(mat);

        for (i, val) in result.values.iter().enumerate() {
            values[i] = FieldElement::from_u64(val.as_canonical_u64());
        }

        Ok(())
    }

    fn max_log_size(&self) -> u32 {
        26 // 2^26 = 64M elements — M4 Max has plenty of memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metal_ntt_accelerator_available() {
        if let Some(acc) = MetalNttAccelerator::new() {
            assert_eq!(acc.name(), "metal-ntt");
            assert!(acc.is_available());
        }
    }

    #[test]
    fn metal_ntt_accelerator_forward_inverse_roundtrip() {
        let acc = match MetalNttAccelerator::new() {
            Some(a) => a,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 1 << 13;
        let mut values: Vec<FieldElement> = (0..n)
            .map(|i| FieldElement::from_u64((i + 1) as u64))
            .collect();
        let original = values.clone();

        acc.forward_ntt(&mut values).unwrap();
        // Should have changed
        assert_ne!(values, original);

        acc.inverse_ntt(&mut values).unwrap();
        // Should be back to original
        assert_eq!(values, original);
    }
}
