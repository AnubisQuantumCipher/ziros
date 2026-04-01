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

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, Witness, ZkfError,
    ZkfResult,
};

pub const RANGE_DECOMPOSITION_METADATA_KEY: &str = "zkf_range_decompositions_v1";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeChunk {
    pub signal: String,
    pub offset_bits: u32,
    pub bits: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeDecomposition {
    pub original_signal: String,
    pub original_bits: u32,
    pub chunks: Vec<RangeChunk>,
}

pub fn lower_large_range_constraints(
    program: &Program,
    max_chunk_bits: u32,
    prefix: &str,
) -> ZkfResult<(Program, Vec<RangeDecomposition>)> {
    let safe_bits = safe_integer_range_bits(program.field);
    let mut lowered = program.clone();
    lowered.constraints.clear();
    let mut decompositions = Vec::new();

    for (constraint_index, constraint) in program.constraints.iter().enumerate() {
        let Constraint::Range {
            signal,
            bits,
            label,
        } = constraint
        else {
            lowered.constraints.push(constraint.clone());
            continue;
        };

        if *bits == 0 || *bits <= max_chunk_bits {
            lowered.constraints.push(constraint.clone());
            continue;
        }

        if *bits >= safe_bits {
            continue;
        }

        let mut chunks = Vec::new();
        let mut terms = Vec::new();
        let mut remaining_bits = *bits;
        let mut offset_bits = 0u32;
        let mut chunk_index = 0u32;

        while remaining_bits > 0 {
            let chunk_bits = remaining_bits.min(max_chunk_bits);
            let chunk_signal = format!("__{prefix}_range_{constraint_index}_chunk_{chunk_index}");
            lowered.signals.push(Signal {
                name: chunk_signal.clone(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            });
            lowered.constraints.push(Constraint::Range {
                signal: chunk_signal.clone(),
                bits: chunk_bits,
                label: Some(chunk_range_label(label.as_deref(), chunk_index, chunk_bits)),
            });
            terms.push(chunk_expr(&chunk_signal, offset_bits));
            chunks.push(RangeChunk {
                signal: chunk_signal,
                offset_bits,
                bits: chunk_bits,
            });

            remaining_bits -= chunk_bits;
            offset_bits += chunk_bits;
            chunk_index += 1;
        }

        lowered.constraints.push(Constraint::Equal {
            lhs: Expr::Signal(signal.clone()),
            rhs: Expr::Add(terms),
            label: Some(range_recombine_label(label.as_deref(), *bits)),
        });
        decompositions.push(RangeDecomposition {
            original_signal: signal.clone(),
            original_bits: *bits,
            chunks,
        });
    }

    Ok((lowered, decompositions))
}

pub fn write_range_decomposition_metadata(
    metadata: &mut BTreeMap<String, String>,
    decompositions: &[RangeDecomposition],
) -> ZkfResult<()> {
    if decompositions.is_empty() {
        metadata.remove(RANGE_DECOMPOSITION_METADATA_KEY);
        return Ok(());
    }

    let encoded = serde_json::to_string(decompositions)
        .map_err(|err| ZkfError::Serialization(format!("range decomposition metadata: {err}")))?;
    metadata.insert(RANGE_DECOMPOSITION_METADATA_KEY.to_string(), encoded);
    Ok(())
}

pub fn enrich_range_witness(
    program: &Program,
    metadata: &BTreeMap<String, String>,
    witness: &Witness,
) -> ZkfResult<Witness> {
    let Some(encoded) = metadata.get(RANGE_DECOMPOSITION_METADATA_KEY) else {
        return Ok(witness.clone());
    };

    let decompositions: Vec<RangeDecomposition> = serde_json::from_str(encoded).map_err(|err| {
        ZkfError::InvalidArtifact(format!("invalid range decomposition metadata: {err}"))
    })?;

    if decompositions.is_empty() {
        return Ok(witness.clone());
    }

    let mut values = witness.values.clone();
    for decomposition in decompositions {
        let original = match values.get(&decomposition.original_signal) {
            Some(value) => value.clone(),
            None => program
                .signal(&decomposition.original_signal)
                .and_then(|signal| signal.constant.clone())
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: decomposition.original_signal.clone(),
                })?,
        };

        let normalized = original.normalized_bigint(program.field)?;
        for chunk in decomposition.chunks {
            let chunk_value = extract_chunk(&normalized, chunk.offset_bits, chunk.bits);
            values.insert(chunk.signal, FieldElement::from_bigint(chunk_value));
        }
    }

    Ok(Witness { values })
}

fn safe_integer_range_bits(field: FieldId) -> u32 {
    field.modulus().bits() as u32
}

fn chunk_expr(signal: &str, offset_bits: u32) -> Expr {
    if offset_bits == 0 {
        Expr::Signal(signal.to_string())
    } else {
        Expr::Mul(
            Box::new(Expr::Const(FieldElement::from_bigint(
                BigInt::from(1u8) << offset_bits,
            ))),
            Box::new(Expr::Signal(signal.to_string())),
        )
    }
}

fn extract_chunk(value: &BigInt, offset_bits: u32, bits: u32) -> BigInt {
    let shifted = value >> offset_bits;
    let mask = (BigInt::from(1u8) << bits) - BigInt::from(1u8);
    shifted & mask
}

fn chunk_range_label(label: Option<&str>, chunk_index: u32, chunk_bits: u32) -> String {
    match label {
        Some(label) => format!("{label}_chunk_{chunk_index}_{chunk_bits}bit"),
        None => format!("range_chunk_{chunk_index}_{chunk_bits}bit"),
    }
}

fn range_recombine_label(label: Option<&str>, bits: u32) -> String {
    match label {
        Some(label) => format!("{label}_recombine_{bits}bit"),
        None => format!("range_recombine_{bits}bit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{FieldId, Signal, Visibility};

    fn large_range_program() -> Program {
        Program {
            name: "range_decomp".to_string(),
            field: FieldId::PastaFp,
            signals: vec![Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Range {
                signal: "x".to_string(),
                bits: 40,
                label: Some("x_range".to_string()),
            }],
            ..Program::default()
        }
    }

    #[test]
    fn lowers_large_range_into_chunk_ranges_and_recombine() {
        let (lowered, decompositions) =
            lower_large_range_constraints(&large_range_program(), 16, "halo2").unwrap();
        assert_eq!(decompositions.len(), 1);
        assert_eq!(decompositions[0].chunks.len(), 3);
        assert_eq!(lowered.signals.len(), 4);
        assert_eq!(lowered.constraints.len(), 4);
        assert!(matches!(
            lowered.constraints.last(),
            Some(Constraint::Equal { .. })
        ));
    }

    #[test]
    fn witness_enrichment_populates_chunk_values() {
        let (lowered, decompositions) =
            lower_large_range_constraints(&large_range_program(), 16, "halo2").unwrap();
        let mut metadata = BTreeMap::new();
        write_range_decomposition_metadata(&mut metadata, &decompositions).unwrap();

        let mut witness = Witness::default();
        witness.values.insert(
            "x".to_string(),
            FieldElement::from_bigint(BigInt::from(0x12_3456_789au64)),
        );

        let enriched = enrich_range_witness(&lowered, &metadata, &witness).unwrap();
        assert_eq!(
            enriched
                .values
                .get("__halo2_range_0_chunk_0")
                .unwrap()
                .normalized_bigint(FieldId::PastaFp)
                .unwrap(),
            BigInt::from(0x789au64)
        );
        assert_eq!(
            enriched
                .values
                .get("__halo2_range_0_chunk_1")
                .unwrap()
                .normalized_bigint(FieldId::PastaFp)
                .unwrap(),
            BigInt::from(0x3456u64)
        );
        assert_eq!(
            enriched
                .values
                .get("__halo2_range_0_chunk_2")
                .unwrap()
                .normalized_bigint(FieldId::PastaFp)
                .unwrap(),
            BigInt::from(0x12u64)
        );
    }
}
