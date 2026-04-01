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

use zkf_core::{FieldElement, WitnessInputs, ZkfError, ZkfResult};

pub fn bytes_to_field_elements(bytes: &[u8]) -> Vec<FieldElement> {
    bytes
        .iter()
        .map(|byte| FieldElement::from_u64(u64::from(*byte)))
        .collect()
}

pub fn string_to_field_elements(value: &str) -> Vec<FieldElement> {
    bytes_to_field_elements(value.as_bytes())
}

pub fn u64s_to_field_elements(values: &[u64]) -> Vec<FieldElement> {
    values
        .iter()
        .map(|value| FieldElement::from_u64(*value))
        .collect()
}

pub fn bools_to_field_elements(values: &[bool]) -> Vec<FieldElement> {
    values
        .iter()
        .map(|value| FieldElement::from_i64(if *value { 1 } else { 0 }))
        .collect()
}

pub fn merkle_path_witness_inputs(
    siblings: &[FieldElement],
    directions: &[bool],
) -> ZkfResult<WitnessInputs> {
    if siblings.len() != directions.len() {
        return Err(ZkfError::InvalidArtifact(format!(
            "merkle path length mismatch: {} siblings but {} directions",
            siblings.len(),
            directions.len()
        )));
    }

    let mut inputs = WitnessInputs::new();
    for (index, sibling) in siblings.iter().enumerate() {
        inputs.insert(format!("sibling_{index}"), sibling.clone());
        inputs.insert(
            format!("direction_{index}"),
            FieldElement::from_i64(if directions[index] { 1 } else { 0 }),
        );
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_strings_encode_deterministically() {
        let bytes = bytes_to_field_elements(&[1, 2, 255]);
        assert_eq!(
            bytes
                .iter()
                .map(FieldElement::to_string)
                .collect::<Vec<_>>(),
            vec!["1".to_string(), "2".to_string(), "255".to_string()]
        );

        let text = string_to_field_elements("A!");
        assert_eq!(
            text.iter().map(FieldElement::to_string).collect::<Vec<_>>(),
            vec!["65".to_string(), "33".to_string()]
        );
    }

    #[test]
    fn slice_helpers_encode_scalars_and_bools() {
        let scalars = u64s_to_field_elements(&[7, 42]);
        let bools = bools_to_field_elements(&[true, false]);
        assert_eq!(
            scalars
                .iter()
                .map(FieldElement::to_string)
                .collect::<Vec<_>>(),
            vec!["7".to_string(), "42".to_string()]
        );
        assert_eq!(
            bools
                .iter()
                .map(FieldElement::to_string)
                .collect::<Vec<_>>(),
            vec!["1".to_string(), "0".to_string()]
        );
    }

    #[test]
    fn merkle_path_helper_uses_template_field_names() {
        let siblings = vec![FieldElement::from_i64(11), FieldElement::from_i64(22)];
        let inputs = merkle_path_witness_inputs(&siblings, &[true, false]).expect("path inputs");
        assert_eq!(
            inputs.get("sibling_0").map(FieldElement::to_string),
            Some("11".to_string())
        );
        assert_eq!(
            inputs.get("direction_1").map(FieldElement::to_string),
            Some("0".to_string())
        );
    }
}
