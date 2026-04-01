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

//! JSON Schema generation for IR validation.
//!
//! Provides schema documents that can validate `.ir.json` files
//! against the formal IR specification.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A minimal JSON Schema representation for IR validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSchema {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub properties: BTreeMap<String, SchemaProperty>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

/// A property in a JSON Schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaProperty>>,
    #[serde(rename = "enum", default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
}

/// Generate the JSON Schema for an IR v2 Program.
pub fn ir_v2_program_schema() -> JsonSchema {
    let mut properties = BTreeMap::new();

    properties.insert(
        "name".into(),
        SchemaProperty {
            ty: "string".into(),
            description: Some("Program name".into()),
            items: None,
            enum_values: None,
        },
    );

    properties.insert(
        "field".into(),
        SchemaProperty {
            ty: "string".into(),
            description: Some("Field identifier".into()),
            items: None,
            enum_values: Some(vec![
                "bn254".into(),
                "bls12-381".into(),
                "pasta-fp".into(),
                "pasta-fq".into(),
                "goldilocks".into(),
                "babybear".into(),
                "mersenne31".into(),
                "any".into(),
            ]),
        },
    );

    properties.insert(
        "signals".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Circuit signals".into()),
            items: Some(Box::new(SchemaProperty {
                ty: "object".into(),
                description: Some("A signal declaration".into()),
                items: None,
                enum_values: None,
            })),
            enum_values: None,
        },
    );

    properties.insert(
        "constraints".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Circuit constraints".into()),
            items: Some(Box::new(SchemaProperty {
                ty: "object".into(),
                description: Some("A constraint".into()),
                items: None,
                enum_values: None,
            })),
            enum_values: None,
        },
    );

    properties.insert(
        "witness_plan".into(),
        SchemaProperty {
            ty: "object".into(),
            description: Some("Witness generation plan".into()),
            items: None,
            enum_values: None,
        },
    );

    properties.insert(
        "metadata".into(),
        SchemaProperty {
            ty: "object".into(),
            description: Some("Frontend-specific metadata".into()),
            items: None,
            enum_values: None,
        },
    );

    JsonSchema {
        schema: "https://json-schema.org/draft/2020-12/schema".into(),
        title: "ZKF IR v2 Program".into(),
        description: "A ZKF intermediate representation program (IR v2).".into(),
        ty: "object".into(),
        properties,
        required: vec![
            "name".into(),
            "field".into(),
            "signals".into(),
            "constraints".into(),
        ],
    }
}

/// Generate the JSON Schema for a ZIR v1 Program.
pub fn zir_v1_program_schema() -> JsonSchema {
    let mut properties = BTreeMap::new();

    properties.insert(
        "name".into(),
        SchemaProperty {
            ty: "string".into(),
            description: Some("Program name".into()),
            items: None,
            enum_values: None,
        },
    );

    properties.insert(
        "field".into(),
        SchemaProperty {
            ty: "string".into(),
            description: Some("Field identifier".into()),
            items: None,
            enum_values: Some(vec![
                "bn254".into(),
                "bls12-381".into(),
                "pasta-fp".into(),
                "pasta-fq".into(),
                "goldilocks".into(),
                "babybear".into(),
                "mersenne31".into(),
                "any".into(),
            ]),
        },
    );

    properties.insert(
        "signals".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Typed circuit signals".into()),
            items: Some(Box::new(SchemaProperty {
                ty: "object".into(),
                description: Some("A typed signal declaration".into()),
                items: None,
                enum_values: None,
            })),
            enum_values: None,
        },
    );

    properties.insert(
        "constraints".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Circuit constraints (extended set)".into()),
            items: Some(Box::new(SchemaProperty {
                ty: "object".into(),
                description: Some("A constraint (supports lookup, custom gate, memory)".into()),
                items: None,
                enum_values: None,
            })),
            enum_values: None,
        },
    );

    properties.insert(
        "lookup_tables".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Named lookup tables".into()),
            items: None,
            enum_values: None,
        },
    );

    properties.insert(
        "memory_regions".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Named memory regions".into()),
            items: None,
            enum_values: None,
        },
    );

    properties.insert(
        "custom_gates".into(),
        SchemaProperty {
            ty: "array".into(),
            description: Some("Custom gate definitions".into()),
            items: None,
            enum_values: None,
        },
    );

    JsonSchema {
        schema: "https://json-schema.org/draft/2020-12/schema".into(),
        title: "ZKF ZIR v1 Program".into(),
        description: "A ZKF zero-knowledge intermediate representation program (ZIR v1).".into(),
        ty: "object".into(),
        properties,
        required: vec![
            "name".into(),
            "field".into(),
            "signals".into(),
            "constraints".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_v2_schema_serializes() {
        let schema = ir_v2_program_schema();
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("ZKF IR v2 Program"));
        assert!(json.contains("bn254"));
    }

    #[test]
    fn zir_v1_schema_serializes() {
        let schema = zir_v1_program_schema();
        let json = serde_json::to_string_pretty(&schema).unwrap();
        assert!(json.contains("ZKF ZIR v1 Program"));
        assert!(json.contains("lookup_tables"));
    }
}
