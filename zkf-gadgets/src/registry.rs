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

//! Gadget specification registry.
//!
//! Each gadget gets a `GadgetSpec` with name, version, input/output types,
//! constraint count formula, supported fields, and audit status.

#[cfg(test)]
use crate::gadget::BUILTIN_GADGET_NAMES;
use crate::gadget::builtin_supported_field_names;
use serde::{Deserialize, Serialize};

/// Audit status of a gadget.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    /// Not yet audited.
    Unaudited,
    /// Informally reviewed (code review, property tests).
    InformallyReviewed,
    /// Formally audited by third party.
    Audited { auditor: String },
}

fn default_true() -> bool {
    true
}

/// Specification of a gadget in the standard library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetSpec {
    /// Canonical name (e.g., "sha256", "poseidon", "ecdsa_secp256k1").
    pub name: String,
    /// Semantic version.
    pub version: String,
    /// Human-readable description.
    pub description: String,
    /// Number of input signals.
    pub input_count: usize,
    /// Number of output signals.
    pub output_count: usize,
    /// Approximate constraint count formula (e.g., "~25000" or "4*n+2").
    pub constraint_count_formula: String,
    /// Fields this gadget supports.
    pub supported_fields: Vec<String>,
    /// Current audit status.
    pub audit_status: AuditStatus,
    /// Supported blackbox ops this gadget maps to (if any).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blackbox_ops: Vec<String>,
    /// Required string parameters for generic gadget emission, when known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_params: Vec<String>,
    /// Whether this gadget has known soundness gaps or is not production-ready.
    #[serde(default)]
    pub is_experimental: bool,
    /// Whether this gadget is production safe (no known soundness gaps).
    #[serde(default = "default_true")]
    pub is_production_safe: bool,
}

/// Return the specifications for all standard library gadgets.
pub fn all_gadget_specs() -> Vec<GadgetSpec> {
    vec![
        GadgetSpec {
            name: "blake3".into(),
            version: "1.0.0".into(),
            description: "BLAKE3 hash function circuit.".into(),
            input_count: 1,
            output_count: 1,
            constraint_count_formula: "~6000".into(),
            supported_fields: builtin_supported_field_names("blake3").unwrap(),
            audit_status: AuditStatus::Unaudited,
            blackbox_ops: vec![],
            required_params: vec![],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "boolean".into(),
            version: "1.0.0".into(),
            description: "Boolean logic gates (AND, OR, NOT, XOR).".into(),
            input_count: 2,
            output_count: 1,
            constraint_count_formula: "1-4".into(),
            supported_fields: builtin_supported_field_names("boolean").unwrap(),
            audit_status: AuditStatus::InformallyReviewed,
            blackbox_ops: vec![],
            required_params: vec!["op".into()],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "comparison".into(),
            version: "1.0.0".into(),
            description: "Comparison operations (less-than, greater-than, equal).".into(),
            input_count: 2,
            output_count: 1,
            constraint_count_formula: "~2*bits".into(),
            supported_fields: builtin_supported_field_names("comparison").unwrap(),
            audit_status: AuditStatus::Unaudited,
            blackbox_ops: vec![],
            required_params: vec!["op".into(), "bits".into()],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "ecdsa".into(),
            version: "1.0.0".into(),
            description: "ECDSA signature verification over secp256k1 (Bitcoin/Ethereum).".into(),
            input_count: 5,
            output_count: 1,
            constraint_count_formula: "~50000".into(),
            supported_fields: builtin_supported_field_names("ecdsa").unwrap(),
            audit_status: AuditStatus::InformallyReviewed,
            blackbox_ops: vec!["ecdsa_secp256k1".into(), "ecdsa_secp256r1".into()],
            required_params: vec![],
            is_experimental: true,
            is_production_safe: false,
        },
        GadgetSpec {
            name: "kzg".into(),
            version: "1.0.0".into(),
            description: "KZG polynomial commitment pairing verification.".into(),
            input_count: 4,
            output_count: 1,
            constraint_count_formula: "~80000".into(),
            supported_fields: builtin_supported_field_names("kzg").unwrap(),
            audit_status: AuditStatus::Unaudited,
            blackbox_ops: vec!["pairing_check".into()],
            required_params: vec![],
            is_experimental: true,
            is_production_safe: false,
        },
        GadgetSpec {
            name: "merkle".into(),
            version: "1.0.0".into(),
            description: "Merkle tree inclusion proof verification.".into(),
            input_count: 3,
            output_count: 1,
            constraint_count_formula: "~300*depth".into(),
            supported_fields: builtin_supported_field_names("merkle").unwrap(),
            audit_status: AuditStatus::InformallyReviewed,
            blackbox_ops: vec![],
            required_params: vec!["depth".into()],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "plonk_gate".into(),
            version: "1.0.0".into(),
            description: "Universal Plonk gate constraint with configurable selectors.".into(),
            input_count: 3,
            output_count: 1,
            constraint_count_formula: "1-2".into(),
            supported_fields: builtin_supported_field_names("plonk_gate").unwrap(),
            audit_status: AuditStatus::Unaudited,
            blackbox_ops: vec![],
            required_params: vec![],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "poseidon".into(),
            version: "1.0.0".into(),
            description: "Poseidon algebraic hash function (ZK-friendly).".into(),
            input_count: 4,
            output_count: 4,
            constraint_count_formula: "~300".into(),
            supported_fields: builtin_supported_field_names("poseidon").unwrap(),
            audit_status: AuditStatus::InformallyReviewed,
            blackbox_ops: vec!["poseidon".into()],
            required_params: vec![],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "range".into(),
            version: "1.0.0".into(),
            description: "Range constraint: value < 2^bits.".into(),
            input_count: 1,
            output_count: 0,
            constraint_count_formula: "bits".into(),
            supported_fields: builtin_supported_field_names("range").unwrap(),
            audit_status: AuditStatus::InformallyReviewed,
            blackbox_ops: vec![],
            required_params: vec!["bits".into()],
            is_experimental: false,
            is_production_safe: true,
        },
        GadgetSpec {
            name: "schnorr".into(),
            version: "1.0.0".into(),
            description: "Schnorr signature verification.".into(),
            input_count: 4,
            output_count: 1,
            constraint_count_formula: "~20000".into(),
            supported_fields: builtin_supported_field_names("schnorr").unwrap(),
            audit_status: AuditStatus::Unaudited,
            blackbox_ops: vec!["schnorr_verify".into()],
            required_params: vec![],
            is_experimental: true,
            is_production_safe: false,
        },
        GadgetSpec {
            name: "sha256".into(),
            version: "1.0.0".into(),
            description: "SHA-256 hash function circuit (NIST FIPS 180-4).".into(),
            input_count: 1,
            output_count: 32,
            constraint_count_formula: "~25000".into(),
            supported_fields: builtin_supported_field_names("sha256").unwrap(),
            audit_status: AuditStatus::InformallyReviewed,
            blackbox_ops: vec!["sha256".into()],
            required_params: vec![],
            is_experimental: false,
            is_production_safe: true,
        },
    ]
}

/// Look up a gadget spec by name.
pub fn gadget_spec(name: &str) -> Option<GadgetSpec> {
    all_gadget_specs().into_iter().find(|g| g.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_specs_present() {
        let specs = all_gadget_specs();
        assert_eq!(specs.len(), BUILTIN_GADGET_NAMES.len());
        assert_eq!(
            specs
                .iter()
                .map(|spec| spec.name.as_str())
                .collect::<Vec<_>>(),
            BUILTIN_GADGET_NAMES
        );
    }

    #[test]
    fn lookup_by_name() {
        let sha = gadget_spec("sha256").unwrap();
        assert_eq!(sha.input_count, 1);
        assert_eq!(sha.output_count, 32);
        assert!(sha.supported_fields.contains(&"bn254".into()));
    }

    #[test]
    fn poseidon_is_reviewed() {
        let p = gadget_spec("poseidon").unwrap();
        assert!(matches!(p.audit_status, AuditStatus::InformallyReviewed));
    }

    #[test]
    fn required_params_are_exposed_for_common_gadgets() {
        let boolean = gadget_spec("boolean").expect("boolean gadget spec");
        let comparison = gadget_spec("comparison").expect("comparison gadget spec");
        let merkle = gadget_spec("merkle").expect("merkle gadget spec");

        assert_eq!(boolean.required_params, vec!["op".to_string()]);
        assert_eq!(
            comparison.required_params,
            vec!["op".to_string(), "bits".to_string()]
        );
        assert_eq!(merkle.required_params, vec!["depth".to_string()]);
    }

    #[test]
    fn poseidon_and_sha256_supported_fields_match_truthful_catalog() {
        let poseidon = gadget_spec("poseidon").expect("poseidon gadget spec");
        let sha256 = gadget_spec("sha256").expect("sha256 gadget spec");

        assert_eq!(
            poseidon.supported_fields,
            vec![
                "bn254".to_string(),
                "bls12-381".to_string(),
                "pasta-fp".to_string(),
                "goldilocks".to_string(),
                "babybear".to_string(),
                "mersenne31".to_string(),
            ]
        );
        assert_eq!(
            sha256.supported_fields,
            vec![
                "bn254".to_string(),
                "bls12-381".to_string(),
                "pasta-fp".to_string(),
                "goldilocks".to_string(),
                "babybear".to_string(),
                "mersenne31".to_string(),
            ]
        );
    }

    #[test]
    fn specs_serialize_to_json() {
        let specs = all_gadget_specs();
        let json = serde_json::to_string_pretty(&specs).unwrap();
        assert!(json.contains("sha256"));
        assert!(json.contains("constraint_count_formula"));
    }
}
