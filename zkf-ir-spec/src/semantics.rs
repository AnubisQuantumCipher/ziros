//! Op semantics -- what every constraint kind, signal type, and blackbox op means.
//!
//! Defines specification structs ([`ConstraintKindSpec`], [`SignalTypeSpec`], [`BlackBoxOpSpec`])
//! and factory functions that return the full catalog for the current IR version.

use serde::{Deserialize, Serialize};

/// How a backend handles a particular constraint kind.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringSupport {
    /// Backend implements this constraint directly.
    Native,
    /// Backend decomposes this constraint into simpler primitives.
    Decomposed,
    /// Backend does not support this constraint kind.
    Unsupported,
}

/// Specification of a constraint kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintKindSpec {
    /// Machine-readable name (e.g., "equal", "boolean", "range", "black_box").
    pub name: String,
    /// Number of expression ports (inputs).
    pub input_ports: PortSpec,
    /// Number of output signals.
    pub output_ports: PortSpec,
    /// Prose description of semantics.
    pub semantics: String,
    /// Formal semantics (optional, e.g., "lhs == rhs mod p").
    pub formal: Option<String>,
    /// Per-backend lowering support.
    pub lowering: Vec<BackendLoweringEntry>,
}

/// How many ports a constraint kind has.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortSpec {
    /// Fixed count.
    Fixed(u32),
    /// Variable (min..max).
    Variable { min: u32, max: Option<u32> },
}

/// Per-backend lowering entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendLoweringEntry {
    pub backend: String,
    pub support: LoweringSupport,
    pub notes: Option<String>,
}

/// Specification of a signal type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalTypeSpec {
    pub name: String,
    pub description: String,
    pub parameters: Vec<String>,
}

/// Specification of a blackbox operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackBoxOpSpec {
    pub name: String,
    pub description: String,
    pub input_count: PortSpec,
    pub output_count: PortSpec,
    pub supported_fields: Vec<String>,
}

/// Return all constraint kind specs for the current IR version.
pub fn all_constraint_kinds() -> Vec<ConstraintKindSpec> {
    vec![
        ConstraintKindSpec {
            name: "equal".into(),
            input_ports: PortSpec::Fixed(2),
            output_ports: PortSpec::Fixed(0),
            semantics: "Assert lhs expression equals rhs expression modulo the field prime.".into(),
            formal: Some("lhs ≡ rhs (mod p)".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Native, notes: None },
            ],
        },
        ConstraintKindSpec {
            name: "boolean".into(),
            input_ports: PortSpec::Fixed(1),
            output_ports: PortSpec::Fixed(0),
            semantics: "Assert signal value is 0 or 1.".into(),
            formal: Some("s * (s - 1) ≡ 0 (mod p)".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Native, notes: None },
            ],
        },
        ConstraintKindSpec {
            name: "range".into(),
            input_ports: PortSpec::Fixed(1),
            output_ports: PortSpec::Fixed(0),
            semantics: "Assert signal value is in range [0, 2^bits).".into(),
            formal: Some("0 ≤ s < 2^bits".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Decomposed, notes: Some("Binary decomposition into bits".into()) },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: Some("Max 12-bit via lookup table".into()) },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Decomposed, notes: Some("Binary decomposition".into()) },
            ],
        },
        ConstraintKindSpec {
            name: "black_box".into(),
            input_ports: PortSpec::Variable { min: 0, max: None },
            output_ports: PortSpec::Variable { min: 0, max: None },
            semantics: "Invoke a named blackbox operation (hash, signature, etc.) with typed inputs/outputs.".into(),
            formal: None,
            lowering: vec![
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Decomposed, notes: Some("Expanded into R1CS gadgets".into()) },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Decomposed, notes: Some("Expanded into AIR constraints".into()) },
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Decomposed, notes: Some("Expanded into Halo2 gadgets".into()) },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Decomposed, notes: Some("Expanded into R1CS gadgets".into()) },
            ],
        },
        ConstraintKindSpec {
            name: "lookup".into(),
            input_ports: PortSpec::Variable { min: 1, max: None },
            output_ports: PortSpec::Fixed(0),
            semantics: "Assert inputs appear in a named lookup table.".into(),
            formal: Some("(inputs) ∈ table".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Unsupported, notes: None },
            ],
        },
        ConstraintKindSpec {
            name: "permutation".into(),
            input_ports: PortSpec::Fixed(2),
            output_ports: PortSpec::Fixed(0),
            semantics: "Assert two signals are a permutation (equality in ZIR).".into(),
            formal: Some("left ≡ right (mod p)".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Decomposed, notes: Some("Lowered to Equal".into()) },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Decomposed, notes: Some("Lowered to Equal".into()) },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Decomposed, notes: Some("Lowered to Equal".into()) },
            ],
        },
        ConstraintKindSpec {
            name: "copy".into(),
            input_ports: PortSpec::Fixed(2),
            output_ports: PortSpec::Fixed(0),
            semantics: "Assert copy equivalence between two signals.".into(),
            formal: Some("from ≡ to (mod p)".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Decomposed, notes: Some("Lowered to Equal".into()) },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Decomposed, notes: Some("Lowered to Equal".into()) },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Decomposed, notes: Some("Lowered to Equal".into()) },
            ],
        },
        ConstraintKindSpec {
            name: "custom_gate".into(),
            input_ports: PortSpec::Variable { min: 0, max: None },
            output_ports: PortSpec::Variable { min: 0, max: None },
            semantics: "Invoke a named custom gate definition.".into(),
            formal: None,
            lowering: vec![
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Unsupported, notes: None },
            ],
        },
        ConstraintKindSpec {
            name: "memory_read".into(),
            input_ports: PortSpec::Fixed(2),
            output_ports: PortSpec::Fixed(0),
            semantics: "Read from a named memory region at index, asserting value equality.".into(),
            formal: Some("memory[index] == value".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Unsupported, notes: None },
            ],
        },
        ConstraintKindSpec {
            name: "memory_write".into(),
            input_ports: PortSpec::Fixed(2),
            output_ports: PortSpec::Fixed(0),
            semantics: "Write to a named memory region at index with value.".into(),
            formal: Some("memory[index] := value".into()),
            lowering: vec![
                BackendLoweringEntry { backend: "halo2".into(), support: LoweringSupport::Native, notes: None },
                BackendLoweringEntry { backend: "arkworks-groth16".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "plonky3".into(), support: LoweringSupport::Unsupported, notes: None },
                BackendLoweringEntry { backend: "nova".into(), support: LoweringSupport::Unsupported, notes: None },
            ],
        },
    ]
}

/// Return all signal type specs.
pub fn all_signal_types() -> Vec<SignalTypeSpec> {
    vec![
        SignalTypeSpec {
            name: "field".into(),
            description: "Native field element.".into(),
            parameters: vec![],
        },
        SignalTypeSpec {
            name: "bool".into(),
            description: "Boolean (0 or 1).".into(),
            parameters: vec![],
        },
        SignalTypeSpec {
            name: "uint".into(),
            description: "Unsigned integer with specified bit width.".into(),
            parameters: vec!["bits".into()],
        },
        SignalTypeSpec {
            name: "array".into(),
            description: "Fixed-length array of a single element type.".into(),
            parameters: vec!["element".into(), "len".into()],
        },
        SignalTypeSpec {
            name: "tuple".into(),
            description: "Heterogeneous tuple of types.".into(),
            parameters: vec!["elements".into()],
        },
        SignalTypeSpec {
            name: "hash_digest".into(),
            description: "Output of a hash function.".into(),
            parameters: vec!["algorithm".into(), "bits".into()],
        },
        SignalTypeSpec {
            name: "commitment".into(),
            description: "Cryptographic commitment.".into(),
            parameters: vec!["scheme".into()],
        },
        SignalTypeSpec {
            name: "ec_point".into(),
            description: "Elliptic curve point.".into(),
            parameters: vec!["curve".into()],
        },
        SignalTypeSpec {
            name: "scalar".into(),
            description: "Scalar field element of a curve.".into(),
            parameters: vec!["curve".into()],
        },
        SignalTypeSpec {
            name: "bounded_int".into(),
            description: "Integer with explicit min/max bounds.".into(),
            parameters: vec!["min".into(), "max".into()],
        },
    ]
}

/// Return all blackbox op specs.
pub fn all_blackbox_ops() -> Vec<BlackBoxOpSpec> {
    vec![
        BlackBoxOpSpec {
            name: "poseidon".into(),
            description: "Poseidon hash function.".into(),
            input_count: PortSpec::Variable { min: 1, max: None },
            output_count: PortSpec::Variable { min: 1, max: None },
            supported_fields: vec!["bn254".into(), "goldilocks".into(), "babybear".into()],
        },
        BlackBoxOpSpec {
            name: "sha256".into(),
            description: "SHA-256 hash.".into(),
            input_count: PortSpec::Variable { min: 1, max: None },
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into(), "bls12-381".into(), "pasta-fp".into()],
        },
        BlackBoxOpSpec {
            name: "keccak256".into(),
            description: "Keccak-256 hash.".into(),
            input_count: PortSpec::Variable { min: 1, max: None },
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "pedersen".into(),
            description: "Pedersen commitment/hash.".into(),
            input_count: PortSpec::Variable { min: 1, max: None },
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "ecdsa_secp256k1".into(),
            description: "ECDSA signature verification over secp256k1.".into(),
            input_count: PortSpec::Fixed(3),
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "ecdsa_secp256r1".into(),
            description: "ECDSA signature verification over secp256r1.".into(),
            input_count: PortSpec::Fixed(3),
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "schnorr_verify".into(),
            description: "Schnorr signature verification.".into(),
            input_count: PortSpec::Fixed(3),
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "blake2s".into(),
            description: "BLAKE2s hash.".into(),
            input_count: PortSpec::Variable { min: 1, max: None },
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "recursive_aggregation_marker".into(),
            description: "Marks a recursive aggregation point.".into(),
            input_count: PortSpec::Variable { min: 0, max: None },
            output_count: PortSpec::Fixed(0),
            supported_fields: vec!["bn254".into()],
        },
        BlackBoxOpSpec {
            name: "scalar_mul_g1".into(),
            description: "Scalar multiplication on G1: [scalar] * base_point.".into(),
            input_count: PortSpec::Fixed(2),
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into(), "bls12-381".into()],
        },
        BlackBoxOpSpec {
            name: "point_add_g1".into(),
            description: "Point addition on G1: P + Q.".into(),
            input_count: PortSpec::Fixed(2),
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into(), "bls12-381".into()],
        },
        BlackBoxOpSpec {
            name: "pairing_check".into(),
            description: "Pairing check: e(A, B) == e(C, D).".into(),
            input_count: PortSpec::Fixed(4),
            output_count: PortSpec::Fixed(1),
            supported_fields: vec!["bn254".into(), "bls12-381".into()],
        },
    ]
}
