use crate::{FieldElement, FieldId, Visibility};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalType {
    Field,
    Bool,
    UInt { bits: u32 },
    Array { element: Box<SignalType>, len: u32 },
    Tuple { elements: Vec<SignalType> },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub name: String,
    pub visibility: Visibility,
    pub ty: SignalType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant: Option<FieldElement>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum Expr {
    Const(FieldElement),
    Signal(String),
    Add(Vec<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlackBoxOp {
    Poseidon,
    Sha256,
    Keccak256,
    Pedersen,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
    SchnorrVerify,
    Blake2s,
    RecursiveAggregationMarker,
    /// Scalar multiplication on G1: [scalar] * base_point
    ScalarMulG1,
    /// Point addition on G1: P + Q (or subtraction via params)
    PointAddG1,
    /// Pairing check: e(A, B) == e(C, D)
    PairingCheck,
}

impl BlackBoxOp {
    pub fn as_str(self) -> &'static str {
        match self {
            BlackBoxOp::Poseidon => "poseidon",
            BlackBoxOp::Sha256 => "sha256",
            BlackBoxOp::Keccak256 => "keccak256",
            BlackBoxOp::Pedersen => "pedersen",
            BlackBoxOp::EcdsaSecp256k1 => "ecdsa_secp256k1",
            BlackBoxOp::EcdsaSecp256r1 => "ecdsa_secp256r1",
            BlackBoxOp::SchnorrVerify => "schnorr_verify",
            BlackBoxOp::Blake2s => "blake2s",
            BlackBoxOp::RecursiveAggregationMarker => "recursive_aggregation_marker",
            BlackBoxOp::ScalarMulG1 => "scalar_mul_g1",
            BlackBoxOp::PointAddG1 => "point_add_g1",
            BlackBoxOp::PairingCheck => "pairing_check",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Constraint {
    Equal {
        lhs: Expr,
        rhs: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Boolean {
        signal: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Range {
        signal: String,
        bits: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Lookup {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        table: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    CustomGate {
        gate: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outputs: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        params: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    MemoryRead {
        memory: String,
        index: Expr,
        value: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    MemoryWrite {
        memory: String,
        index: Expr,
        value: Expr,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    BlackBox {
        op: BlackBoxOp,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<Expr>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        outputs: Vec<String>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        params: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Permutation {
        left: String,
        right: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    Copy {
        from: String,
        to: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

/// A named lookup table with typed column data.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupTable {
    pub name: String,
    pub columns: usize,
    pub values: Vec<Vec<FieldElement>>,
}

/// A named memory region (read-only or read-write).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub name: String,
    pub size: u32,
    pub read_only: bool,
}

/// A named custom gate definition.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustomGateDefinition {
    pub name: String,
    pub input_count: usize,
    pub output_count: usize,
    /// Optional symbolic expression for documentation / debugging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraint_expr: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessAssignment {
    pub target: String,
    pub expr: Expr,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WitnessHintKind {
    #[default]
    Copy,
    InverseOrZero,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessHint {
    pub target: String,
    pub source: String,
    #[serde(default)]
    pub kind: WitnessHintKind,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct WitnessPlan {
    #[serde(default)]
    pub assignments: Vec<WitnessAssignment>,
    #[serde(default)]
    pub hints: Vec<WitnessHint>,
    /// Optional base64-encoded ACIR program bytes for solver-based Brillig resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acir_program_bytes: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub name: String,
    pub field: FieldId,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub witness_plan: WitnessPlan,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookup_tables: Vec<LookupTable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_regions: Vec<MemoryRegion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_gates: Vec<CustomGateDefinition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl Program {
    pub fn digest_hex(&self) -> String {
        let bytes = crate::json_to_vec(self).expect("zir program serialization must succeed");
        let hash = Sha256::digest(bytes);
        format!("{:x}", hash)
    }

    pub fn try_digest_hex(&self) -> crate::ZkfResult<String> {
        let bytes = crate::json_to_vec(self).map_err(|e| {
            crate::ZkfError::InvalidArtifact(format!("zir program serialization failed: {e}"))
        })?;
        let hash = Sha256::digest(bytes);
        Ok(format!("{:x}", hash))
    }
}
