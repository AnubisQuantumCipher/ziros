use crate::error::{ZkfError, ZkfResult};
use crate::{FieldElement, FieldId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Visibility {
    Public,
    #[default]
    Private,
    Constant,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub name: String,
    pub visibility: Visibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constant: Option<FieldElement>,
    /// Optional type annotation (used by DSL and typed IR frontends).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ty: Option<String>,
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

impl Expr {
    pub fn signal(name: impl Into<String>) -> Self {
        Self::Signal(name.into())
    }

    pub fn constant_i64(v: i64) -> Self {
        Self::Const(FieldElement::from_i64(v))
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
    /// Lookup constraint: the input values must appear in the named table.
    /// Must be lowered via `lower_lookup_constraints()` before R1CS synthesis.
    Lookup {
        /// Input expressions to look up in the table.
        inputs: Vec<Expr>,
        /// Name of the lookup table (must be in `Program::lookup_tables`).
        table: String,
        /// Optional output signals to bind to the matched row's output columns.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outputs: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

impl Constraint {
    pub fn label(&self) -> Option<&String> {
        match self {
            Constraint::Equal { label, .. }
            | Constraint::Boolean { label, .. }
            | Constraint::Range { label, .. }
            | Constraint::BlackBox { label, .. }
            | Constraint::Lookup { label, .. } => label.as_ref(),
        }
    }
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
    /// Maps original source names to internal signal names.
    /// E.g., for Noir: `{"a": "w0", "b": "w1", "result": "w4"}`.
    /// Allows developers to use original parameter names in inputs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub input_aliases: BTreeMap<String, String>,
    /// Optional base64-encoded ACIR program bytes for solver-based Brillig resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acir_program_bytes: Option<String>,
}

/// A named lookup table for use with `Constraint::Lookup`.
/// Rows are stored in row-major order: `values[row][col]`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupTable {
    pub name: String,
    pub columns: Vec<String>,
    pub values: Vec<Vec<FieldElement>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct Program {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub field: FieldId,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub witness_plan: WitnessPlan,
    /// Named lookup tables referenced by `Constraint::Lookup`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lookup_tables: Vec<LookupTable>,
    /// Frontend-specific metadata. E.g., `{"frontend": "noir", "solver": "acvm"}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl Program {
    pub fn digest_hex(&self) -> String {
        let bytes = crate::json_to_vec(self).expect("program serialization must succeed");
        let hash = Sha256::digest(bytes);
        format!("{:x}", hash)
    }

    pub fn try_digest_hex(&self) -> ZkfResult<String> {
        let bytes = crate::json_to_vec(self)
            .map_err(|e| ZkfError::InvalidArtifact(format!("program serialization failed: {e}")))?;
        let hash = Sha256::digest(bytes);
        Ok(format!("{:x}", hash))
    }

    pub fn has_signal(&self, name: &str) -> bool {
        self.signals.iter().any(|s| s.name == name)
    }

    pub fn signal(&self, name: &str) -> Option<&Signal> {
        self.signals.iter().find(|s| s.name == name)
    }

    pub fn public_signal_names(&self) -> Vec<&str> {
        self.signals
            .iter()
            .filter_map(|s| (s.visibility == Visibility::Public).then_some(s.name.as_str()))
            .collect()
    }
}
