use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use zkf_core::zir_v1 as zir;
use zkf_core::{FieldElement, FieldId, Program, Visibility};

pub const ZIR_LANGUAGE_NAME: &str = "zir";
pub const ZIR_LANGUAGE_VERSION: &str = "zir-src-v1";
pub const ZIR_LANGUAGE_TIER: &str = ZIR_LANGUAGE_TIER1;
pub const ZIR_LANGUAGE_TIER1: &str = "tier1-total-circuit-subset";
pub const ZIR_LANGUAGE_TIER2: &str = "tier2-explicit-zir-feature-subset";

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ZirTier {
    #[default]
    Tier1,
    Tier2,
}

impl ZirTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tier1 => ZIR_LANGUAGE_TIER1,
            Self::Tier2 => ZIR_LANGUAGE_TIER2,
        }
    }

    pub fn short_name(self) -> &'static str {
        match self {
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
        }
    }

    fn allows_tier2(self) -> bool {
        matches!(self, Self::Tier2)
    }
}

impl fmt::Display for ZirTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short_name())
    }
}

impl FromStr for ZirTier {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1" | "tier1" | "tier-1" | "total" => Ok(Self::Tier1),
            "2" | "tier2" | "tier-2" | "advanced" => Ok(Self::Tier2),
            other => Err(format!(
                "unknown Zir tier '{other}' (expected tier1 or tier2)"
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ZirCompileOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<ZirTier>,
    #[serde(default)]
    pub allow_tier2: bool,
}

impl ZirCompileOptions {
    pub fn entry(entry: impl Into<String>) -> Self {
        Self {
            entry: Some(entry.into()),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirSourceDigest {
    pub algorithm: String,
    pub hex: String,
}

impl ZirSourceDigest {
    pub fn new(source: &str) -> Self {
        let digest = Sha256::digest(source.as_bytes());
        Self {
            algorithm: "sha256".to_string(),
            hex: format!("{digest:x}"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirSourceProgram {
    pub circuits: Vec<ZirCircuit>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirCircuit {
    pub name: String,
    pub field: FieldId,
    #[serde(default)]
    pub tier: ZirTier,
    pub items: Vec<ZirItem>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirItem {
    Const {
        name: String,
        ty: ZirType,
        value: ZirExpr,
    },
    Decl {
        visibility: ZirVisibility,
        name: String,
        ty: ZirType,
    },
    Let {
        name: String,
        ty: ZirType,
        expr: ZirExpr,
    },
    Assign {
        name: String,
        expr: ZirExpr,
    },
    Constrain {
        constraint: ZirConstraint,
    },
    LookupTable {
        name: String,
        columns: usize,
        values: Vec<Vec<ZirExpr>>,
    },
    Memory {
        name: String,
        size: u32,
        read_only: bool,
    },
    BlackBox {
        op: ZirBlackBoxOp,
        inputs: Vec<ZirExpr>,
        outputs: Vec<String>,
    },
    CustomGate {
        gate: String,
        inputs: Vec<ZirExpr>,
        outputs: Vec<String>,
    },
    Copy {
        from: String,
        to: String,
    },
    Permutation {
        left: String,
        right: String,
    },
    Expose {
        name: String,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZirVisibility {
    Public,
    Private,
}

impl From<ZirVisibility> for Visibility {
    fn from(value: ZirVisibility) -> Self {
        match value {
            ZirVisibility::Public => Visibility::Public,
            ZirVisibility::Private => Visibility::Private,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirType {
    Field,
    Bool,
    UInt { bits: u32 },
    Array { element: Box<ZirType>, len: u32 },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirConstraint {
    Equal {
        lhs: ZirExpr,
        rhs: ZirExpr,
    },
    Range {
        signal: String,
        bits: u32,
    },
    Boolean {
        signal: String,
    },
    Lookup {
        inputs: Vec<ZirExpr>,
        table: String,
    },
    Nonzero {
        signal: String,
    },
    Leq {
        lhs: ZirExpr,
        rhs: ZirExpr,
        bits: u32,
    },
    Geq {
        lhs: ZirExpr,
        rhs: ZirExpr,
        bits: u32,
    },
    MemoryRead {
        memory: String,
        index: ZirExpr,
        value: ZirExpr,
    },
    MemoryWrite {
        memory: String,
        index: ZirExpr,
        value: ZirExpr,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZirBlackBoxOp {
    Poseidon,
    Sha256,
    Keccak256,
    Pedersen,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
    SchnorrVerify,
    Blake2s,
    RecursiveAggregationMarker,
    ScalarMulG1,
    PointAddG1,
    PairingCheck,
}

impl ZirBlackBoxOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Poseidon => "poseidon",
            Self::Sha256 => "sha256",
            Self::Keccak256 => "keccak256",
            Self::Pedersen => "pedersen",
            Self::EcdsaSecp256k1 => "ecdsa_secp256k1",
            Self::EcdsaSecp256r1 => "ecdsa_secp256r1",
            Self::SchnorrVerify => "schnorr_verify",
            Self::Blake2s => "blake2s",
            Self::RecursiveAggregationMarker => "recursive_aggregation_marker",
            Self::ScalarMulG1 => "scalar_mul_g1",
            Self::PointAddG1 => "point_add_g1",
            Self::PairingCheck => "pairing_check",
        }
    }
}

impl From<ZirBlackBoxOp> for zir::BlackBoxOp {
    fn from(value: ZirBlackBoxOp) -> Self {
        match value {
            ZirBlackBoxOp::Poseidon => Self::Poseidon,
            ZirBlackBoxOp::Sha256 => Self::Sha256,
            ZirBlackBoxOp::Keccak256 => Self::Keccak256,
            ZirBlackBoxOp::Pedersen => Self::Pedersen,
            ZirBlackBoxOp::EcdsaSecp256k1 => Self::EcdsaSecp256k1,
            ZirBlackBoxOp::EcdsaSecp256r1 => Self::EcdsaSecp256r1,
            ZirBlackBoxOp::SchnorrVerify => Self::SchnorrVerify,
            ZirBlackBoxOp::Blake2s => Self::Blake2s,
            ZirBlackBoxOp::RecursiveAggregationMarker => Self::RecursiveAggregationMarker,
            ZirBlackBoxOp::ScalarMulG1 => Self::ScalarMulG1,
            ZirBlackBoxOp::PointAddG1 => Self::PointAddG1,
            ZirBlackBoxOp::PairingCheck => Self::PairingCheck,
        }
    }
}

impl FromStr for ZirBlackBoxOp {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "poseidon" => Ok(Self::Poseidon),
            "sha256" => Ok(Self::Sha256),
            "keccak256" => Ok(Self::Keccak256),
            "pedersen" => Ok(Self::Pedersen),
            "ecdsa_secp256k1" => Ok(Self::EcdsaSecp256k1),
            "ecdsa_secp256r1" => Ok(Self::EcdsaSecp256r1),
            "schnorr_verify" => Ok(Self::SchnorrVerify),
            "blake2s" => Ok(Self::Blake2s),
            "recursive_aggregation_marker" => Ok(Self::RecursiveAggregationMarker),
            "scalar_mul_g1" => Ok(Self::ScalarMulG1),
            "point_add_g1" => Ok(Self::PointAddG1),
            "pairing_check" => Ok(Self::PairingCheck),
            other => Err(format!("unsupported blackbox op '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirExpr {
    Number(i64),
    Var(String),
    Binary {
        op: ZirBinaryOp,
        left: Box<ZirExpr>,
        right: Box<ZirExpr>,
    },
    Call {
        function: String,
        args: Vec<ZirExpr>,
    },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZirBinaryOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZirDiagnosticSeverity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirDiagnostic {
    pub severity: ZirDiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirProofObligation {
    pub id: String,
    pub category: String,
    pub required_assurance: String,
    pub statement: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirCheckReport {
    pub ok: bool,
    pub language: String,
    pub language_version: String,
    pub language_tier: String,
    pub source_digest: ZirSourceDigest,
    pub entry: Option<String>,
    pub field: Option<FieldId>,
    pub circuit_count: usize,
    pub declaration_count: usize,
    pub public_signals: Vec<String>,
    pub private_signals: Vec<String>,
    pub constraint_count: usize,
    pub witness_assignment_count: usize,
    pub proof_obligations: Vec<ZirProofObligation>,
    pub diagnostics: Vec<ZirDiagnostic>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirCompileReport {
    pub language: String,
    pub language_version: String,
    pub language_tier: String,
    pub source_digest: ZirSourceDigest,
    pub program_name: String,
    pub field: FieldId,
    pub ir_family: String,
    pub signal_count: usize,
    pub public_signals: Vec<String>,
    pub private_signals: Vec<String>,
    pub constraint_count: usize,
    pub witness_assignment_count: usize,
    pub proof_obligations: Vec<ZirProofObligation>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirSourceMapEntry {
    pub generated_kind: String,
    pub generated_name: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirSourceMap {
    pub source_digest: ZirSourceDigest,
    pub entries: Vec<ZirSourceMapEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirInspection {
    pub language: String,
    pub language_version: String,
    pub source_digest: ZirSourceDigest,
    pub circuits: Vec<ZirInspectionCircuit>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirInspectionCircuit {
    pub name: String,
    pub field: FieldId,
    pub tier: ZirTier,
    pub item_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirPackageReport {
    pub ok: bool,
    pub source: String,
    pub package_dir: String,
    pub manifest: String,
    pub source_digest: ZirSourceDigest,
    pub program_digest: String,
    pub ir_family: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirFlowProgram {
    pub workflow: String,
    pub steps: Vec<ZirFlowStep>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirFlowStep {
    Source {
        alias: String,
        path: PathBuf,
    },
    Check {
        alias: String,
        tier: Option<ZirTier>,
    },
    Lower {
        alias: String,
        target: String,
        out: PathBuf,
    },
    Package {
        alias: String,
        out: PathBuf,
    },
    Prove {
        alias: String,
        backend: String,
        inputs: PathBuf,
        out: PathBuf,
        #[serde(default)]
        allow_dev_deterministic_groth16: bool,
    },
    Verify {
        alias: String,
        backend: String,
        artifact: PathBuf,
        #[serde(default)]
        allow_dev_deterministic_groth16: bool,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirFlowPlan {
    pub workflow: String,
    pub approved_required: bool,
    pub steps: Vec<ZirFlowStep>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZirCompileOutput {
    pub source: ZirSourceProgram,
    pub zir: zir::Program,
    pub report: ZirCompileReport,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ZirLangError {
    Diagnostics(Vec<ZirDiagnostic>),
    Core(String),
}

impl fmt::Display for ZirLangError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Diagnostics(diagnostics) => {
                let count = diagnostics.len();
                write!(f, "zir language check failed with {count} diagnostic(s)")
            }
            Self::Core(message) => f.write_str(message),
        }
    }
}

impl Error for ZirLangError {}

impl ZirLangError {
    pub fn diagnostics(&self) -> Vec<ZirDiagnostic> {
        match self {
            Self::Diagnostics(diagnostics) => diagnostics.clone(),
            Self::Core(message) => vec![ZirDiagnostic {
                severity: ZirDiagnosticSeverity::Error,
                code: "zir.core".to_string(),
                message: message.clone(),
                line: 1,
                column: 1,
            }],
        }
    }
}

pub fn parse_source(source: &str) -> Result<ZirSourceProgram, ZirLangError> {
    let tokens = Lexer::new(source).lex()?;
    Parser::new(tokens).parse_program()
}

pub fn check_source(source: &str) -> ZirCheckReport {
    check_source_with_options(source, &ZirCompileOptions::default())
}

pub fn check_source_with_options(source: &str, options: &ZirCompileOptions) -> ZirCheckReport {
    let source_digest = ZirSourceDigest::new(source);
    match compile_source_with_options(source, options) {
        Ok(output) => {
            let (public_signals, private_signals) = signal_names_by_visibility(&output.zir);
            ZirCheckReport {
                ok: true,
                language: ZIR_LANGUAGE_NAME.to_string(),
                language_version: ZIR_LANGUAGE_VERSION.to_string(),
                language_tier: output.report.language_tier.clone(),
                source_digest,
                entry: Some(output.zir.name.clone()),
                field: Some(output.zir.field),
                circuit_count: output.source.circuits.len(),
                declaration_count: output.zir.signals.len(),
                public_signals,
                private_signals,
                constraint_count: output.zir.constraints.len(),
                witness_assignment_count: output.zir.witness_plan.assignments.len(),
                proof_obligations: output.report.proof_obligations,
                diagnostics: Vec::new(),
            }
        }
        Err(error) => ZirCheckReport {
            ok: false,
            language: ZIR_LANGUAGE_NAME.to_string(),
            language_version: ZIR_LANGUAGE_VERSION.to_string(),
            language_tier: ZIR_LANGUAGE_TIER.to_string(),
            source_digest,
            entry: None,
            field: None,
            circuit_count: 0,
            declaration_count: 0,
            public_signals: Vec::new(),
            private_signals: Vec::new(),
            constraint_count: 0,
            witness_assignment_count: 0,
            proof_obligations: base_proof_obligations(),
            diagnostics: error.diagnostics(),
        },
    }
}

pub fn compile_source_to_zir(source: &str) -> Result<ZirCompileOutput, ZirLangError> {
    compile_source_with_options(source, &ZirCompileOptions::default())
}

pub fn compile_source_with_options(
    source: &str,
    options: &ZirCompileOptions,
) -> Result<ZirCompileOutput, ZirLangError> {
    let parsed = parse_source(source)?;
    let circuit = select_circuit(&parsed, options)?;
    let requested_tier = options.tier.unwrap_or(circuit.tier);
    if circuit.tier == ZirTier::Tier2 && !options.allow_tier2 && !requested_tier.allows_tier2() {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zir.tier.requires_tier2",
            "this source declares Tier 2 features; rerun with Tier 2 enabled",
            Span::start(),
        )]));
    }
    if requested_tier == ZirTier::Tier1 && circuit.tier == ZirTier::Tier2 {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zir.tier.mismatch",
            "cannot compile a Tier 2 circuit as Tier 1",
            Span::start(),
        )]));
    }

    let source_digest = ZirSourceDigest::new(source);
    if parsed.circuits.is_empty() {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zir.syntax.empty",
            "expected at least one circuit declaration",
            Span::start(),
        )]));
    }

    let mut compiler = Compiler::new(circuit, requested_tier, source_digest.clone());
    let zir = compiler.compile()?;
    let (public_signals, private_signals) = signal_names_by_visibility(&zir);
    let report = ZirCompileReport {
        language: ZIR_LANGUAGE_NAME.to_string(),
        language_version: ZIR_LANGUAGE_VERSION.to_string(),
        language_tier: requested_tier.as_str().to_string(),
        source_digest,
        program_name: zir.name.clone(),
        field: zir.field,
        ir_family: "zir-v1".to_string(),
        signal_count: zir.signals.len(),
        public_signals,
        private_signals,
        constraint_count: zir.constraints.len(),
        witness_assignment_count: zir.witness_plan.assignments.len(),
        proof_obligations: compiler.proof_obligations,
        notes: vec![
            "Zir is a bounded native source-language frontend; it does not claim automatic formal verification of arbitrary programs.".to_string(),
            "Unsupported source constructs fail closed before ZIR/IR emission.".to_string(),
        ],
    };

    Ok(ZirCompileOutput {
        source: parsed,
        zir,
        report,
    })
}

fn select_circuit<'a>(
    parsed: &'a ZirSourceProgram,
    options: &ZirCompileOptions,
) -> Result<&'a ZirCircuit, ZirLangError> {
    if parsed.circuits.is_empty() {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zir.syntax.empty",
            "expected at least one circuit declaration",
            Span::start(),
        )]));
    }
    if let Some(entry) = options.entry.as_deref() {
        return parsed
            .circuits
            .iter()
            .find(|circuit| circuit.name == entry)
            .ok_or_else(|| {
                ZirLangError::Diagnostics(vec![diagnostic(
                    "zir.entry.not_found",
                    format!("entry circuit '{entry}' was not found"),
                    Span::start(),
                )])
            });
    }
    if parsed.circuits.len() != 1 {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zir.entry.required",
            "multiple circuits are present; pass an explicit entry",
            Span::start(),
        )]));
    }
    Ok(&parsed.circuits[0])
}

pub fn inspect_source(source: &str) -> Result<ZirInspection, ZirLangError> {
    let parsed = parse_source(source)?;
    Ok(ZirInspection {
        language: ZIR_LANGUAGE_NAME.to_string(),
        language_version: ZIR_LANGUAGE_VERSION.to_string(),
        source_digest: ZirSourceDigest::new(source),
        circuits: parsed
            .circuits
            .iter()
            .map(|circuit| ZirInspectionCircuit {
                name: circuit.name.clone(),
                field: circuit.field,
                tier: circuit.tier,
                item_count: circuit.items.len(),
            })
            .collect(),
    })
}

pub fn lower_source_to_ir_v2(source: &str) -> Result<(Program, ZirCompileReport), ZirLangError> {
    lower_source_to_ir_v2_with_options(source, &ZirCompileOptions::default())
}

pub fn lower_source_to_ir_v2_with_options(
    source: &str,
    options: &ZirCompileOptions,
) -> Result<(Program, ZirCompileReport), ZirLangError> {
    let output = compile_source_with_options(source, options)?;
    let mut report = output.report.clone();
    let program = zkf_core::program_zir_to_v2(&output.zir)
        .map_err(|error| ZirLangError::Core(format!("failed to lower ZIR v1 to IR v2: {error}")))?;
    report.ir_family = "ir-v2".to_string();
    Ok((program, report))
}

pub fn format_source(source: &str) -> Result<String, ZirLangError> {
    let parsed = parse_source(source)?;
    Ok(format_program(&parsed))
}

pub fn parse_flow_source(source: &str) -> Result<ZirFlowProgram, ZirLangError> {
    let mut workflow = None;
    let mut steps = Vec::new();
    for (line_index, raw_line) in source.lines().enumerate() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() || line == "}" {
            continue;
        }
        let span = Span {
            line: line_index + 1,
            column: 1,
        };
        if let Some(rest) = line.strip_prefix("workflow ") {
            let name = rest
                .trim_end_matches('{')
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("");
            if name.is_empty() {
                return Err(ZirLangError::Diagnostics(vec![diagnostic(
                    "zirflow.syntax.workflow",
                    "expected workflow name",
                    span,
                )]));
            }
            workflow = Some(name.to_string());
            continue;
        }
        let line = line.trim_end_matches(';').trim();
        if let Some(rest) = line.strip_prefix("source ") {
            let (path, tail) = parse_quoted_path(rest, span)?;
            let alias = tail
                .trim()
                .strip_prefix("as ")
                .ok_or_else(|| {
                    ZirLangError::Diagnostics(vec![diagnostic(
                        "zirflow.syntax.source",
                        "expected `as <alias>` after source path",
                        span,
                    )])
                })?
                .trim();
            steps.push(ZirFlowStep::Source {
                alias: alias.to_string(),
                path,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("check ") {
            let mut parts = rest.split_whitespace();
            let alias = parts.next().unwrap_or("").to_string();
            let mut tier = None;
            while let Some(part) = parts.next() {
                if part == "tier" {
                    let raw_tier = parts.next().ok_or_else(|| {
                        ZirLangError::Diagnostics(vec![diagnostic(
                            "zirflow.syntax.tier",
                            "expected tier value",
                            span,
                        )])
                    })?;
                    tier = Some(raw_tier.parse::<ZirTier>().map_err(|error| {
                        ZirLangError::Diagnostics(vec![diagnostic(
                            "zirflow.syntax.tier",
                            error,
                            span,
                        )])
                    })?);
                }
            }
            steps.push(ZirFlowStep::Check { alias, tier });
            continue;
        }
        if let Some(rest) = line.strip_prefix("lower ") {
            let mut parts = rest.split_whitespace();
            let alias = parts.next().unwrap_or("").to_string();
            expect_flow_word(parts.next(), "to", span)?;
            let target = parts.next().unwrap_or("zir-v1").to_string();
            expect_flow_word(parts.next(), "out", span)?;
            let out = strip_flow_path(parts.next().unwrap_or(""), span)?;
            steps.push(ZirFlowStep::Lower { alias, target, out });
            continue;
        }
        if let Some(rest) = line.strip_prefix("package ") {
            let mut parts = rest.split_whitespace();
            let alias = parts.next().unwrap_or("").to_string();
            expect_flow_word(parts.next(), "out", span)?;
            let out = strip_flow_path(parts.next().unwrap_or(""), span)?;
            steps.push(ZirFlowStep::Package { alias, out });
            continue;
        }
        if let Some(rest) = line.strip_prefix("prove ") {
            let mut parts = rest.split_whitespace();
            let alias = parts.next().unwrap_or("").to_string();
            expect_flow_word(parts.next(), "backend", span)?;
            let backend = strip_flow_string(parts.next().unwrap_or(""), span)?;
            expect_flow_word(parts.next(), "inputs", span)?;
            let inputs = strip_flow_path(parts.next().unwrap_or(""), span)?;
            expect_flow_word(parts.next(), "out", span)?;
            let out = strip_flow_path(parts.next().unwrap_or(""), span)?;
            let allow_dev_deterministic_groth16 =
                parse_flow_flags(parts, &["allow_dev_deterministic_groth16"], span)?
                    .contains("allow_dev_deterministic_groth16");
            steps.push(ZirFlowStep::Prove {
                alias,
                backend,
                inputs,
                out,
                allow_dev_deterministic_groth16,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("verify ") {
            let mut parts = rest.split_whitespace();
            let alias = parts.next().unwrap_or("").to_string();
            expect_flow_word(parts.next(), "backend", span)?;
            let backend = strip_flow_string(parts.next().unwrap_or(""), span)?;
            expect_flow_word(parts.next(), "artifact", span)?;
            let artifact = strip_flow_path(parts.next().unwrap_or(""), span)?;
            let allow_dev_deterministic_groth16 =
                parse_flow_flags(parts, &["allow_dev_deterministic_groth16"], span)?
                    .contains("allow_dev_deterministic_groth16");
            steps.push(ZirFlowStep::Verify {
                alias,
                backend,
                artifact,
                allow_dev_deterministic_groth16,
            });
            continue;
        }
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zirflow.syntax.step",
            format!("unsupported ZirFlow step `{line}`"),
            span,
        )]));
    }
    Ok(ZirFlowProgram {
        workflow: workflow.ok_or_else(|| {
            ZirLangError::Diagnostics(vec![diagnostic(
                "zirflow.syntax.workflow",
                "expected `workflow <name> {`",
                Span::start(),
            )])
        })?,
        steps,
    })
}

pub fn plan_flow_source(source: &str) -> Result<ZirFlowPlan, ZirLangError> {
    let program = parse_flow_source(source)?;
    let approved_required = program.steps.iter().any(|step| {
        matches!(
            step,
            ZirFlowStep::Lower { .. }
                | ZirFlowStep::Package { .. }
                | ZirFlowStep::Prove { .. }
                | ZirFlowStep::Verify { .. }
        )
    });
    Ok(ZirFlowPlan {
        workflow: program.workflow,
        approved_required,
        steps: program.steps,
    })
}

fn parse_quoted_path(value: &str, span: Span) -> Result<(PathBuf, &str), ZirLangError> {
    let trimmed = value.trim();
    if !trimmed.starts_with('"') {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zirflow.syntax.path",
            "expected quoted path",
            span,
        )]));
    }
    let Some(end) = trimmed[1..].find('"') else {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zirflow.syntax.path",
            "unterminated quoted path",
            span,
        )]));
    };
    let end = end + 1;
    Ok((PathBuf::from(&trimmed[1..end]), &trimmed[end + 1..]))
}

fn strip_flow_string(value: &str, span: Span) -> Result<String, ZirLangError> {
    let value = value.trim().trim_end_matches(';').trim_end_matches(',');
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        Ok(value[1..value.len() - 1].to_string())
    } else if value.is_empty() {
        Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zirflow.syntax.value",
            "expected value",
            span,
        )]))
    } else {
        Ok(value.to_string())
    }
}

fn strip_flow_path(value: &str, span: Span) -> Result<PathBuf, ZirLangError> {
    strip_flow_string(value, span).map(PathBuf::from)
}

fn expect_flow_word(value: Option<&str>, expected: &str, span: Span) -> Result<(), ZirLangError> {
    if value == Some(expected) {
        Ok(())
    } else {
        Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zirflow.syntax.expected",
            format!("expected `{expected}`"),
            span,
        )]))
    }
}

fn parse_flow_flags<'a>(
    parts: impl Iterator<Item = &'a str>,
    allowed: &[&str],
    span: Span,
) -> Result<BTreeSet<String>, ZirLangError> {
    let mut flags = BTreeSet::new();
    for part in parts {
        let flag = part.trim().trim_end_matches(';').trim_end_matches(',');
        if flag.is_empty() {
            continue;
        }
        if !allowed.contains(&flag) {
            return Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zirflow.syntax.flag",
                format!("unknown ZirFlow flag '{flag}'"),
                span,
            )]));
        }
        flags.insert(flag.to_string());
    }
    Ok(flags)
}

fn signal_names_by_visibility(program: &zir::Program) -> (Vec<String>, Vec<String>) {
    let mut public = Vec::new();
    let mut private = Vec::new();
    for signal in &program.signals {
        match signal.visibility {
            Visibility::Public => public.push(signal.name.clone()),
            Visibility::Private => private.push(signal.name.clone()),
            Visibility::Constant => {}
        }
    }
    (public, private)
}

fn collect_zir_signal_names(expr: &zir::Expr, out: &mut BTreeSet<String>) {
    match expr {
        zir::Expr::Const(_) => {}
        zir::Expr::Signal(name) => {
            out.insert(name.clone());
        }
        zir::Expr::Add(values) => {
            for value in values {
                collect_zir_signal_names(value, out);
            }
        }
        zir::Expr::Sub(left, right) | zir::Expr::Mul(left, right) | zir::Expr::Div(left, right) => {
            collect_zir_signal_names(left, out);
            collect_zir_signal_names(right, out);
        }
    }
}

fn base_proof_obligations() -> Vec<ZirProofObligation> {
    vec![
        ZirProofObligation {
            id: "zir.source.semantics".to_string(),
            category: "language_semantics".to_string(),
            required_assurance: "mechanized".to_string(),
            statement: "Formalize Tier 1 Zir source semantics and prove determinism for accepted programs.".to_string(),
        },
        ZirProofObligation {
            id: "zir.lowering.source_to_zir_v1".to_string(),
            category: "lowering".to_string(),
            required_assurance: "mechanized".to_string(),
            statement: "Prove source-to-ZIR v1 lowering preserves expression equality, range, boolean, visibility, and witness-assignment meaning.".to_string(),
        },
        ZirProofObligation {
            id: "zir.privacy.public_private_separation".to_string(),
            category: "privacy_boundary".to_string(),
            required_assurance: "mechanized".to_string(),
            statement: "Prove private witness signals are never made public except through explicit public declarations or valid expose statements.".to_string(),
        },
        ZirProofObligation {
            id: "zir.unsupported.fail_closed".to_string(),
            category: "safety".to_string(),
            required_assurance: "bounded_then_mechanized".to_string(),
            statement: "Show unsupported control flow, recursion, host effects, and unknown calls fail before backend artifacts are emitted.".to_string(),
        },
    ]
}

fn diagnostic(code: &str, message: impl Into<String>, span: Span) -> ZirDiagnostic {
    ZirDiagnostic {
        severity: ZirDiagnosticSeverity::Error,
        code: code.to_string(),
        message: message.into(),
        line: span.line,
        column: span.column,
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Span {
    line: usize,
    column: usize,
}

impl Span {
    fn start() -> Self {
        Self { line: 1, column: 1 }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    span: Span,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum TokenKind {
    Ident(String),
    Number(i64),
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    Semi,
    Comma,
    Less,
    Greater,
    Plus,
    Minus,
    Arrow,
    Star,
    Slash,
    Equal,
    EqEq,
    Eof,
}

struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    column: usize,
    _source: &'a str,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            chars: source.chars().collect(),
            pos: 0,
            line: 1,
            column: 1,
            _source: source,
        }
    }

    fn lex(mut self) -> Result<Vec<Token>, ZirLangError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            let span = self.span();
            let Some(ch) = self.peek() else {
                tokens.push(Token {
                    kind: TokenKind::Eof,
                    span,
                });
                return Ok(tokens);
            };

            let kind = match ch {
                '{' => {
                    self.bump();
                    TokenKind::LBrace
                }
                '}' => {
                    self.bump();
                    TokenKind::RBrace
                }
                '(' => {
                    self.bump();
                    TokenKind::LParen
                }
                ')' => {
                    self.bump();
                    TokenKind::RParen
                }
                '[' => {
                    self.bump();
                    TokenKind::LBracket
                }
                ']' => {
                    self.bump();
                    TokenKind::RBracket
                }
                ':' => {
                    self.bump();
                    TokenKind::Colon
                }
                ';' => {
                    self.bump();
                    TokenKind::Semi
                }
                ',' => {
                    self.bump();
                    TokenKind::Comma
                }
                '<' => {
                    self.bump();
                    TokenKind::Less
                }
                '>' => {
                    self.bump();
                    TokenKind::Greater
                }
                '+' => {
                    self.bump();
                    TokenKind::Plus
                }
                '-' => {
                    self.bump();
                    if self.peek() == Some('>') {
                        self.bump();
                        TokenKind::Arrow
                    } else {
                        TokenKind::Minus
                    }
                }
                '*' => {
                    self.bump();
                    TokenKind::Star
                }
                '/' => {
                    self.bump();
                    TokenKind::Slash
                }
                '=' => {
                    self.bump();
                    if self.peek() == Some('=') {
                        self.bump();
                        TokenKind::EqEq
                    } else {
                        TokenKind::Equal
                    }
                }
                ch if ch.is_ascii_alphabetic() || ch == '_' => TokenKind::Ident(self.lex_ident()),
                ch if ch.is_ascii_digit() => TokenKind::Number(self.lex_number(span)?),
                _ => {
                    return Err(ZirLangError::Diagnostics(vec![diagnostic(
                        "zir.syntax.unexpected_character",
                        format!("unexpected character '{ch}'"),
                        span,
                    )]));
                }
            };
            tokens.push(Token { kind, span });
        }
    }

    fn lex_ident(&mut self) -> String {
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                out.push(ch);
                self.bump();
            } else {
                break;
            }
        }
        out
    }

    fn lex_number(&mut self, span: Span) -> Result<i64, ZirLangError> {
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                out.push(ch);
                self.bump();
            } else if ch == '_' {
                self.bump();
            } else {
                break;
            }
        }
        out.parse::<i64>().map_err(|error| {
            ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.number",
                format!("invalid integer literal: {error}"),
                span,
            )])
        })
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.bump();
            }
            if self.peek() == Some('/') && self.peek_next() == Some('/') {
                while let Some(ch) = self.peek() {
                    self.bump();
                    if ch == '\n' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_next(&self) -> Option<char> {
        self.chars.get(self.pos + 1).copied()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            self.pos += 1;
            if ch == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
    }

    fn span(&self) -> Span {
        Span {
            line: self.line,
            column: self.column,
        }
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn parse_program(&mut self) -> Result<ZirSourceProgram, ZirLangError> {
        let mut circuits = Vec::new();
        while !self.at_eof() {
            circuits.push(self.parse_circuit()?);
        }
        Ok(ZirSourceProgram { circuits })
    }

    fn parse_circuit(&mut self) -> Result<ZirCircuit, ZirLangError> {
        self.expect_keyword("circuit")?;
        let name = self.expect_ident("expected circuit name")?;
        self.expect(TokenKind::LParen, "expected '(' after circuit name")?;
        self.expect_keyword("field")?;
        self.expect(TokenKind::Colon, "expected ':' after field")?;
        let field = self.parse_field_id()?;
        let mut tier = ZirTier::Tier1;
        if self.check(&TokenKind::Comma) {
            self.advance();
            self.expect_keyword("tier")?;
            self.expect(TokenKind::Colon, "expected ':' after tier")?;
            tier = self.parse_tier()?;
        }
        self.expect(TokenKind::RParen, "expected ')' after field id")?;
        self.expect(TokenKind::LBrace, "expected '{' before circuit body")?;

        let mut items = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.at_eof() {
            items.push(self.parse_item()?);
        }
        self.expect(TokenKind::RBrace, "expected '}' after circuit body")?;
        Ok(ZirCircuit {
            name,
            field,
            tier,
            items,
        })
    }

    fn parse_tier(&mut self) -> Result<ZirTier, ZirLangError> {
        let token = self.current().clone();
        match token.kind {
            TokenKind::Number(1) => {
                self.advance();
                Ok(ZirTier::Tier1)
            }
            TokenKind::Number(2) => {
                self.advance();
                Ok(ZirTier::Tier2)
            }
            TokenKind::Ident(value) => {
                self.advance();
                value.parse::<ZirTier>().map_err(|error| {
                    ZirLangError::Diagnostics(vec![diagnostic(
                        "zir.syntax.tier",
                        error,
                        token.span,
                    )])
                })
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.tier",
                "expected tier 1, tier 2, tier1, or tier2",
                token.span,
            )])),
        }
    }

    fn parse_item(&mut self) -> Result<ZirItem, ZirLangError> {
        let token = self.current().clone();
        match &token.kind {
            TokenKind::Ident(value) if value == "const" => {
                self.advance();
                let name = self.expect_ident("expected constant name")?;
                self.expect(TokenKind::Colon, "expected ':' after constant name")?;
                let ty = self.parse_type()?;
                self.expect(TokenKind::Equal, "expected '=' after constant type")?;
                let value = self.parse_expr()?;
                self.expect(TokenKind::Semi, "expected ';' after constant")?;
                Ok(ZirItem::Const { name, ty, value })
            }
            TokenKind::Ident(value) if value == "private" || value == "public" => {
                let visibility = if value == "public" {
                    ZirVisibility::Public
                } else {
                    ZirVisibility::Private
                };
                self.advance();
                let name = self.expect_ident("expected signal name")?;
                self.expect(TokenKind::Colon, "expected ':' after signal name")?;
                let ty = self.parse_type()?;
                self.expect(TokenKind::Semi, "expected ';' after declaration")?;
                Ok(ZirItem::Decl {
                    visibility,
                    name,
                    ty,
                })
            }
            TokenKind::Ident(value) if value == "let" => {
                self.advance();
                let name = self.expect_ident("expected let binding name")?;
                self.expect(TokenKind::Colon, "expected ':' after let binding name")?;
                let ty = self.parse_type()?;
                self.expect(TokenKind::Equal, "expected '=' after let binding type")?;
                let expr = self.parse_expr()?;
                self.expect(TokenKind::Semi, "expected ';' after let binding")?;
                Ok(ZirItem::Let { name, ty, expr })
            }
            TokenKind::Ident(value) if value == "constrain" => {
                self.advance();
                let constraint = self.parse_constraint()?;
                self.expect(TokenKind::Semi, "expected ';' after constraint")?;
                Ok(ZirItem::Constrain { constraint })
            }
            TokenKind::Ident(value) if value == "lookup" => self.parse_lookup_table_item(),
            TokenKind::Ident(value) if value == "memory" => self.parse_memory_item(),
            TokenKind::Ident(value) if value == "blackbox" => self.parse_blackbox_item(),
            TokenKind::Ident(value) if value == "custom_gate" => self.parse_custom_gate_item(),
            TokenKind::Ident(value) if value == "copy" => {
                self.advance();
                let from = self.expect_ident("expected source signal after copy")?;
                self.expect(TokenKind::Arrow, "expected '->' in copy statement")?;
                let to = self.expect_ident("expected target signal after copy arrow")?;
                self.expect(TokenKind::Semi, "expected ';' after copy statement")?;
                Ok(ZirItem::Copy { from, to })
            }
            TokenKind::Ident(value) if value == "permutation" => {
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after permutation")?;
                let left = self.expect_ident("expected left signal in permutation")?;
                self.expect(TokenKind::Comma, "expected ',' in permutation")?;
                let right = self.expect_ident("expected right signal in permutation")?;
                self.expect(TokenKind::RParen, "expected ')' after permutation")?;
                self.expect(TokenKind::Semi, "expected ';' after permutation")?;
                Ok(ZirItem::Permutation { left, right })
            }
            TokenKind::Ident(value) if value == "expose" => {
                self.advance();
                let name = self.expect_ident("expected signal name after expose")?;
                self.expect(TokenKind::Semi, "expected ';' after expose statement")?;
                Ok(ZirItem::Expose { name })
            }
            TokenKind::Ident(value) if unsupported_keyword(value) => {
                Err(ZirLangError::Diagnostics(vec![diagnostic(
                    "zir.unsupported.control_flow",
                    format!(
                        "'{value}' is outside Zir Tier 1; use bounded declarative constraints instead"
                    ),
                    token.span,
                )]))
            }
            TokenKind::Ident(name) => {
                let name = name.clone();
                self.advance();
                self.expect(TokenKind::Equal, "expected '=' in assignment")?;
                let expr = self.parse_expr()?;
                self.expect(TokenKind::Semi, "expected ';' after assignment")?;
                Ok(ZirItem::Assign { name, expr })
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.item",
                "expected declaration, let, assignment, constrain, or expose",
                token.span,
            )])),
        }
    }

    fn parse_lookup_table_item(&mut self) -> Result<ZirItem, ZirLangError> {
        self.expect_keyword("lookup")?;
        self.expect_keyword("table")?;
        let name = self.expect_ident("expected lookup table name")?;
        self.expect(TokenKind::LParen, "expected '(' after lookup table name")?;
        self.expect_keyword("columns")?;
        self.expect(TokenKind::Colon, "expected ':' after columns")?;
        let columns = self.expect_u32("expected lookup table column count")? as usize;
        self.expect(TokenKind::RParen, "expected ')' after lookup table columns")?;
        self.expect(TokenKind::LBrace, "expected '{' before lookup table rows")?;
        let mut values = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.at_eof() {
            let row = self.parse_bracketed_expr_list()?;
            values.push(row);
            if self.check(&TokenKind::Comma) {
                self.advance();
            }
        }
        self.expect(TokenKind::RBrace, "expected '}' after lookup table rows")?;
        Ok(ZirItem::LookupTable {
            name,
            columns,
            values,
        })
    }

    fn parse_memory_item(&mut self) -> Result<ZirItem, ZirLangError> {
        self.expect_keyword("memory")?;
        let name = self.expect_ident("expected memory name")?;
        self.expect(TokenKind::LParen, "expected '(' after memory name")?;
        self.expect_keyword("size")?;
        self.expect(TokenKind::Colon, "expected ':' after size")?;
        let size = self.expect_u32("expected memory size")?;
        self.expect(TokenKind::Comma, "expected ',' before read_only")?;
        self.expect_keyword("read_only")?;
        self.expect(TokenKind::Colon, "expected ':' after read_only")?;
        let read_only = self.expect_bool("expected true or false for read_only")?;
        self.expect(TokenKind::RParen, "expected ')' after memory declaration")?;
        self.expect(TokenKind::Semi, "expected ';' after memory declaration")?;
        Ok(ZirItem::Memory {
            name,
            size,
            read_only,
        })
    }

    fn parse_blackbox_item(&mut self) -> Result<ZirItem, ZirLangError> {
        self.expect_keyword("blackbox")?;
        let op_span = self.current().span;
        let op_name = self.expect_ident("expected blackbox operation")?;
        let op = op_name.parse::<ZirBlackBoxOp>().map_err(|error| {
            ZirLangError::Diagnostics(vec![diagnostic("zir.syntax.blackbox", error, op_span)])
        })?;
        self.expect(TokenKind::LParen, "expected '(' after blackbox op")?;
        let inputs = if self.check(&TokenKind::LBracket) {
            self.parse_bracketed_expr_list()?
        } else {
            self.parse_comma_exprs_until(TokenKind::RParen)?
        };
        self.expect(TokenKind::RParen, "expected ')' after blackbox inputs")?;
        self.expect(TokenKind::Arrow, "expected '->' after blackbox inputs")?;
        let outputs = self.parse_bracketed_ident_list()?;
        self.expect(TokenKind::Semi, "expected ';' after blackbox statement")?;
        Ok(ZirItem::BlackBox {
            op,
            inputs,
            outputs,
        })
    }

    fn parse_custom_gate_item(&mut self) -> Result<ZirItem, ZirLangError> {
        self.expect_keyword("custom_gate")?;
        let gate = self.expect_ident("expected custom gate name")?;
        self.expect(TokenKind::LParen, "expected '(' after custom gate name")?;
        let inputs = self.parse_comma_exprs_until(TokenKind::RParen)?;
        self.expect(TokenKind::RParen, "expected ')' after custom gate inputs")?;
        self.expect(TokenKind::Arrow, "expected '->' after custom gate inputs")?;
        let outputs = self.parse_bracketed_ident_list()?;
        self.expect(TokenKind::Semi, "expected ';' after custom gate statement")?;
        Ok(ZirItem::CustomGate {
            gate,
            inputs,
            outputs,
        })
    }

    fn parse_field_id(&mut self) -> Result<FieldId, ZirLangError> {
        let span = self.current().span;
        let mut field = self.expect_ident("expected field id")?;
        if self.check(&TokenKind::Minus) {
            self.advance();
            match self.current().kind.clone() {
                TokenKind::Ident(part) => {
                    field.push('-');
                    field.push_str(&part);
                    self.advance();
                }
                TokenKind::Number(part) => {
                    field.push('-');
                    field.push_str(&part.to_string());
                    self.advance();
                }
                _ => {
                    return Err(ZirLangError::Diagnostics(vec![diagnostic(
                        "zir.syntax.field",
                        "expected field id suffix after '-'",
                        self.current().span,
                    )]));
                }
            }
        }
        FieldId::from_str(&field).map_err(|error| {
            ZirLangError::Diagnostics(vec![diagnostic("zir.syntax.field", error, span)])
        })
    }

    fn parse_type(&mut self) -> Result<ZirType, ZirLangError> {
        let token = self.current().clone();
        let name = self.expect_ident("expected type")?;
        let mut ty = match name.as_str() {
            "field" => Ok(ZirType::Field),
            "bool" => Ok(ZirType::Bool),
            "u8" => Ok(ZirType::UInt { bits: 8 }),
            "u16" => Ok(ZirType::UInt { bits: 16 }),
            "u32" => Ok(ZirType::UInt { bits: 32 }),
            "u64" => {
                if self.check(&TokenKind::Less) {
                    self.advance();
                    let bits = self.expect_u32("expected integer bit width")?;
                    self.expect(TokenKind::Greater, "expected '>' after bit width")?;
                    Ok(ZirType::UInt { bits })
                } else {
                    Ok(ZirType::UInt { bits: 64 })
                }
            }
            other => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.type",
                format!("unsupported type '{other}'"),
                token.span,
            )])),
        }?;
        if self.check(&TokenKind::LBracket) {
            self.advance();
            let len = self.expect_u32("expected array length")?;
            self.expect(TokenKind::RBracket, "expected ']' after array length")?;
            ty = ZirType::Array {
                element: Box::new(ty),
                len,
            };
        }
        Ok(ty)
    }

    fn parse_constraint(&mut self) -> Result<ZirConstraint, ZirLangError> {
        if let TokenKind::Ident(name) = self.current().kind.clone() {
            if name == "range" {
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after range")?;
                let signal = self.expect_ident("expected signal name in range constraint")?;
                self.expect(TokenKind::Comma, "expected ',' in range constraint")?;
                let bits = self.expect_u32("expected range bit width")?;
                self.expect(TokenKind::RParen, "expected ')' after range constraint")?;
                return Ok(ZirConstraint::Range { signal, bits });
            }
            if name == "boolean" {
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after boolean")?;
                let signal = self.expect_ident("expected signal name in boolean constraint")?;
                self.expect(TokenKind::RParen, "expected ')' after boolean constraint")?;
                return Ok(ZirConstraint::Boolean { signal });
            }
            if name == "lookup" {
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after lookup")?;
                let inputs = self.parse_bracketed_expr_list()?;
                self.expect(TokenKind::Comma, "expected ',' after lookup inputs")?;
                let table = self.expect_ident("expected lookup table name")?;
                self.expect(TokenKind::RParen, "expected ')' after lookup constraint")?;
                return Ok(ZirConstraint::Lookup { inputs, table });
            }
            if name == "nonzero" {
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after nonzero")?;
                let signal = self.expect_ident("expected signal name in nonzero constraint")?;
                self.expect(TokenKind::RParen, "expected ')' after nonzero constraint")?;
                return Ok(ZirConstraint::Nonzero { signal });
            }
            if name == "leq" || name == "geq" {
                let is_leq = name == "leq";
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after comparison")?;
                let lhs = self.parse_expr()?;
                self.expect(TokenKind::Comma, "expected ',' after comparison lhs")?;
                let rhs = self.parse_expr()?;
                self.expect(TokenKind::Comma, "expected ',' after comparison rhs")?;
                let bits = self.expect_u32("expected comparison bit width")?;
                self.expect(
                    TokenKind::RParen,
                    "expected ')' after comparison constraint",
                )?;
                return Ok(if is_leq {
                    ZirConstraint::Leq { lhs, rhs, bits }
                } else {
                    ZirConstraint::Geq { lhs, rhs, bits }
                });
            }
            if name == "memory_read" || name == "memory_write" {
                let is_read = name == "memory_read";
                self.advance();
                self.expect(TokenKind::LParen, "expected '(' after memory constraint")?;
                let memory = self.expect_ident("expected memory name")?;
                self.expect(TokenKind::Comma, "expected ',' after memory name")?;
                let index = self.parse_expr()?;
                self.expect(TokenKind::Comma, "expected ',' after memory index")?;
                let value = self.parse_expr()?;
                self.expect(TokenKind::RParen, "expected ')' after memory constraint")?;
                return Ok(if is_read {
                    ZirConstraint::MemoryRead {
                        memory,
                        index,
                        value,
                    }
                } else {
                    ZirConstraint::MemoryWrite {
                        memory,
                        index,
                        value,
                    }
                });
            }
        }
        let lhs = self.parse_expr()?;
        self.expect(TokenKind::EqEq, "expected '==' in equality constraint")?;
        let rhs = self.parse_expr()?;
        Ok(ZirConstraint::Equal { lhs, rhs })
    }

    fn parse_bracketed_expr_list(&mut self) -> Result<Vec<ZirExpr>, ZirLangError> {
        self.expect(TokenKind::LBracket, "expected '['")?;
        let values = self.parse_comma_exprs_until(TokenKind::RBracket)?;
        self.expect(TokenKind::RBracket, "expected ']'")?;
        Ok(values)
    }

    fn parse_bracketed_ident_list(&mut self) -> Result<Vec<String>, ZirLangError> {
        self.expect(TokenKind::LBracket, "expected '['")?;
        let mut values = Vec::new();
        if !self.check(&TokenKind::RBracket) {
            loop {
                values.push(self.expect_ident("expected identifier")?);
                if self.check(&TokenKind::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
        }
        self.expect(TokenKind::RBracket, "expected ']'")?;
        Ok(values)
    }

    fn parse_comma_exprs_until(&mut self, end: TokenKind) -> Result<Vec<ZirExpr>, ZirLangError> {
        let mut values = Vec::new();
        if !self.check(&end) {
            loop {
                values.push(self.parse_expr()?);
                if self.check(&TokenKind::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
        }
        Ok(values)
    }

    fn parse_expr(&mut self) -> Result<ZirExpr, ZirLangError> {
        self.parse_add_sub()
    }

    fn parse_add_sub(&mut self) -> Result<ZirExpr, ZirLangError> {
        let mut expr = self.parse_mul_div()?;
        loop {
            let op = if self.check(&TokenKind::Plus) {
                ZirBinaryOp::Add
            } else if self.check(&TokenKind::Minus) {
                ZirBinaryOp::Sub
            } else {
                break;
            };
            self.advance();
            let right = self.parse_mul_div()?;
            expr = ZirExpr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_mul_div(&mut self) -> Result<ZirExpr, ZirLangError> {
        let mut expr = self.parse_unary()?;
        loop {
            let op = if self.check(&TokenKind::Star) {
                ZirBinaryOp::Mul
            } else if self.check(&TokenKind::Slash) {
                ZirBinaryOp::Div
            } else {
                break;
            };
            self.advance();
            let right = self.parse_unary()?;
            expr = ZirExpr::Binary {
                op,
                left: Box::new(expr),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<ZirExpr, ZirLangError> {
        if self.check(&TokenKind::Minus) {
            self.advance();
            let rhs = self.parse_primary()?;
            return Ok(ZirExpr::Binary {
                op: ZirBinaryOp::Sub,
                left: Box::new(ZirExpr::Number(0)),
                right: Box::new(rhs),
            });
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<ZirExpr, ZirLangError> {
        let token = self.current().clone();
        match token.kind {
            TokenKind::Number(value) => {
                self.advance();
                Ok(ZirExpr::Number(value))
            }
            TokenKind::Ident(name) => {
                self.advance();
                if self.check(&TokenKind::LParen) {
                    self.advance();
                    let mut args = Vec::new();
                    if !self.check(&TokenKind::RParen) {
                        loop {
                            args.push(self.parse_expr()?);
                            if self.check(&TokenKind::Comma) {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    self.expect(TokenKind::RParen, "expected ')' after call arguments")?;
                    Ok(ZirExpr::Call {
                        function: name,
                        args,
                    })
                } else {
                    Ok(ZirExpr::Var(name))
                }
            }
            TokenKind::LParen => {
                self.advance();
                let expr = self.parse_expr()?;
                self.expect(TokenKind::RParen, "expected ')' after expression")?;
                Ok(expr)
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.expr",
                "expected expression",
                token.span,
            )])),
        }
    }

    fn expect_keyword(&mut self, keyword: &str) -> Result<(), ZirLangError> {
        let token = self.current().clone();
        match token.kind {
            TokenKind::Ident(value) if value == keyword => {
                self.advance();
                Ok(())
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.keyword",
                format!("expected '{keyword}'"),
                token.span,
            )])),
        }
    }

    fn expect_ident(&mut self, message: &str) -> Result<String, ZirLangError> {
        let token = self.current().clone();
        match token.kind {
            TokenKind::Ident(value) => {
                self.advance();
                Ok(value)
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.identifier",
                message,
                token.span,
            )])),
        }
    }

    fn expect_u32(&mut self, message: &str) -> Result<u32, ZirLangError> {
        let token = self.current().clone();
        match token.kind {
            TokenKind::Number(value) if value >= 0 && value <= i64::from(u32::MAX) => {
                self.advance();
                Ok(value as u32)
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.integer",
                message,
                token.span,
            )])),
        }
    }

    fn expect_bool(&mut self, message: &str) -> Result<bool, ZirLangError> {
        let token = self.current().clone();
        match token.kind {
            TokenKind::Ident(value) if value == "true" => {
                self.advance();
                Ok(true)
            }
            TokenKind::Ident(value) if value == "false" => {
                self.advance();
                Ok(false)
            }
            _ => Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.boolean",
                message,
                token.span,
            )])),
        }
    }

    fn expect(&mut self, expected: TokenKind, message: &str) -> Result<(), ZirLangError> {
        let token = self.current().clone();
        if self.check(&expected) {
            self.advance();
            Ok(())
        } else {
            Err(ZirLangError::Diagnostics(vec![diagnostic(
                "zir.syntax.expected",
                message,
                token.span,
            )]))
        }
    }

    fn check(&self, expected: &TokenKind) -> bool {
        std::mem::discriminant(&self.current().kind) == std::mem::discriminant(expected)
    }

    fn at_eof(&self) -> bool {
        self.check(&TokenKind::Eof)
    }

    fn current(&self) -> &Token {
        let index = if self.pos < self.tokens.len() {
            self.pos
        } else {
            self.tokens.len().saturating_sub(1)
        };
        &self.tokens[index]
    }

    fn advance(&mut self) {
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
    }
}

fn unsupported_keyword(value: &str) -> bool {
    matches!(
        value,
        "for"
            | "while"
            | "loop"
            | "fn"
            | "rec"
            | "unsafe"
            | "extern"
            | "async"
            | "await"
            | "match"
            | "return"
    )
}

#[derive(Debug, Clone)]
struct SymbolInfo {
    ty: ZirType,
    visibility: Visibility,
    source: SymbolSource,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SymbolSource {
    Decl,
    Let,
    Const,
    Internal,
}

struct Compiler<'a> {
    circuit: &'a ZirCircuit,
    tier: ZirTier,
    source_digest: ZirSourceDigest,
    symbols: BTreeMap<String, SymbolInfo>,
    constants: BTreeMap<String, FieldElement>,
    assigned_targets: BTreeSet<String>,
    signals: Vec<zir::Signal>,
    constraints: Vec<zir::Constraint>,
    assignments: Vec<zir::WitnessAssignment>,
    hints: Vec<zir::WitnessHint>,
    lookup_tables: Vec<zir::LookupTable>,
    memory_regions: Vec<zir::MemoryRegion>,
    custom_gates: Vec<zir::CustomGateDefinition>,
    proof_obligations: Vec<ZirProofObligation>,
    nonlinear_anchors: BTreeSet<String>,
    generated_counter: usize,
}

impl<'a> Compiler<'a> {
    fn new(circuit: &'a ZirCircuit, tier: ZirTier, source_digest: ZirSourceDigest) -> Self {
        Self {
            circuit,
            tier,
            source_digest,
            symbols: BTreeMap::new(),
            constants: BTreeMap::new(),
            assigned_targets: BTreeSet::new(),
            signals: Vec::new(),
            constraints: Vec::new(),
            assignments: Vec::new(),
            hints: Vec::new(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            proof_obligations: base_proof_obligations(),
            nonlinear_anchors: BTreeSet::new(),
            generated_counter: 0,
        }
    }

    fn compile(&mut self) -> Result<zir::Program, ZirLangError> {
        for item in &self.circuit.items {
            self.compile_item(item)?;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("ir_family".to_string(), "zir-v1".to_string());
        metadata.insert("source_language".to_string(), ZIR_LANGUAGE_NAME.to_string());
        metadata.insert(
            "source_language_version".to_string(),
            ZIR_LANGUAGE_VERSION.to_string(),
        );
        metadata.insert("language_tier".to_string(), self.tier.as_str().to_string());
        metadata.insert(
            "zir_source_sha256".to_string(),
            self.source_digest.hex.clone(),
        );
        metadata.insert("entry".to_string(), self.circuit.name.clone());
        metadata.insert("compiler".to_string(), "zkf-lang".to_string());
        metadata.insert("proof_claims".to_string(), "none".to_string());

        Ok(zir::Program {
            name: self.circuit.name.clone(),
            field: self.circuit.field,
            signals: self.signals.clone(),
            constraints: self.constraints.clone(),
            witness_plan: zir::WitnessPlan {
                assignments: self.assignments.clone(),
                hints: self.hints.clone(),
                acir_program_bytes: None,
            },
            lookup_tables: self.lookup_tables.clone(),
            memory_regions: self.memory_regions.clone(),
            custom_gates: self.custom_gates.clone(),
            metadata,
        })
    }

    fn compile_item(&mut self, item: &ZirItem) -> Result<(), ZirLangError> {
        match item {
            ZirItem::Const { name, ty, value } => {
                let lowered = self.lower_expr(value)?;
                let zir::Expr::Const(constant) = lowered else {
                    return Err(self.error(
                        "zir.const.nonliteral",
                        format!("constant '{name}' must lower to a literal value"),
                    ));
                };
                self.declare_constant(name, ty, constant)
            }
            ZirItem::Decl {
                visibility,
                name,
                ty,
            } => self.declare(name, ty, (*visibility).into(), SymbolSource::Decl),
            ZirItem::Let { name, ty, expr } => {
                self.declare(name, ty, Visibility::Private, SymbolSource::Let)?;
                let lowered = self.lower_expr(expr)?;
                self.assignments.push(zir::WitnessAssignment {
                    target: name.clone(),
                    expr: lowered.clone(),
                });
                self.assigned_targets.insert(name.clone());
                self.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Signal(name.clone()),
                    rhs: lowered,
                    label: Some(format!("let_{name}")),
                });
                Ok(())
            }
            ZirItem::Assign { name, expr } => {
                self.require_symbol(name)?;
                if self.assigned_targets.contains(name) {
                    return Err(self.error(
                        "zir.type.duplicate_assignment",
                        format!("signal '{name}' is assigned more than once"),
                    ));
                }
                let lowered = self.lower_expr(expr)?;
                self.assignments.push(zir::WitnessAssignment {
                    target: name.clone(),
                    expr: lowered.clone(),
                });
                self.assigned_targets.insert(name.clone());
                self.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Signal(name.clone()),
                    rhs: lowered,
                    label: Some(format!("assign_{name}")),
                });
                Ok(())
            }
            ZirItem::Constrain { constraint } => self.compile_constraint(constraint),
            ZirItem::LookupTable {
                name,
                columns,
                values,
            } => self.compile_lookup_table(name, *columns, values),
            ZirItem::Memory {
                name,
                size,
                read_only,
            } => self.compile_memory(name, *size, *read_only),
            ZirItem::BlackBox {
                op,
                inputs,
                outputs,
            } => self.compile_blackbox(*op, inputs, outputs),
            ZirItem::CustomGate {
                gate,
                inputs,
                outputs,
            } => self.compile_custom_gate(gate, inputs, outputs),
            ZirItem::Copy { from, to } => {
                self.require_tier2("copy constraints")?;
                self.require_symbol(from)?;
                self.require_symbol(to)?;
                self.constraints.push(zir::Constraint::Copy {
                    from: from.clone(),
                    to: to.clone(),
                    label: Some(format!("copy_{from}_{to}")),
                });
                Ok(())
            }
            ZirItem::Permutation { left, right } => {
                self.require_tier2("permutation constraints")?;
                self.require_symbol(left)?;
                self.require_symbol(right)?;
                self.constraints.push(zir::Constraint::Permutation {
                    left: left.clone(),
                    right: right.clone(),
                    label: Some(format!("permutation_{left}_{right}")),
                });
                Ok(())
            }
            ZirItem::Expose { name } => self.expose(name),
        }
    }

    fn declare_constant(
        &mut self,
        name: &str,
        ty: &ZirType,
        value: FieldElement,
    ) -> Result<(), ZirLangError> {
        if self.symbols.contains_key(name) || self.constants.contains_key(name) {
            return Err(self.error(
                "zir.type.redeclare",
                format!("constant '{name}' is already declared"),
            ));
        }
        if let ZirType::UInt { bits } = ty {
            self.validate_bits(*bits)?;
        }
        self.constants.insert(name.to_string(), value.clone());
        self.symbols.insert(
            name.to_string(),
            SymbolInfo {
                ty: ty.clone(),
                visibility: Visibility::Constant,
                source: SymbolSource::Const,
            },
        );
        self.signals.push(zir::Signal {
            name: name.to_string(),
            visibility: Visibility::Constant,
            ty: lower_type(ty),
            constant: Some(value),
        });
        Ok(())
    }

    fn declare(
        &mut self,
        name: &str,
        ty: &ZirType,
        visibility: Visibility,
        source: SymbolSource,
    ) -> Result<(), ZirLangError> {
        if self.symbols.contains_key(name) {
            return Err(self.error(
                "zir.type.redeclare",
                format!("signal '{name}' is already declared"),
            ));
        }
        if let ZirType::UInt { bits } = ty {
            self.validate_bits(*bits)?;
        }
        self.validate_type(ty)?;
        self.symbols.insert(
            name.to_string(),
            SymbolInfo {
                ty: ty.clone(),
                visibility: visibility.clone(),
                source,
            },
        );
        self.signals.push(zir::Signal {
            name: name.to_string(),
            visibility,
            ty: lower_type(ty),
            constant: None,
        });
        self.add_type_constraints(name, ty);
        Ok(())
    }

    fn declare_internal(&mut self, name: &str, ty: ZirType) -> Result<(), ZirLangError> {
        self.declare(name, &ty, Visibility::Private, SymbolSource::Internal)
    }

    fn generated_signal(&mut self, prefix: &str) -> String {
        let value = format!("{prefix}_{}", self.generated_counter);
        self.generated_counter += 1;
        value
    }

    fn add_type_constraints(&mut self, name: &str, ty: &ZirType) {
        match ty {
            ZirType::Bool => self.constraints.push(zir::Constraint::Boolean {
                signal: name.to_string(),
                label: Some(format!("bool_{name}")),
            }),
            ZirType::UInt { bits } => self.constraints.push(zir::Constraint::Range {
                signal: name.to_string(),
                bits: *bits,
                label: Some(format!("range_{name}_{bits}")),
            }),
            ZirType::Array { .. } => {}
            ZirType::Field => {}
        }
    }

    fn compile_constraint(&mut self, constraint: &ZirConstraint) -> Result<(), ZirLangError> {
        match constraint {
            ZirConstraint::Equal { lhs, rhs } => {
                let lhs = self.lower_expr(lhs)?;
                let rhs = self.lower_expr(rhs)?;
                self.constraints.push(zir::Constraint::Equal {
                    lhs,
                    rhs,
                    label: Some(format!("constraint_{}", self.constraints.len())),
                });
            }
            ZirConstraint::Range { signal, bits } => {
                self.require_symbol(signal)?;
                self.validate_bits(*bits)?;
                self.constraints.push(zir::Constraint::Range {
                    signal: signal.clone(),
                    bits: *bits,
                    label: Some(format!("range_{signal}_{bits}_explicit")),
                });
            }
            ZirConstraint::Boolean { signal } => {
                self.require_symbol(signal)?;
                self.constraints.push(zir::Constraint::Boolean {
                    signal: signal.clone(),
                    label: Some(format!("boolean_{signal}_explicit")),
                });
            }
            ZirConstraint::Lookup { inputs, table } => {
                self.require_tier2("lookup constraints")?;
                if !self
                    .lookup_tables
                    .iter()
                    .any(|candidate| candidate.name == *table)
                {
                    return Err(self.error(
                        "zir.type.unknown_lookup_table",
                        format!("unknown lookup table '{table}'"),
                    ));
                }
                let inputs = inputs
                    .iter()
                    .map(|expr| self.lower_expr(expr))
                    .collect::<Result<Vec<_>, _>>()?;
                self.constraints.push(zir::Constraint::Lookup {
                    inputs,
                    table: table.clone(),
                    label: Some(format!("lookup_{table}_{}", self.constraints.len())),
                });
            }
            ZirConstraint::Nonzero { signal } => {
                self.require_symbol(signal)?;
                let inv = self.generated_signal("__zir_nonzero_inv");
                self.declare_internal(&inv, ZirType::Field)?;
                self.hints.push(zir::WitnessHint {
                    target: inv.clone(),
                    source: signal.clone(),
                    kind: zir::WitnessHintKind::InverseOrZero,
                });
                self.constraints.push(zir::Constraint::Equal {
                    lhs: zir::Expr::Mul(
                        Box::new(zir::Expr::Signal(signal.clone())),
                        Box::new(zir::Expr::Signal(inv.clone())),
                    ),
                    rhs: zir::Expr::Const(FieldElement::ONE),
                    label: Some(format!("nonzero_{signal}")),
                });
            }
            ZirConstraint::Leq { lhs, rhs, bits } => {
                self.compile_bounded_comparison(lhs, rhs, *bits, true)?;
            }
            ZirConstraint::Geq { lhs, rhs, bits } => {
                self.compile_bounded_comparison(lhs, rhs, *bits, false)?;
            }
            ZirConstraint::MemoryRead {
                memory,
                index,
                value,
            } => {
                self.require_tier2("memory reads")?;
                self.require_memory(memory)?;
                let index = self.lower_expr(index)?;
                let value = self.lower_expr(value)?;
                self.constraints.push(zir::Constraint::MemoryRead {
                    memory: memory.clone(),
                    index,
                    value,
                    label: Some(format!("memory_read_{memory}_{}", self.constraints.len())),
                });
            }
            ZirConstraint::MemoryWrite {
                memory,
                index,
                value,
            } => {
                self.require_tier2("memory writes")?;
                let region = self.require_memory(memory)?;
                if region.read_only {
                    return Err(self.error(
                        "zir.memory.read_only",
                        format!("cannot write to read-only memory '{memory}'"),
                    ));
                }
                let index = self.lower_expr(index)?;
                let value = self.lower_expr(value)?;
                self.constraints.push(zir::Constraint::MemoryWrite {
                    memory: memory.clone(),
                    index,
                    value,
                    label: Some(format!("memory_write_{memory}_{}", self.constraints.len())),
                });
            }
        }
        Ok(())
    }

    fn compile_bounded_comparison(
        &mut self,
        lhs: &ZirExpr,
        rhs: &ZirExpr,
        bits: u32,
        leq: bool,
    ) -> Result<(), ZirLangError> {
        self.validate_bits(bits)?;
        let slack = self.generated_signal(if leq {
            "__zir_leq_slack"
        } else {
            "__zir_geq_slack"
        });
        self.declare_internal(&slack, ZirType::UInt { bits })?;
        let lhs = self.lower_expr(lhs)?;
        let rhs = self.lower_expr(rhs)?;
        let slack_expr = if leq {
            zir::Expr::Sub(Box::new(rhs.clone()), Box::new(lhs.clone()))
        } else {
            zir::Expr::Sub(Box::new(lhs.clone()), Box::new(rhs.clone()))
        };
        self.assignments.push(zir::WitnessAssignment {
            target: slack.clone(),
            expr: slack_expr,
        });
        self.assigned_targets.insert(slack.clone());
        let (left, right, label) = if leq {
            (
                zir::Expr::Add(vec![lhs.clone(), zir::Expr::Signal(slack.clone())]),
                rhs.clone(),
                format!("leq_{slack}"),
            )
        } else {
            (
                zir::Expr::Add(vec![rhs.clone(), zir::Expr::Signal(slack.clone())]),
                lhs.clone(),
                format!("geq_{slack}"),
            )
        };
        self.constraints.push(zir::Constraint::Equal {
            lhs: left,
            rhs: right,
            label: Some(label),
        });
        self.anchor_private_expr_signals(&lhs)?;
        self.anchor_private_expr_signals(&rhs)?;
        self.anchor_private_signal_nonlinear(&slack)?;
        Ok(())
    }

    fn anchor_private_expr_signals(&mut self, expr: &zir::Expr) -> Result<(), ZirLangError> {
        let mut names = BTreeSet::new();
        collect_zir_signal_names(expr, &mut names);
        for name in names {
            self.anchor_private_signal_nonlinear(&name)?;
        }
        Ok(())
    }

    fn anchor_private_signal_nonlinear(&mut self, signal: &str) -> Result<(), ZirLangError> {
        let Some(visibility) = self.symbols.get(signal).map(|info| info.visibility.clone()) else {
            return Ok(());
        };
        if visibility != Visibility::Private || !self.nonlinear_anchors.insert(signal.to_string()) {
            return Ok(());
        }
        let anchor = self.generated_signal("__zir_nonlinear_anchor");
        self.declare_internal(&anchor, ZirType::Field)?;
        let square = zir::Expr::Mul(
            Box::new(zir::Expr::Signal(signal.to_string())),
            Box::new(zir::Expr::Signal(signal.to_string())),
        );
        self.assignments.push(zir::WitnessAssignment {
            target: anchor.clone(),
            expr: square.clone(),
        });
        self.assigned_targets.insert(anchor.clone());
        self.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Signal(anchor),
            rhs: square,
            label: Some(format!("nonlinear_anchor_{signal}")),
        });
        Ok(())
    }

    fn compile_lookup_table(
        &mut self,
        name: &str,
        columns: usize,
        values: &[Vec<ZirExpr>],
    ) -> Result<(), ZirLangError> {
        self.require_tier2("lookup tables")?;
        if columns == 0 {
            return Err(self.error(
                "zir.lookup.columns",
                "lookup table needs at least one column",
            ));
        }
        let mut rows = Vec::new();
        for row in values {
            if row.len() != columns {
                return Err(self.error(
                    "zir.lookup.row_width",
                    format!(
                        "lookup table '{name}' expected {columns} column(s), found {}",
                        row.len()
                    ),
                ));
            }
            let mut out = Vec::new();
            for expr in row {
                let lowered = self.lower_expr(expr)?;
                let zir::Expr::Const(value) = lowered else {
                    return Err(self.error(
                        "zir.lookup.nonconstant",
                        format!("lookup table '{name}' rows must be constant values"),
                    ));
                };
                out.push(value);
            }
            rows.push(out);
        }
        self.lookup_tables.push(zir::LookupTable {
            name: name.to_string(),
            columns,
            values: rows,
        });
        self.add_feature_obligation("zir.tier2.lookup", "lookup constraints require backend support or verified lowering before proof generation");
        Ok(())
    }

    fn compile_memory(
        &mut self,
        name: &str,
        size: u32,
        read_only: bool,
    ) -> Result<(), ZirLangError> {
        self.require_tier2("memory regions")?;
        if size == 0 {
            return Err(self.error("zir.memory.size", "memory region size must be nonzero"));
        }
        self.memory_regions.push(zir::MemoryRegion {
            name: name.to_string(),
            size,
            read_only,
        });
        self.add_feature_obligation("zir.tier2.memory", "memory constraints are preserved in ZIR v1 and must fail closed when forced into unsupported IR/backend paths");
        Ok(())
    }

    fn compile_blackbox(
        &mut self,
        op: ZirBlackBoxOp,
        inputs: &[ZirExpr],
        outputs: &[String],
    ) -> Result<(), ZirLangError> {
        self.require_tier2("blackbox constraints")?;
        for output in outputs {
            self.require_symbol(output)?;
        }
        let inputs = inputs
            .iter()
            .map(|expr| self.lower_expr(expr))
            .collect::<Result<Vec<_>, _>>()?;
        self.constraints.push(zir::Constraint::BlackBox {
            op: op.into(),
            inputs,
            outputs: outputs.to_vec(),
            params: BTreeMap::new(),
            label: Some(format!(
                "blackbox_{}_{}",
                op.as_str(),
                self.constraints.len()
            )),
        });
        self.add_feature_obligation("zir.tier2.blackbox", "trusted primitive libraries and backend-specific blackbox lowerings must retain their explicit assurance class");
        Ok(())
    }

    fn compile_custom_gate(
        &mut self,
        gate: &str,
        inputs: &[ZirExpr],
        outputs: &[String],
    ) -> Result<(), ZirLangError> {
        self.require_tier2("custom gates")?;
        for output in outputs {
            self.require_symbol(output)?;
        }
        let inputs = inputs
            .iter()
            .map(|expr| self.lower_expr(expr))
            .collect::<Result<Vec<_>, _>>()?;
        self.custom_gates.push(zir::CustomGateDefinition {
            name: gate.to_string(),
            input_count: inputs.len(),
            output_count: outputs.len(),
            constraint_expr: None,
        });
        self.constraints.push(zir::Constraint::CustomGate {
            gate: gate.to_string(),
            inputs,
            outputs: outputs.to_vec(),
            params: BTreeMap::new(),
            label: Some(format!("custom_gate_{gate}_{}", self.constraints.len())),
        });
        self.add_feature_obligation(
            "zir.tier2.custom_gate",
            "custom gates are preserved in ZIR v1 and must not be flattened silently into IR v2",
        );
        Ok(())
    }

    fn expose(&mut self, name: &str) -> Result<(), ZirLangError> {
        let symbol = self.require_symbol(name)?.clone();
        if symbol.visibility == Visibility::Public {
            return Ok(());
        }
        if symbol.source == SymbolSource::Decl && !self.assigned_targets.contains(name) {
            return Err(self.error(
                "zir.privacy.expose_private_input",
                format!(
                    "cannot expose private input '{name}'; declare a public output and assign it explicitly"
                ),
            ));
        }
        if let Some(signal) = self.signals.iter_mut().find(|signal| signal.name == name) {
            signal.visibility = Visibility::Public;
        }
        if let Some(symbol) = self.symbols.get_mut(name) {
            symbol.visibility = Visibility::Public;
        }
        Ok(())
    }

    fn lower_expr(&mut self, expr: &ZirExpr) -> Result<zir::Expr, ZirLangError> {
        match expr {
            ZirExpr::Number(value) => Ok(zir::Expr::Const(FieldElement::from_i64(*value))),
            ZirExpr::Var(name) => {
                if let Some(value) = self.constants.get(name) {
                    return Ok(zir::Expr::Const(value.clone()));
                }
                self.require_symbol(name)?;
                Ok(zir::Expr::Signal(name.clone()))
            }
            ZirExpr::Binary { op, left, right } => {
                let left = self.lower_expr(left)?;
                let right = self.lower_expr(right)?;
                Ok(match op {
                    ZirBinaryOp::Add => zir::Expr::Add(vec![left, right]),
                    ZirBinaryOp::Sub => zir::Expr::Sub(Box::new(left), Box::new(right)),
                    ZirBinaryOp::Mul => zir::Expr::Mul(Box::new(left), Box::new(right)),
                    ZirBinaryOp::Div => zir::Expr::Div(Box::new(left), Box::new(right)),
                })
            }
            ZirExpr::Call { function, args } => self.lower_call(function, args),
        }
    }

    fn lower_call(&mut self, function: &str, args: &[ZirExpr]) -> Result<zir::Expr, ZirLangError> {
        match function {
            "add" | "sub" | "mul" | "div" if args.len() == 2 => {
                let left = self.lower_expr(&args[0])?;
                let right = self.lower_expr(&args[1])?;
                Ok(match function {
                    "add" => zir::Expr::Add(vec![left, right]),
                    "sub" => zir::Expr::Sub(Box::new(left), Box::new(right)),
                    "mul" => zir::Expr::Mul(Box::new(left), Box::new(right)),
                    "div" => zir::Expr::Div(Box::new(left), Box::new(right)),
                    _ => return Err(self.error("zir.internal", "unreachable call lowering arm")),
                })
            }
            "select" if args.len() == 3 => {
                if let ZirExpr::Var(cond_signal) = &args[0] {
                    let cond_info = self.require_symbol(cond_signal)?;
                    if cond_info.ty != ZirType::Bool {
                        return Err(self.error(
                            "zir.type.select_condition",
                            format!("select condition '{cond_signal}' must have bool type"),
                        ));
                    }
                    self.constraints.push(zir::Constraint::Boolean {
                        signal: cond_signal.clone(),
                        label: Some(format!("select_condition_{cond_signal}")),
                    });
                } else {
                    return Err(self.error(
                        "zir.unsupported.select_condition",
                        "select condition must be a named bool signal",
                    ));
                }
                let cond = self.lower_expr(&args[0])?;
                let if_true = self.lower_expr(&args[1])?;
                let if_false = self.lower_expr(&args[2])?;
                Ok(zir::Expr::Add(vec![
                    if_false.clone(),
                    zir::Expr::Mul(
                        Box::new(cond),
                        Box::new(zir::Expr::Sub(Box::new(if_true), Box::new(if_false))),
                    ),
                ]))
            }
            "range" | "boolean" => Err(self.error(
                "zir.syntax.constraint_call",
                format!("'{function}' is a constraint form; use `constrain {function}(...)`"),
            )),
            _ => Err(self.error(
                "zir.unsupported.call",
                format!(
                    "unsupported call '{function}'; Tier 1 supports add/sub/mul/div and select"
                ),
            )),
        }
    }

    fn require_tier2(&self, feature: &str) -> Result<(), ZirLangError> {
        if self.tier.allows_tier2() {
            Ok(())
        } else {
            Err(self.error(
                "zir.tier2.required",
                format!("{feature} require Zir Tier 2"),
            ))
        }
    }

    fn require_memory(&self, name: &str) -> Result<&zir::MemoryRegion, ZirLangError> {
        self.memory_regions
            .iter()
            .find(|region| region.name == name)
            .ok_or_else(|| {
                self.error(
                    "zir.memory.unknown",
                    format!("unknown memory region '{name}'"),
                )
            })
    }

    fn add_feature_obligation(&mut self, id: &str, statement: &str) {
        if self
            .proof_obligations
            .iter()
            .any(|obligation| obligation.id == id)
        {
            return;
        }
        self.proof_obligations.push(ZirProofObligation {
            id: id.to_string(),
            category: "tier2_backend_compatibility".to_string(),
            required_assurance: "explicit_compatibility_check".to_string(),
            statement: statement.to_string(),
        });
    }

    fn validate_type(&self, ty: &ZirType) -> Result<(), ZirLangError> {
        match ty {
            ZirType::UInt { bits } => self.validate_bits(*bits),
            ZirType::Array { element, len } => {
                if *len == 0 {
                    return Err(self.error("zir.type.array_len", "array length must be nonzero"));
                }
                self.validate_type(element)
            }
            ZirType::Field | ZirType::Bool => Ok(()),
        }
    }

    fn validate_bits(&self, bits: u32) -> Result<(), ZirLangError> {
        if bits == 0 || bits > 256 {
            return Err(self.error(
                "zir.type.range_bits",
                format!("range bit width must be between 1 and 256, found {bits}"),
            ));
        }
        Ok(())
    }

    fn require_symbol(&self, name: &str) -> Result<&SymbolInfo, ZirLangError> {
        self.symbols.get(name).ok_or_else(|| {
            self.error(
                "zir.type.unknown_signal",
                format!("unknown signal '{name}'"),
            )
        })
    }

    fn error(&self, code: &str, message: impl Into<String>) -> ZirLangError {
        ZirLangError::Diagnostics(vec![diagnostic(code, message, Span { line: 1, column: 1 })])
    }
}

fn lower_type(ty: &ZirType) -> zir::SignalType {
    match ty {
        ZirType::Field => zir::SignalType::Field,
        ZirType::Bool => zir::SignalType::Bool,
        ZirType::UInt { bits } => zir::SignalType::UInt { bits: *bits },
        ZirType::Array { element, len } => zir::SignalType::Array {
            element: Box::new(lower_type(element)),
            len: *len,
        },
    }
}

fn format_program(program: &ZirSourceProgram) -> String {
    let mut out = String::new();
    for (index, circuit) in program.circuits.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "circuit {}(field: {}, tier: {}) {{\n",
            circuit.name,
            circuit.field,
            match circuit.tier {
                ZirTier::Tier1 => 1,
                ZirTier::Tier2 => 2,
            }
        ));
        for item in &circuit.items {
            out.push_str("  ");
            out.push_str(&format_item(item));
            out.push('\n');
        }
        out.push_str("}\n");
    }
    out
}

fn format_item(item: &ZirItem) -> String {
    match item {
        ZirItem::Const { name, ty, value } => {
            format!(
                "const {name}: {} = {};",
                format_type(ty),
                format_expr(value)
            )
        }
        ZirItem::Decl {
            visibility,
            name,
            ty,
        } => format!(
            "{} {}: {};",
            format_visibility(*visibility),
            name,
            format_type(ty)
        ),
        ZirItem::Let { name, ty, expr } => {
            format!("let {name}: {} = {};", format_type(ty), format_expr(expr))
        }
        ZirItem::Assign { name, expr } => format!("{name} = {};", format_expr(expr)),
        ZirItem::Constrain { constraint } => {
            format!("constrain {};", format_constraint(constraint))
        }
        ZirItem::LookupTable {
            name,
            columns,
            values,
        } => {
            let rows = values
                .iter()
                .map(|row| {
                    format!(
                        "[{}]",
                        row.iter().map(format_expr).collect::<Vec<_>>().join(", ")
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("lookup table {name}(columns: {columns}) {{ {rows} }}")
        }
        ZirItem::Memory {
            name,
            size,
            read_only,
        } => format!("memory {name}(size: {size}, read_only: {read_only});"),
        ZirItem::BlackBox {
            op,
            inputs,
            outputs,
        } => format!(
            "blackbox {}([{}]) -> [{}];",
            op.as_str(),
            inputs
                .iter()
                .map(format_expr)
                .collect::<Vec<_>>()
                .join(", "),
            outputs.join(", ")
        ),
        ZirItem::CustomGate {
            gate,
            inputs,
            outputs,
        } => format!(
            "custom_gate {gate}({}) -> [{}];",
            inputs
                .iter()
                .map(format_expr)
                .collect::<Vec<_>>()
                .join(", "),
            outputs.join(", ")
        ),
        ZirItem::Copy { from, to } => format!("copy {from} -> {to};"),
        ZirItem::Permutation { left, right } => format!("permutation({left}, {right});"),
        ZirItem::Expose { name } => format!("expose {name};"),
    }
}

fn format_visibility(visibility: ZirVisibility) -> &'static str {
    match visibility {
        ZirVisibility::Public => "public",
        ZirVisibility::Private => "private",
    }
}

fn format_type(ty: &ZirType) -> String {
    match ty {
        ZirType::Field => "field".to_string(),
        ZirType::Bool => "bool".to_string(),
        ZirType::UInt { bits } => match *bits {
            8 => "u8".to_string(),
            16 => "u16".to_string(),
            32 => "u32".to_string(),
            64 => "u64".to_string(),
            other => format!("u64<{other}>"),
        },
        ZirType::Array { element, len } => format!("{}[{len}]", format_type(element)),
    }
}

fn format_constraint(constraint: &ZirConstraint) -> String {
    match constraint {
        ZirConstraint::Equal { lhs, rhs } => {
            format!("{} == {}", format_expr(lhs), format_expr(rhs))
        }
        ZirConstraint::Range { signal, bits } => format!("range({signal}, {bits})"),
        ZirConstraint::Boolean { signal } => format!("boolean({signal})"),
        ZirConstraint::Lookup { inputs, table } => format!(
            "lookup([{}], {table})",
            inputs
                .iter()
                .map(format_expr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ZirConstraint::Nonzero { signal } => format!("nonzero({signal})"),
        ZirConstraint::Leq { lhs, rhs, bits } => {
            format!("leq({}, {}, {bits})", format_expr(lhs), format_expr(rhs))
        }
        ZirConstraint::Geq { lhs, rhs, bits } => {
            format!("geq({}, {}, {bits})", format_expr(lhs), format_expr(rhs))
        }
        ZirConstraint::MemoryRead {
            memory,
            index,
            value,
        } => format!(
            "memory_read({memory}, {}, {})",
            format_expr(index),
            format_expr(value)
        ),
        ZirConstraint::MemoryWrite {
            memory,
            index,
            value,
        } => format!(
            "memory_write({memory}, {}, {})",
            format_expr(index),
            format_expr(value)
        ),
    }
}

fn format_expr(expr: &ZirExpr) -> String {
    match expr {
        ZirExpr::Number(value) => value.to_string(),
        ZirExpr::Var(name) => name.clone(),
        ZirExpr::Binary { op, left, right } => {
            format!(
                "({} {} {})",
                format_expr(left),
                format_op(*op),
                format_expr(right)
            )
        }
        ZirExpr::Call { function, args } => {
            let args = args.iter().map(format_expr).collect::<Vec<_>>().join(", ");
            format!("{function}({args})")
        }
    }
}

fn format_op(op: ZirBinaryOp) -> &'static str {
    match op {
        ZirBinaryOp::Add => "+",
        ZirBinaryOp::Sub => "-",
        ZirBinaryOp::Mul => "*",
        ZirBinaryOp::Div => "/",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_SOURCE: &str = r#"
        circuit invoice_core(field: bn254) {
          private amount: u64<32>;
          private blind: field;
          public approved: field;

          let padded: field = amount + blind;
          approved = padded;
          constrain range(amount, 32);
          constrain approved == padded;
          expose approved;
        }
    "#;

    #[test]
    fn checks_and_lowers_basic_circuit_to_zir_and_ir_v2() -> Result<(), ZirLangError> {
        let report = check_source(BASIC_SOURCE);
        assert!(report.ok, "diagnostics: {:?}", report.diagnostics);
        assert_eq!(report.entry.as_deref(), Some("invoice_core"));
        assert!(report.public_signals.iter().any(|name| name == "approved"));
        assert!(report.private_signals.iter().any(|name| name == "amount"));

        let output = compile_source_to_zir(BASIC_SOURCE)?;
        assert_eq!(
            output
                .zir
                .metadata
                .get("source_language")
                .map(String::as_str),
            Some("zir")
        );
        assert!(output.zir.constraints.len() >= 4);

        let lowered = lower_source_to_ir_v2(BASIC_SOURCE);
        assert!(
            lowered.is_ok(),
            "IR v2 lowering failed: {:?}",
            lowered.err()
        );
        Ok(())
    }

    #[test]
    fn unsupported_control_flow_fails_closed() {
        let source = r#"
            circuit bad(field: bn254) {
              private x: field;
              while x {
              }
            }
        "#;
        let report = check_source(source);
        assert!(!report.ok);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "zir.unsupported.control_flow")
        );
    }

    #[test]
    fn select_lowers_to_arithmetic_mux() -> Result<(), ZirLangError> {
        let source = r#"
            circuit mux(field: bn254) {
              private cond: bool;
              private a: field;
              private b: field;
              public out: field;

              out = select(cond, a, b);
              expose out;
            }
        "#;
        let output = compile_source_to_zir(source)?;
        assert!(output
            .zir
            .constraints
            .iter()
            .any(|constraint| matches!(constraint, zir::Constraint::Boolean { signal, .. } if signal == "cond")));
        assert_eq!(output.zir.witness_plan.assignments.len(), 1);
        Ok(())
    }

    #[test]
    fn formatter_round_trips_parseable_source() -> Result<(), ZirLangError> {
        let formatted = format_source(BASIC_SOURCE)?;
        let report = check_source(&formatted);
        assert!(
            report.ok,
            "formatted source diagnostics: {:?}",
            report.diagnostics
        );
        Ok(())
    }

    #[test]
    fn tier2_lookup_blackbox_and_nonzero_lower_to_zir() -> Result<(), ZirLangError> {
        let source = r#"
            circuit settlement(field: bn254, tier: 2) {
              lookup table risk_table(columns: 2) {
                [0, 0],
                [1, 1],
              }
              private amount: u64<32>;
              private risk: field;
              public digest: field;
              blackbox poseidon([amount, risk]) -> [digest];
              constrain lookup([risk, 1], risk_table);
              constrain nonzero(amount);
              expose digest;
            }
        "#;
        let output = compile_source_with_options(
            source,
            &ZirCompileOptions {
                allow_tier2: true,
                ..ZirCompileOptions::default()
            },
        )?;
        assert_eq!(output.zir.lookup_tables.len(), 1);
        assert!(
            output
                .zir
                .constraints
                .iter()
                .any(|constraint| matches!(constraint, zir::Constraint::BlackBox { .. }))
        );
        assert!(
            output
                .zir
                .witness_plan
                .hints
                .iter()
                .any(|hint| hint.kind == zir::WitnessHintKind::InverseOrZero)
        );
        Ok(())
    }

    #[test]
    fn tier2_feature_fails_in_tier1() {
        let source = r#"
            circuit bad(field: bn254) {
              private x: field;
              public y: field;
              blackbox poseidon([x]) -> [y];
            }
        "#;
        let report = check_source(source);
        assert!(!report.ok);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "zir.tier2.required")
        );
    }

    #[test]
    fn zirflow_plans_approval_required_steps() -> Result<(), ZirLangError> {
        let flow = r#"
            workflow trade {
              source "./program.zir" as settlement;
              check settlement tier tier2;
              lower settlement to zir-v1 out "./build/program.json";
              package settlement out "./build/package";
            }
        "#;
        let plan = plan_flow_source(flow)?;
        assert_eq!(plan.workflow, "trade");
        assert!(plan.approved_required);
        assert_eq!(plan.steps.len(), 4);
        Ok(())
    }
}
