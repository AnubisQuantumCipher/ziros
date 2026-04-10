use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use zkf_core::zir_v1 as zir;
use zkf_core::{FieldElement, FieldId, Program, Visibility};

pub const ZIR_LANGUAGE_NAME: &str = "zir";
pub const ZIR_LANGUAGE_VERSION: &str = "zir-src-v0";
pub const ZIR_LANGUAGE_TIER: &str = "tier1-total-circuit-subset";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirSourceProgram {
    pub circuits: Vec<ZirCircuit>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZirCircuit {
    pub name: String,
    pub field: FieldId,
    pub items: Vec<ZirItem>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirItem {
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
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZirConstraint {
    Equal { lhs: ZirExpr, rhs: ZirExpr },
    Range { signal: String, bits: u32 },
    Boolean { signal: String },
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
    match compile_source_to_zir(source) {
        Ok(output) => {
            let (public_signals, private_signals) = signal_names_by_visibility(&output.zir);
            ZirCheckReport {
                ok: true,
                language: ZIR_LANGUAGE_NAME.to_string(),
                language_version: ZIR_LANGUAGE_VERSION.to_string(),
                language_tier: ZIR_LANGUAGE_TIER.to_string(),
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
    let parsed = parse_source(source)?;
    let circuit = parsed.circuits.first().ok_or_else(|| {
        ZirLangError::Diagnostics(vec![diagnostic(
            "zir.syntax.empty",
            "expected at least one circuit declaration",
            Span::start(),
        )])
    })?;

    if parsed.circuits.len() != 1 {
        return Err(ZirLangError::Diagnostics(vec![diagnostic(
            "zir.unsupported.multicircuit",
            "this first language slice supports exactly one circuit per source file",
            Span::start(),
        )]));
    }

    let mut compiler = Compiler::new(circuit);
    let zir = compiler.compile()?;
    let (public_signals, private_signals) = signal_names_by_visibility(&zir);
    let report = ZirCompileReport {
        language: ZIR_LANGUAGE_NAME.to_string(),
        language_version: ZIR_LANGUAGE_VERSION.to_string(),
        language_tier: ZIR_LANGUAGE_TIER.to_string(),
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
            "This is a bounded Tier 1 source-language frontend; it does not claim mechanized compiler correctness by itself.".to_string(),
            "Unsupported source constructs fail closed before ZIR/IR emission.".to_string(),
        ],
    };

    Ok(ZirCompileOutput {
        source: parsed,
        zir,
        report,
    })
}

pub fn lower_source_to_ir_v2(source: &str) -> Result<(Program, ZirCompileReport), ZirLangError> {
    let output = compile_source_to_zir(source)?;
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
    Colon,
    Semi,
    Comma,
    Less,
    Greater,
    Plus,
    Minus,
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
                    TokenKind::Minus
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
        self.expect(TokenKind::RParen, "expected ')' after field id")?;
        self.expect(TokenKind::LBrace, "expected '{' before circuit body")?;

        let mut items = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.at_eof() {
            items.push(self.parse_item()?);
        }
        self.expect(TokenKind::RBrace, "expected '}' after circuit body")?;
        Ok(ZirCircuit { name, field, items })
    }

    fn parse_item(&mut self) -> Result<ZirItem, ZirLangError> {
        let token = self.current().clone();
        match &token.kind {
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
        match name.as_str() {
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
        }
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
        }
        let lhs = self.parse_expr()?;
        self.expect(TokenKind::EqEq, "expected '==' in equality constraint")?;
        let rhs = self.parse_expr()?;
        Ok(ZirConstraint::Equal { lhs, rhs })
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
}

struct Compiler<'a> {
    circuit: &'a ZirCircuit,
    symbols: BTreeMap<String, SymbolInfo>,
    assigned_targets: BTreeSet<String>,
    signals: Vec<zir::Signal>,
    constraints: Vec<zir::Constraint>,
    assignments: Vec<zir::WitnessAssignment>,
    proof_obligations: Vec<ZirProofObligation>,
}

impl<'a> Compiler<'a> {
    fn new(circuit: &'a ZirCircuit) -> Self {
        Self {
            circuit,
            symbols: BTreeMap::new(),
            assigned_targets: BTreeSet::new(),
            signals: Vec::new(),
            constraints: Vec::new(),
            assignments: Vec::new(),
            proof_obligations: base_proof_obligations(),
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
        metadata.insert("language_tier".to_string(), ZIR_LANGUAGE_TIER.to_string());
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
                hints: Vec::new(),
                acir_program_bytes: None,
            },
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata,
        })
    }

    fn compile_item(&mut self, item: &ZirItem) -> Result<(), ZirLangError> {
        match item {
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
            ZirItem::Expose { name } => self.expose(name),
        }
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
        }
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
    }
}

fn format_program(program: &ZirSourceProgram) -> String {
    let mut out = String::new();
    for (index, circuit) in program.circuits.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "circuit {}(field: {}) {{\n",
            circuit.name, circuit.field
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
    }
}

fn format_constraint(constraint: &ZirConstraint) -> String {
    match constraint {
        ZirConstraint::Equal { lhs, rhs } => {
            format!("{} == {}", format_expr(lhs), format_expr(rhs))
        }
        ZirConstraint::Range { signal, bits } => format!("range({signal}, {bits})"),
        ZirConstraint::Boolean { signal } => format!("boolean({signal})"),
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
}
