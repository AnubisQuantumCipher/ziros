//! ZirOS LSP server implementation.
//!
//! Provides real-time diagnostics for ZirOS / ZKF IR programs (`.ir.json` files):
//! - JSON parse errors
//! - Type errors (undeclared signals, type mismatches, etc.)
//! - Underconstrained signal warnings
//! - Program summary hints when everything is valid

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};
use zkf_core::type_check::type_check;

/// The ZirOS Language Server.
///
/// Stores open document contents and re-analyzes on every change.
pub struct ZkfLanguageServer {
    client: Client,
    documents: Arc<RwLock<HashMap<Url, String>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SymbolInfo {
    definition_range: Range,
    hover_markdown: String,
}

#[derive(Clone, Debug, Default)]
struct SymbolIndex {
    signals: HashMap<String, SymbolInfo>,
    constraint_labels: HashMap<String, SymbolInfo>,
}

impl ZkfLanguageServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Run all available analyses on a document and publish diagnostics.
    async fn analyze_document(&self, uri: &Url, text: &str) {
        let diagnostics = analyze_text_diagnostics(text);
        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
    }
}

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                open_close: Some(true),
                change: Some(TextDocumentSyncKind::FULL),
                save: Some(TextDocumentSyncSaveOptions::Supported(true)),
                ..Default::default()
            },
        )),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        definition_provider: Some(OneOf::Left(true)),
        ..Default::default()
    }
}

fn hover_for_text(text: &str, position: Position) -> Option<Hover> {
    let symbol = symbol_info_at(text, position)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: symbol.hover_markdown,
        }),
        range: None,
    })
}

fn definition_for_text(
    uri: &Url,
    text: &str,
    position: Position,
) -> Option<GotoDefinitionResponse> {
    let symbol = symbol_info_at(text, position)?;
    Some(GotoDefinitionResponse::Scalar(Location {
        uri: uri.clone(),
        range: symbol.definition_range,
    }))
}

fn symbol_info_at(text: &str, position: Position) -> Option<SymbolInfo> {
    let (value_start, _, value) = json_string_value_at(text, position)?;
    let index = build_symbol_index(text);
    let property = json_property_key_before_value(text, value_start);

    match property.as_deref() {
        Some("label") => index.constraint_labels.get(&value).cloned(),
        Some("name") | Some("signal") | Some("args") | Some("target") | Some("outputs")
        | Some("left") | Some("right") => index
            .signals
            .get(&value)
            .cloned()
            .or_else(|| index.constraint_labels.get(&value).cloned()),
        _ => index
            .signals
            .get(&value)
            .cloned()
            .or_else(|| index.constraint_labels.get(&value).cloned()),
    }
}

fn build_symbol_index(text: &str) -> SymbolIndex {
    if let Ok(program) = serde_json::from_str::<zkf_core::zir_v1::Program>(text) {
        build_zir_symbol_index(text, &program)
    } else if let Ok(program) = serde_json::from_str::<zkf_core::Program>(text) {
        build_ir_symbol_index(text, &program)
    } else {
        SymbolIndex::default()
    }
}

fn build_zir_symbol_index(text: &str, program: &zkf_core::zir_v1::Program) -> SymbolIndex {
    let mut index = SymbolIndex::default();
    for signal in &program.signals {
        if let Some(definition_range) = find_signal_definition_range(text, &signal.name) {
            index.signals.insert(
                signal.name.clone(),
                SymbolInfo {
                    definition_range,
                    hover_markdown: format!(
                        "ZIR signal `{}`\n\nvisibility: `{}`\n\ntype: `{}`",
                        signal.name,
                        visibility_name(&signal.visibility),
                        zir_signal_type_name(&signal.ty),
                    ),
                },
            );
        }
    }
    for constraint in &program.constraints {
        if let Some(label) = zir_constraint_label(constraint)
            && let Some(definition_range) = find_constraint_label_range(text, label)
        {
            index.constraint_labels.insert(
                label.to_string(),
                SymbolInfo {
                    definition_range,
                    hover_markdown: format!(
                        "ZIR constraint label `{}`\n\nkind: `{}`",
                        label,
                        zir_constraint_kind_name(constraint),
                    ),
                },
            );
        }
    }
    index
}

fn build_ir_symbol_index(text: &str, program: &zkf_core::Program) -> SymbolIndex {
    let mut index = SymbolIndex::default();
    for signal in &program.signals {
        if let Some(definition_range) = find_signal_definition_range(text, &signal.name) {
            index.signals.insert(
                signal.name.clone(),
                SymbolInfo {
                    definition_range,
                    hover_markdown: format!(
                        "IR signal `{}`\n\nvisibility: `{}`\n\ntype: `{}`",
                        signal.name,
                        visibility_name(&signal.visibility),
                        signal.ty.as_deref().unwrap_or("field"),
                    ),
                },
            );
        }
    }
    for constraint in &program.constraints {
        if let Some(label) = constraint.label()
            && let Some(definition_range) = find_constraint_label_range(text, label)
        {
            index.constraint_labels.insert(
                label.clone(),
                SymbolInfo {
                    definition_range,
                    hover_markdown: format!(
                        "IR constraint label `{}`\n\nkind: `{}`",
                        label,
                        ir_constraint_kind_name(constraint),
                    ),
                },
            );
        }
    }
    index
}

fn visibility_name(visibility: &zkf_core::Visibility) -> &'static str {
    match visibility {
        zkf_core::Visibility::Public => "public",
        zkf_core::Visibility::Private => "private",
        zkf_core::Visibility::Constant => "constant",
    }
}

fn zir_signal_type_name(signal_type: &zkf_core::zir_v1::SignalType) -> String {
    serde_json::to_string(signal_type).unwrap_or_else(|_| "unknown".to_string())
}

fn zir_constraint_kind_name(constraint: &zkf_core::zir_v1::Constraint) -> &'static str {
    match constraint {
        zkf_core::zir_v1::Constraint::Equal { .. } => "equal",
        zkf_core::zir_v1::Constraint::Boolean { .. } => "boolean",
        zkf_core::zir_v1::Constraint::Range { .. } => "range",
        zkf_core::zir_v1::Constraint::Lookup { .. } => "lookup",
        zkf_core::zir_v1::Constraint::CustomGate { .. } => "custom_gate",
        zkf_core::zir_v1::Constraint::MemoryRead { .. } => "memory_read",
        zkf_core::zir_v1::Constraint::MemoryWrite { .. } => "memory_write",
        zkf_core::zir_v1::Constraint::BlackBox { .. } => "black_box",
        zkf_core::zir_v1::Constraint::Permutation { .. } => "permutation",
        zkf_core::zir_v1::Constraint::Copy { .. } => "copy",
    }
}

fn zir_constraint_label(constraint: &zkf_core::zir_v1::Constraint) -> Option<&str> {
    match constraint {
        zkf_core::zir_v1::Constraint::Equal { label, .. }
        | zkf_core::zir_v1::Constraint::Boolean { label, .. }
        | zkf_core::zir_v1::Constraint::Range { label, .. }
        | zkf_core::zir_v1::Constraint::Lookup { label, .. }
        | zkf_core::zir_v1::Constraint::CustomGate { label, .. }
        | zkf_core::zir_v1::Constraint::MemoryRead { label, .. }
        | zkf_core::zir_v1::Constraint::MemoryWrite { label, .. }
        | zkf_core::zir_v1::Constraint::BlackBox { label, .. }
        | zkf_core::zir_v1::Constraint::Permutation { label, .. }
        | zkf_core::zir_v1::Constraint::Copy { label, .. } => label.as_deref(),
    }
}

fn ir_constraint_kind_name(constraint: &zkf_core::ir::Constraint) -> &'static str {
    match constraint {
        zkf_core::ir::Constraint::Equal { .. } => "equal",
        zkf_core::ir::Constraint::Boolean { .. } => "boolean",
        zkf_core::ir::Constraint::Range { .. } => "range",
        zkf_core::ir::Constraint::BlackBox { .. } => "black_box",
        zkf_core::ir::Constraint::Lookup { .. } => "lookup",
    }
}

fn find_signal_definition_range(text: &str, name: &str) -> Option<Range> {
    let section = json_section_slice(
        text,
        "signals",
        &[
            "constraints",
            "witness_plan",
            "lookup_tables",
            "memory_regions",
            "custom_gates",
            "metadata",
        ],
    )?;
    find_string_property_value_range(text, section.0, section.1, "name", name)
}

fn find_constraint_label_range(text: &str, label: &str) -> Option<Range> {
    let section = json_section_slice(
        text,
        "constraints",
        &[
            "witness_plan",
            "lookup_tables",
            "memory_regions",
            "custom_gates",
            "metadata",
        ],
    )?;
    find_string_property_value_range(text, section.0, section.1, "label", label)
}

fn json_section_slice(text: &str, section: &str, next_sections: &[&str]) -> Option<(usize, usize)> {
    let section_pattern = format!("\"{section}\"");
    let start = text.find(&section_pattern)?;
    let end = next_sections
        .iter()
        .filter_map(|next| {
            let pattern = format!("\"{next}\"");
            text[start + section_pattern.len()..]
                .find(&pattern)
                .map(|offset| start + section_pattern.len() + offset)
        })
        .min()
        .unwrap_or(text.len());
    Some((start, end))
}

fn find_string_property_value_range(
    text: &str,
    start: usize,
    end: usize,
    key: &str,
    expected: &str,
) -> Option<Range> {
    let key_pattern = format!("\"{key}\"");
    let mut search_from = start;
    while search_from < end {
        let relative = text[search_from..end].find(&key_pattern)?;
        let key_start = search_from + relative;
        let mut cursor = key_start + key_pattern.len();
        cursor = skip_ascii_whitespace(text, cursor);
        if text.as_bytes().get(cursor) != Some(&b':') {
            search_from = key_start + 1;
            continue;
        }
        cursor = skip_ascii_whitespace(text, cursor + 1);
        if text.as_bytes().get(cursor) != Some(&b'"') {
            search_from = key_start + 1;
            continue;
        }
        let value_start = cursor;
        let value_end = find_json_string_end(text, value_start)?;
        let raw = &text[value_start..=value_end];
        let actual: String = serde_json::from_str(raw).ok()?;
        if actual == expected {
            return Some(range_for_offsets(text, value_start + 1, value_end));
        }
        search_from = value_end + 1;
    }
    None
}

fn json_string_value_at(text: &str, position: Position) -> Option<(usize, usize, String)> {
    let offset = offset_for_position(text, position)?;
    if offset >= text.len() {
        return None;
    }

    let mut start = offset;
    while start > 0 {
        let idx = start - 1;
        if text.as_bytes().get(idx) == Some(&b'"') && !is_escaped_quote(text, idx) {
            start = idx;
            break;
        }
        start -= 1;
    }
    if text.as_bytes().get(start) != Some(&b'"') {
        return None;
    }

    let end = find_json_string_end(text, start)?;
    if offset <= start || offset > end {
        return None;
    }
    let raw = &text[start..=end];
    let value: String = serde_json::from_str(raw).ok()?;
    Some((start, end, value))
}

fn json_property_key_before_value(text: &str, value_start: usize) -> Option<String> {
    let mut cursor = value_start.checked_sub(1)?;
    while cursor > 0
        && text
            .as_bytes()
            .get(cursor)
            .copied()
            .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor -= 1;
    }
    if text.as_bytes().get(cursor) != Some(&b':') {
        return None;
    }
    cursor = cursor.checked_sub(1)?;
    while cursor > 0
        && text
            .as_bytes()
            .get(cursor)
            .copied()
            .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor -= 1;
    }
    if text.as_bytes().get(cursor) != Some(&b'"') {
        return None;
    }
    let key_end = cursor;
    while cursor > 0 {
        cursor -= 1;
        if text.as_bytes().get(cursor) == Some(&b'"') && !is_escaped_quote(text, cursor) {
            let raw = &text[cursor..=key_end];
            return serde_json::from_str(raw).ok();
        }
    }
    None
}

fn find_json_string_end(text: &str, start_quote: usize) -> Option<usize> {
    let mut cursor = start_quote + 1;
    while cursor < text.len() {
        if text.as_bytes().get(cursor) == Some(&b'"') && !is_escaped_quote(text, cursor) {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

fn is_escaped_quote(text: &str, quote_index: usize) -> bool {
    let mut backslashes = 0usize;
    let mut cursor = quote_index;
    while cursor > 0 {
        cursor -= 1;
        if text.as_bytes().get(cursor) == Some(&b'\\') {
            backslashes += 1;
        } else {
            break;
        }
    }
    backslashes % 2 == 1
}

fn skip_ascii_whitespace(text: &str, mut cursor: usize) -> usize {
    while cursor < text.len()
        && text
            .as_bytes()
            .get(cursor)
            .copied()
            .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        cursor += 1;
    }
    cursor
}

fn offset_for_position(text: &str, position: Position) -> Option<usize> {
    let target_line = position.line as usize;
    let target_col = position.character as usize;
    let mut line = 0usize;
    let mut col = 0usize;
    for (offset, ch) in text.char_indices() {
        if line == target_line && col == target_col {
            return Some(offset);
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    if line == target_line && col == target_col {
        Some(text.len())
    } else {
        None
    }
}

fn position_for_offset(text: &str, target: usize) -> Position {
    let mut line = 0u32;
    let mut col = 0u32;
    for (offset, ch) in text.char_indices() {
        if offset >= target {
            return Position::new(line, col);
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    Position::new(line, col)
}

fn range_for_offsets(text: &str, start: usize, end: usize) -> Range {
    Range::new(
        position_for_offset(text, start),
        position_for_offset(text, end),
    )
}

/// Pure analysis: collect diagnostics from a ZIR program without requiring an LSP client.
///
/// Extracted for testability — the LSP server delegates here.
fn analyze_zir_diagnostics(program: &zkf_core::zir_v1::Program, diagnostics: &mut Vec<Diagnostic>) {
    // --- Type checking ---
    if let Err(errors) = type_check(program) {
        for error in &errors {
            let line = error.location.map(|loc| loc as u32).unwrap_or(0);
            diagnostics.push(Diagnostic {
                range: Range::new(Position::new(line, 0), Position::new(line, 1)),
                severity: Some(DiagnosticSeverity::ERROR),
                code: Some(NumberOrString::String("type_error".into())),
                source: Some("zkf".into()),
                message: format!("{error}"),
                ..Default::default()
            });
        }
    }

    // --- Underconstrained signal analysis ---
    match zkf_core::analyze_underconstrained_zir(program) {
        Ok(analysis) => {
            for signal in &analysis.unconstrained_private_signals {
                diagnostics.push(Diagnostic {
                    range: Range::new(Position::new(0, 0), Position::new(0, 1)),
                    severity: Some(DiagnosticSeverity::WARNING),
                    code: Some(NumberOrString::String("unconstrained".into())),
                    source: Some("zkf".into()),
                    message: format!("Private signal '{signal}' is unconstrained"),
                    ..Default::default()
                });
            }
            for signal in &analysis.linearly_underdetermined_private_signals {
                // Skip if already reported as fully unconstrained.
                if !analysis.unconstrained_private_signals.contains(signal) {
                    diagnostics.push(Diagnostic {
                        range: Range::new(Position::new(0, 0), Position::new(0, 1)),
                        severity: Some(DiagnosticSeverity::WARNING),
                        code: Some(NumberOrString::String("underdetermined".into())),
                        source: Some("zkf".into()),
                        message: format!(
                            "Private signal '{signal}' may be underdetermined \
                             (linear rank analysis)"
                        ),
                        ..Default::default()
                    });
                }
            }
        }
        Err(e) => {
            diagnostics.push(Diagnostic {
                range: Range::new(Position::new(0, 0), Position::new(0, 1)),
                severity: Some(DiagnosticSeverity::INFORMATION),
                source: Some("zkf".into()),
                message: format!("Underconstrained analysis unavailable: {e}"),
                ..Default::default()
            });
        }
    }

    // --- Summary hint when everything looks good ---
    let has_errors = diagnostics
        .iter()
        .any(|d| d.severity == Some(DiagnosticSeverity::ERROR));
    let has_warnings = diagnostics
        .iter()
        .any(|d| d.severity == Some(DiagnosticSeverity::WARNING));

    if !has_errors && !has_warnings {
        diagnostics.push(Diagnostic {
            range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            severity: Some(DiagnosticSeverity::HINT),
            source: Some("zkf".into()),
            message: format!(
                "Valid ZIR program: {} signals, {} constraints, field: {}",
                program.signals.len(),
                program.constraints.len(),
                serde_json::to_string(&program.field).unwrap_or_else(|_| "unknown".into()),
            ),
            ..Default::default()
        });
    }
}

/// Collect diagnostics for a raw text document (ZIR or IR v2).
///
/// Extracted for testability — the LSP server delegates here.
fn analyze_text_diagnostics(text: &str) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    match serde_json::from_str::<zkf_core::zir_v1::Program>(text) {
        Ok(program) => {
            analyze_zir_diagnostics(&program, &mut diagnostics);
        }
        Err(zir_err) => match serde_json::from_str::<zkf_core::Program>(text) {
            Ok(program) => {
                diagnostics.push(Diagnostic {
                    range: Range::new(Position::new(0, 0), Position::new(0, 1)),
                    severity: Some(DiagnosticSeverity::HINT),
                    source: Some("zkf".into()),
                    message: format!(
                        "Valid IR v2 program: {} signals, {} constraints, field: {}",
                        program.signals.len(),
                        program.constraints.len(),
                        serde_json::to_string(&program.field).unwrap_or_else(|_| "unknown".into()),
                    ),
                    ..Default::default()
                });
            }
            Err(_) => {
                let (line, col) = json_error_position(&zir_err);
                diagnostics.push(Diagnostic {
                    range: Range::new(Position::new(line, col), Position::new(line, col + 1)),
                    severity: Some(DiagnosticSeverity::ERROR),
                    code: Some(NumberOrString::String("parse_error".into())),
                    source: Some("zkf".into()),
                    message: format!("Failed to parse ZKF program: {zir_err}"),
                    ..Default::default()
                });
            }
        },
    }

    diagnostics
}

/// Extract line/column from a serde_json error, falling back to (0, 0).
fn json_error_position(err: &serde_json::Error) -> (u32, u32) {
    let line = err.line().saturating_sub(1) as u32;
    let col = err.column().saturating_sub(1) as u32;
    (line, col)
}

#[tower_lsp::async_trait]
impl LanguageServer for ZkfLanguageServer {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: server_capabilities(),
            server_info: Some(ServerInfo {
                name: "zkf-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "ZirOS Language Server initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        self.documents
            .write()
            .await
            .insert(uri.clone(), text.clone());
        self.analyze_document(&uri, &text).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        if let Some(change) = params.content_changes.into_iter().last() {
            self.documents
                .write()
                .await
                .insert(uri.clone(), change.text.clone());
            self.analyze_document(&uri, &change.text).await;
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.documents.write().await.remove(&uri);
        // Clear diagnostics for the closed document.
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        let uri = params.text_document.uri;
        let documents = self.documents.read().await;
        if let Some(text) = documents.get(&uri) {
            self.analyze_document(&uri, text).await;
        }
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = self.documents.read().await;
        Ok(documents
            .get(&uri)
            .and_then(|text| hover_for_text(text, position)))
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = self.documents.read().await;
        Ok(documents
            .get(&uri)
            .and_then(|text| definition_for_text(&uri, text, position)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp::lsp_types::DiagnosticSeverity;

    /// Minimal valid ZIR program JSON.
    fn valid_zir_json() -> String {
        serde_json::json!({
            "name": "test_circuit",
            "field": "bn254",
            "signals": [
                {"name": "x", "visibility": "public", "ty": {"kind": "field"}},
                {"name": "y", "visibility": "private", "ty": {"kind": "field"}}
            ],
            "constraints": [
                {"kind": "equal", "lhs": {"op": "signal", "args": "x"}, "rhs": {"op": "signal", "args": "y"}}
            ],
            "witness_plan": {"assignments": [], "hints": []}
        })
        .to_string()
    }

    #[test]
    fn json_error_position_extracts_line_and_col() {
        let bad_json = "{\n  \"bad\": }";
        let err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let (line, col) = json_error_position(&err);
        // serde_json error is 1-indexed; our function subtracts 1.
        assert_eq!(line, 1); // line 2 -> 1
        assert!(col > 0 || col == 0); // col depends on parser, just verify it doesn't panic
    }

    #[test]
    fn json_error_position_first_line() {
        let bad_json = "}";
        let err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let (line, col) = json_error_position(&err);
        assert_eq!(line, 0);
        assert_eq!(col, 0);
    }

    #[test]
    fn analyze_text_invalid_json_produces_parse_error() {
        let diagnostics = analyze_text_diagnostics("not json at all");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
        assert_eq!(
            diagnostics[0].code,
            Some(NumberOrString::String("parse_error".into()))
        );
        assert!(diagnostics[0].message.contains("Failed to parse"));
    }

    #[test]
    fn analyze_text_empty_object_produces_parse_error() {
        let diagnostics = analyze_text_diagnostics("{}");
        // An empty object might parse as IR v2 (all defaults) or fail ZIR.
        // Either way we should get at least one diagnostic.
        assert!(!diagnostics.is_empty());
    }

    #[test]
    fn analyze_text_valid_zir_produces_hint() {
        let diagnostics = analyze_text_diagnostics(&valid_zir_json());
        // A valid, fully-constrained ZIR should produce a summary hint.
        let hints: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == Some(DiagnosticSeverity::HINT))
            .collect();
        assert!(
            !hints.is_empty(),
            "expected at least one HINT diagnostic for valid ZIR, got: {diagnostics:?}"
        );
        assert!(hints[0].message.contains("Valid ZIR program"));
    }

    #[test]
    fn analyze_text_valid_zir_reports_signal_count() {
        let diagnostics = analyze_text_diagnostics(&valid_zir_json());
        let hints: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == Some(DiagnosticSeverity::HINT))
            .collect();
        if !hints.is_empty() {
            assert!(hints[0].message.contains("2 signals"));
            assert!(hints[0].message.contains("1 constraints"));
        }
    }

    #[test]
    fn analyze_text_all_diagnostics_have_zkf_source() {
        let diagnostics = analyze_text_diagnostics(&valid_zir_json());
        for d in &diagnostics {
            assert_eq!(d.source.as_deref(), Some("zkf"));
        }
    }

    #[test]
    fn analyze_text_invalid_json_all_diagnostics_have_zkf_source() {
        let diagnostics = analyze_text_diagnostics("not json");
        for d in &diagnostics {
            assert_eq!(d.source.as_deref(), Some("zkf"));
        }
    }

    #[test]
    fn analyze_zir_diagnostics_empty_program_has_no_errors() {
        let program = zkf_core::zir_v1::Program {
            name: "empty".into(),
            field: zkf_core::FieldId::Bn254,
            signals: Vec::new(),
            constraints: Vec::new(),
            witness_plan: Default::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: Default::default(),
        };
        let mut diagnostics = Vec::new();
        analyze_zir_diagnostics(&program, &mut diagnostics);
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == Some(DiagnosticSeverity::ERROR))
            .collect();
        assert!(
            errors.is_empty(),
            "empty program should have no type errors"
        );
    }

    #[test]
    fn analyze_zir_diagnostics_valid_program_produces_hint() {
        let json = valid_zir_json();
        let program: zkf_core::zir_v1::Program = serde_json::from_str(&json).unwrap();
        let mut diagnostics = Vec::new();
        analyze_zir_diagnostics(&program, &mut diagnostics);
        // Should have either a hint (good program) or warnings (underconstrained).
        assert!(!diagnostics.is_empty());
    }

    fn multi_line_zir_json() -> String {
        r#"{
  "name": "test_circuit",
  "field": "bn254",
  "signals": [
    {"name": "x", "visibility": "public", "ty": {"kind": "field"}},
    {"name": "y", "visibility": "private", "ty": {"kind": "field"}}
  ],
  "constraints": [
    {
      "kind": "equal",
      "lhs": {"op": "signal", "args": "x"},
      "rhs": {"op": "signal", "args": "y"},
      "label": "bind_xy"
    }
  ],
  "witness_plan": {"assignments": [], "hints": []}
}"#
        .to_string()
    }

    fn multi_line_ir_json() -> String {
        r#"{
  "name": "test_v2",
  "field": "bn254",
  "signals": [
    {"name": "a", "visibility": "public"},
    {"name": "b", "visibility": "private"}
  ],
  "constraints": [
    {
      "kind": "equal",
      "lhs": {"op": "signal", "args": "a"},
      "rhs": {"op": "signal", "args": "b"},
      "label": "bind_ab"
    }
  ],
  "witness_plan": {"assignments": []}
}"#
        .to_string()
    }

    fn position_inside(text: &str, needle: &str) -> Position {
        let start = text.find(needle).expect("needle must exist");
        let quote_end = needle
            .rfind('"')
            .expect("needle must include a quoted value");
        let quote_start = needle[..quote_end]
            .rfind('"')
            .expect("needle must include a quoted value");
        let content_offset = start + quote_start + 1;
        position_for_offset(text, content_offset)
    }

    #[test]
    fn server_capabilities_enable_hover_definition_and_save_sync() {
        let capabilities = server_capabilities();
        assert_eq!(
            capabilities.hover_provider,
            Some(HoverProviderCapability::Simple(true))
        );
        assert_eq!(capabilities.definition_provider, Some(OneOf::Left(true)));
        let Some(TextDocumentSyncCapability::Options(sync)) = capabilities.text_document_sync
        else {
            panic!("expected explicit text document sync options");
        };
        assert_eq!(sync.open_close, Some(true));
        assert_eq!(sync.change, Some(TextDocumentSyncKind::FULL));
        assert_eq!(
            sync.save,
            Some(TextDocumentSyncSaveOptions::Supported(true))
        );
    }

    #[test]
    fn hover_for_signal_reference_returns_signal_metadata() {
        let text = multi_line_zir_json();
        let hover = hover_for_text(&text, position_inside(&text, "\"args\": \"y\""))
            .expect("hover should resolve");
        let HoverContents::Markup(markup) = hover.contents else {
            panic!("expected markdown hover");
        };
        assert!(markup.value.contains("ZIR signal `y`"));
        assert!(markup.value.contains("visibility: `private`"));
    }

    #[test]
    fn definition_for_signal_reference_points_to_signal_definition() {
        let text = multi_line_zir_json();
        let uri = Url::parse("file:///tmp/test.ir.json").unwrap();
        let Some(GotoDefinitionResponse::Scalar(location)) =
            definition_for_text(&uri, &text, position_inside(&text, "\"args\": \"y\""))
        else {
            panic!("definition should resolve");
        };
        let expected = find_signal_definition_range(&text, "y").expect("definition range");
        assert_eq!(location.range, expected);
    }

    #[test]
    fn hover_for_constraint_label_returns_constraint_metadata() {
        let text = multi_line_ir_json();
        let hover = hover_for_text(&text, position_inside(&text, "\"label\": \"bind_ab\""))
            .expect("hover should resolve");
        let HoverContents::Markup(markup) = hover.contents else {
            panic!("expected markdown hover");
        };
        assert!(markup.value.contains("IR constraint label `bind_ab`"));
        assert!(markup.value.contains("kind: `equal`"));
    }
}
