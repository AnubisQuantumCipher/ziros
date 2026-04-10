use std::collections::BTreeMap;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticSeverity, DidOpenTextDocumentParams, GotoDefinitionParams,
    GotoDefinitionResponse, Hover, HoverContents, HoverParams, InitializeParams, InitializeResult,
    MarkedString, OneOf, Position, Range, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};

#[derive(Debug, Default)]
struct DocumentState {
    text: String,
    symbols: BTreeMap<String, Position>,
}

#[derive(Debug)]
struct ZirLanguageServer {
    client: Client,
    documents: tokio::sync::RwLock<BTreeMap<Url, DocumentState>>,
}

impl ZirLanguageServer {
    fn new(client: Client) -> Self {
        Self {
            client,
            documents: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    async fn publish(&self, uri: Url, text: String) {
        let diagnostics = diagnostics_for(&text);
        let symbols = symbols_for(&text);
        self.documents
            .write()
            .await
            .insert(uri.clone(), DocumentState { text, symbols });
        self.client
            .publish_diagnostics(uri, diagnostics, None)
            .await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for ZirLanguageServer {
    async fn initialize(&self, _: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(tower_lsp::lsp_types::HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                ..ServerCapabilities::default()
            },
            server_info: Some(tower_lsp::lsp_types::ServerInfo {
                name: "zkf-lsp".to_string(),
                version: Some(zkf_lang::ZIR_LANGUAGE_VERSION.to_string()),
            }),
        })
    }

    async fn initialized(&self, _: tower_lsp::lsp_types::InitializedParams) {}

    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.publish(params.text_document.uri, params.text_document.text)
            .await;
    }

    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = self.documents.read().await;
        let Some(document) = documents.get(&uri) else {
            return Ok(None);
        };
        let Some(word) = word_at(&document.text, position) else {
            return Ok(None);
        };
        let contents = if document.symbols.contains_key(&word) {
            format!("`{word}`: Zir signal or binding")
        } else if matches!(
            word.as_str(),
            "circuit" | "private" | "public" | "constrain" | "blackbox" | "lookup"
        ) {
            format!("`{word}`: Zir language keyword")
        } else {
            return Ok(None);
        };
        Ok(Some(Hover {
            contents: HoverContents::Scalar(MarkedString::String(contents)),
            range: None,
        }))
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> LspResult<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let documents = self.documents.read().await;
        let Some(document) = documents.get(&uri) else {
            return Ok(None);
        };
        let Some(word) = word_at(&document.text, position) else {
            return Ok(None);
        };
        let Some(position) = document.symbols.get(&word).copied() else {
            return Ok(None);
        };
        Ok(Some(GotoDefinitionResponse::Scalar(
            tower_lsp::lsp_types::Location {
                uri,
                range: Range::new(position, position),
            },
        )))
    }

    async fn formatting(
        &self,
        params: tower_lsp::lsp_types::DocumentFormattingParams,
    ) -> LspResult<Option<Vec<tower_lsp::lsp_types::TextEdit>>> {
        let documents = self.documents.read().await;
        let Some(document) = documents.get(&params.text_document.uri) else {
            return Ok(None);
        };
        let Ok(formatted) = zkf_lang::format_source(&document.text) else {
            return Ok(None);
        };
        Ok(Some(vec![tower_lsp::lsp_types::TextEdit {
            range: Range::new(Position::new(0, 0), Position::new(u32::MAX, 0)),
            new_text: formatted,
        }]))
    }
}

pub fn diagnostics_for(text: &str) -> Vec<Diagnostic> {
    zkf_lang::check_source(text)
        .diagnostics
        .into_iter()
        .map(|diagnostic| Diagnostic {
            range: Range::new(
                Position::new(
                    diagnostic.line.saturating_sub(1) as u32,
                    diagnostic.column.saturating_sub(1) as u32,
                ),
                Position::new(
                    diagnostic.line.saturating_sub(1) as u32,
                    diagnostic.column as u32,
                ),
            ),
            severity: Some(match diagnostic.severity {
                zkf_lang::ZirDiagnosticSeverity::Error => DiagnosticSeverity::ERROR,
                zkf_lang::ZirDiagnosticSeverity::Warning => DiagnosticSeverity::WARNING,
                zkf_lang::ZirDiagnosticSeverity::Note => DiagnosticSeverity::INFORMATION,
            }),
            code: Some(tower_lsp::lsp_types::NumberOrString::String(
                diagnostic.code,
            )),
            source: Some("zir".to_string()),
            message: diagnostic.message,
            ..Diagnostic::default()
        })
        .collect()
}

pub fn serve_stdio_blocking() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let (service, socket) = LspService::new(ZirLanguageServer::new);
        Server::new(stdin, stdout, socket).serve(service).await;
    });
    Ok(())
}

fn symbols_for(text: &str) -> BTreeMap<String, Position> {
    let mut symbols = BTreeMap::new();
    for (line_index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        let offset = line.len() - trimmed.len();
        for prefix in ["private ", "public ", "let ", "const "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let name = rest
                    .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                    .next()
                    .unwrap_or("");
                if !name.is_empty() {
                    symbols.insert(
                        name.to_string(),
                        Position::new(line_index as u32, offset as u32),
                    );
                }
            }
        }
    }
    symbols
}

fn word_at(text: &str, position: Position) -> Option<String> {
    let line = text.lines().nth(position.line as usize)?;
    let chars = line.chars().collect::<Vec<_>>();
    let mut start = (position.character as usize).min(chars.len());
    while start > 0 && is_word_char(chars[start - 1]) {
        start -= 1;
    }
    let mut end = (position.character as usize).min(chars.len());
    while end < chars.len() && is_word_char(chars[end]) {
        end += 1;
    }
    (start < end).then(|| chars[start..end].iter().collect())
}

fn is_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_report_invalid_source() {
        let diagnostics = diagnostics_for("circuit bad(field: bn254) { while x { } }");
        assert!(!diagnostics.is_empty());
    }

    #[test]
    fn symbol_index_finds_local_bindings() {
        let symbols = symbols_for("private amount: field;\nlet out: field = amount;");
        assert!(symbols.contains_key("amount"));
        assert!(symbols.contains_key("out"));
    }
}
