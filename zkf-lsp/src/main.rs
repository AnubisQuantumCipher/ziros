//! ZirOS Language Server -- real-time diagnostics for ZirOS / ZKF IR programs.

use zkf_lsp::server;

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = tower_lsp::LspService::new(server::ZkfLanguageServer::new);

    tower_lsp::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;
}
