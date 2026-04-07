import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
final class AgentHostViewModel {
    var socketPath: String
    var statusReport: AgentStatusReport?
    var selectedSessionID: String?
    var selectedLogs: AgentLogsReport?
    var pendingID: String = ""
    var primaryPrompt: String = "Approve this ZirOS agent request."
    var secondaryPrompt: String = ""
    var rejectReason: String = "Rejected from ZirOSAgentHost."
    var isLoading = false
    var errorMessage: String?
    var lastActionMessage: String?

    init(socketPath: String = AgentHostViewModel.defaultSocketPath()) {
        self.socketPath = socketPath
    }

    func refresh() {
        guard !isLoading else { return }
        isLoading = true
        errorMessage = nil
        lastActionMessage = nil
        let socketPath = socketPath
        let currentSelection = selectedSessionID
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<(AgentStatusReport, AgentLogsReport?), Error> = Result {
                let client = AgentDaemonClient(socketPath: socketPath)
                let report = try client.status(limit: 20)
                let targetSessionID = currentSelection ?? report.sessions.first?.sessionID
                let logs = try targetSessionID.map { try client.logs(sessionID: $0) }
                return (report, logs)
            }
            DispatchQueue.main.async {
                self.isLoading = false
                switch result {
                case let .success((report, logs)):
                    withAnimation(.easeInOut(duration: 0.2)) {
                        self.statusReport = report
                        if self.selectedSessionID == nil {
                            self.selectedSessionID = report.sessions.first?.sessionID
                        }
                        self.selectedLogs = logs
                    }
                case let .failure(error):
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }

    func select(sessionID: String) {
        selectedSessionID = sessionID
        loadLogs()
    }

    func approvePending() {
        guard let sessionID = selectedSessionID else {
            errorMessage = "Select a session before approving a pending request."
            return
        }
        let pendingID = pendingID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !pendingID.isEmpty else {
            errorMessage = "Enter a pending approval id."
            return
        }
        let primaryPrompt = primaryPrompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !primaryPrompt.isEmpty else {
            errorMessage = "Enter the approval prompt."
            return
        }
        let secondaryPrompt = secondaryPrompt.trimmingCharacters(in: .whitespacesAndNewlines)
        runWalletAction(successMessage: "Approved \(pendingID).") { client in
            try client.approve(
                sessionID: sessionID,
                pendingID: pendingID,
                primaryPrompt: primaryPrompt,
                secondaryPrompt: secondaryPrompt
            )
        }
    }

    func rejectPending() {
        guard let sessionID = selectedSessionID else {
            errorMessage = "Select a session before rejecting a pending request."
            return
        }
        let pendingID = pendingID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !pendingID.isEmpty else {
            errorMessage = "Enter a pending approval id."
            return
        }
        let rejectReason = rejectReason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rejectReason.isEmpty else {
            errorMessage = "Enter a rejection reason."
            return
        }
        runWalletAction(successMessage: "Rejected \(pendingID).") { client in
            try client.reject(sessionID: sessionID, pendingID: pendingID, reason: rejectReason)
        }
    }

    private func loadLogs() {
        guard let sessionID = selectedSessionID else {
            selectedLogs = nil
            return
        }
        let socketPath = socketPath
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<AgentLogsReport, Error> = Result {
                try AgentDaemonClient(socketPath: socketPath).logs(sessionID: sessionID)
            }
            DispatchQueue.main.async {
                switch result {
                case let .success(logs):
                    withAnimation(.easeInOut(duration: 0.2)) {
                        self.selectedLogs = logs
                    }
                case let .failure(error):
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }

    private func runWalletAction(
        successMessage: String,
        action: @escaping @Sendable (AgentDaemonClient) throws -> Void
    ) {
        errorMessage = nil
        lastActionMessage = nil
        isLoading = true
        let socketPath = socketPath
        DispatchQueue.global(qos: .userInitiated).async {
            let result: Result<Void, Error> = Result {
                try action(AgentDaemonClient(socketPath: socketPath))
            }
            DispatchQueue.main.async {
                self.isLoading = false
                switch result {
                case .success:
                    self.lastActionMessage = successMessage
                    self.refresh()
                case let .failure(error):
                    self.errorMessage = error.localizedDescription
                }
            }
        }
    }

    static func defaultSocketPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".zkf")
            .appendingPathComponent("cache")
            .appendingPathComponent("agent")
            .appendingPathComponent("ziros-agentd.sock")
            .path
    }
}
