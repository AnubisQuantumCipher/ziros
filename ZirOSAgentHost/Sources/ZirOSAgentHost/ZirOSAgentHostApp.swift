import SwiftUI

@main
struct ZirOSAgentHostApp: App {
    @State private var model = AgentHostViewModel()

    var body: some Scene {
        WindowGroup {
            ZirOSAgentHostView(model: model)
                .frame(minWidth: 1240, minHeight: 780)
                .task {
                    model.refresh()
                }
        }
        .windowResizability(.contentSize)
    }
}

struct ZirOSAgentHostView: View {
    @Bindable var model: AgentHostViewModel

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.08, green: 0.1, blue: 0.12),
                    Color(red: 0.13, green: 0.16, blue: 0.2),
                    Color(red: 0.18, green: 0.13, blue: 0.1)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 18) {
                header
                content
            }
            .padding(20)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("ZirOS Agent Host")
                        .font(.system(size: 30, weight: .bold, design: .rounded))
                        .foregroundStyle(.white)
                    Text("Thin supervisory shell over `ziros-agentd` for sessions, receipts, and wallet approvals.")
                        .font(.system(size: 13, weight: .medium, design: .rounded))
                        .foregroundStyle(.white.opacity(0.72))
                }
                Spacer()
                Button {
                    model.refresh()
                } label: {
                    Label(model.isLoading ? "Refreshing" : "Refresh", systemImage: "arrow.clockwise")
                        .font(.system(size: 13, weight: .semibold, design: .rounded))
                }
                .buttonStyle(.borderedProminent)
                .tint(Color(red: 0.89, green: 0.55, blue: 0.28))
                .disabled(model.isLoading)
            }

            HStack(spacing: 12) {
                statCard(
                    title: "Socket",
                    value: model.statusReport?.socketPresent == true ? "Connected" : "Unavailable",
                    accent: model.statusReport?.socketPresent == true ? .green : .red
                )
                statCard(
                    title: "Sessions",
                    value: "\(model.statusReport?.sessions.count ?? 0)",
                    accent: .cyan
                )
                statCard(
                    title: "Projects",
                    value: "\(model.statusReport?.projects.count ?? 0)",
                    accent: .orange
                )
            }

            TextField("Daemon socket path", text: $model.socketPath)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, weight: .medium, design: .monospaced))

            if let errorMessage = model.errorMessage {
                Text(errorMessage)
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.55, blue: 0.55))
            } else if let lastActionMessage = model.lastActionMessage {
                Text(lastActionMessage)
                    .font(.system(size: 12, weight: .semibold, design: .rounded))
                    .foregroundStyle(Color(red: 0.55, green: 0.95, blue: 0.75))
            }
        }
        .padding(20)
        .background(cardBackground)
    }

    private var content: some View {
        HStack(alignment: .top, spacing: 18) {
            sidebar
                .frame(width: 360)
            detail
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Sessions")
                    .sectionTitle()
                if let sessions = model.statusReport?.sessions, !sessions.isEmpty {
                    List(selection: $model.selectedSessionID) {
                        ForEach(sessions) { session in
                            Button {
                                model.select(sessionID: session.sessionID)
                            } label: {
                                VStack(alignment: .leading, spacing: 5) {
                                    HStack {
                                        Text(session.workflowKind)
                                            .font(.system(size: 12, weight: .bold, design: .rounded))
                                            .foregroundStyle(.white)
                                        Spacer()
                                        Text(session.status)
                                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                            .foregroundStyle(statusColor(session.status))
                                    }
                                    Text(session.goalSummary)
                                        .font(.system(size: 11, weight: .medium, design: .rounded))
                                        .foregroundStyle(.white.opacity(0.72))
                                        .lineLimit(2)
                                    Text(session.sessionID)
                                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                                        .foregroundStyle(.white.opacity(0.45))
                                }
                                .padding(.vertical, 6)
                            }
                            .buttonStyle(.plain)
                            .listRowBackground(Color.clear)
                        }
                    }
                    .scrollContentBackground(.hidden)
                    .background(Color.clear)
                } else {
                    emptyState("No agent sessions recorded yet.")
                }
            }
            .padding(18)
            .background(cardBackground)

            VStack(alignment: .leading, spacing: 12) {
                Text("Projects")
                    .sectionTitle()
                if let projects = model.statusReport?.projects, !projects.isEmpty {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(projects) { project in
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(project.name)
                                        .font(.system(size: 13, weight: .bold, design: .rounded))
                                        .foregroundStyle(.white)
                                    Text(project.rootPath)
                                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                                        .foregroundStyle(.white.opacity(0.58))
                                        .textSelection(.enabled)
                                }
                                .padding(12)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                            }
                        }
                    }
                } else {
                    emptyState("No registered projects.")
                }
            }
            .padding(18)
            .background(cardBackground)
        }
    }

    private var detail: some View {
        VStack(alignment: .leading, spacing: 18) {
            sessionDetail
            approvalPanel
            receiptsPanel
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var sessionDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Session Detail")
                .sectionTitle()
            if let session = selectedSession {
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                    GridRow {
                        detailRow(title: "Session", value: session.sessionID)
                        detailRow(title: "Status", value: session.status)
                    }
                    GridRow {
                        detailRow(title: "Workflow", value: session.workflowKind)
                        detailRow(title: "Updated", value: session.updatedAt)
                    }
                    GridRow {
                        detailRow(title: "Project", value: session.projectRoot ?? "None")
                        detailRow(title: "Workgraph", value: session.workgraphID ?? "None")
                    }
                }
                Text(session.goalSummary)
                    .font(.system(size: 14, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.78))
                    .padding(.top, 4)
            } else {
                emptyState("Select a session to inspect its workgraph and receipts.")
            }
        }
        .padding(20)
        .background(cardBackground)
    }

    private var approvalPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Wallet Approval")
                .sectionTitle()
            TextField("Pending approval id", text: $model.pendingID)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, weight: .medium, design: .monospaced))
            TextField("Primary prompt", text: $model.primaryPrompt)
                .textFieldStyle(.roundedBorder)
            TextField("Secondary prompt (optional)", text: $model.secondaryPrompt)
                .textFieldStyle(.roundedBorder)
            TextField("Reject reason", text: $model.rejectReason)
                .textFieldStyle(.roundedBorder)
            HStack(spacing: 10) {
                Button("Approve") {
                    model.approvePending()
                }
                .buttonStyle(.borderedProminent)
                .tint(Color(red: 0.2, green: 0.7, blue: 0.52))
                .disabled(model.isLoading || selectedSession == nil)

                Button("Reject") {
                    model.rejectPending()
                }
                .buttonStyle(.bordered)
                .tint(Color(red: 0.95, green: 0.42, blue: 0.35))
                .disabled(model.isLoading || selectedSession == nil)
            }
        }
        .padding(20)
        .background(cardBackground)
    }

    private var receiptsPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Receipts")
                    .sectionTitle()
                Spacer()
                if let generatedAt = model.selectedLogs?.generatedAt {
                    Text("Updated \(generatedAt)")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.45))
                }
            }
            if let receipts = model.selectedLogs?.receipts, !receipts.isEmpty {
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(receipts) { receipt in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(receipt.actionName)
                                        .font(.system(size: 13, weight: .bold, design: .rounded))
                                        .foregroundStyle(.white)
                                    Spacer()
                                    Text(receipt.status)
                                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                        .foregroundStyle(statusColor(receipt.status))
                                }
                                Text(receipt.createdAt)
                                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                                    .foregroundStyle(.white.opacity(0.45))
                                Text(receipt.payload.prettyPrinted)
                                    .font(.system(size: 11, weight: .regular, design: .monospaced))
                                    .foregroundStyle(.white.opacity(0.76))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .textSelection(.enabled)
                            }
                            .padding(14)
                            .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                        }
                    }
                }
            } else {
                emptyState("No receipts available for the selected session.")
            }
        }
        .padding(20)
        .background(cardBackground)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var selectedSession: AgentSessionView? {
        guard let sessionID = model.selectedSessionID else {
            return nil
        }
        return model.statusReport?.sessions.first(where: { $0.sessionID == sessionID })
    }

    private var cardBackground: some ShapeStyle {
        Color.white.opacity(0.08)
    }

    private func statCard(title: String, value: String, accent: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased())
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundStyle(.white.opacity(0.45))
            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
            Capsule()
                .fill(accent.opacity(0.92))
                .frame(width: 48, height: 4)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(cardBackground, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func detailRow(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundStyle(.white.opacity(0.42))
            Text(value)
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundStyle(.white.opacity(0.84))
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func emptyState(_ message: String) -> some View {
        Text(message)
            .font(.system(size: 12, weight: .medium, design: .rounded))
            .foregroundStyle(.white.opacity(0.55))
            .frame(maxWidth: .infinity, minHeight: 120)
            .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "completed", "approved", "ready", "planned":
            return Color(red: 0.54, green: 0.95, blue: 0.76)
        case "blocked", "rejected", "cancelled":
            return Color(red: 1.0, green: 0.55, blue: 0.52)
        default:
            return Color(red: 0.73, green: 0.84, blue: 1.0)
        }
    }
}

private extension Text {
    func sectionTitle() -> some View {
        self
            .font(.system(size: 16, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
    }
}
