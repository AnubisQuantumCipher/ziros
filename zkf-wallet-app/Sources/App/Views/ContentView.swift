import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

struct ContentView: View {
    @Bindable var coordinator: WalletCoordinator

    private var isLocked: Bool {
        coordinator.snapshot?.locked != false
    }

    var body: some View {
        ZStack {
            if isLocked {
                LockedWalletView(coordinator: coordinator)
                    .transition(.scale(scale: 0.95).combined(with: .opacity))
            } else {
                UnlockedWalletView(coordinator: coordinator)
                    .transition(.scale(scale: 0.98).combined(with: .opacity))
            }
        }
        .sheet(item: $coordinator.pendingApproval) { flow in
            ApprovalSheet(
                flow: flow,
                onApprove: { Task { await coordinator.approvePending() } },
                onReject: coordinator.rejectPending
            )
        }
        .sheet(item: $coordinator.pendingSitePermission) { request in
            SitePermissionSheet(
                request: request,
                onApprove: coordinator.approveSitePermission,
                onReject: coordinator.rejectSitePermission
            )
        }
        .task {
            await coordinator.refresh()
        }
        .background(WalletChrome.background)
        .animation(.spring(response: 0.36, dampingFraction: 0.88), value: isLocked)
    }
}

private struct LockedWalletView: View {
    @Bindable var coordinator: WalletCoordinator

    private var outerPadding: CGFloat {
#if os(iOS)
        20
#else
        40
#endif
    }

    private var motifSize: CGFloat {
#if os(iOS)
        120
#else
        160
#endif
    }

    private var hasImportedSeed: Bool {
        coordinator.snapshot?.hasImportedSeed == true
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 28) {
                Spacer(minLength: 32)

                VStack(spacing: 22) {
                    ZStack {
                        Circle()
                            .fill(WalletChrome.midnightBlue.opacity(0.08))
                            .frame(width: motifSize + 36, height: motifSize + 36)
                            .blur(radius: 22)

                        ClockMotif()
                            .stroke(WalletChrome.midnightBlue, style: StrokeStyle(lineWidth: 1.5, lineCap: .round))
                            .frame(width: motifSize, height: motifSize)
                            .shadow(color: WalletChrome.midnightBlue.opacity(0.4), radius: 20)
                    }

                    VStack(spacing: 12) {
                        Text("Your Midnight. Your Proof.")
                            .font(WalletTypography.lockedHero)
                            .foregroundStyle(Color.white.opacity(0.87))
                            .multilineTextAlignment(.center)
                        Text("Native wallet with hardware-accelerated proving and quantum-safe messaging.")
                            .font(WalletTypography.bodyStrong)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                }
                .frame(maxWidth: 620)

                if hasImportedSeed {
                    Button {
                        WalletBrandAssets.Haptics.tapLight()
                        Task { await coordinator.unlock() }
                    } label: {
                        Label("Unlock With \(WalletPlatformSupport.biometricLabel)", systemImage: WalletPlatformSupport.biometricSymbol)
                            .frame(maxWidth: biometricButtonWidth)
                    }
                    .buttonStyle(PrimaryWalletButtonStyle())
                    .controlSize(.large)
                } else {
                    WalletPanel {
                        VStack(alignment: .leading, spacing: 18) {
                            Label("Import Existing Wallet", systemImage: "square.and.arrow.down")
                                .font(WalletTypography.sectionTitle)
                            Text("Import an existing Midnight mnemonic or master seed. Wallet creation and export stay out of this beta.")
                                .foregroundStyle(.secondary)
                            ImportSeedForm(coordinator: coordinator)
                        }
                    }
                    .frame(maxWidth: 760)
                }

                if let message = coordinator.statusMessage {
                    StatusBanner(message: message)
                        .frame(maxWidth: 760)
                }

                Spacer(minLength: 48)
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, outerPadding)
            .padding(.vertical, 20)
            .scrollContentBackground(.hidden)
        }
    }

    private var biometricButtonWidth: CGFloat? {
#if os(iOS)
        nil
#else
        280
#endif
    }
}

private struct ImportSeedForm: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Picker("Seed Format", selection: $coordinator.seedInputMode) {
                ForEach(SeedInputMode.allCases) { mode in
                    Text(mode == .mnemonic ? "Mnemonic" : "Master Seed").tag(mode)
                }
            }
            .pickerStyle(.segmented)

            TextEditor(text: $coordinator.seedInput)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 180)
                .padding(10)
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18))

            HStack(spacing: 14) {
                Button("Import Seed") {
                    coordinator.importSeed()
                }
                .buttonStyle(PrimaryWalletButtonStyle())
                if coordinator.snapshot?.hasImportedSeed == true {
                    Button("Unlock After Import") {
                        coordinator.importSeed()
                        Task { await coordinator.unlock() }
                    }
                    .buttonStyle(SecondaryWalletButtonStyle())
                }
            }
        }
    }
}

private struct LockedTabPreviewStrip: View {
    var body: some View {
#if os(iOS)
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                LockedPreviewTab(title: "Overview", systemImage: "house", highlighted: false)
                LockedPreviewTab(title: "Transact", systemImage: "arrow.left.arrow.right", highlighted: false)
                LockedPreviewTab(title: "DUST", systemImage: "flame", highlighted: true)
            }
            HStack(spacing: 10) {
                LockedPreviewTab(title: "Messages", systemImage: "bubble.left.and.bubble.right", highlighted: false)
                LockedPreviewTab(title: "More", systemImage: "ellipsis.circle", highlighted: false)
            }
        }
#else
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                lockedTabs
            }
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    LockedPreviewTab(title: "Overview", systemImage: "house", highlighted: false)
                    LockedPreviewTab(title: "Transact", systemImage: "arrow.left.arrow.right", highlighted: false)
                    LockedPreviewTab(title: "DUST", systemImage: "flame", highlighted: true)
                }
                HStack(spacing: 10) {
                    LockedPreviewTab(title: "Messages", systemImage: "bubble.left.and.bubble.right", highlighted: false)
                    LockedPreviewTab(title: "More", systemImage: "ellipsis.circle", highlighted: false)
                }
            }
        }
#endif
    }

    @ViewBuilder
    private var lockedTabs: some View {
        LockedPreviewTab(title: "Overview", systemImage: "house", highlighted: false)
        LockedPreviewTab(title: "Transact", systemImage: "arrow.left.arrow.right", highlighted: false)
        LockedPreviewTab(title: "DUST", systemImage: "flame", highlighted: true)
        LockedPreviewTab(title: "Messages", systemImage: "bubble.left.and.bubble.right", highlighted: false)
        LockedPreviewTab(title: "More", systemImage: "ellipsis.circle", highlighted: false)
    }
}

private struct LockedPreviewTab: View {
    let title: String
    let systemImage: String
    let highlighted: Bool

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: systemImage)
            Text(title)
                .lineLimit(1)
        }
        .font(WalletTypography.caption)
        .foregroundStyle(highlighted ? WalletChrome.dustInk : Color.primary)
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .fixedSize(horizontal: true, vertical: false)
        .background(
            highlighted ? AnyShapeStyle(WalletChrome.dustFill) : AnyShapeStyle(Color.white.opacity(0.06)),
            in: Capsule()
        )
        .overlay(
            Capsule()
                .stroke(highlighted ? WalletChrome.dustStroke : WalletChrome.panelStroke, lineWidth: 1)
        )
    }
}

private struct LockedDustPill: View {
    let title: String
    let value: String

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
            Text(value)
                .fontWeight(.bold)
        }
        .font(WalletTypography.caption)
        .foregroundStyle(WalletChrome.dustInk)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(WalletChrome.dustFill, in: Capsule())
        .overlay(
            Capsule()
                .stroke(WalletChrome.dustStroke, lineWidth: 1)
        )
    }
}

private struct UnlockedWalletView: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
#if os(iOS)
        TabView(selection: $coordinator.selectedSection) {
            mobileTab(.overview)
            mobileTab(.transact)
            mobileTab(.dust)
            mobileTab(.messages)
            mobileTab(.more)
        }
        .background(WalletChrome.background)
#else
        NavigationSplitView {
            DesktopSidebar(coordinator: coordinator)
        } detail: {
            VStack(spacing: 0) {
                HeaderBar(coordinator: coordinator)
                ScrollView {
                    HStack {
                        desktopSectionView(coordinator.selectedSection ?? .overview)
                            .frame(maxWidth: desktopContentWidth(for: coordinator.selectedSection ?? .overview), alignment: .leading)
                        Spacer(minLength: 0)
                    }
                    .padding(28)
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
        .background(WalletChrome.background)
#endif
    }

    @ViewBuilder
    private func mobileTab(_ section: WalletSection) -> some View {
        NavigationStack {
            ScrollView {
                sectionView(section)
                    .padding(20)
            }
            .background(WalletChrome.background)
            .navigationTitle(coordinator.isVisualAuditMode ? "" : section.title)
#if os(iOS)
            .navigationBarTitleDisplayMode(coordinator.isVisualAuditMode ? .automatic : .inline)
#endif
            .toolbar {
                if !coordinator.isVisualAuditMode {
#if os(iOS)
                    ToolbarItemGroup(placement: .topBarTrailing) {
                        Button("Refresh") {
                            Task { await coordinator.refresh() }
                        }
                        Button("Lock") {
                            Task { await coordinator.lock() }
                        }
                    }
#else
                    ToolbarItemGroup(placement: .automatic) {
                        Button("Refresh") {
                            Task { await coordinator.refresh() }
                        }
                        Button("Lock") {
                            Task { await coordinator.lock() }
                        }
                    }
#endif
                }
            }
        }
        .tabItem {
            Label(section.title, systemImage: tabIcon(for: section))
        }
        .tag(Optional(section))
    }

    private func tabIcon(for section: WalletSection) -> String {
        let active = coordinator.selectedSection == section
        switch section {
        case .overview:
            return active ? "house.fill" : "house"
        case .transact:
            return "arrow.left.arrow.right"
        case .dust:
            return active ? "flame.fill" : "flame"
        case .messages:
            return active ? "bubble.left.and.bubble.right.fill" : "bubble.left.and.bubble.right"
        case .more:
            return active ? "ellipsis.circle.fill" : "ellipsis.circle"
        }
    }

    @ViewBuilder
    private func sectionView(_ section: WalletSection) -> some View {
        switch section {
        case .overview:
            OverviewScreen(coordinator: coordinator)
        case .transact:
            TransactScreen(coordinator: coordinator)
        case .dust:
            DustScreen(coordinator: coordinator)
        case .messages:
            MessagesScreen(coordinator: coordinator)
        case .more:
            MoreHubScreen(coordinator: coordinator)
        }
    }

    @ViewBuilder
    private func desktopSectionView(_ section: WalletSection) -> some View {
        sectionView(section)
            .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private func desktopContentWidth(for section: WalletSection) -> CGFloat {
        switch section {
        case .messages:
            return 1320
        case .more:
            return 1220
        case .dust:
            return 1120
        case .transact:
            return 980
        case .overview:
            return 1080
        }
    }
}

#if os(macOS)
private struct DesktopSidebar: View {
    @Bindable var coordinator: WalletCoordinator

    private var unreadCount: Int {
        coordinator.conversations.reduce(0) { $0 + $1.unreadCount }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: WalletChrome.cardSpacing) {
            HStack(spacing: 12) {
                ClockMotif()
                    .stroke(WalletChrome.midnightBlue, style: StrokeStyle(lineWidth: 1.6, lineCap: .round))
                    .frame(width: 32, height: 32)
                Text("Your Midnight")
                    .font(.custom("Outfit-Bold", size: 16))
                    .foregroundStyle(.white.opacity(0.92))
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(WalletSection.allCases) { section in
                        SidebarDestinationButton(
                            section: section,
                            isSelected: coordinator.selectedSection == section,
                            badge: badge(for: section),
                            onSelect: { coordinator.selectedSection = section }
                        )
                    }
                }
            }

            Spacer(minLength: 0)

            HStack(spacing: 8) {
                Image(systemName: "flame.fill")
                    .foregroundStyle(WalletChrome.dustGold)
                Text("\(WalletDisplay.formattedDustCompact(fromRaw: coordinator.overview?.balances.dust.spendableRaw))  •  \(WalletDisplay.estimatedTransactionText(fromDustRaw: coordinator.overview?.balances.dust.spendableRaw))")
                    .font(WalletTypography.caption)
                    .foregroundStyle(WalletChrome.dustInk)
                    .lineLimit(1)
                    .minimumScaleFactor(0.75)
            }
            .padding(.horizontal, 2)
        }
        .padding(20)
        .frame(minWidth: 310, idealWidth: 320, maxWidth: 340, maxHeight: .infinity, alignment: .topLeading)
        .background(WalletChrome.background)
    }

    private func badge(for section: WalletSection) -> String? {
        switch section {
        case .messages:
            return unreadCount > 0 ? "\(unreadCount)" : nil
        default:
            return nil
        }
    }
}

private struct SidebarDestinationButton: View {
    let section: WalletSection
    let isSelected: Bool
    let badge: String?
    let onSelect: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: 12) {
                Image(systemName: section.systemImage)
                    .font(.system(size: 14, weight: .semibold))
                    .frame(width: 18)
                Text(section.title)
                    .font(WalletTypography.bodyStrong)
                Spacer(minLength: 0)
                if let badge {
                    Text(badge)
                        .font(WalletTypography.badge)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            section == .dust ? WalletChrome.dustFill : WalletChrome.midnightBlue.opacity(0.14),
                            in: Capsule()
                        )
                        .foregroundStyle(section == .dust ? WalletChrome.dustInk : WalletChrome.midnightBlue)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(
                isSelected ? AnyShapeStyle(WalletChrome.midnightBlue.opacity(0.22)) : AnyShapeStyle(Color.white.opacity(0.04)),
                in: RoundedRectangle(cornerRadius: 16)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(isSelected ? WalletChrome.midnightBlue.opacity(0.45) : WalletChrome.panelStroke, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

private struct SidebarStatCapsule: View {
    enum Style {
        case standard
        case dust
    }

    let title: String
    let value: String
    let style: Style

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(WalletTypography.caption)
                .foregroundStyle(style == .dust ? WalletChrome.dustInk.opacity(0.8) : .secondary)
                .lineLimit(1)
            Text(value)
                .font(WalletTypography.bodyStrong)
                .foregroundStyle(style == .dust ? WalletChrome.dustInk : .primary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(style == .dust ? WalletChrome.dustFill : Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(style == .dust ? WalletChrome.dustStroke : WalletChrome.panelStroke, lineWidth: 1)
        )
    }
}
#endif

private struct HeaderBar: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 18) {
                Text((coordinator.selectedSection ?? .overview).title)
                    .font(WalletTypography.heroTitle)
                Spacer()
#if os(macOS)
                HStack(spacing: 10) {
                    HeaderStatusPill(value: coordinator.configuration?.networkId.capitalized ?? "Preprod", tone: networkTone)
                    HeaderStatusPill(value: activeProverLabel, tone: proverTone)
                }
#endif
                Button("Refresh") {
                    WalletBrandAssets.Haptics.tapLight()
                    Task { await coordinator.refresh() }
                }
                .buttonStyle(SecondaryWalletButtonStyle())
                Button("Lock") {
                    WalletBrandAssets.Haptics.tapLight()
                    Task { await coordinator.lock() }
                }
                .buttonStyle(SecondaryWalletButtonStyle())
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 16)

            if coordinator.isBusy {
                BrandedLoadingBar()
                    .frame(height: 2)
                    .padding(.horizontal, 28)
                    .padding(.bottom, 16)
            }

            if coordinator.statusMessage != nil || coordinator.lastSubmittedTransactionID != nil {
                StatusBanner(
                    message: coordinator.statusMessage
                        ?? coordinator.lastSubmittedTransactionID.map { "Submitted transaction: \($0)" }
                )
                .padding(.horizontal, 28)
                .padding(.bottom, 16)
            }

            Divider()
        }
        .background(WalletChrome.headerMaterial)
    }

    private var activeProverLabel: String {
        guard coordinator.helperExecutionAvailability.isAvailable else {
            return "Unavailable"
        }
        if let activeURL = coordinator.configuration?.proverServerUri,
           let route = coordinator.configuration?.proveRoutes?.first(where: { $0.proofServerUrl == activeURL }),
           route.kind == "upstream"
        {
            return "Upstream"
        }
        return coordinator.configuration == nil ? "Unavailable" : "Local ZirOS"
    }

    private var networkTone: HeaderStatusPill.Tone {
        guard let overview = coordinator.overview else { return .disconnected }
        return (overview.sync.synced || overview.sync.shieldedConnected || overview.sync.unshieldedConnected || overview.sync.dustConnected)
            ? .connected
            : .disconnected
    }

    private var proverTone: HeaderStatusPill.Tone {
        switch activeProverLabel {
        case "Local ZirOS":
            return .connected
        case "Upstream":
            return .warning
        default:
            return .disconnected
        }
    }

    private var unreadCount: Int {
        coordinator.conversations.reduce(0) { $0 + $1.unreadCount }
    }
}

private struct HeaderStatusPill: View {
    enum Tone {
        case connected
        case warning
        case disconnected
    }

    let value: String
    let tone: Tone

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(dotColor)
                .frame(width: 7, height: 7)
            Text(value)
                .foregroundStyle(WalletChrome.midnightBlue)
        }
        .font(WalletTypography.caption)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(WalletChrome.midnightBlue.opacity(0.12), in: Capsule())
        .overlay(
            Capsule()
                .stroke(WalletChrome.midnightBlue.opacity(0.18), lineWidth: 1)
        )
    }

    private var dotColor: Color {
        switch tone {
        case .connected:
            return WalletBrandAssets.Color.success
        case .warning:
            return WalletBrandAssets.Color.warning
        case .disconnected:
            return WalletBrandAssets.Color.critical
        }
    }
}

private struct OverviewScreen: View {
    @Bindable var coordinator: WalletCoordinator

    private let dustPerTransactionRaw: Double = 1_000_000
    private let dustTargetFor100TransactionsRaw: Double = 100_000_000

    private var shieldedNight: Double {
        numericValue(coordinator.overview?.balances.shielded["NIGHT"])
    }

    private var unshieldedNight: Double {
        numericValue(coordinator.overview?.balances.unshielded["NIGHT"])
    }

    private var totalNight: Double {
        shieldedNight + unshieldedNight
    }

    private var dustRaw: Double {
        numericValue(coordinator.overview?.balances.dust.spendableRaw)
    }

    private var estimatedTransactionsRemaining: Int {
        Int((dustRaw / dustPerTransactionRaw).rounded(.down))
    }

    private var shieldedRatio: Double {
        shieldedNight / max(totalNight, 0.0001)
    }

    private var visibleActivity: [WalletActivityEntry] {
#if os(iOS)
        Array(coordinator.activity.prefix(3))
#else
        Array(coordinator.activity.prefix(5))
#endif
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if let message = coordinator.helperExecutionAvailability.message {
                HelperAvailabilityBanner(message: message)
            }

            WalletPanel {
                overviewHero
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Core Holdings")
                        .font(WalletTypography.sectionTitle)
                    HStack {
                        Text("Wallet Status")
                            .font(WalletTypography.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(coordinator.overview?.sync.synced == true ? "Synced" : "Catching Up")
                            .font(WalletTypography.badge)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(
                                (coordinator.overview?.sync.synced == true ? WalletChrome.midnightBlue.opacity(0.14) : WalletChrome.dustFill),
                                in: Capsule()
                            )
                    }
                    metricGrid
                    Divider()
                    statusRow("Shielded sync", value: yesNo(coordinator.overview?.sync.shieldedConnected))
                    statusRow("Unshielded sync", value: yesNo(coordinator.overview?.sync.unshieldedConnected))
                    statusRow("DUST sync", value: yesNo(coordinator.overview?.sync.dustConnected))
                    statusRow("Address set", value: coordinator.overview == nil ? "Unavailable" : "Ready")
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 14) {
                    Text("Address Summary")
                        .font(WalletTypography.sectionTitle)
                    AddressSummaryRow(title: "Shielded", value: coordinator.overview?.addresses.shieldedAddress ?? "Unavailable")
                    AddressSummaryRow(title: "Unshielded", value: coordinator.overview?.addresses.unshieldedAddress ?? "Unavailable")
                    AddressSummaryRow(title: "DUST", value: coordinator.overview?.addresses.dustAddress ?? "Unavailable")
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("Recent Activity")
                            .font(WalletTypography.sectionTitle)
                        Spacer()
                        Button("See All") {
                            WalletBrandAssets.Haptics.tapLight()
                            coordinator.selectedSection = .more
                        }
                        .buttonStyle(.borderless)
                    }
                    if visibleActivity.isEmpty {
                        WalletEmptyState(
                            title: "No activity yet",
                            message: "Proof-backed transfers, shield operations, and DUST moves appear here once the wallet starts moving funds.",
                            actionTitle: "Open Transact",
                            action: {
                                WalletBrandAssets.Haptics.tapLight()
                                coordinator.selectedSection = .transact
                            }
                        )
                    } else {
                        ForEach(visibleActivity) { entry in
                            ActivityRow(entry: entry)
                            if entry.id != visibleActivity.last?.id {
                                Divider()
                            }
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var overviewHero: some View {
#if os(iOS)
        VStack(alignment: .leading, spacing: 22) {
            balanceCluster
            HStack {
                Spacer()
                DustFuelRing(
                    currentDust: dustRaw,
                    targetDustFor100Txns: dustTargetFor100TransactionsRaw,
                    estimatedTransactionsRemaining: estimatedTransactionsRemaining,
                    style: .hero
                )
                Spacer()
            }
            quickActions
        }
#else
        HStack(alignment: .top, spacing: 28) {
            VStack(alignment: .leading, spacing: 24) {
                balanceCluster
                quickActions
            }
            Spacer(minLength: 0)
            VStack(spacing: 16) {
                DustFuelRing(
                    currentDust: dustRaw,
                    targetDustFor100Txns: dustTargetFor100TransactionsRaw,
                    estimatedTransactionsRemaining: estimatedTransactionsRemaining,
                    style: .hero
                )
                DUSTSummaryPill(
                    title: "Spendable DUST",
                    value: WalletDisplay.formattedDustCompact(fromRaw: coordinator.overview?.balances.dust.spendableRaw),
                    detail: WalletDisplay.estimatedTransactionText(fromDustRaw: coordinator.overview?.balances.dust.spendableRaw)
                )
            }
            .frame(width: 260)
        }
#endif
    }

    private var balanceCluster: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 8) {
                Text(WalletDisplay.formattedNightPrimary(Decimal(totalNight)))
                    .font(WalletTypography.balanceHero)
                    .foregroundStyle(.primary)
                    .contentTransition(.numericText())
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)
                Text("NIGHT")
                    .font(WalletTypography.bodyStrong)
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
            }

            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Privacy Posture")
                        .font(WalletTypography.sectionTitle)
                    Spacer()
                    Text("\(Int((shieldedRatio * 100).rounded()))% shielded")
                        .font(WalletTypography.bodyStrong)
                        .foregroundStyle(WalletChrome.midnightBlue)
                }
                PrivacyGauge(shielded: shieldedNight, unshielded: unshieldedNight)
            }
        }
    }

    private var quickActions: some View {
        HStack(spacing: 14) {
            OverviewQuickActionButton(title: "Send", systemImage: "arrow.up", filled: true) {
                WalletBrandAssets.Haptics.tapLight()
                coordinator.selectedSection = .transact
                coordinator.selectedTransactMode = .send
            }
            OverviewQuickActionButton(title: "Receive", systemImage: "arrow.down", filled: false) {
                WalletBrandAssets.Haptics.tapLight()
                coordinator.selectedSection = .transact
                coordinator.selectedTransactMode = .receive
            }
            OverviewQuickActionButton(title: "Shield", systemImage: "lock.fill", filled: false) {
                WalletBrandAssets.Haptics.tapLight()
                coordinator.selectedSection = .transact
                coordinator.selectedTransactMode = .shield
            }
            OverviewQuickActionButton(title: "Unshield", systemImage: "lock.open.fill", filled: false) {
                WalletBrandAssets.Haptics.tapLight()
                coordinator.selectedSection = .transact
                coordinator.selectedTransactMode = .unshield
            }
        }
    }

    private var metricGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 16)], spacing: 16) {
            WalletMetricCard(
                title: "Shielded NIGHT",
                value: WalletDisplay.formattedNightPrimary(Decimal(shieldedNight)),
                detail: "Private balance"
            )
            WalletMetricCard(
                title: "Unshielded NIGHT",
                value: WalletDisplay.formattedNightPrimary(Decimal(unshieldedNight)),
                detail: "Spendable base layer"
            )
            WalletMetricCard(
                title: "DUST",
                value: WalletDisplay.formattedDustCompact(fromRaw: coordinator.overview?.balances.dust.spendableRaw),
                detail: WalletDisplay.estimatedTransactionText(fromDustRaw: coordinator.overview?.balances.dust.spendableRaw),
                style: .dust
            )
            WalletMetricCard(
                title: "Registered NIGHT UTXOs",
                value: "\(coordinator.overview?.balances.dust.registeredNightUtxos ?? 0)",
                detail: "Eligible for DUST",
                style: .dust
            )
        }
    }

    private func yesNo(_ value: Bool?) -> String {
        value == true ? "Connected" : "Offline"
    }

    private func numericValue(_ raw: String?) -> Double {
        guard let raw else { return 0 }
        let normalized = raw.replacingOccurrences(of: ",", with: "")
        if let decimal = Decimal(string: normalized, locale: Locale(identifier: "en_US_POSIX")) {
            return NSDecimalNumber(decimal: decimal).doubleValue
        }
        return Double(normalized) ?? 0
    }

    private func statusRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
        }
    }
}

private struct MessagesScreen: View {
    @Bindable var coordinator: WalletCoordinator

    private var spendableDustRaw: String {
        coordinator.overview?.balances.dust.spendableRaw ?? "0"
    }

    private let estimatedDustCostRaw: UInt64 = 1_000_000

    private var spendableDustValue: UInt64 {
        UInt64(spendableDustRaw) ?? 0
    }

    private var estimatedMessagesRemaining: String {
        WalletDisplay.estimatedPostText(fromDustRaw: spendableDustRaw, costRaw: "\(estimatedDustCostRaw)")
    }

    private var hasDustBudget: Bool {
        spendableDustValue >= estimatedDustCostRaw
    }

    private var lowDustReason: String? {
        guard coordinator.snapshot?.messagingStatus?.available == true else {
            return nil
        }
        guard !hasDustBudget else {
            return nil
        }
        return "Low DUST. Messages spend DUST on the mailbox lane. Generate or redesignate DUST before sending."
    }

    private var sendDisabled: Bool {
        coordinator.selectedConversationPeerID == nil
            || coordinator.snapshot?.messagingStatus?.available != true
            || !hasDustBudget
    }

    private var receiptDisabled: Bool {
        coordinator.snapshot?.messagingStatus?.available != true || !hasDustBudget
    }

    private var encryptionStatusLine: String {
        guard let rotatedAt = coordinator.activeConversationStatus?.lastRotatedAt else {
            return "Epoch rotated just now"
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return "Epoch rotated \(formatter.localizedString(for: rotatedAt, relativeTo: Date()))"
    }

    var body: some View {
#if os(macOS)
        HStack(alignment: .top, spacing: 18) {
            conversationList
                .frame(minWidth: 320, maxWidth: 360)
            conversationDetail
                .frame(maxWidth: .infinity, alignment: .topLeading)
        }
#else
        VStack(alignment: .leading, spacing: 18) {
            conversationList
            conversationDetail
        }
#endif
    }

    private var conversationList: some View {
        VStack(alignment: .leading, spacing: 16) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 14) {
                    messagesHeader

                    if let reason = coordinator.snapshot?.messagingStatus?.reason {
                        HelperAvailabilityBanner(message: reason)
                    }
                    if let lowDustReason {
                        HStack(alignment: .center, spacing: 14) {
                            Image(systemName: "flame.fill")
                                .foregroundStyle(WalletChrome.dustInk)
                            VStack(alignment: .leading, spacing: 6) {
                                Text("DUST Fuel Low")
                                    .font(WalletTypography.sectionTitle)
                                Text(lowDustReason)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Open DUST") {
                                WalletBrandAssets.Haptics.warning()
                                coordinator.selectedSection = .dust
                            }
                            .buttonStyle(SecondaryWalletButtonStyle())
                        }
                        .padding(16)
                        .background(WalletChrome.dustFill, in: RoundedRectangle(cornerRadius: 18))
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(WalletChrome.dustStroke, lineWidth: 1)
                        )
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Text("Peer Invite JSON")
                            .font(WalletTypography.caption)
                            .foregroundStyle(.secondary)
                        TextEditor(text: $coordinator.remoteInviteJSON)
                            .font(.system(.caption, design: .monospaced))
                            .frame(minHeight: 110)
                            .padding(10)
                            .background(WalletChrome.codeBackground, in: RoundedRectangle(cornerRadius: 16))
                        Button("Open Channel With Invite") {
                            Task { await coordinator.openMessagingChannel() }
                        }
                        .buttonStyle(PrimaryWalletButtonStyle())
                    }
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Conversations")
                            .font(WalletTypography.sectionTitle)
                        Spacer()
                        Text("\(coordinator.conversations.count)")
                            .font(WalletTypography.badge)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(WalletChrome.badgeBackground, in: Capsule())
                    }
                    if coordinator.conversations.isEmpty {
                        WalletEmptyState(
                            title: "Start an encrypted conversation",
                            message: "Paste a peer invite to open a post-quantum channel with DUST-backed delivery.",
                            actionTitle: "Open Channel",
                            action: {
                                WalletBrandAssets.Haptics.tapLight()
                                Task { await coordinator.openMessagingChannel() }
                            },
                            motifSize: 60
                        )
                    } else {
                        ForEach(coordinator.conversations) { conversation in
                            ConversationRow(
                                conversation: conversation,
                                isSelected: coordinator.selectedConversationPeerID == conversation.peerId,
                                onSelect: { coordinator.selectConversation(peerID: conversation.peerId) }
                            )
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var messagesHeader: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Midnight Messages")
                        .font(WalletTypography.sectionTitle)
                    Text("DUST-powered messaging. Rust-owned approvals.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                DustFuelChip(value: spendableDustRaw, remaining: estimatedMessagesRemaining)
            }
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Midnight Messages")
                        .font(WalletTypography.sectionTitle)
                    Text("DUST-powered messaging. Rust-owned approvals.")
                        .foregroundStyle(.secondary)
                }
                HStack {
                    Spacer()
                    DustFuelChip(value: spendableDustRaw, remaining: estimatedMessagesRemaining)
                }
            }
        }
    }

    private var conversationDetail: some View {
        VStack(alignment: .leading, spacing: 18) {
            if coordinator.conversations.isEmpty {
                WalletPanel {
                    WalletEmptyState(
                        title: "Start an encrypted conversation",
                        message: "Open a channel to begin secure Midnight messaging.",
                        actionTitle: "Open Channel",
                        action: {
                            WalletBrandAssets.Haptics.tapLight()
                            Task { await coordinator.openMessagingChannel() }
                        },
                        motifSize: 60
                    )
                }
            } else {
            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text(coordinator.activeConversationStatus?.remoteInvite?.displayName
                                 ?? coordinator.selectedConversationPeerID
                                 ?? "No Conversation Selected")
                                .font(WalletTypography.heroTitle)
                            Text(coordinator.activeConversationStatus?.state.capitalized ?? "Awaiting selection")
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if coordinator.activeConversationStatus != nil {
                            Button("Copy My Invite") {
                                WalletBrandAssets.Haptics.tapMedium()
                                coordinator.copyLocalInvite()
                            }
                            .buttonStyle(SecondaryWalletButtonStyle())
                            Button("Close Channel") {
                                WalletBrandAssets.Haptics.tapLight()
                                coordinator.closeSelectedConversation()
                            }
                            .buttonStyle(SecondaryWalletButtonStyle())
                        }
                    }
                    MessagingEncryptionBadge(rotationLine: encryptionStatusLine)
                    if let localInvite = coordinator.activeConversationStatus?.localInvite {
                        PolicyRow(label: "Channel", value: localInvite.channelId)
                    }
                    if let reason = coordinator.activeConversationStatus?.reason {
                        Text(reason)
                            .foregroundStyle(WalletChrome.warningAccent)
                    }
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Conversation")
                        .font(WalletTypography.sectionTitle)
                    if coordinator.activeMessages.isEmpty {
                        WalletEmptyState(
                            title: "No decrypted messages yet",
                            message: "Once the mailbox lane posts or polls an envelope, the decrypted transcript appears here.",
                            actionTitle: "Copy Invite",
                            action: {
                                WalletBrandAssets.Haptics.tapMedium()
                                coordinator.copyLocalInvite()
                            }
                        )
                    } else {
                        ForEach(coordinator.activeMessages) { message in
                            MessageBubble(
                                message: message,
                                onVerifyReceipt: { receipt in
                                    coordinator.openExplorerTransaction(txHash: receipt.txHash)
                                }
                            )
                        }
                    }
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Compose")
                        .font(WalletTypography.sectionTitle)
                    if let reason = coordinator.snapshot?.messagingStatus?.reason {
                        Text(reason)
                            .foregroundStyle(WalletChrome.warningAccent)
                    }
                    MessagingEncryptionBadge(rotationLine: encryptionStatusLine)
                    TextEditor(text: $coordinator.messageComposerText)
                        .frame(minHeight: 120)
                        .padding(10)
                        .background(WalletChrome.codeBackground, in: RoundedRectangle(cornerRadius: 16))
                    HStack {
                        Text("Estimated DUST cost: \(WalletDisplay.formattedDustCompact(fromRaw: "\(estimatedDustCostRaw)"))")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(WalletChrome.dustInk)
                        Spacer()
                        Button("Send Text Message") {
                            WalletBrandAssets.Haptics.tapLight()
                            Task { await coordinator.sendMessage() }
                        }
                        .buttonStyle(PrimaryWalletButtonStyle())
                        .disabled(sendDisabled)
                    }
                    if let selected = coordinator.selectedConversationPeerID, !coordinator.activity.isEmpty {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Recent receipts for \(selected)")
                                .font(WalletTypography.caption)
                                .foregroundStyle(.secondary)
                            ForEach(Array(coordinator.activity.prefix(3))) { entry in
                                Button {
                                    WalletBrandAssets.Haptics.tapLight()
                                    Task { await coordinator.sendTransferReceipt(from: entry) }
                                } label: {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(entry.hash)
                                                .font(.system(.body, design: .monospaced))
                                            Text(entry.timestamp.formatted(date: .abbreviated, time: .shortened))
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                        }
                                        Spacer()
                                        Text("Send Receipt")
                                            .fontWeight(.semibold)
                                    }
                                    .padding(12)
                                    .background(WalletChrome.selectionFill(isSelected: false), in: RoundedRectangle(cornerRadius: 14))
                                }
                                .buttonStyle(.plain)
                                .disabled(receiptDisabled)
                            }
                        }
                    }
                }
            }
            }
        }
    }
}

private struct TransactScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: WalletChrome.cardSpacing) {
            transactModeSelector
            transactDetail
        }
    }

    @ViewBuilder
    private var transactDetail: some View {
        switch coordinator.selectedTransactMode {
        case .send:
            SendScreen(coordinator: coordinator)
        case .receive:
            ReceiveScreen(coordinator: coordinator)
        case .shield:
            ShieldScreen(coordinator: coordinator)
        case .unshield:
            ShieldScreen(coordinator: coordinator, mode: .unshield)
        }
    }

    @ViewBuilder
    private var transactModeSelector: some View {
        HStack(spacing: 8) {
            ForEach(TransactMode.allCases) { mode in
                Button {
                    WalletBrandAssets.Haptics.tapLight()
                    coordinator.selectedTransactMode = mode
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: mode.systemImage)
                        Text(mode.title)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity)
                    .frame(minHeight: 40)
                    .background(
                        WalletChrome.selectionFill(isSelected: coordinator.selectedTransactMode == mode),
                        in: RoundedRectangle(cornerRadius: 12)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(
                                coordinator.selectedTransactMode == mode ? WalletChrome.midnightBlue.opacity(0.55) : WalletChrome.panelStroke,
                                lineWidth: 1
                            )
                    )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(4)
        .background(WalletChrome.cardBackground, in: RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(WalletChrome.panelStroke, lineWidth: 1)
        )
    }
}

private struct SendScreen: View {
    @Bindable var coordinator: WalletCoordinator

    private let estimatedFeeRaw = "1000000"

    private var sendFormIsValid: Bool {
        !coordinator.sendRecipient.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && WalletDisplay.isPositiveRawNight(coordinator.sendAmountRaw)
    }

    var body: some View {
        WalletPanel {
            VStack(alignment: .leading, spacing: 18) {
                Text("Send NIGHT")
                    .font(WalletTypography.sectionTitle)
                Text(sendSubtitle)
                    .foregroundStyle(.secondary)
                if let message = coordinator.helperExecutionAvailability.message {
                    HelperAvailabilityBanner(message: message)
                }
                LabeledField(title: "Recipient") {
                    WalletInputSurface {
                        HStack(spacing: 10) {
                            TextField("midnight1...", text: $coordinator.sendRecipient)
                                .textFieldStyle(.plain)
                                .font(.system(.body, design: .monospaced))
                            Button {
                                WalletBrandAssets.Haptics.tapMedium()
                                coordinator.sendRecipient = WalletPlatformSupport.pastedString() ?? coordinator.sendRecipient
                            } label: {
                                Image(systemName: "doc.on.clipboard")
                            }
                            .buttonStyle(.plain)
                            Button {
                                coordinator.statusMessage = "QR scanning is not available in the current macOS beta."
                            } label: {
                                Image(systemName: "qrcode.viewfinder")
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(.secondary)
                        }
                    }
                }
                NightAmountField(
                    title: "Amount",
                    amountDisplay: coordinator.sendAmountDisplay,
                    rawAmount: coordinator.sendAmountRaw,
                    placeholder: "0.000",
                    onChange: coordinator.updateSendAmountDisplay,
                    onMax: coordinator.fillMaxSendAmount
                )
                Toggle("Send to shielded receiver", isOn: $coordinator.sendShielded)
                    .toggleStyle(.switch)
                    .tint(WalletChrome.midnightBlue)
                WalletInfoCard(accent: coordinator.sendShielded ? WalletChrome.midnightBlue : Color.white.opacity(0.18)) {
                    HStack(spacing: 10) {
                        Image(systemName: coordinator.sendShielded ? "shield.fill" : "eye")
                            .foregroundStyle(coordinator.sendShielded ? WalletChrome.midnightBlue : .secondary)
                        Text(coordinator.sendShielded ? "Amount hidden from public view." : "Amount visible on-chain.")
                            .foregroundStyle(.secondary)
                    }
                }
                if sendFormIsValid {
                    Text("Estimated fee: \(WalletDisplay.formattedDustFee(fromRaw: estimatedFeeRaw))")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(WalletChrome.dustInk)
                }
                Text("Second \(WalletPlatformSupport.biometricLabel) confirmation is enforced automatically above 100 NIGHT.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: 14) {
                    Button("Review & Send") {
                        WalletBrandAssets.Haptics.tapLight()
                        Task { await coordinator.beginSend() }
                    }
                    .buttonStyle(PrimaryWalletButtonStyle())
                    .disabled(!coordinator.helperExecutionAvailability.isAvailable || !sendFormIsValid)
                }
            }
        }
    }

    private var sendSubtitle: String {
        "Enter NIGHT, review the fee, and confirm with \(WalletPlatformSupport.biometricLabel)."
    }
}

private struct ReceiveScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            if let message = coordinator.helperExecutionAvailability.message {
                HelperAvailabilityBanner(message: message)
            }
            AddressCard(title: shieldedTitle, value: coordinator.overview?.addresses.shieldedAddress)
            AddressCard(title: unshieldedTitle, value: coordinator.overview?.addresses.unshieldedAddress)
            AddressCard(title: dustTitle, value: coordinator.overview?.addresses.dustAddress)
        }
    }

    private var shieldedTitle: String {
#if os(iOS)
        "Shielded"
#else
        "Shielded Address"
#endif
    }

    private var unshieldedTitle: String {
#if os(iOS)
        "Unshielded"
#else
        "Unshielded Address"
#endif
    }

    private var dustTitle: String {
#if os(iOS)
        "DUST"
#else
        "DUST Address"
#endif
    }
}

private struct ShieldScreen: View {
    enum Mode {
        case shield
        case unshield
    }

    @Bindable var coordinator: WalletCoordinator
    let mode: Mode

    private let estimatedFeeRaw = "1000000"

    init(coordinator: WalletCoordinator, mode: Mode = .shield) {
        self.coordinator = coordinator
        self.mode = mode
    }

    var body: some View {
        VStack(alignment: .leading, spacing: WalletChrome.cardSpacing) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 16) {
                    Text(mode == .shield ? "Shield NIGHT" : "Unshield NIGHT")
                        .font(WalletTypography.sectionTitle)
                    Text(modeSubtitle)
                        .foregroundStyle(.secondary)
                    if let message = coordinator.helperExecutionAvailability.message {
                        HelperAvailabilityBanner(message: message)
                    }
                    balanceSummary(
                        title: mode == .shield ? "Available Balance" : "Shielded Balance",
                        value: mode == .shield
                            ? WalletDisplay.formattedNightMetric(fromDisplay: coordinator.overview?.balances.unshielded["NIGHT"])
                            : WalletDisplay.formattedNightMetric(fromDisplay: coordinator.overview?.balances.shielded["NIGHT"])
                    )
                    NightAmountField(
                        title: "Amount",
                        amountDisplay: mode == .shield ? coordinator.shieldAmountDisplay : coordinator.unshieldAmountDisplay,
                        rawAmount: mode == .shield ? coordinator.shieldAmountRaw : coordinator.unshieldAmountRaw,
                        placeholder: "0.000",
                        onChange: { value in
                            if mode == .shield {
                                coordinator.updateShieldAmountDisplay(value)
                            } else {
                                coordinator.updateUnshieldAmountDisplay(value)
                            }
                        },
                        onMax: {
                            if mode == .shield {
                                coordinator.fillMaxShieldAmount()
                            } else {
                                coordinator.fillMaxUnshieldAmount()
                            }
                        }
                    )
                    Text("Estimated fee: \(WalletDisplay.formattedDustFee(fromRaw: estimatedFeeRaw))")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(WalletChrome.dustInk)
                    Button(mode == .shield ? "Review & Shield" : "Review & Unshield") {
                        WalletBrandAssets.Haptics.tapLight()
                        Task {
                            if mode == .shield {
                                await coordinator.beginShield()
                            } else {
                                await coordinator.beginUnshield()
                            }
                        }
                    }
                    .buttonStyle(PrimaryWalletButtonStyle())
                    .disabled(!coordinator.helperExecutionAvailability.isAvailable || !isValid)
                    if mode == .unshield {
                        WalletInfoCard(accent: WalletChrome.panelStroke) {
                            Text("Unshielding moves NIGHT from the private pool to your public balance. The amount becomes visible on-chain.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            if mode == .unshield, !recentUnshieldActivity.isEmpty {
                WalletPanel {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Recent Unshields")
                            .font(WalletTypography.sectionTitle)
                        ForEach(recentUnshieldActivity) { entry in
                            ActivityRow(entry: entry)
                            if entry.id != recentUnshieldActivity.last?.id {
                                Divider()
                            }
                        }
                    }
                }
            }
        }
    }

    private var isValid: Bool {
        WalletDisplay.isPositiveRawNight(mode == .shield ? coordinator.shieldAmountRaw : coordinator.unshieldAmountRaw)
    }

    private var recentUnshieldActivity: [WalletActivityEntry] {
        Array(
            coordinator.activity.filter { entry in
                entry.identifiers.contains { $0.localizedCaseInsensitiveContains("unshield") }
            }
            .prefix(3)
        )
    }

    private var modeSubtitle: String {
        switch mode {
        case .shield:
            return "Move public NIGHT into the private pool with native review and biometric approval."
        case .unshield:
            return "Move private NIGHT back to your public balance for standard spending."
        }
    }

    private func balanceSummary(title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(WalletTypography.caption)
                .foregroundStyle(.secondary)
            Text("\(value) NIGHT")
                .font(.system(size: 28, weight: .bold, design: .monospaced))
                .foregroundStyle(.primary)
        }
    }
}

private struct DustScreen: View {
    @Bindable var coordinator: WalletCoordinator
    @AppStorage("ziros_wallet_dust_explainer_seen") private var hasSeenDustExplainer = false

    private let dustPerTransactionRaw: Double = 1_000_000
    private let dustTargetFor100TransactionsRaw: Double = 100_000_000

    private var dustRaw: Double {
        numericValue(coordinator.overview?.balances.dust.spendableRaw)
    }

    private var estimatedTransactionsRemaining: Int {
        Int((dustRaw / dustPerTransactionRaw).rounded(.down))
    }

    private var selectedCandidates: [DustUtxoCandidate] {
        filteredCandidates.filter { coordinator.selectedDustCandidateIndexes.contains($0.index) }
    }

    private var selectedCandidateTotalNight: String {
        let total = selectedCandidates.reduce(Decimal.zero) { partial, candidate in
            partial + rawNightToDisplay(candidate.valueRaw)
        }
        return total.formatted(.number.precision(.fractionLength(0...2)))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: WalletChrome.cardSpacing) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 16) {
                    Text("DUST")
                        .font(WalletTypography.heroTitle)
                    Text("Fuel for proving, transfers, and encrypted messaging.")
                        .font(WalletTypography.bodyStrong)
                        .foregroundStyle(WalletChrome.dustInk)
                    if let message = coordinator.helperExecutionAvailability.message {
                        HelperAvailabilityBanner(message: message)
                    }

                    HStack {
                        Spacer()
                        DustFuelRing(
                            currentDust: dustRaw,
                            targetDustFor100Txns: dustTargetFor100TransactionsRaw,
                            estimatedTransactionsRemaining: estimatedTransactionsRemaining,
                            style: .dashboard
                        )
                        Spacer()
                    }

                    Text("DUST is the wallet’s live fuel gauge. Select NIGHT outputs, see what is registered, and approve fuel routing deliberately.")
                        .foregroundStyle(.secondary)

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 12) {
                            DUSTSummaryPill(
                                title: "Spendable",
                                value: WalletDisplay.formattedDustCompact(fromRaw: coordinator.overview?.balances.dust.spendableRaw),
                                detail: WalletDisplay.estimatedTransactionText(fromDustRaw: coordinator.overview?.balances.dust.spendableRaw)
                            )
                            DUSTSummaryPill(title: "Registered", value: "\(coordinator.overview?.balances.dust.registeredNightUtxos ?? 0) UTXOs", detail: "fuel generating")
                            DUSTSummaryPill(title: "Generating", value: dustGenerationReadiness, detail: "selection aware")
                        }
                        .padding(.vertical, 2)
                    }

                    Picker("Operation", selection: $coordinator.selectedDustOperation) {
                        ForEach(DustOperationKind.allCases) { operation in
                            Text(operation.rawValue.capitalized).tag(operation)
                        }
                    }
                    .pickerStyle(.segmented)

                    if coordinator.selectedDustOperation != .deregister {
                        LabeledField(title: "DUST Receiver Address") {
                            TextField("midnight1...", text: $coordinator.dustReceiverAddress)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))
                        }
                    }

                    if coordinator.dustCandidates.isEmpty {
                        WalletEmptyState(
                            title: "No NIGHT outputs available",
                            message: "Once the wallet syncs unshielded outputs, they appear here for registration, deregistration, or redesignation.",
                            actionTitle: "Refresh",
                            action: {
                                WalletBrandAssets.Haptics.tapLight()
                                Task { await coordinator.refresh() }
                            }
                        )
                    } else {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(filteredCandidates) { candidate in
                                DustCandidateRow(
                                    candidate: candidate,
                                    isSelected: coordinator.selectedDustCandidateIndexes.contains(candidate.index),
                                    onToggle: { toggle(candidate.index) }
                                )
                            }
                        }
                    }

                    if !selectedCandidates.isEmpty {
                        DUSTActionBar(
                            selectedCount: selectedCandidates.count,
                            totalNight: selectedCandidateTotalNight,
                            selectedOperation: coordinator.selectedDustOperation,
                            onRegister: {
                                WalletBrandAssets.Haptics.tapLight()
                                coordinator.selectedDustOperation = .register
                                Task { await coordinator.beginDustOperation() }
                            },
                            onDeregister: {
                                WalletBrandAssets.Haptics.tapLight()
                                coordinator.selectedDustOperation = .deregister
                                Task { await coordinator.beginDustOperation() }
                            },
                            onRedesignate: {
                                WalletBrandAssets.Haptics.tapLight()
                                coordinator.selectedDustOperation = .redesignate
                                Task { await coordinator.beginDustOperation() }
                            }
                        )
                    }

                    WalletInfoCard(accent: WalletChrome.dustStroke) {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                ClockMotif()
                                    .stroke(WalletChrome.midnightBlue.opacity(0.7), lineWidth: 1.2)
                                    .frame(width: 28, height: 28)
                                Text("What is DUST?")
                                    .font(WalletTypography.bodyStrong)
                            }
                            Text("DUST is Midnight’s fee fuel.")
                            Text("Register NIGHT UTXOs to generate DUST, watch the fuel ring for how many transactions remain, and redesignate output flows when you want to steer fuel elsewhere.")
                                .foregroundStyle(.secondary)
                            if !hasSeenDustExplainer {
                                Button("Understood") {
                                    WalletBrandAssets.Haptics.tapLight()
                                    hasSeenDustExplainer = true
                                }
                                .buttonStyle(SecondaryWalletButtonStyle())
                            }
                        }
                    }
                    .opacity(hasSeenDustExplainer ? 0.82 : 1.0)
                }
            }
        }
    }

    private var filteredCandidates: [DustUtxoCandidate] {
        switch coordinator.selectedDustOperation {
        case .register, .redesignate:
            return coordinator.dustCandidates.filter { !$0.registeredForDustGeneration }
        case .deregister:
            return coordinator.dustCandidates.filter(\.registeredForDustGeneration)
        }
    }

    private func toggle(_ index: Int) {
        WalletBrandAssets.Haptics.tapLight()
        if coordinator.selectedDustCandidateIndexes.contains(index) {
            coordinator.selectedDustCandidateIndexes.remove(index)
        } else {
            coordinator.selectedDustCandidateIndexes.insert(index)
        }
    }

    private var dustGenerationReadiness: String {
        coordinator.selectedDustCandidateIndexes.isEmpty ? "Idle" : "Ready"
    }

    private func numericValue(_ raw: String?) -> Double {
        guard let raw else { return 0 }
        let normalized = raw.replacingOccurrences(of: ",", with: "")
        if let decimal = Decimal(string: normalized, locale: Locale(identifier: "en_US_POSIX")) {
            return NSDecimalNumber(decimal: decimal).doubleValue
        }
        return Double(normalized) ?? 0
    }

    private func formattedInteger(_ value: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.maximumFractionDigits = 0
        return formatter.string(from: NSNumber(value: value.rounded(.down))) ?? "0"
    }

    private func rawNightToDisplay(_ raw: String) -> Decimal {
        let normalized = raw.replacingOccurrences(of: ",", with: "")
        let decimal = Decimal(string: normalized, locale: Locale(identifier: "en_US_POSIX")) ?? 0
        return decimal / Decimal(string: "1000000000000000", locale: Locale(identifier: "en_US_POSIX"))!
    }
}

private struct ActivityScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        WalletPanel {
            VStack(alignment: .leading, spacing: 12) {
                Text("Transaction History")
                    .font(.title2.weight(.bold))
                if let message = coordinator.helperExecutionAvailability.message {
                    HelperAvailabilityBanner(message: message)
                }
                if coordinator.activity.isEmpty {
                    Text("No activity has been synchronized yet.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(coordinator.activity) { entry in
                        ActivityRow(entry: entry)
                        if entry.id != coordinator.activity.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
    }
}

private struct MoreHubScreen: View {
    @Bindable var coordinator: WalletCoordinator
    @State private var selectedPane: MorePane = .activity

    var body: some View {
#if os(macOS)
        VStack(alignment: .leading, spacing: 18) {
            WalletPanel {
                HStack(alignment: .center, spacing: 18) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("More")
                            .font(WalletTypography.sectionTitle)
                        Text("Desktop controls for history, origin permissions, and route configuration.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Picker("Pane", selection: $selectedPane) {
                        ForEach(MorePane.allCases) { pane in
                            Text(pane.title).tag(pane)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 360)
                }
            }

            switch selectedPane {
            case .activity:
                ActivityScreen(coordinator: coordinator)
            case .permissions:
                PermissionsScreen(coordinator: coordinator)
            case .settings:
                SettingsScreen(coordinator: coordinator)
            }
        }
#else
        VStack(alignment: .leading, spacing: 18) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 8) {
                    Text("More")
                        .font(WalletTypography.sectionTitle)
                    Text("Activity, permissions, and settings live here.")
                        .foregroundStyle(.secondary)
                }
            }

            ActivityScreen(coordinator: coordinator)
            PermissionsScreen(coordinator: coordinator)
            SettingsScreen(coordinator: coordinator)
        }
#endif
    }

    private enum MorePane: String, CaseIterable, Identifiable {
        case activity
        case permissions
        case settings

        var id: String { rawValue }

        var title: String {
            switch self {
            case .activity:
                return "Activity"
            case .permissions:
                return "Permissions"
            case .settings:
                return "Settings"
            }
        }
    }
}

private struct PermissionsScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        WalletPanel {
            VStack(alignment: .leading, spacing: 16) {
                Text("DApp Permissions")
                    .font(.title2.weight(.bold))
                Text("Bridge reads stay origin-scoped. Every write request still returns to the native app for review and \(WalletPlatformSupport.biometricLabel). Revoking an origin invalidates queued requests immediately.")
                    .foregroundStyle(.secondary)
                if let grants = coordinator.snapshot?.grants, !grants.isEmpty {
                    ForEach(grants) { grant in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(alignment: .top) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(grant.origin)
                                        .font(.system(.body, design: .monospaced))
                                    Text(grant.scopes.map(\.rawValue).joined(separator: ", "))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Revoke") {
                                    coordinator.revokeOrigin(grant.origin)
                                }
                                .buttonStyle(.bordered)
                            }
                            Divider()
                        }
                    }
                } else {
                    Text("No sites are currently authorized.")
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct SettingsScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Proving Routes")
                        .font(WalletTypography.sectionTitle)
                    Text("The helper prefers the first healthy route. If the active route becomes unhealthy, it reopens the helper session on the next reachable configured prover before any approval sheet is shown.")
                        .foregroundStyle(.secondary)
                    LabeledField(title: "Primary prover URL") {
                        TextField("http://127.0.0.1:6300", text: $coordinator.primaryProverURL)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }
                    LabeledField(title: "Optional fallback prover URL") {
                        TextField("https://prover.example", text: $coordinator.fallbackProverURL)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }
                    LabeledField(title: "Gateway URL") {
                        TextField("http://127.0.0.1:6311", text: $coordinator.gatewayURL)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }
                    Button("Save Settings") {
                        coordinator.saveSettings()
                    }
                    .buttonStyle(PrimaryWalletButtonStyle())
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Current Security Policy")
                        .font(WalletTypography.sectionTitle)
                    PolicyRow(label: "Strict biometrics only", value: "Enabled")
                    PolicyRow(label: "Re-lock on background", value: "Enabled")
                    PolicyRow(label: "Idle relock", value: "\(coordinator.snapshot?.authPolicy?.relockTimeoutSeconds ?? 300) seconds")
                    PolicyRow(label: "Second biometric threshold", value: coordinator.snapshot?.authPolicy?.largeTransferThresholdRaw ?? "100 NIGHT")
                    if let proverRoute = coordinator.configuration?.proveRoutes?.first(where: { $0.proofServerUrl == coordinator.configuration?.proverServerUri }) {
                        PolicyRow(label: "Active prover route", value: proverRoute.label)
                    }
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Messaging Transport")
                        .font(WalletTypography.sectionTitle)
                    PolicyRow(
                        label: "Mailbox lane",
                        value: coordinator.snapshot?.messagingStatus?.available == true ? "Available" : "Unavailable"
                    )
                    PolicyRow(
                        label: "Contract address",
                        value: coordinator.snapshot?.messagingStatus?.mailboxContractAddress
                            ?? coordinator.snapshot?.services?.mailboxContractAddress
                            ?? "Not configured"
                    )
                    PolicyRow(
                        label: "Manifest path",
                        value: coordinator.snapshot?.services?.mailboxManifestPath ?? "Not configured"
                    )
                    if let cursor = coordinator.snapshot?.messagingStatus?.lastObservedCursor {
                        PolicyRow(label: "Last cursor", value: cursor)
                    }
                    if let reason = coordinator.snapshot?.messagingStatus?.reason {
                        Text(reason)
                            .foregroundStyle(WalletChrome.warningAccent)
                    }
                }
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Execution Lane")
                        .font(WalletTypography.sectionTitle)
                    PolicyRow(
                        label: "Helper mode",
                        value: coordinator.helperCompatibilityReport?.mode ?? "Unknown"
                    )
                    PolicyRow(
                        label: "Bridge bootstrap",
                        value: coordinator.helperCompatibilityReport?.bridgeLoaded == true ? "Loaded" : "Unavailable"
                    )
                    PolicyRow(
                        label: "Helper root",
                        value: coordinator.helperCompatibilityReport?.helperRootConfigured == true ? "Configured" : "Missing"
                    )
                    PolicyRow(
                        label: "WebCrypto",
                        value: coordinator.helperCompatibilityReport?.hasWebCrypto == true ? "Available" : "Unavailable"
                    )
                    PolicyRow(
                        label: "randomUUID",
                        value: coordinator.helperCompatibilityReport?.hasRandomUUID == true ? "Available" : "Unavailable"
                    )
                    PolicyRow(
                        label: "WebSocket",
                        value: coordinator.helperCompatibilityReport?.hasWebSocket == true ? "Available" : "Unavailable"
                    )
                    PolicyRow(
                        label: "Runtime ready",
                        value: coordinator.helperCompatibilityReport?.runtimeAvailable == true ? "Yes" : "No"
                    )
                    if let reason = coordinator.helperCompatibilityReport?.reason {
                        Text(reason)
                            .foregroundStyle(WalletChrome.warningAccent)
                    }
                }
            }
        }
    }
}

private struct SitePermissionSheet: View {
    let request: PendingSitePermissionRequest
    let onApprove: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Authorize DApp")
                .font(.title2.weight(.bold))
            Text(request.origin)
                .font(.system(.title3, design: .monospaced))
            Text("This site is requesting Midnight wallet access on \(request.networkId). Read methods remain origin-scoped. Any write request still requires native review, \(WalletPlatformSupport.biometricLabel), and a Rust-issued single-use submission grant.")
                .foregroundStyle(.secondary)
            HStack(spacing: 16) {
                Button("Authorize Site", action: onApprove)
                    .buttonStyle(PrimaryWalletButtonStyle())
                Button("Reject", action: onReject)
                    .buttonStyle(SecondaryWalletButtonStyle())
            }
            Spacer()
        }
        .padding(28)
#if os(macOS)
        .frame(minWidth: 560, minHeight: 260)
#endif
    }
}

private struct ApprovalSheet: View {
    let flow: PendingApprovalFlow
    let onApprove: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            approvalHeader
            amountHero
            detailsCard

            if !flow.review.warnings.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(flow.review.warnings, id: \.self) { warning in
                        WarningBanner(message: warning)
                    }
                }
            }

            VStack(spacing: 12) {
                Button("Approve With \(WalletPlatformSupport.biometricLabel)", action: onApprove)
                    .buttonStyle(PrimaryWalletButtonStyle())
                    .frame(maxWidth: .infinity)
                Button("Reject", action: onReject)
                    .buttonStyle(SecondaryWalletButtonStyle())
                    .frame(maxWidth: .infinity)
            }
        }
        .padding(28)
#if os(macOS)
        .frame(minWidth: 700, minHeight: 520)
#endif
    }

    private var approvalHeader: some View {
        WalletInfoCard(accent: WalletChrome.midnightBlue.opacity(0.18)) {
            HStack(spacing: 14) {
                Image(systemName: headerIcon)
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(WalletChrome.midnightBlue)
                VStack(alignment: .leading, spacing: 4) {
                    Text(headerTitle)
                        .font(WalletTypography.sectionTitle)
                    Text("Review before \(WalletPlatformSupport.biometricLabel)")
                        .font(WalletTypography.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var amountHero: some View {
        VStack(alignment: .center, spacing: 8) {
            Text(heroAmount)
                .font(.system(size: 36, weight: .bold, design: .monospaced))
                .foregroundStyle(.primary)
                .frame(maxWidth: .infinity, alignment: .center)
                .multilineTextAlignment(.center)
            if let feeLine {
                Text(feeLine)
                    .font(.system(size: 17, weight: .medium, design: .monospaced))
                    .foregroundStyle(WalletChrome.dustInk)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
            Text(flow.review.humanSummary)
                .font(WalletTypography.bodyStrong)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity, alignment: .center)
        }
    }

    private var detailsCard: some View {
        WalletInfoCard(accent: WalletChrome.panelStroke) {
            VStack(alignment: .leading, spacing: 14) {
                if let transaction = flow.review.transaction {
                    ApprovalDetailRow(label: "Recipient", value: transaction.outputs.first?.recipient ?? "Hidden")
                    ApprovalDetailRow(label: "Token", value: transaction.outputs.first?.tokenKind ?? "NIGHT")
                    ApprovalDetailRow(label: "Shielded", value: transaction.shielded ? "Yes" : "No")
                    ApprovalDetailRow(label: "Prover", value: transaction.proverRoute ?? "Unavailable")
                    ApprovalDetailRow(label: "Network", value: transaction.network.capitalized)
                    ApprovalDetailRow(label: "Fee", value: WalletDisplay.formattedDustCompact(fromRaw: transaction.feeRaw))
                    if let dustImpact = transaction.dustImpact {
                        ApprovalDetailRow(label: "DUST Impact", value: dustImpact)
                    }
                    if !transaction.outputs.isEmpty {
                        Divider()
                        ForEach(transaction.outputs) { output in
                            VStack(alignment: .leading, spacing: 4) {
                                Text("\(WalletDisplay.formattedNightPrimary(fromRaw: output.amountRaw)) \(output.tokenKind)")
                                    .font(WalletTypography.bodyStrong)
                                Text(output.recipient)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } else if let channelOpen = flow.review.channelOpen {
                    ApprovalDetailRow(label: "Peer", value: channelOpen.displayName ?? channelOpen.peerId)
                    ApprovalDetailRow(label: "Network", value: channelOpen.network.capitalized)
                    ApprovalDetailRow(label: "Digest", value: channelOpen.txDigest)
                } else if let messageSend = flow.review.messageSend {
                    ApprovalDetailRow(label: "Peer", value: messageSend.peerId)
                    ApprovalDetailRow(label: "Channel", value: messageSend.channelId)
                    ApprovalDetailRow(label: "Message Kind", value: messageSend.messageKind)
                    ApprovalDetailRow(label: "Network", value: messageSend.network.capitalized)
                    ApprovalDetailRow(label: "Fee", value: WalletDisplay.formattedDustCompact(fromRaw: messageSend.dustCostRaw))
                    Divider()
                    Text(messageSend.messagePreview)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var headerTitle: String {
        if let transaction = flow.review.transaction {
            return transaction.origin == "native://wallet" ? "ZirOS Wallet" : transaction.origin
        }
        if let channelOpen = flow.review.channelOpen {
            return channelOpen.origin == "native://wallet" ? "ZirOS Wallet" : channelOpen.origin
        }
        if let messageSend = flow.review.messageSend {
            return messageSend.origin == "native://wallet" ? "ZirOS Wallet" : messageSend.origin
        }
        return "ZirOS Wallet"
    }

    private var headerIcon: String {
        headerTitle == "ZirOS Wallet" ? "clock" : "globe"
    }

    private var heroAmount: String {
        if let transaction = flow.review.transaction {
            return "\(WalletDisplay.formattedNightPrimary(fromRaw: transaction.nightTotalRaw)) NIGHT"
        }
        if let messageSend = flow.review.messageSend {
            return WalletDisplay.formattedDustCompact(fromRaw: messageSend.dustCostRaw)
        }
        if let channelOpen = flow.review.channelOpen {
            return channelOpen.displayName ?? channelOpen.peerId
        }
        return flow.review.humanSummary
    }

    private var feeLine: String? {
        if let transaction = flow.review.transaction {
            return "Fee \(WalletDisplay.formattedDustCompact(fromRaw: transaction.feeRaw)) • Fuel \(WalletDisplay.formattedDustCompact(fromRaw: transaction.dustTotalRaw))"
        }
        if let messageSend = flow.review.messageSend {
            return "Mailbox post • \(WalletDisplay.formattedDustCompact(fromRaw: messageSend.dustCostRaw))"
        }
        return nil
    }
}

private struct WalletPanel<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(WalletChrome.cardPadding)
            .background(WalletChrome.panelMaterial, in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
            .overlay(
                RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                    .stroke(WalletChrome.panelStroke, lineWidth: 1)
            )
    }
}

private struct DustFuelChip: View {
    let value: String
    let remaining: String

    var body: some View {
        VStack(alignment: .trailing, spacing: 4) {
            Text("DUST Fuel")
                .font(WalletTypography.caption)
                .foregroundStyle(WalletChrome.dustInk)
            Text(WalletDisplay.formattedDustCompact(fromRaw: value))
                .font(WalletTypography.dustNumber)
                .foregroundStyle(WalletChrome.dustInk)
            Text(remaining)
                .font(.caption)
                .foregroundStyle(WalletChrome.dustInk.opacity(0.8))
                .lineLimit(1)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
#if os(iOS)
        .padding(.trailing, 0)
#endif
        .background(WalletChrome.dustFill, in: RoundedRectangle(cornerRadius: 16))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(WalletChrome.dustStroke, lineWidth: 1)
        )
    }
}

private struct ConversationRow: View {
    let conversation: ConversationView
    let isSelected: Bool
    let onSelect: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack(alignment: .top, spacing: 12) {
                ZStack {
                    Circle()
                        .fill(WalletChrome.midnightBlue.opacity(0.18))
                    ClockMotif()
                        .stroke(WalletChrome.midnightBlue.opacity(0.72), lineWidth: 1.5)
                        .padding(6)
                }
                .frame(width: 42, height: 42)

                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text(conversation.displayName ?? conversation.peerId)
                            .font(WalletTypography.bodyStrong)
                            .lineLimit(1)
                        Spacer()
                        if conversation.unreadCount > 0 {
                            Text("\(conversation.unreadCount)")
                                .font(WalletTypography.badge)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(WalletChrome.midnightBlue.opacity(0.16), in: Capsule())
                                .foregroundStyle(WalletChrome.midnightBlue)
                        }
                    }
                    Text(conversation.lastMessagePreview ?? "No messages yet")
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    HStack {
                        Text(conversation.status.state.capitalized)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(WalletChrome.midnightBlue)
                        Spacer()
                        Text(WalletDisplay.formattedDustConversationTotal(fromRaw: conversation.dustSpentRaw))
                            .font(.caption)
                            .foregroundStyle(WalletChrome.dustInk)
                    }
                }
            }
            .padding(14)
            .background(WalletChrome.selectionFill(isSelected: isSelected), in: RoundedRectangle(cornerRadius: 18))
        }
        .buttonStyle(.plain)
    }
}

private struct MessageBubble: View {
    let message: WalletMessage
    var onVerifyReceipt: ((WalletTransferReceipt) -> Void)? = nil

    var body: some View {
        HStack {
            if message.direction == .outbound {
                Spacer(minLength: 40)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text(messageKindLabel)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(message.direction == .outbound ? .white.opacity(0.7) : WalletChrome.midnightBlue)
                content
                HStack {
                    Text(statusLabel)
                    Spacer()
                    Text(message.sentAt.formatted(date: .omitted, time: .shortened))
                    Text(WalletDisplay.formattedDustCompact(fromRaw: message.dustCostRaw))
                }
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(message.direction == .outbound ? .white.opacity(0.65) : WalletChrome.dustInk)
            }
            .padding(16)
            .background(bubbleBackground, in: RoundedRectangle(cornerRadius: 22))
            .shadow(color: message.direction == .outbound ? .black.opacity(0.2) : .clear, radius: 4, x: 0, y: 2)
            if message.direction == .inbound {
                Spacer(minLength: 40)
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch message.content {
        case let .text(value):
            Text(value)
        case let .transferReceipt(receipt):
            VStack(alignment: .leading, spacing: 6) {
                Rectangle()
                    .fill(WalletChrome.dustGold)
                    .frame(height: 2)
                Text(receipt.summary)
                    .fontWeight(.semibold)
                Text(receipt.txHash)
                    .font(.system(.caption, design: .monospaced))
                if let onVerifyReceipt {
                    Button("Verify") {
                        WalletBrandAssets.Haptics.tapLight()
                        onVerifyReceipt(receipt)
                    }
                    .buttonStyle(SecondaryWalletButtonStyle())
                }
            }
        case let .credentialRequest(request):
            VStack(alignment: .leading, spacing: 6) {
                Rectangle()
                    .fill(WalletChrome.midnightBlue)
                    .frame(height: 2)
                Text("Credential Request")
                    .fontWeight(.semibold)
                Text(request.claimSummary)
            }
        case let .credentialResponse(response):
            VStack(alignment: .leading, spacing: 6) {
                Rectangle()
                    .fill(WalletChrome.midnightBlue.opacity(0.6))
                    .frame(height: 2)
                Text("Credential Response")
                    .fontWeight(.semibold)
                Text(response.disclosureSummary)
            }
        }
    }

    private var bubbleBackground: AnyShapeStyle {
        if message.status == .failed {
            return AnyShapeStyle(LinearGradient(
                colors: [WalletChrome.warningAccent.opacity(0.92), WalletChrome.warningAccent.opacity(0.64)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ))
        }
        if message.direction == .outbound {
            return AnyShapeStyle(LinearGradient(
                colors: [WalletChrome.midnightBlue, WalletChrome.midnightBlue.opacity(0.76)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ))
        } else {
            return AnyShapeStyle(WalletChrome.cardMaterial)
        }
    }

    private var messageKindLabel: String {
        switch message.kind {
        case .text: return "Text"
        case .transferReceipt: return "Transfer Receipt"
        case .credentialRequest: return "Credential Request"
        case .credentialResponse: return "Credential Response"
        }
    }

    private var statusLabel: String {
        switch message.status {
        case .pending:
            return "Pending"
        case .posted:
            return "Posted"
        case .failed:
            return "Failed"
        case .received:
            return "Received"
        }
    }
}

private struct WalletMetricCard: View {
    enum Style {
        case standard
        case dust
    }

    let title: String
    let value: String
    let detail: String
    let style: Style

    init(title: String, value: String, detail: String, style: Style = .standard) {
        self.title = title
        self.value = value
        self.detail = detail
        self.style = style
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(WalletTypography.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(WalletTypography.metric)
                .foregroundStyle(style == .dust ? WalletChrome.dustInk : .primary)
                .lineLimit(1)
                .minimumScaleFactor(0.72)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(WalletChrome.cardPadding)
        .background(cardBackground, in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                .stroke(style == .dust ? WalletChrome.dustStroke : WalletChrome.panelStroke, lineWidth: 1)
        )
    }

    private var cardBackground: AnyShapeStyle {
        switch style {
        case .standard:
            return AnyShapeStyle(WalletChrome.cardMaterial)
        case .dust:
            return AnyShapeStyle(WalletChrome.dustFill)
        }
    }
}

private struct AddressSummaryRow: View {
    let title: String
    let value: String

    var body: some View {
#if os(iOS)
        VStack(alignment: .leading, spacing: 8) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .center, spacing: 12) {
                    Text(title)
                        .fontWeight(.semibold)
                        .lineLimit(1)
                    Spacer()
                    CopyButton(value: value)
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text(title)
                        .fontWeight(.semibold)
                    HStack {
                        CopyButton(value: value)
                        Spacer()
                    }
                }
            }
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
#else
        HStack(alignment: .top, spacing: 12) {
            Text(title)
                .fontWeight(.semibold)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.secondary)
            Spacer()
            CopyButton(value: value)
        }
#endif
    }
}

private struct AddressCard: View {
    let title: String
    let value: String?

    var body: some View {
        WalletPanel {
#if os(iOS)
            VStack(alignment: .leading, spacing: 16) {
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .center, spacing: 12) {
                        Text(title)
                            .font(WalletTypography.sectionTitle)
                            .lineLimit(1)
                        Spacer()
                        if let value {
                            CopyButton(value: value)
                        }
                    }
                    VStack(alignment: .leading, spacing: 10) {
                        Text(title)
                            .font(WalletTypography.sectionTitle)
                        if let value {
                            HStack {
                                CopyButton(value: value)
                                Spacer()
                            }
                        }
                    }
                }
                Text(value ?? "Unavailable")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                if let value {
                    HStack {
                        Spacer()
                        QRCodeView(value: value)
                            .frame(width: 120, height: 120)
                        Spacer()
                    }
                }
            }
#else
            HStack(alignment: .top, spacing: 20) {
                VStack(alignment: .leading, spacing: 12) {
                    Text(title)
                        .font(WalletTypography.sectionTitle)
                    Text(value ?? "Unavailable")
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                    if let value {
                        CopyButton(value: value)
                    }
                }
                Spacer()
                if let value {
                    QRCodeView(value: value)
                        .frame(width: 144, height: 144)
                }
            }
#endif
        }
    }
}

private struct DustCandidateRow: View {
    let candidate: DustUtxoCandidate
    let isSelected: Bool
    let onToggle: () -> Void

    var body: some View {
        Button(action: onToggle) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .center, spacing: 12) {
                        Text("\(WalletDisplay.formattedNightPrimary(fromRaw: candidate.valueRaw)) \(candidate.tokenType)")
                            .font(.system(.body, design: .monospaced).weight(.bold))
                        DustRegistrationChip(isRegistered: candidate.registeredForDustGeneration)
                    }
                    Text("Intent \(candidate.intentHash) • output #\(candidate.outputNo)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text(candidate.registeredForDustGeneration ? "Generating DUST to \(candidate.owner)" : "Not generating DUST")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(WalletChrome.midnightBlue)
                }
            }
            .padding(14)
            .background(WalletChrome.selectionFill(isSelected: isSelected), in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
            .overlay(
                RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                    .stroke(isSelected ? WalletChrome.midnightBlue.opacity(0.48) : WalletChrome.panelStroke, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

private struct DustRegistrationChip: View {
    let isRegistered: Bool

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: isRegistered ? "circle.fill" : "circle")
            Text(isRegistered ? "Registered" : "Unregistered")
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(isRegistered ? WalletChrome.dustInk : .secondary)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(isRegistered ? WalletChrome.dustFill : Color.white.opacity(0.05), in: Capsule())
        .overlay(
            Capsule()
                .stroke(isRegistered ? WalletChrome.dustStroke : WalletChrome.panelStroke, lineWidth: 1)
        )
    }
}

private struct ActivityRow: View {
    let entry: WalletActivityEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(entry.hash)
                .font(.system(.body, design: .monospaced))
            Text("\(entry.status.capitalized) • \(entry.timestamp.formatted(date: .abbreviated, time: .shortened))")
                .foregroundStyle(.secondary)
            if let feesRaw = entry.feesRaw {
                Text("Fees: \(WalletDisplay.formattedDustCompact(fromRaw: feesRaw))")
                    .font(.caption)
                    .foregroundStyle(WalletChrome.dustInk)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct PolicyRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}

private struct LabeledField<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            content
        }
    }
}

private struct NightAmountField: View {
    let title: String
    let amountDisplay: String
    let rawAmount: String
    let placeholder: String
    let onChange: (String) -> Void
    let onMax: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            WalletInputSurface {
                HStack(spacing: 12) {
                    TextField(placeholder, text: Binding(get: { amountDisplay }, set: onChange))
                        .textFieldStyle(.plain)
                        .font(.system(.body, design: .monospaced))
                    Text("NIGHT")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                    Button("MAX") {
                        WalletBrandAssets.Haptics.tapLight()
                        onMax()
                    }
                    .buttonStyle(.plain)
                    .font(WalletTypography.caption)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.white.opacity(0.08), in: Capsule())
                }
                .frame(minHeight: WalletChrome.inputHeight)
            }
            Text(WalletDisplay.rawCaption(rawAmount))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}

private struct CopyButton: View {
    let value: String

    var body: some View {
        Button {
            WalletBrandAssets.Haptics.tapMedium()
            WalletPlatformSupport.copyToPasteboard(value)
        }
        label: {
            Label("Copy", systemImage: "doc.on.doc")
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .buttonStyle(.bordered)
#if os(iOS)
        .controlSize(.small)
#endif
    }
}

private struct QRCodeView: View {
    let value: String

    private let context = CIContext()

    var body: some View {
        Group {
            if let image = qrImage {
                Image(walletPlatformImage: image)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
                    .padding(10)
                    .background(.white, in: RoundedRectangle(cornerRadius: 18))
            } else {
                RoundedRectangle(cornerRadius: 18)
                    .fill(.thinMaterial)
            }
        }
    }

    private var qrImage: WalletPlatformImage? {
        WalletPlatformSupport.qrImage(value: value, context: context)
    }
}

private struct HelperAvailabilityBanner: View {
    let message: String
    var networkName: String = "Preprod"

    var body: some View {
        let copy = WalletDisplay.helperStatus(message: message, networkName: networkName)

        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "info.circle")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text(copy.title)
                    .font(WalletTypography.bodyStrong)
                if let detail = copy.detail {
                    Text(detail)
                        .font(WalletTypography.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(WalletChrome.cardPadding)
        .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                .stroke(WalletChrome.panelStroke, lineWidth: 1)
        )
    }
}

private struct WalletInputSurface<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .background(WalletChrome.inputBackground, in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
            .overlay(
                RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                    .stroke(WalletChrome.panelStroke, lineWidth: 1)
            )
    }
}

private struct WalletInfoCard<Content: View>: View {
    let accent: Color
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(WalletChrome.cardPadding)
            .background(WalletChrome.inputBackground, in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
            .overlay(
                RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                    .stroke(accent, lineWidth: 1)
            )
    }
}

private struct DUSTSummaryPill: View {
    let title: String
    let value: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(WalletTypography.caption)
                .foregroundStyle(WalletChrome.dustInk.opacity(0.86))
            Text(value)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.bold)
                .foregroundStyle(WalletChrome.dustInk)
            Text(detail)
                .font(.caption)
                .foregroundStyle(WalletChrome.dustInk.opacity(0.82))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(WalletChrome.dustFill, in: Capsule())
        .overlay(
            Capsule()
                .stroke(WalletChrome.dustStroke, lineWidth: 1)
        )
    }
}

private struct MessagingEncryptionBadge: View {
    let rotationLine: String

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 10) {
                badgeContent
            }
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.shield.fill")
                        .foregroundStyle(WalletChrome.midnightBlue)
                    Text("ML-KEM-1024 + X25519")
                        .font(.custom("Outfit-Medium", size: 10))
                        .foregroundStyle(WalletChrome.midnightBlue)
                }
                Text("\(rotationLine) • ChaCha20-Poly1305")
                    .font(.system(size: 9, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 14)
        .frame(maxWidth: .infinity, minHeight: 32, alignment: .leading)
        .background(WalletChrome.midnightBlue.opacity(0.06), in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                .stroke(WalletChrome.midnightBlue.opacity(0.12), lineWidth: 1)
        )
    }

    private var badgeContent: some View {
        Group {
            Image(systemName: "lock.shield.fill")
                .foregroundStyle(WalletChrome.midnightBlue)
                .font(.system(size: 14, weight: .semibold))
            Text("ML-KEM-1024 + X25519")
                .font(.custom("Outfit-Medium", size: 10))
                .foregroundStyle(WalletChrome.midnightBlue)
            Text("•")
                .foregroundStyle(.secondary)
            Text(rotationLine)
                .font(.custom("Outfit-Medium", size: 10))
                .foregroundStyle(.secondary)
            Text("•")
                .foregroundStyle(.secondary)
            Text("ChaCha20-Poly1305")
                .font(.system(size: 9, weight: .medium, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}

private struct WalletEmptyState: View {
    let title: String
    let message: String
    let actionTitle: String
    let action: () -> Void
    var motifSize: CGFloat = 44

    var body: some View {
        VStack(spacing: 14) {
            ClockMotif()
                .stroke(WalletChrome.midnightBlue.opacity(0.75), lineWidth: 1.4)
                .frame(width: motifSize, height: motifSize)
            Text(title)
                .font(WalletTypography.sectionTitle)
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(actionTitle, action: action)
                .buttonStyle(PrimaryWalletButtonStyle())
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
    }
}

private struct DUSTActionBar: View {
    let selectedCount: Int
    let totalNight: String
    let selectedOperation: DustOperationKind
    let onRegister: () -> Void
    let onDeregister: () -> Void
    let onRedesignate: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Rectangle()
                .fill(WalletChrome.dustGold)
                .frame(height: 2)
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(selectedCount) selected")
                        .font(WalletTypography.bodyStrong)
                    Text("\(totalNight) NIGHT")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                actionButton(title: "Register", active: selectedOperation == .register, action: onRegister)
                actionButton(title: "Deregister", active: selectedOperation == .deregister, action: onDeregister)
                actionButton(title: "Redesignate", active: selectedOperation == .redesignate, action: onRedesignate)
            }
        }
        .padding(WalletChrome.cardPadding)
        .background(WalletChrome.inputBackground, in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
        .overlay(
            RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                .stroke(WalletChrome.dustStroke, lineWidth: 1)
        )
    }

    private func actionButton(title: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .buttonStyle(.plain)
            .font(WalletTypography.caption)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(active ? WalletChrome.midnightBlue.opacity(0.18) : Color.white.opacity(0.06), in: Capsule())
            .overlay(
                Capsule()
                    .stroke(active ? WalletChrome.midnightBlue.opacity(0.4) : WalletChrome.panelStroke, lineWidth: 1)
            )
    }
}

private struct WarningBanner: View {
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(WalletChrome.warningAccent)
            Text(message)
                .foregroundStyle(.primary)
        }
        .padding(14)
        .background(WalletChrome.dustFill, in: RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(WalletChrome.dustStroke, lineWidth: 1)
        )
    }
}

private struct ApprovalDetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .multilineTextAlignment(.trailing)
        }
    }
}

private struct BrandedLoadingBar: View {
    @State private var animate = false

    var body: some View {
        GeometryReader { geometry in
            Capsule()
                .fill(WalletChrome.midnightBlue.opacity(0.18))
                .overlay(alignment: .leading) {
                    Capsule()
                        .fill(
                            LinearGradient(
                                colors: [WalletChrome.midnightBlue.opacity(0.2), WalletChrome.midnightBlue, WalletChrome.midnightBlue.opacity(0.2)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                        .frame(width: max(120, geometry.size.width * 0.24))
                        .offset(x: animate ? geometry.size.width - max(120, geometry.size.width * 0.24) : 0)
                }
                .onAppear {
                    withAnimation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true)) {
                        animate = true
                    }
                }
        }
    }
}

private struct OverviewQuickActionButton: View {
    let title: String
    let systemImage: String
    let filled: Bool
    let action: () -> Void

    private var diameter: CGFloat {
#if os(iOS)
        56
#else
        64
#endif
    }

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                ZStack {
                    Circle()
                        .fill(filled ? WalletChrome.midnightBlue : WalletChrome.cardBackground)
                        .overlay(
                            Circle()
                                .stroke(filled ? WalletChrome.midnightBlue : WalletChrome.panelStroke, lineWidth: 1)
                        )
                    Image(systemName: systemImage)
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(filled ? Color.white : Color.primary)
                }
                .frame(width: diameter, height: diameter)

                Text(title)
                    .font(WalletTypography.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
    }
}

private struct StatusBanner: View {
    let message: String?

    var body: some View {
        if let userFacingMessage = WalletDisplay.userFacingError(message) {
            Text(userFacingMessage)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(WalletChrome.cardPadding)
                .background(WalletChrome.statusBackground, in: RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius))
                .overlay(
                    RoundedRectangle(cornerRadius: WalletChrome.cardCornerRadius)
                        .stroke(WalletChrome.statusStroke, lineWidth: 1)
                )
        }
    }
}

private struct ClockMotif: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.addEllipse(in: rect.insetBy(dx: rect.width * 0.14, dy: rect.height * 0.14))
        let center = CGPoint(x: rect.midX, y: rect.midY)
        path.move(to: center)
        path.addLine(to: CGPoint(x: rect.midX, y: rect.minY + rect.height * 0.24))
        path.move(to: center)
        path.addLine(to: CGPoint(x: rect.maxX - rect.width * 0.22, y: rect.midY))
        return path
    }
}

private enum WalletTypography {
    #if os(iOS)
    static let lockedHero = Font.custom("Outfit-ExtraBold", size: 26)
    static let balanceHero = Font.system(size: 38, weight: .bold, design: .monospaced)
    static let heroTitle = Font.custom("Outfit-ExtraBold", size: 20)
    #else
    static let lockedHero = Font.custom("Outfit-ExtraBold", size: 42)
    static let balanceHero = Font.system(size: 48, weight: .bold, design: .monospaced)
    static let heroTitle = Font.custom("Outfit-ExtraBold", size: 28)
    #endif
#if os(iOS)
    static let sectionTitle = Font.custom("Outfit-SemiBold", size: 18)
    static let bodyStrong = Font.custom("Outfit-Medium", size: 14)
    static let caption = Font.custom("Outfit-Medium", size: 10.5)
    static let metric = Font.system(size: 22, weight: .bold, design: .monospaced)
    static let dustNumber = Font.custom("Outfit-Bold", size: 15)
#else
    static let sectionTitle = Font.custom("Outfit-SemiBold", size: 22)
    static let bodyStrong = Font.custom("Outfit-Medium", size: 16)
    static let caption = Font.custom("Outfit-Medium", size: 12)
    static let metric = Font.system(size: 28, weight: .bold, design: .monospaced)
    static let dustNumber = Font.custom("Outfit-Bold", size: 18)
#endif
    static let badge = Font.custom("Outfit-Bold", size: 12)
}

private struct PrimaryWalletButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, horizontalPadding)
            .padding(.vertical, verticalPadding)
            .background(
                WalletChrome.primaryButtonBackground(isPressed: configuration.isPressed),
                in: Capsule()
            )
            .foregroundStyle(WalletChrome.primaryButtonForeground)
            .fontWeight(.bold)
    }

    private var horizontalPadding: CGFloat {
#if os(iOS)
        14
#else
        18
#endif
    }

    private var verticalPadding: CGFloat {
#if os(iOS)
        10
#else
        12
#endif
    }
}

private struct SecondaryWalletButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, horizontalPadding)
            .padding(.vertical, verticalPadding)
            .background(WalletChrome.secondaryButtonBackground(isPressed: configuration.isPressed), in: Capsule())
            .foregroundStyle(.primary)
            .fontWeight(.semibold)
    }

    private var horizontalPadding: CGFloat {
#if os(iOS)
        14
#else
        18
#endif
    }

    private var verticalPadding: CGFloat {
#if os(iOS)
        10
#else
        12
#endif
    }
}

private struct CriticalTextButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.vertical, 10)
            .foregroundStyle(Color.red.opacity(configuration.isPressed ? 0.72 : 0.9))
            .fontWeight(.semibold)
    }
}

private enum WalletChrome {
    static let midnightBlack = Color.black
    static let midnightBlue = Color(red: 0.0, green: 0.0, blue: 0.996)
    static let dustGold = Color(red: 0.957, green: 0.773, blue: 0.259)
    static let dustInk = Color(red: 0.541, green: 0.357, blue: 0.0)
    static let cardBackground = Color(red: 0.067, green: 0.067, blue: 0.067)
    static let dustFill = dustGold.opacity(0.12)
    static let dustStroke = dustGold.opacity(0.24)
    static let warningAccent = Color(red: 1.0, green: 0.584, blue: 0.0)
    static let badgeBackground = midnightBlue.opacity(0.12)
    static let codeBackground = Color.white.opacity(0.04)
    static let inputBackground = Color(red: 0.04, green: 0.04, blue: 0.04)
    static let cardCornerRadius: CGFloat = 16
    static let cardSpacing: CGFloat = 16
    static let inputHeight: CGFloat = 48

    static let background = midnightBlack

    static let headerMaterial: some ShapeStyle = midnightBlack
    static let panelMaterial: some ShapeStyle = cardBackground
    static let cardMaterial: some ShapeStyle = cardBackground

    static let panelStroke = Color(red: 0.102, green: 0.102, blue: 0.102)
    static let statusBackground = midnightBlue.opacity(0.12)
    static let statusStroke = midnightBlue.opacity(0.24)

    static var cardPadding: CGFloat {
#if os(iOS)
        16
#else
        20
#endif
    }

    static func selectionFill(isSelected: Bool) -> some ShapeStyle {
        if isSelected {
            return midnightBlue.opacity(0.14)
        } else {
            return Color.white.opacity(0.06)
        }
    }

    static func primaryButtonBackground(isPressed: Bool) -> LinearGradient {
        LinearGradient(
            colors: [
                midnightBlue,
                midnightBlue.opacity(0.72)
            ].map { isPressed ? $0.opacity(0.8) : $0 },
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    static let primaryButtonForeground: Color = .white

    static func secondaryButtonBackground(isPressed: Bool) -> some ShapeStyle {
        Color.white.opacity(isPressed ? 0.10 : 0.16)
    }
}
