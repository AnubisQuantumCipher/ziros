import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI

struct ContentView: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        Group {
            if coordinator.snapshot?.locked != false {
                LockedWalletView(coordinator: coordinator)
            } else {
                UnlockedWalletView(coordinator: coordinator)
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
    }
}

private struct LockedWalletView: View {
    @Bindable var coordinator: WalletCoordinator

    private var shellPadding: CGFloat {
#if os(iOS)
        20
#else
        36
#endif
    }

    private var usesCompactLayout: Bool {
#if os(iOS)
        true
#else
        false
#endif
    }

    private var hasImportedSeed: Bool {
        coordinator.snapshot?.hasImportedSeed == true
    }

    private var previewDustRaw: Double {
        guard let value = coordinator.overview?.balances.dust.spendableRaw else {
            return 94_000_000
        }
        return Double(value) ?? 94_000_000
    }

    private var previewShieldedNight: Double {
        parseNightBalance(coordinator.overview?.balances.shielded["NIGHT"]) ?? 38_400
    }

    private var previewUnshieldedNight: Double {
        parseNightBalance(coordinator.overview?.balances.unshielded["NIGHT"]) ?? 11_600
    }

    private var previewTransactionsRemaining: Int {
        max(Int((previewDustRaw / 1_000_000).rounded(.down)), 0)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                WalletPanel {
                    VStack(alignment: .leading, spacing: 24) {
                        ViewThatFits(in: .horizontal) {
                            HStack(alignment: .top, spacing: 28) {
                                lockedHeroCopy
                                Spacer(minLength: 0)
                                lockedHeroMetrics
                            }
                            VStack(alignment: .leading, spacing: 24) {
                                lockedHeroCopy
                                lockedHeroMetrics
                            }
                        }

                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                Label("Privacy Posture", systemImage: "eye.slash")
                                    .font(WalletTypography.sectionTitle)
                                Spacer()
                                Text("\(Int((previewShieldedNight / max(previewShieldedNight + previewUnshieldedNight, 1)) * 100))% shielded")
                                    .font(WalletTypography.caption)
                                    .foregroundStyle(WalletChrome.midnightBlue)
                            }
                            PrivacyGauge(
                                shielded: previewShieldedNight,
                                unshielded: previewUnshieldedNight
                            )
                        }
                    }
                }

                if hasImportedSeed {
                    WalletPanel {
                        VStack(alignment: .leading, spacing: 18) {
                            Label("Wallet Locked", systemImage: "faceid")
                                .font(WalletTypography.sectionTitle)
                            Text("Cold unlock requires \(WalletPlatformSupport.biometricLabel). The helper session and private state stay closed until the biometric gate succeeds.")
                                .foregroundStyle(.secondary)
                            HStack(spacing: 14) {
                                Button("Unlock With \(WalletPlatformSupport.biometricLabel)") {
                                    Task { await coordinator.unlock() }
                                }
                                .buttonStyle(PrimaryWalletButtonStyle())
                                Button("Refresh Snapshot") {
                                    Task { await coordinator.refresh() }
                                }
                                .buttonStyle(SecondaryWalletButtonStyle())
                            }

                            Divider()

                            DisclosureGroup("Replace Imported Seed") {
                                ImportSeedForm(coordinator: coordinator)
                                    .padding(.top, 12)
                            }
                            .tint(.primary)
                        }
                    }
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
                }

                if !coordinator.helperExecutionAvailability.isAvailable {
                    WalletPanel {
                        VStack(alignment: .leading, spacing: 14) {
                            Label("iPhone Beta Scope", systemImage: "iphone.gen3.radiowaves.left.and.right")
                                .font(WalletTypography.sectionTitle)
                            Text("Rust policy, biometric unlock, seed import, permissions, and settings are live on iPhone. Midnight execution stays fail-closed until the mobile helper lane clears its WebKit audit.")
                                .foregroundStyle(.secondary)
                            Divider()
                            PolicyRow(label: "Live Now", value: "Import, biometrics, permissions, settings")
                            PolicyRow(label: "Held Closed", value: "Sync, receive, send, shield, unshield, DUST, history")
                            PolicyRow(label: "Reason", value: "Current helper still assumes Node/stdin + LevelDB runtime surfaces")
                        }
                    }
                }

                StatusBanner(message: coordinator.statusMessage)
            }
            .padding(shellPadding)
            .frame(maxWidth: 920, alignment: .leading)
            .scrollContentBackground(.hidden)
        }
    }

    @ViewBuilder
    private var lockedHeroCopy: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("MIDNIGHT PREPROD BETA")
                .font(WalletTypography.caption)
                .kerning(1.2)
                .foregroundStyle(WalletChrome.midnightBlue)
            Text("DUST-first wallet.\nPrivacy visible.")
                .font(WalletTypography.lockedHero)
                .lineLimit(3)
                .minimumScaleFactor(0.8)
            Text("Fuel stays glanceable, privacy posture stays visible, and DUST plus Messages stay top-level.")
                .font(WalletTypography.bodyStrong)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            LockedTabPreviewStrip()
        }
    }

    @ViewBuilder
    private var lockedHeroMetrics: some View {
        VStack(alignment: .center, spacing: 16) {
            DustFuelRing(
                currentDust: previewDustRaw,
                targetDustFor100Txns: 100_000_000,
                estimatedTransactionsRemaining: previewTransactionsRemaining
            )
            .scaleEffect(usesCompactLayout ? 0.78 : 1.0)
            VStack(spacing: 8) {
                Text("DUST drives every action")
                    .font(WalletTypography.bodyStrong)
                LockedDustPill(
                    title: "Fuel State",
                    value: previewTransactionsRemaining > 24 ? "Healthy" : "Low"
                )
            }
            .multilineTextAlignment(.center)
        }
        .frame(maxWidth: 220)
    }

    private func parseNightBalance(_ raw: String?) -> Double? {
        guard let raw else { return nil }
        if let numeric = Double(raw) {
            return numeric
        }
        let filtered = raw.filter { $0.isNumber || $0 == "." }
        return Double(filtered)
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
            List(selection: $coordinator.selectedSection) {
                ForEach(WalletSection.allCases) { section in
                    Label(section.title, systemImage: section.systemImage)
                        .tag(Optional(section))
                }
            }
            .navigationTitle("ZirOS Wallet")
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .background(.clear)
            .tint(.accentColor)
        } detail: {
            VStack(spacing: 0) {
                HeaderBar(coordinator: coordinator)
                ScrollView {
                    sectionView(coordinator.selectedSection ?? .overview)
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
            .navigationTitle(section.title)
#if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
#endif
            .toolbar {
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
}

private struct HeaderBar: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Text((coordinator.selectedSection ?? .overview).title)
                        .font(WalletTypography.heroTitle)
                    Text(headerSubtitle)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if coordinator.isBusy {
                    ProgressView()
                        .controlSize(.small)
                }
                Button("Refresh") {
                    Task { await coordinator.refresh() }
                }
                .buttonStyle(SecondaryWalletButtonStyle())
                Button("Lock") {
                    Task { await coordinator.lock() }
                }
                .buttonStyle(PrimaryWalletButtonStyle())
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 16)

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

    private var headerSubtitle: String {
        if let configuration = coordinator.configuration {
            return "Network: \(configuration.networkId)  •  Prover: \(configuration.proverServerUri ?? "Unavailable")"
        }
        return "Midnight native wallet"
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

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if let message = coordinator.helperExecutionAvailability.message {
                HelperAvailabilityBanner(message: message)
            }

            heroBalance

            WalletPanel {
#if os(iOS)
                VStack(alignment: .leading, spacing: 18) {
                    Text("DUST Fuel")
                        .font(WalletTypography.sectionTitle)
                    HStack {
                        Spacer()
                        DustFuelRing(
                            currentDust: dustRaw,
                            targetDustFor100Txns: dustTargetFor100TransactionsRaw,
                            estimatedTransactionsRemaining: estimatedTransactionsRemaining
                        )
                        .frame(width: 184, height: 184)
                        Spacer()
                    }
                    HStack {
                        Spacer()
                        DustFuelChip(
                            value: formattedInteger(dustRaw),
                            remaining: "\(estimatedTransactionsRemaining)"
                        )
                    }
                    metricGrid
                }
#else
                VStack(alignment: .leading, spacing: 18) {
                    overviewDustHeader
                    HStack {
                        Spacer()
                        DustFuelRing(
                            currentDust: dustRaw,
                            targetDustFor100Txns: dustTargetFor100TransactionsRaw,
                            estimatedTransactionsRemaining: estimatedTransactionsRemaining
                        )
                        .frame(width: 184, height: 184)
                        Spacer()
                    }
                    metricGrid
                }
#endif
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Privacy Posture")
                        .font(WalletTypography.sectionTitle)
                    PrivacyGauge(shielded: shieldedNight, unshielded: unshieldedNight)
                    HStack(spacing: 12) {
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
            }

            WalletPanel {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("Wallet Status")
                            .font(WalletTypography.sectionTitle)
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
                        Button("Open Activity") {
                            coordinator.selectedSection = .more
                        }
                        .buttonStyle(.borderless)
                    }
                    if coordinator.activity.isEmpty {
                        Text("No transactions have been loaded yet.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(coordinator.activity.prefix(5))) { entry in
                            ActivityRow(entry: entry)
                            if entry.id != coordinator.activity.prefix(5).last?.id {
                                Divider()
                            }
                        }
                    }
                }
            }
        }
    }

    private var heroBalance: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(formattedNight(totalNight))
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
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private var overviewDustHeader: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("DUST Fuel")
                        .font(WalletTypography.sectionTitle)
                    Text("The ring shows how many actions remain before you need more DUST.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                DustFuelChip(
                    value: formattedInteger(dustRaw),
                    remaining: "\(estimatedTransactionsRemaining)"
                )
            }
            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("DUST Fuel")
                        .font(WalletTypography.sectionTitle)
                    Text("The ring shows how many actions remain before you need more DUST.")
                        .foregroundStyle(.secondary)
                }
                HStack {
                    Spacer()
                    DustFuelChip(
                        value: formattedInteger(dustRaw),
                        remaining: "\(estimatedTransactionsRemaining)"
                    )
                }
            }
        }
    }

    private var metricGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 16)], spacing: 16) {
            WalletMetricCard(
                title: "Shielded NIGHT",
                value: formattedNight(shieldedNight),
                detail: "Private balance"
            )
            WalletMetricCard(
                title: "Unshielded NIGHT",
                value: formattedNight(unshieldedNight),
                detail: "Spendable base layer"
            )
            WalletMetricCard(
                title: "DUST",
                value: formattedInteger(dustRaw),
                detail: "~\(estimatedTransactionsRemaining) transactions remaining",
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

    private func formattedNight(_ value: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.maximumFractionDigits = value >= 1_000 ? 0 : 2
        return formatter.string(from: NSNumber(value: value)) ?? "0"
    }

    private func formattedInteger(_ value: Double) -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        formatter.maximumFractionDigits = 0
        return formatter.string(from: NSNumber(value: value.rounded(.down))) ?? "0"
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
        return "\(spendableDustValue / estimatedDustCostRaw)"
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
            return "Encrypted • Wallet-owned keys active"
        }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return "Encrypted • Keys rotated \(formatter.localizedString(for: rotatedAt, relativeTo: Date()))"
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
                        WalletPanel {
                            HStack(alignment: .center, spacing: 14) {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("DUST Fuel Low")
                                        .font(WalletTypography.sectionTitle)
                                    Text(lowDustReason)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Open DUST") {
                                    coordinator.selectedSection = .dust
                                }
                                .buttonStyle(SecondaryWalletButtonStyle())
                            }
                        }
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
                        Text("No encrypted channels yet. Paste a peer invite to open one.")
                            .foregroundStyle(.secondary)
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
                                coordinator.copyLocalInvite()
                            }
                            .buttonStyle(SecondaryWalletButtonStyle())
                            Button("Close Channel") {
                                coordinator.closeSelectedConversation()
                            }
                            .buttonStyle(SecondaryWalletButtonStyle())
                        }
                    }
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
                        Text("No messages have been decrypted for this conversation yet.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(coordinator.activeMessages) { message in
                            MessageBubble(message: message)
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
                    Text(encryptionStatusLine)
                        .font(WalletTypography.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $coordinator.messageComposerText)
                        .frame(minHeight: 120)
                        .padding(10)
                        .background(WalletChrome.codeBackground, in: RoundedRectangle(cornerRadius: 16))
                    HStack {
                        Text("Estimated DUST cost: \(estimatedDustCostRaw)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(WalletChrome.dustInk)
                        Spacer()
                        Button("Send Text Message") {
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

private struct TransactScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Transact")
                        .font(WalletTypography.sectionTitle)
                    Text(transactSubtitle)
                        .foregroundStyle(.secondary)
                    transactModeSelector
                }
            }

            Group {
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
        }
    }

    @ViewBuilder
    private var transactModeSelector: some View {
#if os(iOS)
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
            ForEach(TransactMode.allCases) { mode in
                Button {
                    coordinator.selectedTransactMode = mode
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: mode.systemImage)
                        Text(mode.title)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(
                        WalletChrome.selectionFill(isSelected: coordinator.selectedTransactMode == mode),
                        in: RoundedRectangle(cornerRadius: 14)
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(
                                coordinator.selectedTransactMode == mode ? WalletChrome.midnightBlue.opacity(0.55) : WalletChrome.panelStroke,
                                lineWidth: 1
                            )
                    )
                }
                .buttonStyle(.plain)
            }
        }
#else
        Picker("Transact Mode", selection: $coordinator.selectedTransactMode) {
            ForEach(TransactMode.allCases) { mode in
                Label(mode.title, systemImage: mode.systemImage)
                    .tag(mode)
            }
        }
        .pickerStyle(.segmented)
#endif
    }

    private var transactSubtitle: String {
#if os(iOS)
        "Move funds and switch privacy from one surface."
#else
        "Send, receive, shield, and unshield all live here so every money movement starts from one deliberate surface."
#endif
    }
}

private struct SendScreen: View {
    @Bindable var coordinator: WalletCoordinator

    var body: some View {
        WalletPanel {
            VStack(alignment: .leading, spacing: 18) {
                Text("Send NIGHT")
                    .font(.title2.weight(.bold))
                Text(sendSubtitle)
                    .foregroundStyle(.secondary)
                if let message = coordinator.helperExecutionAvailability.message {
                    HelperAvailabilityBanner(message: message)
                }
                LabeledField(title: "Recipient") {
                    TextField("midnight1...", text: $coordinator.sendRecipient)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                }
                LabeledField(title: "Amount (raw)") {
                    TextField("1000000000000000", text: $coordinator.sendAmountRaw)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                }
                Toggle("Send to shielded receiver", isOn: $coordinator.sendShielded)
                Text("Second \(WalletPlatformSupport.biometricLabel) confirmation is enforced automatically above 100 NIGHT.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: 14) {
                    Button("Create Approval Request") {
                        Task { await coordinator.beginSend() }
                    }
                    .buttonStyle(PrimaryWalletButtonStyle())
                    .disabled(!coordinator.helperExecutionAvailability.isAvailable)
                    Button("Paste Recipient") {
                        coordinator.sendRecipient = WalletPlatformSupport.pastedString() ?? coordinator.sendRecipient
                    }
                    .buttonStyle(SecondaryWalletButtonStyle())
                }
            }
        }
    }

    private var sendSubtitle: String {
#if os(iOS)
        "Every send pauses for review and \(WalletPlatformSupport.biometricLabel)."
#else
        "Every send request becomes a native pending approval with a full transaction review before \(WalletPlatformSupport.biometricLabel)."
#endif
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

    init(coordinator: WalletCoordinator, mode: Mode = .shield) {
        self.coordinator = coordinator
        self.mode = mode
    }

    var body: some View {
        WalletPanel {
            VStack(alignment: .leading, spacing: 16) {
                Text(mode == .shield ? "Shield NIGHT" : "Unshield NIGHT")
                    .font(.title3.weight(.bold))
                Text(modeSubtitle)
                    .foregroundStyle(.secondary)
                if let message = coordinator.helperExecutionAvailability.message {
                    HelperAvailabilityBanner(message: message)
                }
                TextField("Amount (raw)", text: mode == .shield ? $coordinator.shieldAmountRaw : $coordinator.unshieldAmountRaw)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                Button(mode == .shield ? "Create Shield Approval" : "Create Unshield Approval") {
                    Task {
                        if mode == .shield {
                            await coordinator.beginShield()
                        } else {
                            await coordinator.beginUnshield()
                        }
                    }
                }
                .buttonStyle(PrimaryWalletButtonStyle())
                .disabled(!coordinator.helperExecutionAvailability.isAvailable)
            }
        }
    }

    private var modeSubtitle: String {
        switch mode {
        case .shield:
#if os(iOS)
            return "Move NIGHT into the shielded pool using the same approval chain as send."
#else
            return "Moves spendable NIGHT into the shielded pool using the same Rust-enforced approval chain as send."
#endif
        case .unshield:
            return "Move NIGHT back to the unshielded side for standard spending."
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

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            WalletPanel {
                VStack(alignment: .leading, spacing: 16) {
                    Text("DUST Management")
                        .font(WalletTypography.heroTitle)
                    Text("DUST is fuel.")
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
                            estimatedTransactionsRemaining: estimatedTransactionsRemaining
                        )
                        .frame(width: 200, height: 200)
                        Spacer()
                    }

                    Text("This screen keeps fuel visible, selectable, and actionable instead of burying it behind raw UTXO state.")
                        .foregroundStyle(.secondary)

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 14) {
                            WalletMetricCard(
                                title: "Spendable DUST",
                                value: formattedInteger(dustRaw),
                                detail: "~\(estimatedTransactionsRemaining) transactions remaining",
                                style: .dust
                            )
                            WalletMetricCard(
                                title: "Registered UTXOs",
                                value: "\(coordinator.overview?.balances.dust.registeredNightUtxos ?? 0)",
                                detail: "\(coordinator.dustCandidates.count) total visible",
                                style: .dust
                            )
                            WalletMetricCard(
                                title: "Generation Readiness",
                                value: dustGenerationReadiness,
                                detail: "Designate NIGHT to replenish fuel",
                                style: .dust
                            )
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
                        Text("No NIGHT UTXOs are available yet.")
                            .foregroundStyle(.secondary)
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

                    Button("Create DUST Approval") {
                        Task { await coordinator.beginDustOperation() }
                    }
                    .buttonStyle(PrimaryWalletButtonStyle())
                    .disabled(!coordinator.helperExecutionAvailability.isAvailable)

                    DisclosureGroup(
                        isExpanded: Binding(
                            get: { !hasSeenDustExplainer },
                            set: { expanded in hasSeenDustExplainer = !expanded }
                        )
                    ) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("DUST is Midnight’s fee fuel.")
                            Text("Register NIGHT UTXOs to generate DUST, watch the fuel ring for how many transactions remain, and redesignate output flows when you want to steer fuel elsewhere.")
                                .foregroundStyle(.secondary)
                            Button("Understood") {
                                hasSeenDustExplainer = true
                            }
                            .buttonStyle(SecondaryWalletButtonStyle())
                        }
                        .padding(.top, 8)
                    } label: {
                        Text("What is DUST?")
                            .font(WalletTypography.bodyStrong)
                    }
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

    var body: some View {
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
        VStack(alignment: .leading, spacing: 18) {
            Text("Review Before \(WalletPlatformSupport.biometricLabel)")
                .font(WalletTypography.sectionTitle)
            Text(flow.review.humanSummary)
                .font(WalletTypography.bodyStrong)

            if let transaction = flow.review.transaction {
                WalletPanel {
                    VStack(alignment: .leading, spacing: 10) {
                        PolicyRow(label: "Origin", value: transaction.origin)
                        PolicyRow(label: "Network", value: transaction.network)
                        PolicyRow(label: "Method", value: transaction.method)
                        PolicyRow(label: "Tx Digest", value: transaction.txDigest)
                        PolicyRow(label: "Prover Route", value: transaction.proverRoute ?? "Unavailable")
                        PolicyRow(label: "NIGHT Total", value: transaction.nightTotalRaw)
                        PolicyRow(label: "DUST Total", value: transaction.dustTotalRaw)
                        PolicyRow(label: "Fee", value: transaction.feeRaw)
                        PolicyRow(label: "Shielded", value: transaction.shielded ? "Yes" : "No")
                        if let dustImpact = transaction.dustImpact {
                            PolicyRow(label: "DUST Impact", value: dustImpact)
                        }
                    }
                }

                WalletPanel {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Outputs")
                            .font(.headline)
                        if transaction.outputs.isEmpty {
                            Text("No direct outputs are exposed for this action.")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(transaction.outputs) { output in
                                HStack(alignment: .top) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("\(output.amountRaw) \(output.tokenKind)")
                                            .fontWeight(.semibold)
                                        Text(output.recipient)
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                }
                            }
                        }
                    }
                }
            } else if let channelOpen = flow.review.channelOpen {
                WalletPanel {
                    VStack(alignment: .leading, spacing: 10) {
                        PolicyRow(label: "Origin", value: channelOpen.origin)
                        PolicyRow(label: "Network", value: channelOpen.network)
                        PolicyRow(label: "Method", value: channelOpen.method)
                        PolicyRow(label: "Peer", value: channelOpen.displayName ?? channelOpen.peerId)
                        PolicyRow(label: "Digest", value: channelOpen.txDigest)
                    }
                }
            } else if let messageSend = flow.review.messageSend {
                WalletPanel {
                    VStack(alignment: .leading, spacing: 10) {
                        PolicyRow(label: "Origin", value: messageSend.origin)
                        PolicyRow(label: "Network", value: messageSend.network)
                        PolicyRow(label: "Method", value: messageSend.method)
                        PolicyRow(label: "Peer", value: messageSend.peerId)
                        PolicyRow(label: "Channel", value: messageSend.channelId)
                        PolicyRow(label: "Message Kind", value: messageSend.messageKind)
                        PolicyRow(label: "DUST Cost", value: messageSend.dustCostRaw)
                    }
                }

                WalletPanel {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Message Preview")
                            .font(.headline)
                        Text(messageSend.messagePreview)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if !flow.review.warnings.isEmpty {
                WalletPanel {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Warnings")
                            .font(.headline)
                        ForEach(flow.review.warnings, id: \.self) { warning in
                            Text(warning)
                                .foregroundStyle(WalletChrome.warningAccent)
                        }
                    }
                }
            }

            HStack {
                Button("Reject", action: onReject)
                    .buttonStyle(SecondaryWalletButtonStyle())
                Button("Approve With \(WalletPlatformSupport.biometricLabel)", action: onApprove)
                    .buttonStyle(PrimaryWalletButtonStyle())
            }
        }
        .padding(28)
#if os(macOS)
        .frame(minWidth: 700, minHeight: 520)
#endif
    }
}

private struct WalletPanel<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(panelPadding)
            .background(WalletChrome.panelMaterial, in: RoundedRectangle(cornerRadius: 20))
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .stroke(WalletChrome.panelStroke, lineWidth: 1)
            )
    }

    private var panelPadding: CGFloat {
#if os(iOS)
        16
#else
        22
#endif
    }
}

private struct DustFuelChip: View {
    let value: String
    let remaining: String

    private var formattedValue: String {
        let digits = value.replacingOccurrences(of: ",", with: "")
        guard let number = Int(digits) else {
            return value
        }
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.groupingSeparator = ","
        return formatter.string(from: NSNumber(value: number)) ?? value
    }

    var body: some View {
        VStack(alignment: .trailing, spacing: 4) {
            Text("DUST Fuel")
                .font(WalletTypography.caption)
                .foregroundStyle(WalletChrome.dustInk)
            Text(formattedValue)
                .font(WalletTypography.dustNumber)
                .foregroundStyle(WalletChrome.dustInk)
            Text("~\(remaining) text posts")
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
                        Text("DUST \(conversation.dustSpentRaw)")
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
                    Text("DUST \(message.dustCostRaw)")
                }
                .font(.caption2)
                .foregroundStyle(message.direction == .outbound ? .white.opacity(0.65) : .secondary)
            }
            .padding(16)
            .background(bubbleBackground, in: RoundedRectangle(cornerRadius: 22))
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
                Text(receipt.summary)
                    .fontWeight(.semibold)
                Text(receipt.txHash)
                    .font(.system(.caption, design: .monospaced))
            }
        case let .credentialRequest(request):
            VStack(alignment: .leading, spacing: 6) {
                Text("Credential Request")
                    .fontWeight(.semibold)
                Text(request.claimSummary)
            }
        case let .credentialResponse(response):
            VStack(alignment: .leading, spacing: 6) {
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
        .padding(cardPadding)
        .background(cardBackground, in: RoundedRectangle(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18)
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

    private var cardPadding: CGFloat {
#if os(iOS)
        16
#else
        20
#endif
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
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(isSelected ? Color.accentColor : Color.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(candidate.valueRaw) \(candidate.tokenType)")
                        .fontWeight(.semibold)
                    Text("Intent \(candidate.intentHash) • output #\(candidate.outputNo)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Text(candidate.registeredForDustGeneration ? "Already registered for DUST generation" : "Not registered for DUST generation")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(14)
            .background(WalletChrome.selectionFill(isSelected: isSelected), in: RoundedRectangle(cornerRadius: 18))
        }
        .buttonStyle(.plain)
    }
}

private struct ActivityRow: View {
    let entry: WalletActivityEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(entry.hash)
                .font(.system(.body, design: .monospaced))
            Text("\(entry.status) • \(entry.timestamp.formatted(date: .abbreviated, time: .shortened))")
                .foregroundStyle(.secondary)
            if let feesRaw = entry.feesRaw {
                Text("Fees: \(feesRaw)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

    var body: some View {
        Text(message)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background(Color.orange.opacity(0.14), in: RoundedRectangle(cornerRadius: 14))
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(Color.orange.opacity(0.35), lineWidth: 1)
            )
    }
}

private struct OverviewQuickActionButton: View {
    let title: String
    let systemImage: String
    let filled: Bool
    let action: () -> Void

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
                .frame(width: 56, height: 56)

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
        if let message {
            Text(message)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(WalletChrome.statusBackground, in: RoundedRectangle(cornerRadius: 14))
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
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
    static let metric = Font.custom("Outfit-ExtraBold", size: 22)
    static let dustNumber = Font.custom("Outfit-Bold", size: 15)
#else
    static let sectionTitle = Font.custom("Outfit-SemiBold", size: 22)
    static let bodyStrong = Font.custom("Outfit-Medium", size: 16)
    static let caption = Font.custom("Outfit-Medium", size: 12)
    static let metric = Font.custom("Outfit-ExtraBold", size: 30)
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

    static let background = midnightBlack

    static let headerMaterial: some ShapeStyle = midnightBlack
    static let panelMaterial: some ShapeStyle = cardBackground
    static let cardMaterial: some ShapeStyle = cardBackground

    static let panelStroke = Color(red: 0.102, green: 0.102, blue: 0.102)
    static let statusBackground = midnightBlue.opacity(0.12)
    static let statusStroke = midnightBlue.opacity(0.24)

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
