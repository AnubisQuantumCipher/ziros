import SwiftUI
import Foundation

struct RootTabView: View {
    enum Tab {
        case overview, transact, dust, messages, more
    }
    
    @State private var selection: Tab = .overview
    
    var body: some View {
        TabView(selection: $selection) {
            LegacyOverviewScreen()
                .tabItem {
                    Label("Overview", systemImage: "house")
                }
                .tag(Tab.overview)
            
            LegacyTransactScreen()
                .tabItem {
                    Label("Transact", systemImage: "arrow.left.arrow.right")
                }
                .tag(Tab.transact)
            
            LegacyDustScreen()
                .tabItem {
                    Label {
                        Text("DUST")
                    } icon: {
                        Image(systemName: "flame")
                            .symbolRenderingMode(.hierarchical)
                            .foregroundStyle(selection == .dust ? WalletBrandAssets.Color.dustAmber : WalletBrandAssets.Color.textPrimary)
                    }
                }
                .tag(Tab.dust)
            
            LegacyMessagesScreen()
                .tabItem {
                    Label("Messages", systemImage: "bubble.left.and.bubble.right")
                }
                .tag(Tab.messages)
            
            MoreScreen()
                .tabItem {
                    Label("More", systemImage: "ellipsis.circle")
                }
                .tag(Tab.more)
        }
        .tint(WalletBrandAssets.Color.midnightBlue)
        .background(WalletBrandAssets.Color.background)
        .brandBackground()
        .onReceive(NotificationCenter.default.publisher(for: .selectTransactSegment)) { output in
            if let segment = output.object as? LegacyTransactScreen.Segment {
                selection = .transact
                NotificationCenter.default.post(name: .applyTransactSegment, object: segment)
            }
        }
    }
}

// MARK: - LegacyOverviewScreen

struct LegacyOverviewScreen: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("3,482,053.94")
                .font(WalletBrandAssets.Typography.balanceHero)
                .foregroundColor(WalletBrandAssets.Color.textPrimary)
            
            Text("NIGHT")
                .font(WalletBrandAssets.Typography.caption)
                .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.8))
                .textCase(.uppercase)
            
            HStack(spacing: 16) {
                QuickActionButton(title: "Send", systemImage: "arrow.up", filled: true) {
                    WalletBrandAssets.Haptics.tapLight()
                    // Switch to Transact tab and select Send
                    NotificationCenter.default.post(name: .selectTransactSegment, object: LegacyTransactScreen.Segment.send)
                }
                QuickActionButton(title: "Receive", systemImage: "arrow.down", filled: false) {
                    WalletBrandAssets.Haptics.tapLight()
                    NotificationCenter.default.post(name: .selectTransactSegment, object: LegacyTransactScreen.Segment.receive)
                }
                QuickActionButton(title: "Shield", systemImage: "lock.fill", filled: false) {
                    WalletBrandAssets.Haptics.tapLight()
                    NotificationCenter.default.post(name: .selectTransactSegment, object: LegacyTransactScreen.Segment.shield)
                }
                QuickActionButton(title: "Unshield", systemImage: "lock.open.fill", filled: false) {
                    WalletBrandAssets.Haptics.tapLight()
                    NotificationCenter.default.post(name: .selectTransactSegment, object: LegacyTransactScreen.Segment.unshield)
                }
            }
            
            // Privacy posture
            PrivacyGauge(shielded: 38_400, unshielded: 41_600)
                .frame(width: 64, height: 64)
            
            HStack(spacing: 8) {
                Text("DUST: 47.2M  •  ~94 txns")
                    .brandMono()
                    .foregroundColor(WalletBrandAssets.Color.textPrimary)
                    .brandPill()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .brandBackground()
    }
}

// MARK: - LegacyTransactScreen

struct LegacyTransactScreen: View {
    enum Segment: String, CaseIterable, Identifiable {
        case send = "Send"
        case receive = "Receive"
        case shield = "Shield"
        case unshield = "Unshield"
        
        var id: String { rawValue }
    }
    
    @State private var selectedSegment: Segment = .send
    
    var body: some View {
        VStack {
            Picker("Transact", selection: $selectedSegment) {
                ForEach(Segment.allCases) { segment in
                    Text(segment.rawValue)
                        .tag(segment)
                }
            }
            .pickerStyle(SegmentedPickerStyle())
            .tint(WalletBrandAssets.Color.midnightBlue)
            .padding()
            
            Spacer()
            
            switch selectedSegment {
            case .send:
                PlaceholderContentView(text: "Send screen placeholder")
            case .receive:
                PlaceholderContentView(text: "Receive screen placeholder")
            case .shield:
                PlaceholderContentView(text: "Shield screen placeholder")
            case .unshield:
                PlaceholderContentView(text: "Unshield screen placeholder")
            }
            
            Spacer()
        }
        .brandBackground()
        .foregroundColor(WalletBrandAssets.Color.textPrimary)
        .onReceive(NotificationCenter.default.publisher(for: .applyTransactSegment)) { output in
            if let segment = output.object as? Segment {
                selectedSegment = segment
            }
        }
    }
}

private struct PlaceholderContentView: View {
    let text: String
    var body: some View {
        Text(text)
            .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.7))
            .font(.title3)
    }
}

// MARK: - LegacyDustScreen

struct LegacyDustScreen: View {
    var body: some View {
        VStack(spacing: 32) {
            DustFuelRing(currentDust: 47_200_000, targetDustFor100Txns: 50_000_000)
                .frame(width: 160, height: 160)
            
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 16) {
                    MetricCard(
                        title: "Spendable",
                        value: "12,345 NIGHT",
                        systemImage: "wallet.pass"
                    )
                    MetricCard(
                        title: "Registered UTXOs",
                        value: "3,482",
                        systemImage: "tray.full"
                    )
                    MetricCard(
                        title: "Generation Rate",
                        value: "0.023 DUST/sec",
                        systemImage: "speedometer"
                    )
                }
                .padding(.horizontal)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .brandBackground()
        .foregroundColor(WalletBrandAssets.Color.textPrimary)
    }
}

struct MetricCard: View {
    let title: String
    let value: String
    let systemImage: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .foregroundColor(WalletBrandAssets.Color.midnightBlue)
                Text(title)
                    .font(.headline)
            }
            Text(value)
                .font(.title3)
                .monospacedDigit()
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 16).fill(WalletBrandAssets.Color.card))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(WalletBrandAssets.Color.cardBorder, lineWidth: 1)
        )
        .frame(minWidth: 140)
    }
}

// MARK: - LegacyMessagesScreen

struct LegacyMessagesScreen: View {
    var body: some View {
        NavigationView {
            List {
                Section {
                    Text("DUST")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .padding(.vertical, 4)
                        .padding(.horizontal, 10)
                        .background(
                            Capsule()
                                .fill(WalletBrandAssets.Color.card)
                        )
                        .foregroundColor(WalletBrandAssets.Color.textPrimary)
                        .listRowBackground(Color.clear)
                }
                
                ForEach(0..<5) { index in
                    HStack(spacing: 12) {
                        Circle()
                            .fill(WalletBrandAssets.Color.midnightBlue.opacity(0.2))
                            .frame(width: 44, height: 44)
                            .overlay(
                                Image(systemName: "bubble.left.and.bubble.right.fill")
                                    .font(.title2)
                                    .foregroundColor(WalletBrandAssets.Color.midnightBlue)
                            )
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Conversation \(index + 1)")
                                .font(.headline)
                                .foregroundColor(WalletBrandAssets.Color.textPrimary)
                            Text("Last message preview here...")
                                .font(.subheadline)
                                .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.7))
                        }
                        Spacer()
                        Text("2d")
                            .font(.caption)
                            .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.5))
                    }
                    .padding(.vertical, 8)
                }
            }
            .listStyle(.inset)
            .background(WalletBrandAssets.Color.background)
            .navigationTitle("Messages")
        }
    }
}

// MARK: - MoreScreen

struct MoreScreen: View {
    var body: some View {
        NavigationView {
            List {
                Section {
                    Text("Activity History")
                    Text("Permissions")
                    Text("Settings")
                }
            }
            .listStyle(.inset)
            .background(WalletBrandAssets.Color.background)
            .navigationTitle("More")
            .foregroundColor(WalletBrandAssets.Color.textPrimary)
        }
    }
}

private struct QuickActionButton: View {
    let title: String
    let systemImage: String
    let filled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                ZStack {
                    Circle()
                        .fill(filled ? WalletBrandAssets.Color.midnightBlue : .clear)
                        .overlay(
                            Circle().stroke(WalletBrandAssets.Color.cardBorder, lineWidth: filled ? 0 : 1)
                        )
                        .frame(width: 56, height: 56)
                        .overlay(
                            Image(systemName: systemImage)
                                .font(.system(size: 20, weight: .semibold))
                                .foregroundColor(filled ? .white : WalletBrandAssets.Color.textPrimary)
                        )
                }
                Text(title)
                    .font(WalletBrandAssets.Typography.caption)
                    .foregroundColor(WalletBrandAssets.Color.textSecondary)
            }
        }
        .buttonStyle(.plain)
    }
}

extension Notification.Name {
    static let selectTransactSegment = Notification.Name("selectTransactSegment")
    static let applyTransactSegment = Notification.Name("applyTransactSegment")
}

#Preview {
    RootTabView()
}
