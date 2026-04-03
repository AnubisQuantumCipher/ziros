import SwiftUI
import Foundation

struct RootTabView: View {
    enum Tab {
        case overview, transact, dust, messages, more
    }
    
    @State private var selection: Tab = .overview
    
    var body: some View {
        TabView(selection: $selection) {
            OverviewScreen()
                .tabItem {
                    Label("Overview", systemImage: "house")
                }
                .tag(Tab.overview)
            
            TransactScreen()
                .tabItem {
                    Label("Transact", systemImage: "arrow.left.arrow.right")
                }
                .tag(Tab.transact)
            
            DustScreen()
                .tabItem {
                    Label {
                        Text("DUST")
                    } icon: {
                        Image(systemName: "flame")
                            .symbolRenderingMode(.hierarchical)
                            .foregroundStyle(selection == .dust ? WalletBrandAssets.Color.amber : WalletBrandAssets.Color.textPrimary)
                    }
                }
                .tag(Tab.dust)
            
            MessagesScreen()
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
    }
}

// MARK: - OverviewScreen

struct OverviewScreen: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("3,482,053.94")
                .font(WalletBrandAssets.Typography.balanceHero)
                .foregroundColor(WalletBrandAssets.Color.textPrimary)
            
            Text("NIGHT")
                .font(.caption)
                .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.8))
                .textCase(.uppercase)
            
            PrivacyGauge(value: 0.73)
                .frame(width: 64, height: 64)
            
            HStack(spacing: 8) {
                Text("DUST: 47.2M  •  ~94 txns")
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(WalletBrandAssets.Color.textPrimary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(WalletBrandAssets.Color.cardBackground)
                    )
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(WalletBrandAssets.Color.background)
    }
}

// MARK: - TransactScreen

struct TransactScreen: View {
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
        .background(WalletBrandAssets.Color.background)
        .foregroundColor(WalletBrandAssets.Color.textPrimary)
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

// MARK: - DustScreen

struct DustScreen: View {
    var body: some View {
        VStack(spacing: 32) {
            DustFuelRing(progress: 0.67, fuelValue: 47_200_000, generationRate: 0.023)
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
        .background(WalletBrandAssets.Color.background)
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
        .background(RoundedRectangle(cornerRadius: 16).fill(WalletBrandAssets.Color.cardBackground))
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(WalletBrandAssets.Color.cardBorder, lineWidth: 1)
        )
        .frame(minWidth: 140)
    }
}

// MARK: - MessagesScreen

struct MessagesScreen: View {
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
                                .fill(WalletBrandAssets.Color.cardBackground)
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
            .listStyle(InsetGroupedListStyle())
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
            .listStyle(InsetGroupedListStyle())
            .background(WalletBrandAssets.Color.background)
            .navigationTitle("More")
            .foregroundColor(WalletBrandAssets.Color.textPrimary)
        }
    }
}

// MARK: - Supporting Views

struct PrivacyGauge: View {
    let value: CGFloat // 0 to 1
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(WalletBrandAssets.Color.cardBorder, lineWidth: 8)
            Circle()
                .trim(from: 0, to: value)
                .stroke(WalletBrandAssets.Color.midnightBlue, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(Int(value * 100))%")
                .font(.caption)
                .fontWeight(.semibold)
                .foregroundColor(WalletBrandAssets.Color.textPrimary)
        }
    }
}

struct DustFuelRing: View {
    let progress: CGFloat // 0 to 1
    let fuelValue: Int
    let generationRate: Double
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(WalletBrandAssets.Color.cardBorder, lineWidth: 14)
                .opacity(0.3)
            Circle()
                .trim(from: 0, to: progress)
                .stroke(WalletBrandAssets.Color.amber, style: StrokeStyle(lineWidth: 14, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 4) {
                Text("\(fuelValue.formatted(.number))")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    .foregroundColor(WalletBrandAssets.Color.textPrimary)
                Text("DUST")
                    .font(.caption)
                    .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.7))
                Text("~\(generationRate, specifier: "%.3f") DUST/sec")
                    .font(.caption2)
                    .foregroundColor(WalletBrandAssets.Color.textPrimary.opacity(0.5))
            }
        }
    }
}

#Preview {
    RootTabView()
}
