import SwiftUI

@main
struct ZirOSWalletApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var coordinator = WalletCoordinator()

    init() {
        WalletBrandAssets.registerFontsIfNeeded()
    }

    var body: some Scene {
        WindowGroup {
            ContentView(coordinator: coordinator)
#if os(macOS)
                .frame(minWidth: 1100, minHeight: 760)
#endif
                .preferredColorScheme(.dark)
                .tint(Color(red: 0.0, green: 0.0, blue: 0.996))
                .onOpenURL { url in
                    coordinator.handleIncomingBridgeURL(url)
                }
        }
#if os(macOS)
        .commands {
            CommandMenu("Wallet") {
                Button("Refresh") {
                    Task { await coordinator.refresh() }
                }
                .keyboardShortcut("r")

                Button("Lock") {
                    Task { await coordinator.lock() }
                }
                .keyboardShortcut("l")

                Divider()

                Button("Open Overview") {
                    coordinator.selectedSection = .overview
                }
                Button("Open Transact") {
                    coordinator.selectedSection = .transact
                    coordinator.selectedTransactMode = .send
                }
                Button("Open Messages") {
                    coordinator.selectedSection = .messages
                }
                Button("Open DUST") {
                    coordinator.selectedSection = .dust
                }
                Button("Open More") {
                    coordinator.selectedSection = .more
                }
            }
        }
#endif
        .onChange(of: scenePhase) { _, newPhase in
            if newPhase == .background {
                Task { await coordinator.appBackgrounded() }
            } else if newPhase == .active {
                Task { await coordinator.refresh() }
            }
        }
    }
}
