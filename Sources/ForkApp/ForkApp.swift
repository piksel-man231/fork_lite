import SwiftUI
import ForkCore

@main
struct ForkApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView().environmentObject(model)
        } label: {
            Image(systemName: model.menuSymbol)
        }
        .menuBarExtraStyle(.window)

        Window("Fork Lite", id: "main") {
            TabView {
                ConnectionsView().tabItem { Label("Соединения", systemImage: "list.bullet.rectangle") }
                ServersView().tabItem { Label("Серверы", systemImage: "server.rack") }
                RulesView().tabItem { Label("Правила", systemImage: "arrow.triangle.branch") }
            }
            .environmentObject(model).frame(minWidth: 860, minHeight: 560)
            .onAppear { NSApp.setActivationPolicy(.regular) }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { event in
                guard let window = event.object as? NSWindow, window.title == "Fork Lite" else { return }
                NSApp.setActivationPolicy(.accessory)
            }
        }
    }
}

extension AppModel {
    var menuSymbol: String {
        switch settings.xrayOn {
        case false: return "arrow.triangle.branch"
        default: return "arrow.triangle.merge"
        }
    }
}
