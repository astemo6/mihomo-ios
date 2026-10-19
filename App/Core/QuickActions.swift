import UserNotifications
import UIKit
import SwiftUI
import NetworkExtension

/// Home-screen quick actions (UIApplicationShortcutItems in Info.plist): toggle and outbound modes.
enum QuickActions {
    static func handle(_ type: String) {
        let action = type.split(separator: ".").last.map(String.init) ?? type
        Task { @MainActor in
            switch action {
            case "toggle":
                let vpn = VPNManager.shared
                await vpn.load()
                if vpn.isConnected || vpn.status == .connecting { await vpn.disconnectAndWait() } else { _ = await vpn.connectAndWait() }
            case "rule", "global", "direct":
                await VPNManager.shared.load()
                await DashboardModel.shared.setMode(action)
            default:
                break
            }
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // v0.11: Live Activity background refresh + refresh button (must be registered during launch).
        LiveActivityController.registerBackgroundWork()
        ControllerClient.migrateCloseOnSwitch()
        // v0.14: scheduled subscription updates in the background + banners while the app is open.
        ScheduledUpdates.registerBackgroundWork()
        UNUserNotificationCenter.current().delegate = NotificationPresenter.shared
        return true
    }

    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession,
                     options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        if let item = options.shortcutItem { QuickActions.handle(item.type) }
        // Documents / links that launched the app; onOpenURL normally delivers them, this is the fallback.
        let urls = options.urlContexts.map(\.url)
        if !urls.isEmpty {
            Task { @MainActor in ImportRouter.shared.coldLaunchURLs.append(contentsOf: urls) }
        }
        let cfg = UISceneConfiguration(name: nil, sessionRole: connectingSceneSession.role)
        cfg.delegateClass = QuickActionSceneDelegate.self
        return cfg
    }
}

final class QuickActionSceneDelegate: NSObject, UIWindowSceneDelegate {
    func windowScene(_ windowScene: UIWindowScene, performActionFor shortcutItem: UIApplicationShortcutItem,
                     completionHandler: @escaping (Bool) -> Void) {
        QuickActions.handle(shortcutItem.type)
        completionHandler(true)
    }
}
