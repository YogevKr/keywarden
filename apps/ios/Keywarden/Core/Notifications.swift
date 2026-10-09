import UIKit
import UserNotifications

enum NotificationPermission: Equatable {
    case checking, notRequested, enabled, quiet, alertsOff, denied, unavailable

    init(authorization: UNAuthorizationStatus, alerts: UNNotificationSetting) {
        switch authorization {
        case .notDetermined: self = .notRequested
        case .denied: self = .denied
        case .provisional: self = .quiet
        case .authorized, .ephemeral: self = alerts == .enabled ? .enabled : .alertsOff
        @unknown default: self = .unavailable
        }
    }

    var title: String {
        switch self {
        case .checking: return "Checking…"
        case .notRequested: return "Not enabled"
        case .enabled: return "Enabled"
        case .quiet: return "Delivered quietly"
        case .alertsOff: return "Alerts off"
        case .denied: return "Disabled"
        case .unavailable: return "Unavailable"
        }
    }

    var guidance: String {
        switch self {
        case .checking: return "Checking notification permission on this iPhone."
        case .notRequested: return "Get an alert when an agent needs your approval."
        case .enabled: return "iOS permits alerts. Focus and notification schedules can delay them."
        case .quiet: return "Requests arrive quietly. Turn on alerts in iOS Settings to see banners."
        case .alertsOff: return "Notification permission is on, but visible alerts are off. Change this in iOS Settings."
        case .denied: return "Allow notifications in iOS Settings to receive approval alerts."
        case .unavailable: return "Check notification permission in iOS Settings."
        }
    }

    var canRegister: Bool { self == .enabled || self == .quiet || self == .alertsOff }
    var canOpenSettings: Bool { self != .checking && self != .notRequested }
}

extension Notification.Name {
    static let keywardenDeviceToken = Notification.Name("keywarden.deviceToken")
}

final class NotificationDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    private let approvalCategory = "KEYWARDEN_APPROVAL"

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        // Foreground actions already require device unlock. The app performs
        // a fresh biometric check before it signs either decision.
        let approve = UNNotificationAction(identifier: NotificationAction.approve.rawValue, title: "Approve", options: [.foreground])
        let reject = UNNotificationAction(identifier: NotificationAction.reject.rawValue, title: "Reject", options: [.foreground, .destructive])
        let review = UNNotificationAction(identifier: NotificationAction.review.rawValue, title: "More details", options: [.foreground])
        let category = UNNotificationCategory(identifier: approvalCategory, actions: [approve, reject, review], intentIdentifiers: [], options: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-fixture") {
            if ProcessInfo.processInfo.arguments.contains("--notification-preview-fixture") {
                Task {
                    guard (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) == true else { return }
                    let content = UNMutableNotificationContent()
                    content.title = "Approval requested"
                    content.body = "Tap to review the access request."
                    content.categoryIdentifier = approvalCategory
                    content.userInfo = ["requestId": "request_fixture"]
                    try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "keywarden-preview-fixture", content: content, trigger: UNTimeIntervalNotificationTrigger(timeInterval: 8, repeats: false)))
                }
            }
            return true
        }
        #endif
        Task {
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            if NotificationPermission(authorization: settings.authorizationStatus, alerts: settings.alertSetting).canRegister {
                await MainActor.run { application.registerForRemoteNotifications() }
            }
        }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let value = deviceToken.map { String(format: "%02x", $0) }.joined()
        NotificationCenter.default.post(name: .keywardenDeviceToken, object: value)
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        return [.banner, .sound]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let route = NotificationRoute(requestID: requestID(from: response.notification), actionIdentifier: response.actionIdentifier) else { return }
        await MainActor.run { NotificationInbox.shared.receive(route) }
    }

    private func requestID(from notification: UNNotification) -> String? {
        notification.request.content.userInfo["requestId"] as? String
    }
}

struct PushRegistration: Encodable {
    let version = 1
    let type = "push_registration"
    let phoneId: String
    let deviceToken: String
    let environment: String
}
