import Foundation
import UserNotifications

enum NotificationAction: String {
    case review = "KEYWARDEN_REVIEW"
    case approve = "KEYWARDEN_APPROVE"
    case reject = "KEYWARDEN_REJECT"
}

struct NotificationRoute: Equatable {
    let requestID: String
    let action: NotificationAction

    init?(requestID: String?, actionIdentifier: String) {
        guard let requestID, requestID.range(of: "^[A-Za-z0-9_-]{1,200}$", options: .regularExpression) != nil else { return nil }
        if actionIdentifier == UNNotificationDefaultActionIdentifier {
            action = .review
        } else if let known = NotificationAction(rawValue: actionIdentifier) {
            action = known
        } else { return nil }
        self.requestID = requestID
    }
}

@MainActor
final class NotificationInbox: ObservableObject {
    static let shared = NotificationInbox()
    @Published private(set) var route: NotificationRoute?

    func receive(_ route: NotificationRoute) { self.route = route }
    func take() -> NotificationRoute? {
        defer { route = nil }
        return route
    }
}
