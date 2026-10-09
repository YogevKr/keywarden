import Foundation
import UserNotifications

struct NotificationBanner: Equatable {
    let title: String
    let subtitle: String
    let body: String

    init(request: SessionRequest) {
        // Do not put free-text intent, item names, field values, or session names in banners.
        title = "\(Self.clean(request.client?.displayName ?? request.agent, limit: 40)) requests access"
        subtitle = Self.clean(request.scope.accounts.map { $0.capitalized }.joined(separator: ", "), limit: 80)
        let vaults = request.scope.vaults.contains("*") ? "All allowed vaults" : request.scope.vaults.joined(separator: ", ")
        let operations = request.scope.operations.map { $0.capitalized }.joined(separator: ", ")
        let duration = request.durationSeconds < 60 ? "\(request.durationSeconds) sec" : "\(request.durationSeconds / 60) min"
        body = "\(Self.clean(operations, limit: 50)) · \(Self.clean(vaults, limit: 100)) · \(duration)"
    }

    private static func clean(_ value: String, limit: Int) -> String {
        let printable = value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && $0.properties.generalCategory != .format }
        return String(String(String.UnicodeScalarView(printable)).prefix(limit))
    }
}

struct NotificationBannerLoader {
    let relay: RelayClient
    let loadContext: () throws -> NotificationPreviewContext?

    init(relay: RelayClient = NotificationPreviewLoader().relay,
         loadContext: @escaping () throws -> NotificationPreviewContext? = { try NotificationPreviewStore().load() }) {
        self.relay = relay
        self.loadContext = loadContext
    }

    func banner(requestID: String, previews: UNShowPreviewsSetting) async throws -> NotificationBanner? {
        // iOS hides this text on the Lock Screen. Never enrich when previews are set to Always.
        guard previews == .whenAuthenticated, let context = try loadContext() else { return nil }
        let request = try await NotificationPreviewLoader(relay: relay).request(requestID, context: context)
        try Task.checkCancellation()
        // Keychain becomes unavailable after locking. Recheck it after the network wait.
        guard let current = try loadContext(), current.settings == context.settings,
              current.decryptionKey == context.decryptionKey,
              !current.completedRequestIDs.contains(requestID),
              let expiry = parseDate(request.expiresAt), expiry > Date() else { return nil }
        return NotificationBanner(request: request)
    }
}

// The extension can expire while a relay call finishes. Deliver exactly once in either path.
final class NotificationBannerDelivery {
    private let lock = NSLock()
    private let original: UNNotificationContent
    private var handler: ((UNNotificationContent) -> Void)?

    init(original: UNNotificationContent, handler: @escaping (UNNotificationContent) -> Void) {
        self.original = original
        self.handler = handler
    }

    func finish(_ banner: NotificationBanner? = nil) {
        lock.lock()
        let callback = handler
        handler = nil
        lock.unlock()
        guard let callback else { return }
        guard let banner, let content = original.mutableCopy() as? UNMutableNotificationContent else {
            callback(original)
            return
        }
        content.title = banner.title
        content.subtitle = banner.subtitle
        content.body = banner.body
        callback(content)
    }
}
