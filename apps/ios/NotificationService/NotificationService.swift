import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private var work: Task<Void, Never>?
    private var delivery: NotificationBannerDelivery?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        work?.cancel()
        delivery?.finish()
        let delivery = NotificationBannerDelivery(original: request.content, handler: contentHandler)
        self.delivery = delivery
        work = Task {
            do {
                guard request.content.categoryIdentifier == "KEYWARDEN_APPROVAL",
                      let id = request.content.userInfo["requestId"] as? String else { delivery.finish(); return }
                let settings = await UNUserNotificationCenter.current().notificationSettings()
                let banner = try await NotificationBannerLoader().banner(requestID: id, previews: settings.showPreviewsSetting)
                try Task.checkCancellation()
                let current = await UNUserNotificationCenter.current().notificationSettings()
                try Task.checkCancellation()
                delivery.finish(current.showPreviewsSetting == .whenAuthenticated ? banner : nil)
            } catch { delivery.finish() }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        work?.cancel()
        delivery?.finish()
    }
}
