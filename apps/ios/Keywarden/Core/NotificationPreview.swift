import Foundation

struct NotificationPreviewContext: Codable {
    let settings: Settings
    let decryptionKey: Data
    let requests: [RelayRequest]
    let completedRequestIDs: [String]
}

struct NotificationPreviewStore {
    let keychain: KeychainStore

    init(keychain: KeychainStore? = nil) {
        self.keychain = keychain ?? KeychainStore(
            service: "ai.sawmills.keywarden.notification-preview",
            accessGroup: Bundle.main.object(forInfoDictionaryKey: "NotificationKeychainAccessGroup") as? String
        )
    }

    func save(_ context: NotificationPreviewContext) throws {
        try keychain.save(JSONEncoder().encode(context), for: "context")
    }

    func load() throws -> NotificationPreviewContext? {
        try keychain.load("context").map { try JSONDecoder().decode(NotificationPreviewContext.self, from: $0) }
    }
}

enum VerifiedRequest {
    static func decode(_ item: RelayRequest, settings: Settings, crypto: CryptoBox, now: Date = Date()) throws -> SessionRequest {
        let pinned = try JSONDecoder().decode(JWK.self, from: Data(settings.brokerSigningPublicJWK.utf8))
        guard try crypto.verify(item.envelope, from: pinned, kind: "session_request") else { throw KeywardenError.invalidEnvelope }
        let request = try JSONDecoder().decode(SessionRequest.self, from: crypto.decrypt(item.envelope.body))
        guard request.version == 1, request.type == "open_session", request.id == item.requestId,
              request.phoneId == settings.phoneID, item.phoneId == settings.phoneID,
              request.expiresAt == item.expiresAt, let expiry = parseDate(request.expiresAt),
              request.durationSeconds > 0, request.durationSeconds <= 86400,
              request.idleTimeoutSeconds > 0, request.idleTimeoutSeconds <= request.durationSeconds else {
            throw KeywardenError.invalidEnvelope
        }
        guard expiry > now else { throw KeywardenError.requestExpired }
        return request
    }
}

struct NotificationPreviewLoader {
    let relay: RelayClient

    init(relay: RelayClient? = nil) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 6
        configuration.timeoutIntervalForResource = 8
        self.relay = relay ?? RelayClient(session: URLSession(configuration: configuration))
    }

    func request(_ id: String, context: NotificationPreviewContext) async throws -> SessionRequest {
        guard id.range(of: "^[A-Za-z0-9_-]{1,200}$", options: .regularExpression) != nil,
              context.settings.isConfigured else { throw KeywardenError.invalidEnvelope }
        guard !context.completedRequestIDs.contains(id) else { throw KeywardenError.requestExpired }
        let crypto = CryptoBox(decryptionKey: context.decryptionKey)
        if let cached = context.requests.first(where: { $0.id == id }) {
            return try VerifiedRequest.decode(cached, settings: context.settings, crypto: crypto)
        }
        let received = try await relay.pendingRequests(settings: context.settings)
        try Task.checkCancellation()
        guard let item = received.first(where: { $0.id == id }) else { throw KeywardenError.requestExpired }
        return try VerifiedRequest.decode(item, settings: context.settings, crypto: crypto)
    }
}
