import Foundation

extension ApprovalModel {
    static func applicationModel() -> ApprovalModel {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-fixture") {
            let fixtureAuthentication: ((String) async throws -> Void)? = ProcessInfo.processInfo.arguments.contains("--notification-preview-fixture") ? { reason in
                throw NSError(domain: "KeywardenUITest", code: 1, userInfo: [NSLocalizedDescriptionKey: "Notification test: \(reason)"])
            } : nil
            let model = ApprovalModel(keychain: KeychainStore(service: "keywarden.ui-fixtures"), defaults: UserDefaults(suiteName: "keywarden.ui-fixtures")!, authentication: fixtureAuthentication)
            model.settings = Settings(relayURL: "https://example.invalid", relayToken: "fixture", brokerID: "broker_fixture", phoneID: "phone_fixture", brokerSigningPublicJWK: "{}", brokerEncryptionPublicJWK: "{}")
            model.lastSync = Date()
            model.notificationPermission = .enabled
            let arguments = ProcessInfo.processInfo.arguments
            if arguments.contains("--notifications-denied") { model.notificationPermission = .denied }
            if arguments.contains("--notifications-new") { model.notificationPermission = .notRequested }
            if arguments.contains("--notifications-quiet") { model.notificationPermission = .quiet }
            if arguments.contains("--notifications-alerts-off") { model.notificationPermission = .alertsOff }
            if arguments.contains("--unpaired") { model.settings = Settings(); model.lastSync = nil }
            let formatter = ISO8601DateFormatter()
            func request(_ id: String, reason: String) -> SessionRequest {
                SessionRequest(version: 1, type: "open_session", id: id, agent: "Codex", host: "Developer Mac", phoneId: "phone_fixture", reason: reason, scope: SessionScope(accounts: ["agent"], vaults: ["agents"], items: .all, operations: ["read"]), durationSeconds: 900, idleTimeoutSeconds: 300, createdAt: formatter.string(from: Date()), expiresAt: formatter.string(from: Date().addingTimeInterval(300)), nonce: "fixture")
            }
            let current = request("request_fixture", reason: "Read credentials for the deployment check.")
            let key = JWK(kty: "EC", crv: "P-256", x: nil, y: nil, d: nil, ext: nil, keyOps: nil)
            let envelope = SignedEnvelope(version: 1, kind: "session_request", body: EncryptedPayload(version: 1, algorithm: "ECDH-P256-AES-256-GCM", ephemeralPublicKey: key, iv: "", ciphertext: ""), senderPublicKey: key, signature: "")
            if !ProcessInfo.processInfo.arguments.contains("--empty") {
                model.requests = [DecodedRequest(relayRequest: RelayRequest(requestId: current.id, phoneId: current.phoneId, expiresAt: current.expiresAt, envelope: envelope), request: current)]
            }
            model.history = [
                ApprovalRecord(brokerID: "broker_fixture", request: request("old_approved", reason: "Check the test connection."), requestHash: "fixture", decision: "approve", decidedAt: Date().addingTimeInterval(-3600), session: SessionStatus(version: 1, type: "session_status", requestId: "old_approved", requestHash: "fixture", status: "expired", issuedAt: nil, expiresAt: nil, idleUntil: nil, observedAt: formatter.string(from: Date()))),
                ApprovalRecord(brokerID: "broker_fixture", request: request("old_denied", reason: "Requested access was too broad."), requestHash: "fixture", decision: "deny", decidedAt: Date().addingTimeInterval(-7200))
            ]
            if arguments.contains("--notification-preview-fixture") {
                do {
                    let broker = CryptoBox(keychain: KeychainStore(service: "keywarden.notification-fixture.broker"))
                    let phone = CryptoBox(keychain: KeychainStore(service: "keywarden.notification-fixture.phone"))
                    model.settings.brokerSigningPublicJWK = String(decoding: try JSONEncoder().encode(broker.signingPublicKey()), as: UTF8.self)
                    model.settings.brokerEncryptionPublicJWK = String(decoding: try JSONEncoder().encode(broker.encryptionPublicKey()), as: UTF8.self)
                    var preview = current
                    preview.client = ClientMetadata(product: "codex", clientName: "Codex", displayName: "Codex", productVersion: "test", protocolVersion: "test", transport: "stdio", sessionID: "fixture", sessionName: "Notification preview test", host: current.host, project: nil, pid: nil, capabilities: [])
                    let signed = try broker.sign(preview, kind: "session_request", for: phone.encryptionPublicKey())
                    let item = RelayRequest(requestId: preview.id, phoneId: preview.phoneId, expiresAt: preview.expiresAt, envelope: signed)
                    model.requests = [DecodedRequest(relayRequest: item, request: preview)]
                    try NotificationPreviewStore().save(NotificationPreviewContext(settings: model.settings, decryptionKey: phone.notificationDecryptionKey(), requests: [item], completedRequestIDs: []))
                } catch { model.errorMessage = "Could not prepare the notification test." }
            }
            return model
        }
        #endif
        return ApprovalModel()
    }
}
