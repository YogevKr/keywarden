import Foundation
import LocalAuthentication
import UIKit
import UserNotifications

@MainActor
final class ApprovalModel: ObservableObject {
    @Published var settings = Settings()
    @Published var requests: [DecodedRequest] = []
    @Published var history: [ApprovalRecord] = []
    @Published var message = ""
    @Published var errorMessage: String?
    @Published var isPolling = false
    @Published var showingScanner = false
    @Published var busyID: String?
    @Published var lastSync: Date?
    @Published var notificationPermission: NotificationPermission = .checking
    @Published var notificationError: String?
    @Published var requestingNotifications = false
    @Published var presentedRequest: DecodedRequest?
    private(set) var notificationAction: NotificationRoute?
    private var deviceToken: String?

    private let relay: RelayClient
    private let crypto: CryptoBox
    private let keychain: KeychainStore
    private let defaults: UserDefaults
    private let authentication: ((String) async throws -> Void)?
    private let settingsKey = "keywarden.settings"
    private var timer: Task<Void, Never>?
    private var refreshing = false

    init(relay: RelayClient = RelayClient(), crypto: CryptoBox = CryptoBox(), keychain: KeychainStore = KeychainStore(), defaults: UserDefaults = .standard, authentication: ((String) async throws -> Void)? = nil) {
        self.relay = relay
        self.crypto = crypto
        self.keychain = keychain
        self.defaults = defaults
        self.authentication = authentication
        if let data = defaults.data(forKey: settingsKey), let saved = try? JSONDecoder().decode(Settings.self, from: data) { settings = saved }
        do {
            if let data = try keychain.load("relay-token"), let token = String(data: data, encoding: .utf8) { settings.relayToken = token }
            if let data = try keychain.load("approval-history") { history = try JSONDecoder().decode([ApprovalRecord].self, from: data) }
        } catch { errorMessage = "Could not load saved data. Unlock your phone and try again." }
    }

    @discardableResult
    func saveSettings() -> Bool {
        do {
            var persisted = settings
            persisted.relayToken = ""
            let data = try JSONEncoder().encode(persisted)
            try keychain.save(Data(settings.relayToken.utf8), for: "relay-token")
            defaults.set(data, forKey: settingsKey)
            prepareNotificationPreview()
            errorMessage = nil
            return true
        } catch {
            errorMessage = "Could not save settings. Try again."
            return false
        }
    }

    func applySetupQR(_ value: String) async {
        guard busyID == nil else { return }
        busyID = "pairing"
        defer { busyID = nil }
        do {
            let payload = try SetupPayload.decode(value)
            var updated = Settings()
            updated.relayURL = payload.relayURL
            updated.relayToken = payload.relayToken
            updated.brokerID = payload.brokerId
            updated.phoneID = payload.phoneId
            updated.brokerSigningPublicJWK = String(decoding: try JSONEncoder().encode(payload.brokerSigningPublicJWK), as: UTF8.self)
            updated.brokerEncryptionPublicJWK = String(decoding: try JSONEncoder().encode(payload.brokerEncryptionPublicJWK), as: UTF8.self)
            let pairing = PhonePairingPayload(phoneId: payload.phoneId, pairingToken: payload.pairingToken, signingPublicJWK: try crypto.signingPublicKey(), encryptionPublicJWK: try crypto.encryptionPublicKey())
            try await relay.submitPairing(crypto.sign(pairing, kind: "phone_pairing", for: payload.brokerEncryptionPublicJWK), settings: updated)
            stopPolling()
            settings = updated
            requests = []
            lastSync = nil
            guard saveSettings() else { return }
            message = "Phone connected."
            startPolling()
            if let deviceToken { await registerPush(deviceToken) }
        } catch { errorMessage = "Could not connect this phone. \(error.localizedDescription)" }
    }

    func startPolling() {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-fixture") { return }
        #endif
        guard settings.isConfigured, !isPolling else { return }
        isPolling = true
        timer = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll()
                do { try await Task.sleep(for: .seconds(3)) } catch { break }
            }
        }
    }

    func stopPolling() {
        timer?.cancel()
        timer = nil
        isPolling = false
    }

    func enableNotifications() async {
        guard !requestingNotifications, notificationPermission == .notRequested else { return }
        requestingNotifications = true
        defer { requestingNotifications = false }
        do {
            _ = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
            notificationError = nil
            await refreshNotificationState()
        } catch { notificationError = "Could not check notification permission. Try again." }
    }

    func refreshNotificationState() async {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-fixture") { return }
        #endif
        let state = await UNUserNotificationCenter.current().notificationSettings()
        notificationPermission = NotificationPermission(authorization: state.authorizationStatus, alerts: state.alertSetting)
        if notificationPermission.canRegister { UIApplication.shared.registerForRemoteNotifications() }
    }

    func registerPush(_ token: String) async {
        deviceToken = token
        guard settings.isConfigured else { return }
        do {
            #if DEBUG
            let environment = "development"
            #else
            let environment = "production"
            #endif
            let payload = PushRegistration(phoneId: settings.phoneID, deviceToken: token, environment: environment)
            let key = try JSONDecoder().decode(JWK.self, from: Data(settings.brokerEncryptionPublicJWK.utf8))
            try await relay.registerPush(crypto.sign(payload, kind: "push_registration", for: key), settings: settings)
            notificationError = nil
        } catch { notificationError = "Could not register this phone for alerts. Check your connection and try again." }
    }

    func prepareNotificationPreview() {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-fixture") { return }
        #endif
        do {
            if settings.relayToken.isEmpty, let data = try keychain.load("relay-token"),
               let token = String(data: data, encoding: .utf8) { settings.relayToken = token }
            try NotificationPreviewStore().save(NotificationPreviewContext(
                settings: settings,
                decryptionKey: settings.isConfigured ? try crypto.notificationDecryptionKey() : Data(),
                requests: requests.map(\.relayRequest),
                completedRequestIDs: history.filter { $0.brokerID == settings.brokerID }.map(\.id)
            ))
        } catch { notificationError = "Could not prepare notification previews. Open Keywarden while your phone is unlocked." }
    }

    func poll() async {
        #if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--ui-fixture") { return }
        #endif
        guard settings.isConfigured, !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        requests.removeAll { request in
            guard let expiry = parseDate(request.request.expiresAt) else { return true }
            return expiry <= Date()
        }
        let connection = settings
        do {
            let pinnedKey = try JSONDecoder().decode(JWK.self, from: Data(connection.brokerSigningPublicJWK.utf8))
            let received = try await relay.pendingRequests(settings: connection)
            guard connection.brokerID == settings.brokerID, !Task.isCancelled else { return }
            var decoded: [DecodedRequest] = []
            var rejected = false
            for item in received {
                do {
                    let request = try VerifiedRequest.decode(item, settings: connection, crypto: crypto)
                    if history.contains(where: { $0.id == request.id }) { continue }
                    if !decoded.contains(where: { $0.id == request.id }) { decoded.append(DecodedRequest(relayRequest: item, request: request)) }
                } catch KeywardenError.requestExpired { continue }
                  catch { rejected = true }
            }
            requests = decoded.sorted { $0.request.createdAt > $1.request.createdAt }
            prepareNotificationPreview()
            errorMessage = rejected ? "A request failed verification. It cannot be approved." : nil
            lastSync = Date()
            await refreshHistory(connection: connection, pinnedKey: pinnedKey)
        } catch {
            if !Task.isCancelled {
                requests.removeAll()
                errorMessage = "Cannot reach your connection. Pull down to try again."
            }
        }
    }

    func openRequest(_ requestID: String?) async {
        presentedRequest = nil
        notificationAction = nil
        guard let requestID else { message = "This notification has no request."; return }
        while refreshing {
            do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
        }
        await poll()
        guard !Task.isCancelled, let request = requests.first(where: { $0.id == requestID }) else {
            message = "This request is no longer available."
            return
        }
        presentedRequest = request
    }

    func openNotification(_ route: NotificationRoute) async {
        await openRequest(route.requestID)
        if presentedRequest?.id == route.requestID { notificationAction = route }
    }

    func performNotificationAction(for requestID: String) async {
        guard let route = notificationAction, route.requestID == requestID,
              let request = presentedRequest, request.id == requestID, busyID == nil else { return }
        notificationAction = nil
        switch route.action {
        case .approve: await approve(request)
        case .reject: await deny(request)
        case .review: break
        }
    }

    func approve(_ request: DecodedRequest) async { await decide(request, value: "approve") }
    func deny(_ request: DecodedRequest) async { await decide(request, value: "deny") }

    private func decide(_ decoded: DecodedRequest, value: String) async {
        guard busyID == nil else { return }
        busyID = decoded.id
        defer { busyID = nil }
        let connection = settings
        do {
            guard let expiry = parseDate(decoded.request.expiresAt), expiry > Date() else { throw KeywardenError.requestExpired }
            try await authenticateUser(reason: value == "approve" ? "Approve access for \(decoded.request.agent)" : "Deny this access request")
            guard expiry > Date() else { throw KeywardenError.requestExpired }
            guard connection.brokerID == settings.brokerID, connection.phoneID == settings.phoneID,
                  connection.brokerSigningPublicJWK == settings.brokerSigningPublicJWK,
                  requests.contains(where: { $0.id == decoded.id }),
                  !history.contains(where: { $0.id == decoded.id }) else { throw KeywardenError.invalidEnvelope }
            let hash = try crypto.hash(decoded.request)
            let decision = ApprovalDecision(version: 1, type: "approval_decision", requestId: decoded.request.id, requestHash: hash, decision: value, decidedAt: ISO8601DateFormatter().string(from: Date()), nonce: UUID().uuidString)
            let brokerKey = try JSONDecoder().decode(JWK.self, from: Data(settings.brokerEncryptionPublicJWK.utf8))
            let envelope = try crypto.signDecision(decision, brokerEncryptionKey: brokerKey)
            try await relay.submitDecision(envelope, requestID: decoded.id, settings: settings)
            history.removeAll { $0.id == decoded.id }
            history.insert(ApprovalRecord(brokerID: settings.brokerID, request: decoded.request, requestHash: hash, decision: value, decidedAt: Date()), at: 0)
            try saveHistory()
            requests.removeAll { $0.id == decoded.id }
            prepareNotificationPreview()
            await removeNotification(for: decoded.id)
            if presentedRequest?.id == decoded.id { presentedRequest = nil }
            errorMessage = nil
            message = value == "approve" ? "Approval sent. Waiting for your Mac." : "Request denied."
            await poll()
        } catch {
            if case KeywardenError.requestExpired = error {
                requests.removeAll { $0.id == decoded.id }
                errorMessage = error.localizedDescription
            } else if (error as? LAError)?.code != .userCancel {
                errorMessage = "Could not send your decision. \(error.localizedDescription)"
            }
        }
    }

    private func removeNotification(for requestID: String) async {
        let center = UNUserNotificationCenter.current()
        let delivered = await center.deliveredNotifications()
        let identifiers = delivered.filter { $0.request.content.userInfo["requestId"] as? String == requestID }.map { $0.request.identifier }
        center.removeDeliveredNotifications(withIdentifiers: identifiers)
    }

    func revoke(_ record: ApprovalRecord) async {
        guard busyID == nil, record.brokerID == settings.brokerID else { return }
        busyID = record.id
        defer { busyID = nil }
        do {
            try await authenticateUser(reason: "Revoke access for \(record.request.agent)")
            let value = SessionRevocation(requestId: record.id, requestHash: record.requestHash, decidedAt: ISO8601DateFormatter().string(from: Date()), nonce: UUID().uuidString)
            let key = try JSONDecoder().decode(JWK.self, from: Data(settings.brokerEncryptionPublicJWK.utf8))
            try await relay.revoke(crypto.sign(value, kind: "session_revoke", for: key), requestID: record.id, settings: settings)
            if let index = history.firstIndex(where: { $0.id == record.id }) { history[index].revokeRequested = true }
            try saveHistory()
            message = "Revocation sent. Waiting for your Mac."
            errorMessage = nil
            await poll()
        } catch { errorMessage = "Could not revoke access. Try again." }
    }

    private func refreshHistory(connection: Settings, pinnedKey: JWK) async {
        let records = history.filter { $0.brokerID == connection.brokerID && !["expired", "revoked", "denied"].contains($0.state()) }
        for record in records {
            do {
                guard let envelope = try await relay.sessionStatus(requestID: record.id, settings: connection) else { continue }
                guard try crypto.verify(envelope, from: pinnedKey, kind: "session_status") else { throw KeywardenError.invalidEnvelope }
                let status = try JSONDecoder().decode(SessionStatus.self, from: crypto.decrypt(envelope.body))
                guard status.version == 1, status.type == "session_status", status.requestId == record.id, status.requestHash == record.requestHash,
                      let observed = parseDate(status.observedAt), observed <= Date().addingTimeInterval(30) else { throw KeywardenError.invalidEnvelope }
                if let old = record.session.flatMap({ parseDate($0.observedAt) }), observed < old { continue }
                if let index = history.firstIndex(where: { $0.id == record.id }) { history[index].session = status }
            } catch { errorMessage = "Cannot confirm session status. Access status may be out of date." }
        }
        do { try saveHistory() } catch { errorMessage = "Could not save approval history." }
    }

    private func saveHistory() throws {
        history = Array(history.prefix(200))
        try keychain.save(JSONEncoder().encode(history), for: "approval-history")
    }

    private func authenticateUser(reason: String) async throws {
        if let authentication { try await authentication(reason); return }
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            if let error { throw error }
            throw KeywardenError.authenticationFailed
        }
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
    }
}

struct DecodedRequest: Identifiable {
    let relayRequest: RelayRequest
    let request: SessionRequest
    var id: String { relayRequest.id }
}
