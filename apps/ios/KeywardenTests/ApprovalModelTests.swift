import CryptoKit
import Security
import UserNotifications
import XCTest
@testable import Keywarden

final class StubRelayProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw URLError(.badServerResponse) }
            let (code, data) = try handler(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}

@MainActor
final class ApprovalModelTests: XCTestCase {
    func testNotificationPermissionDistinguishesQuietAndDisabledAlerts() {
        XCTAssertEqual(NotificationPermission(authorization: .notDetermined, alerts: .disabled), .notRequested)
        XCTAssertEqual(NotificationPermission(authorization: .denied, alerts: .disabled), .denied)
        XCTAssertEqual(NotificationPermission(authorization: .authorized, alerts: .enabled), .enabled)
        XCTAssertEqual(NotificationPermission(authorization: .authorized, alerts: .disabled), .alertsOff)
        XCTAssertEqual(NotificationPermission(authorization: .provisional, alerts: .enabled), .quiet)
        XCTAssertEqual(NotificationPermission(authorization: .ephemeral, alerts: .enabled), .enabled)
        XCTAssertFalse(NotificationPermission.notRequested.canOpenSettings)
        XCTAssertFalse(NotificationPermission.denied.canRegister)
        XCTAssertTrue(NotificationPermission.quiet.canRegister)
        XCTAssertTrue(NotificationPermission.alertsOff.canOpenSettings)
    }

    private var services: [String] = []
    private var suite = ""
    private var defaults: UserDefaults!
    private var phoneStore: KeychainStore!
    private var phone: CryptoBox!
    private var broker: CryptoBox!
    private var relay: RelayClient!
    private var settings: Settings!
    private var authenticationCount = 0

    override func setUp() async throws {
        suite = "keywarden.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
        phoneStore = store()
        phone = CryptoBox(keychain: phoneStore)
        broker = CryptoBox(keychain: store())
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubRelayProtocol.self]
        relay = RelayClient(session: URLSession(configuration: configuration))
        settings = Settings(relayURL: "https://relay.test", relayToken: "test-token", brokerID: "broker_test", phoneID: "phone_test", brokerSigningPublicJWK: String(decoding: try JSONEncoder().encode(broker.signingPublicKey()), as: UTF8.self), brokerEncryptionPublicJWK: String(decoding: try JSONEncoder().encode(broker.encryptionPublicKey()), as: UTF8.self))
    }

    override func tearDown() async throws {
        StubRelayProtocol.handler = nil
        defaults.removePersistentDomain(forName: suite)
        for service in services { SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service] as CFDictionary) }
    }

    private func store() -> KeychainStore {
        let service = "keywarden.tests.\(UUID().uuidString)"
        services.append(service)
        return KeychainStore(service: service)
    }

    private func model() -> ApprovalModel {
        let model = ApprovalModel(relay: relay, crypto: phone, keychain: phoneStore, defaults: defaults, authentication: { [weak self] _ in self?.authenticationCount += 1 })
        model.settings = settings
        return model
    }

    private func request(id: String = "request_test") -> SessionRequest {
        let formatter = ISO8601DateFormatter()
        return SessionRequest(version: 1, type: "open_session", id: id, agent: "Codex", host: "MacBook", phoneId: "phone_test", reason: "Read a test credential", scope: SessionScope(accounts: ["agent"], vaults: ["agents"], items: .values(["test-item"]), operations: ["read"]), durationSeconds: 300, idleTimeoutSeconds: 120, createdAt: formatter.string(from: Date()), expiresAt: formatter.string(from: Date().addingTimeInterval(300)), nonce: "test-nonce-(id)")
    }

    func testNotificationOpensTheTargetRequest() async throws {
        let first = request()
        let second = request(id: "request_second")
        let firstEnvelope = try broker.sign(first, kind: "session_request", for: phone.encryptionPublicKey())
        let secondEnvelope = try broker.sign(second, kind: "session_request", for: phone.encryptionPublicKey())
        StubRelayProtocol.handler = { _ in
            (200, try JSONEncoder().encode(RelayRequestList(requests: [
                RelayRequest(requestId: first.id, phoneId: first.phoneId, expiresAt: first.expiresAt, envelope: firstEnvelope),
                RelayRequest(requestId: second.id, phoneId: second.phoneId, expiresAt: second.expiresAt, envelope: secondEnvelope)
            ])))
        }
        let model = model()
        await model.openRequest(second.id)
        XCTAssertEqual(model.presentedRequest?.id, second.id)
    }

    func testMissingNotificationNeverFallsBackToAnotherRequest() async throws {
        let request = request()
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        StubRelayProtocol.handler = { _ in
            (200, try JSONEncoder().encode(RelayRequestList(requests: [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)])))
        }
        let model = model()
        await model.openNotification(try XCTUnwrap(NotificationRoute(requestID: "missing_request", actionIdentifier: NotificationAction.approve.rawValue)))
        await model.performNotificationAction(for: request.id)
        XCTAssertNil(model.presentedRequest)
        XCTAssertNil(model.notificationAction)
        XCTAssertEqual(authenticationCount, 0)
        XCTAssertEqual(model.message, "This request is no longer available.")
    }

    func testNotificationActionAuthenticatesAndSubmitsOnlyTheTargetOnce() async throws {
        for action in [NotificationAction.approve, .reject] {
            let request = request(id: "request_\(action.rawValue)")
            let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
            let broker = self.broker!
            var decisions: [ApprovalDecision] = []
            StubRelayProtocol.handler = { urlRequest in
                if urlRequest.url!.path.hasSuffix("/decision") {
                    let signed = try JSONDecoder().decode(SignedEnvelope.self, from: Self.body(urlRequest))
                    decisions.append(try JSONDecoder().decode(ApprovalDecision.self, from: broker.decrypt(signed.body)))
                    return (200, Data("{}".utf8))
                }
                if urlRequest.url!.path.hasSuffix("/status") { return (404, Data()) }
                return (200, try JSONEncoder().encode(RelayRequestList(requests: decisions.isEmpty ? [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)] : [])))
            }
            let model = model()
            let before = authenticationCount
            await model.openNotification(try XCTUnwrap(NotificationRoute(requestID: request.id, actionIdentifier: action.rawValue)))
            XCTAssertEqual(decisions.count, 0)
            await model.performNotificationAction(for: "wrong_request")
            XCTAssertEqual(authenticationCount, before)
            await model.performNotificationAction(for: request.id)
            await model.performNotificationAction(for: request.id)
            XCTAssertEqual(authenticationCount, before + 1)
            XCTAssertEqual(decisions.count, 1)
            XCTAssertEqual(decisions.first?.requestId, request.id)
            XCTAssertEqual(decisions.first?.decision, action == .approve ? "approve" : "deny")
        }
    }

    func testCancelledAuthenticationDoesNotSubmitNotificationDecision() async throws {
        let request = request()
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        StubRelayProtocol.handler = { urlRequest in
            XCTAssertEqual(urlRequest.httpMethod, "GET")
            return (200, try JSONEncoder().encode(RelayRequestList(requests: [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)])))
        }
        let model = ApprovalModel(relay: relay, crypto: phone, keychain: phoneStore, defaults: defaults, authentication: { _ in throw KeywardenError.authenticationFailed })
        model.settings = settings
        await model.openNotification(try XCTUnwrap(NotificationRoute(requestID: request.id, actionIdentifier: NotificationAction.approve.rawValue)))
        await model.performNotificationAction(for: request.id)
        XCTAssertTrue(model.history.isEmpty)
        XCTAssertEqual(model.presentedRequest?.id, request.id)
        XCTAssertNil(model.notificationAction)
    }

    func testNotificationInboxRetainsColdLaunchActionAndRejectsUnknownActions() throws {
        let inbox = NotificationInbox()
        let route = try XCTUnwrap(NotificationRoute(requestID: "request_cold", actionIdentifier: NotificationAction.approve.rawValue))
        inbox.receive(route)
        XCTAssertEqual(inbox.take(), route)
        XCTAssertNil(inbox.take())
        XCTAssertNil(NotificationRoute(requestID: nil, actionIdentifier: NotificationAction.approve.rawValue))
        XCTAssertNil(NotificationRoute(requestID: "../wrong", actionIdentifier: NotificationAction.approve.rawValue))
        XCTAssertNil(NotificationRoute(requestID: "request_cold", actionIdentifier: UNNotificationDismissActionIdentifier))
    }

    func testPreviewDecryptsOnlyVerifiedTargetAndRejectsCompletedRequests() async throws {
        let request = request()
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        let item = RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)
        let context = NotificationPreviewContext(settings: settings, decryptionKey: try phone.notificationDecryptionKey(), requests: [item], completedRequestIDs: [])
        let loader = NotificationPreviewLoader(relay: relay)
        let decoded = try await loader.request(request.id, context: context)
        XCTAssertEqual(decoded.reason, request.reason)
        let stored = try JSONEncoder().encode(context)
        XCTAssertFalse(String(decoding: stored, as: UTF8.self).contains(request.reason))
        XCTAssertFalse(String(decoding: stored, as: UTF8.self).contains("signing-private"))
        let completed = NotificationPreviewContext(settings: settings, decryptionKey: context.decryptionKey, requests: [item], completedRequestIDs: [request.id])
        do {
            _ = try await loader.request(request.id, context: completed)
            XCTFail("Completed request must not appear as pending")
        } catch KeywardenError.requestExpired { }
        let changed = RelayRequest(requestId: "other_request", phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)
        XCTAssertThrowsError(try VerifiedRequest.decode(changed, settings: settings, crypto: phone))
        XCTAssertThrowsError(try VerifiedRequest.decode(item, settings: settings, crypto: phone, now: Date().addingTimeInterval(600)))
        let attacker = CryptoBox(keychain: store())
        let forged = RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: try attacker.sign(request, kind: "session_request", for: phone.encryptionPublicKey()))
        XCTAssertThrowsError(try VerifiedRequest.decode(forged, settings: settings, crypto: phone))
    }

    func testPreviewFetchesEncryptedRequestWhenAppHasNotPolled() async throws {
        let request = request()
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        var fetched = false
        StubRelayProtocol.handler = { urlRequest in
            fetched = true
            XCTAssertEqual(urlRequest.httpMethod, "GET")
            return (200, try JSONEncoder().encode(RelayRequestList(requests: [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)])))
        }
        let context = NotificationPreviewContext(settings: settings, decryptionKey: try phone.notificationDecryptionKey(), requests: [], completedRequestIDs: [])
        let decoded = try await NotificationPreviewLoader(relay: relay).request(request.id, context: context)
        XCTAssertEqual(decoded.id, request.id)
        XCTAssertTrue(fetched)
    }

    func testApprovalStatusRevocationAndHistorySurviveRelaunch() async throws {
        let request = request()
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        let hash = try phone.hash(request)
        var decided = false
        var revoked = false
        let broker = self.broker!
        let phone = self.phone!
        StubRelayProtocol.handler = { urlRequest in
            let path = urlRequest.url!.path
            if path.hasSuffix("/decision") {
                let signed = try JSONDecoder().decode(SignedEnvelope.self, from: Self.body(urlRequest))
                XCTAssertTrue(try broker.verify(signed, from: phone.signingPublicKey(), kind: "approval_decision"))
                let decision = try JSONDecoder().decode(ApprovalDecision.self, from: broker.decrypt(signed.body))
                XCTAssertEqual(decision.requestHash, hash)
                XCTAssertEqual(decision.decision, "approve")
                decided = true
                return (200, Data("{}".utf8))
            }
            if path.hasSuffix("/revocation") {
                let signed = try JSONDecoder().decode(SignedEnvelope.self, from: Self.body(urlRequest))
                XCTAssertTrue(try broker.verify(signed, from: phone.signingPublicKey(), kind: "session_revoke"))
                let value = try JSONSerialization.jsonObject(with: broker.decrypt(signed.body)) as! [String: Any]
                XCTAssertEqual(value["requestHash"] as? String, hash)
                revoked = true
                return (200, Data("{}".utf8))
            }
            if path.hasSuffix("/status") {
                let date = ISO8601DateFormatter()
                let status = SessionStatus(version: 1, type: "session_status", requestId: request.id, requestHash: hash, status: revoked ? "revoked" : "active", issuedAt: date.string(from: Date()), expiresAt: date.string(from: Date().addingTimeInterval(300)), idleUntil: date.string(from: Date().addingTimeInterval(120)), observedAt: date.string(from: Date()))
                return (200, try JSONEncoder().encode(["envelope": broker.sign(status, kind: "session_status", for: phone.encryptionPublicKey())]))
            }
            return (200, try JSONEncoder().encode(RelayRequestList(requests: decided ? [] : [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)])))
        }
        let model = model()
        await model.poll()
        XCTAssertEqual(model.requests.count, 1)
        await model.approve(try XCTUnwrap(model.requests.first))
        XCTAssertEqual(authenticationCount, 1)
        XCTAssertTrue(model.requests.isEmpty)
        XCTAssertEqual(model.history.first?.state(), "active")
        let restored = self.model()
        XCTAssertEqual(restored.history.count, 1)
        await restored.revoke(try XCTUnwrap(restored.history.first))
        XCTAssertEqual(authenticationCount, 2)
        XCTAssertEqual(restored.history.first?.state(), "revoked")
        XCTAssertEqual(self.model().history.first?.state(), "revoked")
    }

    func testRejectsSignedRequestFromDifferentBroker() async throws {
        let request = request()
        let attacker = CryptoBox(keychain: store())
        let envelope = try attacker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        StubRelayProtocol.handler = { _ in (200, try JSONEncoder().encode(RelayRequestList(requests: [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)]))) }
        let model = model()
        await model.poll()
        XCTAssertTrue(model.requests.isEmpty)
        XCTAssertNotNil(model.errorMessage)
    }

    func testRejectsChangedRelayRequestIdentity() async throws {
        let request = request()
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        StubRelayProtocol.handler = { _ in (200, try JSONEncoder().encode(RelayRequestList(requests: [RelayRequest(requestId: "different_request", phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)]))) }
        let model = model()
        await model.poll()
        XCTAssertTrue(model.requests.isEmpty)
    }

    func testQRPairingIsEncryptedAndReplacesExistingSettings() async throws {
        let payload = SetupPayload(version: 1, type: "keywarden_setup", relayURL: settings.relayURL, relayToken: "new-test-token", brokerId: settings.brokerID, phoneId: settings.phoneID, pairingToken: "qr-secret-challenge", brokerSigningPublicJWK: try broker.signingPublicKey(), brokerEncryptionPublicJWK: try broker.encryptionPublicKey())
        let broker = self.broker!
        var paired = false
        StubRelayProtocol.handler = { request in
            if request.url!.path.hasSuffix("/pairing") {
                let body = Self.body(request)
                XCTAssertFalse(String(decoding: body, as: UTF8.self).contains("qr-secret-challenge"))
                struct Pairing: Decodable { let phoneId: String; let envelope: SignedEnvelope }
                let pairing = try JSONDecoder().decode(Pairing.self, from: body)
                let clear = try JSONDecoder().decode(PhonePairingPayload.self, from: broker.decrypt(pairing.envelope.body))
                XCTAssertEqual(clear.pairingToken, "qr-secret-challenge")
                XCTAssertTrue(try broker.verify(pairing.envelope, from: clear.signingPublicJWK, kind: "phone_pairing"))
                paired = true
                return (200, Data("{}".utf8))
            }
            return (200, Data("{\"requests\":[]}".utf8))
        }
        let model = model()
        model.settings.relayURL = "old text"
        await model.applySetupQR("kw1:" + Base64URL.encode(try JSONEncoder().encode(payload)))
        model.stopPolling()
        XCTAssertTrue(paired)
        XCTAssertEqual(model.settings.relayURL, "https://relay.test")
        XCTAssertEqual(model.settings.relayToken, "new-test-token")
        XCTAssertNil(model.errorMessage)
    }

    func testExpiredIdleSnapshotNeedsNewConfirmation() throws {
        let date = ISO8601DateFormatter()
        let request = request()
        let status = SessionStatus(version: 1, type: "session_status", requestId: request.id, requestHash: "test", status: "active", issuedAt: nil, expiresAt: date.string(from: Date().addingTimeInterval(300)), idleUntil: date.string(from: Date().addingTimeInterval(-1)), observedAt: date.string(from: Date()))
        let record = ApprovalRecord(brokerID: "test", request: request, requestHash: "test", decision: "approve", decidedAt: Date(), session: status)
        XCTAssertEqual(record.state(), "confirming")
    }

    nonisolated private static func body(_ request: URLRequest) -> Data {
        if let data = request.httpBody { return data }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var result = Data()
        var bytes = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&bytes, maxLength: bytes.count)
            if count <= 0 { break }
            result.append(contentsOf: bytes.prefix(count))
        }
        return result
    }
}
