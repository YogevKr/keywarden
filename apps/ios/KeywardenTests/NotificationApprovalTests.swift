import CryptoKit
import LocalAuthentication
import Security
import XCTest
@testable import Keywarden

@MainActor
final class NotificationApprovalTests: XCTestCase {
    private var service = ""
    private var phone: CryptoBox!
    private var broker: CryptoBox!
    private var context: NotificationPreviewContext!
    private var relay: RelayClient!
    private var receipts: NotificationDecisionStore!
    private var request: SessionRequest!
    private var authenticationCount = 0
    private var submissions = 0
    private var received: ApprovalDecision?
    private var wrongStatusHash = false

    override func setUp() async throws {
        service = "keywarden.notification-tests.\(UUID().uuidString)"
        phone = CryptoBox(decryptionKey: P256.KeyAgreement.PrivateKey().rawRepresentation, signingKey: P256.Signing.PrivateKey().rawRepresentation)
        broker = CryptoBox(decryptionKey: P256.KeyAgreement.PrivateKey().rawRepresentation, signingKey: P256.Signing.PrivateKey().rawRepresentation)
        let settings = Settings(relayURL: "https://example.invalid", relayToken: "test", brokerID: "broker_test", phoneID: "phone_test",
            brokerSigningPublicJWK: String(decoding: try JSONEncoder().encode(broker.signingPublicKey()), as: UTF8.self),
            brokerEncryptionPublicJWK: String(decoding: try JSONEncoder().encode(broker.encryptionPublicKey()), as: UTF8.self))
        let date = ISO8601DateFormatter()
        request = SessionRequest(version: 1, type: "open_session", id: "request_inline", agent: "Codex", host: "Test Mac", phoneId: settings.phoneID,
            reason: "Test notification approval", scope: SessionScope(accounts: ["personal"], vaults: ["Test Vault"], items: .all, operations: ["list"]),
            durationSeconds: 300, idleTimeoutSeconds: 60, createdAt: date.string(from: Date()), expiresAt: date.string(from: Date().addingTimeInterval(300)), nonce: "test")
        let envelope = try broker.sign(request!, kind: "session_request", for: phone.encryptionPublicKey())
        context = NotificationPreviewContext(settings: settings, decryptionKey: try phone.notificationDecryptionKey(),
            requests: [RelayRequest(requestId: request.id, phoneId: settings.phoneID, expiresAt: request.expiresAt, envelope: envelope)], completedRequestIDs: [])
        receipts = NotificationDecisionStore(keychain: KeychainStore(service: service))
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubRelayProtocol.self]
        relay = RelayClient(session: URLSession(configuration: config))
        authenticationCount = 0; submissions = 0; received = nil; wrongStatusHash = false
        StubRelayProtocol.handler = { [self] request in
            if request.httpMethod == "POST" {
                submissions += 1
                let envelope = try JSONDecoder().decode(SignedEnvelope.self, from: Self.body(request))
                XCTAssertTrue(try broker.verify(envelope, from: phone.signingPublicKey(), kind: "approval_decision"))
                received = try JSONDecoder().decode(ApprovalDecision.self, from: broker.decrypt(envelope.body))
                XCTAssertEqual(received?.requestHash, try phone.hash(self.request!))
                return (200, Data("{}".utf8))
            }
            let decision = try XCTUnwrap(received)
            let status = SessionStatus(version: 1, type: "session_status", requestId: decision.requestId,
                requestHash: wrongStatusHash ? "wrong-hash" : decision.requestHash, status: decision.decision == "approve" ? "active" : "denied",
                issuedAt: date.string(from: Date()), expiresAt: date.string(from: Date().addingTimeInterval(300)),
                idleUntil: date.string(from: Date().addingTimeInterval(60)), observedAt: date.string(from: Date()))
            let reply = try broker.sign(status, kind: "session_status", for: phone.encryptionPublicKey())
            return (200, try JSONEncoder().encode(["envelope": reply]))
        }
    }

    override func tearDown() async throws {
        StubRelayProtocol.handler = nil
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service] as CFDictionary)
    }

    static func body(_ request: URLRequest) throws -> Data {
        if let data = request.httpBody { return data }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open(); defer { stream.close() }
        var data = Data(); var bytes = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable { let count = stream.read(&bytes, maxLength: bytes.count); if count <= 0 { break }; data.append(contentsOf: bytes.prefix(count)) }
        return data
    }

    private func engine(signer: NotificationApproval.Signer? = nil) -> NotificationApproval {
        NotificationApproval(relay: relay, loadContext: { self.context }, receipts: receipts, signer: signer ?? { _, _ in self.authenticationCount += 1; return self.phone })
    }

    func testApproveSignsExactScopeAndRequiresBrokerConfirmation() async throws {
        let result = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!))
        XCTAssertEqual(authenticationCount, 1)
        XCTAssertEqual(submissions, 1)
        XCTAssertEqual(result.session?.status, "active")
        XCTAssertEqual(try receipts.records(settings: context.settings).first?.session?.status, "active")
        XCTAssertEqual(received?.requestId, request.id)
    }

    func testRejectSignsDenialAndConfirmsIt() async throws {
        let result = try await engine().decide(requestID: request.id, decision: "deny", displayedHash: phone.hash(request!))
        XCTAssertEqual(authenticationCount, 1)
        XCTAssertEqual(received?.decision, "deny")
        XCTAssertEqual(result.session?.status, "denied")
    }

    func testCancelledFaceIDNeverSignsOrSends() async throws {
        do { _ = try await engine(signer: { _, _ in throw LAError(.userCancel) }).decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!)); XCTFail("Cancellation must fail") }
        catch { XCTAssertEqual((error as? LAError)?.code, .userCancel) }
        XCTAssertEqual(submissions, 0)
        XCTAssertTrue(try receipts.records(settings: context.settings).isEmpty)
    }

    func testChangedConnectionAfterFaceIDCannotSend() async throws {
        let engine = engine(signer: { _, _ in self.context = NotificationPreviewContext(settings: Settings(), decryptionKey: Data(), requests: [], completedRequestIDs: []); return self.phone })
        do { _ = try await engine.decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!)); XCTFail("Changed pairing must fail") } catch {}
        XCTAssertEqual(submissions, 0)
    }

    func testWrongDisplayedScopeCannotAuthenticateOrSend() async throws {
        do { _ = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: "wrong"); XCTFail("Changed scope must fail") } catch {}
        XCTAssertEqual(authenticationCount, 0)
        XCTAssertEqual(submissions, 0)
    }

    func testWrongBrokerConfirmationCannotShowSuccess() async throws {
        wrongStatusHash = true
        do { _ = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!)); XCTFail("Wrong hash must fail") } catch {}
        XCTAssertEqual(submissions, 1)
        XCTAssertNil(try receipts.records(settings: context.settings).first?.session)
    }

    func testExpiryDuringFaceIDCannotSend() async throws {
        request = SessionRequest(version: 1, type: request.type, id: request.id, agent: request.agent,
            host: request.host, phoneId: request.phoneId, reason: request.reason, scope: request.scope,
            durationSeconds: request.durationSeconds, idleTimeoutSeconds: request.idleTimeoutSeconds,
            createdAt: request.createdAt, expiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(1)), nonce: request.nonce)
        let envelope = try broker.sign(request!, kind: "session_request", for: phone.encryptionPublicKey())
        context = NotificationPreviewContext(settings: context.settings, decryptionKey: context.decryptionKey,
            requests: [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)], completedRequestIDs: [])
        let engine = engine(signer: { _, _ in try await Task.sleep(for: .seconds(2)); return self.phone })
        do { _ = try await engine.decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!)); XCTFail("Expired request must fail") }
        catch KeywardenError.requestExpired { }
        XCTAssertEqual(submissions, 0)
    }

    func testMissingConfirmationNeverShowsSuccess() async throws {
        let original = StubRelayProtocol.handler!
        StubRelayProtocol.handler = { request in
            if request.httpMethod == "POST" { return try original(request) }
            return (404, Data())
        }
        do { _ = try await engine().decide(requestID: request.id, decision: "deny", displayedHash: phone.hash(request!)); XCTFail("Missing confirmation must fail") }
        catch NotificationApprovalError.unconfirmed { }
        let record = try XCTUnwrap(receipts.records(settings: context.settings).first)
        XCTAssertNil(record.session)
        XCTAssertEqual(record.state(), "confirming")
        XCTAssertEqual(submissions, 1)
    }

    func testNetworkFailurePreservesDecisionForRetry() async throws {
        let original = StubRelayProtocol.handler!
        StubRelayProtocol.handler = { request in
            _ = try original(request)
            throw URLError(.networkConnectionLost)
        }
        do { _ = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!)); XCTFail("Dropped response must fail") } catch {}
        let nonce = try XCTUnwrap(received?.nonce)
        XCTAssertNil(try receipts.records(settings: context.settings).first?.session)
        StubRelayProtocol.handler = original
        let result = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!))
        XCTAssertEqual(result.session?.status, "active")
        XCTAssertEqual(received?.nonce, nonce)
    }

    func testRetryCannotConfirmReplayedActiveStatus() async throws {
        let hash = try phone.hash(request!)
        let oldDate = Date().addingTimeInterval(-60)
        let oldDecision = ApprovalDecision(version: 1, type: "approval_decision", requestId: request.id,
            requestHash: hash, decision: "approve", decidedAt: ISO8601DateFormatter().string(from: oldDate), nonce: "old-decision")
        try receipts.save(NotificationDecisionReceipt(record: ApprovalRecord(brokerID: context.settings.brokerID,
            request: request, requestHash: hash, decision: "approve", decidedAt: oldDate),
            envelope: phone.signDecision(oldDecision, brokerEncryptionKey: broker.encryptionPublicKey()), phoneID: request.phoneId))
        let original = StubRelayProtocol.handler!
        StubRelayProtocol.handler = { [self] urlRequest in
            if urlRequest.httpMethod == "POST" { return try original(urlRequest) }
            let date = ISO8601DateFormatter()
            let stale = SessionStatus(version: 1, type: "session_status", requestId: request.id,
                requestHash: hash, status: "active", issuedAt: date.string(from: oldDate),
                expiresAt: date.string(from: Date().addingTimeInterval(300)), idleUntil: date.string(from: Date().addingTimeInterval(60)),
                observedAt: date.string(from: Date().addingTimeInterval(-30)))
            return (200, try JSONEncoder().encode(["envelope": broker.sign(stale, kind: "session_status", for: phone.encryptionPublicKey())]))
        }
        do { _ = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: hash); XCTFail("Replayed active status must fail") }
        catch NotificationApprovalError.unconfirmed { }
        XCTAssertNil(try receipts.records(settings: context.settings).first?.session)
    }

    func testMainAppImportsReceiptAndKeepsNewerStatus() async throws {
        let record = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: phone.hash(request!))
        let suite = "keywarden.inline-history.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        let historyStore = KeychainStore(service: suite)
        defer {
            defaults.removePersistentDomain(forName: suite)
            SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: suite] as CFDictionary)
        }
        StubRelayProtocol.handler = { request in
            if request.url!.path.hasSuffix("/status") { return (404, Data()) }
            return (200, Data("{\"requests\":[]}".utf8))
        }
        let model = ApprovalModel(relay: relay, crypto: phone, keychain: historyStore,
            defaults: defaults, notificationDecisions: receipts)
        model.settings = context.settings
        await model.poll()
        XCTAssertEqual(model.history.first?.id, record.id)
        XCTAssertEqual(model.history.first?.state(), "active")
        let active = try XCTUnwrap(record.session)
        let revoked = SessionStatus(version: 1, type: "session_status", requestId: record.id,
            requestHash: record.requestHash, status: "revoked", issuedAt: active.issuedAt,
            expiresAt: active.expiresAt, idleUntil: active.idleUntil,
            observedAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(10)))
        model.history[0].session = revoked
        await model.poll()
        XCTAssertEqual(model.history.first?.state(), "revoked")
        let restored = ApprovalModel(keychain: historyStore, defaults: defaults, notificationDecisions: receipts)
        XCTAssertEqual(restored.history.first?.state(), "revoked")
    }

    func testRetryReusesSignedDecisionAndRejectsOppositeDecision() async throws {
        let hash = try phone.hash(request!)
        _ = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: hash)
        let nonce = received?.nonce
        _ = try await engine().decide(requestID: request.id, decision: "approve", displayedHash: hash)
        XCTAssertEqual(received?.nonce, nonce)
        XCTAssertEqual(authenticationCount, 2)
        do { _ = try await engine().decide(requestID: request.id, decision: "deny", displayedHash: hash); XCTFail("Conflicting decision must fail") } catch {}
        XCTAssertEqual(submissions, 2)
    }
}
