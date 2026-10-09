import CryptoKit
import Security
import UserNotifications
import XCTest
@testable import Keywarden

final class NotificationBannerTests: XCTestCase {
    private func fixture() throws -> (NotificationPreviewContext, SessionRequest) {
        let broker = CryptoBox(decryptionKey: P256.KeyAgreement.PrivateKey().rawRepresentation, signingKey: P256.Signing.PrivateKey().rawRepresentation)
        let phone = CryptoBox(decryptionKey: P256.KeyAgreement.PrivateKey().rawRepresentation, signingKey: P256.Signing.PrivateKey().rawRepresentation)
        let settings = Settings(relayURL: "https://example.invalid", relayToken: "test", brokerID: "broker_test", phoneID: "phone_test",
            brokerSigningPublicJWK: String(decoding: try JSONEncoder().encode(broker.signingPublicKey()), as: UTF8.self),
            brokerEncryptionPublicJWK: String(decoding: try JSONEncoder().encode(broker.encryptionPublicKey()), as: UTF8.self))
        let date = ISO8601DateFormatter()
        let request = SessionRequest(version: 1, type: "open_session", id: "request_banner", agent: "Codex", host: "Test Mac", phoneId: settings.phoneID,
            reason: "private free-text reason", scope: SessionScope(accounts: ["personal"], vaults: ["Test Vault"], items: .values(["private-item-name"]), operations: ["read", "list"]),
            durationSeconds: 300, idleTimeoutSeconds: 60, createdAt: date.string(from: Date()), expiresAt: date.string(from: Date().addingTimeInterval(300)), nonce: "test")
        let envelope = try broker.sign(request, kind: "session_request", for: phone.encryptionPublicKey())
        return (NotificationPreviewContext(settings: settings, decryptionKey: try phone.notificationDecryptionKey(),
            requests: [RelayRequest(requestId: request.id, phoneId: request.phoneId, expiresAt: request.expiresAt, envelope: envelope)], completedRequestIDs: []), request)
    }

    func testUnlockedPreviewVerifiesAndSummarizesOnlyScope() async throws {
        let (context, request) = try fixture()
        let banner = try await NotificationBannerLoader(loadContext: { context }).banner(requestID: request.id, previews: .whenAuthenticated)
        XCTAssertEqual(banner?.title, "Codex requests access")
        XCTAssertEqual(banner?.subtitle, "Personal")
        XCTAssertEqual(banner?.body, "Read, List · Test Vault · 5 min")
        XCTAssertFalse(String(describing: banner).contains(request.reason))
        XCTAssertFalse(String(describing: banner).contains("private-item-name"))
    }

    func testAlwaysAndNeverPreviewsDoNotReadProtectedStorage() async throws {
        for setting in [UNShowPreviewsSetting.always, .never] {
            var reads = 0
            let result = try await NotificationBannerLoader(loadContext: { reads += 1; return nil }).banner(requestID: "request_test", previews: setting)
            XCTAssertNil(result)
            XCTAssertEqual(reads, 0)
        }
    }

    func testLockedKeychainCannotProducePreview() async throws {
        let loader = NotificationBannerLoader(loadContext: { throw KeywardenError.keychain(errSecInteractionNotAllowed) })
        do { _ = try await loader.banner(requestID: "request_test", previews: .whenAuthenticated); XCTFail("Locked storage must fail") }
        catch KeywardenError.keychain { }
    }

    func testLockDuringFetchCannotProducePreview() async throws {
        let (context, request) = try fixture()
        var reads = 0
        let loader = NotificationBannerLoader(loadContext: {
            reads += 1
            if reads > 1 { throw KeywardenError.keychain(errSecInteractionNotAllowed) }
            return context
        })
        do { _ = try await loader.banner(requestID: request.id, previews: .whenAuthenticated); XCTFail("Locking must fail") }
        catch KeywardenError.keychain { }
        XCTAssertEqual(reads, 2)
    }

    func testChangedConnectionCannotProducePreview() async throws {
        let (context, request) = try fixture()
        var reads = 0
        let loader = NotificationBannerLoader(loadContext: {
            reads += 1
            if reads == 1 { return context }
            var changed = context.settings; changed.brokerID = "another_broker"
            return NotificationPreviewContext(settings: changed, decryptionKey: context.decryptionKey, requests: [], completedRequestIDs: [])
        })
        let banner = try await loader.banner(requestID: request.id, previews: .whenAuthenticated)
        XCTAssertNil(banner)
    }

    func testWrongNotificationIDCannotProducePreview() async throws {
        let (context, request) = try fixture()
        let source = context.requests[0]
        let changed = RelayRequest(requestId: "request_changed", phoneId: source.phoneId, expiresAt: source.expiresAt, envelope: source.envelope)
        let changedContext = NotificationPreviewContext(settings: context.settings, decryptionKey: context.decryptionKey, requests: [changed], completedRequestIDs: [])
        do { _ = try await NotificationBannerLoader(loadContext: { changedContext }).banner(requestID: changed.id, previews: .whenAuthenticated); XCTFail("Mismatched identity must fail") }
        catch KeywardenError.invalidEnvelope { }
        XCTAssertNotEqual(request.id, changed.id)
    }

    func testTimeoutDeliversOriginalOnceAndIgnoresLatePreview() throws {
        let (_, request) = try fixture()
        let original = UNMutableNotificationContent()
        original.title = "Approval requested"; original.userInfo = ["requestId": request.id]
        var results: [UNNotificationContent] = []
        let delivery = NotificationBannerDelivery(original: original) { results.append($0) }
        delivery.finish()
        delivery.finish(NotificationBanner(request: request))
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].title, original.title)
    }

    func testPreviewKeepsCategoryAndRoutingIdentifier() throws {
        let (_, request) = try fixture()
        let original = UNMutableNotificationContent()
        original.title = "Approval requested"; original.categoryIdentifier = "KEYWARDEN_APPROVAL"
        original.userInfo = ["requestId": request.id]
        var results: [UNNotificationContent] = []
        let delivery = NotificationBannerDelivery(original: original) { results.append($0) }
        delivery.finish(NotificationBanner(request: request)); delivery.finish()
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].categoryIdentifier, original.categoryIdentifier)
        XCTAssertEqual(results[0].userInfo["requestId"] as? String, request.id)
        XCTAssertEqual(results[0].title, "Codex requests access")
    }
}
