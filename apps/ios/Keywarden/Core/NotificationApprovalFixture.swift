#if DEBUG
import Foundation

// Synthetic keys and an in-process relay. This code is absent from release builds.
enum NotificationApprovalFixture {
    static func broker() -> CryptoBox { CryptoBox(decryptionKey: Data(repeating: 8, count: 32), signingKey: Data(repeating: 7, count: 32)) }
    static func phone() -> CryptoBox { CryptoBox(decryptionKey: Data(repeating: 9, count: 32), signingKey: Data(repeating: 10, count: 32)) }

    @MainActor
    static func approval() -> NotificationApproval? {
        guard let context = try? NotificationPreviewStore().load(),
              context.settings.relayURL == "https://example.invalid",
              context.settings.brokerID == "broker_fixture", context.settings.phoneID == "phone_fixture" else { return nil }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [NotificationFixtureRelay.self]
        let relay = RelayClient(session: URLSession(configuration: configuration))
        if context.usesRealBiometrics == true { return NotificationApproval(relay: relay) }
        return NotificationApproval(relay: relay, signer: { _, _ in phone() })
    }
}

private final class NotificationFixtureRelay: URLProtocol {
    private static var decision: ApprovalDecision?
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "example.invalid" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let broker = NotificationApprovalFixture.broker(), phone = NotificationApprovalFixture.phone()
            let data: Data
            if request.httpMethod == "POST" {
                var body = request.httpBody ?? Data()
                if body.isEmpty, let stream = request.httpBodyStream {
                    stream.open(); defer { stream.close() }
                    var bytes = [UInt8](repeating: 0, count: 4096)
                    while stream.hasBytesAvailable { let n = stream.read(&bytes, maxLength: bytes.count); if n <= 0 { break }; body.append(contentsOf: bytes.prefix(n)) }
                }
                let envelope = try JSONDecoder().decode(SignedEnvelope.self, from: body)
                guard try broker.verify(envelope, from: phone.signingPublicKey(), kind: "approval_decision") else { throw KeywardenError.invalidEnvelope }
                Self.decision = try JSONDecoder().decode(ApprovalDecision.self, from: broker.decrypt(envelope.body))
                data = Data("{}".utf8)
            } else {
                guard let decision = Self.decision else { throw KeywardenError.invalidEnvelope }
                let formatter = ISO8601DateFormatter()
                let status = SessionStatus(version: 1, type: "session_status", requestId: decision.requestId,
                    requestHash: decision.requestHash, status: decision.decision == "approve" ? "active" : "denied",
                    issuedAt: formatter.string(from: Date()), expiresAt: formatter.string(from: Date().addingTimeInterval(300)),
                    idleUntil: formatter.string(from: Date().addingTimeInterval(60)), observedAt: formatter.string(from: Date()))
                data = try JSONEncoder().encode(["envelope": broker.sign(status, kind: "session_status", for: phone.encryptionPublicKey())])
            }
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
#endif
