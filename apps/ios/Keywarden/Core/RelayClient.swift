import Foundation

final class RelayClient {
    private let session: URLSession
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(session: URLSession = .shared) {
        self.session = session
        self.encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    func pendingRequests(settings: Settings) async throws -> [RelayRequest] {
        let url = try makeURL(settings, path: "/v1/brokers/\(settings.brokerID)/phones/\(settings.phoneID)/requests")
        var request = URLRequest(url: url)
        addHeaders(&request, settings: settings)
        let (data, response) = try await session.data(for: request)
        try check(response)
        return try decoder.decode(RelayRequestList.self, from: data).requests
    }

    func submitDecision(_ envelope: SignedEnvelope, requestID: String, settings: Settings) async throws {
        let url = try makeURL(settings, path: "/v1/brokers/\(settings.brokerID)/phones/\(settings.phoneID)/requests/\(requestID)/decision")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        addHeaders(&request, settings: settings)
        request.httpBody = try encoder.encode(envelope)
        let (_, response) = try await session.data(for: request)
        try check(response)
    }

    func submitPairing(_ envelope: SignedEnvelope, settings: Settings) async throws {
        let url = try makeURL(settings, path: "/v1/brokers/\(settings.brokerID)/pairing")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        addHeaders(&request, settings: settings)
        struct Pairing: Encodable { let phoneId: String; let envelope: SignedEnvelope }
        request.httpBody = try encoder.encode(Pairing(phoneId: settings.phoneID, envelope: envelope))
        let (_, response) = try await session.data(for: request)
        try check(response)
    }

    func sessionStatus(requestID: String, settings: Settings) async throws -> SignedEnvelope? {
        var request = URLRequest(url: try makeURL(settings, path: "/v1/brokers/\(settings.brokerID)/requests/\(requestID)/status"))
        addHeaders(&request, settings: settings)
        let (data, response) = try await session.data(for: request)
        if (response as? HTTPURLResponse)?.statusCode == 404 { return nil }
        try check(response)
        struct Response: Decodable { let envelope: SignedEnvelope }
        return try decoder.decode(Response.self, from: data).envelope
    }

    func registerPush(_ envelope: SignedEnvelope, settings: Settings) async throws {
        var request = URLRequest(url: try makeURL(settings, path: "/v1/brokers/\(settings.brokerID)/phones/\(settings.phoneID)/push"))
        request.httpMethod = "POST"
        addHeaders(&request, settings: settings)
        request.httpBody = try encoder.encode(envelope)
        let (_, response) = try await session.data(for: request)
        try check(response)
    }

    func revoke(_ envelope: SignedEnvelope, requestID: String, settings: Settings) async throws {
        var request = URLRequest(url: try makeURL(settings, path: "/v1/brokers/\(settings.brokerID)/requests/\(requestID)/revocation"))
        request.httpMethod = "POST"
        addHeaders(&request, settings: settings)
        request.httpBody = try encoder.encode(envelope)
        let (_, response) = try await session.data(for: request)
        try check(response)
    }

    private func makeURL(_ settings: Settings, path: String) throws -> URL {
        guard let base = URL(string: settings.relayURL), base.scheme == "https", base.host != nil,
              base.user == nil, base.password == nil,
              settings.brokerID.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil,
              settings.phoneID.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
            throw KeywardenError.missingSetting("relayURL, brokerID, or phoneID")
        }
        guard let url = URL(string: path, relativeTo: base)?.absoluteURL else {
            throw KeywardenError.invalidEncoding
        }
        return url
    }

    private func addHeaders(_ request: inout URLRequest, settings: Settings) {
        request.setValue("Bearer \(settings.relayToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }

    private func check(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { throw KeywardenError.invalidEnvelope }
        guard (200..<300).contains(http.statusCode) else { throw KeywardenError.relayStatus(http.statusCode) }
    }
}
