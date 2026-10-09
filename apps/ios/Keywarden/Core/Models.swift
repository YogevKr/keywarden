import Foundation
import Compression

struct JWK: Codable, Equatable {
    let kty: String
    let crv: String
    let x: String?
    let y: String?
    let d: String?
    let ext: Bool?
    let keyOps: [String]?

    enum CodingKeys: String, CodingKey {
        case kty, crv, x, y, d, ext
        case keyOps = "key_ops"
    }
}

struct EncryptedPayload: Codable {
    let version: Int
    let algorithm: String
    let ephemeralPublicKey: JWK
    let iv: String
    let ciphertext: String
}

struct SignedEnvelope: Codable {
    let version: Int
    let kind: String
    let body: EncryptedPayload
    let senderPublicKey: JWK
    let signature: String
}

struct SessionScope: Codable {
    let accounts: [String]
    let vaults: [String]
    let items: StringOrList
    let operations: [String]
}

struct ApprovalIntent: Codable {
    let task: String?
    let reason: String
}

struct ClientMetadata: Codable {
    let product: String
    let clientName: String
    let displayName: String
    let productVersion: String
    let protocolVersion: String
    let transport: String
    let sessionID: String?
    let sessionName: String?
    let host: String
    let project: String?
    let pid: Int?
    let capabilities: [String]

    enum CodingKeys: String, CodingKey {
        case product, clientName, displayName, productVersion, protocolVersion, transport
        case sessionID = "sessionId"
        case sessionName, host, project, pid, capabilities
    }
}

enum StringOrList: Codable {
    case all
    case values([String])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(String.self), value == "all" {
            self = .all
        } else {
            self = .values(try container.decode([String].self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .all: try container.encode("all")
        case .values(let values): try container.encode(values)
        }
    }
}

struct SessionRequest: Codable, Identifiable {
    let version: Int
    let type: String
    let id: String
    let agent: String
    let host: String
    let phoneId: String
    let reason: String
    var intent: ApprovalIntent? = nil
    var client: ClientMetadata? = nil
    let scope: SessionScope
    let durationSeconds: Int
    let idleTimeoutSeconds: Int
    let createdAt: String
    let expiresAt: String
    let nonce: String
}

struct RelayRequest: Codable, Identifiable {
    let requestId: String
    let phoneId: String
    let expiresAt: String
    let envelope: SignedEnvelope

    var id: String { requestId }
}

struct RelayRequestList: Codable {
    let requests: [RelayRequest]
}

struct PhonePairingPayload: Codable {
    let phoneId: String
    let pairingToken: String
    let signingPublicJWK: JWK
    let encryptionPublicJWK: JWK

    enum CodingKeys: String, CodingKey {
        case phoneId, pairingToken
        case signingPublicJWK = "signingPublicJwk"
        case encryptionPublicJWK = "encryptionPublicJwk"
    }
}

struct ApprovalDecision: Codable {
    let version: Int
    let type: String
    let requestId: String
    let requestHash: String
    let decision: String
    let decidedAt: String
    let nonce: String
}

struct Settings: Codable {
    var relayURL: String = ""
    var relayToken: String = ""
    var brokerID: String = ""
    var phoneID: String = "phone-1"
    var brokerSigningPublicJWK: String = ""
    var brokerEncryptionPublicJWK: String = ""

    var isConfigured: Bool {
        !relayURL.isEmpty && !relayToken.isEmpty && !brokerID.isEmpty && !phoneID.isEmpty
            && !brokerSigningPublicJWK.isEmpty && !brokerEncryptionPublicJWK.isEmpty
    }
}

struct SessionStatus: Codable {
    let version: Int
    let type: String
    let requestId: String
    let requestHash: String
    let status: String
    let issuedAt: String?
    let expiresAt: String?
    let idleUntil: String?
    let observedAt: String
}

struct SessionRevocation: Encodable {
    let version = 1
    let type = "session_revoke"
    let requestId: String
    let requestHash: String
    let decidedAt: String
    let nonce: String
}

struct ApprovalRecord: Codable, Identifiable {
    let brokerID: String
    let request: SessionRequest
    let requestHash: String
    let decision: String
    let decidedAt: Date
    var session: SessionStatus?
    var revokeRequested = false
    var id: String { request.id }

    func state(at date: Date = Date()) -> String {
        if let session {
            if ["revoked", "expired", "denied"].contains(session.status) { return session.status }
            if let expiry = session.expiresAt.flatMap(parseDate), expiry <= date { return "expired" }
            if revokeRequested { return "revoking" }
            if let idle = session.idleUntil.flatMap(parseDate), idle <= date { return "confirming" }
            if session.status == "active", let observed = parseDate(session.observedAt), date.timeIntervalSince(observed) <= 20 { return "active" }
        }
        if revokeRequested { return "revoking" }
        if decision == "deny" { return "denied" }
        if let requestedExpiry = parseDate(request.expiresAt), date >= requestedExpiry.addingTimeInterval(Double(request.durationSeconds)) { return "expired" }
        return "confirming"
    }
}

func parseDate(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
}

extension StringOrList {
    var displayValue: String {
        switch self {
        case .all: return "All items"
        case .values(let values): return values.isEmpty ? "No items" : values.joined(separator: ", ")
        }
    }
}

struct SetupPayload: Codable {
    let version: Int
    let type: String
    let relayURL: String
    let relayToken: String
    let brokerId: String
    let phoneId: String
    let pairingToken: String
    let brokerSigningPublicJWK: JWK
    let brokerEncryptionPublicJWK: JWK

    private struct Compact: Decodable {
        let relayURL: String
        let relayToken: String
        let brokerId: String
        let phoneId: String
        let pairingToken: String
        let signingPublicKey: [String]
        let encryptionPublicKey: [String]

        enum CodingKeys: String, CodingKey {
            case relayURL = "r"
            case relayToken = "t"
            case brokerId = "b"
            case phoneId = "p"
            case pairingToken = "q"
            case signingPublicKey = "s"
            case encryptionPublicKey = "e"
        }
    }

    static func decode(_ value: String) throws -> SetupPayload {
        let data: Data
        if value.hasPrefix("kw1:") {
            data = try Base64URL.decode(String(value.dropFirst(4)))
        } else if value.hasPrefix("kw2:") {
            let compressed = try Base64URL.decode(String(value.dropFirst(4)))
            return try decodeCompact(decompress(compressed))
        } else {
            throw KeywardenError.invalidSetupQR
        }
        let payload = try JSONDecoder().decode(SetupPayload.self, from: data)
        guard payload.version == 1, payload.type == "keywarden_setup" else { throw KeywardenError.invalidSetupQR }
        return payload
    }

    private static func decodeCompact(_ data: Data) throws -> SetupPayload {
        let compact = try JSONDecoder().decode(Compact.self, from: data)
        guard compact.signingPublicKey.count == 2, compact.encryptionPublicKey.count == 2 else {
            throw KeywardenError.invalidSetupQR
        }
        func jwk(_ key: [String]) -> JWK {
            JWK(kty: "EC", crv: "P-256", x: key[0], y: key[1], d: nil, ext: true, keyOps: nil)
        }
        return SetupPayload(
            version: 1,
            type: "keywarden_setup",
            relayURL: compact.relayURL,
            relayToken: compact.relayToken,
            brokerId: compact.brokerId,
            phoneId: compact.phoneId,
            pairingToken: compact.pairingToken,
            brokerSigningPublicJWK: jwk(compact.signingPublicKey),
            brokerEncryptionPublicJWK: jwk(compact.encryptionPublicKey)
        )
    }

    private static func decompress(_ data: Data) throws -> Data {
        guard !data.isEmpty else { throw KeywardenError.invalidSetupQR }
        var capacity = max(data.count * 4, 1024)
        for _ in 0..<8 {
            var output = Data(count: capacity)
            let decodedSize = output.withUnsafeMutableBytes { outputBuffer in
                data.withUnsafeBytes { inputBuffer in
                    compression_decode_buffer(
                        outputBuffer.bindMemory(to: UInt8.self).baseAddress!,
                        capacity,
                        inputBuffer.bindMemory(to: UInt8.self).baseAddress!,
                        data.count,
                        nil,
                        COMPRESSION_ZLIB
                    )
                }
            }
            if decodedSize > 0 {
                output.removeSubrange(decodedSize..<output.count)
                return output
            }
            capacity *= 2
        }
        throw KeywardenError.invalidSetupQR
    }
}
