import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum NotificationApprovalError: LocalizedError {
    case openApp, connectionChanged, differentDecision, unconfirmed
    var errorDescription: String? {
        switch self {
        case .openApp: return "Open Keywarden once to enable notification approval."
        case .connectionChanged: return "The connection changed. Open the current request in Keywarden."
        case .differentDecision: return "This request already has a decision. Open Keywarden for its status."
        case .unconfirmed: return "Your Mac has not confirmed the decision. Open Keywarden to check its status."
        }
    }
}

struct NotificationSigningStore {
    private var group: String? { Bundle.main.object(forInfoDictionaryKey: "NotificationKeychainAccessGroup") as? String }

    private func query(_ id: String) throws -> [String: Any] {
        guard let group, !group.isEmpty else { throw NotificationApprovalError.openApp }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "ai.sawmills.keywarden.notification-signing",
                kSecAttrAccount as String: id, kSecAttrAccessGroup as String: group]
    }

    func prepare(crypto: CryptoBox) throws -> String {
        let publicKey = try crypto.signingPublicKey()
        let id = Base64URL.encode(Data(SHA256.hash(data: Data("\(publicKey.x ?? "").\(publicKey.y ?? "")".utf8))))
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           .biometryAny, &error) else { throw NotificationApprovalError.openApp }
        var item = try query(id)
        item[kSecAttrAccessControl as String] = control
        item[kSecValueData as String] = try crypto.notificationSigningKey()
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else { throw KeywardenError.keychain(status) }
        return id
    }

    @MainActor
    func signer(context: NotificationPreviewContext, reason: String) async throws -> CryptoBox {
        guard let id = context.signingKeyID else { throw NotificationApprovalError.openApp }
        let authentication = LAContext()
        authentication.localizedFallbackTitle = ""
        authentication.touchIDAuthenticationAllowableReuseDuration = 0
        defer { authentication.invalidate() }
        guard try await authentication.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
            throw KeywardenError.authenticationFailed
        }
        try Task.checkCancellation()
        var item = try query(id)
        item[kSecUseAuthenticationContext as String] = authentication
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(item as CFDictionary, &result)
        guard status == errSecSuccess, let key = result as? Data else { throw NotificationApprovalError.openApp }
        return CryptoBox(decryptionKey: context.decryptionKey, signingKey: key)
    }
}

struct NotificationDecisionReceipt: Codable {
    var record: ApprovalRecord
    let envelope: SignedEnvelope
    let phoneID: String
}

struct NotificationDecisionStore {
    let keychain: KeychainStore
    init(keychain: KeychainStore? = nil) {
        self.keychain = keychain ?? KeychainStore(service: "ai.sawmills.keywarden.notification-decisions",
            accessGroup: Bundle.main.object(forInfoDictionaryKey: "NotificationKeychainAccessGroup") as? String)
    }
    private func key(broker: String, phone: String, request: String) -> String {
        Base64URL.encode(Data(SHA256.hash(data: Data("\(broker)/\(phone)/\(request)".utf8))))
    }
    func load(settings: Settings, request: String) throws -> NotificationDecisionReceipt? {
        try keychain.load(key(broker: settings.brokerID, phone: settings.phoneID, request: request))
            .map { try JSONDecoder().decode(NotificationDecisionReceipt.self, from: $0) }
    }
    func save(_ receipt: NotificationDecisionReceipt) throws {
        try keychain.save(JSONEncoder().encode(receipt), for: key(broker: receipt.record.brokerID,
            phone: receipt.phoneID, request: receipt.record.id))
    }
    func records(settings: Settings) throws -> [ApprovalRecord] {
        try keychain.allData().compactMap { data in
            let receipt = try JSONDecoder().decode(NotificationDecisionReceipt.self, from: data)
            return receipt.record.brokerID == settings.brokerID && receipt.phoneID == settings.phoneID ? receipt.record : nil
        }
    }
    #if DEBUG
    func removeFixture(settings: Settings, request: String) throws {
        guard settings.brokerID == "broker_fixture", settings.phoneID == "phone_fixture" else { throw KeywardenError.invalidEnvelope }
        try keychain.remove(key(broker: settings.brokerID, phone: settings.phoneID, request: request))
    }
    #endif
}

@MainActor
final class NotificationApproval {
    typealias Signer = (NotificationPreviewContext, String) async throws -> CryptoBox
    private let relay: RelayClient
    private let loadContext: () throws -> NotificationPreviewContext?
    private let signer: Signer
    private let receipts: NotificationDecisionStore
    private(set) var busy = false

    init(relay: RelayClient = NotificationPreviewLoader().relay,
         loadContext: @escaping () throws -> NotificationPreviewContext? = { try NotificationPreviewStore().load() },
         receipts: NotificationDecisionStore = NotificationDecisionStore(),
         signer: @escaping Signer = { try await NotificationSigningStore().signer(context: $0, reason: $1) }) {
        self.relay = relay; self.loadContext = loadContext; self.receipts = receipts; self.signer = signer
    }

    func decide(requestID: String, decision: String, displayedHash: String) async throws -> ApprovalRecord {
        guard !busy, ["approve", "deny"].contains(decision) else { throw KeywardenError.invalidEnvelope }
        busy = true
        defer { busy = false }
        guard let context = try loadContext() else { throw NotificationApprovalError.openApp }
        let request = try await NotificationPreviewLoader(relay: relay).request(requestID, context: context)
        let verifier = CryptoBox(decryptionKey: context.decryptionKey)
        let hash = try verifier.hash(request)
        guard hash == displayedHash else { throw KeywardenError.invalidEnvelope }
        let existing = try receipts.load(settings: context.settings, request: requestID)
        if let existing {
            guard existing.record.requestHash == hash, existing.record.decision == decision else {
                throw NotificationApprovalError.differentDecision
            }
        }
        let crypto = try await signer(context, decision == "approve" ? "Approve access for \(request.agent)" : "Deny this access request")
        try Task.checkCancellation()
        guard let latest = try loadContext(), latest.settings == context.settings,
              latest.signingKeyID == context.signingKeyID,
              latest.decryptionKey == context.decryptionKey,
              !latest.completedRequestIDs.contains(requestID) else { throw NotificationApprovalError.connectionChanged }
        guard let expiry = parseDate(request.expiresAt), expiry > Date() else { throw KeywardenError.requestExpired }
        let brokerKey = try JSONDecoder().decode(JWK.self, from: Data(context.settings.brokerEncryptionPublicJWK.utf8))
        let value = ApprovalDecision(version: 1, type: "approval_decision", requestId: requestID,
            requestHash: hash, decision: decision, decidedAt: ISO8601DateFormatter().string(from: Date()), nonce: UUID().uuidString)
        var receipt = try existing ?? NotificationDecisionReceipt(record: ApprovalRecord(brokerID: context.settings.brokerID,
            request: request, requestHash: hash, decision: decision, decidedAt: Date()),
            envelope: crypto.signDecision(value, brokerEncryptionKey: brokerKey), phoneID: context.settings.phoneID)
        // Save before sending. A dropped response must not lose the decision or create a conflicting retry.
        try receipts.save(receipt)
        try await relay.submitDecision(receipt.envelope, requestID: requestID, settings: context.settings)
        let pinned = try JSONDecoder().decode(JWK.self, from: Data(context.settings.brokerSigningPublicJWK.utf8))
        for _ in 0..<8 {
            try Task.checkCancellation()
            if let envelope = try await relay.sessionStatus(requestID: requestID, settings: context.settings) {
                guard try verifier.verify(envelope, from: pinned, kind: "session_status") else { throw KeywardenError.invalidEnvelope }
                let status = try JSONDecoder().decode(SessionStatus.self, from: verifier.decrypt(envelope.body))
                guard status.version == 1, status.type == "session_status", status.requestId == requestID,
                      status.requestHash == hash, let observed = parseDate(status.observedAt),
                      observed >= receipt.record.decidedAt.addingTimeInterval(-5), observed <= Date().addingTimeInterval(30) else {
                    throw KeywardenError.invalidEnvelope
                }
                if ["active", "denied", "cancelled", "revoked", "expired"].contains(status.status) {
                    if status.status == "active" {
                        guard decision == "approve", let expires = status.expiresAt.flatMap(parseDate), expires > Date(),
                              let idle = status.idleUntil.flatMap(parseDate), idle > Date() else { throw KeywardenError.invalidEnvelope }
                    }
                    receipt.record.session = status
                    try receipts.save(receipt)
                    return receipt.record
                }
            }
            try await Task.sleep(for: .milliseconds(500))
        }
        throw NotificationApprovalError.unconfirmed
    }
}
