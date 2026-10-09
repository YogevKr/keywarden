import CryptoKit
import Foundation

final class CryptoBox {
    private let keychain: KeychainStore
    private let encoder: JSONEncoder
    private let decryptionKey: Data?
    private let signingKey: Data?

    init(keychain: KeychainStore = KeychainStore(), decryptionKey: Data? = nil, signingKey: Data? = nil) {
        self.keychain = keychain
        self.decryptionKey = decryptionKey
        self.signingKey = signingKey
        self.encoder = JSONEncoder()
        self.encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    }

    func signingPublicKey() throws -> JWK {
        let privateKey = try signingPrivateKey()
        return try publicJWK(from: privateKey.publicKey.x963Representation)
    }

    func encryptionPublicKey() throws -> JWK {
        let privateKey = try encryptionPrivateKey()
        return try publicJWK(from: privateKey.publicKey.x963Representation)
    }

    func decrypt(_ payload: EncryptedPayload) throws -> Data {
        guard payload.version == 1, payload.algorithm == "ECDH-P256-AES-256-GCM" else { throw KeywardenError.invalidEnvelope }
        let privateKey = try encryptionPrivateKey()
        let ephemeral = try agreementPublicKey(from: payload.ephemeralPublicKey)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetricKey = SymmetricKey(data: sharedData(shared))
        let combinedCiphertext = try Base64URL.decode(payload.ciphertext)
        guard combinedCiphertext.count >= 16 else { throw KeywardenError.invalidEnvelope }
        let sealed = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Base64URL.decode(payload.iv)),
            ciphertext: Data(combinedCiphertext.dropLast(16)),
            tag: Data(combinedCiphertext.suffix(16)),
        )
        return try AES.GCM.open(sealed, using: symmetricKey)
    }

    func verify(_ envelope: SignedEnvelope) throws -> Bool {
        guard envelope.version == 1 else { throw KeywardenError.invalidEnvelope }
        let publicKey = try signingPublicKey(from: envelope.senderPublicKey)
        let unsigned = UnsignedEnvelope(version: envelope.version, kind: envelope.kind, body: envelope.body, senderPublicKey: envelope.senderPublicKey)
        let data = try encoder.encode(unsigned)
        return publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: Base64URL.decode(envelope.signature)), for: data)
    }

    func verify(_ envelope: SignedEnvelope, from pinnedKey: JWK, kind: String) throws -> Bool {
        let sender = envelope.senderPublicKey
        guard envelope.kind == kind, sender.kty == "EC", sender.crv == "P-256", sender.d == nil,
              sender.x == pinnedKey.x, sender.y == pinnedKey.y, pinnedKey.x != nil, pinnedKey.y != nil else {
            return false
        }
        return try verify(envelope)
    }

    func hash<T: Encodable>(_ value: T) throws -> String {
        Base64URL.encode(Data(SHA256.hash(data: try encoder.encode(value))))
    }

    func signDecision(_ decision: ApprovalDecision, brokerEncryptionKey: JWK) throws -> SignedEnvelope {
        try sign(decision, kind: "approval_decision", for: brokerEncryptionKey)
    }

    func sign<T: Encodable>(_ value: T, kind: String, for recipient: JWK) throws -> SignedEnvelope {
        let plaintext = try encoder.encode(value)
        let body = try encrypt(plaintext, for: recipient)
        let publicKey = try signingPublicKey()
        let unsigned = UnsignedEnvelope(version: 1, kind: kind, body: body, senderPublicKey: publicKey)
        let signature = try signingPrivateKey().signature(for: encoder.encode(unsigned))
        return SignedEnvelope(version: 1, kind: kind, body: body, senderPublicKey: publicKey, signature: Base64URL.encode(signature.rawRepresentation))
    }

    private func encrypt(_ plaintext: Data, for recipient: JWK) throws -> EncryptedPayload {
        let recipientKey = try agreementPublicKey(from: recipient)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipientKey)
        let symmetricKey = SymmetricKey(data: sharedData(shared))
        let sealed = try AES.GCM.seal(plaintext, using: symmetricKey)
        let ciphertext = sealed.ciphertext + sealed.tag
        return EncryptedPayload(
            version: 1,
            algorithm: "ECDH-P256-AES-256-GCM",
            ephemeralPublicKey: try publicJWK(from: ephemeral.publicKey.x963Representation),
            iv: Base64URL.encode(Data(sealed.nonce)),
            ciphertext: Base64URL.encode(ciphertext),
        )
    }

    private func signingPrivateKey() throws -> P256.Signing.PrivateKey {
        if let signingKey { return try P256.Signing.PrivateKey(rawRepresentation: signingKey) }
        if let data = try keychain.load("signing-private") {
            return try P256.Signing.PrivateKey(rawRepresentation: data)
        }
        let key = P256.Signing.PrivateKey()
        try keychain.save(key.rawRepresentation, for: "signing-private")
        return key
    }

    private func encryptionPrivateKey() throws -> P256.KeyAgreement.PrivateKey {
        if let decryptionKey { return try P256.KeyAgreement.PrivateKey(rawRepresentation: decryptionKey) }
        if let data = try keychain.load("encryption-private") {
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: data)
        }
        let key = P256.KeyAgreement.PrivateKey()
        try keychain.save(key.rawRepresentation, for: "encryption-private")
        return key
    }

    // Only the decryption key is shared with the notification extension.
    func notificationDecryptionKey() throws -> Data {
        try encryptionPrivateKey().rawRepresentation
    }

    // Only store this copy behind biometric Keychain access control.
    func notificationSigningKey() throws -> Data {
        try signingPrivateKey().rawRepresentation
    }

    private func publicJWK(from x963: Data) throws -> JWK {
        guard x963.count == 65, x963.first == 4 else { throw KeywardenError.invalidKey }
        return JWK(kty: "EC", crv: "P-256", x: Base64URL.encode(Data(x963.dropFirst().prefix(32))), y: Base64URL.encode(Data(x963.suffix(32))), d: nil, ext: true, keyOps: nil)
    }

    private func agreementPublicKey(from jwk: JWK) throws -> P256.KeyAgreement.PublicKey {
        guard let x = jwk.x, let y = jwk.y else { throw KeywardenError.invalidKey }
        return try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + Base64URL.decode(x) + Base64URL.decode(y))
    }

    private func signingPublicKey(from jwk: JWK) throws -> P256.Signing.PublicKey {
        guard let x = jwk.x, let y = jwk.y else { throw KeywardenError.invalidKey }
        return try P256.Signing.PublicKey(x963Representation: Data([4]) + Base64URL.decode(x) + Base64URL.decode(y))
    }

    private func sharedData(_ shared: SharedSecret) -> Data {
        shared.withUnsafeBytes { Data($0) }
    }
}

private struct UnsignedEnvelope: Encodable {
    let version: Int
    let kind: String
    let body: EncryptedPayload
    let senderPublicKey: JWK
}
