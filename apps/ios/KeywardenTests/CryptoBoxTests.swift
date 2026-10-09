import CryptoKit
import Security
import XCTest
@testable import Keywarden

final class CryptoBoxTests: XCTestCase {
    private var service: String!
    private var store: KeychainStore!
    private var box: CryptoBox!

    override func setUpWithError() throws {
        service = "ai.sawmills.keywarden.tests.\(UUID().uuidString)"
        store = KeychainStore(service: service)
        box = CryptoBox(keychain: store)
    }

    override func tearDownWithError() throws {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service!,
        ] as CFDictionary)
    }

    func testDecryptsCombinedCiphertextAndTagAcrossBase64Boundaries() throws {
        // GCM uses a 16-byte tag. It must be split after base64 decoding.
        for length in [0, 1, 2, 3, 31, 32, 33, 256] {
            let plaintext = Data((0..<length).map { UInt8($0 % 251) })
            let payload = try encryptedPayload(plaintext)
            XCTAssertEqual(try box.decrypt(payload), plaintext, "Length: \(length)")
            let reloaded = CryptoBox(keychain: KeychainStore(service: service))
            XCTAssertEqual(try reloaded.decrypt(payload), plaintext)
        }
    }

    func testRejectsModifiedAuthenticationTag() throws {
        let payload = try encryptedPayload(Data("session request".utf8))
        var bytes = try Base64URL.decode(payload.ciphertext)
        bytes[bytes.count - 1] ^= 1
        let modified = replacingCiphertext(payload, with: bytes)
        XCTAssertThrowsError(try box.decrypt(modified))
    }

    func testRejectsTruncatedAuthenticationTag() throws {
        let payload = try encryptedPayload(Data())
        let truncated = replacingCiphertext(payload, with: Data(repeating: 0, count: 15))
        XCTAssertThrowsError(try box.decrypt(truncated)) { error in
            guard case KeywardenError.invalidEnvelope = error else {
                return XCTFail("Expected invalidEnvelope, received \(error)")
            }
        }
    }

    private func encryptedPayload(_ plaintext: Data) throws -> EncryptedPayload {
        let recipient = try box.encryptionPublicKey()
        let point = Data([4]) + (try Base64URL.decode(XCTUnwrap(recipient.x)))
            + (try Base64URL.decode(XCTUnwrap(recipient.y)))
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: point)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: publicKey)
        let symmetric = SymmetricKey(data: shared.withUnsafeBytes { Data($0) })
        let sealed = try AES.GCM.seal(plaintext, using: symmetric)
        let ephemeralPoint = ephemeral.publicKey.x963Representation
        return EncryptedPayload(
            version: 1,
            algorithm: "ECDH-P256-AES-256-GCM",
            ephemeralPublicKey: JWK(
                kty: "EC", crv: "P-256",
                x: Base64URL.encode(Data(ephemeralPoint.dropFirst().prefix(32))),
                y: Base64URL.encode(Data(ephemeralPoint.suffix(32))),
                d: nil, ext: true, keyOps: nil
            ),
            iv: Base64URL.encode(Data(sealed.nonce)),
            ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag)
        )
    }

    private func replacingCiphertext(_ payload: EncryptedPayload, with data: Data) -> EncryptedPayload {
        EncryptedPayload(
            version: payload.version, algorithm: payload.algorithm,
            ephemeralPublicKey: payload.ephemeralPublicKey, iv: payload.iv,
            ciphertext: Base64URL.encode(data)
        )
    }
}
