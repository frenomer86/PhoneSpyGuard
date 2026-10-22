import CryptoKit
import Foundation
import PSGCore
import Security

/// Signs evidence entries with a non-exportable P-256 key in the Secure
/// Enclave (NFR-SEC-13), the iPhone's equivalent of the Android Keystore key.
/// Signatures are ECDSA-SHA256 in DER, exactly what Android writes, so one
/// verifier checks both phones' exports.
///
/// The Secure Enclave key itself cannot leave the chip; what is stored in the
/// Keychain is an opaque handle that only this device's enclave can use. The
/// Simulator has no Secure Enclave, so there the key is an ordinary software
/// key and its id says so.
final class SecureEnclaveEvidenceSigner: EvidenceSigner {
    let keyId: String
    private let signWithKey: (Data) throws -> Data
    let publicKey: P256.Signing.PublicKey

    private static let account = "evidence-signing-key"

    init() throws {
        if SecureEnclave.isAvailable {
            let key: SecureEnclave.P256.Signing.PrivateKey
            if let stored = Self.load() {
                key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored)
            } else {
                let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)!
                key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
                try Self.save(key.dataRepresentation)
            }
            keyId = "ios-secure-enclave"
            publicKey = key.publicKey
            signWithKey = { try key.signature(for: $0).derRepresentation }
        } else {
            let key: P256.Signing.PrivateKey
            if let stored = Self.load(), let k = try? P256.Signing.PrivateKey(rawRepresentation: stored) {
                key = k
            } else {
                key = P256.Signing.PrivateKey()
                try Self.save(key.rawRepresentation)
            }
            keyId = "ios-software-key"
            publicKey = key.publicKey
            signWithKey = { try key.signature(for: $0).derRepresentation }
        }
    }

    func sign(_ data: Data) throws -> Data { try signWithKey(data) }

    func verify(_ data: Data, signature: Data) -> Bool {
        guard let s = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
        return publicKey.isValidSignature(s, for: data)
    }

    /// X.509 SubjectPublicKeyInfo, as Android's `publicKeyEncoded()` gives.
    var publicKeyX509: Data { publicKey.derRepresentation }

    private static func load() -> Data? { Keychain.load(account) }
    private static func save(_ data: Data) throws { try Keychain.save(data, account) }
}
