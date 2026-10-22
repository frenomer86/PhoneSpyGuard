import CryptoKit
import DeviceCheck
import Foundation
import PSGCore

/// Apple App Attest (NFR-SEC-02, review finding H7): Apple's servers vouch,
/// in a certificate chain to Apple's App Attest root, that a key belongs to
/// this app on a genuine iPhone. The attestation's client data is the SHA-256
/// of the evidence public key, which ties that key to a real device.
///
/// It needs the App Attest capability (entitlement
/// `com.apple.developer.devicecheck.appattest-environment`), which the free
/// Apple ID used for sideloading may not grant, so this is best effort: with
/// no capability, on the Simulator, or offline, the export simply has no
/// `appAttest` field and says nothing it cannot prove.
enum DeviceAttestation {
    private static let keyAccount = "app-attest-key-id"

    static func attest(publicKeyX509: Data) async -> JSONValue? {
        let service = DCAppAttestService.shared
        guard service.isSupported else { return nil }
        do {
            let keyId: String
            if let stored = Keychain.load(keyAccount) {
                keyId = String(decoding: stored, as: UTF8.self)
            } else {
                keyId = try await service.generateKey()
                try Keychain.save(Data(keyId.utf8), keyAccount)
            }
            let clientDataHash = Data(SHA256.hash(data: publicKeyX509))
            let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)
            return .object(JSONObject([
                ("format", .string("apple-app-attest")),
                ("keyId", .string(keyId)),
                ("clientDataHash", .string(clientDataHash.hexString)),
                ("clientData", .string("SHA-256 of publicKeyX509")),
                ("attestation", .string(attestation.base64EncodedString())),
                ("verify", .string("Check the attestation's certificate chain against Apple's App Attest root CA and that its nonce covers clientDataHash: https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server")),
            ]))
        } catch {
            return nil
        }
    }
}
