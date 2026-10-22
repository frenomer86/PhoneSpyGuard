import Crypto
import Foundation

/// One Ed25519 signature over the exact bundle payload bytes.
public struct BundleSignature: Sendable {
    public let keyId: String
    public let signature: Data

    public init(keyId: String, signature: Data) {
        self.keyId = keyId
        self.signature = signature
    }
}

/// A trusted release key.
public struct TrustedKey {
    public let keyId: String
    public let publicKey: Curve25519.Signing.PublicKey
    /// A test key whose private half is not held offline. Release builds of
    /// the app refuse these (see `TrustStore.excludingDevelopmentKeys`).
    public let development: Bool

    public init(keyId: String, publicKey: Curve25519.Signing.PublicKey, development: Bool = false) {
        self.keyId = keyId
        self.publicKey = publicKey
        self.development = development
    }

    /// The fixed DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
    public static let spkiPrefix: [UInt8] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]

    /// From an X.509 SubjectPublicKeyInfo DER Ed25519 key, the encoding
    /// `TrustedKey.fromX509` takes on Android and in Rust, so one
    /// `trusted-keys.json` serves every app.
    public static func fromX509(keyId: String, x509: Data, development: Bool = false) throws -> TrustedKey {
        let bytes = [UInt8](x509)
        guard bytes.count == 44, Array(bytes.prefix(12)) == spkiPrefix else {
            throw BundleRejected("Key \(keyId) is not an Ed25519 SubjectPublicKeyInfo")
        }
        return TrustedKey(keyId: keyId, publicKey: try Curve25519.Signing.PublicKey(rawRepresentation: bytes.suffix(32)),
                          development: development)
    }
}

/// The trust file shipped with the app:
/// `{"threshold":2,"keys":[{"keyId","publicKey","development"?}]}`.
///
/// The same key may not appear twice, under the same id or a different one:
/// otherwise one signer could count twice towards 2-of-3.
public struct TrustStore {
    public let threshold: Int
    public let keys: [TrustedKey]

    /// The development keys whose private halves sat in `desktop/dev-keys/`
    /// (review finding H6). They were deleted and revoked on 2026-10-22, and
    /// no trust file may list them again (same list as REVOKED_KEYS in Rust).
    public static let revokedKeys = [
        "MCowBQYDK2VwAyEAPLV2Dk5hwc2ugW7RzGg3G5aMZKdcOVKCtMqZdHzcmXE=",
        "MCowBQYDK2VwAyEAX0dJ10X/B16/Y31cicRNqzhZkt6Yl8E26g/YFHDgiYc=",
        "MCowBQYDK2VwAyEAcJvqgASL7C/W7RQdqK+bdcLzgZy44g3pPytVr5umJi0=",
    ]

    public init(threshold: Int, keys: [TrustedKey]) throws {
        guard threshold >= 1 else { throw BundleRejected("Trust threshold must be at least 1") }
        guard keys.count >= threshold else { throw BundleRejected("Trust file has fewer keys than its threshold") }
        let revoked = Set(Self.revokedKeys.compactMap { Data(base64Encoded: $0) }.map { $0.suffix(32) })
        var ids = Set<String>(), raw = Set<Data>()
        for k in keys {
            guard !revoked.contains(k.publicKey.rawRepresentation) else {
                throw BundleRejected("Trust file lists revoked key \(k.keyId)")
            }
            guard ids.insert(k.keyId).inserted else { throw BundleRejected("Trust file lists key id \(k.keyId) twice") }
            guard raw.insert(k.publicKey.rawRepresentation).inserted else {
                throw BundleRejected("Trust file lists the same public key twice (\(k.keyId))")
            }
        }
        self.threshold = threshold
        self.keys = keys
    }

    public init(json text: String) throws {
        guard let root = try JSON.parse(text).objectValue, let items = root["keys"]?.arrayValue else {
            throw BundleRejected("Trust file has no 'keys'")
        }
        let keys = try items.map { item in
            guard let id = item["keyId"]?.stringValue, let b64 = item["publicKey"]?.stringValue, let der = Data(base64Encoded: b64) else {
                throw BundleRejected("Trust file has a malformed key")
            }
            return try TrustedKey.fromX509(keyId: id, x509: der, development: item["development"]?.boolValue ?? false)
        }
        try self.init(threshold: Int(root["threshold"]?.primitiveLong ?? 2), keys: keys)
    }

    public var hasDevelopmentKeys: Bool { keys.contains { $0.development } }

    /// The store a release build uses: development keys removed, threshold
    /// unchanged, so a bundle signed only with test keys no longer verifies.
    public func excludingDevelopmentKeys() -> TrustStore {
        // Not through init: fewer keys than the threshold is the point here,
        // so verification then fails with "Needs 2 valid signatures".
        TrustStore(unchecked: threshold, keys: keys.filter { !$0.development })
    }

    private init(unchecked threshold: Int, keys: [TrustedKey]) {
        self.threshold = threshold
        self.keys = keys
    }
}

/// The outcome of verifying a candidate bundle before it is applied.
public enum VerifyResult: Equatable, Sendable {
    case accepted
    case rejected(String)
}

/// Decides whether a signed bundle may be applied (FR-RUL-01, NFR-SEC-15):
/// at least `threshold` distinct trusted keys signed the exact bytes, it
/// parses, it is not older than the installed version, and it has not
/// expired. Mirrors `BundleVerifier` in Kotlin and `verifier.rs`.
public struct BundleVerifier {
    public let trustedKeys: [TrustedKey]
    public let threshold: Int
    private let clock: () -> Date

    public init(trustedKeys: [TrustedKey], threshold: Int = 2, clock: @escaping () -> Date = Date.init) {
        self.trustedKeys = trustedKeys
        self.threshold = threshold
        self.clock = clock
    }

    public init(trust: TrustStore, clock: @escaping () -> Date = Date.init) {
        self.init(trustedKeys: trust.keys, threshold: trust.threshold, clock: clock)
    }

    /// Only the 2-of-3 signature check, for signed files that are not rule
    /// bundles (the iPhone's indicator file).
    public func checkSignatures(payload: Data, signatures: [BundleSignature]) -> VerifyResult {
        // Count distinct public keys, not ids, so a key listed twice under
        // two ids still counts once.
        var valid = Set<Data>()
        for sig in signatures {
            guard let key = trustedKeys.first(where: { $0.keyId == sig.keyId }) else { continue }
            if key.publicKey.isValidSignature(sig.signature, for: payload) { valid.insert(key.publicKey.rawRepresentation) }
        }
        if valid.count < threshold {
            return .rejected("Needs \(threshold) valid signatures, found \(valid.count)")
        }
        return .accepted
    }

    public func verify(payload: Data, signatures: [BundleSignature], installedVersion: Int) -> VerifyResult {
        if case .rejected(let why) = checkSignatures(payload: payload, signatures: signatures) { return .rejected(why) }
        guard let text = String(data: payload, encoding: .utf8) else { return .rejected("Bundle is not UTF-8") }
        let bundle: RuleBundle
        do {
            bundle = try RuleBundleParser().parse(text)
        } catch {
            return .rejected("\(error)")
        }
        if bundle.version < installedVersion {
            return .rejected("Bundle version \(bundle.version) is older than installed \(installedVersion)")
        }
        if !(bundle.expiresAt > clock()) {
            return .rejected("Bundle expired at \(ISO8601.format(bundle.expiresAt))")
        }
        return .accepted
    }

    /// Verify and parse in one step: the only way the app loads rules.
    public func load(payload: Data, signatureFile: Data, installedVersion: Int = 0) throws -> RuleBundle {
        let sigs = try Self.parseSignatureFile(signatureFile)
        switch verify(payload: payload, signatures: sigs, installedVersion: installedVersion) {
        case .accepted:
            return try RuleBundleParser().parse(String(decoding: payload, as: UTF8.self))
        case .rejected(let reason):
            throw BundleRejected(reason)
        }
    }

    /// `name.sig.json`: `{"signatures":[{"keyId":"k1","signature":"<base64>"}]}`.
    public static func parseSignatureFile(_ data: Data) throws -> [BundleSignature] {
        guard let items = try JSON.parse(data)["signatures"]?.arrayValue else {
            throw BundleRejected("Signature file has no 'signatures'")
        }
        return items.compactMap { item in
            guard let id = item["keyId"]?.stringValue, let b64 = item["signature"]?.stringValue,
                  let sig = Data(base64Encoded: b64) else { return nil }
            return BundleSignature(keyId: id, signature: sig)
        }
    }
}
