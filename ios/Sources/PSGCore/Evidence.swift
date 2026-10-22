import Crypto
import Foundation

/// What an evidence entry records (FR-EVD-01). Raw values are the names
/// Kotlin and Rust write.
public enum EntryType: String, CaseIterable, Sendable {
    case finding = "FINDING"
    case change = "CHANGE"
    case answer = "ANSWER"
    case export = "EXPORT"
    case watchGap = "WATCH_GAP"
    case note = "NOTE"
}

/// One append-only entry in the evidence timeline. Field names and hashing
/// are byte-identical to `EvidenceEntry` on Android and the desktop.
public struct EvidenceEntry: Equatable, Sendable {
    public let seq: Int64
    public let timestampMillis: Int64
    public let type: EntryType
    public let summary: String
    public let details: [String: String]
    public let prevHash: String
    public let entryHash: String
    public let keyId: String
    /// Base64 (no wrapping) of the signature over the entry-hash bytes.
    public let signature: String

    public init(seq: Int64, timestampMillis: Int64, type: EntryType, summary: String, details: [String: String],
                prevHash: String, entryHash: String, keyId: String, signature: String) {
        self.seq = seq
        self.timestampMillis = timestampMillis
        self.type = type
        self.summary = summary
        self.details = details
        self.prevHash = prevHash
        self.entryHash = entryHash
        self.keyId = keyId
        self.signature = signature
    }

    public func with(summary: String) -> EvidenceEntry {
        EvidenceEntry(seq: seq, timestampMillis: timestampMillis, type: type, summary: summary, details: details,
                      prevHash: prevHash, entryHash: entryHash, keyId: keyId, signature: signature)
    }
}

/// Signs and verifies entry hashes. On the iPhone this is a non-exportable
/// P-256 key in the Secure Enclave (NFR-SEC-13), see the app's
/// `SecureEnclaveEvidenceSigner`.
public protocol EvidenceSigner {
    var keyId: String { get }
    func sign(_ data: Data) throws -> Data
    func verify(_ data: Data, signature: Data) -> Bool
}

/// The result of checking a chain (FR-EVD-02/03).
public enum ChainCheck: Equatable, Sendable {
    case intact
    case broken(atSeq: Int64, reason: String)
}

public let genesisHash = String(repeating: "0", count: 64)

/// An append-only, SHA-256 hash-chained, signed evidence timeline. Any later
/// edit, deletion or reordering breaks `verify`. Persistence is the app's job
/// (an encrypted file under iOS Data Protection); this type holds the chain.
public final class EvidenceLog {
    let signer: EvidenceSigner
    let clock: () -> Int64
    public private(set) var entries: [EvidenceEntry]

    public init(signer: EvidenceSigner, clock: @escaping () -> Int64 = EvidenceLog.nowMillis, initial: [EvidenceEntry] = []) {
        self.signer = signer
        self.clock = clock
        self.entries = initial
    }

    public static func nowMillis() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }

    public var count: Int { entries.count }

    @discardableResult
    public func append(_ type: EntryType, _ summary: String, details: [String: String] = [:]) throws -> EvidenceEntry {
        let seq = Int64(entries.count)
        let prev = entries.last?.entryHash ?? genesisHash
        let ts = clock()
        let hash = Data(SHA256.hash(data: Self.canonicalContent(seq: seq, timestampMillis: ts, type: type, summary: summary, details: details, prevHash: prev)))
        let sig = try signer.sign(hash)
        let entry = EvidenceEntry(seq: seq, timestampMillis: ts, type: type, summary: summary, details: details,
                                  prevHash: prev, entryHash: hash.hexString, keyId: signer.keyId,
                                  signature: sig.base64EncodedString())
        entries.append(entry)
        return entry
    }

    public func verify() -> ChainCheck { Self.verify(entries, signer: signer) }

    /// The whole timeline as JSON, the same array format Kotlin exports.
    public func exportJSON(pretty: Bool = false) -> String { Self.encode(entries, pretty: pretty) }

    // MARK: Static helpers shared with importers and verifiers

    public static func verify(_ entries: [EvidenceEntry], signer: EvidenceSigner) -> ChainCheck {
        verify(entries) { data, sig in signer.verify(data, signature: sig) }
    }

    public static func verify(_ entries: [EvidenceEntry], verifySignature: (Data, Data) -> Bool) -> ChainCheck {
        var expectedPrev = genesisHash
        for (index, e) in entries.enumerated() {
            if e.seq != Int64(index) { return .broken(atSeq: e.seq, reason: "Sequence number out of order") }
            if e.prevHash != expectedPrev { return .broken(atSeq: e.seq, reason: "Previous-hash link does not match") }
            let recomputed = Data(SHA256.hash(data: canonicalContent(seq: e.seq, timestampMillis: e.timestampMillis, type: e.type,
                                                                     summary: e.summary, details: e.details, prevHash: e.prevHash)))
            if recomputed.hexString != e.entryHash { return .broken(atSeq: e.seq, reason: "Entry hash does not match its content") }
            guard let sig = Data(base64Encoded: e.signature) else {
                return .broken(atSeq: e.seq, reason: "Signature is not valid base64")
            }
            if !verifySignature(recomputed, sig) { return .broken(atSeq: e.seq, reason: "Signature does not verify") }
            expectedPrev = e.entryHash
        }
        return .intact
    }

    /// The canonical bytes an entry hash covers. Fixed field order, details
    /// sorted by key in UTF-16 order (Kotlin's `toSortedMap`), and `\`, newline,
    /// `;` and `=` escaped so values cannot forge field boundaries.
    public static func canonicalContent(seq: Int64, timestampMillis: Int64, type: EntryType, summary: String,
                                        details: [String: String], prevHash: String) -> Data {
        let detailBlock = details.keys.sorted(by: utf16Less).map { "\(escape($0))=\(escape(details[$0]!))" }.joined(separator: ";")
        let content = "\(seq)\n\(timestampMillis)\n\(type.rawValue)\n\(escape(summary))\n\(detailBlock)\n\(prevHash)"
        return Data(content.utf8)
    }

    static func escape(_ s: String) -> String {
        // Work on scalars so "\r\n" is not treated as one character.
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            switch u {
            case "\\": out.append(contentsOf: "\\\\".unicodeScalars)
            case "\n": out.append(contentsOf: "\\n".unicodeScalars)
            case ";": out.append(contentsOf: "\\;".unicodeScalars)
            case "=": out.append(contentsOf: "\\=".unicodeScalars)
            default: out.append(u)
            }
        }
        return String(out)
    }

    // MARK: JSON

    public static func encode(_ entries: [EvidenceEntry], pretty: Bool = false) -> String {
        JSONValue.array(entries.map(\.json)).serialized(pretty: pretty)
    }

    /// Reads either a bare array of entries (the Android / iPhone export) or
    /// an object with an `entries` array (the desktop's export format).
    public static func decode(_ text: String) throws -> [EvidenceEntry] {
        let root = try JSON.parse(text)
        guard let items = root.arrayValue ?? root["entries"]?.arrayValue else {
            throw JSONError(description: "No evidence entries found")
        }
        return try items.map(EvidenceEntry.init(json:))
    }
}

extension EvidenceEntry {
    public var json: JSONValue {
        var details = JSONObject()
        for k in self.details.keys.sorted(by: utf16Less) { details[k] = .string(self.details[k]!) }
        return .object(JSONObject([
            ("seq", .int(seq)),
            ("timestampMillis", .int(timestampMillis)),
            ("type", .string(type.rawValue)),
            ("summary", .string(summary)),
            ("details", .object(details)),
            ("prevHash", .string(prevHash)),
            ("entryHash", .string(entryHash)),
            ("keyId", .string(keyId)),
            ("signature", .string(signature)),
        ]))
    }

    public init(json: JSONValue) throws {
        func s(_ k: String) throws -> String {
            guard let v = json[k]?.stringValue else { throw JSONError(description: "Entry is missing '\(k)'") }
            return v
        }
        func n(_ k: String) throws -> Int64 {
            guard let v = json[k], case .number = v, let i = v.primitiveLong else { throw JSONError(description: "Entry is missing '\(k)'") }
            return i
        }
        guard let type = EntryType(rawValue: try s("type")) else { throw JSONError(description: "Unknown entry type") }
        var details = [String: String]()
        for (k, v) in json["details"]?.objectValue?.entries ?? [] {
            guard let str = v.stringValue else { throw JSONError(description: "Detail '\(k)' is not a string") }
            details[k] = str
        }
        self.init(seq: try n("seq"), timestampMillis: try n("timestampMillis"), type: type, summary: try s("summary"),
                  details: details, prevHash: try s("prevHash"), entryHash: try s("entryHash"), keyId: try s("keyId"),
                  signature: try s("signature"))
    }
}

// MARK: - Software signers and verifiers

/// An Ed25519 signer held in memory. Used by tests, the command-line tool and
/// for verifying desktop exports; the phone itself signs in the Secure Enclave.
public struct Ed25519EvidenceSigner: EvidenceSigner {
    public let keyId: String
    private let key: Curve25519.Signing.PrivateKey

    public init(keyId: String, seed: Data) throws {
        self.keyId = keyId
        self.key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    public func sign(_ data: Data) throws -> Data { try key.signature(for: data) }

    public func verify(_ data: Data, signature: Data) -> Bool {
        key.publicKey.isValidSignature(signature, for: data)
    }

    public var publicKeyX509: Data { Data(TrustedKey.spkiPrefix) + key.publicKey.rawRepresentation }
}

/// Verifies a timeline written by another device from its exported public
/// key: Ed25519 (desktop) or ECDSA P-256 with SHA-256 (Android Keystore and the
/// iPhone Secure Enclave, DER signatures).
public struct PublicKeyEvidenceVerifier: EvidenceSigner {
    public let keyId: String
    private let check: (Data, Data) -> Bool

    public init(keyId: String, publicKeyX509 der: Data) throws {
        self.keyId = keyId
        let bytes = [UInt8](der)
        if bytes.count == 44, Array(bytes.prefix(12)) == TrustedKey.spkiPrefix {
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: bytes.suffix(32))
            check = { data, sig in key.isValidSignature(sig, for: data) }
        } else {
            let key = try P256.Signing.PublicKey(derRepresentation: der)
            check = { data, sig in
                guard let s = try? P256.Signing.ECDSASignature(derRepresentation: sig) else { return false }
                return key.isValidSignature(s, for: data)
            }
        }
    }

    public func sign(_ data: Data) throws -> Data {
        throw JSONError(description: "This key can only verify")
    }

    public func verify(_ data: Data, signature: Data) -> Bool { check(data, signature) }
}

extension Data {
    public var hexString: String { map { String(format: "%02x", $0) }.joined() }
}
