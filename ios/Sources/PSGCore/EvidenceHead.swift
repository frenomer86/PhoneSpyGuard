import Crypto
import Foundation

/// A signed statement of how long the timeline was at a moment: its entry
/// count and the hash of its last entry. The hash chain alone cannot show
/// that the newest entries were deleted, because what is left still links up;
/// a head can (review finding H7).
///
/// The app keeps the latest head apart from the timeline file (in the
/// Keychain) and puts it in every export. The owner can also send a head off
/// the phone as a checkpoint (an email to themselves, a trusted contact).
/// Anyone holding the phone can sign a new head, so only a checkpoint that
/// left the phone proves the timeline was at least that long at that time.
///
/// Signed bytes: SHA-256 of
/// `psg-evidence-head/1\n<count>\n<lastHash>\n<timestampMillis>\n<keyId>`,
/// with `keyId` escaped like entry fields. `lastHash` is 64 zeros for an
/// empty timeline. Same signer and signature format as the entries.
public struct EvidenceHead: Equatable, Sendable {
    public static let format = "psg-evidence-head/1"

    public let count: Int64
    public let lastHash: String
    public let timestampMillis: Int64
    public let keyId: String
    public let signature: String

    public init(count: Int64, lastHash: String, timestampMillis: Int64, keyId: String, signature: String) {
        self.count = count
        self.lastHash = lastHash
        self.timestampMillis = timestampMillis
        self.keyId = keyId
        self.signature = signature
    }

    public static func digest(count: Int64, lastHash: String, timestampMillis: Int64, keyId: String) -> Data {
        let content = "\(format)\n\(count)\n\(lastHash)\n\(timestampMillis)\n\(EvidenceLog.escape(keyId))"
        return Data(SHA256.hash(data: Data(content.utf8)))
    }

    public func signatureValid(_ verifySignature: (Data, Data) -> Bool) -> Bool {
        guard let sig = Data(base64Encoded: signature) else { return false }
        return verifySignature(Self.digest(count: count, lastHash: lastHash, timestampMillis: timestampMillis, keyId: keyId), sig)
    }

    public var json: JSONValue {
        .object(JSONObject([
            ("format", .string(Self.format)),
            ("count", .number(String(count))),
            ("lastHash", .string(lastHash)),
            ("timestampMillis", .number(String(timestampMillis))),
            ("keyId", .string(keyId)),
            ("signature", .string(signature)),
        ]))
    }

    /// Reads the iPhone's JSON and the desktop's (which names the time
    /// `signedMillis` and has no `format`), so one checker serves both.
    public init(json v: JSONValue) throws {
        if let f = v["format"]?.stringValue, f != Self.format { throw JSONError(description: "Not an evidence checkpoint") }
        guard let count = v["count"]?.primitiveLong, let last = v["lastHash"]?.stringValue,
              let ts = (v["timestampMillis"] ?? v["signedMillis"])?.primitiveLong, let keyId = v["keyId"]?.stringValue,
              let sig = v["signature"]?.stringValue else {
            throw JSONError(description: "Not an evidence checkpoint")
        }
        self.init(count: count, lastHash: last, timestampMillis: ts, keyId: keyId, signature: sig)
    }

    /// Finds the checkpoint inside a pasted text or e-mail: the iPhone's JSON
    /// object (between the first `{` and the last `}`), or the desktop's
    /// "name: value" lines (entries, last-hash, signed-millis, pc-key,
    /// signature). Quoting marks such as "> " are ignored.
    public init(text: String) throws {
        if let open = text.firstIndex(of: "{"), let close = text.lastIndex(of: "}"), open < close,
           let v = try? JSON.parse(String(text[open...close])), let head = try? EvidenceHead(json: v) {
            self = head
            return
        }
        var fields = [String: String]()
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.drop { $0 == ">" || $0 == " " || $0 == "\t" }
            guard let colon = line.firstIndex(of: ":") else { continue }
            fields[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard let count = fields["entries"].flatMap({ Int64($0) }), let last = fields["last-hash"],
              let ts = fields["signed-millis"].flatMap({ Int64($0) }), let keyId = fields["pc-key"] ?? fields["key-id"],
              let sig = fields["signature"] else {
            throw JSONError(description: "No checkpoint found in the text")
        }
        self.init(count: count, lastHash: last, timestampMillis: ts, keyId: keyId, signature: sig)
    }

    /// A plain message the owner can send to themselves or someone they trust.
    public var checkpointText: String {
        let when = ISO8601.format(Date(timeIntervalSince1970: TimeInterval(timestampMillis) / 1000))
        return """
        Phone Spy Guard evidence checkpoint
        On \(when) the evidence timeline on my phone had \(count) entries.
        Keep this message. It lets anyone check later that no entries were deleted.

        \(json.serialized(pretty: false))
        """
    }
}

extension EvidenceLog {
    /// Sign a head for the timeline as it is now.
    public func signHead() throws -> EvidenceHead {
        let count = Int64(entries.count)
        let last = entries.last?.entryHash ?? genesisHash
        let ts = clock()
        let sig = try signer.sign(EvidenceHead.digest(count: count, lastHash: last, timestampMillis: ts, keyId: signer.keyId))
        return EvidenceHead(count: count, lastHash: last, timestampMillis: ts, keyId: signer.keyId, signature: sig.base64EncodedString())
    }

    public func verify(heads: [EvidenceHead]) -> ChainCheck {
        Self.verify(entries, heads: heads) { data, sig in signer.verify(data, signature: sig) }
    }

    /// The chain check plus every head: each must carry a valid signature,
    /// and the timeline must still hold the entry it names, with that hash.
    /// A timeline shorter than a head means its newest entries were deleted.
    public static func verify(_ entries: [EvidenceEntry], heads: [EvidenceHead], verifySignature: (Data, Data) -> Bool) -> ChainCheck {
        let chain = verify(entries, verifySignature: verifySignature)
        if case .broken = chain { return chain }
        for head in heads {
            let when = ISO8601.format(Date(timeIntervalSince1970: TimeInterval(head.timestampMillis) / 1000))
            guard head.signatureValid(verifySignature) else {
                return .broken(atSeq: head.count, reason: "The checkpoint of \(when) has a signature that does not verify")
            }
            if Int64(entries.count) < head.count {
                return .broken(atSeq: Int64(entries.count),
                               reason: "A checkpoint of \(when) says the timeline had \(head.count) entries, but only \(entries.count) are left: the newest entries were deleted")
            }
            let expected = head.count == 0 ? genesisHash : entries[Int(head.count - 1)].entryHash
            if expected != head.lastHash {
                return .broken(atSeq: max(0, head.count - 1), reason: "Entry \(head.count - 1) differs from the checkpoint of \(when)")
            }
        }
        return .intact
    }
}
