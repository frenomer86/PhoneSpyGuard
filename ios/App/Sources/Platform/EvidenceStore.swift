import CryptoKit
import Foundation
import PSGCore
import UIKit

/// Keeps the evidence timeline on the phone (FR-EVD-01) in a file protected
/// by iOS Data Protection (`completeFileProtection`: encrypted with a key the
/// Secure Enclave releases only while the phone is unlocked), and exports it
/// as signed JSON and PDF (FR-EVD-02/03). Nothing leaves the phone unless the
/// owner shares an export.
final class EvidenceStore {
    let signer: SecureEnclaveEvidenceSigner
    let log: EvidenceLog
    private let url: URL
    /// The last signed head (count + last hash), kept in the Keychain apart
    /// from the timeline file, so deleting the newest entries from the file
    /// shows up as a broken timeline (review finding H7).
    private(set) var head: EvidenceHead?
    /// When the owner last sent a checkpoint off the phone.
    private(set) var lastCheckpoint: Date?
    private static let headAccount = "evidence-head"
    private static let checkpointAccount = "evidence-last-checkpoint"

    init() throws {
        signer = try SecureEnclaveEvidenceSigner()
        let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        url = dir.appendingPathComponent("evidence.json")
        var initial = [EvidenceEntry]()
        if let data = try? Data(contentsOf: url) {
            initial = (try? EvidenceLog.decode(String(decoding: data, as: UTF8.self))) ?? []
        }
        log = EvidenceLog(signer: signer, initial: initial)
        head = Keychain.load(Self.headAccount).flatMap { try? EvidenceHead(json: JSON.parse($0)) }
        lastCheckpoint = Keychain.load(Self.checkpointAccount).flatMap { Double(String(decoding: $0, as: UTF8.self)) }
            .map(Date.init(timeIntervalSince1970:))
    }

    /// Writes the timeline, then signs a new head for it. If the timeline no
    /// longer matches the stored head, the old head is kept, so the warning
    /// stays until someone looks at it.
    func save() throws {
        try Data(log.exportJSON().utf8).write(to: url, options: [.atomic, .completeFileProtection])
        if case .intact = check {
            let h = try log.signHead()
            try Keychain.save(Data(h.json.serialized(pretty: false).utf8), Self.headAccount)
            head = h
        }
    }

    var check: ChainCheck { log.verify(heads: head.map { [$0] } ?? []) }

    /// A checkpoint for the owner to send off the phone (to themselves by
    /// e-mail, or to someone they trust). Anyone holding the phone could sign
    /// a new head, but not one dated in the past that was already sent away,
    /// so a sent checkpoint proves the timeline was at least this long.
    func checkpoint() throws -> String {
        try log.append(.export, "Checkpoint made to send off the phone", details: ["entries": String(log.count)])
        try save()
        let h = try log.signHead()
        lastCheckpoint = Date()
        try? Keychain.save(Data(String(Date().timeIntervalSince1970).utf8), Self.checkpointAccount)
        return h.checkpointText + "\n\nCheck it with: psg-ios-check verify-evidence evidence-timeline.json --checkpoint <this message saved as a file>"
    }

    /// The export envelope the desktop also uses: the entries plus the public
    /// key that verifies them, a signed head, and (when the build has the App
    /// Attest capability) Apple's attestation that the key's app runs on a
    /// genuine iPhone. Anyone can check the file with
    /// `psg-ios-check verify-evidence` or the desktop app.
    func exportJSON() async throws -> URL {
        try log.append(.export, "Evidence exported as JSON", details: ["entries": String(log.count)])
        try save()
        var fields: [(String, JSONValue)] = [
            ("format", .string("phone-spy-guard-evidence/1")),
            ("exportedAt", .string(ISO8601.format(Date()))),
            ("device", .string("iPhone, iOS \(UIDevice.current.systemVersion)")),
            ("keyId", .string(signer.keyId)),
            ("publicKeyX509", .string(signer.publicKeyX509.base64EncodedString())),
            ("chain", .string(chainText)),
            ("head", try log.signHead().json),
        ]
        if let attest = await DeviceAttestation.attest(publicKeyX509: signer.publicKeyX509) {
            fields.append(("appAttest", attest))
        }
        fields.append(("entries", .array(log.entries.map(\.json))))
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("evidence-timeline.json")
        try Data(JSONValue.object(JSONObject(fields)).serialized(pretty: true).utf8).write(to: out, options: .atomic)
        return out
    }

    var chainText: String {
        switch check {
        case .intact: return "Intact: every entry's hash and signature verify."
        case .broken(let seq, let reason): return "WARNING: the timeline is broken at entry \(seq) (\(reason)). Entries from there on cannot be trusted, and someone may have changed or deleted them."
        }
    }

    /// A readable PDF of the same entries, with the chain status and key
    /// fingerprint on the first page (FR-EVD-02/03).
    func exportPDF() throws -> URL {
        try log.append(.export, "Evidence exported as PDF", details: ["entries": String(log.count)])
        try save()
        let page = CGRect(x: 0, y: 0, width: 595, height: 842) // A4 in points
        let margin: CGFloat = 40
        let renderer = UIGraphicsPDFRenderer(bounds: page)
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("evidence-timeline.pdf")
        typealias Attrs = [NSAttributedString.Key: Any]
        let title: Attrs = [.font: UIFont.boldSystemFont(ofSize: 18)]
        let body: Attrs = [.font: UIFont.systemFont(ofSize: 10)]
        let heading: Attrs = [.font: UIFont.boldSystemFont(ofSize: 10)]
        let small: Attrs = [.font: UIFont.monospacedSystemFont(ofSize: 7, weight: .regular), .foregroundColor: UIColor.darkGray]
        let warn: Attrs = [.font: UIFont.boldSystemFont(ofSize: 11), .foregroundColor: UIColor.systemRed]
        let fmt = DateFormatter()
        fmt.dateStyle = .medium
        fmt.timeStyle = .medium
        let fingerprint = Data(SHA256Hex.digest(signer.publicKeyX509).prefix(16)).hexString

        try renderer.writePDF(to: out) { ctx in
            var y = page.maxY
            func newPage() { ctx.beginPage(); y = margin }
            func draw(_ s: String, _ attrs: Attrs) {
                let text = NSAttributedString(string: s, attributes: attrs)
                let height = text.boundingRect(with: CGSize(width: page.width - 2 * margin, height: .greatestFiniteMagnitude),
                                               options: .usesLineFragmentOrigin, context: nil).height
                if y + height > page.height - margin { newPage() }
                text.draw(with: CGRect(x: margin, y: y, width: page.width - 2 * margin, height: height), options: .usesLineFragmentOrigin, context: nil)
                y += height + 4
            }
            newPage()
            draw("Phone Spy Guard evidence timeline", title)
            draw("Exported \(fmt.string(from: Date())) from an iPhone on iOS \(UIDevice.current.systemVersion).", body)
            if case .intact = check { draw(chainText, body) } else { draw(chainText, warn) }
            draw("Signing key \(signer.keyId), fingerprint \(fingerprint). The JSON export holds the full public key for checking.", body)
            if let h = head {
                draw("Signed head: \(h.count) entries, last hash \(h.lastHash.prefix(16))…, at \(fmt.string(from: Date(timeIntervalSince1970: TimeInterval(h.timestampMillis) / 1000))).", body)
            }
            if let c = lastCheckpoint {
                draw("Last checkpoint sent off the phone: \(fmt.string(from: c)).", body)
            } else {
                draw("No checkpoint has been sent off the phone yet, so deleting the newest entries cannot be ruled out by a third party.", body)
            }
            y += 8
            for e in log.entries {
                let when = fmt.string(from: Date(timeIntervalSince1970: TimeInterval(e.timestampMillis) / 1000))
                draw("#\(e.seq)  \(when)  \(e.type.rawValue)", heading)
                draw(e.summary, body)
                for (k, v) in e.details.sorted(by: { $0.key < $1.key }) { draw("\(k): \(v)", body) }
                draw("hash \(e.entryHash)  prev \(e.prevHash.prefix(16))…", small)
                y += 6
            }
        }
        return out
    }
}

enum SHA256Hex {
    static func digest(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }
}
