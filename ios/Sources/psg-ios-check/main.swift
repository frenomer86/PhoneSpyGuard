// psg-ios-check: the iPhone companion's checks from a command line, for
// testing on any computer with Swift (macOS, Linux, Windows).
//
//   psg-ios-check analyze <sysdiagnose.tar.gz | shutdown.log> [--stix <file.stix2>]
//   Release keys (the ceremony in ../desktop/rules/KEY-CEREMONY.md; same files as psg-sign):
//   psg-ios-check keygen <key-id> <offline-dir>              holder: <id>.key.json + <id>.pub.json
//   psg-ios-check trust <threshold> <pub.json>...            builder: prints trusted-keys.json
//   psg-ios-check sign <signed-file.json> <key.json>...      holder: adds a signature to <name>.sig.json
//   psg-ios-check log <Resources dir> <rule-log.json>        builder: public log entry per file
//   psg-ios-check sign-once <file.json>...                   single-use keys, destroyed after signing
//   psg-ios-check verify <bundle.json> <trusted-keys.json>
//   psg-ios-check verify-evidence <export.json> [<publicKeyX509 base64>] [--checkpoint <file>]...

import Crypto
import Foundation
import PSGCompanion
import PSGCore

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

/// A lab tool: it accepts rules signed with the development keys, and says so.
func loadRules() throws -> CompanionRules {
    let rules = try CompanionRules.bundled(allowDevelopmentKeys: true)
    if rules.developmentKeys { FileHandle.standardError.write(Data("note: rules accepted on development keys (lab build)\n".utf8)) }
    return rules
}

/// Refuse to sign what the app would reject.
func checkSignable(_ payload: Data, at url: URL) throws {
    switch (try? JSON.parse(payload))?["format"]?.stringValue {
    case "phone-spy-guard-indicators/1":
        _ = try IndicatorSet.fromIndicatorFile(payload)
    default:
        _ = try RuleBundleParser().parse(String(decoding: payload, as: UTF8.self))
    }
}

func publicEntry(_ id: String, _ key: Curve25519.Signing.PublicKey) -> JSONValue {
    .object(JSONObject([("keyId", .string(id)), ("publicKey", .string((Data(TrustedKey.spkiPrefix) + key.rawRepresentation).base64EncodedString()))]))
}

/// True if `dir` is inside a Phone Spy Guard source tree, where a private key
/// would end up next to the code (review finding H6).
func insideSourceTree(_ dir: URL) -> Bool {
    var d = dir
    while d.path != "/" && !d.path.isEmpty {
        let fm = FileManager.default
        if fm.fileExists(atPath: d.appendingPathComponent("Sources/PSGCore").path)
            || fm.fileExists(atPath: d.appendingPathComponent("desktop/crates/psg-core").path)
            || fm.fileExists(atPath: d.appendingPathComponent("ios/Sources/PSGCore").path) { return true }
        d = d.deletingLastPathComponent()
    }
    return false
}

func printFindings(_ cards: [Finding]) {
    for f in cards {
        print("  [\(f.rating.label)] \(f.displayName) — \(f.verdict.confidence.rawValue)")
        for r in f.concerningRules { print("      \(r.id): \(r.title)") }
        for (k, v) in f.details.sorted(by: { $0.key < $1.key }) { print("      \(k): \(v)") }
    }
}

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    fail("usage: psg-ios-check analyze|keygen|trust|sign|log|sign-once|verify|verify-evidence ... (see source header)")
}
args.removeFirst()

do {
    switch command {
    case "analyze":
        guard let path = args.first else { fail("analyze needs a file") }
        var extra: IndicatorSet?
        if let i = args.firstIndex(of: "--stix"), i + 1 < args.count {
            extra = try IndicatorSet.fromSTIX2(String(contentsOfFile: args[i + 1], encoding: .utf8), source: (args[i + 1] as NSString).lastPathComponent)
        }
        let analyzer = DiagnosticAnalyzer(rules: try loadRules(), extraIndicators: extra)
        let started = Date()
        let report = try analyzer.analyze(url: URL(fileURLWithPath: path))
        print("Result: \(report.rating.label)")
        print("Restarts in shutdown log: \(report.rebootsSeen), processes: \(report.findings.count), crash reports: \(report.crashReportsSeen)")
        printFindings(report.cards)
        for l in report.limits { print("  note: \(l)") }
        print(String(format: "(%.1f s)", Date().timeIntervalSince(started)))

    case "keygen":
        // Step 1 of the key ceremony (../desktop/rules/KEY-CEREMONY.md), the
        // same file formats as the desktop's psg-sign: each holder runs this
        // on their own offline machine and sends only <id>.pub.json.
        guard args.count == 2 else { fail("keygen <key-id> <out-dir>") }
        let dir = URL(fileURLWithPath: args[1]).standardizedFileURL
        if insideSourceTree(dir) { fail("refusing to write a private release key inside the source tree; use an offline machine or removable drive") }
        let key = Curve25519.Signing.PrivateKey()
        let id = args[0]
        let priv = dir.appendingPathComponent("\(id).key.json"), pub = dir.appendingPathComponent("\(id).pub.json")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try (JSONValue.object(JSONObject([("keyId", .string(id)), ("seed", .string(key.rawRepresentation.base64EncodedString()))])).serialized(pretty: true) + "\n")
            .write(to: priv, atomically: true, encoding: .utf8)
        try (publicEntry(id, key.publicKey).serialized(pretty: true) + "\n").write(to: pub, atomically: true, encoding: .utf8)
        print("private key: \(priv.path) (keep offline; never send it)")
        print("public key:  \(pub.path) (send this to whoever builds the app)")

    case "trust":
        // Step 2: the builder makes trusted-keys.json from the holders' public files.
        guard args.count >= 3, let threshold = Int(args[0]), threshold >= 2 else { fail("trust <threshold, at least 2> <pub.json>...") }
        var entries = [JSONValue](), keys = [TrustedKey]()
        for path in args.dropFirst() {
            let v = try JSON.parse(Data(contentsOf: URL(fileURLWithPath: path)))
            guard let id = v["keyId"]?.stringValue, let b64 = v["publicKey"]?.stringValue, let der = Data(base64Encoded: b64) else {
                fail("\(path) is not a public key file (send .pub.json, never .key.json)")
            }
            keys.append(try TrustedKey.fromX509(keyId: id, x509: der))
            entries.append(.object(JSONObject([("keyId", .string(id)), ("publicKey", .string(b64))])))
        }
        _ = try TrustStore(threshold: threshold, keys: keys) // refuses duplicates and revoked keys
        print(JSONValue.object(JSONObject([("threshold", .number(String(threshold))), ("keys", .array(entries))])).serialized(pretty: true))

    case "sign":
        // Step 3: a holder adds their signature on their own machine. Signatures
        // already in <name>.sig.json are kept; this holder's own is replaced.
        guard args.count >= 2 else { fail("sign <signed-file.json> <key.json>...") }
        let fileURL = URL(fileURLWithPath: args[0])
        let payload = try Data(contentsOf: fileURL)
        try checkSignable(payload, at: fileURL)
        let out = fileURL.deletingPathExtension().appendingPathExtension("sig.json")
        var sigs = ((try? Data(contentsOf: out)).flatMap { try? BundleVerifier.parseSignatureFile($0) }) ?? []
        for keyPath in args.dropFirst() {
            let key = try JSON.parse(Data(contentsOf: URL(fileURLWithPath: keyPath)))
            guard let id = key["keyId"]?.stringValue, let seed = key["seed"]?.stringValue.flatMap({ Data(base64Encoded: $0) }) else {
                fail("\(keyPath) is not a private key file")
            }
            let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let spki = (Data(TrustedKey.spkiPrefix) + priv.publicKey.rawRepresentation).base64EncodedString()
            if TrustStore.revokedKeys.contains(spki) { fail("\(id) is a revoked development key and can never sign again") }
            sigs.removeAll { $0.keyId == id }
            sigs.append(BundleSignature(keyId: id, signature: try priv.signature(for: payload)))
        }
        let json = JSONValue.object(JSONObject([("signatures", .array(sigs.map {
            .object(JSONObject([("keyId", .string($0.keyId)), ("signature", .string($0.signature.base64EncodedString()))]))
        }))]))
        try (json.serialized(pretty: true) + "\n").write(to: out, atomically: true, encoding: .utf8)
        print("wrote \(out.path) (\(sigs.count) signature(s) so far)")
        print("sha256 \(Data(SHA256.hash(data: payload)).hexString)")

    case "log":
        // Step 4: append the released files to the public rule log (NFR-SEC-18).
        guard args.count == 2 else { fail("log <Resources dir> <rule-log.json>") }
        let dir = URL(fileURLWithPath: args[0])
        let logURL = URL(fileURLWithPath: args[1])
        var log = ((try? JSON.parse(Data(contentsOf: logURL)))?.arrayValue) ?? []
        for file in SignedFile.allCases {
            let payload = try Data(contentsOf: dir.appendingPathComponent(file.rawValue))
            let sigs = try BundleVerifier.parseSignatureFile(Data(contentsOf: dir.appendingPathComponent(file.signatureName)))
            let version = (try? JSON.parse(payload))?["version"]?.primitiveLong ?? 0
            log.append(.object(JSONObject([
                ("file", .string(file.rawValue)), ("version", .number(String(version))),
                ("sha256", .string(Data(SHA256.hash(data: payload)).hexString)),
                ("signedBy", .array(sigs.map { .string($0.keyId) })),
                ("logged", .string(String(ISO8601.format(Date()).prefix(10)))),
            ])))
        }
        try (JSONValue.array(log).serialized(pretty: true) + "\n").write(to: logURL, atomically: true, encoding: .utf8)
        print("appended \(SignedFile.allCases.count) entries to \(logURL.path)")

    case "sign-once":
        // Signing with no private key left anywhere (same idea as
        // the desktop's `psg-sign sign-once`): three keys are made in memory,
        // sign every file given, and are thrown away. Writes a new
        // trusted-keys.json next to the first file. Changing any signed file
        // later means running this again for all of them.
        guard args.count >= 1 else { fail("sign-once <file.json>...") }
        let keys = (1...3).map { _ in Curve25519.Signing.PrivateKey() }
        let stamp = ISO8601.format(Date()).prefix(10)
        let ids = (1...3).map { "once-\(stamp)-\($0)" }
        for path in args {
            let url = URL(fileURLWithPath: path)
            let payload = try Data(contentsOf: url)
            try checkSignable(payload, at: url)
            let sigs = try zip(ids, keys).map { id, key in
                JSONValue.object(JSONObject([("keyId", .string(id)), ("signature", .string(try key.signature(for: payload).base64EncodedString()))]))
            }
            let out = url.deletingPathExtension().appendingPathExtension("sig.json")
            try (JSONValue.object(JSONObject([("signatures", .array(sigs))])).serialized(pretty: true) + "\n").write(to: out, atomically: true, encoding: .utf8)
            print("wrote \(out.path)")
        }
        let trust = JSONValue.object(JSONObject([
            ("_note", .string("Single-use build keys from psg-ios-check sign-once on \(stamp): the private keys were made in memory, signed the bundled files and were destroyed, so nobody can sign anything else with them, including later updates. A store release replaces this file with the release keys from the key ceremony (desktop/rules/KEY-CEREMONY.md, psg-ios-check keygen/trust/sign); the release workflow refuses to publish while once- keys are here.")),
            ("threshold", .number("2")),
            ("keys", .array(zip(ids, keys).map { id, key in
                .object(JSONObject([("keyId", .string(id)),
                                    ("publicKey", .string((Data(TrustedKey.spkiPrefix) + key.publicKey.rawRepresentation).base64EncodedString()))]))
            })),
        ]))
        let trustURL = URL(fileURLWithPath: args[0]).deletingLastPathComponent().appendingPathComponent("trusted-keys.json")
        try (trust.serialized(pretty: true) + "\n").write(to: trustURL, atomically: true, encoding: .utf8)
        print("wrote \(trustURL.path); the private keys are gone")

    case "verify":
        guard args.count == 2 else { fail("verify <bundle.json> <trusted-keys.json>") }
        let bundleURL = URL(fileURLWithPath: args[0])
        let trust = try TrustStore(json: String(contentsOfFile: args[1], encoding: .utf8))
        let sig = try Data(contentsOf: bundleURL.deletingPathExtension().appendingPathExtension("sig.json"))
        let bundle = try BundleVerifier(trust: trust).load(payload: Data(contentsOf: bundleURL), signatureFile: sig)
        print("OK: version \(bundle.version), \(bundle.rules.count) rules, expires \(ISO8601.format(bundle.expiresAt))")

    case "verify-evidence":
        guard let path = args.first else { fail("verify-evidence <export.json> [publicKeyX509] [--checkpoint <file>]...") }
        var rest = Array(args.dropFirst())
        var checkpoints = [EvidenceHead]()
        while let i = rest.firstIndex(of: "--checkpoint"), i + 1 < rest.count {
            checkpoints.append(try EvidenceHead(text: String(contentsOfFile: rest[i + 1], encoding: .utf8)))
            rest.removeSubrange(i...(i + 1))
        }
        let text = try String(contentsOfFile: path, encoding: .utf8)
        let doc = try JSON.parse(text)
        guard let b64 = rest.first ?? doc["publicKeyX509"]?.stringValue, let der = Data(base64Encoded: b64) else {
            fail("no public key given or in the export")
        }
        let entries = try EvidenceLog.decode(text)
        let verifier = try PublicKeyEvidenceVerifier(keyId: entries.first?.keyId ?? "", publicKeyX509: der)
        var heads = checkpoints
        if let h = doc["head"] { heads.append(try EvidenceHead(json: h)) }
        switch EvidenceLog.verify(entries, heads: heads, verifySignature: { verifier.verify($0, signature: $1) }) {
        case .intact:
            print("Intact: \(entries.count) entries, every hash and signature checks out")
            if checkpoints.isEmpty {
                print("  note: no off-device checkpoint given, so deleting the newest entries cannot be ruled out (use --checkpoint)")
            } else {
                print("  \(checkpoints.count) checkpoint(s) match: nothing up to them was deleted or changed")
            }
        case .broken(let seq, let reason): fail("BROKEN at entry \(seq): \(reason)")
        }

    default:
        fail("unknown command \(command)")
    }
} catch {
    fail("error: \(error)")
}
