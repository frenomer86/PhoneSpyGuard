import Crypto
import Foundation
import XCTest
@testable import PSGCore

/// Runs the shared fixtures in `desktop/conformance/`, the same files the
/// Kotlin core and the Rust desktop core run, so all three engines must agree
/// on parsing, operators, verdicts and evidence hashes.
final class ConformanceTests: XCTestCase {
    static var dir: URL {
        if let env = ProcessInfo.processInfo.environment["PSG_CONFORMANCE_DIR"] {
            return URL(fileURLWithPath: env)
        }
        // ios/Tests/PSGCoreTests/this-file -> phone-spy-guard/desktop/conformance
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("desktop/conformance")
    }

    func read(_ name: String) throws -> String {
        let url = Self.dir.appendingPathComponent(name)
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            XCTFail("Missing shared fixture \(url.path). Keep ios/ next to desktop/ or set PSG_CONFORMANCE_DIR.")
            throw JSONError(description: "missing fixture")
        }
        return text
    }

    /// Same fact typing as the Kotlin and Rust conformance tests.
    func facts(_ v: JSONValue?) -> Facts {
        var f = Facts()
        for (k, value) in v?.objectValue?.entries ?? [] {
            switch value {
            case .array(let a): f.textList(k, a.compactMap(\.stringValue))
            case .string(let s): f.text(k, s)
            case .bool(let b): f.bool(k, b)
            case .number: f.number(k, value.primitiveLong!)
            default: XCTFail("unsupported fact \(k)")
            }
        }
        return f
    }

    func testEngineCasesMatchTheSharedVerdicts() throws {
        let doc = try JSON.parse(try read("engine-cases.json"))
        let bundle = try RuleBundleParser().parse(try read(doc["bundle"]!.stringValue!))
        let engine = DetectionEngine(bundle: bundle)
        let cases = doc["cases"]!.arrayValue!
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let name = c["name"]!.stringValue!
            let ev = engine.evaluate(subject: name, facts: facts(c["facts"]))
            XCTAssertEqual(ev.verdict.confidence.rawValue, c["confidence"]!.stringValue!, name)
            XCTAssertEqual(ev.verdict.signals.map(\.ruleId), c["matched"]!.arrayValue!.map { $0.stringValue! }, name)
            XCTAssertTrue(ev.skippedRuleIds.isEmpty, name)
        }
    }

    func testOperatorCasesMatch() throws {
        let doc = try JSON.parse(try read("operator-cases.json"))
        for (i, c) in doc["cases"]!.arrayValue!.enumerated() {
            let bundle = ruleBundle(c["when"]!.serialized())
            let engine = DetectionEngine(bundle: try RuleBundleParser().parse(bundle))
            let matched = !engine.evaluate(subject: "s", facts: facts(c["facts"])).verdict.signals.isEmpty
            XCTAssertEqual(matched, c["matches"]!.boolValue!, "operator case #\(i): \(c.serialized())")
        }
    }

    func ruleBundle(_ when: String) -> String {
        #"{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[{"id":"R","severity":"low","contribution":"risk","when":\#(when)}]}"#
    }

    func testParseCasesAcceptAndRejectAlike() throws {
        let doc = try JSON.parse(try read("parse-cases.json"))
        for c in doc["cases"]!.arrayValue! {
            let text: String
            if let b = c["bundle"]?.stringValue {
                text = b
            } else if let n = c["nested"]?.primitiveLong {
                var w = #"{"fact":"a","exists":true}"#
                for _ in 0..<n { w = #"{"not":\#(w)}"# }
                text = ruleBundle(w)
            } else {
                let n = c["wide"]!.primitiveLong!
                text = ruleBundle(#"{"all":[\#((0..<n).map { #"{"fact":"f\#($0)","exists":true}"# }.joined(separator: ","))]}"#)
            }
            let ok = (try? RuleBundleParser().parse(text)) != nil
            XCTAssertEqual(ok, c["accept"]!.boolValue!, c["name"]!.stringValue!)
        }
    }

    func testPhoneLaunchBundleParsesToTheExpectedShape() throws {
        let bundle = try RuleBundleParser().parse(try read("phone-launch-bundle.json"))
        XCTAssertEqual(bundle.version, 1)
        XCTAssertEqual(bundle.rules.count, 7)
        guard case .all(let of) = bundle.rule(id: "PSG-BEH-014")!.condition else { return XCTFail("not all") }
        XCTAssertEqual(of.count, 3)
        XCTAssertFalse(bundle.rule(id: "PSG-INNOCENT-001")!.log)
    }

    func testEvidenceVectorsHashIdentically() throws {
        let doc = try JSON.parse(try read("evidence-vectors.json"))
        for v in doc["vectors"]!.arrayValue! {
            var details = [String: String]()
            for (k, val) in v["details"]!.objectValue!.entries { details[k] = val.stringValue! }
            let bytes = EvidenceLog.canonicalContent(
                seq: v["seq"]!.primitiveLong!, timestampMillis: v["timestampMillis"]!.primitiveLong!,
                type: EntryType(rawValue: v["type"]!.stringValue!)!, summary: v["summary"]!.stringValue!,
                details: details, prevHash: v["prevHash"]!.stringValue!)
            XCTAssertEqual(Data(SHA256.hash(data: bytes)).hexString, v["entryHash"]!.stringValue!, "vector seq \(v["seq"]!.primitiveLong!)")
        }
    }

    func testDesktopWrittenTimelineVerifiesAndDetectsTamper() throws {
        let text = try read("evidence-sample-export.json")
        let doc = try JSON.parse(text)
        let verifier = try PublicKeyEvidenceVerifier(keyId: doc["keyId"]!.stringValue!,
                                                     publicKeyX509: Data(base64Encoded: doc["publicKeyX509"]!.stringValue!)!)
        let entries = try EvidenceLog.decode(text)
        XCTAssertEqual(entries.count, 4)
        XCTAssertEqual(EvidenceLog.verify(entries, signer: verifier), .intact)

        var tampered = entries
        tampered[1] = tampered[1].with(summary: tampered[1].summary + "!")
        XCTAssertEqual(EvidenceLog.verify(tampered, signer: verifier), .broken(atSeq: 1, reason: "Entry hash does not match its content"))

        var dropped = entries
        dropped.remove(at: 2)
        guard case .broken = EvidenceLog.verify(dropped, signer: verifier) else { return XCTFail("deletion not detected") }
    }

    func testDesktopSignedBundleVerifiesWithTheSharedTrustFile() throws {
        let rules = Self.dir.deletingLastPathComponent().appendingPathComponent("rules")
        guard let payload = try? Data(contentsOf: rules.appendingPathComponent("desktop-bundle.json")) else {
            throw XCTSkip("desktop/rules not present")
        }
        let sig = try Data(contentsOf: rules.appendingPathComponent("desktop-bundle.sig.json"))
        let trustText = try String(contentsOf: rules.appendingPathComponent("trusted-keys.json"), encoding: .utf8)
        if TrustStore.revokedKeys.contains(where: trustText.contains) {
            throw XCTSkip("desktop/rules/trusted-keys.json still lists the revoked development keys; re-run once the desktop bundle is re-signed")
        }
        let trust = try TrustStore(json: trustText)
        let verifier = BundleVerifier(trust: trust, clock: { ISO8601.parseInstant("2026-10-22T00:00:00Z")! })
        let bundle = try verifier.load(payload: payload, signatureFile: sig)
        XCTAssertFalse(bundle.rules.isEmpty)

        var flipped = payload
        flipped[flipped.count / 2] ^= 0x01
        XCTAssertThrowsError(try verifier.load(payload: flipped, signatureFile: sig))
    }
}
