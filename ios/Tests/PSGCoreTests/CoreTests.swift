import Crypto
import Foundation
import XCTest
@testable import PSGCore

final class EvidenceLogTests: XCTestCase {
    func signer(_ id: String = "test-key") throws -> Ed25519EvidenceSigner {
        try Ed25519EvidenceSigner(keyId: id, seed: Data(repeating: 7, count: 32))
    }

    func testAppendChainsAndVerifies() throws {
        var t: Int64 = 1_000
        let log = EvidenceLog(signer: try signer(), clock: { t += 1; return t })
        try log.append(.finding, "Passcode is not set", details: ["subject": "device:iphone", "rules": "PSG-IOS-DEV-001"])
        try log.append(.answer, "Owner answered: I did this", details: ["answer": "i_did_this"])
        try log.append(.note, "multi\nline; with = signs\\")
        XCTAssertEqual(log.entries.map(\.seq), [0, 1, 2])
        XCTAssertEqual(log.entries[0].prevHash, genesisHash)
        XCTAssertEqual(log.entries[1].prevHash, log.entries[0].entryHash)
        XCTAssertEqual(log.verify(), .intact)
    }

    func testExportRoundTripsAndStillVerifies() throws {
        let log = EvidenceLog(signer: try signer())
        try log.append(.finding, "Ünïcødé “quoted” \u{1}", details: ["k=1": "v;2", "emoji😀": "z"])
        let text = log.exportJSON()
        let back = try EvidenceLog.decode(text)
        XCTAssertEqual(back, log.entries)
        XCTAssertEqual(EvidenceLog.verify(back, signer: try signer()), .intact)
    }

    func testSignedHeadDetectsDeletingTheNewestEntries() throws {
        var t: Int64 = 5_000
        let log = EvidenceLog(signer: try signer(), clock: { t += 1; return t })
        for i in 0..<4 { try log.append(.finding, "finding \(i)") }
        let head = try log.signHead()
        XCTAssertEqual(head.count, 4)
        XCTAssertEqual(log.verify(heads: [head]), .intact)

        // Without the head, a truncated timeline still reads as intact...
        let truncated = Array(log.entries.prefix(2))
        let s = try signer()
        XCTAssertEqual(EvidenceLog.verify(truncated, signer: s), .intact)
        // ...with it, the deletion is caught.
        guard case .broken(2, let why) = EvidenceLog.verify(truncated, heads: [head], verifySignature: { s.verify($0, signature: $1) }) else {
            return XCTFail("truncation not detected")
        }
        XCTAssertTrue(why.contains("newest entries were deleted"), why)

        // Appending more is fine; replacing entries after the head is not.
        try log.append(.note, "later")
        XCTAssertEqual(log.verify(heads: [head]), .intact)
        let other = EvidenceLog(signer: s, clock: { 9_999 }, initial: Array(log.entries.prefix(3)))
        try other.append(.note, "a different fourth entry")
        guard case .broken = other.verify(heads: [head]) else { return XCTFail("rewritten entry not detected") }

        // A forged head (different count, same signature) fails.
        let forged = EvidenceHead(count: 1, lastHash: log.entries[0].entryHash, timestampMillis: head.timestampMillis,
                                  keyId: head.keyId, signature: head.signature)
        guard case .broken = log.verify(heads: [forged]) else { return XCTFail("forged head accepted") }
    }

    func testCheckpointTravelsAsPlainText() throws {
        let log = EvidenceLog(signer: try signer(), clock: { 1_700_000_000_000 })
        try log.append(.note, "one")
        let head = try log.signHead()
        let text = head.checkpointText
        XCTAssertTrue(text.contains("had 1 entries") || text.contains("1 entries"))
        XCTAssertEqual(try EvidenceHead(text: "Fwd: \n> " + text + "\n-- sent from my phone"), head)
        XCTAssertEqual(try EvidenceHead(json: JSON.parse(head.json.serialized(pretty: true))), head)
        // The desktop's checkpoint text and JSON names read the same head.
        let desktopText = "> pc-key: \(head.keyId)\n> public-key: AAAA\n> entries: \(head.count)\n> last-hash: \(head.lastHash)\n> time-utc: x\n> signed-millis: \(head.timestampMillis)\n> signature: \(head.signature)"
        XCTAssertEqual(try EvidenceHead(text: desktopText), head)
        let desktopJSON = #"{"count":\#(head.count),"lastHash":"\#(head.lastHash)","signedMillis":\#(head.timestampMillis),"keyId":"\#(head.keyId)","signature":"\#(head.signature)"}"#
        XCTAssertEqual(try EvidenceHead(json: JSON.parse(desktopJSON)), head)
    }

    func testReorderAndWrongKeyAreDetected() throws {
        let log = EvidenceLog(signer: try signer())
        for i in 0..<3 { try log.append(.change, "change \(i)") }
        var swapped = log.entries
        swapped.swapAt(1, 2)
        XCTAssertEqual(EvidenceLog.verify(swapped, signer: try signer()), .broken(atSeq: 2, reason: "Sequence number out of order"))

        let other = try Ed25519EvidenceSigner(keyId: "other", seed: Data(repeating: 9, count: 32))
        XCTAssertEqual(EvidenceLog.verify(log.entries, signer: other), .broken(atSeq: 0, reason: "Signature does not verify"))
    }

    /// The phone apps sign with ECDSA P-256 (Android Keystore, Secure
    /// Enclave). An iPhone export must verify from its public key alone.
    func testP256SignedTimelineVerifiesFromPublicKey() throws {
        struct P256Signer: EvidenceSigner {
            let keyId = "secure-enclave"
            let key = P256.Signing.PrivateKey()
            func sign(_ data: Data) throws -> Data { try key.signature(for: data).derRepresentation }
            func verify(_ data: Data, signature: Data) -> Bool { false }
        }
        let s = P256Signer()
        let log = EvidenceLog(signer: s)
        try log.append(.finding, "one")
        try log.append(.answer, "two")
        let verifier = try PublicKeyEvidenceVerifier(keyId: s.keyId, publicKeyX509: s.key.publicKey.derRepresentation)
        XCTAssertEqual(EvidenceLog.verify(try EvidenceLog.decode(log.exportJSON()), signer: verifier), .intact)
    }
}

final class BundleTests: XCTestCase {
    func testVerifierNeedsTwoOfThreeAndRefusesRollbackAndExpiry() throws {
        let keys = try (1...3).map { try Ed25519EvidenceSigner(keyId: "k\($0)", seed: Data(repeating: UInt8($0), count: 32)) }
        let trusted = try keys.map { try TrustedKey.fromX509(keyId: $0.keyId, x509: $0.publicKeyX509) }
        let payload = Data(#"{"version":5,"expires":"2030-01-01T00:00:00Z","rules":[]}"#.utf8)
        let sigs = try keys.map { BundleSignature(keyId: $0.keyId, signature: try $0.sign(payload)) }
        let now = ISO8601.parseInstant("2026-10-22T00:00:00Z")!
        let v = BundleVerifier(trustedKeys: trusted, clock: { now })

        XCTAssertEqual(v.verify(payload: payload, signatures: Array(sigs.prefix(2)), installedVersion: 5), .accepted)
        XCTAssertEqual(v.verify(payload: payload, signatures: [sigs[0], sigs[0]], installedVersion: 0), .rejected("Needs 2 valid signatures, found 1"))
        XCTAssertEqual(v.verify(payload: payload, signatures: sigs, installedVersion: 6), .rejected("Bundle version 5 is older than installed 6"))
        let late = BundleVerifier(trustedKeys: trusted, clock: { ISO8601.parseInstant("2031-01-01T00:00:00Z")! })
        guard case .rejected = late.verify(payload: payload, signatures: sigs, installedVersion: 0) else { return XCTFail("expired accepted") }
    }

    func testOneKeyUnderTwoIdsCannotMakeTwoOfThree() throws {
        let k = try Ed25519EvidenceSigner(keyId: "a", seed: Data(repeating: 7, count: 32))
        let other = try Ed25519EvidenceSigner(keyId: "c", seed: Data(repeating: 8, count: 32))
        let a = try TrustedKey.fromX509(keyId: "a", x509: k.publicKeyX509)
        let b = try TrustedKey.fromX509(keyId: "b", x509: k.publicKeyX509)
        let c = try TrustedKey.fromX509(keyId: "c", x509: other.publicKeyX509)
        // The trust file is refused outright...
        XCTAssertThrowsError(try TrustStore(threshold: 2, keys: [a, b, c]))
        XCTAssertThrowsError(try TrustStore(threshold: 2, keys: [a, a]))
        // ...and the verifier counts keys, not ids, if handed one anyway.
        let payload = Data(#"{"version":1,"expires":"2030-01-01T00:00:00Z","rules":[]}"#.utf8)
        let sig = try k.sign(payload)
        let v = BundleVerifier(trustedKeys: [a, b, c], clock: { ISO8601.parseInstant("2026-10-22T00:00:00Z")! })
        XCTAssertEqual(v.verify(payload: payload, signatures: [BundleSignature(keyId: "a", signature: sig), BundleSignature(keyId: "b", signature: sig)],
                                installedVersion: 0), .rejected("Needs 2 valid signatures, found 1"))
    }

    func testRevokedDevelopmentKeysAreRefused() throws {
        let json = #"{"threshold":2,"keys":[{"keyId":"a","publicKey":"\#(TrustStore.revokedKeys[0])"},{"keyId":"b","publicKey":"\#(TrustStore.revokedKeys[1])"}]}"#
        XCTAssertThrowsError(try TrustStore(json: json)) { XCTAssertTrue("\($0)".contains("revoked"), "\($0)") }
    }

    func testDevelopmentKeysAreDroppedForReleaseBuilds() throws {
        let keys = try (1...3).map { try Ed25519EvidenceSigner(keyId: "k\($0)", seed: Data(repeating: UInt8($0 + 20), count: 32)) }
        let json = """
        {"threshold":2,"keys":[
          {"keyId":"k1","publicKey":"\(keys[0].publicKeyX509.base64EncodedString())","development":true},
          {"keyId":"k2","publicKey":"\(keys[1].publicKeyX509.base64EncodedString())","development":true},
          {"keyId":"k3","publicKey":"\(keys[2].publicKeyX509.base64EncodedString())"}]}
        """
        let trust = try TrustStore(json: json)
        XCTAssertTrue(trust.hasDevelopmentKeys)
        let release = trust.excludingDevelopmentKeys()
        XCTAssertEqual(release.keys.map(\.keyId), ["k3"])
        let payload = Data(#"{"version":1,"expires":"2030-01-01T00:00:00Z","rules":[]}"#.utf8)
        let sigs = try keys.prefix(2).map { BundleSignature(keyId: $0.keyId, signature: try $0.sign(payload)) }
        let now = { ISO8601.parseInstant("2026-10-22T00:00:00Z")! }
        XCTAssertEqual(BundleVerifier(trust: trust, clock: now).verify(payload: payload, signatures: sigs, installedVersion: 0), .accepted)
        XCTAssertEqual(BundleVerifier(trust: release, clock: now).verify(payload: payload, signatures: sigs, installedVersion: 0),
                       .rejected("Needs 2 valid signatures, found 0"))
    }

    func testTimeBudgetSkipsRatherThanHangs() throws {
        let bundle = try RuleBundleParser().parse(#"{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[{"id":"R","severity":"low","contribution":"risk","when":{"fact":"a","exists":true}}]}"#)
        var t: Int64 = 0
        var limits = EvaluationLimits()
        limits.maxEvaluationMillis = 0
        // A clock that jumps forward on every read exceeds any budget.
        let interp = BoundedInterpreter(limits: limits, clock: { t += 10; return t })
        XCTAssertThrowsError(try interp.matches(bundle.rules[0].condition, Facts(["a": .bool(true)])))
    }

    func testExactStringEqualityLikeKotlin() throws {
        // "é" precomposed vs "e" + combining acute: Swift == says equal, Kotlin does not.
        let bundle = try RuleBundleParser().parse(#"{"version":1,"expires":"2099-01-01T00:00:00Z","rules":[{"id":"R","severity":"low","contribution":"risk","when":{"fact":"a","eq":"é"}}]}"#)
        let e = DetectionEngine(bundle: bundle)
        XCTAssertFalse(e.evaluate(subject: "s", facts: Facts(["a": .text("e\u{301}")])).verdict.signals.count > 0)
        XCTAssertTrue(e.evaluate(subject: "s", facts: Facts(["a": .text("\u{e9}")])).verdict.signals.count > 0)
    }

    func testISO8601Instants() {
        XCTAssertEqual(ISO8601.parseInstant("1970-01-01T00:00:00Z")?.timeIntervalSince1970, 0)
        XCTAssertEqual(ISO8601.parseInstant("2027-01-01T01:00:00+01:00"), ISO8601.parseInstant("2027-01-01T00:00:00Z"))
        XCTAssertNil(ISO8601.parseInstant("next year"))
        XCTAssertNil(ISO8601.parseInstant("2027-02-30T00:00:00Z"))
    }
}
