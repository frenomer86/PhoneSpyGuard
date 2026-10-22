import Crypto
import Foundation
import XCTest
@testable import PSGCompanion
@testable import PSGCore

/// Signed rule updates (FR-RUL-02), checked
/// against keys made for the test so new versions can be signed.
final class RuleUpdateTests: XCTestCase {
    let now = ISO8601.parseInstant("2026-10-22T00:00:00Z")!
    var keys: [Curve25519.Signing.PrivateKey]!
    var trust: TrustStore!
    /// The app's own files, re-signed with the test keys.
    var builtIn: [String: Data]!
    var dir: URL!
    /// The built-in rules' version; updates in these tests are numbered from it.
    var base: Int { try! RuleBundleParser().parse(String(decoding: builtIn["ios-bundle.json"]!, as: UTF8.self)).version }

    override func setUpWithError() throws {
        keys = (0..<3).map { _ in Curve25519.Signing.PrivateKey() }
        trust = try TrustStore(threshold: 2, keys: keys.enumerated().map { TrustedKey(keyId: "t\($0.offset)", publicKey: $0.element.publicKey) })
        builtIn = [:]
        for file in SignedFile.allCases {
            let payload = try CompanionResources.data(file.rawValue)
            builtIn[file.rawValue] = payload
            builtIn[file.signatureName] = try sign(payload, with: [0, 1])
        }
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("psg-updates-\(UUID().uuidString)")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func sign(_ payload: Data, with signers: [Int]) throws -> Data {
        let sigs = try signers.map { i in
            JSONValue.object(JSONObject([("keyId", .string("t\(i)")), ("signature", .string(try keys[i].signature(for: payload).base64EncodedString()))]))
        }
        return Data(JSONValue.object(JSONObject([("signatures", .array(sigs))])).serialized(pretty: false).utf8)
    }

    /// The built-in file with its first `"version": N` raised to `version`.
    func bumped(_ file: SignedFile, to version: Int, expires: String? = nil) throws -> Data {
        var text = String(decoding: builtIn[file.rawValue]!, as: UTF8.self)
        let range = text.range(of: #""version": \d+"#, options: .regularExpression)!
        text.replaceSubrange(range, with: "\"version\": \(version)")
        if let expires { text = text.replacingOccurrences(of: "2027-04-01T00:00:00Z", with: expires) }
        return Data(text.utf8)
    }

    func load(_ updates: URL? = nil, at when: Date? = nil) throws -> CompanionRules {
        try CompanionRules.load(now: when ?? now, updates: updates, trust: trust, builtIn: { [builtIn] name in
            guard let d = builtIn?[name] else { throw ArchiveError("missing \(name)") }
            return d
        })
    }

    func updater(serving files: [String: Data], requested: Locked<[String]>? = nil) -> RuleUpdater {
        RuleUpdater(baseURL: URL(string: "https://rules.example/ios/")!, directory: dir, trust: trust,
                    builtIn: { [builtIn] name in
                        guard let d = builtIn?[name] else { throw ArchiveError("missing \(name)") }
                        return d
                    },
                    fetch: { url in
                        requested?.mutate { $0.append(url.lastPathComponent) }
                        guard let d = files[url.lastPathComponent] else { throw URLError(.fileDoesNotExist) }
                        return d
                    })
    }

    /// Everything the server would publish: the built-in files, with
    /// `overrides` replacing some.
    func server(_ overrides: [String: Data] = [:]) -> [String: Data] {
        builtIn.filter { $0.key != "trusted-keys.json" }.merging(overrides) { _, new in new }
    }

    func testBuiltInFilesLoadWithProvenance() throws {
        let rules = try load()
        XCTAssertEqual(rules.provenance.map(\.file), [.rules, .indicators])
        XCTAssertTrue(rules.provenance.allSatisfy { !$0.downloaded && $0.sha256.count == 64 })
        XCTAssertEqual(rules.provenance[0].sha256, Data(SHA256.hash(data: builtIn["ios-bundle.json"]!)).hexString)
    }

    func testAlteredBuiltInRulesStopTheApp() throws {
        builtIn["ios-bundle.json"]!.append(contentsOf: Array(" ".utf8))
        XCTAssertThrowsError(try load())
        try setUpWithError()
        builtIn["ios-indicators.sig.json"] = try sign(builtIn["ios-indicators.json"]!, with: [0])
        XCTAssertThrowsError(try load(), "one signature is not enough")
    }

    func testNewerSignedRulesAreDownloadedAndUsed() async throws {
        let v4 = try bumped(.rules, to: base + 1)
        let requested = Locked<[String]>([])
        let outcome = await updater(serving: server(["ios-bundle.json": v4, "ios-bundle.sig.json": try sign(v4, with: [1, 2])]),
                                    requested: requested).run(now: now)
        XCTAssertEqual(outcome, .updated([.rules]))
        XCTAssertEqual(Set(requested.value), Set(SignedFile.allCases.flatMap(\.allNames)))
        let rules = try load(dir)
        XCTAssertEqual(rules.bundle.version, base + 1)
        XCTAssertTrue(rules.provenance[0].downloaded)
        XCTAssertFalse(rules.provenance[1].downloaded)
        // Nothing left behind but the files themselves.
        let left = try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
        XCTAssertEqual(left, ["ios-bundle.json", "ios-bundle.sig.json"])

        // Asking again changes nothing.
        let again = await updater(serving: server(["ios-bundle.json": v4, "ios-bundle.sig.json": try sign(v4, with: [1, 2])])).run(now: now)
        XCTAssertEqual(again, .alreadyCurrent)
    }

    func testTamperedOrUnderSignedUpdatesChangeNothing() async throws {
        let v4 = try bumped(.rules, to: base + 1)
        var tampered = v4
        tampered.append(contentsOf: Array(" ".utf8))
        let bad = await updater(serving: server(["ios-bundle.json": tampered, "ios-bundle.sig.json": try sign(v4, with: [0, 1])])).run(now: now)
        XCTAssertEqual(bad, .alreadyCurrent)
        let one = await updater(serving: server(["ios-bundle.json": v4, "ios-bundle.sig.json": try sign(v4, with: [2])])).run(now: now)
        XCTAssertEqual(one, .alreadyCurrent)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.appendingPathComponent("ios-bundle.json").path))
        XCTAssertEqual(try load(dir).bundle.version, base)
    }

    func testRollbackIsRefused() async throws {
        let v5 = try bumped(.rules, to: base + 2)
        let v4 = try bumped(.rules, to: base + 1)
        _ = await updater(serving: server(["ios-bundle.json": v5, "ios-bundle.sig.json": try sign(v5, with: [0, 1])])).run(now: now)
        XCTAssertEqual(try load(dir).bundle.version, base + 2)
        // A correctly signed but older file (an attacker replaying an earlier update) is not taken.
        let old = await updater(serving: server(["ios-bundle.json": v4, "ios-bundle.sig.json": try sign(v4, with: [0, 1])])).run(now: now)
        XCTAssertEqual(old, .alreadyCurrent)
        XCTAssertEqual(try load(dir).bundle.version, base + 2)
        // An update folder planted with an older file than the app's own is ignored.
        let v2 = try bumped(.rules, to: base - 1)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try v2.write(to: dir.appendingPathComponent("ios-bundle.json"))
        try sign(v2, with: [0, 1]).write(to: dir.appendingPathComponent("ios-bundle.sig.json"))
        XCTAssertEqual(try load(dir).bundle.version, base)
    }

    func testAnUpdateKeepsTheAppWorkingAfterTheBuiltInRulesExpire() async throws {
        let later = ISO8601.parseInstant("2027-05-01T00:00:00Z")!
        XCTAssertThrowsError(try load(at: later), "expired rules are not used")
        let v4 = try bumped(.rules, to: base + 1, expires: "2027-10-01T00:00:00Z")
        let outcome = await updater(serving: server(["ios-bundle.json": v4, "ios-bundle.sig.json": try sign(v4, with: [0, 2])])).run(now: later)
        XCTAssertEqual(outcome, .updated([.rules]))
        XCTAssertEqual(try load(dir, at: later).bundle.version, base + 1)
    }

    func testFailedDownloadOrPlainHTTPChangesNothing() async throws {
        var files = server()
        files.removeValue(forKey: "ios-indicators.sig.json")
        let missing = await updater(serving: files).run(now: now)
        guard case .failed = missing else { return XCTFail("expected failure, got \(missing)") }
        let plain = RuleUpdater(baseURL: URL(string: "http://rules.example/")!, directory: dir, trust: trust, fetch: { _ in Data() })
        guard case .failed(let why) = await plain.run(now: now) else { return XCTFail("plain HTTP must fail") }
        XCTAssertTrue(why.contains("HTTPS"))
        let left = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        XCTAssertEqual(left, [], "a failed download leaves nothing behind")
    }

}

/// A value shared with an `@Sendable` closure in tests.
final class Locked<T>: @unchecked Sendable {
    private var stored: T
    private let lock = NSLock()
    init(_ value: T) { stored = value }
    var value: T { lock.lock(); defer { lock.unlock() }; return stored }
    func mutate(_ f: (inout T) -> Void) { lock.lock(); defer { lock.unlock() }; f(&stored) }
}
