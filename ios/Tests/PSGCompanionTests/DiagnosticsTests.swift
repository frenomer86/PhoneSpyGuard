import Crypto
import Foundation
import XCTest
@testable import PSGCompanion
@testable import PSGCore

func fixture(_ name: String) -> URL {
    let ext = (name as NSString).pathExtension
    return Bundle.module.url(forResource: (name as NSString).deletingPathExtension, withExtension: ext, subdirectory: "Fixtures")!
}

final class InflateTests: XCTestCase {
    func drain(_ s: ByteStream) throws -> Data {
        var out = Data()
        while true {
            let c = try s.read(max: 50_000)
            if c.isEmpty { return out }
            out.append(contentsOf: c)
        }
    }

    func testEveryBlockTypeInflatesExactly() throws {
        let expected = try JSON.parse(Data(contentsOf: fixture("deflate-expected.json")))
        for name in ["stored", "fixed", "dynamic", "fast"] {
            // Small chunks make block and bit boundaries fall across reads.
            let source = DataByteSource(try Data(contentsOf: fixture("deflate-\(name).gz")), chunkSize: 997)
            let data = try drain(try ArchiveStreams.open(source))
            XCTAssertEqual(data.count, Int(expected["size"]!.primitiveLong!), name)
            XCTAssertEqual(Data(SHA256.hash(data: data)).hexString, expected["sha256"]!.stringValue!, name)
        }
    }

    func testMultiMemberGzip() throws {
        let expected = try JSON.parse(Data(contentsOf: fixture("deflate-expected.json")))
        let data = try drain(try ArchiveStreams.open(FileByteSource(url: fixture("deflate-multimember.gz"))))
        XCTAssertEqual(Data(SHA256.hash(data: data)).hexString, expected["multimemberSha256"]!.stringValue!)
    }

    func testCorruptionIsCaught() throws {
        var bytes = try Data(contentsOf: fixture("deflate-dynamic.gz"))
        bytes[bytes.count / 2] ^= 0x10
        XCTAssertThrowsError(try drain(try ArchiveStreams.open(DataByteSource(bytes))))

        let truncated = try Data(contentsOf: fixture("deflate-fixed.gz")).prefix(5_000)
        XCTAssertThrowsError(try drain(try ArchiveStreams.open(DataByteSource(Data(truncated)))))
    }
}

final class DiagnosticsTests: XCTestCase {
    var rules: CompanionRules!

    override func setUpWithError() throws {
        rules = try CompanionRules.bundled(now: ISO8601.parseInstant("2026-10-22T00:00:00Z")!, allowDevelopmentKeys: true)
    }

    func testShutdownLogParsing() throws {
        let log = ShutdownLog(text: """
        After 2.01s, these clients are still here:
        \t\tremaining client pid: 1 (/usr/libexec/a)
        \t\tremaining client pid: 2 (/private/var/tmp/x y)
        SIGTERM: [1700000000] (MAKESHUTDOWNLOG)
        \t\tremaining client pid: 3 (/usr/libexec/a)
        SIGTERM: [1700000100]
        \t\tremaining client pid: 4 (/late/one)
        """)
        XCTAssertEqual(log.reboots.count, 3)
        XCTAssertEqual(log.reboots[0].processes, ["/usr/libexec/a", "/private/var/tmp/x y"])
        XCTAssertNil(log.reboots[2].time)
        let a = log.processes.first { $0.path == "/usr/libexec/a" }!
        XCTAssertEqual(a.delayCount, 2)
        XCTAssertEqual(a.firstSeen, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(a.lastSeen, Date(timeIntervalSince1970: 1_700_000_100))
    }

    func testInfectedArchiveIsFlaggedFromTheShutdownLogAndCrashReports() throws {
        let report = try DiagnosticAnalyzer(rules: rules).analyze(url: fixture("sysdiagnose-infected.tar.gz"))
        XCTAssertTrue(report.shutdownLogFound)
        XCTAssertEqual(report.rebootsSeen, 3)
        XCTAssertEqual(report.crashReportsSeen, 2)
        XCTAssertEqual(report.rating, .actNow)

        func card(_ name: String) -> Finding? { report.findings.first { $0.displayName == name } }
        // Published Pegasus path and process name: Confirmed.
        XCTAssertEqual(card("bh")?.verdict.confidence, .confirmed)
        XCTAssertEqual(card("bh")?.details["delayed_restarts"], "2")
        // Sticky process in /private/var/tmp: Very likely (Kaspersky's heuristic).
        XCTAssertEqual(card("netwatchd")?.verdict.confidence, .veryLikely)
        // Unknown location, no indicator: Possible, for an expert.
        XCTAssertEqual(card("helper")?.verdict.confidence, .possible)
        // A crash report named after a Pegasus process.
        XCTAssertEqual(card("msgacntd")?.verdict.confidence, .confirmed)
        XCTAssertEqual(card("msgacntd")?.details["source"], "crash report")
        // iOS and App Store processes stay clear.
        XCTAssertEqual(card("backboardd")?.rating, .clear)
        XCTAssertEqual(card("Signal")?.rating, .clear)
        XCTAssertNil(card("MobileSafari"))
    }

    func testRunningProcessesFromPsTxt() throws {
        let report = try DiagnosticAnalyzer(rules: rules).analyze(url: fixture("sysdiagnose-infected.tar.gz"))
        func card(_ name: String) -> Finding? { report.findings.first { $0.displayName == name } }
        XCTAssertEqual(report.runningProcessesSeen, 6)
        // Running from a staging folder, seen only in ps.txt: Very likely.
        XCTAssertEqual(card("ckmd")?.verdict.confidence, .veryLikely)
        XCTAssertEqual(card("ckmd")?.details["source"], "ps.txt")
        XCTAssertTrue(card("ckmd")!.concerningRules.map(\.id).contains("PSG-IOS-PS-001"))
        // Also in the shutdown log: one card, marked as still running.
        XCTAssertEqual(report.findings.filter { $0.displayName == "bh" }.count, 1)
        XCTAssertEqual(card("bh")?.details["running_when_captured"], "yes")
        // iOS and App Store programs, including an app name with a space.
        XCTAssertEqual(card("SpringBoard")?.rating, .clear)
        XCTAssertEqual(card("My Notes")?.rating, .clear)
        XCTAssertEqual(card("My Notes")?.details["path"], "/private/var/containers/Bundle/Application/9F8E7D6C-0000-1111-2222-333344445555/My Notes.app/My Notes")
        XCTAssertNil(card("kernel_task"))
    }

    func testProcessListParsing() {
        let ps = """
        USER   PID COMMAND
        root     1 /sbin/launchd
        mobile  44 /private/var/tmp/x -flag value
        mobile  45 /var/containers/Bundle/Application/A/Two Words.app/Two Words --arg
        root     0 kernel_task
        root     1 /sbin/launchd
        """
        XCTAssertEqual(DiagnosticAnalyzer.processPaths(psText: ps),
                       ["/sbin/launchd", "/private/var/tmp/x", "/var/containers/Bundle/Application/A/Two Words.app/Two Words"])
        XCTAssertEqual(DiagnosticAnalyzer.processPaths(psText: "no header here\n/sbin/launchd"), [])
    }

    func testCleanArchiveIsNeverCalledSafe() throws {
        let report = try DiagnosticAnalyzer(rules: rules).analyze(url: fixture("sysdiagnose-clean.tar.gz"))
        XCTAssertTrue(report.shutdownLogFound)
        XCTAssertEqual(report.rating, .clear)
        XCTAssertTrue(report.cards.isEmpty)
        XCTAssertEqual(report.rating.label, "Nothing found by these checks")
        XCTAssertTrue(report.limits.contains { $0.contains("never proof") })
        XCTAssertFalse(report.rating.label.lowercased().contains("safe"))
    }

    func testBareShutdownLogAndSTIXIndicators() throws {
        let stix = try IndicatorSet.fromSTIX2(String(contentsOf: fixture("test-indicators.stix2"), encoding: .utf8))
        XCTAssertEqual(stix.processNames, ["helper", "it'sd"])
        XCTAssertEqual(stix.fileNames, ["payload.dylib"])
        XCTAssertEqual(stix.domains, ["evil-cdn.example", "track.badlink.example"])
        XCTAssertTrue(stix.source.contains("TestSpy"))

        let report = try DiagnosticAnalyzer(rules: rules, extraIndicators: stix).analyze(url: fixture("shutdown.log"))
        // With the shared STIX file, "helper" now matches an indicator.
        XCTAssertEqual(report.findings.first { $0.displayName == "helper" }?.verdict.confidence, .confirmed)
        XCTAssertEqual(report.rebootsSeen, 1)
        XCTAssertTrue(report.limits.first!.contains("fewer than two restarts"))
    }

    func testRejectsFilesThatAreNotDiagnostics() throws {
        XCTAssertThrowsError(try DiagnosticAnalyzer(rules: rules).analyze(source: DataByteSource(Data("hello world".utf8))))
    }

    func testFindingsGoIntoTheEvidenceTimeline() throws {
        let report = try DiagnosticAnalyzer(rules: rules).analyze(url: fixture("sysdiagnose-infected.tar.gz"))
        let signer = try Ed25519EvidenceSigner(keyId: "k", seed: Data(repeating: 3, count: 32))
        let log = EvidenceLog(signer: signer)
        let written = try EvidenceRecorder(log: log).record(report.asSection)
        XCTAssertEqual(written.count, 5) // bh, msgacntd, netwatchd, ckmd, helper
        XCTAssertEqual(written.first?.details["confidence"], "CONFIRMED")
        XCTAssertEqual(log.verify(), .intact)
    }

    func testCrashReportNames() {
        XCTAssertEqual(DiagnosticAnalyzer.crashProcessName("x/crashes_and_spins/bh-2021-07-01-102030.ips"), "bh")
        XCTAssertEqual(DiagnosticAnalyzer.crashProcessName("ExcUserFault_mediaserverd-2026-01-02-030405.ips"), "ExcUserFault_mediaserverd")
        XCTAssertNil(DiagnosticAnalyzer.crashProcessName("notes.txt"))
    }
}
