import Foundation
import XCTest
@testable import PSGCompanion
@testable import PSGCore

final class BundleAndDeviceTests: XCTestCase {
    var rules: CompanionRules!

    override func setUpWithError() throws {
        rules = try CompanionRules.bundled(now: ISO8601.parseInstant("2026-10-22T00:00:00Z")!, allowDevelopmentKeys: true)
    }

    func testBundledRulesAreSignedAndCarryTheIOSBlocks() throws {
        XCTAssertEqual(rules.bundle.rules.count, 16)
        XCTAssertEqual(rules.releases.majors.last, "27")
        XCTAssertTrue(rules.bundle.rules.allSatisfy { $0.id.hasPrefix("PSG-IOS-") })

        // An edited bundle no longer verifies, so the app refuses it.
        var payload = try CompanionResources.data("ios-bundle.json")
        payload.append(contentsOf: Array(" ".utf8))
        let trust = try TrustStore(json: String(decoding: try CompanionResources.data("trusted-keys.json"), as: UTF8.self))
        XCTAssertThrowsError(try BundleVerifier(trust: trust, clock: { ISO8601.parseInstant("2026-10-22T00:00:00Z")! }).load(payload: payload, signatureFile: try CompanionResources.data("ios-bundle.sig.json")))
    }

    func testShippedRulesNeedNoDevelopmentKeys() throws {
        // Signed with single-use keys whose private halves no longer exist,
        // so a release build (no development keys allowed) loads them.
        XCTAssertFalse(rules.developmentKeys)
        let release = try CompanionRules.bundled(now: ISO8601.parseInstant("2026-10-22T00:00:00Z")!)
        XCTAssertEqual(release.bundle.version, rules.bundle.version)
        let trust = String(decoding: try CompanionResources.data("trusted-keys.json"), as: UTF8.self)
        XCTAssertFalse(TrustStore.revokedKeys.contains(where: trust.contains))
    }

    func testSignedIndicatorFileIsLoadedAndTamperingIsRefused() throws {
        // The published Pegasus, Predator, KingSpawn and Triangulation sets.
        XCTAssertGreaterThan(rules.indicators.processNames.count, 50)
        XCTAssertGreaterThan(rules.indicators.domains.count, 1000)
        XCTAssertTrue(rules.indicators.processNames.contains("bh"))
        XCTAssertNotNil(rules.indicators.match(processPath: "/private/var/db/com.apple.xpc.roleaccountd.staging/subridged"))

        var payload = try CompanionResources.data("ios-indicators.json")
        payload.append(contentsOf: Array("\n".utf8))
        let trust = try TrustStore(json: String(decoding: try CompanionResources.data("trusted-keys.json"), as: UTF8.self))
        let sigs = try BundleVerifier.parseSignatureFile(try CompanionResources.data("ios-indicators.sig.json"))
        XCTAssertNotEqual(BundleVerifier(trust: trust).checkSignatures(payload: payload, signatures: sigs), .accepted)
    }

    func testEveryRuleStepHasPlainText() {
        for rule in rules.bundle.rules {
            for step in rule.steps { XCTAssertNotNil(Steps.catalog[step], "\(rule.id) step \(step)") }
            if rule.contribution != .innocent { XCTAssertFalse(rule.explain.isEmpty, rule.id) }
        }
    }

    func testVersionMaths() {
        let r = rules.releases
        XCTAssertEqual(IOSReleases.compare("17.10", "17.9"), .orderedDescending)
        XCTAssertEqual(r.majorsBehind("27.0.1"), 0)
        XCTAssertEqual(r.majorsBehind("26.7.1"), 1)
        XCTAssertEqual(r.majorsBehind("18.6"), 2)
        XCTAssertEqual(r.majorsBehind("16.7"), 4)
        XCTAssertEqual(r.majorsBehind("28.0"), 0) // newer than the bundle knows: current
        XCTAssertTrue(r.updateAvailable("27.0"))
        XCTAssertFalse(r.updateAvailable("27.0.1"))
        XCTAssertTrue(r.updateAvailable("26.7"))
        XCTAssertFalse(r.updateAvailable("28.0"))
    }

    func testCurrentIPhoneWithPasscodeHasNothingToShow() {
        let p = DevicePosture(passcodeSet: true, osVersion: "27.0.1", httpProxySet: false, profileAnswer: DevicePosture.ProfileAnswer.none,
                              threatNotification: false, safetyCheckReviewed: true)
        let result = DeviceCheck(rules: rules).run(p)
        XCTAssertEqual(result.rating, .clear)
        XCTAssertTrue(result.unanswered.isEmpty)
        XCTAssertEqual(result.headline, "Nothing found by these checks")
        XCTAssertEqual(result.outcome, .clear)
    }

    func testUnansweredGuidedStepsMakeTheCheckIncompleteNeverClear() {
        let p = DevicePosture(passcodeSet: true, osVersion: "27.0.1", httpProxySet: false)
        let result = DeviceCheck(rules: rules).run(p)
        XCTAssertEqual(result.rating, .clear)
        XCTAssertEqual(result.outcome, .incomplete)
        XCTAssertTrue(result.headline.hasPrefix("Incomplete:"))
    }

    func testRiskySettingsAreWorthALook() {
        let result = DeviceCheck(rules: rules).run(DevicePosture(passcodeSet: false, osVersion: "18.2"))
        XCTAssertEqual(result.rating, .worthALook)
        let security = result.findings.first { $0.subject == "device:security" }!
        XCTAssertEqual(Set(security.concerningRules.map(\.id)), ["PSG-IOS-DEV-001", "PSG-IOS-DEV-002", "PSG-IOS-DEV-003"])
        XCTAssertEqual(security.steps, ["set_passcode", "update_ios"])
        XCTAssertTrue(result.headline.hasPrefix("Worth a look"))
    }

    func testWorkProfileExplainsTheProxyButNotAJailbreak() {
        var p = DevicePosture(passcodeSet: true, osVersion: "27.0.1", httpProxySet: true, profileAnswer: .employer)
        var result = DeviceCheck(rules: rules).run(p)
        XCTAssertEqual(result.findings.first { $0.subject == "device:profiles" }?.rating, .clear)
        XCTAssertEqual(result.findings.first { $0.subject == "device:proxy" }?.rating, .clear)

        // Without the work-profile answer the same proxy is worth a look.
        p.profileAnswer = DevicePosture.ProfileAnswer.none
        XCTAssertEqual(DeviceCheck(rules: rules).run(p).findings.first { $0.subject == "device:proxy" }?.rating, .worthALook)

        // A work profile never excuses a jailbreak.
        p.profileAnswer = .employer
        p.jailbreakSigns = ["/Applications/Cydia.app"]
        result = DeviceCheck(rules: rules).run(p)
        XCTAssertEqual(result.rating, .actNow)
        XCTAssertTrue(result.unanswered.contains("Did you jailbreak it yourself?"))
    }

    func testOwnerJailbreakStaysARiskNotAnExcuse() {
        var p = DevicePosture(passcodeSet: true, osVersion: "27.0.1", jailbreakSigns: ["/Applications/Sileo.app"], ownerJailbroke: true)
        let jb = DeviceCheck(rules: rules).run(p).findings.first { $0.subject == "device:jailbreak" }!
        XCTAssertEqual(jb.rating, .worthALook)
        XCTAssertEqual(jb.concerningRules.map(\.id), ["PSG-IOS-DEV-008"])
        p.ownerJailbroke = false
        XCTAssertEqual(DeviceCheck(rules: rules).run(p).findings.first { $0.subject == "device:jailbreak" }?.rating, .actNow)
    }

    func testNoInnocentRuleSharesASubjectWithAnUnrelatedSignal() {
        // Every innocent rule's facts must belong to a subject whose other
        // rules it explains; checked by listing the facts each innocent rule
        // reads and the subject that supplies them.
        let check = DeviceCheck(rules: rules)
        let subjects = check.facts(DevicePosture(passcodeSet: true, osVersion: "27.0.1", httpProxySet: true, jailbreakSigns: ["x"],
                                                 profileAnswer: .employer, ownerJailbroke: true, threatNotification: true))
        for s in subjects {
            let eval = rules.evaluate(subject: s.subject, facts: s.facts)
            let innocent = eval.matchedRules.filter { $0.contribution == .innocent }.map(\.id)
            let concerning = eval.matchedRules.filter { $0.contribution == .strong || $0.contribution == .confirm }.map(\.id)
            XCTAssertTrue(innocent.isEmpty || concerning.isEmpty, "\(s.subject): \(innocent) would cancel \(concerning)")
        }
    }

    func testUnknownProfileAndThreatNotificationAreActNow() {
        let result = DeviceCheck(rules: rules).run(DevicePosture(passcodeSet: true, osVersion: "27.0.1", profileAnswer: .unrecognised, threatNotification: true))
        let cards = result.cards.map(\.subject)
        XCTAssertEqual(Set(cards), ["device:profiles", "device:targeting"])
        let threat = result.cards.first { $0.subject == "device:targeting" }!
        XCTAssertEqual(threat.steps.first, "turn_on_lockdown")
    }
}

final class HelplineTests: XCTestCase {
    func testHelplinesByCountryWithInternationalFallback() throws {
        let help = try ContactDirectory.bundled("helplines.json")
        XCTAssertTrue(help.forCountry("US").contains { $0.kind == "DOMESTIC_ABUSE" })
        XCTAssertTrue(help.forCountry("gh").contains { $0.number == "0800 111 222" })
        XCTAssertTrue(help.forCountry("ZZ").contains { $0.kind == "EXPERT" }) // falls back to international
    }
}
