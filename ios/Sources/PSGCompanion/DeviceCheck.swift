import Foundation
import PSGCore

/// What the companion can learn about the iPhone itself (FR-IOS-02).
///
/// iOS does not let one app inspect other apps, so the device part is short
/// and honest: a few things the app can read, plus guided checks where the
/// owner looks in Settings and answers. `nil` means "not known yet".
public struct DevicePosture: Sendable, Equatable {
    // Read by the app (see App/Platform/DevicePostureReader.swift).
    public var passcodeSet: Bool?
    public var osVersion: String
    public var httpProxySet: Bool?
    /// Names of jailbreak traces found from inside the sandbox.
    public var jailbreakSigns: [String]
    public var debuggerAttached: Bool

    // Answered by the owner in the guided steps.
    public var profileAnswer: ProfileAnswer?
    public var ownerJailbroke: Bool?
    public var threatNotification: Bool?
    public var lockdownModeOn: Bool?
    public var safetyCheckReviewed: Bool?

    public enum ProfileAnswer: String, Sendable, CaseIterable {
        case none, employer, unrecognised
    }

    public init(passcodeSet: Bool? = nil, osVersion: String, httpProxySet: Bool? = nil, jailbreakSigns: [String] = [],
                debuggerAttached: Bool = false, profileAnswer: ProfileAnswer? = nil, ownerJailbroke: Bool? = nil,
                threatNotification: Bool? = nil, lockdownModeOn: Bool? = nil, safetyCheckReviewed: Bool? = nil) {
        self.passcodeSet = passcodeSet
        self.osVersion = osVersion
        self.httpProxySet = httpProxySet
        self.jailbreakSigns = jailbreakSigns
        self.debuggerAttached = debuggerAttached
        self.profileAnswer = profileAnswer
        self.ownerJailbroke = ownerJailbroke
        self.threatNotification = threatNotification
        self.lockdownModeOn = lockdownModeOn
        self.safetyCheckReviewed = safetyCheckReviewed
    }
}

/// Turns the posture into facts and evaluates them. Each concern is its own
/// subject, and the shared scoring lets an innocent rule cancel everything in
/// its subject, so every innocent rule sits alone with the one signal it
/// explains: a work profile explains that profile and a proxy, never a
/// jailbreak. An owner-made jailbreak is still a risk, not an excuse.
public struct DeviceCheck {
    public let rules: CompanionRules

    public init(rules: CompanionRules) { self.rules = rules }

    public func facts(_ p: DevicePosture) -> [(subject: String, name: String, facts: Facts)] {
        var security = Facts()
        if let s = p.passcodeSet { security.bool("device.passcode_set", s) }
        security.text("device.os_version", p.osVersion)
        security.bool("device.os_update_available", rules.releases.updateAvailable(p.osVersion))
        security.number("device.os_majors_behind", Int64(rules.releases.majorsBehind(p.osVersion)))
        security.bool("device.debugger_attached", p.debuggerAttached)

        var profiles = Facts()
        if let a = p.profileAnswer { profiles.text("device.profile_found", a.rawValue) }

        // The proxy is its own subject: a work profile may explain a proxy,
        // but must not cancel an unrecognised profile or anything else.
        var proxy = Facts()
        if let on = p.httpProxySet { proxy.bool("device.http_proxy_set", on) }
        // Its own fact name: every rule runs on every subject, so reusing
        // device.profile_found here would repeat the profile finding.
        if let a = p.profileAnswer { proxy.bool("device.work_profile_present", a == .employer) }

        var jailbreak = Facts()
        jailbreak.number("device.jailbreak_signs", Int64(p.jailbreakSigns.count))
        if let o = p.ownerJailbroke { jailbreak.bool("device.owner_jailbroke", o) }

        var targeting = Facts()
        if let t = p.threatNotification { targeting.bool("device.threat_notification", t) }
        if let l = p.lockdownModeOn { targeting.bool("device.lockdown_mode", l) }

        return [
            ("device:security", "Passcode and iOS version", security),
            ("device:profiles", "Profiles and device management", profiles),
            ("device:proxy", "Web proxy", proxy),
            ("device:jailbreak", "Jailbreak", jailbreak),
            ("device:targeting", "Apple threat notification", targeting),
        ]
    }

    public func run(_ p: DevicePosture) -> SectionResult {
        let findings = facts(p).map { s -> Finding in
            var details = [String: String]()
            if s.subject == "device:security" { details["ios"] = p.osVersion }
            if s.subject == "device:jailbreak", !p.jailbreakSigns.isEmpty { details["traces"] = p.jailbreakSigns.joined(separator: ", ") }
            return Finding(subject: s.subject, displayName: s.name, evaluation: rules.evaluate(subject: s.subject, facts: s.facts), details: details)
        }
        var unanswered = [String]()
        if p.passcodeSet == nil { unanswered.append("Passcode") }
        if p.profileAnswer == nil { unanswered.append("Configuration profiles") }
        if p.threatNotification == nil { unanswered.append("Apple threat notification") }
        if p.safetyCheckReviewed == nil { unanswered.append("Safety Check") }
        if !p.jailbreakSigns.isEmpty, p.ownerJailbroke == nil { unanswered.append("Did you jailbreak it yourself?") }
        return SectionResult(section: .device, findings: findings, limits: Self.limits, unanswered: unanswered)
    }

    public static let limits = [
        "iPhone apps cannot look inside other apps, so this check cannot list installed spyware. It relies on your settings and diagnostic archives.",
        "For a deeper look, share a diagnostic archive into the app, or run the deep check from the desktop app with a USB cable.",
    ]
}

/// The guided Apple settings (FR-IOS-02): Safety Check, Lockdown Mode and the
/// configuration-profile check. iOS does not let apps open these screens
/// directly, so each step says exactly where to tap.
public struct GuidedStep: Sendable, Identifiable {
    public let id: String
    public let title: String
    public let why: String
    public let path: [String]
    public let note: String?
}

public enum AppleGuides {
    public static let safetyCheck = GuidedStep(
        id: "safety_check",
        title: "Run Apple's Safety Check",
        why: "Safety Check shows who you share location, photos and passwords with, which devices are signed in to your Apple Account, and lets you stop all of it at once.",
        path: ["Settings", "Privacy & Security", "Safety Check", "Manage Sharing & Access"],
        note: "Emergency Reset stops all sharing immediately. If the person may notice and that could put you at risk, read the safety guidance first.")

    public static let profiles = GuidedStep(
        id: "profiles",
        title: "Look for configuration profiles",
        why: "A profile can route your traffic through someone else's server or let them manage the phone. If the menu below is missing, no profile is installed.",
        path: ["Settings", "General", "VPN & Device Management"],
        note: "Look under Configuration Profile and Mobile Device Management. A profile from your work or school is normal; anything else is not.")

    public static let lockdown = GuidedStep(
        id: "lockdown",
        title: "Turn on Lockdown Mode if you may be targeted",
        why: "Lockdown Mode switches off the features mercenary spyware such as Pegasus has used to break in. It is meant for journalists, activists and anyone who got an Apple threat notification.",
        path: ["Settings", "Privacy & Security", "Lockdown Mode", "Turn On Lockdown Mode"],
        note: "Some websites, attachments and calls from unknown people work differently while it is on. The iPhone restarts to apply it.")

    public static let threatNotification = GuidedStep(
        id: "threat_notification",
        title: "Check for an Apple threat notification",
        why: "Apple emails and messages people it believes were targeted by mercenary spyware, and shows a banner at the top of the Apple Account page.",
        path: ["Sign in at account.apple.com", "Look for a Threat Notification banner"],
        note: "A real notification never asks you to click a link or install anything. Apple sends it from threat-notifications@apple.com.")

    public static let passcode = GuidedStep(
        id: "passcode",
        title: "Set a passcode only you know",
        why: "Most stalkerware on iPhone needs the phone in someone's hands for a few minutes. A passcode they don't know stops that.",
        path: ["Settings", "Face ID & Passcode", "Change Passcode"],
        note: "If someone else might know your passcode, change it now, and choose one that is not a birthday or a pattern.")

    public static let all = [passcode, profiles, safetyCheck, threatNotification, lockdown]
}
