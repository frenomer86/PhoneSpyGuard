import Foundation
import PSGCore

/// The parts of a check result (FR-CHK-02).
public enum CheckSection: String, CaseIterable, Sendable {
    case device = "Device"
}

/// How a result is shown to the owner: clear, worth a look, or act now.
///
/// There is deliberately no "safe": a clean result is never presented as
/// proof that the phone is safe (FR-CHK-03), so `clear` reads "Nothing found
/// by these checks" and always comes with what the checks cannot see.
public enum Rating: Int, Comparable, Sendable {
    case clear = 0, worthALook = 1, actNow = 2

    public init(_ c: Confidence) {
        switch c {
        case .confirmed, .veryLikely: self = .actNow
        case .possible: self = .worthALook
        case .unlikely: self = .clear
        }
    }

    public static func < (a: Rating, b: Rating) -> Bool { a.rawValue < b.rawValue }

    public var label: String {
        switch self {
        case .clear: return "Nothing found by these checks"
        case .worthALook: return "Worth a look"
        case .actNow: return "Act now"
        }
    }
}

/// One evidence card: a subject, its verdict, and the reasoning.
public struct Finding: Sendable, Identifiable {
    public var id: String { subject }
    public let subject: String
    /// What the subject is, in the owner's words ("WhatsApp", "This iPhone").
    public let displayName: String
    public let verdict: Verdict
    public let rules: [Rule]
    public let skippedRuleIds: [String]
    /// Extra facts for the card and the evidence log (paths, dates, sources).
    public let details: [String: String]

    public var rating: Rating { Rating(verdict.confidence) }
    public var concerningRules: [Rule] { rules.filter { $0.contribution != .innocent } }
    public var innocentRules: [Rule] { rules.filter { $0.contribution == .innocent } }

    /// Next steps, in rule order, without repeats.
    public var steps: [String] {
        var seen = Set<String>()
        return concerningRules.flatMap(\.steps).filter { seen.insert($0).inserted }
    }

    /// Plain-language reasons (FR-ALR-01).
    public var reasons: [String] { concerningRules.map(\.explain).filter { !$0.isEmpty } }

    init(subject: String, displayName: String, evaluation: DetectionEngine.Evaluation, details: [String: String] = [:]) {
        self.subject = subject
        self.displayName = displayName
        self.verdict = evaluation.verdict
        self.rules = evaluation.matchedRules
        self.skippedRuleIds = evaluation.skippedRuleIds
        self.details = details
    }
}

/// One part of the result.
public struct SectionResult: Sendable {
    public let section: CheckSection
    public let findings: [Finding]
    /// What these checks could not cover, shown with every result.
    public let limits: [String]
    /// Guided items the owner has not answered yet.
    public let unanswered: [String]
    /// Items answered "can't find" or skipped: looked at, but not checked.
    public let notChecked: [String]

    public init(section: CheckSection, findings: [Finding], limits: [String], unanswered: [String], notChecked: [String] = []) {
        self.section = section
        self.findings = findings
        self.limits = limits
        self.unanswered = unanswered
        self.notChecked = notChecked
    }

    /// The section's result, as the desktop and Android report it. A section
    /// with anything unanswered, not found or skipped is INCOMPLETE, never
    /// CLEAR; a concern found elsewhere in it still shows as that concern.
    public enum Outcome: String, Sendable {
        case clear = "CLEAR"
        case incomplete = "INCOMPLETE"
        case worthALook = "WORTH_A_LOOK"
        case actNow = "ACT_NOW"
    }

    public var outcome: Outcome {
        switch rating {
        case .actNow: return .actNow
        case .worthALook: return .worthALook
        case .clear: return unanswered.isEmpty && notChecked.isEmpty ? .clear : .incomplete
        }
    }

    public var rating: Rating {
        findings.map(\.rating).max() ?? .clear
    }

    public var headline: String {
        if outcome == .incomplete {
            let n = unanswered.count + notChecked.count
            return "Incomplete: \(n) item\(n == 1 ? "" : "s") not checked"
        }
        return rating.label
    }

    /// Findings worth showing as cards, most serious first.
    public var cards: [Finding] {
        findings.filter { $0.rating > .clear }.sorted { $0.rating > $1.rating }
    }
}

/// Writes results and answers into the evidence timeline (FR-EVD-01). Only
/// rules marked `log` are written, and only for subjects that rated above
/// clear, so the timeline holds what matters to a bank or the police.
public struct EvidenceRecorder {
    public let log: EvidenceLog

    public init(log: EvidenceLog) { self.log = log }

    @discardableResult
    public func record(_ result: SectionResult) throws -> [EvidenceEntry] {
        var written = [EvidenceEntry]()
        for f in result.cards {
            let logged = f.concerningRules.filter(\.log)
            guard !logged.isEmpty else { continue }
            var details = f.details
            details["section"] = result.section.rawValue
            details["subject"] = f.subject
            details["confidence"] = f.verdict.confidence.rawValue
            details["rules"] = logged.map(\.id).joined(separator: ",")
            if !f.innocentRules.isEmpty { details["explained_by"] = f.innocentRules.map(\.id).joined(separator: ",") }
            written.append(try log.append(.finding, "\(f.displayName): \(logged.map(\.title).joined(separator: "; "))", details: details))
        }
        return written
    }

    /// Record one of the owner's answers ("I did this", "found a device").
    @discardableResult
    public func recordAnswer(_ summary: String, item: String, answer: String) throws -> EvidenceEntry {
        try log.append(.answer, summary, details: ["item": item, "answer": answer])
    }
}
