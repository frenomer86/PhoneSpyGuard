import Foundation

/// The four confidence levels (FR-ATT-05), most to least concerning.
public enum Confidence: String, Sendable, CaseIterable {
    case confirmed = "CONFIRMED"
    case veryLikely = "VERY_LIKELY"
    case possible = "POSSIBLE"
    case unlikely = "UNLIKELY"
}

/// One rule that matched a subject, kept for the evidence card.
public struct MatchedSignal: Equatable, Sendable {
    public let ruleId: String
    public let title: String
    public let severity: Severity
    public let contribution: Contribution
    /// For an innocent signal, the rule ids it explains.
    public var explains: [String] = []
}

/// The verdict for one subject, with the reasoning behind it.
public struct Verdict: Sendable {
    public let subject: String
    public let confidence: Confidence
    public let signals: [MatchedSignal]
    public let innocentExplanations: [MatchedSignal]

    public var concerning: [MatchedSignal] { signals.filter { $0.contribution != .innocent } }
}

/// The shared scoring specification, pinned by
/// `desktop/conformance/engine-cases.json` for Kotlin, Rust and Swift.
/// An INNOCENT rule explains only the rule ids in its `explains` list, and
/// the verdict comes from the signals left unexplained:
///  1. any CONFIRM (never explained)   -> CONFIRMED
///  2. >= 1 unexplained STRONG         -> VERY_LIKELY
///  3. an unexplained RISK             -> POSSIBLE
///  4. otherwise                       -> UNLIKELY
public enum Scoring {
    public static func classify(subject: String, matched: [MatchedSignal]) -> Verdict {
        let innocent = matched.filter { $0.contribution == .innocent }
        let explained = Set(innocent.flatMap(\.explains))
        let open = matched.filter { s in
            s.contribution != .innocent && (s.contribution == .confirm || !explained.contains(s.ruleId))
        }

        let confidence: Confidence
        if open.contains(where: { $0.contribution == .confirm }) {
            confidence = .confirmed
        } else if open.contains(where: { $0.contribution == .strong }) {
            confidence = .veryLikely
        } else if open.contains(where: { $0.contribution == .risk }) {
            confidence = .possible
        } else {
            confidence = .unlikely
        }
        return Verdict(subject: subject, confidence: confidence, signals: matched, innocentExplanations: innocent)
    }
}

/// The detection engine: evaluates a validated bundle against one subject's
/// facts. No network access of its own. A rule that runs out of budget is
/// skipped and reported, so a scan is never presented as complete when a rule
/// could not run (FR-CHK-03).
public struct DetectionEngine {
    public let bundle: RuleBundle
    private let interpreter: BoundedInterpreter

    public struct Evaluation: Sendable {
        public let verdict: Verdict
        public let skippedRuleIds: [String]
        /// The full rules that matched, for explanations and steps.
        public let matchedRules: [Rule]
    }

    public init(bundle: RuleBundle, limits: EvaluationLimits = .default) {
        self.bundle = bundle
        self.interpreter = BoundedInterpreter(limits: limits)
    }

    public func evaluate(subject: String, facts: Facts) -> Evaluation {
        var matched = [MatchedSignal]()
        var rules = [Rule]()
        var skipped = [String]()
        for rule in bundle.rules {
            do {
                if try interpreter.matches(rule.condition, facts) {
                    matched.append(MatchedSignal(ruleId: rule.id, title: rule.title, severity: rule.severity, contribution: rule.contribution, explains: rule.explains))
                    rules.append(rule)
                }
            } catch {
                skipped.append(rule.id)
            }
        }
        return Evaluation(verdict: Scoring.classify(subject: subject, matched: matched), skippedRuleIds: skipped, matchedRules: rules)
    }
}
