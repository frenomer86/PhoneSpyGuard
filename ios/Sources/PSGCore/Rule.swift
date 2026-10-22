import Foundation

/// Severity of a finding. Mirrors the shared rule format.
public enum Severity: String, Sendable, CaseIterable {
    case low = "LOW", medium = "MEDIUM", high = "HIGH", critical = "CRITICAL"
}

/// How a matched rule contributes to the confidence verdict (FR-ATT-05).
public enum Contribution: String, Sendable {
    /// A known spyware product or published indicator matched -> Confirmed.
    case confirm = "CONFIRM"
    /// A strong behavioural signal.
    case strong = "STRONG"
    /// A risky power or setting with no harmful activity seen.
    case risk = "RISK"
    /// A legitimate use that can explain risky powers away.
    case innocent = "INNOCENT"
}

/// One detection rule. A rule is data the engine evaluates, never code it
/// runs (FR-RUL-01, NFR-SEC-16).
public struct Rule: Sendable {
    public let id: String
    public let version: Int
    public let severity: Severity
    public let title: String
    public let contribution: Contribution
    public let condition: Condition
    public let evidence: [String]
    public let explain: String
    public let steps: [String]
    public let log: Bool
    /// For an INNOCENT rule: the ids of the rules it explains. It excuses
    /// those and nothing else (review finding H5).
    public let explains: [String]
}

/// The predicate tree. Closed, so evaluation is total and bounded.
public indirect enum Condition: Sendable {
    case all([Condition])
    case any([Condition])
    case not(Condition)
    case fact(key: String, op: Operator)
}

/// The closed set of leaf operators. None can read a second fact, call out
/// or loop.
public enum Operator: Sendable {
    case eq(FactValue)
    case `in`([String])
    case gt(Int64)
    case gte(Int64)
    case lt(Int64)
    case lte(Int64)
    case contains(String)
    case exists
}
