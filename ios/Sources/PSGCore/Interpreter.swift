import Foundation

/// Thrown when evaluation exceeds the time or depth budget.
public struct EvaluationBudgetExceeded: Error, CustomStringConvertible {
    public let description: String
}

/// Limits that bound rule evaluation (NFR-SEC-16). Node count and depth are
/// enforced at parse time; the time budget here, per subject.
public struct EvaluationLimits: Sendable {
    public var maxConditionNodes = 256
    public var maxDepth = 16
    public var maxEvaluationMillis: Int64 = 250

    public init() {}
    public static let `default` = EvaluationLimits()
}

/// Evaluates a `Condition` against `Facts`: reads facts, compares, combines
/// with and/or/not, nothing else. Mirrors `BoundedInterpreter` in Kotlin.
public struct BoundedInterpreter {
    private let limits: EvaluationLimits
    private let clock: () -> Int64

    public init(limits: EvaluationLimits = .default, clock: @escaping () -> Int64 = BoundedInterpreter.monotonicMillis) {
        self.limits = limits
        self.clock = clock
    }

    public static func monotonicMillis() -> Int64 {
        Int64(ProcessInfo.processInfo.systemUptime * 1000)
    }

    public func matches(_ condition: Condition, _ facts: Facts) throws -> Bool {
        let deadline = clock() + limits.maxEvaluationMillis
        return try eval(condition, facts, depth: 0, deadline: deadline)
    }

    private func eval(_ condition: Condition, _ facts: Facts, depth: Int, deadline: Int64) throws -> Bool {
        if clock() > deadline {
            throw EvaluationBudgetExceeded(description: "Rule evaluation exceeded \(limits.maxEvaluationMillis) ms budget")
        }
        if depth > limits.maxDepth {
            throw EvaluationBudgetExceeded(description: "Rule nesting exceeded depth \(limits.maxDepth)")
        }
        switch condition {
        case .all(let of):
            for c in of where try !eval(c, facts, depth: depth + 1, deadline: deadline) { return false }
            return true
        case .any(let of):
            for c in of where try eval(c, facts, depth: depth + 1, deadline: deadline) { return true }
            return false
        case .not(let of):
            return try !eval(of, facts, depth: depth + 1, deadline: deadline)
        case .fact(let key, let op):
            return Self.evalLeaf(key: key, op: op, facts: facts)
        }
    }

    static func evalLeaf(key: String, op: Operator, facts: Facts) -> Bool {
        let value = facts[key]
        switch op {
        case .exists:
            return value != nil
        case .eq(let expected):
            guard let value else { return false }
            switch (value, expected) {
            case (.text(let a), .text(let b)): return exactlyEqual(a, b)
            case (.bool(let a), .bool(let b)): return a == b
            case (.number(let a), .number(let b)): return a == b
            default: return false // same-type only
            }
        case .in(let choices):
            guard case .text(let s)? = value else { return false }
            return choices.contains { exactlyEqual($0, s) }
        case .contains(let needle):
            guard case .textList(let list)? = value else { return false }
            return list.contains { exactlyEqual($0, needle) }
        case .gt(let n): return number(value).map { $0 > n } ?? false
        case .gte(let n): return number(value).map { $0 >= n } ?? false
        case .lt(let n): return number(value).map { $0 < n } ?? false
        case .lte(let n): return number(value).map { $0 <= n } ?? false
        }
    }

    private static func number(_ v: FactValue?) -> Int64? {
        if case .number(let n)? = v { return n }
        return nil
    }
}
