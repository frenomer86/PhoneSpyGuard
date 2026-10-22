import Foundation

/// A parsed, validated set of rules. `extensions` keeps the bundle's other
/// top-level blocks (the iPhone bundles carry an `ios` block with the current
/// iOS release and spyware indicators); the Kotlin and Rust parsers ignore
/// unknown keys, so one format serves every app.
public struct RuleBundle: Sendable {
    public let version: Int
    public let expiresAt: Date
    public let rules: [Rule]
    public let extensions: [String: JSONValue]

    public func rule(id: String) -> Rule? { rules.first { $0.id == id } }
}

extension JSONValue: @unchecked Sendable {}

/// A malformed bundle or one that breaches a limit. The message is what the
/// app would show, never a stack trace.
public struct BundleRejected: Error, CustomStringConvertible, Equatable {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// Limits on bundle shape, enforced at parse time (NFR-SEC-16).
public struct BundleLimits: Sendable {
    public var maxBytes = 256 * 1024
    public var maxRules = 1024
    public var maxConditionNodes = 256
    public var maxDepth = 16

    public init() {}
    public static let `default` = BundleLimits()
}

/// Parses a rule bundle into typed, bounded rules. Accepts exactly what
/// `RuleBundleParser` in Kotlin accepts; `desktop/conformance/parse-cases.json`
/// pins that.
public struct RuleBundleParser {
    public let limits: BundleLimits

    public init(limits: BundleLimits = .default) { self.limits = limits }

    public func parse(_ text: String) throws -> RuleBundle {
        if text.utf8.count > limits.maxBytes {
            throw BundleRejected("Bundle exceeds \(limits.maxBytes) bytes")
        }
        guard let root = (try? JSON.parse(text))?.objectValue else {
            throw BundleRejected("Bundle is not a JSON object")
        }
        guard let rawVersion = try primitive(root["version"], "version")?.primitiveLong else {
            throw BundleRejected("Bundle has no integer 'version'")
        }
        guard let expiresText = try primitive(root["expires"], "expires")?.primitiveContent,
              let expiresAt = ISO8601.parseInstant(expiresText) else {
            throw BundleRejected("Bundle has no valid ISO-8601 'expires'")
        }
        guard let ruleArray = root["rules"] else { throw BundleRejected("Bundle has no 'rules' array") }
        guard let items = ruleArray.arrayValue else { throw BundleRejected("Bundle 'rules' is not an array") }
        if items.count > limits.maxRules {
            throw BundleRejected("Bundle has \(items.count) rules, limit \(limits.maxRules)")
        }
        let rules = try items.map { item -> Rule in
            guard let obj = item.objectValue else { throw BundleRejected("Rule is not an object") }
            return try parseRule(obj)
        }
        var extensions = [String: JSONValue]()
        for (k, v) in root.entries where !["version", "expires", "rules"].contains(k) { extensions[k] = v }
        // Kotlin narrows the version with toInt(); keep the same wrap-around.
        return RuleBundle(version: Int(truncatingIfNeeded: Int32(truncatingIfNeeded: rawVersion)), expiresAt: expiresAt, rules: rules, extensions: extensions)
    }

    /// kotlinx `jsonPrimitive` throws on an object or array: that is a reject.
    private func primitive(_ v: JSONValue?, _ name: String) throws -> JSONValue? {
        guard let v else { return nil }
        guard v.isPrimitive else { throw BundleRejected("'\(name)' is not a scalar") }
        return v
    }

    private func parseRule(_ obj: JSONObject) throws -> Rule {
        guard let id = str(obj, "id") else { throw BundleRejected("Rule has no 'id'") }
        guard let whenValue = obj["when"] else { throw BundleRejected("Rule \(id) has no 'when'") }
        guard let whenNode = whenValue.objectValue else { throw BundleRejected("Rule \(id) 'when' is not an object") }

        var counter = 0
        let condition = try parseCondition(whenNode, ruleId: id, depth: 0, counter: &counter)

        let version = try primitive(obj["version"], "version")?.primitiveLong.map { Int(truncatingIfNeeded: Int32(truncatingIfNeeded: $0)) } ?? 1
        let contribution = try parseContribution(str(obj, "contribution"), id)
        return Rule(
            id: id,
            version: version,
            severity: try parseSeverity(str(obj, "severity"), id),
            title: str(obj, "title") ?? id,
            contribution: contribution,
            condition: condition,
            evidence: try strList(obj, "evidence"),
            explain: str(obj, "explain") ?? "",
            steps: try strList(obj, "steps"),
            log: try primitive(obj["log"], "log")?.primitiveBool ?? true,
            explains: try explainsList(obj, id, contribution)
        )
    }

    /// `explains`: absent or null is empty; otherwise an array of at most 64
    /// strings, and non-empty only on an INNOCENT rule.
    private func explainsList(_ obj: JSONObject, _ id: String, _ contribution: Contribution) throws -> [String] {
        guard let v = obj["explains"] else { return [] }
        if case .null = v { return [] }
        guard let items = v.arrayValue else { throw BundleRejected("Rule \(id) 'explains' is not an array") }
        if items.count > 64 { throw BundleRejected("Rule \(id) explains more than 64 rules") }
        let ids = try items.map { item -> String in
            guard case .string(let s) = item else { throw BundleRejected("Rule \(id) 'explains' has a non-string entry") }
            return s
        }
        if !ids.isEmpty && contribution != .innocent {
            throw BundleRejected("Rule \(id) is not innocent but has 'explains'")
        }
        return ids
    }

    private func parseCondition(_ node: JSONObject, ruleId: String, depth: Int, counter: inout Int) throws -> Condition {
        counter += 1
        if counter > limits.maxConditionNodes {
            throw BundleRejected("Rule exceeds \(limits.maxConditionNodes) condition nodes")
        }
        if depth > limits.maxDepth {
            throw BundleRejected("Rule \(ruleId) nests deeper than \(limits.maxDepth)")
        }
        if node.contains("all") {
            return .all(try childList(node, "all", ruleId).map { try parseCondition($0, ruleId: ruleId, depth: depth + 1, counter: &counter) })
        }
        if node.contains("any") {
            return .any(try childList(node, "any", ruleId).map { try parseCondition($0, ruleId: ruleId, depth: depth + 1, counter: &counter) })
        }
        if node.contains("not") {
            guard let child = node["not"]?.objectValue else { throw BundleRejected("Rule \(ruleId) 'not' is not an object") }
            return .not(try parseCondition(child, ruleId: ruleId, depth: depth + 1, counter: &counter))
        }
        if node.contains("fact") {
            return try parseLeaf(node, ruleId: ruleId)
        }
        throw BundleRejected("Rule \(ruleId) has an unknown condition node")
    }

    private func parseLeaf(_ node: JSONObject, ruleId: String) throws -> Condition {
        guard let key = str(node, "fact") else { throw BundleRejected("Rule \(ruleId) leaf has no 'fact'") }
        let op: Operator
        if node.contains("exists") {
            op = .exists
        } else if let v = node["eq"] {
            op = .eq(try factValue(v, ruleId))
        } else if node.contains("in") {
            guard let items = node["in"]?.arrayValue else { throw BundleRejected("Rule \(ruleId) 'in' is not an array") }
            op = .in(try items.map { item in
                guard let c = item.primitiveContent else { throw BundleRejected("Rule \(ruleId) has a non-scalar list entry") }
                return c
            })
        } else if node.contains("contains") {
            guard let s = str(node, "contains") else { throw BundleRejected("Rule \(ruleId) 'contains' is not a string") }
            op = .contains(s)
        } else if node.contains("gt") {
            op = .gt(try longOp(node, "gt", ruleId))
        } else if node.contains("gte") {
            op = .gte(try longOp(node, "gte", ruleId))
        } else if node.contains("lt") {
            op = .lt(try longOp(node, "lt", ruleId))
        } else if node.contains("lte") {
            op = .lte(try longOp(node, "lte", ruleId))
        } else {
            throw BundleRejected("Rule \(ruleId) leaf for '\(key)' has no known operator")
        }
        return .fact(key: key, op: op)
    }

    /// Same inference as Kotlin: boolean content first (so "true" is a bool),
    /// then integer content (so "5" is a number), then a JSON string is text.
    private func factValue(_ v: JSONValue, _ ruleId: String) throws -> FactValue {
        guard v.isPrimitive else { throw BundleRejected("Rule \(ruleId) has a non-scalar 'eq' value") }
        if let b = v.primitiveBool { return .bool(b) }
        if let n = v.primitiveLong { return .number(n) }
        if case .string(let s) = v { return .text(s) }
        throw BundleRejected("Rule \(ruleId) has an unsupported 'eq' value")
    }

    private func longOp(_ node: JSONObject, _ key: String, _ ruleId: String) throws -> Int64 {
        guard let v = node[key], v.isPrimitive, let n = v.primitiveLong else {
            throw BundleRejected("Rule \(ruleId) '\(key)' is not an integer")
        }
        return n
    }

    private func str(_ obj: JSONObject, _ key: String) -> String? {
        obj[key]?.stringValue
    }

    private func strList(_ obj: JSONObject, _ key: String) throws -> [String] {
        guard let v = obj[key], let items = v.arrayValue else { return [] }
        return try items.map { item in
            guard let c = item.primitiveContent else { throw BundleRejected("'\(key)' has a non-scalar entry") }
            return c
        }
    }

    private func childList(_ node: JSONObject, _ key: String, _ ruleId: String) throws -> [JSONObject] {
        guard let items = node[key]?.arrayValue else { throw BundleRejected("Rule \(ruleId) '\(key)' is not an array") }
        return try items.map { item in
            guard let o = item.objectValue else { throw BundleRejected("Rule \(ruleId) '\(key)' entry is not an object") }
            return o
        }
    }

    private func parseSeverity(_ raw: String?, _ ruleId: String) throws -> Severity {
        switch raw?.lowercased() {
        case "low": return .low
        case "medium": return .medium
        case "high": return .high
        case "critical": return .critical
        default: throw BundleRejected("Rule \(ruleId) has unknown severity '\(raw ?? "null")'")
        }
    }

    private func parseContribution(_ raw: String?, _ ruleId: String) throws -> Contribution {
        switch raw?.lowercased() {
        case "confirm": return .confirm
        case "strong": return .strong
        case "risk": return .risk
        case "innocent": return .innocent
        default: throw BundleRejected("Rule \(ruleId) has unknown contribution '\(raw ?? "null")'")
        }
    }
}

/// ISO-8601 instants as `java.time.Instant.parse` accepts them:
/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`.
public enum ISO8601 {
    public static func parseInstant(_ s: String) -> Date? {
        let pattern = #"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2}(?::\d{2})?)$"#
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) else { return nil }
        func group(_ i: Int) -> String? {
            guard let r = Range(m.range(at: i), in: s) else { return nil }
            return String(s[r])
        }
        guard let y = Int(group(1)!), let mo = Int(group(2)!), let d = Int(group(3)!),
              let h = Int(group(4)!), let mi = Int(group(5)!) else { return nil }
        let sec = group(6).flatMap(Int.init) ?? 0
        guard (1...12).contains(mo), (0...23).contains(h), (0...59).contains(mi), (0...59).contains(sec) else { return nil }
        let daysInMonth = [31, (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard d >= 1, d <= daysInMonth[mo - 1] else { return nil }

        var seconds = Double(daysFromCivil(y, mo, d)) * 86_400 + Double(h * 3600 + mi * 60 + sec)
        if let frac = group(7) { seconds += Double("0." + frac) ?? 0 }
        let zone = group(8)!
        if zone != "Z" {
            let sign: Double = zone.hasPrefix("-") ? -1 : 1
            let parts = zone.dropFirst().split(separator: ":").compactMap { Int($0) }
            let offset = Double(parts[0] * 3600 + parts[1] * 60 + (parts.count > 2 ? parts[2] : 0))
            seconds -= sign * offset
        }
        return Date(timeIntervalSince1970: seconds)
    }

    /// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
    static func daysFromCivil(_ year: Int, _ month: Int, _ day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (month + 9) % 12
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    public static func format(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: date)
    }
}
