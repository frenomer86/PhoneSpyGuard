import Foundation

/// A single fact read by a collector. Facts are the only thing a rule can
/// inspect; mirrors `FactValue` in core:detection and psg-core.
public enum FactValue: Equatable, Sendable {
    case text(String)
    case bool(Bool)
    case number(Int64)
    case textList([String])
}

/// An immutable bag of facts about one subject: on iPhone that is the device
/// itself, one account the owner audited, one shared message, or one process
/// seen in a diagnostic archive. Keys are dotted paths matching rule bundles.
public struct Facts: Equatable, Sendable {
    private var values: [String: FactValue]

    public init(_ values: [String: FactValue] = [:]) {
        self.values = values
    }

    public subscript(key: String) -> FactValue? { values[key] }

    public var keys: Dictionary<String, FactValue>.Keys { values.keys }

    public func has(_ key: String) -> Bool { values[key] != nil }

    public mutating func set(_ key: String, _ value: FactValue) { values[key] = value }

    public mutating func text(_ key: String, _ v: String) { values[key] = .text(v) }
    public mutating func bool(_ key: String, _ v: Bool) { values[key] = .bool(v) }
    public mutating func number(_ key: String, _ v: Int64) { values[key] = .number(v) }
    public mutating func textList(_ key: String, _ v: [String]) { values[key] = .textList(v) }
}

extension Facts {
    /// Decode facts the way `FactsCodec.decode` does on Android: an array is a
    /// text list, a boolean is a bool, an integer is a number, anything else
    /// is text.
    public init(json: JSONObject) {
        var f = Facts()
        for (key, value) in json.entries {
            switch value {
            case .array(let items):
                f.textList(key, items.compactMap { $0.primitiveContent })
            case .object:
                continue
            default:
                if let b = value.primitiveBool {
                    f.bool(key, b)
                } else if let n = value.primitiveLong {
                    f.number(key, n)
                } else {
                    f.text(key, value.primitiveContent ?? "")
                }
            }
        }
        self = f
    }

    /// Encode as `FactsCodec.encode` does (keys sorted for stable output).
    public var json: JSONObject {
        var o = JSONObject()
        for key in keys.sorted() {
            switch self[key]! {
            case .text(let s): o[key] = .string(s)
            case .bool(let b): o[key] = .bool(b)
            case .number(let n): o[key] = .int(n)
            case .textList(let l): o[key] = .array(l.map { .string($0) })
            }
        }
        return o
    }
}

/// Exact string equality, as Kotlin and Rust compare strings (code unit by
/// code unit). Swift's `==` treats canonically equivalent strings as equal
/// (e.g. "é" precomposed and decomposed), which would let the iPhone match a
/// rule the other two engines do not.
@inline(__always)
func exactlyEqual(_ a: String, _ b: String) -> Bool {
    a.utf8.elementsEqual(b.utf8)
}

/// Kotlin's `String.compareTo` order: lexicographic over UTF-16 code units.
/// Used wherever the shared formats sort keys.
func utf16Less(_ a: String, _ b: String) -> Bool {
    a.utf16.lexicographicallyPrecedes(b.utf16)
}
