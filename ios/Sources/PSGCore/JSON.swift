import Foundation

/// A small JSON tree with the exact semantics the shared formats need.
///
/// Foundation's `JSONSerialization` turns `true` and `1` into the same
/// `NSNumber` on Apple platforms and behaves differently on Linux, and it
/// loses object key order. The rule-bundle parser has to tell booleans from
/// integers exactly as kotlinx.serialization does, so we parse JSON ourselves.
/// Numbers keep their source text so integer handling matches Kotlin's
/// `longOrNull` (a value like `5.0` is not an integer).
public indirect enum JSONValue: Equatable {
    case null
    case bool(Bool)
    case number(String)
    case string(String)
    case array([JSONValue])
    case object(JSONObject)

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var objectValue: JSONObject? {
        if case .object(let o) = self { return o }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    /// Whether this is a scalar ("primitive" in kotlinx terms, including null).
    public var isPrimitive: Bool {
        switch self {
        case .array, .object: return false
        default: return true
        }
    }

    /// The textual content of a primitive, as kotlinx's `JsonPrimitive.content`.
    public var primitiveContent: String? {
        switch self {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let n): return n
        case .string(let s): return s
        default: return nil
        }
    }

    /// kotlinx `booleanOrNull`: a primitive whose content is exactly
    /// `true` / `false`, including the strings "true" and "false".
    public var primitiveBool: Bool? {
        switch primitiveContent {
        case "true": return true
        case "false": return false
        default: return nil
        }
    }

    /// kotlinx `longOrNull`: a primitive whose content is a decimal Int64,
    /// including a string such as "5".
    public var primitiveLong: Int64? {
        guard isPrimitive, case .some(let c) = primitiveContent else { return nil }
        if case .null = self { return nil }
        return Int64(c)
    }
}

/// A JSON object that remembers insertion order (for deterministic output).
public struct JSONObject: Equatable {
    public private(set) var keys: [String] = []
    private var storage: [String: JSONValue] = [:]

    public init() {}

    public init(_ pairs: [(String, JSONValue)]) {
        for (k, v) in pairs { self[k] = v }
    }

    public subscript(key: String) -> JSONValue? {
        get { storage[key] }
        set {
            if storage[key] == nil, newValue != nil { keys.append(key) }
            if newValue == nil { keys.removeAll { $0 == key } }
            storage[key] = newValue
        }
    }

    public func contains(_ key: String) -> Bool { storage[key] != nil }

    public var entries: [(key: String, value: JSONValue)] {
        keys.map { ($0, storage[$0]!) }
    }

    public var count: Int { keys.count }
}

public struct JSONError: Error, CustomStringConvertible {
    public let description: String
    public init(description: String) { self.description = description }
}

// MARK: - Parsing

public enum JSON {
    public static func parse(_ text: String) throws -> JSONValue {
        var p = Parser(bytes: Array(text.utf8))
        p.skipWhitespace()
        let v = try p.value(depth: 0)
        p.skipWhitespace()
        guard p.atEnd else { throw JSONError(description: "Trailing characters after JSON value") }
        return v
    }

    public static func parse(_ data: Data) throws -> JSONValue {
        guard let text = String(data: data, encoding: .utf8) else {
            throw JSONError(description: "JSON is not valid UTF-8")
        }
        return try parse(text)
    }

    private struct Parser {
        let bytes: [UInt8]
        var i = 0
        /// Guards against stack exhaustion on hostile input; far above anything
        /// the bundle limits allow.
        let maxDepth = 512

        var atEnd: Bool { i >= bytes.count }

        mutating func skipWhitespace() {
            while i < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[i]) { i += 1 }
        }

        mutating func value(depth: Int) throws -> JSONValue {
            guard depth < maxDepth else { throw JSONError(description: "JSON nests too deeply") }
            guard i < bytes.count else { throw JSONError(description: "Unexpected end of JSON") }
            switch bytes[i] {
            case UInt8(ascii: "{"): return try object(depth: depth)
            case UInt8(ascii: "["): return try array(depth: depth)
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            default: return .number(try number())
            }
        }

        mutating func literal(_ word: String) throws {
            let w = Array(word.utf8)
            guard i + w.count <= bytes.count, Array(bytes[i..<i + w.count]) == w else {
                throw JSONError(description: "Invalid literal at \(i)")
            }
            i += w.count
        }

        mutating func number() throws -> String {
            let start = i
            if i < bytes.count, bytes[i] == UInt8(ascii: "-") { i += 1 }
            func digits() -> Int {
                let s = i
                while i < bytes.count, (0x30...0x39).contains(bytes[i]) { i += 1 }
                return i - s
            }
            guard i < bytes.count else { throw JSONError(description: "Invalid number") }
            if bytes[i] == UInt8(ascii: "0") {
                i += 1
            } else if digits() == 0 {
                throw JSONError(description: "Invalid number at \(start)")
            }
            if i < bytes.count, bytes[i] == UInt8(ascii: ".") {
                i += 1
                guard digits() > 0 else { throw JSONError(description: "Invalid number at \(start)") }
            }
            if i < bytes.count, bytes[i] == UInt8(ascii: "e") || bytes[i] == UInt8(ascii: "E") {
                i += 1
                if i < bytes.count, bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "-") { i += 1 }
                guard digits() > 0 else { throw JSONError(description: "Invalid number at \(start)") }
            }
            return String(decoding: bytes[start..<i], as: UTF8.self)
        }

        mutating func string() throws -> String {
            i += 1 // opening quote
            var out = [UInt8]()
            while true {
                guard i < bytes.count else { throw JSONError(description: "Unterminated string") }
                let b = bytes[i]
                if b == UInt8(ascii: "\"") { i += 1; break }
                if b < 0x20 { throw JSONError(description: "Control character in string") }
                if b != UInt8(ascii: "\\") { out.append(b); i += 1; continue }
                i += 1
                guard i < bytes.count else { throw JSONError(description: "Bad escape") }
                let e = bytes[i]; i += 1
                switch e {
                case UInt8(ascii: "\""): out.append(0x22)
                case UInt8(ascii: "\\"): out.append(0x5C)
                case UInt8(ascii: "/"): out.append(0x2F)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    var scalar = try hex4()
                    if (0xD800...0xDBFF).contains(scalar) {
                        // A surrogate pair encodes one astral character.
                        guard i + 1 < bytes.count, bytes[i] == UInt8(ascii: "\\"), bytes[i + 1] == UInt8(ascii: "u") else {
                            throw JSONError(description: "Lone surrogate in string")
                        }
                        i += 2
                        let low = try hex4()
                        guard (0xDC00...0xDFFF).contains(low) else { throw JSONError(description: "Bad surrogate pair") }
                        scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
                    }
                    guard let u = Unicode.Scalar(scalar) else { throw JSONError(description: "Invalid code point") }
                    out.append(contentsOf: Array(String(Character(u)).utf8))
                default:
                    throw JSONError(description: "Bad escape \\\(Character(Unicode.Scalar(e)))")
                }
            }
            guard let s = String(bytes: out, encoding: .utf8) else {
                throw JSONError(description: "String is not valid UTF-8")
            }
            return s
        }

        mutating func hex4() throws -> UInt32 {
            guard i + 4 <= bytes.count,
                  let v = UInt32(String(decoding: bytes[i..<i + 4], as: UTF8.self), radix: 16) else {
                throw JSONError(description: "Bad \\u escape")
            }
            i += 4
            return v
        }

        mutating func array(depth: Int) throws -> JSONValue {
            i += 1
            var items = [JSONValue]()
            skipWhitespace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
            while true {
                skipWhitespace()
                items.append(try value(depth: depth + 1))
                skipWhitespace()
                guard i < bytes.count else { throw JSONError(description: "Unterminated array") }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
                throw JSONError(description: "Expected , or ] at \(i)")
            }
        }

        mutating func object(depth: Int) throws -> JSONValue {
            i += 1
            var obj = JSONObject()
            skipWhitespace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "}") { i += 1; return .object(obj) }
            while true {
                skipWhitespace()
                guard i < bytes.count, bytes[i] == UInt8(ascii: "\"") else {
                    throw JSONError(description: "Expected object key at \(i)")
                }
                let key = try string()
                skipWhitespace()
                guard i < bytes.count, bytes[i] == UInt8(ascii: ":") else {
                    throw JSONError(description: "Expected : at \(i)")
                }
                i += 1
                skipWhitespace()
                // Last duplicate wins, as in kotlinx.
                obj[key] = try value(depth: depth + 1)
                skipWhitespace()
                guard i < bytes.count else { throw JSONError(description: "Unterminated object") }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(obj) }
                throw JSONError(description: "Expected , or } at \(i)")
            }
        }
    }
}

// MARK: - Writing

extension JSONValue {
    /// Compact JSON text in the same style kotlinx.serialization writes:
    /// keys in insertion order, non-ASCII left as is, control characters
    /// escaped.
    public func serialized(pretty: Bool = false) -> String {
        var out = ""
        write(into: &out, pretty: pretty, indent: 0)
        return out
    }

    private func write(into out: inout String, pretty: Bool, indent: Int) {
        let pad = { (n: Int) in String(repeating: "  ", count: n) }
        switch self {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .number(let n): out += n
        case .string(let s): JSONValue.writeString(s, into: &out)
        case .array(let items):
            if items.isEmpty { out += "[]"; return }
            out += "["
            for (n, item) in items.enumerated() {
                if n > 0 { out += "," }
                if pretty { out += "\n" + pad(indent + 1) }
                item.write(into: &out, pretty: pretty, indent: indent + 1)
            }
            if pretty { out += "\n" + pad(indent) }
            out += "]"
        case .object(let obj):
            if obj.count == 0 { out += "{}"; return }
            out += "{"
            for (n, entry) in obj.entries.enumerated() {
                if n > 0 { out += "," }
                if pretty { out += "\n" + pad(indent + 1) }
                JSONValue.writeString(entry.key, into: &out)
                out += pretty ? ": " : ":"
                entry.value.write(into: &out, pretty: pretty, indent: indent + 1)
            }
            if pretty { out += "\n" + pad(indent) }
            out += "}"
        }
    }

    static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 {
                    out += String(format: "\\u%04x", u.value)
                } else {
                    out.unicodeScalars.append(u)
                }
            }
        }
        out += "\""
    }
}

extension JSONValue {
    public static func int(_ v: Int64) -> JSONValue { .number(String(v)) }
}
