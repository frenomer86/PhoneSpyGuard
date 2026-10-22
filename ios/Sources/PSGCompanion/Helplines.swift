import Foundation
import PSGCore

/// One verified place to get help (FR-SAF-03).
public struct Contact: Sendable, Equatable {
    public let name: String
    public let number: String
    public let kind: String
}

/// Per-country verified helplines from `helplines.json`.
public struct ContactDirectory: Sendable {
    private let byCountry: [String: [Contact]]

    public init(json: JSONValue) {
        var map = [String: [Contact]]()
        for c in json["countries"]?.arrayValue ?? [] {
            guard let code = c["country"]?.stringValue?.uppercased() else { continue }
            map[code] = (c["contacts"]?.arrayValue ?? []).compactMap { e in
                guard let n = e["name"]?.stringValue, let num = e["number"]?.stringValue else { return nil }
                return Contact(name: n, number: num, kind: e["kind"]?.stringValue ?? "")
            }
        }
        byCountry = map
    }

    public static func bundled(_ file: String) throws -> ContactDirectory {
        ContactDirectory(json: try JSON.parse(CompanionResources.data(file)))
    }

    public func forCountry(_ iso: String) -> [Contact] { byCountry[iso.uppercased()] ?? byCountry["INTL"] ?? [] }
    public func hasCountry(_ iso: String) -> Bool { byCountry[iso.uppercased()] != nil }
    public var countries: [String] { byCountry.keys.sorted() }
}
