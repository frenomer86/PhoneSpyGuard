import Foundation
import PSGCore

/// Published indicators of compromise for mercenary spyware (FR-IOS-03):
/// process names, file paths and domains. The app ships the full set from the
/// STIX2 files Amnesty's MVT reads (Amnesty Tech, Citizen Lab, Kaspersky and
/// others) as `ios-indicators.json`, signed 2-of-3 like the rules
/// (`tools/build_indicators.py` builds it). The owner can also share in a
/// newer STIX2 file, which is used for that analysis only.
public struct IndicatorSet: Sendable, Equatable {
    public var source: String
    public var processNames: Set<String>
    public var pathPrefixes: [String]
    public var fileNames: Set<String>
    public var domains: Set<String>

    public init(source: String, processNames: Set<String> = [], pathPrefixes: [String] = [], fileNames: Set<String> = [], domains: Set<String> = []) {
        self.source = source
        self.processNames = processNames
        self.pathPrefixes = pathPrefixes
        self.fileNames = fileNames
        self.domains = Set(domains.map { $0.lowercased() })
    }

    public var isEmpty: Bool { processNames.isEmpty && pathPrefixes.isEmpty && fileNames.isEmpty && domains.isEmpty }
    public var count: Int { processNames.count + pathPrefixes.count + fileNames.count + domains.count }

    public mutating func merge(_ other: IndicatorSet) {
        source = [source, other.source].filter { !$0.isEmpty }.joined(separator: " + ")
        processNames.formUnion(other.processNames)
        pathPrefixes.append(contentsOf: other.pathPrefixes.filter { !pathPrefixes.contains($0) })
        fileNames.formUnion(other.fileNames)
        domains.formUnion(other.domains)
    }

    /// Why a process path matches, or nil.
    public func match(processPath path: String) -> String? {
        let name = (path as NSString).lastPathComponent
        if processNames.contains(name) { return "process name \"\(name)\"" }
        if fileNames.contains(name) { return "file name \"\(name)\"" }
        if let p = pathPrefixes.first(where: { path.hasPrefix($0) }) { return "path \(p)" }
        return nil
    }

    /// True if `host` is a listed domain or a subdomain of one.
    public func matches(domain host: String) -> Bool {
        var h = host.lowercased()
        if h.hasSuffix(".") { h.removeLast() }
        while true {
            if domains.contains(h) { return true }
            guard let dot = h.firstIndex(of: ".") else { return false }
            h = String(h[h.index(after: dot)...])
        }
    }

    // MARK: Loading

    /// The `indicators` object of the iPhone bundle's `ios` block.
    public init(bundleBlock v: JSONValue?) {
        func list(_ k: String) -> [String] { v?[k]?.arrayValue?.compactMap(\.stringValue) ?? [] }
        self.init(source: v?["source"]?.stringValue ?? "bundled",
                  processNames: Set(list("processNames")), pathPrefixes: list("pathPrefixes"),
                  fileNames: Set(list("fileNames")), domains: Set(list("domains")))
    }

    /// The signed indicator file (`format: phone-spy-guard-indicators/1`).
    /// Check its signatures with `BundleVerifier.checkSignatures` first.
    public static func fromIndicatorFile(_ data: Data) throws -> (set: IndicatorSet, version: Int, generated: String) {
        let v = try JSON.parse(data)
        guard v["format"]?.stringValue == "phone-spy-guard-indicators/1", let version = v["version"]?.primitiveLong else {
            throw JSONError(description: "Not a Phone Spy Guard indicator file")
        }
        let generated = v["generated"]?.stringValue ?? "unknown date"
        var set = IndicatorSet(bundleBlock: v)
        set.source = "published indicators of \(generated.prefix(10))"
        return (set, Int(version), generated)
    }

    /// Read a STIX 2.x bundle and keep the indicator patterns we can use:
    /// `process:name`, `file:name`, `file:path`/`file:parent_directory_ref`
    /// style paths, `domain-name:value` and `url:value`.
    public static func fromSTIX2(_ text: String, source: String = "STIX2 file") throws -> IndicatorSet {
        let root = try JSON.parse(text)
        guard let objects = root["objects"]?.arrayValue else {
            throw JSONError(description: "This is not a STIX 2 bundle (no 'objects')")
        }
        var set = IndicatorSet(source: source)
        let comparison = try NSRegularExpression(pattern: #"([a-z0-9-]+):([a-z0-9_.]+)\s*=\s*'((?:\\'|[^'])*)'"#, options: [.caseInsensitive])
        for obj in objects where obj["type"]?.stringValue == "indicator" {
            guard let pattern = obj["pattern"]?.stringValue else { continue }
            let ns = pattern as NSString
            for m in comparison.matches(in: pattern, range: NSRange(location: 0, length: ns.length)) {
                let object = ns.substring(with: m.range(at: 1)).lowercased()
                let property = ns.substring(with: m.range(at: 2)).lowercased()
                let value = ns.substring(with: m.range(at: 3)).replacingOccurrences(of: "\\'", with: "'")
                switch (object, property) {
                case ("process", "name"): set.processNames.insert(value)
                case ("file", "name"): set.fileNames.insert(value)
                case ("file", "path"), ("directory", "path"): set.pathPrefixes.append(value)
                case ("domain-name", "value"): set.domains.insert(value.lowercased())
                case ("url", "value"):
                    if let host = URL(string: value)?.host { set.domains.insert(host.lowercased()) }
                default: continue
                }
            }
        }
        if let name = objects.first(where: { $0["type"]?.stringValue == "malware" })?["name"]?.stringValue {
            set.source = "\(source) (\(name))"
        }
        return set
    }
}
