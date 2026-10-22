import Foundation
import PSGCore

/// The iPhone's signed rule bundle and the data blocks it carries.
///
/// Rules ship as `ios-bundle.json` + `ios-bundle.sig.json`, signed 2-of-3 by
/// the same release keys as the desktop bundle (`trusted-keys.json` is the
/// same file). The app verifies the signatures before it uses a single rule;
/// a bundle that fails is never used (FR-RUL-01, FR-CHK-04 offline).
public struct CompanionRules {
    public let bundle: RuleBundle
    public let engine: DetectionEngine
    public let releases: IOSReleases
    /// The bundle's own indicators plus the signed indicator file.
    public internal(set) var indicators: IndicatorSet
    public let stagingDirs: [String]
    public let knownPathPrefixes: [String]
    /// True when the rules were accepted on development (test) keys. The app
    /// shows a "development build" banner, and release builds never set it.
    public internal(set) var developmentKeys = false
    /// Version and SHA-256 of each signed file in use, and whether it came
    /// from an update (shown in the app; compare with the public rule log).
    public internal(set) var provenance: [RuleProvenance] = []

    public init(bundle: RuleBundle) {
        self.bundle = bundle
        engine = DetectionEngine(bundle: bundle)
        let ios = bundle.extensions["ios"]
        releases = IOSReleases(ios?["releases"])
        indicators = IndicatorSet(bundleBlock: ios?["indicators"])
        stagingDirs = ios?["stagingDirs"]?.arrayValue?.compactMap(\.stringValue) ?? []
        knownPathPrefixes = ios?["knownPathPrefixes"]?.arrayValue?.compactMap(\.stringValue) ?? []
    }

    /// Load and verify the files built into the app, ignoring downloads.
    /// See `load(now:allowDevelopmentKeys:updates:)`.
    ///
    /// Keys marked `"development": true` in `trusted-keys.json` are dropped
    /// unless `allowDevelopmentKeys` is set (the app sets it only in DEBUG
    /// builds or with the `PSG_ALLOW_DEV_KEYS` flag).
    public static func bundled(now: Date = Date(), allowDevelopmentKeys: Bool = false) throws -> CompanionRules {
        try load(now: now, allowDevelopmentKeys: allowDevelopmentKeys, updates: nil)
    }

    func evaluate(subject: String, facts: Facts) -> DetectionEngine.Evaluation {
        engine.evaluate(subject: subject, facts: facts)
    }
}

/// iOS release lines and their newest builds, from the bundle.
public struct IOSReleases: Sendable {
    public let majors: [String]
    public let latest: [String: String]
    public let minimumSupported: String

    init(_ v: JSONValue?) {
        majors = v?["majors"]?.arrayValue?.compactMap(\.stringValue) ?? []
        var l = [String: String]()
        for (k, val) in v?["latest"]?.objectValue?.entries ?? [] { if let s = val.stringValue { l[k] = s } }
        latest = l
        minimumSupported = v?["minimumSupported"]?.stringValue ?? "16.0"
    }

    /// Compare dotted versions numerically ("17.10" > "17.9").
    public static func compare(_ a: String, _ b: String) -> ComparisonResult {
        let x = a.split(separator: ".").map { Int($0) ?? 0 }
        let y = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(x.count, y.count) {
            let p = i < x.count ? x[i] : 0, q = i < y.count ? y[i] : 0
            if p != q { return p < q ? .orderedAscending : .orderedDescending }
        }
        return .orderedSame
    }

    /// How many release lines behind the newest this version is. A version
    /// newer than anything in the bundle counts as current, so a stale bundle
    /// can only miss an update, never raise a false alarm.
    public func majorsBehind(_ version: String) -> Int {
        let major = String(version.split(separator: ".").first ?? "")
        guard let newest = majors.last else { return 0 }
        if let i = majors.firstIndex(of: major) { return majors.count - 1 - i }
        return Self.compare(major, newest) == .orderedDescending ? 0 : majors.count
    }

    /// Whether a newer build of the same release line is known.
    public func updateAvailable(_ version: String) -> Bool {
        let major = String(version.split(separator: ".").first ?? "")
        guard let newest = latest[major] else { return false }
        return Self.compare(version, newest) == .orderedAscending
    }
}

/// Access to the package's bundled resources.
public enum CompanionResources {
    public static func url(_ name: String) throws -> URL {
        let ext = (name as NSString).pathExtension
        guard let url = Bundle.module.url(forResource: (name as NSString).deletingPathExtension, withExtension: ext, subdirectory: "Resources") else {
            throw ArchiveError("Missing bundled resource \(name)")
        }
        return url
    }

    public static func data(_ name: String) throws -> Data {
        try Data(contentsOf: try url(name))
    }
}
