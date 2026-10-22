import Crypto
import Foundation
import PSGCore

/// The signed data files the iPhone app runs on. Each is signed 2-of-3 by the
/// release keys in `trusted-keys.json` and checked before use:
///
/// - `ios-bundle.json`: the rules (with the `ios` block)
/// - `ios-indicators.json`: published spyware indicators (MVT's STIX2 sets)
///
/// The same files can arrive by update (FR-RUL-02). An update is kept apart
/// from the copy inside the app and used only if it verifies and is not older
/// than the built-in copy, so a bad or rolled-back download can never replace
/// good rules.
public enum SignedFile: String, CaseIterable, Sendable {
    case rules = "ios-bundle.json"
    case indicators = "ios-indicators.json"

    public var signatureName: String { (rawValue as NSString).deletingPathExtension + ".sig.json" }
    public var allNames: [String] { [rawValue, signatureName] }
}

/// Where a loaded file came from, for the "About these rules" screen and the
/// public rule log (NFR-SEC-18).
public struct RuleProvenance: Sendable, Equatable {
    public var file: SignedFile
    public var version: Int
    public var sha256: String
    public var downloaded: Bool
    public var detail: String
}

extension CompanionRules {
    /// Load the rules and indicators: from `updates` when a downloaded copy
    /// there verifies and is newer than the built-in one, otherwise from the
    /// app. Files that fail to verify stop the app: it must not run on
    /// unverified rules.
    ///
    /// `trust` and `builtIn` default to the app's own `trusted-keys.json` and
    /// resources; tests pass their own.
    public static func load(now: Date = Date(), allowDevelopmentKeys: Bool = false, updates: URL? = nil,
                            trust: TrustStore? = nil, builtIn: (String) throws -> Data = CompanionResources.data) throws -> CompanionRules {
        var trust = try trust ?? TrustStore(json: String(decoding: try builtIn("trusted-keys.json"), as: UTF8.self))
        if !allowDevelopmentKeys { trust = trust.excludingDevelopmentKeys() }
        let verifier = BundleVerifier(trust: trust, clock: { now })

        func bundledData(_ name: String) throws -> Data { try builtIn(name) }
        func updateData(_ name: String) -> Data? { updates.flatMap { try? Data(contentsOf: $0.appendingPathComponent(name)) } }

        // Rules. The built-in copy must carry valid signatures (otherwise the
        // app itself was altered). A downloaded copy is used when it verifies
        // and is newer; that also keeps the app working after the built-in
        // copy expires. With no usable update, the built-in copy must pass
        // the full check, expiry included.
        let builtInPayload = try bundledData(SignedFile.rules.rawValue)
        let builtInSigs = try BundleVerifier.parseSignatureFile(try bundledData(SignedFile.rules.signatureName))
        if case .rejected(let why) = verifier.checkSignatures(payload: builtInPayload, signatures: builtInSigs) {
            throw BundleRejected("The rules inside the app failed their signature check: \(why)")
        }
        let builtInVersion = try RuleBundleParser().parse(String(decoding: builtInPayload, as: UTF8.self)).version
        let bundle: RuleBundle
        var rulesPayload = builtInPayload
        var rulesDownloaded = false
        if let p = updateData(SignedFile.rules.rawValue), let s = updateData(SignedFile.rules.signatureName),
           let b = try? verifier.load(payload: p, signatureFile: s, installedVersion: builtInVersion + 1) {
            bundle = b
            rulesPayload = p
            rulesDownloaded = true
        } else {
            bundle = try verifier.load(payload: builtInPayload, signatureFile: try bundledData(SignedFile.rules.signatureName))
        }
        var rules = CompanionRules(bundle: bundle)
        rules.developmentKeys = trust.hasDevelopmentKeys
        rules.provenance.append(RuleProvenance(file: .rules, version: bundle.version, sha256: Data(SHA256.hash(data: rulesPayload)).hexString,
                                               downloaded: rulesDownloaded, detail: "\(bundle.rules.count) rules, expires \(ISO8601.format(bundle.expiresAt).prefix(10))"))

        // Indicators.
        func verifiedIndicators(_ payload: Data, _ sig: Data) -> (set: IndicatorSet, version: Int, generated: String)? {
            guard let sigs = try? BundleVerifier.parseSignatureFile(sig),
                  case .accepted = verifier.checkSignatures(payload: payload, signatures: sigs) else { return nil }
            return try? IndicatorSet.fromIndicatorFile(payload)
        }
        let iocPayload = try bundledData(SignedFile.indicators.rawValue)
        guard var ioc = verifiedIndicators(iocPayload, try bundledData(SignedFile.indicators.signatureName)) else {
            throw BundleRejected("Indicator file failed its signature check")
        }
        var iocData = iocPayload, iocDownloaded = false
        if let p = updateData(SignedFile.indicators.rawValue), let s = updateData(SignedFile.indicators.signatureName),
           let u = verifiedIndicators(p, s), u.version > ioc.version {
            ioc = u
            iocData = p
            iocDownloaded = true
        }
        rules.indicators.merge(ioc.set)
        rules.provenance.append(RuleProvenance(file: .indicators, version: ioc.version, sha256: Data(SHA256.hash(data: iocData)).hexString,
                                               downloaded: iocDownloaded, detail: "\(ioc.set.count) indicators, published \(ioc.generated.prefix(10))"))

        return rules
    }
}

/// Downloads signed rule updates (FR-RUL-02). The app calls `run` with its
/// update address; every file is checked with the same 2-of-3 signatures
/// before it is stored, and only files newer than what the phone already uses
/// are kept. A failed or partial download changes nothing.
///
/// Privacy: the request carries no identifier, cookie or link the owner
/// checked. The server learns only that some copy of the app asked for the
/// public rule files.
public struct RuleUpdater {
    public let baseURL: URL
    public let directory: URL
    public let allowDevelopmentKeys: Bool
    /// Largest file accepted; the indicator file is well under 1 MB.
    public static let maxFileBytes = 32 << 20
    private let fetch: (URL) async throws -> Data
    private let trust: TrustStore?
    private let builtIn: (String) throws -> Data

    public init(baseURL: URL, directory: URL, allowDevelopmentKeys: Bool = false, trust: TrustStore? = nil,
                builtIn: @escaping (String) throws -> Data = CompanionResources.data,
                fetch: @escaping (URL) async throws -> Data) {
        self.baseURL = baseURL
        self.directory = directory
        self.allowDevelopmentKeys = allowDevelopmentKeys
        self.trust = trust
        self.builtIn = builtIn
        self.fetch = fetch
    }

    private func load(_ now: Date, _ updates: URL) throws -> CompanionRules {
        try CompanionRules.load(now: now, allowDevelopmentKeys: allowDevelopmentKeys, updates: updates, trust: trust, builtIn: builtIn)
    }

    public enum Outcome: Equatable, Sendable {
        /// Newer signed files were stored; names of what changed.
        case updated([SignedFile])
        case alreadyCurrent
        case failed(String)
    }

    public func run(now: Date = Date()) async -> Outcome {
        do {
            guard baseURL.scheme == "https" else { return .failed("Updates are only fetched over HTTPS") }
            // What the phone uses now. This fails once the built-in rules
            // have expired with no update yet, and then any valid update is
            // an improvement.
            let before = try? load(now, directory)
            // Download everything into a fresh staging folder first.
            let staging = directory.appendingPathComponent(".staging-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: staging) }
            for file in SignedFile.allCases {
                for name in file.allNames {
                    let data = try await fetch(baseURL.appendingPathComponent(name))
                    guard data.count <= Self.maxFileBytes else { return .failed("\(name) is larger than any rule file should be") }
                    try data.write(to: staging.appendingPathComponent(name), options: .atomic)
                }
            }
            // Verify the downloaded set exactly as the app will load it.
            let after = try load(now, staging)
            var changed = [SignedFile]()
            for p in after.provenance where p.downloaded {
                let old = before?.provenance.first { $0.file == p.file }
                if old == nil || p.version > old!.version { changed.append(p.file) }
            }
            guard !changed.isEmpty else { return .alreadyCurrent }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            // The signature file goes last, so an interrupted copy leaves a
            // payload that no longer matches its old signature and is
            // ignored, never a mismatched pair that verifies.
            for file in changed {
                for name in [file.rawValue, file.signatureName] {
                    let target = directory.appendingPathComponent(name)
                    let data = try Data(contentsOf: staging.appendingPathComponent(name))
                    try data.write(to: target, options: .atomic)
                }
            }
            return .updated(changed)
        } catch {
            return .failed("\(error)")
        }
    }
}
