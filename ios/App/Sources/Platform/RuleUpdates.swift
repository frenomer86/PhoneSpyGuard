import Foundation
import PSGCompanion

/// Where downloaded rule updates live and where they come from (FR-RUL-02).
///
/// The address is set at build time (`PSG_RULES_BASE_URL` in project.yml,
/// written into Info.plist as `PSGRulesBaseURL`), so whoever publishes a build
/// also decides where its signed rule files are served. A build without one
/// still works fully offline on the rules inside it and says that updates are
/// off. Nothing a server sends is used unless it carries 2-of-3 signatures
/// from the keys in the app.
enum RuleUpdates {
    static var baseURL: URL? {
        guard let s = Bundle.main.object(forInfoDictionaryKey: "PSGRulesBaseURL") as? String,
              !s.isEmpty, let url = URL(string: s.hasSuffix("/") ? s : s + "/"), url.scheme == "https" else { return nil }
        return url
    }

    static var directory: URL {
        let root = (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
        return root.appendingPathComponent("rule-updates", isDirectory: true)
    }

    /// Rules from a verified update when there is one, else those in the app.
    static func load() throws -> CompanionRules {
        try CompanionRules.load(allowDevelopmentKeys: BuildFlags.allowDevelopmentKeys, updates: directory)
    }

    /// No cookies, cache, credentials or stored state: the server learns only
    /// that some copy of the app asked for the public rule files.
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieAcceptPolicy = .never
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        c.timeoutIntervalForRequest = 30
        c.timeoutIntervalForResource = 120
        c.waitsForConnectivity = false
        c.tlsMinimumSupportedProtocolVersion = .TLSv12
        c.httpAdditionalHeaders = ["User-Agent": "PhoneSpyGuard"]
        return URLSession(configuration: c)
    }()

    /// Reads at most `RuleUpdater.maxFileBytes`, so a hostile or broken
    /// server cannot fill the phone's memory.
    static func fetch(_ url: URL) async throws -> Data {
        let (bytes, response) = try await session.bytes(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
        guard response.url?.scheme == "https" else { throw URLError(.secureConnectionFailed) }
        let limit = RuleUpdater.maxFileBytes
        guard response.expectedContentLength <= Int64(limit) else { throw URLError(.dataLengthExceedsMaximum) }
        var data = Data()
        data.reserveCapacity(max(0, Int(response.expectedContentLength)))
        for try await byte in bytes {
            guard data.count < limit else { throw URLError(.dataLengthExceedsMaximum) }
            data.append(byte)
        }
        return data
    }

    static func updater() -> RuleUpdater? {
        guard let baseURL else { return nil }
        return RuleUpdater(baseURL: baseURL, directory: directory, allowDevelopmentKeys: BuildFlags.allowDevelopmentKeys, fetch: fetch)
    }
}
