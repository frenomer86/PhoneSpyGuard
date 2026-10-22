import Foundation
import PSGCore

/// Analyses a diagnostic archive the owner shares into the app, on the phone,
/// against published indicators of mercenary spyware (FR-IOS-03).
///
/// The owner makes the archive themselves (a sysdiagnose: press both volume
/// buttons and the side button for about a second, wait ten minutes, then
/// Settings > Privacy & Security > Analytics & Improvements > Analytics Data,
/// find `sysdiagnose_...`, and share it to Phone Spy Guard). Nothing is
/// uploaded. The archive is read in one streaming pass and only three kinds
/// of file are kept: the shutdown log, the process list (`ps.txt`, what was
/// running when the archive was made) and the names of crash reports.
public struct DiagnosticAnalyzer {
    public let rules: CompanionRules
    public let indicators: IndicatorSet

    /// Largest shutdown.log we keep in memory; real ones are well under 1 MB.
    static let maxShutdownLogBytes = 16 << 20
    /// Largest ps.txt we keep; a real one is a few hundred KB.
    static let maxProcessListBytes = 16 << 20

    public init(rules: CompanionRules, extraIndicators: IndicatorSet? = nil) {
        self.rules = rules
        var set = rules.indicators
        if let extra = extraIndicators { set.merge(extra) }
        indicators = set
    }

    public struct Report: Sendable {
        public let findings: [Finding]
        public let rebootsSeen: Int
        public let firstReboot: Date?
        public let lastReboot: Date?
        public let shutdownLogFound: Bool
        public let crashReportsSeen: Int
        /// Processes in `ps.txt`, or nil when the archive had none.
        public let runningProcessesSeen: Int?
        public let indicatorSource: String
        public let indicatorCount: Int
        public let limits: [String]

        public var rating: Rating { findings.map(\.rating).max() ?? .clear }
        public var cards: [Finding] { findings.filter { $0.rating > .clear }.sorted { $0.rating > $1.rating } }

        public var asSection: SectionResult {
            SectionResult(section: .device, findings: findings, limits: limits, unanswered: [])
        }
    }

    /// Analyse a file: a sysdiagnose `.tar.gz`, a plain `.tar`, or a bare
    /// `shutdown.log` text file.
    public func analyze(url: URL) throws -> Report {
        try analyze(source: FileByteSource(url: url), name: url.lastPathComponent)
    }

    public func analyze(source: ByteSource, name: String = "") throws -> Report {
        let stream = try ArchiveStreams.open(source)
        // Peek: a tar header has "ustar" at offset 257 or a valid checksum;
        // otherwise treat the input as a shutdown.log text file.
        let head = try readUpTo(stream, 512)
        let looksLikeTar = head.count == 512 && (TarReader.cString(head[257..<262]) == "ustar" || TarReader.checksumOK(head))
        if !looksLikeTar {
            var text = head
            while text.count < Self.maxShutdownLogBytes {
                let more = try stream.read(max: 1 << 16)
                if more.isEmpty { break }
                text.append(contentsOf: more)
            }
            let log = String(decoding: text, as: UTF8.self)
            guard log.contains("remaining client pid") || log.contains("SIGTERM") else {
                throw ArchiveError("This file is not a sysdiagnose archive or a shutdown log")
            }
            return report(shutdown: ShutdownLog(text: log), running: nil, crashNames: [])
        }

        let tar = TarReader(stream: PrefixedStream(prefix: head, rest: stream))
        var shutdown: ShutdownLog?
        var crashNames = [String]()
        var running: [String]?
        while let entry = try tar.next() {
            guard entry.isFile else { continue }
            let path = entry.path
            if path.hasSuffix("/shutdown.log") || path == "shutdown.log" {
                let data = try tar.readData(limit: Self.maxShutdownLogBytes)
                shutdown = ShutdownLog(text: String(decoding: data, as: UTF8.self))
            } else if path.hasSuffix("/ps.txt") || path == "ps.txt" {
                let data = try tar.readData(limit: Self.maxProcessListBytes)
                running = Self.processPaths(psText: String(decoding: data, as: UTF8.self))
            } else if path.contains("crashes_and_spins/") || path.hasSuffix(".ips") {
                if let n = Self.crashProcessName(path) { crashNames.append(n) }
            }
        }
        return report(shutdown: shutdown, running: running, crashNames: crashNames)
    }

    /// The executable paths in a sysdiagnose `ps.txt` (`ps` output with a
    /// header line ending in COMMAND), each once, in order. The command is
    /// whatever follows the columns before COMMAND; only absolute paths are
    /// kept (kernel threads have none). An app's executable path may contain
    /// spaces (`/…/My App.app/My App`), so for app bundles the path runs to
    /// the executable named after the bundle; otherwise to the first space.
    static func processPaths(psText: String) -> [String] {
        var columns: Int?
        var seen = Set<String>()
        var paths = [String]()
        let appRe = try! NSRegularExpression(pattern: #"^(/.*?/([^/]+)\.app/\2)(?:\s|$)"#)
        for raw in psText.split(whereSeparator: \.isNewline) {
            let fields = raw.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let n = columns else {
                if fields.last == "COMMAND" || fields.last == "CMD" { columns = fields.count }
                continue
            }
            guard fields.count >= n, n >= 1 else { continue }
            // Start of the command: the n-th field, left in place so spaces survive.
            let commandStart = fields[n - 1].startIndex
            let command = String(raw[commandStart...]).trimmingCharacters(in: .whitespaces)
            guard command.hasPrefix("/") else { continue }
            let ns = command as NSString
            let path: String
            if let m = appRe.firstMatch(in: command, range: NSRange(location: 0, length: ns.length)) {
                path = ns.substring(with: m.range(at: 1))
            } else {
                path = String(command.prefix { $0 != " " && $0 != "\t" })
            }
            if seen.insert(path).inserted { paths.append(path) }
        }
        return paths
    }

    /// `bh-2021-07-01-102030.ips` -> `bh`.
    static func crashProcessName(_ path: String) -> String? {
        let file = (path as NSString).lastPathComponent
        guard file.hasSuffix(".ips") || file.hasSuffix(".crash") else { return nil }
        let re = try! NSRegularExpression(pattern: #"^(.+?)[-_]\d{4}-\d{2}-\d{2}-\d{6}"#)
        let ns = file as NSString
        guard let m = re.firstMatch(in: file, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return ns.substring(with: m.range(at: 1))
    }

    func report(shutdown: ShutdownLog?, running: [String]?, crashNames: [String]) -> Report {
        var findings = [Finding]()
        let processes = shutdown?.processes ?? []
        for p in processes {
            var facts = Facts()
            facts.text("proc.path", p.path)
            facts.text("proc.name", (p.path as NSString).lastPathComponent)
            facts.number("proc.delay_count", Int64(p.delayCount))
            let match = indicators.match(processPath: p.path)
            facts.bool("proc.indicator_match", match != nil)
            facts.bool("proc.in_staging_dir", rules.stagingDirs.contains { p.path.hasPrefix($0) })
            facts.bool("proc.outside_known_paths", !rules.knownPathPrefixes.contains { p.path.hasPrefix($0) })
            var details = ["path": p.path, "delayed_restarts": String(p.delayCount), "source": "shutdown.log"]
            if let f = p.firstSeen { details["first_seen"] = ISO8601.format(f) }
            if let l = p.lastSeen { details["last_seen"] = ISO8601.format(l) }
            if let m = match { details["indicator"] = "\(m) (\(indicators.source))" }
            if running?.contains(p.path) == true { details["running_when_captured"] = "yes" }
            let subject = "process:\(p.path)"
            findings.append(Finding(subject: subject, displayName: (p.path as NSString).lastPathComponent,
                                    evaluation: rules.evaluate(subject: subject, facts: facts), details: details))
        }
        // Processes running when the archive was made (ps.txt). Ones the
        // shutdown log already showed are noted on that card above.
        let shutdownPaths = Set(processes.map(\.path))
        for path in running ?? [] where !shutdownPaths.contains(path) {
            var facts = Facts()
            facts.text("proc.path", path)
            facts.text("proc.name", (path as NSString).lastPathComponent)
            let match = indicators.match(processPath: path)
            facts.bool("proc.indicator_match", match != nil)
            facts.bool("proc.running_in_staging_dir", rules.stagingDirs.contains { path.hasPrefix($0) })
            facts.bool("proc.running_outside_known_paths", !rules.knownPathPrefixes.contains { path.hasPrefix($0) })
            var details = ["path": path, "source": "ps.txt", "running_when_captured": "yes"]
            if let m = match { details["indicator"] = "\(m) (\(indicators.source))" }
            let subject = "process:\(path)"
            findings.append(Finding(subject: subject, displayName: (path as NSString).lastPathComponent,
                                    evaluation: rules.evaluate(subject: subject, facts: facts), details: details))
        }

        // Crash reports only carry a process name, so only an indicator match counts.
        var seen = Set(processes.map { ($0.path as NSString).lastPathComponent } + (running ?? []).map { ($0 as NSString).lastPathComponent })
        for name in crashNames where seen.insert(name).inserted {
            guard let m = indicators.match(processPath: name) else { continue }
            var facts = Facts()
            facts.text("proc.name", name)
            facts.bool("proc.indicator_match", true)
            let subject = "process:\(name)"
            findings.append(Finding(subject: subject, displayName: name,
                                    evaluation: rules.evaluate(subject: subject, facts: facts),
                                    details: ["source": "crash report", "indicator": "\(m) (\(indicators.source))"]))
        }

        var limits = [
            "Checked against \(indicators.count) published indicators (\(indicators.source)). Spyware that is new or changed its traces will not match.",
            "Mercenary spyware can leave no trace in these records, so this result is never proof that the iPhone is clean.",
        ]
        if shutdown == nil {
            limits.insert("No shutdown log was found in this archive. Make a fresh sysdiagnose and share the whole .tar.gz file.", at: 0)
        } else if (shutdown?.reboots.count ?? 0) < 2 {
            limits.insert("The shutdown log covers fewer than two restarts. Restart the iPhone a few times over the next days and check again; the log keeps more history then.", at: 0)
        }
        if running == nil && shutdown != nil {
            limits.append("This archive had no process list (ps.txt), so only programs that delayed a restart were checked.")
        }
        let times = shutdown?.reboots.compactMap(\.time) ?? []
        return Report(findings: findings, rebootsSeen: shutdown?.reboots.count ?? 0, firstReboot: times.min(), lastReboot: times.max(),
                      shutdownLogFound: shutdown != nil, crashReportsSeen: crashNames.count, runningProcessesSeen: running?.count,
                      indicatorSource: indicators.source, indicatorCount: indicators.count, limits: limits)
    }

    private func readUpTo(_ s: ByteStream, _ n: Int) throws -> [UInt8] {
        var out = [UInt8]()
        while out.count < n {
            let c = try s.read(max: n - out.count)
            if c.isEmpty { break }
            out.append(contentsOf: c)
        }
        return out
    }
}

/// Replays bytes already read before continuing with the stream.
final class PrefixedStream: ByteStream {
    private var prefix: [UInt8]
    private let rest: ByteStream

    init(prefix: [UInt8], rest: ByteStream) {
        self.prefix = prefix
        self.rest = rest
    }

    func read(max: Int) throws -> [UInt8] {
        if prefix.isEmpty { return try rest.read(max: max) }
        let n = min(max, prefix.count)
        defer { prefix.removeFirst(n) }
        return Array(prefix[0..<n])
    }
}
