import Foundation

/// The iOS shutdown log (`system_logs.logarchive/Extra/shutdown.log` in a
/// sysdiagnose). At each restart iOS records which processes were still
/// running and delaying the shutdown. Kaspersky showed in 2024 that Pegasus,
/// Reign and Predator infections leave "sticky" processes here, running from
/// unusual folders such as `/private/var/db/` and `/private/var/tmp/`, and the
/// log survives long after the implant itself is gone.
public struct ShutdownLog: Sendable {
    /// One restart, with every process that delayed it.
    public struct Reboot: Sendable, Equatable {
        public let time: Date?
        public let processes: [String]
    }

    /// Every distinct process path, with how many restarts it delayed and
    /// when it was first and last seen.
    public struct Process: Sendable, Equatable {
        public let path: String
        public var delayCount: Int
        public var firstSeen: Date?
        public var lastSeen: Date?
    }

    public let reboots: [Reboot]

    public init(text: String) {
        var reboots = [Reboot]()
        var current = [String]()
        let clientRe = try! NSRegularExpression(pattern: #"remaining client pid:\s*\d+\s*\((.*)\)\s*$"#)
        let sigtermRe = try! NSRegularExpression(pattern: #"SIGTERM:\s*\[(\d+)\]"#)
        text.enumerateLines { line, _ in
            let ns = line as NSString
            let range = NSRange(location: 0, length: ns.length)
            if let m = clientRe.firstMatch(in: line, range: range) {
                let path = ns.substring(with: m.range(at: 1)).trimmingCharacters(in: .whitespaces)
                if !path.isEmpty, !current.contains(path) { current.append(path) }
            } else if let m = sigtermRe.firstMatch(in: line, range: range) {
                let time = TimeInterval(ns.substring(with: m.range(at: 1))).map { Date(timeIntervalSince1970: $0) }
                reboots.append(Reboot(time: time, processes: current))
                current = []
            }
        }
        // Delays logged after the last SIGTERM marker belong to a restart
        // whose timestamp was not written.
        if !current.isEmpty { reboots.append(Reboot(time: nil, processes: current)) }
        self.reboots = reboots
    }

    public var processes: [Process] {
        var byPath = [String: Process]()
        var order = [String]()
        for r in reboots {
            for p in r.processes {
                if byPath[p] == nil {
                    byPath[p] = Process(path: p, delayCount: 0, firstSeen: r.time, lastSeen: r.time)
                    order.append(p)
                }
                byPath[p]!.delayCount += 1
                if let t = r.time {
                    if byPath[p]!.firstSeen.map({ t < $0 }) ?? true { byPath[p]!.firstSeen = t }
                    if byPath[p]!.lastSeen.map({ t > $0 }) ?? true { byPath[p]!.lastSeen = t }
                }
            }
        }
        return order.map { byPath[$0]! }
    }
}
