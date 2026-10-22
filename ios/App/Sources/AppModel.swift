import Foundation
import PSGCompanion
import PSGCore
import UIKit

/// The owner's answers and app state, kept in a Data Protection file on the
/// phone. Nothing here is ever sent anywhere.
struct SavedState: Codable {
    var onboarded = false
    var profileAnswer: String?
    var ownerJailbroke: Bool?
    var threatNotification: Bool?
    var lockdownModeOn: Bool?
    var safetyCheckReviewed: Bool?
    var lastAlert: Date?
    /// subject|confidence|rules of findings already written to the timeline,
    /// so a finding is recorded once, and again only if it changes.
    var recorded: [String] = []
    /// Optional so state saved by older builds still decodes.
    var appLockOn: Bool?
    var lastRuleCheck: Date?
    var lastRuleCheckResult: String?
}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var rules: CompanionRules?
    @Published private(set) var loadError: String?
    @Published var state = SavedState()
    @Published private(set) var posture = DevicePosture(osVersion: UIDevice.current.systemVersion)
    @Published private(set) var device: SectionResult?
    @Published private(set) var diagnostics: DiagnosticAnalyzer.Report?
    @Published var diagnosticsBusy = false
    @Published var diagnosticsError: String?
    @Published var extraIndicators: IndicatorSet?
    @Published private(set) var evidenceVersion = 0
    /// True while the app lock is on and the owner has not unlocked yet.
    @Published var locked = false
    @Published private(set) var ruleCheckBusy = false

    let helplines: ContactDirectory?
    private(set) var evidence: EvidenceStore?

    private let stateURL: URL = {
        let dir = (try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true))
            ?? FileManager.default.temporaryDirectory
        return dir.appendingPathComponent("state.json")
    }()

    var country: String { Locale.current.region?.identifier ?? "INTL" }

    init() {
        helplines = try? ContactDirectory.bundled("helplines.json")
        do {
            // FR-CHK-04: works fully offline with the signed rules in the
            // app, or a newer verified update (FR-RUL-02).
            rules = try RuleUpdates.load()
        } catch {
            loadError = "The detection rules failed their check, so no check can run. Update or reinstall the app from the App Store. (\(error))"
        }
        evidence = try? EvidenceStore()
        if let data = try? Data(contentsOf: stateURL), let s = try? JSONDecoder().decode(SavedState.self, from: data) {
            state = s
        }
        locked = state.appLockOn == true
        refresh()
    }

    // MARK: Running the checks

    func refresh() {
        guard let rules else { return }
        var p = DevicePosture(osVersion: UIDevice.current.systemVersion)
        DevicePostureReader.read(into: &p)
        p.profileAnswer = state.profileAnswer.flatMap(DevicePosture.ProfileAnswer.init(rawValue:))
        p.ownerJailbroke = state.ownerJailbroke
        p.threatNotification = state.threatNotification
        p.lockdownModeOn = state.lockdownModeOn
        p.safetyCheckReviewed = state.safetyCheckReviewed
        posture = p
        device = PSGCompanion.DeviceCheck(rules: rules).run(p) // qualified: Apple also has a DeviceCheck module
        if let device { record(device) }
        persist()
    }

    /// Write new or changed findings to the evidence timeline.
    private func record(_ section: SectionResult) {
        guard let evidence else { return }
        let fresh = section.cards.filter { !state.recorded.contains(key($0)) }
        guard !fresh.isEmpty else { return }
        let partial = SectionResult(section: section.section, findings: fresh, limits: [], unanswered: [])
        if (try? EvidenceRecorder(log: evidence.log).record(partial)) != nil {
            state.recorded.append(contentsOf: fresh.map(key))
            if fresh.contains(where: { $0.rating == .actNow }) { state.lastAlert = Date() }
            try? evidence.save()
            evidenceVersion += 1
        }
    }

    private func key(_ f: Finding) -> String {
        "\(f.subject)|\(f.verdict.confidence.rawValue)|\(f.concerningRules.map(\.id).joined(separator: ","))"
    }

    /// Record one answer in the timeline and re-score.
    func answered(_ summary: String, item: String, answer: String) {
        if let evidence {
            try? EvidenceRecorder(log: evidence.log).recordAnswer(summary, item: item, answer: answer)
            try? evidence.save()
            evidenceVersion += 1
        }
        refresh()
    }

    // MARK: Diagnostic archives (FR-IOS-03)

    func analyze(url: URL) {
        guard let rules else { return }
        diagnosticsBusy = true
        diagnosticsError = nil
        let extra = extraIndicators
        Task.detached(priority: .userInitiated) {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let report = try DiagnosticAnalyzer(rules: rules, extraIndicators: extra).analyze(url: url)
                await MainActor.run {
                    self.diagnostics = report
                    self.diagnosticsBusy = false
                    if let evidence = self.evidence {
                        try? evidence.log.append(.note, "Diagnostic archive analysed", details: [
                            "file": url.lastPathComponent, "restarts": String(report.rebootsSeen),
                            "indicators": "\(report.indicatorCount) from \(report.indicatorSource)",
                            "result": report.rating.label,
                        ])
                        self.record(report.asSection)
                        try? evidence.save()
                        self.evidenceVersion += 1
                    }
                    self.persist()
                }
            } catch {
                await MainActor.run {
                    self.diagnosticsError = "\(error)"
                    self.diagnosticsBusy = false
                }
            }
        }
    }

    /// A shared STIX2 file adds indicators for the next analyses.
    func loadIndicators(url: URL) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let set = try IndicatorSet.fromSTIX2(String(contentsOf: url, encoding: .utf8), source: url.lastPathComponent)
        if var current = extraIndicators { current.merge(set); extraIndicators = current } else { extraIndicators = set }
    }

    /// Anything shared into the app: indicator files are loaded, everything
    /// else is treated as a diagnostic archive.
    func open(url: URL) {
        let name = url.lastPathComponent.lowercased()
        if name.hasSuffix(".stix2") || name.hasSuffix(".stix") {
            do { try loadIndicators(url: url) } catch { diagnosticsError = "\(error)" }
        } else {
            analyze(url: url)
        }
    }

    // MARK: App lock

    func lockIfNeeded() {
        if state.appLockOn == true { locked = true }
    }

    func unlock() async {
        if await AppLock.unlock() { locked = false }
    }

    /// Turning the lock on or off needs the owner's Face ID or passcode, so
    /// someone else holding the unlocked phone cannot quietly switch it off.
    func setAppLock(_ on: Bool) async {
        guard await AppLock.unlock() else { return }
        state.appLockOn = on
        persist()
    }

    var developmentBuild: Bool { rules?.developmentKeys == true }

    // MARK: Rule updates (FR-RUL-02)

    var ruleUpdatesAvailable: Bool { RuleUpdates.baseURL != nil }

    /// Checks at most once a day on its own; the owner can check any time.
    func checkForRuleUpdates(manual: Bool = false) async {
        guard let updater = RuleUpdates.updater(), !ruleCheckBusy else { return }
        if !manual, let last = state.lastRuleCheck, Date().timeIntervalSince(last) < 24 * 3600 { return }
        ruleCheckBusy = true
        defer { ruleCheckBusy = false }
        let outcome = await updater.run()
        state.lastRuleCheck = Date()
        switch outcome {
        case .updated(let files):
            do {
                let fresh = try RuleUpdates.load()
                rules = fresh
                loadError = nil
                let versions = fresh.provenance.filter { files.contains($0.file) }
                    .map { "\($0.file.rawValue) v\($0.version)" }.joined(separator: ", ")
                state.lastRuleCheckResult = "Updated: \(versions)"
                if let evidence {
                    // Which rules produced later findings is part of the record.
                    try? evidence.log.append(.note, "Detection rules updated", details: Dictionary(uniqueKeysWithValues:
                        fresh.provenance.filter { files.contains($0.file) }.map { ($0.file.rawValue, "v\($0.version) sha256 \($0.sha256)") }))
                    try? evidence.save()
                    evidenceVersion += 1
                }
                refresh()
            } catch {
                state.lastRuleCheckResult = "The update could not be loaded, so the app keeps its current rules."
            }
        case .alreadyCurrent:
            state.lastRuleCheckResult = "Already up to date"
        case .failed:
            state.lastRuleCheckResult = "Could not reach the update server. The app keeps working with its current rules."
        }
        persist()
    }

    // MARK: Persistence

    func persist() {
        if let data = try? JSONEncoder().encode(state) {
            try? data.write(to: stateURL, options: [.atomic, .completeFileProtection])
        }
    }

    var overall: Rating {
        [device?.rating, diagnostics?.rating].compactMap { $0 }.max() ?? .clear
    }
}
